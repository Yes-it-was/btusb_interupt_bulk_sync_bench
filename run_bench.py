#!/usr/bin/python3
"""Run the standalone BlueZ GATT/USB ordering reproduction benchmark."""

import argparse
import configparser
import csv
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from common import (
    ADAPTER_IFACE, BLUEZ_SERVICE, adapter_path, bluetooth_address, load_config,
    managed_objects,
)


HERE = Path(__file__).resolve().parent
ACTIVE_PROCESSES = []
INTERRUPTED = False
PHY_NAMES = frozenset((
    "BR1M1SLOT", "BR1M3SLOT", "BR1M5SLOT",
    "EDR2M1SLOT", "EDR2M3SLOT", "EDR2M5SLOT",
    "EDR3M1SLOT", "EDR3M3SLOT", "EDR3M5SLOT",
    "LE1MTX", "LE1MRX", "LE2MTX", "LE2MRX", "LECODEDTX", "LECODEDRX",
))
SUMMARY_FIELDS = (
    "attempt", "server_hardware_name", "status", "phase",
    "usb_delta_ms", "hci_delta_ms", "mtu_request_observed",
    "mtu_request_dropped_unknown_handle", "gatt_state_glitched",
    "bug_reproduced", "duration_seconds", "error",
)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def display_path(path):
    return os.path.relpath(os.path.abspath(path), os.getcwd())


def command_text(command):
    import shlex
    return shlex.join([str(item) for item in command])


def run(command, timeout, *, sudo=False, output=None, check=True):
    full = (["sudo", "-n", "--"] if sudo else []) + [str(item) for item in command]
    kwargs = {"timeout": timeout, "check": False, "text": True}
    if output is None:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        kwargs.update(stdout=output, stderr=subprocess.STDOUT)
    result = subprocess.run(full, **kwargs)
    if check and result.returncode:
        detail = (result.stdout or "").strip() if output is None else "see command log"
        raise RuntimeError("command failed ({}): {}{}".format(
            result.returncode, command_text(full), "\n" + detail if detail else ""))
    return result


def write_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def redact_device_addresses(value):
    if not isinstance(value, str):
        return value
    value = re.sub(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
                   "<bluetooth-address>", value)
    return re.sub(r"(?i)(?:[0-9a-f]{2}_){5}[0-9a-f]{2}",
                  "<bluetooth-address>", value)


def shareable_hardware(identity):
    fields = (
        "name", "source", "chipset_name", "device_name", "manufacturer",
        "usb_vendor_id", "usb_product_id",
    )
    return {key: identity.get(key) for key in fields}


def summary_result(result):
    output = {key: result.get(key, "") for key in SUMMARY_FIELDS}
    output["error"] = redact_device_addresses(output["error"])
    return output


def parse_actions(value):
    actions = tuple(item.strip() for item in value.split(",") if item.strip())
    if not actions:
        raise argparse.ArgumentTypeError("actions must not be empty")
    return actions


def effective_config(source, destination, args):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    with open(source, "r", encoding="ascii") as handle:
        parser.read_file(handle)
    if args.server:
        parser.set("server", "adapter", args.server)
    if args.client:
        parser.set("client", "adapter", args.client)
    if args.actions:
        parser.set("client", "actions", ", ".join(args.actions))
    if args.attempts:
        parser.set("run", "attempts", str(args.attempts))
    if args.log_root:
        parser.set("run", "log_root", os.path.abspath(args.log_root))
    elif not os.path.isabs(parser.get("run", "log_root")):
        parser.set("run", "log_root", os.path.abspath(os.path.join(
            os.path.dirname(source), parser.get("run", "log_root"))))
    with open(destination, "w", encoding="ascii") as handle:
        parser.write(handle)


def update_bluez_config(text, reverse_discovery, just_works_repairing, gatt_cache):
    wanted = {
        "General": {
            "ReverseServiceDiscovery": "true" if reverse_discovery else "false",
            "JustWorksRepairing": just_works_repairing,
        },
        "GATT": {"Cache": gatt_cache},
    }
    lines = text.splitlines()
    output = []
    current = None
    written = set()

    def finish_section(section):
        for key, value in wanted.get(section, {}).items():
            marker = (section, key)
            if marker not in written:
                output.append("{} = {}".format(key, value))
                written.add(marker)

    for line in lines:
        match = re.match(r"^\s*\[([^]]+)\]\s*$", line)
        if match:
            finish_section(current)
            current = match.group(1)
            output.append(line)
            continue
        if current in wanted:
            for key, value in wanted[current].items():
                if re.match(r"^\s*(?:#\s*)?{}\s*=".format(re.escape(key)), line,
                            re.IGNORECASE):
                    marker = (current, key)
                    if marker not in written:
                        output.append("{} = {}".format(key, value))
                        written.add(marker)
                    break
            else:
                output.append(line)
            continue
        output.append(line)
    finish_section(current)
    for section, values in wanted.items():
        missing = [(key, value) for key, value in values.items()
                   if (section, key) not in written]
        if missing:
            if output and output[-1]:
                output.append("")
            output.append("[{}]".format(section))
            output.extend("{} = {}".format(key, value) for key, value in missing)
    return "\n".join(output) + "\n"


def systemd_quote(value):
    return '"{}"'.format(str(value).replace("\\", "\\\\").replace('"', '\\"'))


class BluezOverride:
    def __init__(self, config, run_id, run_dir):
        self.config = config
        self.run_id = run_id
        self.run_dir = run_dir
        self.initially_active = False
        self.dropin = Path("/run/systemd/system") / (config.bluez.service + ".d") / (
            "{}-{}.conf".format(config.bluez.dropin_prefix, run_id))
        self.runtime_dir = Path(config.bluez.runtime_root) / (
            "{}-{}".format(config.bluez.dropin_prefix, run_id))
        self.runtime_config = self.runtime_dir / "main.conf"
        self.installed = False

    def install(self):
        cfg = self.config
        status = run(["systemctl", "is-active", "--quiet", cfg.bluez.service],
                     cfg.timeouts.command, check=False)
        self.initially_active = status.returncode == 0
        if run(["test", "-e", self.dropin], cfg.timeouts.command,
               sudo=True, check=False).returncode == 0:
            raise RuntimeError("refusing to overwrite existing drop-in {}".format(self.dropin))
        try:
            source = Path(cfg.bluez.source_config).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError("cannot read BlueZ source config {}: {}".format(
                cfg.bluez.source_config, exc)) from exc
        generated = update_bluez_config(
            source, cfg.bluez.reverse_service_discovery,
            cfg.bluez.just_works_repairing, cfg.bluez.gatt_cache)
        snapshot = self.run_dir / "bluez-main.conf"
        snapshot.write_text(generated, encoding="utf-8")

        shown = run(["systemctl", "show", cfg.bluez.service, "-p", "ExecStart", "--value"],
                    cfg.timeouts.command).stdout
        match = re.search(r"(?:^|[ {;])path=([^ ;}]+)", shown)
        daemon = match.group(1) if match else None
        if not daemon or not os.path.isabs(daemon) or not os.access(daemon, os.X_OK):
            raise RuntimeError("could not determine the bluetoothd executable from systemd")
        local_dropin = self.run_dir / self.dropin.name
        local_dropin.write_text(
            "[Service]\nExecStart=\nExecStart={} -n -d -f {}\n".format(
                systemd_quote(daemon), systemd_quote(self.runtime_config)), encoding="utf-8")
        self.installed = True
        run(["install", "-d", "-m", "0755", self.runtime_dir, self.dropin.parent],
            cfg.timeouts.command, sudo=True)
        run(["install", "-m", "0644", snapshot, self.runtime_config],
            cfg.timeouts.command, sudo=True)
        run(["install", "-m", "0644", local_dropin, self.dropin],
            cfg.timeouts.command, sudo=True)
        run(["systemctl", "daemon-reload"], cfg.timeouts.command, sudo=True)

    def restore(self):
        if not self.installed:
            return
        cfg = self.config
        errors = []
        for command in (
                ["systemctl", "stop", cfg.bluez.service],
                ["rm", "-f", "--", self.dropin],
                ["rm", "-f", "--", self.runtime_config],
                ["rmdir", "--", self.runtime_dir],
                ["systemctl", "daemon-reload"]):
            try:
                result = run(command, cfg.timeouts.command, sudo=True, check=False)
                if result.returncode:
                    errors.append(command_text(command))
            except BaseException as exc:
                errors.append("{} ({})".format(command_text(command), exc))
        desired = "start" if self.initially_active else "stop"
        command = ["systemctl", desired, cfg.bluez.service]
        try:
            result = run(command, cfg.timeouts.service, sudo=True, check=False)
            if result.returncode:
                errors.append(command_text(command))
        except BaseException as exc:
            errors.append("{} ({})".format(command_text(command), exc))
        self.installed = False
        if errors:
            print("WARNING: BlueZ restoration failures: {}".format(", ".join(errors)),
                  file=sys.stderr)


def adapter_address(config, adapter):
    path = Path("/sys/class/bluetooth") / adapter / "address"
    try:
        return bluetooth_address(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        result = run(["hciconfig", adapter],
                     config.timeouts.command, sudo=True)
        match = re.search(
            r"^\s*BD Address:\s*((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})\b",
            result.stdout, re.IGNORECASE | re.MULTILINE)
        if match:
            return bluetooth_address(match.group(1))
        raise RuntimeError("cannot determine Bluetooth address for {}\n{}".format(
            adapter, result.stdout.strip()))


def parse_selected_phys(output):
    match = re.search(r"^Selected phys:\s*(.*?)\s*$", output,
                      re.IGNORECASE | re.MULTILINE)
    if not match:
        raise RuntimeError("btmgmt PHY output has no selected PHY line")
    phys = tuple(match.group(1).upper().split())
    unknown = set(phys) - PHY_NAMES
    if not phys or unknown:
        raise RuntimeError("invalid selected PHY list{}".format(
            ": " + ", ".join(sorted(unknown)) if unknown else ""))
    return phys


def parse_powered(output):
    match = re.search(r"^\s*current settings:\s*(.*?)\s*$", output,
                      re.IGNORECASE | re.MULTILINE)
    if not match:
        raise RuntimeError("btmgmt info output has no current settings line")
    return "powered" in match.group(1).lower().split()


def snapshot_controllers(config):
    snapshots = []
    for role in ("server", "client"):
        adapter = getattr(config, role).adapter
        index = adapter[3:]
        phy_output = run(["btmgmt", "--index", index, "phy"],
                         config.timeouts.command, sudo=True).stdout
        info_output = run(["btmgmt", "--index", index, "info"],
                          config.timeouts.command, sudo=True).stdout
        snapshots.append({
            "role": role,
            "adapter": adapter,
            "powered": parse_powered(info_output),
            "selected_phys": list(parse_selected_phys(phy_output)),
        })
    return snapshots


def restore_controllers(config, snapshots, log_path):
    errors = []
    with open(log_path, "w", encoding="utf-8") as log:
        def logged(command, timeout=None):
            print("$ {}".format(command_text(command)), file=log, flush=True)
            result = run(command, timeout or config.timeouts.command,
                         sudo=True, check=False)
            if result.stdout:
                print(result.stdout.rstrip(), file=log, flush=True)
            if result.returncode:
                raise RuntimeError("command failed ({}): {}".format(
                    result.returncode, command_text(command)))
            return result.stdout or ""

        for snapshot in snapshots:
            adapter = snapshot["adapter"]
            index = adapter[3:]
            restore_error = None
            try:
                target = tuple(snapshot["selected_phys"])
                restored = parse_selected_phys(
                    logged(["btmgmt", "--index", index, "phy"]))
                set_timeout = None
                if set(restored) != set(target):
                    logged(["btmgmt", "--index", index, "power", "on"])
                    time.sleep(1)
                    try:
                        logged(["btmgmt", "--index", index, "phy"] + list(target),
                               timeout=getattr(config, snapshot["role"]).controller.btmgmt_timeout)
                    except subprocess.TimeoutExpired as exc:
                        set_timeout = exc
                        print("WARNING: set PHY timed out; verifying controller state",
                              file=log, flush=True)
                    time.sleep(1)
                    restored = parse_selected_phys(
                        logged(["btmgmt", "--index", index, "phy"]))
                if set(restored) != set(snapshot["selected_phys"]):
                    detail = "PHY verification mismatch: expected {}; got {}".format(
                        " ".join(snapshot["selected_phys"]), " ".join(restored))
                    if set_timeout is not None:
                        detail = "{}; set command timed out after {}s".format(
                            detail, set_timeout.timeout)
                    raise RuntimeError(detail)
            except BaseException as exc:
                restore_error = exc
            finally:
                if not snapshot["powered"]:
                    try:
                        logged(["btmgmt", "--index", index, "power", "off"])
                        time.sleep(0.5)
                    except BaseException as exc:
                        if restore_error is None:
                            restore_error = exc
                        else:
                            restore_error = RuntimeError("{}; power restoration failed: {}".format(
                                restore_error, exc))
                try:
                    powered = parse_powered(
                        logged(["btmgmt", "--index", index, "info"]))
                    if powered != snapshot["powered"]:
                        raise RuntimeError("power verification mismatch: expected {}; got {}".format(
                            "on" if snapshot["powered"] else "off",
                            "on" if powered else "off"))
                except BaseException as exc:
                    if restore_error is None:
                        restore_error = exc
                    else:
                        restore_error = RuntimeError("{}; power verification failed: {}".format(
                            restore_error, exc))
            if restore_error is not None:
                errors.append("{}: {}".format(adapter, restore_error))
                print("ERROR: {}".format(errors[-1]), file=log, flush=True)
            else:
                print("Restored {} PHY and power state".format(adapter),
                      file=log, flush=True)
    return errors


def resolve_usb(adapter):
    path = (Path("/sys/class/bluetooth") / adapter / "device").resolve()
    while path != path.parent:
        bus_file = path / "busnum"
        dev_file = path / "devnum"
        if bus_file.is_file() and dev_file.is_file():
            return {
                "path": str(path),
                "bus": int(bus_file.read_text(encoding="ascii").strip(), 10),
                "device": int(dev_file.read_text(encoding="ascii").strip(), 10),
            }
        path = path.parent
    raise RuntimeError("{} is not backed by a USB device".format(adapter))


def adapter_hardware_identity(adapter, timeout):
    def read_attribute(path, name):
        try:
            return (path / name).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            return ""

    def clean(value):
        return re.sub(r"\s+", " ", value.replace("_", " ")).strip()

    try:
        usb = resolve_usb(adapter)
    except RuntimeError:
        return {
            "name": adapter,
            "label": adapter,
            "source": "adapter-name",
            "usb_vendor_id": None,
            "usb_product_id": None,
        }

    path = Path(usb["path"])
    manufacturer = clean(read_attribute(path, "manufacturer"))
    product = clean(read_attribute(path, "product"))
    vendor_id = read_attribute(path, "idVendor").lower()
    product_id = read_attribute(path, "idProduct").lower()
    properties = {}
    if shutil.which("udevadm"):
        queried = run(["udevadm", "info", "--query=property", "--path", path],
                      timeout, check=False)
        if queried.returncode == 0:
            for line in queried.stdout.splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    properties[key] = clean(value)

    chipset = properties.get("ID_MODEL_FROM_DATABASE", "")
    vendor = (manufacturer or properties.get("ID_VENDOR_FROM_DATABASE") or
              properties.get("ID_VENDOR", ""))
    device_name = product or properties.get("ID_MODEL", "") or adapter
    model = chipset or device_name
    name = " ".join(item for item in (vendor, model) if item)
    usb_id = ":".join(item for item in (vendor_id, product_id) if item)
    if usb_id:
        name = "{} [{}]".format(name or adapter, usb_id)
    label = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:64] or adapter
    return {
        "name": name or adapter,
        "label": label,
        "source": "udev-model-database" if chipset else "usb-device-name",
        "chipset_name": chipset or None,
        "device_name": device_name or None,
        "manufacturer": manufacturer or None,
        "usb_vendor_id": vendor_id or None,
        "usb_product_id": product_id or None,
        "usb_path": str(path),
    }


def wait_service(config, active):
    deadline = time.monotonic() + config.timeouts.service
    while time.monotonic() < deadline:
        result = run(["systemctl", "is-active", "--quiet", config.bluez.service],
                     config.timeouts.command, check=False)
        if (result.returncode == 0) == active:
            return
        time.sleep(0.2)
    raise RuntimeError("timed out waiting for {} to become {}".format(
        config.bluez.service, "active" if active else "inactive"))


def provision(config, role, log_handle):
    command = [sys.executable, HERE / "adapter.py", "--config", config.path, "--role", role]
    run(command, config.timeouts.command + getattr(config, role).controller.btmgmt_timeout * 5,
        sudo=True, output=log_handle)


def start_process(command, stdout_path, *, sudo=False, stderr_path=None):
    stdout_handle = open(stdout_path, "wb")
    stderr_handle = (open(stderr_path, "wb") if stderr_path else subprocess.STDOUT)
    full = (["sudo", "-n", "--"] if sudo else []) + [str(item) for item in command]
    process = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=stdout_handle,
                                # sudo timestamps are terminal-scoped on this host. Keep
                                # privileged captures in that session so `sudo -n` can use
                                # the credential acquired by the harness.
                                stderr=stderr_handle, start_new_session=not sudo)
    process._bench_handles = [stdout_handle] + ([] if stderr_handle is subprocess.STDOUT else [stderr_handle])
    process._bench_command = full
    process._bench_pgid = None if sudo else process.pid
    process._bench_sudo = sudo
    ACTIVE_PROCESSES.append(process)
    return process


def signal_process_group(process, group_signal, timeout):
    pgid = process._bench_pgid
    if process._bench_sudo:
        result = subprocess.run(
            ["sudo", "-n", "kill", "-{}".format(group_signal.name.removeprefix("SIG")),
             "--", str(process.pid)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=min(timeout, 2.0), check=False)
        if result.returncode and process.poll() is None:
            raise RuntimeError("sudo kill {} for process {} failed with status {}".format(
                group_signal.name, process.pid, result.returncode))
        return
    if pgid == os.getpgrp():
        raise RuntimeError("refusing to signal harness process group {}".format(pgid))
    try:
        os.killpg(pgid, group_signal)
    except ProcessLookupError:
        return


def wait_process_group(process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process.poll()
        if process._bench_sudo:
            if process.poll() is not None:
                return True
        else:
            try:
                os.killpg(process._bench_pgid, 0)
            except ProcessLookupError:
                return True
        time.sleep(0.05)
    return False


def stop_process(process, timeout, interrupt=False):
    if process is None:
        return
    stopped = False
    errors = []
    try:
        signals = ((signal.SIGINT, signal.SIGTERM, signal.SIGKILL) if interrupt else
                   (signal.SIGTERM, signal.SIGKILL))
        for group_signal in signals:
            try:
                signal_process_group(process, group_signal, timeout)
                stopped = wait_process_group(process, timeout)
            except BaseException as exc:
                errors.append("{}: {}".format(group_signal.name, exc))
            if stopped:
                break
        if not stopped:
            detail = "; ".join(errors)
            target = process.pid if process._bench_sudo else process._bench_pgid
            raise RuntimeError("process {} survived SIGKILL{}".format(
                target, ": " + detail if detail else ""))
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("process-group leader did not exit") from exc
    finally:
        for handle in getattr(process, "_bench_handles", []):
            handle.close()
        if stopped and process in ACTIVE_PROCESSES:
            ACTIVE_PROCESSES.remove(process)


def stop_all(config):
    for process in list(reversed(ACTIVE_PROCESSES)):
        try:
            is_dumpcap = any("dumpcap" in str(item) for item in process._bench_command)
            stop_process(process, config.timeouts.capture_stop, interrupt=is_dumpcap)
        except BaseException as exc:
            print("WARNING: process cleanup failed: {}".format(exc), file=sys.stderr)


def wait_ready(process, log_path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited before READY with status {}".format(process.returncode))
        try:
            if "READY" in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for server READY")


def collect_journal(config, since, path):
    with open(path, "w", encoding="utf-8") as handle:
        run(["journalctl", "-u", config.bluez.service, "--since", since,
             "--no-pager", "-o", "short-precise"], config.timeouts.command,
            sudo=True, output=handle, check=False)


def reset_peer_bonds(config, server_address, client_address):
    import dbus

    bus = dbus.SystemBus()
    removed = []
    for adapter, peer_address in (
            (config.server.adapter, client_address),
            (config.client.adapter, server_address)):
        peer_path = adapter_path(adapter) + "/dev_" + peer_address.replace(":", "_")
        if dbus.ObjectPath(peer_path) not in managed_objects(bus):
            continue
        dbus.Interface(
            bus.get_object(BLUEZ_SERVICE, adapter_path(adapter)),
            ADAPTER_IFACE).RemoveDevice(dbus.ObjectPath(peer_path))
        removed.append(peer_path)
    return removed


def run_attempt(number, config, run_dir, server_address, client_address,
                server_hardware):
    attempt_dir = run_dir / "attempt-{:04d}".format(number)
    attempt_dir.mkdir()
    started = time.monotonic()
    since = utc_now()
    phase = "reset-bluez"
    result = {"attempt": number, "status": "failed", "started_at": since}
    result["server_hardware"] = server_hardware
    result["server_hardware_name"] = server_hardware["name"]
    processes = []
    usb = None
    server_process = None
    try:
        run(["systemctl", "stop", config.bluez.service], config.timeouts.service, sudo=True)
        wait_service(config, False)
        if config.bluez.delete_client_cache:
            cache = Path("/var/lib/bluetooth") / client_address / "cache" / server_address
            run(["rm", "-f", "--", cache], config.timeouts.command, sudo=True)
            result["deleted_cache"] = str(cache)
        run(["systemctl", "start", config.bluez.service], config.timeouts.service, sudo=True)
        wait_service(config, True)

        phase = "provision-adapters"
        with open(attempt_dir / "adapter.log", "w", encoding="utf-8") as adapter_log:
            provision(config, "server", adapter_log)
            time.sleep(config.timeouts.adapter_delay)
            provision(config, "client", adapter_log)
            time.sleep(config.timeouts.adapter_delay)
            provision(config, "server", adapter_log)
            time.sleep(config.timeouts.adapter_delay)

        if config.bluez.reset_peer_bonds:
            phase = "reset-peer-bonds"
            result["removed_peer_devices"] = reset_peer_bonds(
                config, server_address, client_address)

        if config.captures.usbmon:
            phase = "resolve-server-usb"
            usb = resolve_usb(config.server.adapter)
            result["server_usb"] = usb

        phase = "start-captures"
        if config.captures.server_btmon:
            processes.append(start_process(
                ["btmon", "--index", config.server.adapter[3:]],
                attempt_dir / "btmon-server.log", sudo=True))
        if config.captures.client_btmon:
            processes.append(start_process(
                ["btmon", "--index", config.client.adapter[3:]],
                attempt_dir / "btmon-client.log", sudo=True))
        if config.captures.kernel_journal:
            processes.append(start_process(
                ["journalctl", "-k", "-f", "--since", since, "--no-pager",
                 "-o", "short-monotonic"], attempt_dir / "kernel.log", sudo=True))
        if config.captures.usbmon:
            processes.append(start_process(
                ["dumpcap", "-q", "-i", "usbmon{}".format(usb["bus"]), "-s", "0", "-w", "-"],
                attempt_dir / "usbmon.pcapng", sudo=True,
                stderr_path=attempt_dir / "dumpcap.log"))
        time.sleep(config.timeouts.capture_start_delay)
        failed_captures = [command_text(item._bench_command) for item in processes
                           if item.poll() is not None]
        if failed_captures:
            raise RuntimeError("capture exited early: {}".format(", ".join(failed_captures)))

        phase = "server-ready"
        server_process = start_process(
            [sys.executable, HERE / "server.py", "--config", config.path,
             "--server-address", server_address, "--client-address", client_address],
            attempt_dir / "server.log")
        wait_ready(server_process, attempt_dir / "server.log", config.timeouts.server_ready)

        phase = "client"
        client_process = start_process(
            [sys.executable, HERE / "client.py", "--config", config.path,
             "--address", server_address], attempt_dir / "client-result.json",
            stderr_path=attempt_dir / "client.log")
        client_timed_out = False
        try:
            client_status = client_process.wait(timeout=config.timeouts.client)
        except subprocess.TimeoutExpired:
            client_timed_out = True
            client_status = None
        client_stop_error = None
        try:
            stop_process(client_process, config.timeouts.server_stop)
        except BaseException as exc:
            client_stop_error = exc
        try:
            result["client"] = json.loads(
                (attempt_dir / "client-result.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            if client_timed_out:
                raise RuntimeError("client timed out after {}s; result is not valid JSON: {}".format(
                    config.timeouts.client, exc)) from exc
            raise RuntimeError("client result is not valid JSON: {}".format(exc)) from exc
        if client_stop_error is not None:
            raise RuntimeError("client cleanup failed: {}".format(client_stop_error))
        if client_timed_out:
            raise RuntimeError("client timed out after {}s".format(config.timeouts.client))
        if client_status:
            raise RuntimeError("client failed with exit status {}".format(client_status))
        result["status"] = "passed"
        result["phase"] = "complete"
    except Exception as exc:
        result["phase"] = phase
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
    finally:
        cleanup_errors = []
        if server_process is not None:
            try:
                stop_process(server_process, config.timeouts.server_stop)
            except BaseException as exc:
                cleanup_errors.append("server: {}".format(exc))
        for process in reversed(processes):
            try:
                stop_process(process, config.timeouts.capture_stop,
                             interrupt=any("dumpcap" in str(item) for item in process._bench_command))
            except BaseException as exc:
                cleanup_errors.append("capture: {}".format(exc))
        if config.captures.bluetooth_journal:
            try:
                collect_journal(config, since, attempt_dir / "bluetooth-journal.log")
            except BaseException as exc:
                cleanup_errors.append("Bluetooth journal: {}".format(exc))
        try:
            run(["chmod", "-R", "u+rwX,go-rwx", attempt_dir], config.timeouts.command,
                check=False)
        except BaseException as exc:
            cleanup_errors.append("permissions: {}".format(exc))
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            if result["status"] == "passed":
                result.update(status="failed", phase="cleanup", error="; ".join(cleanup_errors))

    if config.captures.usb_analyzer and config.captures.usbmon and usb:
        analyzer_command = [
            sys.executable, HERE / "analyze_usb.py", "--pcapng", attempt_dir / "usbmon.pcapng",
            "--bus", str(usb["bus"]), "--device", str(usb["device"]),
            "--tsv-output", attempt_dir / "usb-events.tsv",
            "--json-output", attempt_dir / "usb-analysis.json",
            "--timing-output", attempt_dir / "timing.tsv",
            "--server-name", server_hardware["name"],
        ]
        if config.captures.server_btmon:
            analyzer_command.extend(("--btmon-log", attempt_dir / "btmon-server.log"))
        if config.captures.kernel_journal:
            analyzer_command.extend(("--kernel-log", attempt_dir / "kernel.log"))
        try:
            with open(attempt_dir / "analyzer.log", "w", encoding="utf-8") as analyzer_log:
                analyzed = run(analyzer_command, config.timeouts.analyzer,
                               output=analyzer_log, check=False)
            result["analyzer_status"] = analyzed.returncode
            if analyzed.returncode == 0:
                analysis = json.loads(
                    (attempt_dir / "usb-analysis.json").read_text(encoding="utf-8"))
                timing = analysis.get("timing_summary", {})
                result["usb_delta_ms"] = timing.get("minimum_usb_delta_ms")
                result["hci_delta_ms"] = timing.get("minimum_hci_delta_ms")
                result["mtu_request_observed"] = timing.get("mtu_request_observed")
                result["mtu_request_dropped_unknown_handle"] = timing.get(
                    "mtu_request_dropped_unknown_handle")
            if analyzed.returncode and result["status"] == "passed":
                result.update(status="failed", phase="analyzer",
                              error="analyzer failed with exit status {}".format(analyzed.returncode))
        except Exception as exc:
            result["analyzer_status"] = "error"
            if result["status"] == "passed":
                result.update(status="failed", phase="analyzer",
                              error="{}: {}".format(type(exc).__name__, exc))
    gatt_state = result.get("client", {}).get("gatt_state")
    result["gatt_state"] = gatt_state
    result["gatt_state_glitched"] = (gatt_state.get("glitched")
                                      if isinstance(gatt_state, dict) else None)
    dropped = result.get("mtu_request_dropped_unknown_handle")
    if dropped is None or result["gatt_state_glitched"] is None:
        result["bug_reproduced"] = None
    else:
        result["bug_reproduced"] = (dropped is True and
                                    result["gatt_state_glitched"] is True)
    result["finished_at"] = utc_now()
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(attempt_dir / "result.json", result)
    return result


def dependencies(config):
    names = {"btmgmt", "hciconfig", "journalctl", "sudo", "systemctl"}
    if config.captures.server_btmon or config.captures.client_btmon:
        names.add("btmon")
    if config.captures.usbmon:
        names.update(("dumpcap", "modprobe"))
    privileged = {"dumpcap", "modprobe"}
    missing = []
    for name in names:
        if name in privileged:
            found = any((Path(directory or os.curdir) / name).is_file()
                        for directory in os.environ.get("PATH", os.defpath).split(os.pathsep))
        else:
            found = shutil.which(name) is not None
        if not found:
            missing.append(name)
    if missing:
        raise RuntimeError("missing commands: {}".format(", ".join(sorted(missing))))
    try:
        import dbus.exceptions  # noqa: F401
        import dbus.service  # noqa: F401
        from dbus.mainloop.glib import DBusGMainLoop  # noqa: F401
        from gi.repository import GLib  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "missing Python D-Bus bindings for {}: {}; on Arch Linux install "
            "python-dbus and python-gobject".format(sys.executable, exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(HERE / "config.ini"), help="strict benchmark INI")
    parser.add_argument("--attempts", type=int, help="positive attempt count override")
    parser.add_argument("--server", help="server hciN override")
    parser.add_argument("--client", help="client hciN override")
    parser.add_argument("--actions", type=parse_actions, help="comma-separated client actions override")
    parser.add_argument("--log-root", help="output root override")
    parser.add_argument("--validate-config", action="store_true", help="validate config and exit without sudo or hardware access")
    args = parser.parse_args(argv)
    if args.attempts is not None and args.attempts <= 0:
        parser.error("--attempts must be positive")
    base = load_config(args.config)
    if args.validate_config:
        print("valid config: {}".format(display_path(base.path)))
        return 0
    if os.geteuid() == 0:
        parser.error("run as a normal user; this command requests sudo itself")

    os.umask(0o077)
    server_adapter = args.server or base.server.adapter
    server_hardware = adapter_hardware_identity(server_adapter, base.timeouts.command)
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime(
        "{}-%Y%m%dT%H%M%SZ-{}".format(server_hardware["label"], os.getpid()))
    log_root = Path(os.path.abspath(args.log_root)) if args.log_root else Path(base.run.log_root)
    run_dir = log_root / run_id
    summary = []
    run_dir_created = False
    config = None
    override = None
    controller_snapshots = None
    controller_profile_modified = False
    loaded_usbmon = None
    usbmon_loaded_by_run = False
    completed = False
    run_error = None
    cleanup_errors = []
    aggregate = None
    try:
        run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
        run_dir_created = True
        config_path = run_dir / "effective-config.ini"
        effective_config(base.path, config_path, args)
        config = load_config(config_path)
        if config.server.adapter == config.client.adapter:
            raise RuntimeError("server and client adapters must be distinct")
        dependencies(config)

        loaded_usbmon = Path("/sys/module/usbmon").exists()
        if config.captures.usbmon and not loaded_usbmon:
            release = os.uname().release
            modules = Path("/lib/modules") / release
            if not modules.is_dir():
                raise RuntimeError(
                    "usbmon cannot be loaded: kernel modules for running kernel {} "
                    "are unavailable at {}; reboot into the installed kernel or install "
                    "matching kernel modules".format(release, modules))

        run(["sudo", "-v"], config.timeouts.command)

        controller_snapshots = snapshot_controllers(config)
        write_json(run_dir / "controller-snapshot.json", controller_snapshots)
        server_address = adapter_address(config, config.server.adapter)
        client_address = adapter_address(config, config.client.adapter)
        if server_address == client_address:
            raise RuntimeError("server and client adapters have the same address")

        if config.captures.usbmon and not loaded_usbmon:
            try:
                run(["modprobe", "usbmon"], config.timeouts.command, sudo=True)
            except RuntimeError as exc:
                raise RuntimeError(
                    "{}; ensure the running kernel provides CONFIG_USB_MON and its "
                    "matching modules are installed".format(exc)) from exc
            usbmon_loaded_by_run = True
        if config.captures.usbmon:
            usb = resolve_usb(config.server.adapter)
            interfaces = run(["dumpcap", "-D"], config.timeouts.command, sudo=True).stdout
            if not re.search(r"\busbmon{}\b".format(usb["bus"]), interfaces):
                raise RuntimeError("dumpcap does not expose usbmon{}".format(usb["bus"]))

        override = BluezOverride(config, run_id, run_dir)
        summary_tsv = run_dir / "summary.tsv"
        metadata = {
            "run_id": run_id, "started_at": utc_now(), "attempts": config.run.attempts,
            "server_adapter": config.server.adapter, "server_address": server_address,
            "server_hardware": server_hardware,
            "server_hardware_name": server_hardware["name"],
            "client_adapter": config.client.adapter, "client_address": client_address,
            "side_effects": {
                "controller_phy": "original PHY selection is restored during cleanup",
                "controller_sysconfig": "runtime sysconfig remains until reboot or adapter re-enumeration",
                "adapter_power": "original adapter power state is restored during cleanup",
                "usbmon_loaded_by_run": usbmon_loaded_by_run,
                "usbmon_unload_requested": config.captures.unload_usbmon,
                "client_cache_entry_deleted_each_attempt": config.bluez.delete_client_cache,
                "peer_bonds_removed_each_attempt": config.bluez.reset_peer_bonds,
                "persistent_system_defaults_modified": False,
            },
        }
        write_json(run_dir / "metadata.json", metadata)
        print("Run {}: server={} hardware={} client={} logs={}".format(
            run_id, config.server.adapter, server_hardware["name"],
            config.client.adapter, display_path(run_dir)), flush=True)
        override.install()
        with open(summary_tsv, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SUMMARY_FIELDS,
                dialect="excel-tab")
            writer.writeheader()
            for number in range(1, config.run.attempts + 1):
                controller_profile_modified = True
                result = run_attempt(number, config, run_dir, server_address,
                                     client_address, server_hardware)
                summary.append(result)
                writer.writerow(summary_result(result))
                handle.flush()
                def timing_text(value):
                    return "missing" if value is None else "{:+.3f} ms".format(value)
                def drop_text(value, observed):
                    if observed is False:
                        return "not-observed"
                    return "unknown" if value is None else ("UNKNOWN-HANDLE" if value else "no")
                def gatt_text(value):
                    if not isinstance(value, dict):
                        actions = result.get("client", {}).get("actions", [])
                        failed_action = next((item.get("action") for item in reversed(actions)
                                              if item.get("status") == "error"), None)
                        return ("not-reached({}-failed)".format(failed_action)
                                if failed_action else "not-inspected")
                    if value.get("glitched"):
                        return "GLITCHED(connected+resolved+empty)"
                    return "services={}/chars={}".format(
                        value.get("service_count", "?"),
                        value.get("characteristic_count", "?"))
                def bug_text(value):
                    return "unknown" if value is None else ("YES" if value else "no")
                print("[{}/{}] {}{} SERVER={} USB={} HCI={} MTU-DROP={} GATT={} BUG={}".format(
                     number, config.run.attempts, result["status"].upper(),
                     " at " + result.get("phase", "") if result["status"] != "passed" else "",
                     server_hardware["name"],
                     timing_text(result.get("usb_delta_ms")),
                     timing_text(result.get("hci_delta_ms")),
                     drop_text(result.get("mtu_request_dropped_unknown_handle"),
                               result.get("mtu_request_observed")),
                     gatt_text(result.get("gatt_state")),
                     bug_text(result.get("bug_reproduced"))),
                    flush=True)
                if number < config.run.attempts:
                    time.sleep(config.timeouts.between_attempts)
        completed = True
    except BaseException as exc:
        run_error = exc
        raise
    finally:
        if config is not None:
            try:
                stop_all(config)
            except BaseException as exc:
                cleanup_errors.append("processes: {}".format(exc))
        if override is not None:
            try:
                override.restore()
            except BaseException as exc:
                cleanup_errors.append("BlueZ restoration: {}".format(exc))
        if (config is not None and controller_profile_modified and
                controller_snapshots is not None):
            try:
                cleanup_errors.extend(restore_controllers(
                    config, controller_snapshots, run_dir / "controller-restore.log"))
            except BaseException as exc:
                cleanup_errors.append("controller restoration: {}".format(exc))
        if (config is not None and usbmon_loaded_by_run and
                config.captures.unload_usbmon):
            try:
                result = run(["modprobe", "-r", "usbmon"], config.timeouts.command,
                             sudo=True, check=False)
                if result.returncode:
                    cleanup_errors.append("usbmon unload failed with status {}".format(
                        result.returncode))
            except BaseException as exc:
                cleanup_errors.append("usbmon unload: {}".format(exc))

        usb_deltas = [item["usb_delta_ms"] for item in summary
                      if item.get("usb_delta_ms") is not None]
        hci_deltas = [item["hci_delta_ms"] for item in summary
                      if item.get("hci_delta_ms") is not None]
        aggregate = {
            "run_id": run_id, "finished_at": utc_now(), "attempts": len(summary),
            "server_hardware": shareable_hardware(server_hardware),
            "server_hardware_name": server_hardware["name"],
            "passed": sum(item["status"] == "passed" for item in summary),
            "failed": sum(item["status"] != "passed" for item in summary),
            "status": ("complete" if completed else
                       "interrupted" if isinstance(run_error, KeyboardInterrupt) else "setup-failed"),
            "results": [summary_result(item) for item in summary],
            "minimum_usb_delta_ms": min(usb_deltas) if usb_deltas else None,
            "minimum_hci_delta_ms": min(hci_deltas) if hci_deltas else None,
            "mtu_request_observed_attempts": sum(
                item.get("mtu_request_observed") is True for item in summary),
            "mtu_unknown_handle_drop_attempts": sum(
                item.get("mtu_request_dropped_unknown_handle") is True for item in summary),
            "gatt_state_inspected_attempts": sum(
                isinstance(item.get("gatt_state"), dict) for item in summary),
            "glitched_gatt_state_attempts": sum(
                item.get("gatt_state_glitched") is True for item in summary),
            "bug_signature_evaluable_attempts": sum(
                item.get("bug_reproduced") is not None for item in summary),
            "bug_reproduced_attempts": sum(
                item.get("bug_reproduced") is True for item in summary),
        }
        if run_error is not None:
            aggregate["error"] = redact_device_addresses(
                "{}: {}".format(type(run_error).__name__, run_error))
        if cleanup_errors:
            aggregate["cleanup_errors"] = [redact_device_addresses(item)
                                           for item in cleanup_errors]
            aggregate["status"] = "cleanup-failed"
            print("WARNING: cleanup failures: {}".format("; ".join(cleanup_errors)),
                  file=sys.stderr)
        if run_dir_created:
            try:
                write_json(run_dir / "summary.json", aggregate)
            except BaseException as exc:
                print("WARNING: could not write summary.json: {}".format(exc), file=sys.stderr)
        if run_dir_created and config is not None:
            try:
                result = run(["chmod", "-R", "u+rwX,go-rwx", run_dir],
                             config.timeouts.command, check=False)
                if result.returncode:
                    print("WARNING: could not secure run directory permissions", file=sys.stderr)
            except BaseException as exc:
                print("WARNING: permission cleanup failed: {}".format(exc), file=sys.stderr)

    print("Complete: {passed} passed, {failed} failed; {path}".format(
        path=display_path(run_dir), **aggregate))
    print("Minimum event-to-control delta: USB={} HCI={}".format(
        "missing" if aggregate["minimum_usb_delta_ms"] is None else
        "{:+.3f} ms".format(aggregate["minimum_usb_delta_ms"]),
        "missing" if aggregate["minimum_hci_delta_ms"] is None else
        "{:+.3f} ms".format(aggregate["minimum_hci_delta_ms"])))
    print("Confirmed symptoms: MTU unknown-handle drop={}/{} observed; "
          "connected+resolved+empty GATT={}/{} inspected; "
          "combined bug signature={}/{} evaluable".format(
              aggregate["mtu_unknown_handle_drop_attempts"],
              aggregate["mtu_request_observed_attempts"],
              aggregate["glitched_gatt_state_attempts"],
              aggregate["gatt_state_inspected_attempts"],
              aggregate["bug_reproduced_attempts"],
              aggregate["bug_signature_evaluable_attempts"]))
    return 1 if aggregate["failed"] or cleanup_errors else 0


def interrupted(signum, _frame):
    global INTERRUPTED
    INTERRUPTED = True
    raise KeyboardInterrupt("signal {}".format(signum))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("benchmark interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print("run_bench: {}".format(exc), file=sys.stderr)
        sys.exit(2)
