#!/usr/bin/python3
"""Apply and verify one role's complete Bluetooth controller profile."""

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

from common import adapter_path, controller_summary, load_config


SYSCONFIG_TYPES = (
    ("0017", "le_min_connection_interval"),
    ("0018", "le_max_connection_interval"),
    ("0019", "le_connection_latency"),
    ("001a", "le_supervision_timeout"),
)


def little_endian(value):
    return value.to_bytes(2, "little").hex()


def use_pty(mode):
    if mode == "always":
        return True
    if mode == "never":
        return False
    return not sys.stdin.isatty() and shutil.which("script") is not None


def run_btmgmt(index, controller, description, arguments):
    command = ["btmgmt", "--index", str(index)] + list(arguments)
    pty = use_pty(controller.btmgmt_pty)
    if pty:
        script = shutil.which("script")
        if script is None:
            raise RuntimeError("btmgmt PTY mode is always, but util-linux script was not found")
        command = [script, "-q", "-e", "-f", "-c", shlex.join(command), "/dev/null"]
    print("{}: {} ({})".format(description, shlex.join(command),
                                "PTY" if pty else "direct"), flush=True)
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL if pty else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=controller.btmgmt_timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        raise RuntimeError(
            "{} timed out after {}s\n{}".format(
                description, controller.btmgmt_timeout, output)) from exc
    if result.stdout:
        print(result.stdout.rstrip(), flush=True)
    if result.returncode:
        raise RuntimeError("{} failed with exit status {}".format(
            description, result.returncode))
    return result.stdout


def verify_sysconfig(output, controller):
    failures = []
    for type_code, attribute in SYSCONFIG_TYPES:
        expected = little_endian(getattr(controller, attribute))
        pattern = (r"Type:\s*0x{}\b(?:(?!\bType:).)*?"
                   r"Value:\s*(?:0x)?{}\b").format(type_code, expected)
        if not re.search(pattern, output, re.IGNORECASE | re.DOTALL):
            failures.append("0x{}={} (little-endian {})".format(
                type_code, hex(getattr(controller, attribute)), expected))
    if failures:
        relevant = [line for line in output.splitlines()
                    if re.search(r"0x001[789a]", line, re.IGNORECASE)]
        raise RuntimeError(
            "read-sysconfig verification failed; missing {}\nRelevant output:\n{}".format(
                ", ".join(failures), "\n".join(relevant) or "(none)"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="INI file (default: config.ini beside this script)")
    parser.add_argument("--role", choices=("server", "client"), required=True)
    parser.add_argument("--adapter", help="hciN override for the selected role")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("adapter configuration must run as root (use sudo)")
    if shutil.which("btmgmt") is None:
        parser.error("btmgmt was not found; install BlueZ management tools")

    config = load_config(args.config)
    role = getattr(config, args.role)
    adapter = args.adapter or role.adapter
    adapter_path(adapter)
    index = int(adapter[3:])
    controller = role.controller
    print("Configuring {} role on {} with profile {}".format(
        args.role, adapter, controller_summary(controller)), flush=True)

    powered_off = False
    powered_on = False
    try:
        run_btmgmt(index, controller, "power off " + adapter, ("power", "off"))
        powered_off = True
        time.sleep(0.5)
        run_btmgmt(index, controller, "power on " + adapter, ("power", "on"))
        powered_on = True
        time.sleep(1)
        run_btmgmt(index, controller, "replace PHY selection on " + adapter,
                   ("phy",) + controller.phys)
        time.sleep(1)
        values = tuple("{}:2:{}".format(type_code, little_endian(getattr(controller, attribute)))
                       for type_code, attribute in SYSCONFIG_TYPES)
        run_btmgmt(index, controller, "set LE defaults on " + adapter,
                   ("set-sysconfig", "-v") + values)
        output = run_btmgmt(index, controller, "read system configuration on " + adapter,
                            ("read-sysconfig",))
        verify_sysconfig(output, controller)
    finally:
        if powered_off and not powered_on:
            try:
                run_btmgmt(index, controller, "recovery power on " + adapter,
                           ("power", "on"))
            except BaseException as exc:
                print("WARNING: failed to power {} back on: {}".format(adapter, exc),
                      file=sys.stderr)
    print("Verified {} role on {}".format(args.role, adapter), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("adapter: {}".format(exc), file=sys.stderr)
        sys.exit(1)
