#!/usr/bin/python3
"""Action-driven BlueZ D-Bus GATT client for the standalone repro."""

import argparse
import json
import signal
import sys
import time

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from common import (
    ADAPTER_IFACE, BLUEZ_SERVICE, DBUS_PROPERTIES, DEVICE_IFACE,
    GATT_CHARACTERISTIC_IFACE, GATT_SERVICE_IFACE, OBJECT_MANAGER,
    adapter_path, bluetooth_address, controller_summary, event, load_config,
    managed_objects,
)


class Client:
    def __init__(self, config, address, actions):
        self.config = config
        self.client_config = config.client
        self.address = address.upper()
        self.actions = actions
        self.bus = dbus.SystemBus()
        self.adapter_path = adapter_path(self.client_config.adapter)
        self.adapter_object = self.bus.get_object(BLUEZ_SERVICE, self.adapter_path)
        self.adapter = dbus.Interface(self.adapter_object, ADAPTER_IFACE)
        self.adapter_properties = dbus.Interface(self.adapter_object, DBUS_PROPERTIES)
        self.device_path = None
        self.service_path = None
        self.characteristic_path = None
        self.discovering = False
        self.interrupted = False
        self.results = []
        self.gatt_state = None
        objects = managed_objects(self.bus)
        if ADAPTER_IFACE not in objects.get(dbus.ObjectPath(self.adapter_path), {}):
            raise RuntimeError("adapter not found: " + self.adapter_path)
        self.adapter_properties.Set(ADAPTER_IFACE, "Powered", dbus.Boolean(True))
        self.bus.add_signal_receiver(
            self._properties_changed, signal_name="PropertiesChanged",
            dbus_interface=DBUS_PROPERTIES, path_keyword="path")
        self.bus.add_signal_receiver(
            self._interfaces_added, signal_name="InterfacesAdded",
            dbus_interface=OBJECT_MANAGER)

    def _properties_changed(self, interface, changed, invalidated, path=None):
        if interface == DEVICE_IFACE and path == self.device_path:
            fields = [name for name in ("Connected", "ServicesResolved") if name in changed]
            if fields:
                event("device " + ", ".join(
                    "{}={}".format(name, bool(changed[name])) for name in fields))

    def _interfaces_added(self, path, interfaces):
        device = interfaces.get(DEVICE_IFACE)
        if (device and str(path).startswith(self.adapter_path + "/") and
                str(device.get("Address", "")).upper() == self.address and
                str(device.get("AddressType", "")).lower() == self.client_config.address_type):
            self.device_path = str(path)
            event("target appeared at " + self.device_path)

    def _iterate(self):
        context = GLib.MainContext.default()
        while context.pending():
            context.iteration(False)

    def _wait(self, predicate, timeout, description):
        deadline = time.monotonic() + timeout
        while not predicate():
            if self.interrupted:
                raise KeyboardInterrupt
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for " + description)
            self._iterate()
            time.sleep(0.05)

    def _sleep(self, seconds):
        deadline = time.monotonic() + seconds
        while True:
            if self.interrupted:
                raise KeyboardInterrupt
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._iterate()
            time.sleep(min(0.05, remaining))

    def _device_properties(self):
        if not self.device_path:
            return {}
        objects = managed_objects(self.bus)
        return objects.get(dbus.ObjectPath(self.device_path), {}).get(DEVICE_IFACE, {})

    def _snapshot_gatt_state(self, objects=None):
        if not self.device_path:
            return None
        objects = objects or managed_objects(self.bus)
        prefix = self.device_path + "/"
        properties = objects.get(
            dbus.ObjectPath(self.device_path), {}).get(DEVICE_IFACE, {})
        services = [interfaces[GATT_SERVICE_IFACE]
                    for path, interfaces in objects.items()
                    if str(path).startswith(prefix) and GATT_SERVICE_IFACE in interfaces]
        characteristics = [interfaces[GATT_CHARACTERISTIC_IFACE]
                           for path, interfaces in objects.items()
                           if (str(path).startswith(prefix) and
                               GATT_CHARACTERISTIC_IFACE in interfaces)]
        connected = bool(properties.get("Connected", False))
        resolved = bool(properties.get("ServicesResolved", False))
        empty = not services and not characteristics
        self.gatt_state = {
            "connected": connected,
            "services_resolved": resolved,
            "service_count": len(services),
            "characteristic_count": len(characteristics),
            "service_uuids": sorted(str(item.get("UUID", "")).lower()
                                    for item in services),
            "characteristic_uuids": sorted(str(item.get("UUID", "")).lower()
                                           for item in characteristics),
            "empty": empty,
            "glitched": connected and resolved and empty,
        }
        event("GATT state Connected={} ServicesResolved={} services={} characteristics={}{}".format(
            connected, resolved, len(services), len(characteristics),
            " GLITCHED" if self.gatt_state["glitched"] else ""))
        return self.gatt_state

    def _find_device(self):
        prefix = self.adapter_path + "/"
        for path, interfaces in managed_objects(self.bus).items():
            device = interfaces.get(DEVICE_IFACE)
            if (str(path).startswith(prefix) and device and
                    str(device.get("Address", "")).upper() == self.address and
                    str(device.get("AddressType", "")).lower() == self.client_config.address_type):
                self.device_path = str(path)
                return True
        return False

    def _start_scan(self):
        self.adapter.SetDiscoveryFilter(dbus.Dictionary({
            "Transport": dbus.String("le"),
        }, signature="sv"))
        try:
            self.adapter.StartDiscovery()
        except dbus.DBusException as exc:
            if exc.get_dbus_name() != "org.bluez.Error.InProgress":
                raise
        self.discovering = True
        event("LE discovery started")

    def _stop_scan(self):
        if not self.discovering:
            return
        try:
            self.adapter.StopDiscovery()
        except dbus.DBusException as exc:
            if exc.get_dbus_name() not in ("org.bluez.Error.NotReady", "org.bluez.Error.Failed"):
                event("StopDiscovery: {}".format(exc))
        self.discovering = False
        event("LE discovery stopped")

    def ensure_device(self):
        if self._find_device():
            event("target already known at " + self.device_path)
            return
        self._start_scan()
        try:
            self._wait(self._find_device, self.client_config.discovery_timeout, "target discovery")
        finally:
            self._stop_scan()

    def connect(self):
        self.ensure_device()
        event("connecting to {} through {}".format(self.address, self.client_config.adapter))
        try:
            dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE, self.device_path), DEVICE_IFACE).Connect()
        except dbus.DBusException as exc:
            if exc.get_dbus_name() not in ("org.bluez.Error.AlreadyConnected", "org.bluez.Error.InProgress"):
                raise
        self._wait(
            lambda: bool(self._device_properties().get("Connected", False)),
            self.client_config.operation_timeout, "Connected=true")

    def wait_services(self):
        if not self.device_path:
            raise RuntimeError("wait-services requires a known device")
        self._wait(
            lambda: bool(self._device_properties().get("ServicesResolved", False)),
            self.client_config.operation_timeout, "ServicesResolved=true")
        self._snapshot_gatt_state()

    def discover_gatt(self):
        if not self.device_path:
            self.ensure_device()
        service_uuid = self.config.bluetooth.service_uuid
        characteristic_uuid = self.config.bluetooth.characteristic_uuid
        self.service_path = None
        self.characteristic_path = None
        objects = managed_objects(self.bus)
        self._snapshot_gatt_state(objects)
        for path, interfaces in objects.items():
            service = interfaces.get(GATT_SERVICE_IFACE)
            if (str(path).startswith(self.device_path + "/") and service and
                    str(service.get("UUID", "")).lower() == service_uuid):
                self.service_path = str(path)
                break
        if not self.service_path:
            raise RuntimeError("service not found: " + service_uuid)
        for path, interfaces in objects.items():
            characteristic = interfaces.get(GATT_CHARACTERISTIC_IFACE)
            if (characteristic and str(characteristic.get("Service", "")) == self.service_path and
                    str(characteristic.get("UUID", "")).lower() == characteristic_uuid):
                self.characteristic_path = str(path)
                break
        if not self.characteristic_path:
            raise RuntimeError("characteristic not found: " + characteristic_uuid)
        event("GATT characteristic found at " + self.characteristic_path)

    def _characteristic(self):
        if not self.characteristic_path:
            self.discover_gatt()
        if not self.characteristic_path:
            raise RuntimeError("GATT characteristic is not available")
        return dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE, self.characteristic_path),
            GATT_CHARACTERISTIC_IFACE)

    def disconnect(self):
        if self.device_path and bool(self._device_properties().get("Connected", False)):
            event("disconnecting")
            dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE, self.device_path), DEVICE_IFACE).Disconnect()
            self._wait(
                lambda: not bool(self._device_properties().get("Connected", False)),
                self.client_config.operation_timeout, "Connected=false")

    def remove_device(self):
        if not self.device_path:
            self._find_device()
        if self.device_path:
            event("removing " + self.device_path)
            self.adapter.RemoveDevice(dbus.ObjectPath(self.device_path))
            self.device_path = None
            self.service_path = None
            self.characteristic_path = None

    def run_action(self, action):
        if action == "connect":
            self.connect()
            result = None
        elif action == "wait-services":
            self.wait_services()
            result = None
        elif action == "discover-device":
            self.ensure_device()
            result = self.device_path
        elif action == "discover-gatt":
            self.discover_gatt()
            result = self.characteristic_path
        elif action == "read":
            value = bytes(self._characteristic().ReadValue({}))
            result = value.hex()
            event("read {} byte(s): {}".format(len(value), result))
        elif action.startswith("write:"):
            try:
                value = bytes.fromhex(action.partition(":")[2])
            except ValueError as exc:
                raise ValueError("invalid write hex in action {!r}".format(action)) from exc
            self._characteristic().WriteValue(
                dbus.Array((dbus.Byte(item) for item in value), signature="y"), {})
            result = value.hex()
            event("wrote {} byte(s): {}".format(len(value), result))
        elif action.startswith("sleep:"):
            try:
                seconds = float(action.partition(":")[2])
            except ValueError as exc:
                raise ValueError("invalid sleep duration in action {!r}".format(action)) from exc
            if seconds < 0:
                raise ValueError("sleep duration must not be negative")
            self._sleep(seconds)
            result = seconds
        elif action == "disconnect":
            self.disconnect()
            result = None
        elif action == "remove-device":
            self.remove_device()
            result = None
        else:
            raise ValueError("unknown action: " + action)
        return result

    def run(self):
        event("adapter {} controller profile {}".format(
            self.client_config.adapter, controller_summary(self.client_config.controller)))
        for action in self.actions:
            event("action " + action)
            record = {"action": action, "status": "started", "started_at": time.monotonic()}
            self.results.append(record)
            try:
                record["result"] = self.run_action(action)
            except BaseException as exc:
                record.update(status="error", completed_at=time.monotonic(),
                              error="{}: {}".format(type(exc).__name__, exc))
                raise
            record.update(status="completed", completed_at=time.monotonic())

    def stop(self, signum=None, frame=None):
        self.interrupted = True
        event("interrupted on signal {}".format(signum))

    def cleanup(self):
        try:
            self._stop_scan()
        except BaseException as exc:
            event("scan cleanup: {}".format(exc))
        try:
            self.disconnect()
        except BaseException as exc:
            event("disconnect cleanup: {}".format(exc))


def parse_actions(values, defaults):
    if not values:
        return defaults
    actions = []
    for value in values:
        actions.extend(item.strip() for item in value.split(",") if item.strip())
    return tuple(actions)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="INI file (default: config.ini beside this script)")
    parser.add_argument("--address", help="target Bluetooth address; overrides config")
    parser.add_argument(
        "--action", action="append",
        help="action or comma-separated actions; may be repeated")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    address_value = args.address or config.client.target_address
    if not address_value:
        parser.error("target address is required via --address or [client] target_address")
    address = bluetooth_address(address_value)
    DBusGMainLoop(set_as_default=True)
    client = Client(config, address, parse_actions(args.action, config.client.actions))
    signal.signal(signal.SIGINT, client.stop)
    signal.signal(signal.SIGTERM, client.stop)
    status = "ok"
    error = None
    try:
        client.run()
    except KeyboardInterrupt:
        status = "interrupted"
        error = "interrupted"
    except Exception as exc:
        status = "error"
        error = str(exc)
    finally:
        client.cleanup()
    output = {
        "status": status,
        "adapter": config.client.adapter,
        "address": address,
        "address_type": config.client.address_type,
        "service_uuid": config.bluetooth.service_uuid,
        "characteristic_uuid": config.bluetooth.characteristic_uuid,
        "actions": client.results,
        "gatt_state": client.gatt_state,
    }
    if error is not None:
        output["error"] = error
    print(json.dumps(output, sort_keys=True), flush=True)
    if error is not None:
        raise RuntimeError(error)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        event("client failed: {}".format(exc))
        sys.exit(1)
