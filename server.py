#!/usr/bin/python3
"""Standalone BlueZ GATT server and LE advertisement."""

import argparse
import signal
import sys

import dbus
import dbus.exceptions
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from common import (
    ADAPTER_IFACE, ADVERTISEMENT_IFACE, ADVERTISING_MANAGER_IFACE,
    BLUEZ_SERVICE, DBUS_PROPERTIES, GATT_CHARACTERISTIC_IFACE,
    GATT_MANAGER_IFACE, GATT_SERVICE_IFACE, OBJECT_MANAGER, adapter_path,
    controller_summary, event, load_config, managed_objects,
)


AGENT_IFACE = "org.bluez.Agent1"
AGENT_MANAGER_IFACE = "org.bluez.AgentManager1"


class InvalidArguments(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.InvalidArgs"


class PropertyReadOnly(dbus.exceptions.DBusException):
    _dbus_error_name = "org.freedesktop.DBus.Error.PropertyReadOnly"


class InvalidOffset(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.InvalidOffset"


class InvalidValueLength(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.InvalidValueLength"


class Rejected(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.Rejected"


class Agent(dbus.service.Object):
    def __init__(self, bus, allowed_paths):
        self.path = "/com/example/dbusrepro/agent"
        super().__init__(bus, self.path)
        self.allowed_paths = frozenset(allowed_paths)

    def _authorize(self, device):
        if str(device) not in self.allowed_paths:
            raise Rejected("device is not part of this benchmark")

    @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
    def Release(self):
        pass

    @dbus.service.method(AGENT_IFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        self._authorize(device)
        event("confirmed benchmark pairing for {}".format(device))

    @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        self._authorize(device)

    @dbus.service.method(AGENT_IFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        self._authorize(device)

    @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
    def Cancel(self):
        pass


class PropertiesObject(dbus.service.Object):
    interface = None

    @dbus.service.method(DBUS_PROPERTIES, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != self.interface:
            raise InvalidArguments("unknown interface " + interface)
        return self.properties()

    @dbus.service.method(DBUS_PROPERTIES, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        properties = self.GetAll(interface)
        if prop not in properties:
            raise InvalidArguments("unknown property " + prop)
        return properties[prop]

    @dbus.service.method(DBUS_PROPERTIES, in_signature="ssv", out_signature="")
    def Set(self, interface, prop, value):
        raise PropertyReadOnly("properties are read-only")


class Service(PropertiesObject):
    interface = GATT_SERVICE_IFACE

    def __init__(self, bus, path, uuid):
        super().__init__(bus, path)
        self.path = path
        self.uuid = uuid
        self.characteristics = []

    def properties(self):
        return {
            "UUID": dbus.String(self.uuid),
            "Primary": dbus.Boolean(True),
            "Characteristics": dbus.Array(
                [dbus.ObjectPath(item.path) for item in self.characteristics], signature="o"),
        }


class Characteristic(PropertiesObject):
    interface = GATT_CHARACTERISTIC_IFACE

    def __init__(self, bus, path, uuid, service, initial_value):
        super().__init__(bus, path)
        self.path = path
        self.uuid = uuid
        self.service = service
        self.value = bytearray(initial_value)

    def properties(self):
        return {
            "UUID": dbus.String(self.uuid),
            "Service": dbus.ObjectPath(self.service.path),
            "Flags": dbus.Array(["read", "write"], signature="s"),
        }

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        offset = int(options.get("offset", 0))
        if offset > len(self.value):
            raise InvalidOffset("offset exceeds value length")
        payload = self.value[offset:]
        event("read {} byte(s) at offset {}: {}".format(
            len(payload), offset, payload.hex()))
        return dbus.Array((dbus.Byte(value) for value in payload), signature="y")

    @dbus.service.method(GATT_CHARACTERISTIC_IFACE, in_signature="aya{sv}", out_signature="")
    def WriteValue(self, value, options):
        payload = bytes(value)
        offset = int(options.get("offset", 0))
        if offset > len(self.value):
            raise InvalidOffset("offset exceeds value length")
        if offset + len(payload) > 512:
            raise InvalidValueLength("resulting value exceeds 512 bytes")
        self.value[offset:offset + len(payload)] = payload
        event("write {} byte(s) at offset {}: {}".format(
            len(payload), offset, payload.hex()))


class Application(dbus.service.Object):
    def __init__(self, bus, bluetooth):
        super().__init__(bus, "/com/example/dbusrepro")
        self.path = "/com/example/dbusrepro"
        self.service = Service(bus, self.path + "/service0", bluetooth.service_uuid)
        self.characteristic = Characteristic(
            bus, self.service.path + "/char0", bluetooth.characteristic_uuid,
            self.service, bluetooth.initial_value)
        self.service.characteristics.append(self.characteristic)

    @dbus.service.method(OBJECT_MANAGER, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        return {
            dbus.ObjectPath(self.service.path): {
                GATT_SERVICE_IFACE: self.service.properties(),
            },
            dbus.ObjectPath(self.characteristic.path): {
                GATT_CHARACTERISTIC_IFACE: self.characteristic.properties(),
            },
        }


class Advertisement(PropertiesObject):
    interface = ADVERTISEMENT_IFACE

    def __init__(self, bus, bluetooth):
        self.path = "/com/example/dbusrepro/advertisement0"
        super().__init__(bus, self.path)
        self.bluetooth = bluetooth

    def properties(self):
        return {
            "Type": dbus.String("peripheral"),
            "ServiceUUIDs": dbus.Array([self.bluetooth.service_uuid], signature="s"),
            "LocalName": dbus.String(self.bluetooth.local_name),
        }

    @dbus.service.method(ADVERTISEMENT_IFACE, in_signature="", out_signature="")
    def Release(self):
        event("advertisement released by BlueZ")


class Server:
    def __init__(self, config, server_address, client_address):
        self.config = config
        self.loop = GLib.MainLoop()
        self.bus = dbus.SystemBus()
        self.path = adapter_path(config.server.adapter)
        objects = managed_objects(self.bus)
        interfaces = objects.get(dbus.ObjectPath(self.path), {})
        required = {ADAPTER_IFACE, GATT_MANAGER_IFACE, ADVERTISING_MANAGER_IFACE}
        missing = required - set(interfaces)
        if missing:
            raise RuntimeError("{} lacks interfaces: {}".format(self.path, ", ".join(sorted(missing))))
        adapter_object = self.bus.get_object(BLUEZ_SERVICE, self.path)
        dbus.Interface(adapter_object, DBUS_PROPERTIES).Set(
            ADAPTER_IFACE, "Powered", dbus.Boolean(True))
        self.gatt_manager = dbus.Interface(adapter_object, GATT_MANAGER_IFACE)
        self.advertising_manager = dbus.Interface(adapter_object, ADVERTISING_MANAGER_IFACE)
        server_device = self.path + "/dev_" + client_address.replace(":", "_")
        client_device = (adapter_path(config.client.adapter) + "/dev_" +
                         server_address.replace(":", "_"))
        self.agent = Agent(self.bus, (server_device, client_device))
        self.agent_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE, "/org/bluez"), AGENT_MANAGER_IFACE)
        self.agent_registered = False
        self.application = Application(self.bus, config.bluetooth)
        self.advertisement = Advertisement(self.bus, config.bluetooth)
        self.app_registered = False
        self.ad_registered = False
        self.stopping = False

    def _registered(self, kind):
        if kind == "application":
            self.app_registered = True
        else:
            self.ad_registered = True
        event(kind + " registered")
        if self.app_registered and self.ad_registered:
            print("READY", flush=True)

    def _registration_error(self, error):
        event("registration failed: {}".format(error))
        self.loop.quit()

    def run(self):
        event("adapter {} controller profile {}".format(
            self.config.server.adapter, controller_summary(self.config.server.controller)))
        self.agent_manager.RegisterAgent(self.agent.path, "NoInputNoOutput")
        self.agent_registered = True
        self.agent_manager.RequestDefaultAgent(self.agent.path)
        event("noninteractive pairing agent registered")
        self.gatt_manager.RegisterApplication(
            self.application.path, {},
            reply_handler=lambda: self._registered("application"),
            error_handler=self._registration_error)
        self.advertising_manager.RegisterAdvertisement(
            self.advertisement.path, {},
            reply_handler=lambda: self._registered("advertisement"),
            error_handler=self._registration_error)
        self.loop.run()
        self.cleanup()
        if not (self.app_registered and self.ad_registered) and not self.stopping:
            raise RuntimeError("BlueZ registration failed")

    def stop(self, signum=None, frame=None):
        if not self.stopping:
            self.stopping = True
            event("stopping" + (" on signal {}".format(signum) if signum else ""))
            self.loop.quit()

    def cleanup(self):
        if self.ad_registered:
            try:
                self.advertising_manager.UnregisterAdvertisement(self.advertisement.path)
            except dbus.DBusException as exc:
                event("advertisement cleanup: {}".format(exc))
            self.ad_registered = False
        if self.app_registered:
            try:
                self.gatt_manager.UnregisterApplication(self.application.path)
            except dbus.DBusException as exc:
                event("application cleanup: {}".format(exc))
            self.app_registered = False
        if self.agent_registered:
            try:
                self.agent_manager.UnregisterAgent(self.agent.path)
            except dbus.DBusException as exc:
                event("agent cleanup: {}".format(exc))
            self.agent_registered = False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="INI file (default: config.ini beside this script)")
    parser.add_argument("--server-address", required=True, help="benchmark server Bluetooth address")
    parser.add_argument("--client-address", required=True, help="benchmark client Bluetooth address")
    args = parser.parse_args(argv)
    DBusGMainLoop(set_as_default=True)
    config = load_config(args.config)
    server = Server(config, args.server_address.upper(), args.client_address.upper())
    signal.signal(signal.SIGINT, server.stop)
    signal.signal(signal.SIGTERM, server.stop)
    server.run()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("server: {}".format(exc), file=sys.stderr)
        sys.exit(1)
