#!/usr/bin/python3
"""Shared, strict configuration and BlueZ helpers for the D-Bus repro."""

import configparser
import dataclasses
import os
import re
import sys
import time
from typing import Tuple


BLUEZ_SERVICE = "org.bluez"
DBUS_PROPERTIES = "org.freedesktop.DBus.Properties"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
ADAPTER_IFACE = "org.bluez.Adapter1"
DEVICE_IFACE = "org.bluez.Device1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHARACTERISTIC_IFACE = "org.bluez.GattCharacteristic1"
ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ADDRESS_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SECTIONS = {
    "bluetooth": {
        "service_uuid", "characteristic_uuid", "local_name", "initial_value_hex"
    },
    "controller": {
        "phys", "le_min_connection_interval", "le_max_connection_interval",
        "le_connection_latency", "le_supervision_timeout", "btmgmt_timeout",
        "btmgmt_pty"
    },
    "server": {"adapter"},
    "client": {
        "adapter", "target_address", "address_type", "discovery_timeout",
        "operation_timeout", "actions"
    },
    "server.controller": {
        "phys", "le_min_connection_interval", "le_max_connection_interval",
        "le_connection_latency", "le_supervision_timeout", "btmgmt_timeout",
        "btmgmt_pty"
    },
    "client.controller": {
        "phys", "le_min_connection_interval", "le_max_connection_interval",
        "le_connection_latency", "le_supervision_timeout", "btmgmt_timeout",
        "btmgmt_pty"
    },
    "run": {"attempts", "log_root"},
    "bluez": {
        "service", "source_config", "runtime_root", "dropin_prefix",
        "reverse_service_discovery", "just_works_repairing", "gatt_cache",
        "delete_client_cache", "reset_peer_bonds"
    },
    "captures": {
        "server_btmon", "client_btmon", "kernel_journal", "bluetooth_journal",
        "usbmon", "usb_analyzer", "unload_usbmon"
    },
    "timeouts": {
        "service", "server_ready", "client", "command", "analyzer",
        "capture_start_delay", "capture_stop", "server_stop", "adapter_delay",
        "between_attempts"
    },
}
_REQUIRED_SECTIONS = frozenset(
    ("bluetooth", "controller", "server", "client", "run", "bluez", "captures", "timeouts"))
_CONTROLLER_KEYS = tuple(_SECTIONS["controller"])


@dataclasses.dataclass(frozen=True)
class ControllerConfig:
    phys: Tuple[str, ...]
    le_min_connection_interval: int
    le_max_connection_interval: int
    le_connection_latency: int
    le_supervision_timeout: int
    btmgmt_timeout: float
    btmgmt_pty: str


@dataclasses.dataclass(frozen=True)
class BluetoothConfig:
    service_uuid: str
    characteristic_uuid: str
    local_name: str
    initial_value: bytes


@dataclasses.dataclass(frozen=True)
class ServerConfig:
    adapter: str
    controller: ControllerConfig


@dataclasses.dataclass(frozen=True)
class ClientConfig:
    adapter: str
    target_address: str
    address_type: str
    discovery_timeout: float
    operation_timeout: float
    actions: Tuple[str, ...]
    controller: ControllerConfig


@dataclasses.dataclass(frozen=True)
class RunConfig:
    attempts: int
    log_root: str


@dataclasses.dataclass(frozen=True)
class BluezConfig:
    service: str
    source_config: str
    runtime_root: str
    dropin_prefix: str
    reverse_service_discovery: bool
    just_works_repairing: str
    gatt_cache: str
    delete_client_cache: bool
    reset_peer_bonds: bool


@dataclasses.dataclass(frozen=True)
class CaptureConfig:
    server_btmon: bool
    client_btmon: bool
    kernel_journal: bool
    bluetooth_journal: bool
    usbmon: bool
    usb_analyzer: bool
    unload_usbmon: bool


@dataclasses.dataclass(frozen=True)
class TimeoutConfig:
    service: float
    server_ready: float
    client: float
    command: float
    analyzer: float
    capture_start_delay: float
    capture_stop: float
    server_stop: float
    adapter_delay: float
    between_attempts: float


@dataclasses.dataclass(frozen=True)
class Config:
    bluetooth: BluetoothConfig
    server: ServerConfig
    client: ClientConfig
    run: RunConfig
    bluez: BluezConfig
    captures: CaptureConfig
    timeouts: TimeoutConfig
    path: str


def _required(parser, section, option):
    if not parser.has_option(section, option):
        raise ValueError("missing [{}] {}".format(section, option))
    value = parser.get(section, option).strip()
    if not value:
        raise ValueError("[{}] {} must not be empty".format(section, option))
    return value


def _uint16(value, label):
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise ValueError("{} must be an integer: {!r}".format(label, value)) from exc
    if not 0 <= parsed <= 0xffff:
        raise ValueError("{} must be between 0 and 0xffff".format(label))
    return parsed


def _positive_float(value, label):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError("{} must be a number: {!r}".format(label, value)) from exc
    if parsed <= 0:
        raise ValueError("{} must be positive".format(label))
    return parsed


def _nonnegative_float(value, label):
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError("{} must be a number: {!r}".format(label, value)) from exc
    if parsed < 0:
        raise ValueError("{} must not be negative".format(label))
    return parsed


def _positive_int(value, label):
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise ValueError("{} must be a decimal integer: {!r}".format(label, value)) from exc
    if parsed <= 0:
        raise ValueError("{} must be positive".format(label))
    return parsed


def _boolean(parser, section, option):
    _required(parser, section, option)
    try:
        return parser.getboolean(section, option)
    except ValueError as exc:
        raise ValueError("[{}] {} must be true or false".format(section, option)) from exc


def _absolute_path(parser, section, option):
    value = _required(parser, section, option)
    if not os.path.isabs(value):
        raise ValueError("[{}] {} must be an absolute path".format(section, option))
    return os.path.normpath(value)


def _controller(parser, role):
    values = dict(parser.items("controller"))
    section = role + ".controller"
    if parser.has_section(section):
        values.update(parser.items(section))
    missing = set(_CONTROLLER_KEYS) - set(values)
    if missing:
        raise ValueError("missing [controller] values: {}".format(", ".join(sorted(missing))))
    phys = tuple(item.strip() for item in values["phys"].split(",") if item.strip())
    if not phys:
        raise ValueError("[controller] phys must not be empty")
    if len(set(phys)) != len(phys):
        raise ValueError("controller phys contains duplicate entries")
    prefix = "[{}] ".format(section if parser.has_section(section) else "controller")
    result = ControllerConfig(
        phys=phys,
        le_min_connection_interval=_uint16(
            values["le_min_connection_interval"], prefix + "le_min_connection_interval"),
        le_max_connection_interval=_uint16(
            values["le_max_connection_interval"], prefix + "le_max_connection_interval"),
        le_connection_latency=_uint16(
            values["le_connection_latency"], prefix + "le_connection_latency"),
        le_supervision_timeout=_uint16(
            values["le_supervision_timeout"], prefix + "le_supervision_timeout"),
        btmgmt_timeout=_positive_float(values["btmgmt_timeout"], prefix + "btmgmt_timeout"),
        btmgmt_pty=values["btmgmt_pty"].lower(),
    )
    if result.le_min_connection_interval > result.le_max_connection_interval:
        raise ValueError("minimum connection interval exceeds maximum")
    if result.btmgmt_pty not in ("auto", "always", "never"):
        raise ValueError("{}btmgmt_pty must be auto, always, or never".format(prefix))
    return result


def load_config(path=None):
    path = os.path.abspath(path or os.path.join(os.path.dirname(__file__), "config.ini"))
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with open(path, "r", encoding="ascii") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeError, configparser.Error) as exc:
        raise ValueError("cannot read config {}: {}".format(path, exc)) from exc

    unknown_sections = set(parser.sections()) - set(_SECTIONS)
    missing_sections = _REQUIRED_SECTIONS - set(parser.sections())
    if parser.defaults():
        raise ValueError("[DEFAULT] options are not allowed")
    if unknown_sections:
        raise ValueError("unknown config sections: {}".format(", ".join(sorted(unknown_sections))))
    if missing_sections:
        raise ValueError("missing config sections: {}".format(", ".join(sorted(missing_sections))))
    for section in parser.sections():
        unknown = set(parser.options(section)) - _SECTIONS[section]
        if unknown:
            raise ValueError("unknown options in [{}]: {}".format(section, ", ".join(sorted(unknown))))

    service_uuid = _required(parser, "bluetooth", "service_uuid").lower()
    characteristic_uuid = _required(parser, "bluetooth", "characteristic_uuid").lower()
    if not _UUID_RE.fullmatch(service_uuid) or not _UUID_RE.fullmatch(characteristic_uuid):
        raise ValueError("service_uuid and characteristic_uuid must be full 128-bit UUIDs")
    if service_uuid == characteristic_uuid:
        raise ValueError("service and characteristic UUIDs must differ")
    try:
        initial_value = bytes.fromhex(_required(parser, "bluetooth", "initial_value_hex"))
    except ValueError as exc:
        raise ValueError("[bluetooth] initial_value_hex is invalid") from exc
    if len(initial_value) > 512:
        raise ValueError("initial_value_hex exceeds the 512-byte GATT limit")

    target = parser.get("client", "target_address", fallback="").strip().upper()
    if target:
        target = bluetooth_address(target)
    address_type = _required(parser, "client", "address_type").lower()
    if address_type not in ("public", "random"):
        raise ValueError("[client] address_type must be public or random")
    actions = tuple(item.strip() for item in _required(parser, "client", "actions").split(","))
    if any(not item for item in actions):
        raise ValueError("[client] actions contains an empty action")

    bluetooth = BluetoothConfig(
        service_uuid=service_uuid,
        characteristic_uuid=characteristic_uuid,
        local_name=_required(parser, "bluetooth", "local_name"),
        initial_value=initial_value,
    )
    server_adapter = _required(parser, "server", "adapter")
    client_adapter = _required(parser, "client", "adapter")
    adapter_path(server_adapter)
    adapter_path(client_adapter)
    config_dir = os.path.dirname(path)
    log_root = _required(parser, "run", "log_root")
    if not os.path.isabs(log_root):
        log_root = os.path.join(config_dir, log_root)
    gatt_cache = _required(parser, "bluez", "gatt_cache").lower()
    if gatt_cache not in ("yes", "no", "always"):
        raise ValueError("[bluez] gatt_cache must be yes, no, or always")
    just_works_repairing = _required(
        parser, "bluez", "just_works_repairing").lower()
    if just_works_repairing not in ("never", "confirm", "always"):
        raise ValueError(
            "[bluez] just_works_repairing must be never, confirm, or always")
    dropin_prefix = _required(parser, "bluez", "dropin_prefix")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", dropin_prefix):
        raise ValueError("[bluez] dropin_prefix contains unsafe characters")
    service = _required(parser, "bluez", "service")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", service):
        raise ValueError("[bluez] service must be a systemd .service unit name")
    return Config(
        bluetooth=bluetooth,
        server=ServerConfig(
            adapter=server_adapter,
            controller=_controller(parser, "server"),
        ),
        client=ClientConfig(
            adapter=client_adapter,
            target_address=target,
            address_type=address_type,
            discovery_timeout=_positive_float(
                _required(parser, "client", "discovery_timeout"), "[client] discovery_timeout"),
            operation_timeout=_positive_float(
                _required(parser, "client", "operation_timeout"), "[client] operation_timeout"),
            actions=actions,
            controller=_controller(parser, "client"),
        ),
        run=RunConfig(
            attempts=_positive_int(_required(parser, "run", "attempts"), "[run] attempts"),
            log_root=os.path.abspath(log_root),
        ),
        bluez=BluezConfig(
            service=service,
            source_config=_absolute_path(parser, "bluez", "source_config"),
            runtime_root=_absolute_path(parser, "bluez", "runtime_root"),
            dropin_prefix=dropin_prefix,
            reverse_service_discovery=_boolean(
                parser, "bluez", "reverse_service_discovery"),
            just_works_repairing=just_works_repairing,
            gatt_cache=gatt_cache,
            delete_client_cache=_boolean(parser, "bluez", "delete_client_cache"),
            reset_peer_bonds=_boolean(parser, "bluez", "reset_peer_bonds"),
        ),
        captures=CaptureConfig(**{
            option: _boolean(parser, "captures", option)
            for option in _SECTIONS["captures"]
        }),
        timeouts=TimeoutConfig(
            service=_positive_float(_required(parser, "timeouts", "service"), "[timeouts] service"),
            server_ready=_positive_float(_required(parser, "timeouts", "server_ready"), "[timeouts] server_ready"),
            client=_positive_float(_required(parser, "timeouts", "client"), "[timeouts] client"),
            command=_positive_float(_required(parser, "timeouts", "command"), "[timeouts] command"),
            analyzer=_positive_float(_required(parser, "timeouts", "analyzer"), "[timeouts] analyzer"),
            capture_start_delay=_nonnegative_float(_required(parser, "timeouts", "capture_start_delay"), "[timeouts] capture_start_delay"),
            capture_stop=_positive_float(_required(parser, "timeouts", "capture_stop"), "[timeouts] capture_stop"),
            server_stop=_positive_float(_required(parser, "timeouts", "server_stop"), "[timeouts] server_stop"),
            adapter_delay=_nonnegative_float(_required(parser, "timeouts", "adapter_delay"), "[timeouts] adapter_delay"),
            between_attempts=_nonnegative_float(_required(parser, "timeouts", "between_attempts"), "[timeouts] between_attempts"),
        ),
        path=path,
    )


def adapter_path(adapter):
    if not re.fullmatch(r"hci[0-9]+", adapter):
        raise ValueError("adapter must have the form hciN: {!r}".format(adapter))
    return "/org/bluez/" + adapter


def bluetooth_address(address):
    normalized = address.strip().upper()
    if not _ADDRESS_RE.fullmatch(normalized):
        raise ValueError("not a Bluetooth address: {!r}".format(address))
    return normalized


def managed_objects(bus):
    import dbus
    return dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), OBJECT_MANAGER).GetManagedObjects()


def event(message):
    print("[{:.3f}] {}".format(time.monotonic(), message), file=sys.stderr, flush=True)


def controller_summary(controller):
    return {
        "phys": list(controller.phys),
        "le_min_connection_interval": "0x{:04x}".format(controller.le_min_connection_interval),
        "le_max_connection_interval": "0x{:04x}".format(controller.le_max_connection_interval),
        "le_connection_latency": "0x{:04x}".format(controller.le_connection_latency),
        "le_supervision_timeout": "0x{:04x}".format(controller.le_supervision_timeout),
        "btmgmt_timeout": controller.btmgmt_timeout,
        "btmgmt_pty": controller.btmgmt_pty,
    }
