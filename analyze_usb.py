#!/usr/bin/env python3
"""Analyze Bluetooth HCI traffic in a Linux usbmon pcapng capture."""

import argparse
import csv
import json
import os
import re
import struct
import sys
from collections import defaultdict


USB_LINUX = 189
USB_LINUX_MMAPPED = 220
ATT_CID = 0x0004

ATT_OPCODES = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x16: "Prepare Write Request",
    0x17: "Prepare Write Response",
    0x18: "Execute Write Request",
    0x19: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x20: "Read Multiple Variable Request",
    0x21: "Read Multiple Variable Response",
    0x23: "Multiple Handle Value Notification",
    0x52: "Write Command",
    0xD2: "Signed Write Command",
}

TSV_FIELDS = [
    "record_type", "frame", "time", "direction", "endpoint", "bus",
    "device", "transfer_type", "urb_id", "urb_event", "usb_status",
    "usb_length", "usb_captured_length", "source_frames", "handle",
    "pb_flag", "event_code", "subevent_code", "status", "att_opcode",
    "att_opcode_name", "payload",
]

TIMING_FIELDS = [
    "sample", "server_hardware_name", "handle_decimal", "handle_hex",
    "usb_connection_frame", "usb_mtu_request_frame",
    "usb_connection_time", "usb_mtu_request_time", "usb_delta_ms", "usb_ordering",
    "hci_connection_line", "hci_mtu_request_line",
    "hci_connection_time", "hci_mtu_request_time", "hci_delta_ms", "hci_ordering",
    "mtu_response_usb", "kernel_unknown_handle",
]


class AnalysisError(Exception):
    pass


def integer(value):
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer (decimal or 0x...)") from exc


def hex_bytes(data):
    return data.hex()


def format_time(value):
    return "" if value is None else "{:.9f}".format(value)


def display_path(path):
    return os.path.relpath(os.path.abspath(path), os.getcwd())


def read_u16(data, offset, endian):
    return struct.unpack_from(endian + "H", data, offset)[0]


def read_u32(data, offset, endian):
    return struct.unpack_from(endian + "I", data, offset)[0]


class PcapngReader:
    """Minimal pcapng reader supporting the packet blocks used by usbmon."""

    def __init__(self, path, warnings):
        self.path = path
        self.warnings = warnings
        self.endian = None
        self.interfaces = []
        self.section = -1
        self.frame = 0

    def _warn(self, message):
        self.warnings.append("pcapng: " + message)

    def _interface(self, index):
        if index >= len(self.interfaces):
            self._warn("packet references missing interface {}".format(index))
            return None
        return self.interfaces[index]

    def _options(self, raw, endian):
        options = defaultdict(list)
        offset = 0
        while offset + 4 <= len(raw):
            code, length = struct.unpack_from(endian + "HH", raw, offset)
            offset += 4
            if code == 0:
                break
            if offset + length > len(raw):
                self._warn("truncated interface option {}".format(code))
                break
            options[code].append(raw[offset:offset + length])
            offset += (length + 3) & ~3
        return options

    def _add_interface(self, body):
        if len(body) < 8:
            self._warn("short interface description block")
            return
        linktype = read_u16(body, 0, self.endian)
        snaplen = read_u32(body, 4, self.endian)
        options = self._options(body[8:], self.endian)
        resolution = 1e-6
        if options.get(9) and options[9][0]:
            value = options[9][0][0]
            resolution = 2.0 ** -(value & 0x7f) if value & 0x80 else 10.0 ** -value
        offset = 0
        if options.get(14) and len(options[14][0]) >= 8:
            offset = struct.unpack_from(self.endian + "q", options[14][0], 0)[0]
        self.interfaces.append({
            "linktype": linktype,
            "snaplen": snaplen,
            "timestamp_resolution": resolution,
            "timestamp_offset": offset,
            "section": self.section,
        })

    def _timestamp(self, interface, high, low):
        ticks = (high << 32) | low
        return interface["timestamp_offset"] + ticks * interface["timestamp_resolution"]

    def packets(self):
        try:
            source = open(self.path, "rb")
        except OSError as exc:
            raise AnalysisError("cannot open pcapng input: {}".format(exc)) from exc
        with source:
            while True:
                header = source.read(8)
                if not header:
                    break
                if len(header) < 8:
                    self._warn("truncated block header at end of file")
                    break
                raw_type = header[:4]
                if raw_type == b"\x0a\x0d\x0d\x0a":
                    bom = source.read(4)
                    if len(bom) < 4:
                        self._warn("truncated section header at end of file")
                        break
                    if bom == b"\x4d\x3c\x2b\x1a":
                        endian = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        endian = ">"
                    else:
                        raise AnalysisError("invalid pcapng byte-order magic")
                    total_length = read_u32(header, 4, endian)
                    block_type = 0x0A0D0D0A
                    body_prefix = bom
                    consumed = 12
                else:
                    if self.endian is None:
                        raise AnalysisError("pcapng does not begin with a section header")
                    endian = self.endian
                    block_type, total_length = struct.unpack_from(endian + "II", header, 0)
                    body_prefix = b""
                    consumed = 8
                minimum = consumed + 4
                if total_length < minimum or total_length % 4:
                    raise AnalysisError("invalid pcapng block length {}".format(total_length))
                remainder = source.read(total_length - consumed)
                if len(remainder) != total_length - consumed:
                    self._warn("truncated block of {} bytes".format(total_length))
                    break
                trailing = read_u32(remainder, len(remainder) - 4, endian)
                if trailing != total_length:
                    self._warn("block length trailer mismatch; block skipped")
                    continue
                body = body_prefix + remainder[:-4]
                if block_type == 0x0A0D0D0A:
                    self.endian = endian
                    self.interfaces = []
                    self.section += 1
                    continue
                if block_type == 1:
                    self._add_interface(body)
                    continue
                packet = None
                if block_type in (2, 3, 6):
                    self.frame += 1
                if block_type == 6 and len(body) >= 20:
                    interface_id, high, low, captured, original = struct.unpack_from(
                        endian + "IIIII", body, 0)
                    interface = self._interface(interface_id)
                    if interface is not None:
                        available = max(0, len(body) - 20)
                        if captured > available:
                            self._warn("enhanced packet block has truncated packet data")
                        packet = (interface, self._timestamp(interface, high, low),
                                  body[20:20 + min(captured, available)], original)
                elif block_type == 2 and len(body) >= 20:
                    interface_id, _drops, high, low, captured, original = struct.unpack_from(
                        endian + "HHIIII", body, 0)
                    interface = self._interface(interface_id)
                    if interface is not None:
                        available = max(0, len(body) - 20)
                        packet = (interface, self._timestamp(interface, high, low),
                                  body[20:20 + min(captured, available)], original)
                elif block_type == 3 and len(body) >= 4:
                    interface = self._interface(0)
                    if interface is not None:
                        original = read_u32(body, 0, endian)
                        captured = min(original, len(body) - 4, interface["snaplen"])
                        packet = (interface, None, body[4:4 + captured], original)
                elif block_type in (2, 3, 6):
                    self._warn("short packet block type {}".format(block_type))
                if packet is not None:
                    interface, timestamp, data, original = packet
                    yield {
                        "frame": self.frame,
                        "time": timestamp,
                        "data": data,
                        "original_length": original,
                        "interface": interface,
                        "endian": endian,
                    }


def decode_usbmon(packet, warnings):
    data = packet["data"]
    linktype = packet["interface"]["linktype"]
    header_length = 48 if linktype == USB_LINUX else 64
    if linktype not in (USB_LINUX, USB_LINUX_MMAPPED):
        return None
    if len(data) < header_length:
        warnings.append("frame {}: short usbmon header".format(packet["frame"]))
        return None
    endian = packet["endian"]
    try:
        urb_id = struct.unpack_from(endian + "Q", data, 0)[0]
        event = chr(data[8]) if 32 <= data[8] < 127 else "0x{:02x}".format(data[8])
        transfer = data[9]
        endpoint = data[10]
        device = data[11]
        bus = read_u16(data, 12, endian)
        status = struct.unpack_from(endian + "i", data, 28)[0]
        length = read_u32(data, 32, endian)
        captured_length = read_u32(data, 36, endian)
    except (IndexError, struct.error) as exc:
        warnings.append("frame {}: malformed usbmon header ({})".format(packet["frame"], exc))
        return None
    available = len(data) - header_length
    if captured_length > available:
        warnings.append("frame {}: usbmon payload truncated from {} to {} bytes".format(
            packet["frame"], captured_length, available))
    payload = data[header_length:header_length + min(captured_length, available)]
    return {
        "frame": packet["frame"], "time": packet["time"], "urb_id": urb_id,
        "event": event, "transfer": transfer, "endpoint_raw": endpoint,
        "endpoint": endpoint & 0x7f, "direction": "in" if endpoint & 0x80 else "out",
        "device": device, "bus": bus, "status": status, "length": length,
        "captured_length": captured_length, "payload": payload,
    }


class ByteStream:
    def __init__(self):
        self.chunks = []
        self.size = 0

    def append(self, data, metadata):
        if data:
            self.chunks.append([bytearray(data), metadata])
            self.size += len(data)

    def peek(self, count):
        output = bytearray()
        for data, _metadata in self.chunks:
            output.extend(data[:count - len(output)])
            if len(output) == count:
                break
        return bytes(output)

    def consume(self, count):
        output = bytearray()
        metadata = []
        while count and self.chunks:
            data, item_metadata = self.chunks[0]
            take = min(count, len(data))
            output.extend(data[:take])
            if not metadata or metadata[-1] is not item_metadata:
                metadata.append(item_metadata)
            del data[:take]
            self.size -= take
            count -= take
            if not data:
                self.chunks.pop(0)
        return bytes(output), metadata


def row_usb_fields(metadata):
    first = metadata[0]
    return {
        "frame": first["frame"], "time": format_time(first["time"]),
        "direction": first["direction"], "endpoint": "0x{:02x}".format(first["endpoint_raw"]),
        "bus": first["bus"], "device": first["device"], "transfer_type": first["transfer"],
        "urb_id": "0x{:016x}".format(first["urb_id"]), "urb_event": first["event"],
        "usb_status": first["status"], "usb_length": first["length"],
        "usb_captured_length": first["captured_length"],
        "source_frames": ",".join(str(item["frame"]) for item in metadata),
    }


class Analyzer:
    def __init__(self, bus, device):
        self.bus = bus
        self.device = device
        self.warnings = []
        self.rows = []
        self.connections = []
        self.att = []
        self.usb_packets = 0
        self.selected_usb_packets = 0
        self.malformed_packets = 0
        self.event_streams = defaultdict(ByteStream)
        self.acl_streams = defaultdict(ByteStream)
        self.l2cap = {}

    def process(self, packet):
        usb = decode_usbmon(packet, self.warnings)
        if usb is None:
            return
        self.usb_packets += 1
        if usb["bus"] != self.bus or usb["device"] != self.device:
            return
        self.selected_usb_packets += 1
        if not usb["payload"]:
            return
        if usb["transfer"] == 1 and usb["direction"] == "in" and usb["event"] == "C":
            key = usb["endpoint_raw"]
            stream = self.event_streams[key]
            stream.append(usb["payload"], usb)
            self._drain_events(stream)
        elif usb["transfer"] == 3:
            wanted = ((usb["direction"] == "in" and usb["event"] == "C") or
                      (usb["direction"] == "out" and usb["event"] == "S"))
            if wanted:
                key = (usb["direction"], usb["endpoint_raw"])
                stream = self.acl_streams[key]
                stream.append(usb["payload"], usb)
                self._drain_acl(stream, usb["direction"])

    def _drain_events(self, stream):
        while stream.size >= 2:
            header = stream.peek(2)
            total = 2 + header[1]
            if stream.size < total:
                return
            event, metadata = stream.consume(total)
            if event[0] != 0x3E or len(event) < 6:
                continue
            subevent = event[2]
            if subevent not in (0x01, 0x0A, 0x29):
                continue
            status = event[3]
            handle = int.from_bytes(event[4:6], "little") & 0x0fff
            event_name = {
                0x01: "LE Connection Complete",
                0x0A: "LE Enhanced Connection Complete",
                0x29: "LE Enhanced Connection Complete v2",
            }[subevent]
            base = row_usb_fields(metadata)
            row = dict.fromkeys(TSV_FIELDS, "")
            row.update(base)
            row.update({
                "record_type": "connection_complete", "handle": "0x{:04x}".format(handle),
                "event_code": "0x3e", "subevent_code": "0x{:02x}".format(subevent),
                "status": status, "att_opcode_name": event_name,
                "payload": hex_bytes(event[2:]),
            })
            self.rows.append(row)
            self.connections.append({
                "frame": base["frame"], "time": metadata[0]["time"], "handle": handle,
                "status": status, "subevent": subevent, "name": event_name,
                "endpoint": base["endpoint"], "source_frames": base["source_frames"],
            })

    def _drain_acl(self, stream, direction):
        while stream.size >= 4:
            header = stream.peek(4)
            data_length = int.from_bytes(header[2:4], "little")
            total = 4 + data_length
            if stream.size < total:
                return
            packet, metadata = stream.consume(total)
            handle_flags = int.from_bytes(packet[:2], "little")
            handle = handle_flags & 0x0fff
            pb_flag = (handle_flags >> 12) & 0x03
            self._process_acl_data(direction, handle, pb_flag, packet[4:], metadata)

    def _process_acl_data(self, direction, handle, pb_flag, data, metadata):
        key = (direction, handle)
        if pb_flag in (0, 2, 3):
            if key in self.l2cap:
                self.warnings.append("frame {}: new ACL start replaced incomplete L2CAP PDU for handle 0x{:04x}".format(
                    metadata[0]["frame"], handle))
                self.malformed_packets += 1
            if len(data) < 4:
                self.warnings.append("frame {}: short L2CAP start".format(metadata[0]["frame"]))
                self.malformed_packets += 1
                return
            length = int.from_bytes(data[:2], "little")
            cid = int.from_bytes(data[2:4], "little")
            state = {"length": length, "cid": cid, "data": bytearray(data[4:]),
                     "metadata": list(metadata), "pb_flag": pb_flag}
            self.l2cap[key] = state
        elif pb_flag == 1:
            state = self.l2cap.get(key)
            if state is None:
                self.warnings.append("frame {}: ACL continuation without start for handle 0x{:04x}".format(
                    metadata[0]["frame"], handle))
                self.malformed_packets += 1
                return
            state["data"].extend(data)
            state["metadata"].extend(item for item in metadata if item not in state["metadata"])
        else:
            return
        state = self.l2cap.get(key)
        if state is None or len(state["data"]) < state["length"]:
            return
        del self.l2cap[key]
        if len(state["data"]) > state["length"]:
            self.warnings.append("frame {}: L2CAP PDU has {} trailing byte(s)".format(
                state["metadata"][0]["frame"], len(state["data"]) - state["length"]))
        payload = bytes(state["data"][:state["length"]])
        if state["cid"] != ATT_CID or not payload:
            return
        opcode = payload[0]
        name = ATT_OPCODES.get(opcode, "Unknown ATT opcode")
        base = row_usb_fields(state["metadata"])
        row = dict.fromkeys(TSV_FIELDS, "")
        row.update(base)
        row.update({
            "record_type": "att", "direction": direction,
            "handle": "0x{:04x}".format(handle), "pb_flag": state["pb_flag"],
            "att_opcode": "0x{:02x}".format(opcode), "att_opcode_name": name,
            "payload": hex_bytes(payload[1:]),
        })
        self.rows.append(row)
        self.att.append({
            "frame": base["frame"], "time": state["metadata"][0]["time"],
            "direction": direction, "handle": handle, "opcode": opcode, "name": name,
            "payload": hex_bytes(payload[1:]), "endpoint": base["endpoint"],
            "source_frames": base["source_frames"],
        })

    def finish(self):
        for stream in list(self.event_streams.values()) + list(self.acl_streams.values()):
            if stream.size:
                self.warnings.append("capture ended with {} unassembled HCI byte(s)".format(stream.size))
        for (direction, handle), state in self.l2cap.items():
            self.warnings.append("capture ended with incomplete {} L2CAP PDU for handle 0x{:04x} ({}/{})".format(
                direction, handle, len(state["data"]), state["length"]))


def extract_handle(text):
    match = re.search(r"\bhandle\s*(?::|=)?\s*(0x[0-9a-f]+|\d+)", text, re.IGNORECASE)
    return int(match.group(1), 0) if match else None


def inspect_btmon(path, warnings):
    result = {"path": path, "connection_complete": [], "att": []}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as source:
            lines = list(source)
    except OSError as exc:
        warnings.append("btmon: cannot read {}: {}".format(path, exc))
        result["error"] = str(exc)
        return result
    header_re = re.compile(
        r"(?:#\d+|\{0x[0-9a-f]+\})\s+(?:\[hci\d+\]\s+)?"
        r"([0-9]+(?:\.[0-9]+)?)\s*$", re.IGNORECASE)
    current_time = None
    current_acl_handle = None
    connection = None
    for index, line in enumerate(lines):
        stripped = line.rstrip("\n")
        header = header_re.search(stripped)
        if header:
            current_time = float(header.group(1))
            incoming_acl = ("ACL Data RX:" in stripped or
                            re.match(r"^>\s+(?:LE-)?ACL:", stripped) is not None)
            current_acl_handle = extract_handle(stripped) if incoming_acl else None
            connection = None
            continue
        if current_time is None:
            continue
        if re.search(r"LE (?:Enhanced )?Connection Complete", stripped, re.IGNORECASE):
            connection = {"line": index + 1, "time": current_time, "status": None,
                          "handle": None, "text": stripped.strip()}
            continue
        if connection is not None and "Status:" in stripped:
            connection["status"] = "Success" in stripped or "0x00" in stripped
            continue
        if connection is not None:
            handle = extract_handle(stripped)
            if handle is not None:
                connection["handle"] = handle
                if connection["status"] is not False:
                    result["connection_complete"].append(connection)
                connection = None
                continue
        match = re.search(r"\bATT:\s+(.+?)\s+\((0x[0-9a-f]{2})\)", stripped, re.IGNORECASE)
        if match and current_acl_handle is not None:
            result["att"].append({
                "line": index + 1, "time": current_time, "handle": current_acl_handle,
                "opcode": int(match.group(2), 16), "name": match.group(1).strip(),
            })
            current_acl_handle = None
    result["counts"] = {
        "connection_complete": len(result["connection_complete"]), "att": len(result["att"]),
    }
    return result


def inspect_kernel(path, warnings):
    result = {"path": path, "unknown_connection_handle": []}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as source:
            for line_number, line in enumerate(source, 1):
                if re.search(r"unknown\s+(?:connection\s+)?handle", line, re.IGNORECASE):
                    result["unknown_connection_handle"].append({
                        "line": line_number, "handle": extract_handle(line), "text": line.rstrip("\n"),
                    })
    except OSError as exc:
        warnings.append("kernel log: cannot read {}: {}".format(path, exc))
        result["error"] = str(exc)
    result["count"] = len(result["unknown_connection_handle"])
    return result


def closest_pair(connections, request):
    candidates = [connection for connection in connections
                  if abs(request["time"] - connection["time"]) <= 5.0]
    if not candidates:
        return None
    return min(candidates, key=lambda connection: abs(request["time"] - connection["time"]))


def correlate(analyzer, btmon, kernel):
    successful = defaultdict(list)
    for connection in analyzer.connections:
        if connection["status"] == 0:
            successful[connection["handle"]].append(connection)
    handles = sorted(set(successful) | {item["handle"] for item in analyzer.att})
    output = []
    for handle in handles:
        connections = successful.get(handle, [])
        incoming = [item for item in analyzer.att if item["handle"] == handle and item["direction"] == "in"]
        outgoing = [item for item in analyzer.att if item["handle"] == handle and item["direction"] == "out"]
        before = []
        for item in incoming:
            prior = [event for event in connections if event["frame"] < item["frame"]]
            if not prior:
                marked = dict(item)
                marked["reason"] = "no earlier successful connection complete"
                before.append(marked)
        usb_mtu_requests = [item for item in analyzer.att
                            if item["handle"] == handle and item["direction"] == "in" and item["opcode"] == 0x02]
        bt_connections = [] if not btmon else [item for item in btmon["connection_complete"]
                                                if item.get("handle") == handle]
        bt_mtu_requests = [] if not btmon else [item for item in btmon["att"]
                                                 if item.get("handle") == handle and item["opcode"] == 0x02]
        output.append({
            "handle": handle, "handle_hex": "0x{:04x}".format(handle),
            "connection_complete": connections, "incoming_att_count": len(incoming),
            "outgoing_att_count": len(outgoing), "att_before_connection_complete": before,
            "mtu_requests": usb_mtu_requests,
            "mtu_responses": [item for item in analyzer.att if item["handle"] == handle and item["opcode"] == 0x03],
            "btmon_connection_complete": bt_connections,
            "btmon_mtu_requests": bt_mtu_requests,
        })
    return output


def json_safe(value):
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    return value


def timing_rows(correlations, kernel):
    unknown_handles = set()
    if kernel:
        unknown_handles = {entry["handle"] for entry in kernel["unknown_connection_handle"]
                           if entry.get("handle") is not None}
    rows = []
    for item in correlations:
        handle = item["handle"]
        for occurrence, request in enumerate(item["mtu_requests"]):
            usb_connection = closest_pair(item["connection_complete"], request)
            # usbmon and btmon have unrelated time bases. The handles and
            # per-handle occurrence order tie the corresponding observations.
            bt_request = (item["btmon_mtu_requests"][occurrence]
                          if occurrence < len(item["btmon_mtu_requests"]) else None)
            bt_connection = closest_pair(item["btmon_connection_complete"], bt_request) if bt_request else None
            usb_delta = None if usb_connection is None else (request["time"] - usb_connection["time"]) * 1000.0
            bt_delta = None if bt_connection is None else (bt_request["time"] - bt_connection["time"]) * 1000.0
            response_seen = any(response["time"] >= request["time"] and
                                response["time"] - request["time"] <= 5.0
                                for response in item["mtu_responses"])
            rows.append({
                "handle": handle, "request": request, "usb_connection": usb_connection,
                "bt_request": bt_request, "bt_connection": bt_connection,
                "usb_delta": usb_delta, "bt_delta": bt_delta,
                "response_seen": response_seen, "kernel_drop": handle in unknown_handles,
            })
    return rows


def worst_negative_delta(rows, key):
    values = [row[key] for row in rows if row[key] is not None and row[key] < 0]
    return min(values) if values else None


def minimum_delta(rows, key):
    values = [row[key] for row in rows if row[key] is not None]
    return min(values) if values else None


def write_outputs(args, analyzer, pcap_reader, btmon, kernel):
    correlations = correlate(analyzer, btmon, kernel)
    timings = timing_rows(correlations, kernel)
    summary = {
        "schema_version": 2,
        "input": {
            "pcapng": args.pcapng, "btmon_log": args.btmon_log,
            "kernel_log": args.kernel_log, "usb_bus": args.bus, "usb_device": args.device,
            "server_hardware_name": args.server_name,
        },
        "capture": {
            "pcapng_sections": pcap_reader.section + 1,
            "packet_frames": pcap_reader.frame, "usbmon_packets": analyzer.usb_packets,
            "selected_usb_packets": analyzer.selected_usb_packets,
            "malformed_packets": analyzer.malformed_packets,
        },
        "counts": {
            "connection_complete": len(analyzer.connections),
            "incoming_att": sum(item["direction"] == "in" for item in analyzer.att),
            "outgoing_att": sum(item["direction"] == "out" for item in analyzer.att),
            "att_before_connection_complete": sum(
                len(item["att_before_connection_complete"]) for item in correlations),
            "mtu_requests": sum(item["opcode"] == 0x02 for item in analyzer.att),
            "mtu_responses": sum(item["opcode"] == 0x03 for item in analyzer.att),
            "kernel_unknown_connection_handle": kernel.get("count", 0) if kernel else 0,
            "mtu_requests_dropped_unknown_handle": sum(
                row["kernel_drop"] and not row["response_seen"] for row in timings),
        },
        "connection_complete": analyzer.connections,
        "att": analyzer.att,
        "correlation_by_handle": correlations,
        "mtu_timing": timings,
        "timing_summary": {
            # This measures the ordering pair exercised by the default client:
            # LE Connection Complete (event) before ATT Exchange MTU Request
            # (control). USB completion timestamps show host arrival order;
            # HCI monitor timestamps show the driver's later reordered view.
            # They are intentionally not cross-compared.
            "event": "LE Connection Complete",
            "control": "ATT Exchange MTU Request",
            "expected_hci_order": "event before control",
            "minimum_usb_delta_ms": minimum_delta(timings, "usb_delta"),
            "minimum_hci_delta_ms": minimum_delta(timings, "bt_delta"),
            "worst_usb_negative_delta_ms": worst_negative_delta(timings, "usb_delta"),
            "worst_hci_negative_delta_ms": worst_negative_delta(timings, "bt_delta"),
            "mtu_request_observed": bool(timings),
            "mtu_request_dropped_unknown_handle": (
                any(row["kernel_drop"] and not row["response_seen"] for row in timings)
                if timings else None),
        },
        "btmon": btmon,
        "kernel": kernel,
        "warnings": analyzer.warnings,
    }
    try:
        with open(args.tsv_output, "w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=TSV_FIELDS, dialect="excel-tab", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(analyzer.rows)
        with open(args.json_output, "w", encoding="utf-8") as output:
            json.dump(json_safe(summary), output, indent=2, sort_keys=True)
            output.write("\n")
        if args.timing_output:
            with open(args.timing_output, "w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=TIMING_FIELDS, dialect="excel-tab")
                writer.writeheader()
                for sample, row in enumerate(timings, 1):
                    def value(event, name):
                        return "" if event is None else event.get(name, "")
                    def decimal(number):
                        return "" if number is None else "{:.3f}".format(number)
                    writer.writerow({
                        "sample": sample, "handle_decimal": row["handle"],
                        "server_hardware_name": args.server_name,
                        "handle_hex": "0x{:04x}".format(row["handle"]),
                        "usb_connection_frame": value(row["usb_connection"], "frame"),
                        "usb_mtu_request_frame": value(row["request"], "frame"),
                        "usb_connection_time": value(row["usb_connection"], "time"),
                        "usb_mtu_request_time": value(row["request"], "time"),
                        "usb_delta_ms": decimal(row["usb_delta"]),
                        "usb_ordering": "missing" if row["usb_delta"] is None else ("good" if row["usb_delta"] >= 0 else "bad"),
                        "hci_connection_line": value(row["bt_connection"], "line"),
                        "hci_mtu_request_line": value(row["bt_request"], "line"),
                        "hci_connection_time": value(row["bt_connection"], "time"),
                        "hci_mtu_request_time": value(row["bt_request"], "time"),
                        "hci_delta_ms": decimal(row["bt_delta"]),
                        "hci_ordering": "missing" if row["bt_delta"] is None else ("good" if row["bt_delta"] >= 0 else "bad"),
                        "mtu_response_usb": "yes" if row["response_seen"] else "no",
                        "kernel_unknown_handle": "yes" if row["kernel_drop"] else "no",
                    })
    except OSError as exc:
        raise AnalysisError("cannot write output: {}".format(exc)) from exc
    return summary


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Analyze Bluetooth HCI/ATT traffic for one Linux usbmon device in pcapng format.")
    parser.add_argument("pcapng", nargs="?", help="server usbmon pcapng capture")
    parser.add_argument("--pcapng", dest="pcapng_option", help="server usbmon pcapng capture")
    parser.add_argument("--btmon-log", "--server-btmon", help="optional server btmon text log")
    parser.add_argument("--kernel-log", help="optional kernel text log")
    parser.add_argument("--bus", "--usb-bus", required=True, type=integer, help="server USB bus number")
    parser.add_argument("--device", "--usb-device", required=True, type=integer,
                        help="server USB device number")
    parser.add_argument("--server-name", default="unknown",
                        help="server adapter chipset or device name")
    parser.add_argument("--tsv-output", "--output-tsv", required=True, help="event TSV output path")
    parser.add_argument("--json-output", "--output-json", required=True, help="summary JSON output path")
    parser.add_argument("--timing-output", help="optional MTU timing TSV output path")
    args = parser.parse_args(argv)
    if args.pcapng and args.pcapng_option:
        parser.error("provide the pcapng input either positionally or with --pcapng, not both")
    args.pcapng = args.pcapng or args.pcapng_option
    if not args.pcapng:
        parser.error("a pcapng input is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    analyzer = Analyzer(args.bus, args.device)
    reader = PcapngReader(args.pcapng, analyzer.warnings)
    try:
        for packet in reader.packets():
            analyzer.process(packet)
        analyzer.finish()
        btmon = inspect_btmon(args.btmon_log, analyzer.warnings) if args.btmon_log else None
        kernel = inspect_kernel(args.kernel_log, analyzer.warnings) if args.kernel_log else None
        summary = write_outputs(args, analyzer, reader, btmon, kernel)
    except AnalysisError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    counts = summary["counts"]
    print("USB {}/{}: {} selected packet(s), {} connection complete, {} incoming ATT, {} outgoing ATT".format(
        args.bus, args.device, summary["capture"]["selected_usb_packets"],
        counts["connection_complete"], counts["incoming_att"], counts["outgoing_att"]))
    timing = summary["timing_summary"]
    print("ATT before LE Connection Complete: {}; MTU request/response: {}/{}; "
          "kernel unknown handle: {}; MTU dropped for unknown handle: {}".format(
        counts["att_before_connection_complete"], counts["mtu_requests"], counts["mtu_responses"],
        counts["kernel_unknown_connection_handle"],
        (counts["mtu_requests_dropped_unknown_handle"]
         if timing["mtu_request_observed"] else "not observed")))
    print("Worst negative MTU delta: USB={} ms; HCI={} ms".format(
        "none" if timing["worst_usb_negative_delta_ms"] is None else "{:.3f}".format(timing["worst_usb_negative_delta_ms"]),
        "none" if timing["worst_hci_negative_delta_ms"] is None else "{:.3f}".format(timing["worst_hci_negative_delta_ms"])))
    print("Wrote {} and {} ({} warning(s))".format(
        display_path(args.tsv_output), display_path(args.json_output),
        len(summary["warnings"])))
    if not summary["capture"]["usbmon_packets"]:
        print("error: capture contains no supported Linux usbmon packets", file=sys.stderr)
        return 3
    if not summary["capture"]["selected_usb_packets"]:
        print("error: capture contains no packets for USB {}/{}".format(
            args.bus, args.device), file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
