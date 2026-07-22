#!/usr/bin/env python3
"""Scoped mitmproxy addon for Apple network-location responses.

Only ``gs-loc.apple.com`` and ``gs-loc-cn.apple.com`` ``/clls/wloc``
responses are considered. The protobuf framing follows the public WLOC
research implemented by https://github.com/Yu9191/wloc, but this module is a
standalone Python implementation for the PrivDNS Gateway sidecar.
"""
from __future__ import annotations

import gzip
import json
import logging
import math
import os
import re
from collections import namedtuple

try:
    from mitmproxy import ctx as MITM_CTX
except ImportError:  # Unit tests do not require mitmproxy to be installed.
    MITM_CTX = None

CONFIG_PATH = "/var/lib/pdg-wloc/wloc.json"
TARGET_HOSTS = {"gs-loc.apple.com", "gs-loc-cn.apple.com"}
TARGET_PATH = "/clls/wloc"
MAC_RE = re.compile(r"^[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}$")
LOG = logging.getLogger("pdg-wloc")

Field = namedtuple("Field", "field_no wire_type value raw")


class WlocFormatError(ValueError):
    pass


def _log(level, message, *args):
    rendered = message % args if args else message
    if MITM_CTX is not None:
        mitm_log = getattr(MITM_CTX, "log", None)
        method = getattr(mitm_log, level, None)
        if method is None and level == "warning":
            method = getattr(mitm_log, "warn", None)
        if callable(method):
            method(rendered)
            return
        LOG.log(getattr(logging, level.upper(), logging.INFO), rendered)
    else:
        getattr(LOG, level)(rendered)


def _new_stats():
    return {"wifi": 0, "cell": 0, "locations": 0, "skipped": 0}


def read_varint(data, offset):
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise WlocFormatError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise WlocFormatError("varint too long")


def encode_varint(value):
    value = int(value)
    if value < 0:
        value = (1 << 64) + value
    if value < 0 or value >= 1 << 64:
        raise WlocFormatError("varint outside int64 range")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_int64(value):
    value = int(value)
    return value - (1 << 64) if value >= 1 << 63 else value


def parse_fields(data):
    data = bytes(data)
    fields = []
    offset = 0
    while offset < len(data):
        start = offset
        key, offset = read_varint(data, offset)
        field_no, wire_type = key >> 3, key & 7
        if field_no == 0:
            raise WlocFormatError("protobuf field zero")
        if wire_type == 0:
            value, offset = read_varint(data, offset)
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise WlocFormatError("truncated fixed64")
            value = data[offset:offset + 8]
            offset += 8
        elif wire_type == 2:
            size, offset = read_varint(data, offset)
            if size < 0 or offset + size > len(data):
                raise WlocFormatError("truncated bytes field")
            value = data[offset:offset + size]
            offset += size
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise WlocFormatError("truncated fixed32")
            value = data[offset:offset + 4]
            offset += 4
        else:
            raise WlocFormatError(f"unsupported protobuf wire type {wire_type}")
        fields.append(Field(field_no, wire_type, value, data[start:offset]))
    return fields


def encode_field(field_no, wire_type, value):
    key = encode_varint((int(field_no) << 3) | int(wire_type))
    if wire_type == 0:
        return key + encode_varint(value)
    if wire_type in (1, 5):
        raw = bytes(value)
        expected = 8 if wire_type == 1 else 4
        if len(raw) != expected:
            raise WlocFormatError(f"wire type {wire_type} requires {expected} bytes")
        return key + raw
    if wire_type == 2:
        raw = bytes(value)
        return key + encode_varint(len(raw)) + raw
    raise WlocFormatError(f"cannot encode protobuf wire type {wire_type}")


def _patch_location(data, latitude, longitude, stats):
    fields = parse_fields(data)
    has_lat = any(f.field_no == 1 and f.wire_type == 0 for f in fields)
    has_lon = any(f.field_no == 2 and f.wire_type == 0 for f in fields)
    if not has_lat or not has_lon:
        return bytes(data), False
    out = []
    for field in fields:
        if field.field_no == 1 and field.wire_type == 0:
            out.append(encode_field(1, 0, round(latitude * 100_000_000)))
        elif field.field_no == 2 and field.wire_type == 0:
            out.append(encode_field(2, 0, round(longitude * 100_000_000)))
        else:
            # Preserve Apple's reported accuracy and every unknown field. A
            # very precise value paired with a large coordinate jump can make
            # iOS discard the network-location response as implausible.
            out.append(field.raw)
    stats["locations"] += 1
    return b"".join(out), True


def _patch_wifi(data, latitude, longitude, stats):
    fields = parse_fields(data)
    is_wifi = False
    for field in fields:
        if field.field_no == 1 and field.wire_type == 2:
            try:
                is_wifi = bool(MAC_RE.fullmatch(field.value.decode("ascii")))
            except (UnicodeDecodeError, ValueError):
                pass
    if not is_wifi:
        return bytes(data), False
    out = []
    changed = False
    for field in fields:
        if field.field_no == 2 and field.wire_type == 2:
            try:
                patched, did_patch = _patch_location(
                    field.value, latitude, longitude, stats)
                out.append(encode_field(field.field_no, field.wire_type, patched))
                changed = changed or did_patch
            except WlocFormatError:
                stats["skipped"] += 1
                out.append(field.raw)
        else:
            out.append(field.raw)
    if changed:
        stats["wifi"] += 1
    return b"".join(out), changed


def _patch_cell(data, latitude, longitude, stats):
    fields = parse_fields(data)
    out = []
    changed = False
    for field in fields:
        if field.field_no == 5 and field.wire_type == 2:
            try:
                patched, did_patch = _patch_location(
                    field.value, latitude, longitude, stats)
                out.append(encode_field(field.field_no, field.wire_type, patched))
                changed = changed or did_patch
            except WlocFormatError:
                stats["skipped"] += 1
                out.append(field.raw)
        else:
            out.append(field.raw)
    if changed:
        stats["cell"] += 1
    return b"".join(out), changed


def _patch_payload(data, latitude, longitude, stats):
    fields = parse_fields(data)
    out = []
    before = stats["locations"]
    for field in fields:
        if field.field_no == 2 and field.wire_type == 2:
            patched, _ = _patch_wifi(field.value, latitude, longitude, stats)
            out.append(encode_field(field.field_no, field.wire_type, patched))
        elif field.field_no in (22, 24) and field.wire_type == 2:
            patched, _ = _patch_cell(field.value, latitude, longitude, stats)
            out.append(encode_field(field.field_no, field.wire_type, patched))
        else:
            out.append(field.raw)
    if stats["locations"] == before:
        raise WlocFormatError("no patchable WLOC locations")
    return b"".join(out)


def _patch_frame(data, base, latitude, longitude):
    if base < 0 or len(data) < base + 10:
        raise WlocFormatError("WLOC frame too short")
    size = int.from_bytes(data[base + 8:base + 10], "big")
    if size <= 0 or base + 10 + size > len(data):
        raise WlocFormatError("invalid WLOC frame length")
    stats = _new_stats()
    payload = data[base + 10:base + 10 + size]
    patched = _patch_payload(payload, latitude, longitude, stats)
    if len(patched) > 0xFFFF:
        raise WlocFormatError("patched WLOC payload too large")
    body = (data[:base + 8] + len(patched).to_bytes(2, "big") + patched
            + data[base + 10 + size:])
    return body, stats


def _patch_plain_body(data, latitude, longitude):
    if len(data) < 10:
        raise WlocFormatError("WLOC response too short")
    preferred = list(range(0, 18, 2))
    limit = min(96, len(data) - 10)
    preferred.extend(i for i in range(limit + 1) if i not in preferred)
    for base in preferred:
        try:
            return _patch_frame(data, base, latitude, longitude)
        except WlocFormatError:
            pass
    for base in range(min(256, len(data)) + 1):
        stats = _new_stats()
        try:
            patched = _patch_payload(data[base:], latitude, longitude, stats)
            return data[:base] + patched, stats
        except WlocFormatError:
            pass
    raise WlocFormatError("no patchable WLOC payload found")


def patch_wloc_body(data, latitude, longitude):
    latitude = float(latitude)
    longitude = float(longitude)
    if not math.isfinite(latitude) or not -90 <= latitude <= 90:
        raise ValueError("latitude outside -90..90")
    if not math.isfinite(longitude) or not -180 <= longitude <= 180:
        raise ValueError("longitude outside -180..180")
    raw = bytes(data)
    if raw.startswith(b"\x1f\x8b"):
        patched, stats = _patch_plain_body(gzip.decompress(raw), latitude, longitude)
        return gzip.compress(patched, mtime=0), stats
    return _patch_plain_body(raw, latitude, longitude)


def _load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
        if not config.get("enabled"):
            return None
        latitude = float(config["latitude"])
        longitude = float(config["longitude"])
        if not math.isfinite(latitude) or not -90 <= latitude <= 90:
            return None
        if not math.isfinite(longitude) or not -180 <= longitude <= 180:
            return None
        return latitude, longitude
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return None


class WlocAddon:
    def __init__(self, config_path=CONFIG_PATH):
        self.config_path = config_path

    def responseheaders(self, flow):
        host = str(getattr(flow.request, "pretty_host", "")).lower()
        path = str(getattr(flow.request, "path", "")).split("?", 1)[0]
        if host not in TARGET_HOSTS or path != TARGET_PATH or flow.response is None:
            return
        headers = flow.response.headers
        _log("info", "WLOC response headers host=%s client_http=%s server_http=%s "
             "length=%s encoding=%s transfer=%s",
             host, getattr(flow.request, "http_version", "?"),
             getattr(flow.response, "http_version", "?"),
             headers.get("content-length", "-"),
             headers.get("content-encoding", "-"),
             headers.get("transfer-encoding", "-"))

    def response(self, flow):
        host = str(getattr(flow.request, "pretty_host", "")).lower()
        path = str(getattr(flow.request, "path", "")).split("?", 1)[0]
        if host not in TARGET_HOSTS or path != TARGET_PATH or flow.response is None:
            return
        config = _load_config(self.config_path)
        if config is None:
            return
        try:
            original = flow.response.content
            if not original:
                _log("warning", "WLOC response passthrough: empty response body")
                return
            patched, stats = patch_wloc_body(original, *config)
            flow.response.content = patched
            for key in list(flow.response.headers.keys()):
                if str(key).lower() == "content-length":
                    flow.response.headers.pop(key, None)
            _log("info", "WLOC patched host=%s bytes=%s locations=%s wifi=%s cell=%s",
                 host, len(original), stats["locations"], stats["wifi"],
                 stats["cell"])
        except Exception as exc:  # mitm failure must not break Apple passthrough
            _log("warning", "WLOC response passthrough host=%s: %s", host, exc)


addons = [WlocAddon()]
