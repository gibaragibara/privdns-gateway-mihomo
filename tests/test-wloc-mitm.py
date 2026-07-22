#!/usr/bin/env python3
"""Unit tests for the scoped Apple WLOC mitmproxy addon."""
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "deploy/wloc/wloc_mitm.py"

spec = importlib.util.spec_from_file_location("wloc_mitm", ADDON)
wloc = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(wloc)


class LegacyMitmLog:
    def __init__(self):
        self.warnings = []

    def warn(self, message):
        self.warnings.append(message)


legacy_log = LegacyMitmLog()
original_ctx = wloc.MITM_CTX
wloc.MITM_CTX = type("Context", (), {"log": legacy_log})()
wloc._log("warning", "invalid payload: %s", "passthrough")
assert legacy_log.warnings == ["invalid payload: passthrough"]
wloc.MITM_CTX = object()
wloc._log("info", "standalone import")
wloc.MITM_CTX = original_ctx


def location(lat, lon, accuracy):
    return b"".join((
        wloc.encode_field(1, 0, round(lat * 100_000_000)),
        wloc.encode_field(2, 0, round(lon * 100_000_000)),
        wloc.encode_field(3, 0, accuracy),
    ))


def fixture_body():
    wifi = b"".join((
        wloc.encode_field(1, 2, b"aa:bb:cc:dd:ee:ff"),
        wloc.encode_field(2, 2, location(1.25, 2.5, 99)),
    ))
    cell = wloc.encode_field(5, 2, location(3.75, 4.5, 88))
    payload = b"".join((
        wloc.encode_field(2, 2, wifi),
        wloc.encode_field(22, 2, cell),
    ))
    return b"PDGWLOC!" + len(payload).to_bytes(2, "big") + payload


def extract_locations(body):
    frame_len = int.from_bytes(body[8:10], "big")
    payload = body[10:10 + frame_len]
    found = []
    for outer in wloc.parse_fields(payload):
        if outer.field_no == 2:
            for wifi in wloc.parse_fields(outer.value):
                if wifi.field_no == 2:
                    found.append(wifi.value)
        elif outer.field_no in (22, 24):
            for cell in wloc.parse_fields(outer.value):
                if cell.field_no == 5:
                    found.append(cell.value)
    values = []
    for raw in found:
        fields = {f.field_no: f.value for f in wloc.parse_fields(raw)}
        values.append((wloc.decode_int64(fields[1]) / 100_000_000,
                       wloc.decode_int64(fields[2]) / 100_000_000,
                       fields[3]))
    return values


body = fixture_body()
patched, stats = wloc.patch_wloc_body(body, latitude=-33.8688, longitude=151.2093)
assert extract_locations(patched) == [(-33.8688, 151.2093, 99), (-33.8688, 151.2093, 88)]
assert stats == {"wifi": 1, "cell": 1, "locations": 2, "skipped": 0}, stats


class Request:
    pretty_host = "gs-loc.apple.com"
    path = "/clls/wloc"


class Response:
    def __init__(self, content):
        self.content = content
        self.headers = {"content-length": str(len(content))}


class Flow:
    def __init__(self, content):
        self.request = Request()
        self.response = Response(content)


with tempfile.TemporaryDirectory() as td:
    config = Path(td) / "wloc.json"
    config.write_text(json.dumps({
        "enabled": True,
        "latitude": 35.681236,
        "longitude": 139.767125,
        "accuracy": 30,
    }), encoding="utf-8")
    addon = wloc.WlocAddon(str(config))
    flow = Flow(body)
    addon.response(flow)
    assert extract_locations(flow.response.content) == [
        (35.681236, 139.767125, 99),
        (35.681236, 139.767125, 88),
    ]
    assert "content-length" not in flow.response.headers

    config.write_text(json.dumps({"enabled": False}), encoding="utf-8")
    passthrough = Flow(body)
    addon.response(passthrough)
    assert passthrough.response.content == body

    other = Flow(body)
    other.request.pretty_host = "example.com"
    config.write_text(json.dumps({
        "enabled": True, "latitude": 1, "longitude": 2, "accuracy": 25,
    }), encoding="utf-8")
    addon.response(other)
    assert other.response.content == body

    class BrokenResponse:
        headers = {}

        @property
        def content(self):
            raise ValueError("invalid content-encoding")

    broken = Flow(body)
    broken.response = BrokenResponse()
    addon.response(broken)  # malformed upstream encoding must remain a passthrough

print("wloc-mitm regression OK")
