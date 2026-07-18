#!/usr/bin/env python3
"""Regression tests for scoped declarative MITM ad blocking."""
import importlib.util
import gzip
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "deploy/mitm/adblock_mitm.py"

spec = importlib.util.spec_from_file_location("adblock_mitm", ADDON)
adblock = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(adblock)


class Request:
    def __init__(self, host="api.example.com", path="/ad"):
        self.pretty_host = host
        self.pretty_url = f"https://{host}{path}"


class Response:
    def __init__(self, status=200, body=b"", headers=None):
        self.status_code = status
        self.content = body
        self.headers = dict(headers or {})


class EncodedResponse(Response):
    def __init__(self, body):
        super().__init__(200, gzip.compress(body), {
            "content-encoding": "gzip", "content-length": "999",
        })

    def get_content(self, strict=False):
        return gzip.decompress(self.content)

    def set_content(self, body):
        self.content = gzip.compress(body)
        self.headers["content-length"] = str(len(self.content))


class Flow:
    def __init__(self, host="api.example.com", path="/ad", response=None):
        self.request = Request(host, path)
        self.response = response


def response_factory(status, body, headers):
    return Response(status, body, headers)


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    state = root / "adblock.json"
    rules = root / "rules.json"
    state.write_text(json.dumps({"enabled": True}), encoding="utf-8")
    rules.write_text(json.dumps({
        "hosts": ["api.example.com"],
        "rules": [
            {"pattern": r"^https://api\.example\.com/ad", "action": "reject-dict",
             "arguments": {}, "source": "test"},
            {"pattern": r"^https://api\.example\.com/config", "action": "response-body-json-del",
             "arguments": {"values": ["data.ad"]}, "source": "test"},
            {"pattern": r"^https://api\.example\.com/config", "action": "response-body-json-replace",
             "arguments": {"pairs": [["data.enabled", False]]}, "source": "test"},
        ],
    }), encoding="utf-8")
    addon = adblock.AdblockAddon(str(state), str(rules), response_factory)

    blocked = Flow()
    addon.request(blocked)
    assert blocked.response.status_code == 200
    assert blocked.response.content == b"{}"
    assert blocked.response.headers["content-type"] == "application/json"

    unrelated = Flow("other.example.com", "/ad")
    addon.request(unrelated)
    assert unrelated.response is None

    payload = {"data": {"ad": {"id": 1}, "enabled": True, "keep": 2}}
    modified = Flow(path="/config", response=Response(
        200, json.dumps(payload).encode(), {"content-length": "99"}))
    addon.response(modified)
    assert json.loads(modified.response.content) == {
        "data": {"enabled": False, "keep": 2},
    }
    assert "content-length" not in modified.response.headers

    encoded = Flow(path="/config", response=EncodedResponse(json.dumps(payload).encode()))
    addon.response(encoded)
    assert json.loads(gzip.decompress(encoded.response.content)) == {
        "data": {"enabled": False, "keep": 2},
    }
    assert int(encoded.response.headers["content-length"]) == len(encoded.response.content)

    state.write_text(json.dumps({"enabled": False}), encoding="utf-8")
    disabled = Flow()
    addon.request(disabled)
    assert disabled.response is None

value = {"a": {"items": [{"x": 1}, {"x": 2}]}}
assert adblock.json_set(value, "a.items[1].x", 9)
assert adblock.json_delete(value, "a.items[0]")
assert value == {"a": {"items": [{"x": 9}]}}

print("adblock-mitm regression OK")
