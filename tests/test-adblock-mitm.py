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


class LegacyMitmLog:
    def __init__(self):
        self.warnings = []

    def warn(self, message):
        self.warnings.append(message)


legacy_log = LegacyMitmLog()
original_ctx = adblock.MITM_CTX
adblock.MITM_CTX = type("Context", (), {"log": legacy_log})()
adblock._log("warning", "bad response: %s", "not json")
assert legacy_log.warnings == ["bad response: not json"]
adblock.MITM_CTX = object()
adblock._log("info", "standalone import")
adblock.MITM_CTX = original_ctx


class Request:
    def __init__(self, host="api.example.com", path="/ad", headers=None):
        self.pretty_host = host
        self.pretty_url = f"https://{host}{path}"
        self.headers = dict(headers or {})


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
    def __init__(self, host="api.example.com", path="/ad", response=None, headers=None):
        self.request = Request(host, path, headers)
        self.response = response


def response_factory(status, body, headers):
    return Response(status, body, headers)


original_run_jq = adblock.run_jq


def fake_run_jq(value, program, jq_bin=None):
    assert program == "keep-non-ads"
    value["items"] = [item for item in value["items"] if not item.get("ad")]
    return value


adblock.run_jq = fake_run_jq


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    state = root / "adblock.json"
    rules = root / "rules.json"
    state.write_text(json.dumps({"enabled": True}), encoding="utf-8")
    rules.write_text(json.dumps({
        "hosts": ["api.example.com", "other.example.com"],
        "rules": [
            {"pattern": r"^https://api\.example\.com/ad", "action": "reject-dict",
             "arguments": {}, "source": "test", "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/config", "action": "response-body-json-del",
             "arguments": {"values": ["data.ad", "data.extraAd"]}, "source": "test",
             "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/config", "action": "response-body-json-replace",
             "arguments": {"pairs": [["data.enabled", False], ["data.mode", "clean"]]},
             "source": "test",
             "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/header", "action": "request-header-mock",
             "arguments": {"headers": [{"name": "x-mode", "pattern": "^(?:ad|promo)$"}],
                           "mode": "any", "status": 404, "body": "", "content_type": "text"},
             "source": "test", "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/html", "action": "response-body-text-replace",
             "arguments": {"pairs": [["old.example", "new.example"]]}, "source": "test",
             "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/html", "action": "response-body-html-remove",
             "arguments": {"tag": "div", "markers": ["ad-marker"]}, "source": "test",
             "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/html", "action": "response-body-html-json-jq",
             "arguments": {"element_id": "__NEXT_DATA__", "program": "keep-non-ads"},
             "source": "test", "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/response-header", "action": "response-body-json-replace",
             "arguments": {"pairs": [["upstream", False]]}, "source": "test",
             "hosts": ["api.example.com"]},
            {"pattern": r"^https://api\.example\.com/response-header", "action": "response-request-header-mock",
             "arguments": {"headers": [{"name": "rpid", "pattern": "promo"}],
                           "mode": "any", "status": 404, "body": "", "content_type": "text"},
             "source": "test", "hosts": ["api.example.com"]},
        ],
    }), encoding="utf-8")
    addon = adblock.AdblockAddon(str(state), str(rules), response_factory)

    blocked = Flow()
    addon.request(blocked)
    assert blocked.response.status_code == 200
    assert blocked.response.content == b"{}"
    assert blocked.response.headers["content-type"] == "application/json"
    assert len(addon.rules.request_rules["api.example.com"]) == 2
    assert len(addon.rules.response_rules["api.example.com"]) == 7
    assert "other.example.com" not in addon.rules.request_rules
    assert addon.rules.request_fallback == []

    unrelated = Flow("other.example.com", "/ad")
    addon.request(unrelated)
    assert unrelated.response is None

    payload = {"data": {"ad": {"id": 1}, "extraAd": {"id": 2},
                        "enabled": True, "mode": "normal", "keep": 2}}
    modified = Flow(path="/config", response=Response(
        200, json.dumps(payload).encode(), {"content-length": "99"}))
    addon.response(modified)
    assert json.loads(modified.response.content) == {
        "data": {"enabled": False, "mode": "clean", "keep": 2},
    }
    assert "content-length" not in modified.response.headers

    encoded = Flow(path="/config", response=EncodedResponse(json.dumps(payload).encode()))
    addon.response(encoded)
    assert json.loads(gzip.decompress(encoded.response.content)) == {
        "data": {"enabled": False, "mode": "clean", "keep": 2},
    }
    assert int(encoded.response.headers["content-length"]) == len(encoded.response.content)

    header_passthrough = Flow(path="/header", headers={"X-Mode": "normal"})
    addon.request(header_passthrough)
    assert header_passthrough.response is None
    header_blocked = Flow(path="/header", headers={"X-Mode": "promo"})
    addon.request(header_blocked)
    assert header_blocked.response.status_code == 404

    html = (b'<html><div>old.example</div><div class="ad-marker"><div>x</div></div>'
            b'<script id="__NEXT_DATA__">{"items":[{"id":1,"ad":true},{"id":2}]}'
            b'</script></html>')
    html_flow = Flow(path="/html", response=Response(200, html))
    addon.response(html_flow)
    rewritten = html_flow.response.content.decode()
    assert "new.example" in rewritten and "old.example" not in rewritten
    assert "ad-marker" not in rewritten
    assert '"items":[{"id":2}]' in rewritten

    dangerous = ('<script id="__NEXT_DATA__">'
                 '{"items":[],"name":"\\u003c/script\\u003e\\u003cscript\\u003ealert(1)"}'
                 '</script>')
    escaped, count = adblock.rewrite_embedded_json(
        dangerous, "__NEXT_DATA__", "keep-non-ads")
    assert count == 1
    assert escaped.lower().count("</script>") == 1
    embedded = escaped.split(">", 1)[1].rsplit("<", 1)[0]
    assert json.loads(embedded)["name"] == "</script><script>alert(1)"
    assert "\\u003c/script\\u003e" in embedded

    response_mock = Flow(path="/response-header", headers={"Rpid": "promo"},
                         response=Response(200, b'{"upstream":true}'))
    addon.response(response_mock)
    assert response_mock.response.status_code == 404
    assert response_mock.response.content == b""

    state.write_text(json.dumps({"enabled": False}), encoding="utf-8")
    disabled = Flow()
    addon.request(disabled)
    assert disabled.response is None

adblock.run_jq = original_run_jq

value = {"a": {"items": [{"x": 1}, {"x": 2}]}}
assert adblock.json_set(value, "a.items[1].x", 9)
assert adblock.json_delete(value, "a.items[0]")
assert value == {"a": {"items": [{"x": 9}]}}

print("adblock-mitm regression OK")
