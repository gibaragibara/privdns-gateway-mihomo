#!/usr/bin/env python3
"""Regression tests for the declarative Loon/Egern adblock compiler."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / "deploy/mitm/sync_adblock.py"

spec = importlib.util.spec_from_file_location("sync_adblock", SYNC)
sync = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(sync)

MODULE = r'''
#!name=test
[Rewrite]
^https:\/\/api\.example\.com\/ad reject-dict
^https:\/\/api\.example\.com\/config response-body-json-replace data.enabled false data.items []
^https:\/\/api\.example\.com\/feed response-body-json-jq '.items |= map(select(.ad != true))'
^https:\/\/api\.example\.com\/mock mock-response-body data-type=json status-code=200 data="{"ok":true}"
^https:\/\/api\.example\.com\/external response-body-json-jq jq-path="https://example.com/a.jq"
[Script]
http-response ^https:\/\/api\.example\.com script-path=https://example.com/a.js
[MitM]
hostname=api.example.com, *.wild.example.com
'''

parsed = sync.parse_module(MODULE, "test", "https://example.com/test.lpx")
assert parsed["hosts"] == ["api.example.com"]
assert [rule["action"] for rule in parsed["rules"]] == [
    "reject-dict", "response-body-json-replace", "response-body-json-jq",
    "mock-response-body",
]
assert parsed["rules"][1]["arguments"]["pairs"] == [
    ["data.enabled", False], ["data.items", []],
]
assert parsed["rules"][3]["arguments"]["body"] == '{"ok":true}'
assert parsed["stats"] == {
    "supported_rewrites": 4,
    "unsupported_rewrites": 1,
    "unsupported_actions": {"response-body-json-jq": 1},
    "unported_scripts": 1,
    "skipped_hosts": 1,
}

config = {"sources": [
    {"name": "one", "url": "https://example.com/one", "enabled": True},
    {"name": "off", "url": "https://example.com/off", "enabled": False},
]}
compiled = sync.compile_sources(config, fetcher=lambda _url: MODULE)
assert compiled["stats"]["source_count"] == 1
assert compiled["stats"]["host_count"] == 1
assert compiled["stats"]["rule_count"] == 4
assert compiled["stats"]["unported_scripts"] == 1
assert compiled["failures"] == []

partial = sync.compile_sources({"sources": [
    {"name": "one", "url": "https://example.com/one"},
    {"name": "broken", "url": "https://example.com/broken"},
]}, fetcher=lambda url: (_ for _ in ()).throw(RuntimeError("offline"))
   if url.endswith("broken") else MODULE)
assert partial["stats"]["failed_sources"] == 1
assert partial["failures"][0]["name"] == "broken"

try:
    sync.parse_action("response-body-json-jq", "'env'")
except sync.CompileError:
    pass
else:
    raise AssertionError("unsafe jq capability must be rejected")

print("adblock-sync regression OK")
