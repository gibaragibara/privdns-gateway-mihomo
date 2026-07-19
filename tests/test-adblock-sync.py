#!/usr/bin/env python3
"""Regression tests for the declarative Loon/Egern adblock compiler."""
import importlib.util
import json
import os
import stat
import tempfile
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

domain_set = """
# comment
.ads.example.com
exact.example.net
*.unsupported.example.org
"""
parsed_domains = sync.parse_domain_source(
    domain_set, "domain-set", "https://example.com/domains", "domain-set")
assert parsed_domains["rules"] == [
    "DOMAIN-SUFFIX,ads.example.com", "DOMAIN,exact.example.net",
]
assert parsed_domains["stats"]["unsupported_lines"] == 1

classical = """
DOMAIN,api.ads.example.com
DOMAIN,api-noresolve.example.com,no-resolve
DOMAIN-SUFFIX,ads.example.com
DOMAIN-KEYWORD,-ad.example
IP-CIDR,192.0.2.9/24,no-resolve
PROCESS-NAME,bad
"""
parsed_classical = sync.parse_domain_source(
    classical, "classical", "https://example.com/rules", "classical")
assert parsed_classical["rules"] == [
    "DOMAIN,api.ads.example.com", "DOMAIN,api-noresolve.example.com",
    "DOMAIN-SUFFIX,ads.example.com", "DOMAIN-KEYWORD,-ad.example",
    "IP-CIDR,192.0.2.0/24,no-resolve",
]
assert parsed_classical["stats"]["unsupported_lines"] == 1

domain_config = {"domain_sources": [
    {"name": "one", "url": "https://example.com/one", "format": "domain-set"},
    {"name": "two", "url": "https://example.com/two", "format": "classical"},
]}
compiled_domains = sync.compile_domain_sources(
    domain_config, fetcher=lambda url: domain_set if url.endswith("one") else classical)
assert compiled_domains["stats"] == {
    "domain_source_count": 2,
    "domain_failed_sources": 0,
    "domain_rule_count": 6,
    "domain_unsupported_lines": 2,
}
domain_rules, classical_rules = sync.split_domain_rules(compiled_domains["rules"])
assert domain_rules == [
    ".ads.example.com", "exact.example.net", "api.ads.example.com",
    "api-noresolve.example.com",
]
assert classical_rules == [
    "DOMAIN-KEYWORD,-ad.example", "IP-CIDR,192.0.2.0/24,no-resolve",
]

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    provider = root / "provider.yaml"
    sync.atomic_write_provider(str(provider), compiled_domains["rules"])
    assert provider.read_text(encoding="utf-8").startswith(
        'payload:\n  - "DOMAIN-SUFFIX,ads.example.com"\n')
    assert os.stat(provider).st_mode & 0o777 == 0o600

    converter = root / "fake-mihomo"
    converter.write_text(
        "#!/bin/sh\n"
        "test \"$1 $2 $3\" = \"convert-ruleset domain text\" || exit 2\n"
        "cp \"$4\" \"$5\"\n",
        encoding="utf-8",
    )
    converter.chmod(converter.stat().st_mode | stat.S_IXUSR)
    mrs = root / "provider.mrs"
    sync.atomic_write_domain_mrs(str(mrs), domain_rules, str(converter))
    assert mrs.read_text(encoding="utf-8").splitlines() == domain_rules
    assert os.stat(mrs).st_mode & 0o777 == 0o600

    failing = root / "failing-mihomo"
    failing.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    failing.chmod(failing.stat().st_mode | stat.S_IXUSR)
    mrs.write_bytes(b"previous")
    try:
        sync.atomic_write_domain_mrs(str(mrs), domain_rules, str(failing))
    except sync.CompileError:
        pass
    else:
        raise AssertionError("failed MRS conversion must be rejected")
    assert mrs.read_bytes() == b"previous"

    fallback = root / "classical.yaml"
    sync.atomic_write_provider(str(fallback), classical_rules)
    assert fallback.read_text(encoding="utf-8").splitlines() == [
        "payload:",
        '  - "DOMAIN-KEYWORD,-ad.example"',
        '  - "IP-CIDR,192.0.2.0/24,no-resolve"',
    ]

    current = root / "sources.json"
    defaults = root / "defaults.json"
    current.write_text(json.dumps({"sources": []}), encoding="utf-8")
    defaults.write_text(json.dumps({"sources": [1], "domain_sources": [2]}), encoding="utf-8")
    assert sync.merge_source_defaults(str(current), str(defaults))
    assert json.loads(current.read_text(encoding="utf-8")) == {
        "sources": [], "domain_sources": [2],
    }
    assert not sync.merge_source_defaults(str(current), str(defaults))

try:
    sync.parse_action("response-body-json-jq", "'env'")
except sync.CompileError:
    pass
else:
    raise AssertionError("unsafe jq capability must be rejected")

print("adblock-sync regression OK")
