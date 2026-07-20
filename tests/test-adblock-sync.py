#!/usr/bin/env python3
"""Regression tests for the declarative Loon/Egern adblock compiler."""
import importlib.util
import json
import os
import stat
import tempfile
import threading
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
assert all(rule["hosts"] == ["api.example.com"] for rule in parsed["rules"])
assert parsed["stats"] == {
    "supported_rewrites": 4,
    "unsupported_rewrites": 1,
    "unsupported_actions": {"response-body-json-jq": 1},
    "unported_scripts": 1,
    "skipped_hosts": 1,
    "unused_hosts": 0,
}

GROUPED_MODULE = r'''
[Rewrite]
^https:\/\/(?:api|app)\.example\.com\/ad reject-dict
[Script]
http-response ^https:\/\/script-only\.example\.com script-path=https://example.com/a.js
[MitM]
hostname=api.example.com, app.example.com, script-only.example.com
'''
grouped = sync.parse_module(GROUPED_MODULE, "grouped")
assert grouped["hosts"] == ["api.example.com", "app.example.com"]
assert grouped["rules"][0]["hosts"] == ["api.example.com", "app.example.com"]
assert grouped["stats"]["unused_hosts"] == 1
assert grouped["stats"]["unported_scripts"] == 1

config = {"sources": [
    {"name": "one", "url": "https://example.com/one", "enabled": True},
    {"name": "off", "url": "https://example.com/off", "enabled": False},
]}
compiled = sync.compile_sources(config, fetcher=lambda _url: MODULE)
assert compiled["stats"]["source_count"] == 1
assert compiled["stats"]["host_count"] == 1
assert compiled["stats"]["declared_host_count"] == 1
assert compiled["stats"]["excluded_host_count"] == 0
assert compiled["stats"]["rule_count"] == 4
assert compiled["stats"]["unported_scripts"] == 1
assert compiled["failures"] == []

excluded = sync.compile_sources({
    "sources": [{"name": "one", "url": "https://example.com/one"}],
    "mitm_exclude_hosts": ["API.EXAMPLE.COM."],
}, fetcher=lambda _url: MODULE)
assert excluded["hosts"] == []
assert excluded["excluded_hosts"] == ["api.example.com"]
assert excluded["stats"]["declared_host_count"] == 1
assert excluded["stats"]["excluded_host_count"] == 1
assert excluded["stats"]["rule_count"] == 4

for invalid_exclusions in ("api.example.com", ["*.example.com"], [123]):
    try:
        sync.compile_sources({"sources": [], "mitm_exclude_hosts": invalid_exclusions})
    except sync.CompileError:
        pass
    else:
        raise AssertionError(f"invalid MITM exclusions accepted: {invalid_exclusions!r}")

barrier = threading.Barrier(sync.SOURCE_FETCH_WORKERS)
worker_ids = set()
worker_lock = threading.Lock()


def concurrent_fetch(_url):
    with worker_lock:
        worker_ids.add(threading.get_ident())
    barrier.wait(timeout=10)
    return MODULE


parallel = sync.compile_sources({"sources": [
    {"name": str(index), "url": f"https://example.com/{index}"}
    for index in range(sync.SOURCE_FETCH_WORKERS)
]}, fetcher=concurrent_fetch)
assert parallel["stats"]["source_count"] == sync.SOURCE_FETCH_WORKERS
assert len(worker_ids) == sync.SOURCE_FETCH_WORKERS

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

auto_list = """
# mixed plain list
.suffix.auto.example
exact.auto.example
commented.auto.example # inline comment
DOMAIN-SUFFIX,tracker.auto.example
DOMAIN-KEYWORD,ad-token
*.wild.auto.example
||unsupported.example^
"""
parsed_auto = sync.parse_domain_source(
    auto_list, "auto-list", "https://example.com/auto.list", "auto")
assert parsed_auto["rules"] == [
    "DOMAIN-SUFFIX,suffix.auto.example",
    "DOMAIN,exact.auto.example",
    "DOMAIN,commented.auto.example",
    "DOMAIN-SUFFIX,tracker.auto.example",
    "DOMAIN-KEYWORD,ad-token",
    "DOMAIN-WILDCARD,*.wild.auto.example",
]
assert parsed_auto["stats"]["unsupported_lines"] == 1

deduplicated = sync.parse_domain_source(
    "duplicate.example\n" * 1000, "duplicates", "", "auto")
assert deduplicated["rules"] == ["DOMAIN,duplicate.example"]

original_line_limit = sync.MAX_DOMAIN_SOURCE_LINES
sync.MAX_DOMAIN_SOURCE_LINES = 2
try:
    sync.parse_domain_source("one.example\ntwo.example\nthree.example", "dense", "", "auto")
except sync.CompileError as exc:
    assert "line limit" in str(exc)
else:
    raise AssertionError("dense source must be rejected before splitting into an unbounded list")
finally:
    sync.MAX_DOMAIN_SOURCE_LINES = original_line_limit

original_source_rule_limit = sync.MAX_DOMAIN_RULES_PER_SOURCE
sync.MAX_DOMAIN_RULES_PER_SOURCE = 2
try:
    sync.parse_domain_source("one.example\ntwo.example\nthree.example", "large", "", "auto")
except sync.CompileError as exc:
    assert "rule limit" in str(exc)
else:
    raise AssertionError("per-source rule limit must be enforced")
finally:
    sync.MAX_DOMAIN_RULES_PER_SOURCE = original_source_rule_limit

yaml_provider = """
name: synthetic
payload:
  - 'DOMAIN-SUFFIX,yaml-classical.example'
  - ".yaml-domain.example" # quoted domain behavior
  - plain-yaml.example # unquoted domain behavior
  - '*.wild-yaml.example'
  - {bad: mapping}
interval: 86400
"""
parsed_yaml = sync.parse_domain_source(
    yaml_provider, "auto-yaml", "https://example.com/rules.yaml", "auto")
assert parsed_yaml["rules"] == [
    "DOMAIN-SUFFIX,yaml-classical.example",
    "DOMAIN-SUFFIX,yaml-domain.example",
    "DOMAIN,plain-yaml.example",
    "DOMAIN-WILDCARD,*.wild-yaml.example",
]
assert parsed_yaml["stats"]["unsupported_lines"] == 1

json_provider = json.dumps({"payload": ["+.json.example", "json-exact.example", 7]})
parsed_json_provider = sync.parse_domain_source(
    json_provider, "auto-json", "https://example.com/rules.json", "auto")
assert parsed_json_provider["rules"] == [
    "DOMAIN-SUFFIX,json.example", "DOMAIN,json-exact.example",
]
assert parsed_json_provider["stats"]["unsupported_lines"] == 1

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
    "domain_local_rule_count": 0,
    "domain_unsupported_lines": 2,
}
domain_rules, classical_rules = sync.split_domain_rules(compiled_domains["rules"])
assert domain_rules == [
    "+.ads.example.com", "exact.example.net", "api.ads.example.com",
    "api-noresolve.example.com",
]
assert classical_rules == [
    "DOMAIN-KEYWORD,-ad.example", "IP-CIDR,192.0.2.0/24,no-resolve",
]
auto_domains, auto_classical = sync.split_domain_rules(parsed_auto["rules"])
assert auto_domains == [
    "+.suffix.auto.example", "exact.auto.example", "commented.auto.example",
    "+.tracker.auto.example", "*.wild.auto.example",
]
assert auto_classical == ["DOMAIN-KEYWORD,ad-token"]

compiled_local = sync.compile_domain_sources({
    "domain_sources": [],
    "local_domain_rules": [
        "local-exact.example",
        "+.local-suffix.example",
        "DOMAIN,local-exact.example",
        "DOMAIN-KEYWORD,local-ad-token",
    ],
})
assert compiled_local["rules"] == [
    "DOMAIN,local-exact.example",
    "DOMAIN-SUFFIX,local-suffix.example",
    "DOMAIN-KEYWORD,local-ad-token",
]
assert compiled_local["stats"] == {
    "domain_source_count": 0,
    "domain_failed_sources": 0,
    "domain_rule_count": 3,
    "domain_local_rule_count": 3,
    "domain_unsupported_lines": 0,
}
for invalid_local in ("not-a-list", [7], ["PROCESS-NAME,bad"]):
    try:
        sync.compile_domain_sources({"local_domain_rules": invalid_local})
    except sync.CompileError:
        pass
    else:
        raise AssertionError(f"invalid local rules accepted: {invalid_local!r}")

original_total_rule_limit = sync.MAX_DOMAIN_RULES_TOTAL
sync.MAX_DOMAIN_RULES_TOTAL = 2
try:
    sync.compile_domain_sources({"domain_sources": [
        {"name": "one", "url": "https://example.com/one"},
        {"name": "two", "url": "https://example.com/two"},
    ]}, fetcher=lambda url: ("one.example\ntwo.example" if url.endswith("one")
                            else "three.example"))
except sync.CompileError as exc:
    assert "compiled domain rules" in str(exc)
else:
    raise AssertionError("combined rule limit must be enforced")
finally:
    sync.MAX_DOMAIN_RULES_TOTAL = original_total_rule_limit

original_source_limit = sync.MAX_ADBLOCK_SOURCES
sync.MAX_ADBLOCK_SOURCES = 1
try:
    sync.compile_domain_sources({"domain_sources": [
        {"url": "https://example.com/one"},
        {"url": "https://example.com/two"},
    ]}, fetcher=lambda _url: "one.example")
except sync.CompileError as exc:
    assert "source limit" in str(exc)
else:
    raise AssertionError("source count limit must be enforced")
finally:
    sync.MAX_ADBLOCK_SOURCES = original_source_limit

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
    current.write_text(json.dumps({
        "sources": [],
        "mitm_exclude_hosts": ["private.example.com"],
        "compatibility_routes": [
            {"type": "domain", "value": "private.example.com", "outbound": "private"},
        ],
    }), encoding="utf-8")
    defaults.write_text(json.dumps({"sources": [1], "domain_sources": [2]}), encoding="utf-8")
    assert sync.merge_source_defaults(str(current), str(defaults))
    assert json.loads(current.read_text(encoding="utf-8")) == {
        "sources": [], "domain_sources": [2],
        "mitm_exclude_hosts": ["private.example.com"],
        "compatibility_routes": [
            {"type": "domain", "value": "private.example.com", "outbound": "private"},
        ],
    }
    assert not sync.merge_source_defaults(str(current), str(defaults))

try:
    sync.parse_action("response-body-json-jq", "'env'")
except sync.CompileError:
    pass
else:
    raise AssertionError("unsafe jq capability must be rejected")

print("adblock-sync regression OK")
