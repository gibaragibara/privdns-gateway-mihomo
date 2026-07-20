#!/usr/bin/env python3
"""Regression tests for Bot/runtime WLOC integration."""
import importlib.util
import json
import plistlib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"
DEFAULT_PRESETS = ROOT / "deploy/wloc/wloc-presets.json"

default_presets = json.loads(DEFAULT_PRESETS.read_text(encoding="utf-8"))["presets"]
assert default_presets[0]["name"] == "香港西九龙站"

spec = importlib.util.spec_from_file_location("pdg_bot", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

BASE = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "direct", "tag": "residential"},
    ],
    "route": {
        "rules": [{"ip_cidr": ["203.0.113.10/32", "127.0.0.0/8"], "action": "reject"}],
        "final": "jp",
    },
}

assert bot._wloc_parse_coordinates("22.543096, 114.057865") == (22.543096, 114.057865)
assert bot._wloc_parse_coordinates("0 -0.25") == (0.0, -0.25)
for invalid in ("", "1", "91,1", "1,181", "nan,2"):
    try:
        bot._wloc_parse_coordinates(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError(f"invalid coordinates accepted: {invalid!r}")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    bot.WLOC_STATE = str(root / "wloc.json")
    bot.WLOC_DOMAINS = str(root / "wloc.txt")
    bot.MOSDNS_FORCE_PROXY = str(root / "force_proxy.txt")
    bot.MOSDNS_CONF = str(root / "mosdns.yaml")
    bot.WLOC_CA = str(root / "mitmproxy-ca-cert.cer")
    bot.WLOC_PRESETS = str(root / "wloc-presets.json")
    bot.ADBLOCK_STATE = str(root / "adblock.json")
    bot.ADBLOCK_RULES = str(root / "adblock-rules.json")
    bot.ADBLOCK_DOMAINS = str(root / "adblock.txt")
    bot.ADBLOCK_SOURCES = str(root / "adblock-sources.json")
    bot.ADBLOCK_DOMAIN_PROVIDER_FILE = str(root / "adblock-provider.mrs")
    bot.ADBLOCK_CLASSICAL_PROVIDER_FILE = str(root / "adblock-classical.yaml")
    bot.MITM_LOCK_FILE = str(root / "pdg-mitm.lock")
    bot.STATE = str(root / "state.json")
    bot.RS_DIR = str(root / "rs")
    bot.RS_META = str(root / "rulesets.json")
    Path(bot.RS_DIR).mkdir()
    Path(bot.STATE).write_text(json.dumps(BASE), encoding="utf-8")
    Path(bot.MOSDNS_CONF).write_text(
        "tag: geosite_wloc\ntag: geosite_force_proxy\ntag: geosite_adblock\n"
        "tag: wloc_sequence\nqname $geosite_wloc\nqname $geosite_force_proxy\n"
        "qname $geosite_adblock\n", encoding="utf-8")
    bot._adblock_write_state(bot._adblock_default())
    Path(bot.ADBLOCK_RULES).write_text(json.dumps({"hosts": [], "rules": []}),
                                         encoding="utf-8")
    Path(bot.ADBLOCK_SOURCES).write_text(json.dumps({
        "sources": [
            {"name": "插件一", "url": "https://example.com/one.lpx", "enabled": True},
            {"name": "插件二", "url": "https://example.com/two.lpx", "enabled": True},
        ],
        "domain_sources": [{"name": "reject", "url": "https://example.com/reject.list"}],
        "local_domain_rules": ["ads.private.example"],
        "script_conversions": [{"script_url": "https://example.com/a.js"}],
        "external_jq_pins": [{"url": "https://example.com/a.jq"}],
        "mitm_exclude_hosts": ["api.example.com"],
        "compatibility_routes": [
            {"type": "domain", "value": "api.example.com", "outbound": "residential"},
            {"type": "domain-suffix", "value": "cdn.example.com",
             "outbound": "residential"},
        ],
    }), encoding="utf-8")
    assert len(bot._adblock_module_sources()) == 2
    assert len(bot._adblock_domain_sources()) == 1
    assert bot._adblock_excluded_hosts(strict=True) == ["api.example.com"]
    assert bot._adblock_compatibility_routes(
        bot._adblock_source_config(), BASE, strict=True) == [
            {"type": "domain", "value": "api.example.com", "outbound": "residential"},
            {"type": "domain-suffix", "value": "cdn.example.com",
             "outbound": "residential"},
        ]
    try:
        bot._adblock_compatibility_routes({
            "compatibility_routes": [
                {"type": "domain", "value": "api.example.com", "outbound": "missing"},
            ],
        }, BASE, strict=True)
    except ValueError as exc:
        assert "出口不存在" in str(exc)
    else:
        raise AssertionError("compatibility route accepted an unknown outbound")

    compact_surge = ("# comment DOMAIN-SUFFIX,push.example # next "
                     "IP-CIDR,17.1.0.0/16,no-resolve "
                     "IP-CIDR6,2001:db8::/32,no-resolve")
    assert bot._parse_surge_rules(compact_surge) == (
        [], ["push.example"], [], ["17.1.0.0/16", "2001:db8::/32"])

    force_provider = Path(bot.RS_DIR) / "rs_apns.yaml"
    force_provider.write_text(
        "payload:\n  - DOMAIN-SUFFIX,push.example\n"
        "  - IP-CIDR6,2001:db8::/32\n", encoding="utf-8")
    force_state = json.loads(json.dumps(BASE))
    force_state["route"]["rule_set"] = [{
        "tag": "rs_apns", "type": "local", "format": "classical",
        "path": str(force_provider),
    }]
    force_state["route"]["rules"] = [{
        "rule_set": "rs_apns", "outbound": "jp", "force_gateway": True,
    }, *force_state["route"]["rules"]]
    assert bot._force_gateway_domain_lines(force_state) == ["domain:push.example"]
    bot._adblock_write_state(bot._adblock_default())
    forced_config = bot._mihomo_config(force_state)
    assert forced_config["rules"][0] == "RULE-SET,rs_apns,jp"
    assert not any(bot.WLOC_OUTBOUND in rule for rule in forced_config["rules"])
    ok, detail = bot._write_force_gateway_domains(force_state, restart=False)
    assert ok and detail == ""
    assert Path(bot.MOSDNS_FORCE_PROXY).read_text() == "domain:push.example\n"
    bot._adblock_check_plugin = lambda _url: (True, {
        "supported_rewrites": 2, "unported_scripts": 1,
    })
    ok, _ = bot.add_adblock_plugin("https://example.com/custom.lpx")
    assert ok and len(bot._adblock_module_sources()) == 3
    custom_id = bot._adblock_source_id("https://example.com/custom.lpx")
    ok, _ = bot.delete_adblock_plugin(custom_id)
    assert ok and len(bot._adblock_module_sources()) == 2
    bot._adblock_check_domain_source = lambda _url: (True, {
        "supported_rules": 4, "domain_mrs_rule_count": 3,
        "domain_classical_rule_count": 1,
    })
    domain_url = "https://example.com/custom-rules.yaml"
    ok, _ = bot.add_adblock_domain_source(domain_url)
    assert ok and len(bot._adblock_domain_sources()) == 2
    assert bot._adblock_source_config()["domain_sources"][-1]["format"] == "auto"
    ok, _ = bot.add_adblock_domain_source(domain_url)
    assert not ok
    ok, _ = bot.delete_adblock_domain_source(bot._adblock_source_id(domain_url))
    assert ok and len(bot._adblock_domain_sources()) == 1
    preserved_config = bot._adblock_source_config()
    assert preserved_config["local_domain_rules"] == ["ads.private.example"]
    assert preserved_config["script_conversions"] == [
        {"script_url": "https://example.com/a.js"}]
    assert preserved_config["external_jq_pins"] == [
        {"url": "https://example.com/a.jq"}]
    assert preserved_config["mitm_exclude_hosts"] == ["api.example.com"]
    assert len(preserved_config["compatibility_routes"]) == 2

    valid_sources = Path(bot.ADBLOCK_SOURCES).read_bytes()
    Path(bot.ADBLOCK_SOURCES).write_text("{broken json", encoding="utf-8")
    damaged_sources = Path(bot.ADBLOCK_SOURCES).read_bytes()
    ok, message = bot.add_adblock_domain_source("https://example.com/must-not-overwrite.list")
    assert not ok and "拒绝覆盖" in message
    assert Path(bot.ADBLOCK_SOURCES).read_bytes() == damaged_sources
    ok, message = bot.delete_adblock_domain_source(
        bot._adblock_source_id("https://example.com/reject.list"))
    assert not ok and "拒绝覆盖" in message
    assert Path(bot.ADBLOCK_SOURCES).read_bytes() == damaged_sources
    original_sh = bot.sh
    sync_commands = []
    bot.sh = lambda *args, **kwargs: sync_commands.append((args, kwargs))
    ok, message = bot._adblock_sync_rules()
    assert not ok and "规则同步失败" in message and not sync_commands
    bot.sh = original_sh
    Path(bot.ADBLOCK_SOURCES).write_bytes(valid_sources)

    assert bot._adblock_sync_timeout() == 350
    large_source_config = {
        "sources": [{"url": f"https://example.com/module-{index}.lpx"}
                    for index in range(bot.ADBLOCK_SOURCE_LIMIT)],
        "domain_sources": [{"url": f"https://example.com/rules-{index}.list"}
                           for index in range(bot.ADBLOCK_SOURCE_LIMIT)],
    }
    Path(bot.ADBLOCK_SOURCES).write_text(json.dumps(large_source_config), encoding="utf-8")
    assert bot._adblock_sync_timeout() == 1520
    Path(bot.ADBLOCK_SOURCES).write_bytes(valid_sources)

    Path(bot.WLOC_PRESETS).write_text(json.dumps({"presets": [
        {"id": "p001", "name": "香港西九龙站", "latitude": 22.303611,
         "longitude": 114.165, "accuracy": 25},
        {"id": "bad", "name": "坏坐标", "latitude": 200, "longitude": 1},
        {"id": "p001", "name": "重复", "latitude": 1, "longitude": 2},
    ]}), encoding="utf-8")
    presets = bot._wloc_presets()
    assert presets == [{"id": "p001", "name": "香港西九龙站", "latitude": 22.303611,
                        "longitude": 114.165, "accuracy": 25}]
    assert bot._wloc_preset("p001")["name"] == "香港西九龙站"

    bot._wloc_write_state(bot._wloc_default())
    disabled = bot._mihomo_config(BASE)
    assert bot.WLOC_OUTBOUND not in [p["name"] for p in disabled["proxies"]]
    assert not any("gs-loc" in rule for rule in disabled["rules"])

    active = {"enabled": True, "latitude": 22.5, "longitude": 114.0,
              "accuracy": 25, "updated_at": "now"}
    bot._wloc_write_state(active)
    enabled = bot._mihomo_config(BASE)
    sidecar = next(p for p in enabled["proxies"] if p["name"] == bot.WLOC_OUTBOUND)
    assert sidecar == {"name": bot.WLOC_OUTBOUND, "type": "http",
                       "server": "127.0.0.1", "port": 9080}
    assert enabled["rules"][:2] == [
        f"DOMAIN,{host},{bot.WLOC_OUTBOUND}" for host in bot.WLOC_HOSTS
    ]
    assert enabled["rules"][2].startswith("IP-CIDR,203.0.113.10/32,REJECT-DROP")

    bot._wloc_write_state(bot._wloc_default())
    bot._adblock_write_state({"enabled": True, "updated_at": "now"})
    Path(bot.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": ["ads.example.com"],
        "rules": [{"pattern": "^https://ads\\.example\\.com/", "action": "reject"}],
    }), encoding="utf-8")
    adblock_only = bot._mihomo_config(BASE)
    assert adblock_only["rules"][:3] == [
        "DOMAIN,api.example.com,residential",
        "DOMAIN-SUFFIX,cdn.example.com,residential",
        f"DOMAIN,ads.example.com,{bot.WLOC_OUTBOUND}",
    ]
    assert not any("gs-loc" in rule for rule in adblock_only["rules"])

    Path(bot.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": ["ads.example.com"],
        "rules": [{"pattern": "^https://ads\\.example\\.com/", "action": "reject"}],
        "stats": {"domain_rule_count": 2, "domain_mrs_rule_count": 1,
                  "domain_classical_rule_count": 1},
    }), encoding="utf-8")
    Path(bot.ADBLOCK_DOMAIN_PROVIDER_FILE).write_bytes(b"mrs")
    Path(bot.ADBLOCK_CLASSICAL_PROVIDER_FILE).write_text(
        'payload:\n  - "DOMAIN-KEYWORD,-ad.example"\n', encoding="utf-8")
    combined = bot._mihomo_config(BASE)
    assert combined["rule-providers"][bot.ADBLOCK_DOMAIN_PROVIDER] == {
        "type": "file", "behavior": "domain", "format": "mrs",
        "path": bot.ADBLOCK_DOMAIN_PROVIDER_FILE,
    }
    assert combined["rule-providers"][bot.ADBLOCK_CLASSICAL_PROVIDER] == {
        "type": "file", "behavior": "classical",
        "path": bot.ADBLOCK_CLASSICAL_PROVIDER_FILE,
    }
    assert combined["rules"][:5] == [
        "DOMAIN,api.example.com,residential",
        "DOMAIN-SUFFIX,cdn.example.com,residential",
        f"DOMAIN,ads.example.com,{bot.WLOC_OUTBOUND}",
        f"RULE-SET,{bot.ADBLOCK_DOMAIN_PROVIDER},REJECT",
        f"RULE-SET,{bot.ADBLOCK_CLASSICAL_PROVIDER},REJECT",
    ]

    Path(bot.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": [], "rules": [],
        "stats": {"domain_rule_count": 2, "domain_mrs_rule_count": 1,
                  "domain_classical_rule_count": 1},
    }), encoding="utf-8")
    normal_only = bot._mihomo_config(BASE)
    assert bot.WLOC_OUTBOUND not in [proxy["name"] for proxy in normal_only["proxies"]]
    assert normal_only["rules"][:4] == [
        "DOMAIN,api.example.com,residential",
        "DOMAIN-SUFFIX,cdn.example.com,residential",
        f"RULE-SET,{bot.ADBLOCK_DOMAIN_PROVIDER},REJECT",
        f"RULE-SET,{bot.ADBLOCK_CLASSICAL_PROVIDER},REJECT",
    ]
    assert not bot._mitm_active()

    Path(bot.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": ["ads.example.com"],
        "rules": [{"pattern": "^https://ads\\.example\\.com/", "action": "reject"}],
        "stats": {"domain_rule_count": 2, "domain_mrs_rule_count": 1,
                  "domain_classical_rule_count": 1},
    }), encoding="utf-8")
    bot._adblock_write_state(bot._adblock_default())

    cert = b"\x30\x03\x02\x01\x01"
    Path(bot.WLOC_CA).write_text(bot.ssl.DER_cert_to_PEM_cert(cert), encoding="ascii")
    profile = plistlib.loads(bot._wloc_ca_profile())
    assert profile["PayloadType"] == "Configuration"
    assert profile["PayloadContent"][0]["PayloadType"] == "com.apple.security.root"
    assert profile["PayloadContent"][0]["PayloadContent"] == cert

    Path(bot.WLOC_CA).write_bytes(cert)
    assert bot._wloc_ca_der() == cert

    events = []

    def service(on):
        events.append(("service", on)); return True, ""

    def apply(_modify):
        events.append(("mihomo", True)); return True, ""

    def dns():
        events.append(("mosdns", True)); return True, ""

    bot._mitm_set_service = service
    bot.apply_sb = apply
    bot._wloc_restart_mosdns = dns

    bot._wloc_write_state(bot._wloc_default())
    ok, _ = bot.set_wloc(35.681236, 139.767125, label="东京站")
    assert ok
    assert bot._wloc_load()["enabled"] is True
    assert bot._wloc_load()["label"] == "东京站"
    assert Path(bot.WLOC_DOMAINS).read_text().splitlines() == [
        "full:gs-loc.apple.com", "full:gs-loc-cn.apple.com"
    ]
    assert events == [("service", True), ("mihomo", True), ("mosdns", True)]

    events.clear()
    ok, message = bot.set_wloc(1.25, 2.5)
    assert ok and "未重启" in message
    assert bot._wloc_load()["label"] is None
    assert events == [("service", True)], "coordinate-only update must not restart DNS or mihomo"

    events.clear()
    ok, _ = bot.disable_wloc()
    assert ok and bot._wloc_load()["enabled"] is False
    assert Path(bot.WLOC_DOMAINS).read_text() == ""
    assert events == [("mosdns", True), ("mihomo", True), ("service", False)]

    # Turning off location must keep the shared sidecar alive while adblock uses it.
    bot._wloc_write_state(active)
    bot._adblock_write_state({"enabled": True, "updated_at": "now"})
    events.clear()
    ok, _ = bot.disable_wloc()
    assert ok
    assert events == [("mosdns", True), ("mihomo", True), ("service", True)]
    bot._adblock_write_state(bot._adblock_default())

    bot._adblock_sync_rules = lambda: (True, {
        "source_count": 1, "host_count": 1, "rule_count": 1,
        "domain_source_count": 1, "domain_rule_count": 2,
        "domain_mrs_rule_count": 1, "domain_classical_rule_count": 1,
        "unported_scripts": 0,
    })
    events.clear()
    ok, _ = bot.enable_adblock()
    assert ok and bot._adblock_active()
    assert Path(bot.ADBLOCK_DOMAINS).read_text() == "full:ads.example.com\n"
    assert events == [("service", True), ("mihomo", True), ("mosdns", True)]

    events.clear()
    ok, _ = bot.disable_adblock()
    assert ok and not bot._adblock_active()
    assert Path(bot.ADBLOCK_DOMAINS).read_text() == ""
    assert events == [("mosdns", True), ("mihomo", True), ("service", False)]

    class Result:
        stdout = "active\n"

    edits = []
    bot.sh = lambda _cmd: Result()
    bot._dot_host = lambda: "dot.test"
    bot.edit = lambda _chat, _mid, text, kb=None: edits.append((text, kb))
    bot.run_bg = lambda fn, *args, **kwargs: fn(*args, **kwargs)

    bot.state[7] = "wloc_location"
    bot.handle_cb(7, 9, "wloc")
    assert 7 not in bot.state and "iOS WLOC" in edits[-1][0]
    bot.handle_cb(7, 9, "nav:client")
    assert "客户端接入" in edits[-1][0]
    bot.handle_cb(7, 9, "wloc")
    assert any(button.get("callback_data") == "wloc_use:p001"
               for row in edits[-1][1]["inline_keyboard"] for button in row)

    bot.handle_cb(7, 9, "adblock_sources")
    assert "MITM 插件管理" in edits[-1][0]
    assert sum(button.get("callback_data", "").startswith("adsrc_del:")
               for row in edits[-1][1]["inline_keyboard"] for button in row) == 2
    bot.handle_cb(7, 9, "adsrc_add")
    assert bot.state[7] == "adblock_add_source"
    bot.handle_cb(7, 9, "adblock_domain_sources")
    assert "普通 REJECT 规则源" in edits[-1][0]
    assert sum(button.get("callback_data", "").startswith("adrej_del:")
               for row in edits[-1][1]["inline_keyboard"] for button in row) == 1
    bot.handle_cb(7, 9, "adrej_add")
    assert bot.state[7] == "adblock_add_domain_source"
    bot.handle_cb(7, 9, "adblock")
    assert 7 not in bot.state

    events.clear()
    bot.handle_cb(7, 9, "wloc_use:p001")
    assert bot._wloc_load()["label"] == "香港西九龙站"
    assert events == [("service", True), ("mihomo", True), ("mosdns", True)]
    assert "香港西九龙站" in edits[-1][0]

source = BOT.read_text(encoding="utf-8")
assert 'm.get("location") or m.get("venue", {}).get("location")' in source
assert '"command": "wloc"' in source
assert '"callback_data": "wloc"' in source.split("MENU =", 1)[1].split("BACK =", 1)[0]
assert '"callback_data": "adblock"' in source.split("MENU =", 1)[1].split("BACK =", 1)[0]
assert 'data.startswith("wloc_use:")' in source
assert 'data.startswith("adsrc_del:")' in source
assert "只撤销两个 Apple 定位域名；共享 CA 和其它 MITM 功能不受影响" in source

print("wloc-bot regression OK")
