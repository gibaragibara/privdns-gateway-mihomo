#!/usr/bin/env python3
"""Static and pure-Python regressions for the optional full-device Relay."""
import importlib.util
import json
import plistlib
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


relay = load_module("pdg_relayctl", ROOT / "deploy/relay/pdg-relayctl.py")
config = {
    "enabled": True,
    "host": "relay.example.com",
    "listen_port": 20443,
    "token": "a" * 64,
    "relay_uuid": "11111111-1111-4111-8111-111111111111",
    "payload_uuid": "22222222-2222-4222-8222-222222222222",
    "profile_uuid": "33333333-3333-4333-8333-333333333333",
}

profile = plistlib.loads(relay.profile_bytes(config))
assert profile["PayloadRemovalDisallowed"] is False
assert len(profile["PayloadContent"]) == 1
payload = profile["PayloadContent"][0]
assert payload["PayloadType"] == "com.apple.relay.managed"
assert "MatchDomains" not in payload, "omitting MatchDomains is what makes the profile full-device"
assert "MatchFQDNs" not in payload
assert payload["ExcludedDomains"] == ["relay.example.com"], "the relay endpoint must bypass itself"
assert payload["RelayUUID"] == config["relay_uuid"]
server = payload["Relays"][0]
assert server["HTTP2RelayURL"] == "https://relay.example.com:20443/"
assert "HTTP3RelayURL" not in server, "the current Envoy listener is HTTP/2 only"
assert server["AdditionalHTTPHeaderFields"] == {"X-Relay-Token": "a" * 64}

envoy = relay.render_envoy_text(config)
for marker in (
        "codec_type: HTTP2", "stream_idle_timeout: 0s", "request_timeout: 0s",
        "upgrade_type: CONNECT", "upgrade_type: CONNECT-UDP", "allow_connect: true",
        "name: x-relay-token", "dynamic_forward_proxy",
        "envoy.resource_monitors.global_downstream_max_connections",
        "max_active_downstream_connections: 1024", "[relay-error]",
        "status_code_filter", "authority=%REQ(:AUTHORITY)%"):
    assert marker in envoy, marker
assert "stream_idle_timeout: 300s" not in envoy, "quiet push sockets must not be killed every five minutes"

with tempfile.TemporaryDirectory() as directory:
    policy_root = Path(directory)
    relay.CHINA_PROVIDERS = tuple(policy_root / name for name in ("domain.mrs", "ip.mrs", "classical.yaml"))
    relay.MIHOMO_CONFIG = policy_root / "mihomo.yaml"
    try:
        relay._assert_china_direct()
        raise AssertionError("missing ChinaMax providers must block Relay profile delivery")
    except relay.RelayError:
        pass
    for provider in relay.CHINA_PROVIDERS:
        provider.write_text("valid", encoding="utf-8")
    relay.MIHOMO_CONFIG.write_text(
        "rules:\n"
        "  - RULE-SET,__pdg_china_domain,DIRECT\n"
        "  - RULE-SET,__pdg_china_ip,DIRECT,no-resolve\n",
        encoding="utf-8",
    )
    relay._assert_china_direct()

tproxy = (ROOT / "deploy/relay/pdg-relay-tproxy.sh").read_text(encoding="utf-8")
assert "table inet pdg_relay" in tproxy
assert "meta skuid $uid" in tproxy
assert "meta mark $MARK return" in tproxy
assert "meta skuid $uid tcp sport $port return" in tproxy, "outer Relay replies must not loop into mihomo"
assert "meta mark $MARK meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:7893 counter accept" in tproxy
assert "meta skuid $uid meta l4proto { tcp, udp } counter meta mark set $MARK" in tproxy
assert "MARK=0x233" in tproxy and "TABLE=10123" in tproxy
assert 'uidrange "$uid-$uid" table "$TABLE"' in tproxy
assert 'ipproto tcp sport "$port" table main' in tproxy
assert 'check) up 1' in tproxy
assert "meta skuid $uid meta l4proto" in tproxy, "never mark unrelated server output"
assert "chain output" in tproxy and "chain prerouting" in tproxy

unit = (ROOT / "deploy/relay/pdg-relay.service").read_text(encoding="utf-8")
assert "User=pdg-relay" in unit and "Group=pdg-relay" in unit
assert "ExecStartPre=+/usr/local/bin/pdg-relay-tproxy.sh up" in unit
assert "ExecStopPost=+/usr/local/bin/pdg-relay-tproxy.sh down" in unit
assert "Requires=mihomo.service" in unit
assert "BindsTo=mihomo.service" in unit and "PartOf=mihomo.service" in unit
assert "ReadWritePaths=/etc/pdg-relay" in unit and "AF_NETLINK" in unit
assert "wait_mihomo" in tproxy and "mihomo :7893 在 10 秒内未就绪" in tproxy

pdg = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
for marker in (
        "etc/systemd/system/pdg-relay.service", "usr/local/bin/pdg-relayctl",
        "usr/local/bin/pdg-relay-tproxy.sh", "opt/pdg-relay",
        'cmd_relay "$@"', "pdg-relayctl ensure-envoy", "compile-china-rules.py"):
    assert marker in pdg, marker

checks = load_module("pdg_checks_relay", ROOT / "deploy/bot/checks.py")
with tempfile.TemporaryDirectory() as directory:
    relay_state = Path(directory) / "relay.json"
    envoy_state = Path(directory) / "envoy.yaml"
    mihomo_state = Path(directory) / "mihomo.yaml"
    china_domain = Path(directory) / "china-domain.mrs"
    china_ip = Path(directory) / "china-ip.mrs"
    china_classical = Path(directory) / "china-classical.yaml"
    checks.RELAY_CONFIG = str(relay_state)
    checks.RELAY_ENVOY_CONFIG = str(envoy_state)
    checks.MIHOMO_CFG = str(mihomo_state)
    checks.CHINA_DOMAIN_PROVIDER = str(china_domain)
    checks.CHINA_IP_PROVIDER = str(china_ip)
    checks.CHINA_CLASSICAL_PROVIDER = str(china_classical)

    def stopped(command, t=10):
        del t
        if command[:3] == ["systemctl", "is-active", "pdg-relay"]:
            return 3, "inactive\n", ""
        return 0, "", ""

    checks._run = stopped
    assert checks.check_relay() == ("ok", "Apple Relay", "未配置（旧 DoT/TPROXY 模式）")
    relay_state.write_text(json.dumps({"enabled": False}), encoding="utf-8")
    assert checks.check_relay()[0] == "ok"

    relay_state.write_text(json.dumps(config), encoding="utf-8")
    envoy_state.write_text("valid", encoding="utf-8")
    mihomo_state.write_text(
        "rules:\n"
        "  - RULE-SET,__pdg_china_domain,DIRECT\n"
        "  - RULE-SET,__pdg_china_ip,DIRECT,no-resolve\n",
        encoding="utf-8")
    for provider in (china_domain, china_ip, china_classical):
        provider.write_text("valid", encoding="utf-8")

    def healthy(command, t=10):
        del t
        if command[:3] == ["systemctl", "is-active", "pdg-relay"]:
            return 0, "active\n", ""
        if command[:4] == ["nft", "list", "table", "inet"]:
            return 0, "meta skuid 995 tproxy ip to 127.0.0.1:7893", ""
        if command[:4] == ["ip", "-6", "rule", "show"]:
            return 0, "10122: from all uidrange 995-995 lookup 10123", ""
        if command[:2] == ["ss", "-lntH"]:
            return 0, "LISTEN 0 4096 0.0.0.0:20443 0.0.0.0:*", ""
        return 0, "", ""

    checks._run = healthy
    level, label, detail = checks.check_relay()
    assert level == "ok" and label == "Apple Relay" and "relay.example.com:20443" in detail

print("relay profile/lifecycle regression OK")
