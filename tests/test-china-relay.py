#!/usr/bin/env python3
"""ChinaMax MRS conversion and full-device direct-route regression."""
import importlib.util
import os
import stat
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compiler = load_module("pdg_compile_china", ROOT / "deploy/bot/compile-china-rules.py")

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    source = root / "ChinaMax.list"
    source.write_text(
        "\n".join((
            "DOMAIN,Exact.Example.cn",
            "DOMAIN-SUFFIX,example.cn",
            "DOMAIN-SUFFIX,example.cn",
            "DOMAIN-WILDCARD,*.cdn.example.cn",
            "DOMAIN-KEYWORD,china-cdn",
            "IP-CIDR,10.10.10.7/24,no-resolve",
            "IP-CIDR6,2001:db8::1/48,no-resolve",
            "IP-CIDR,not-a-network",
            "PROCESS-NAME,ignored-on-the-gateway",
            "IP-ASN,4134",
        )) + "\n",
        encoding="utf-8",
    )
    fake = root / "mihomo"
    fake.write_text(
        "#!/bin/sh\n"
        "test \"$1\" = convert-ruleset || exit 2\n"
        "test \"$3\" = text || exit 3\n"
        "cp \"$4\" \"$5\"\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    output = root / "rs"
    counts = compiler.compile_rules(source, output, str(fake), min_domains=1, min_cidrs=1)
    assert counts == {"domains": 3, "ipv4_cidrs": 1, "classical": 1}

    domain_file = output / compiler.DOMAIN_OUTPUT
    ip_file = output / compiler.IP_OUTPUT
    classical_file = output / compiler.CLASSICAL_OUTPUT
    assert domain_file.read_text(encoding="utf-8").splitlines() == [
        "exact.example.cn", "+.example.cn", "*.cdn.example.cn"]
    assert ip_file.read_text(encoding="utf-8").splitlines() == ["10.10.10.0/24"]
    assert '"DOMAIN-KEYWORD,china-cdn"' in classical_file.read_text(encoding="utf-8")
    for path in (domain_file, ip_file, classical_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    bot = load_module("pdg_bot_china", ROOT / "deploy/bot/pdg-bot.py")
    bot.CHINA_DOMAIN_PROVIDER_FILE = str(domain_file)
    bot.CHINA_IP_PROVIDER_FILE = str(ip_file)
    bot.CHINA_CLASSICAL_PROVIDER_FILE = str(classical_file)
    config = bot._mihomo_config({
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "direct", "tag": "jp"},
        ],
        "route": {
            "rule_set": [],
            "rules": [{"domain": ["forced.example.cn"], "outbound": "jp"}],
            "final": "jp",
        },
    })
    providers = config["rule-providers"]
    assert providers[bot.CHINA_DOMAIN_PROVIDER]["format"] == "mrs"
    assert providers[bot.CHINA_IP_PROVIDER]["behavior"] == "ipcidr"
    assert providers[bot.CHINA_CLASSICAL_PROVIDER]["behavior"] == "classical"
    rules = config["rules"]
    explicit = rules.index("DOMAIN,forced.example.cn,jp")
    china_domain = rules.index(f"RULE-SET,{bot.CHINA_DOMAIN_PROVIDER},DIRECT")
    china_keyword = rules.index(f"RULE-SET,{bot.CHINA_CLASSICAL_PROVIDER},DIRECT")
    china_ip = rules.index(f"RULE-SET,{bot.CHINA_IP_PROVIDER},DIRECT,no-resolve")
    fallback = rules.index("MATCH,jp")
    assert explicit < china_domain < china_keyword < china_ip < fallback

update_script = (ROOT / "deploy/bot/update-rules.sh").read_text(encoding="utf-8")
for marker in ("compile-china-rules.py", "backup_china_providers",
               "restore_china_providers", "refresh_china_routes"):
    assert marker in update_script, marker

pdg = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
assert "compile-china-rules.py" in pdg
assert "Relay 已启用但缺少 ChinaMax.list" in pdg

print("ChinaMax MRS/full-device direct-route regression OK")
