#!/usr/bin/env python3
"""Local probe and Telegram listeners must bypass TPROXY before prerouting."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
template = (ROOT / "deploy/firewall/nftables.conf").read_text(encoding="utf-8")

bypass = ("ip saddr __INTERNAL_CIDR__ ip daddr __SERVER_IP__ "
          "tcp dport { 81, 8445 } accept")
assert bypass in template
assert template.index(bypass) < template.index("tproxy ip to 127.0.0.1:7893")

rendered = (template.replace("__INTERNAL_CIDR__", "172.22.0.0/16")
            .replace("__SERVER_IP__", "203.0.113.10")
            .replace("__SSH_PORT__", "22"))
assert "__" not in rendered
assert "ip daddr 203.0.113.10 tcp dport { 81, 8445 } accept" in rendered

pdg = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
assert "migrate_fw_local_service_bypass" in pdg
assert 's/__SERVER_IP__/$server_ip/g' in pdg

print("firewall local-service bypass regression OK")
