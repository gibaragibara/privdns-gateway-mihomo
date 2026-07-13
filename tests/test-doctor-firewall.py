#!/usr/bin/env python3
"""Static + dynamic regression for doctor firewall port coverage (mihomo edition)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
checks_src = (ROOT / "deploy/bot/checks.py").read_text(encoding="utf-8")

assert "5228" in checks_src and "8445" in checks_src, (
    "doctor firewall leak detection must include TG SOCKS5 8445 and GMS 5228"
)
# 853 is intentionally public for Android Wi-Fi Private DNS — must NOT be treated as leak
assert '不含 853' in checks_src or '"853"' not in checks_src.split("sens =")[1].split("\n")[0], (
    "853 should not be in the leak sensitive set"
)

spec = importlib.util.spec_from_file_location("pdg_checks", ROOT / "deploy/bot/checks.py")
checks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checks)

# 5228-5230 对全网开放 → leak
checks._run = lambda cmd: (0, "chain input {\n tcp dport { 22 } accept\n"
                              " tcp dport { 5228-5230 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "fail" and "5228" in msg and "5230" in msg, (st, msg)

# 853 公网开放不算泄露(安卓 Wi-Fi DoT)
checks._run = lambda cmd: (0, "chain input {\n tcp dport { 22 } accept\n"
                              " tcp dport 853 accept\n"
                              " ip saddr 172.22.0.0/16 tcp dport { 53, 80, 81, 443, 5228-5230, 8445 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "ok", (st, msg)

# 宽区间对全网开放
checks._run = lambda cmd: (0, "chain input {\n tcp dport { 1-65535 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "fail", (st, msg)
for p in ("53", "443", "5228", "5230", "8445"):
    assert p in msg, (p, msg)
assert "853" not in msg, msg  # 853 不在敏感集

# 宽区间但限定内网
checks._run = lambda cmd: (0, "chain input {\n ip saddr 172.22.0.0/16 tcp dport { 1-65535 } accept\n}", "")
st, _, msg = checks.check_nft()
assert st == "ok", (st, msg)

# check_gms: TPROXY 存在 → ok
checks._run = lambda cmd: (
    (0, "chain input {\n ip saddr 172.22.0.0/16 tcp dport { 53, 80, 81, 443, 5228-5230, 8445 } accept\n}", "")
    if "input" in " ".join(cmd)
    else (0, "chain prerouting {\n tproxy ip to 127.0.0.1:7893\n}", "")
)
st, _, msg = checks.check_gms()
assert st == "ok", (st, msg)

# 无 5228 也无 tproxy → warn
checks._run = lambda cmd: (0, "chain input {\n ip saddr 172.22.0.0/16 tcp dport { 53, 80, 81, 443, 8445 } accept\n}", "")
st, _, msg = checks.check_gms()
assert st == "warn", (st, msg)

print("doctor-firewall regression OK")
