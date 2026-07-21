#!/usr/bin/env python3
"""Regression tests for conditional WLOC health checks."""
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "deploy/bot/checks.py"

spec = importlib.util.spec_from_file_location("checks", CHECKS)
checks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checks)

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    checks.WLOC_STATE = str(root / "wloc.json")
    checks.WLOC_DOMAINS = str(root / "wloc.txt")
    checks.WLOC_CA = str(root / "ca.cer")
    checks.MIHOMO_CFG = str(root / "mihomo.yaml")
    checks.ADBLOCK_STATE = str(root / "adblock.json")
    checks.ADBLOCK_RULES = str(root / "adblock-rules.json")
    checks.ADBLOCK_DOMAINS = str(root / "adblock.txt")
    checks.ADBLOCK_DOMAIN_PROVIDER = str(root / "adblock-provider.mrs")
    checks.ADBLOCK_CLASSICAL_PROVIDER = str(root / "adblock-classical.yaml")

    active = False

    def run(cmd, t=10):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[-1] == "pdg-wloc":
            return 0, "active\n" if active else "inactive\n", ""
        return 0, "", ""

    checks._run = run
    Path(checks.ADBLOCK_STATE).write_text(json.dumps({"enabled": False}), encoding="utf-8")
    Path(checks.WLOC_STATE).write_text(json.dumps({"enabled": False}), encoding="utf-8")
    assert checks.check_wloc()[0] == "ok"

    active = True
    assert checks.check_wloc()[0] == "warn"
    Path(checks.ADBLOCK_STATE).write_text(json.dumps({"enabled": True}), encoding="utf-8")
    assert checks.check_wloc() == (
        "ok", "WLOC", "关闭(Apple 定位原始直连)；共享 MITM 由去广告使用")
    Path(checks.ADBLOCK_STATE).write_text(json.dumps({"enabled": False}), encoding="utf-8")

    Path(checks.WLOC_STATE).write_text(json.dumps({
        "enabled": True, "latitude": 22.5, "longitude": 114.0,
    }), encoding="utf-8")
    Path(checks.WLOC_DOMAINS).write_text(
        "full:gs-loc.apple.com\nfull:gs-loc-cn.apple.com\n", encoding="utf-8")
    Path(checks.WLOC_CA).write_bytes(b"cert")
    Path(checks.MIHOMO_CFG).write_text(
        "__pdg_wloc_mitm gs-loc.apple.com gs-loc-cn.apple.com", encoding="utf-8")
    assert checks.check_wloc()[0] == "ok"

    Path(checks.WLOC_DOMAINS).write_text("", encoding="utf-8")
    level, _, detail = checks.check_wloc()
    assert level == "fail" and "mosdns" in detail

    Path(checks.WLOC_STATE).write_text(json.dumps({"enabled": False}), encoding="utf-8")
    Path(checks.ADBLOCK_STATE).write_text(json.dumps({"enabled": True}), encoding="utf-8")
    Path(checks.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": ["ads.example.com"],
        "stats": {"source_count": 1, "host_count": 1, "rule_count": 2,
                  "domain_rule_count": 3, "domain_mrs_rule_count": 2,
                  "domain_classical_rule_count": 1},
    }), encoding="utf-8")
    Path(checks.ADBLOCK_DOMAINS).write_text("full:ads.example.com\n", encoding="utf-8")
    Path(checks.ADBLOCK_DOMAIN_PROVIDER).write_bytes(b"mrs")
    Path(checks.ADBLOCK_CLASSICAL_PROVIDER).write_text(
        'payload:\n  - "DOMAIN-KEYWORD,-ad.example"\n', encoding="utf-8")
    Path(checks.MIHOMO_CFG).write_text(
        "__pdg_wloc_mitm RULE-SET,__pdg_adblock_reject,REJECT "
        "RULE-SET,__pdg_adblock_reject_classical,REJECT ads.example.com",
        encoding="utf-8")
    assert checks.check_adblock() == (
        "ok", "去广告", "开启 → 1 模块 / 1 主机 / 2 重写；不可达 0；排除 0 主机；普通 REJECT 3 条")

    Path(checks.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": ["ads.example.com"],
        "stats": {"source_count": 1, "host_count": 1, "rule_count": 2,
                  "domain_source_count": 0, "domain_rule_count": 0,
                  "domain_mrs_rule_count": 0, "domain_classical_rule_count": 0},
    }), encoding="utf-8")
    Path(checks.MIHOMO_CFG).write_text(
        "__pdg_wloc_mitm ads.example.com", encoding="utf-8")
    assert checks.check_adblock() == (
        "ok", "去广告", "开启 → 1 模块 / 1 主机 / 2 重写；不可达 0；排除 0 主机；普通 REJECT 0 条")

    Path(checks.ADBLOCK_RULES).write_text(json.dumps({
        "hosts": [], "excluded_hosts": ["api.example.com"],
        "stats": {"source_count": 1, "host_count": 0, "declared_host_count": 1,
                  "excluded_host_count": 1, "rule_count": 2,
                  "domain_source_count": 0, "domain_rule_count": 0,
                  "domain_mrs_rule_count": 0, "domain_classical_rule_count": 0},
    }), encoding="utf-8")
    Path(checks.ADBLOCK_DOMAINS).write_text("", encoding="utf-8")
    Path(checks.MIHOMO_CFG).write_text("DOMAIN,api.example.com,residential", encoding="utf-8")
    assert checks.check_adblock() == (
        "ok", "去广告", "开启 → 1 模块 / 0 主机 / 2 重写；不可达 0；排除 1 主机；普通 REJECT 0 条")

    payload = json.loads(Path(checks.ADBLOCK_RULES).read_text(encoding="utf-8"))
    payload["stats"]["pending_module_updates"] = 1
    Path(checks.ADBLOCK_RULES).write_text(json.dumps(payload), encoding="utf-8")
    status, name, detail = checks.check_adblock()
    assert status == "warn" and name == "去广告" and "1 个模块更新待批准" in detail

print("wloc-checks regression OK")
