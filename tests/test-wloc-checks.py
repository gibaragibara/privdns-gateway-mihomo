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
        "stats": {"source_count": 1, "host_count": 1, "rule_count": 2},
    }), encoding="utf-8")
    Path(checks.ADBLOCK_DOMAINS).write_text("full:ads.example.com\n", encoding="utf-8")
    Path(checks.MIHOMO_CFG).write_text(
        "__pdg_wloc_mitm ads.example.com", encoding="utf-8")
    assert checks.check_adblock() == (
        "ok", "MITM 去广告", "开启 → 1 模块 / 1 主机 / 2 规则")

print("wloc-checks regression OK")
