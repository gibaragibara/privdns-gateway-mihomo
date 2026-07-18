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

    active = False

    def run(cmd, t=10):
        if cmd[:2] == ["systemctl", "is-active"] and cmd[-1] == "pdg-wloc":
            return 0, "active\n" if active else "inactive\n", ""
        return 0, "", ""

    checks._run = run
    Path(checks.WLOC_STATE).write_text(json.dumps({"enabled": False}), encoding="utf-8")
    assert checks.check_wloc()[0] == "ok"

    active = True
    assert checks.check_wloc()[0] == "warn"

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

print("wloc-checks regression OK")
