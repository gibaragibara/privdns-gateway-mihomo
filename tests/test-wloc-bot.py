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
    "outbounds": [{"type": "direct", "tag": "jp"}],
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
    bot.MOSDNS_CONF = str(root / "mosdns.yaml")
    bot.WLOC_CA = str(root / "mitmproxy-ca-cert.cer")
    bot.WLOC_PRESETS = str(root / "wloc-presets.json")
    Path(bot.MOSDNS_CONF).write_text(
        "tag: geosite_wloc\ntag: wloc_sequence\nqname $geosite_wloc\n", encoding="utf-8")
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

    bot._wloc_set_service = service
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

    events.clear()
    bot.handle_cb(7, 9, "wloc_use:p001")
    assert bot._wloc_load()["label"] == "香港西九龙站"
    assert events == [("service", True), ("mihomo", True), ("mosdns", True)]
    assert "香港西九龙站" in edits[-1][0]

source = BOT.read_text(encoding="utf-8")
assert 'm.get("location") or m.get("venue", {}).get("location")' in source
assert '"command": "wloc"' in source
assert '"callback_data": "wloc"' in source.split("MENU =", 1)[1].split("BACK =", 1)[0]
assert 'data.startswith("wloc_use:")' in source

print("wloc-bot regression OK")
