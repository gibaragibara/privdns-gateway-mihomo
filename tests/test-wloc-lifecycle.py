#!/usr/bin/env python3
"""Static regression for the shared WLOC/adblock MITM lifecycle."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
install = (ROOT / "install.sh").read_text(encoding="utf-8")
pdg = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
unit = (ROOT / "deploy/wloc/pdg-wloc.service").read_text(encoding="utf-8")
addon = (ROOT / "deploy/wloc/wloc_mitm.py").read_text(encoding="utf-8")
adblock_addon = (ROOT / "deploy/mitm/adblock_mitm.py").read_text(encoding="utf-8")
bot = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")
scheduled = (ROOT / "deploy/bot/scheduled-update.sh").read_text(encoding="utf-8")

for marker in ("mitmproxy", "wloc_mitm.py", "migrate_wloc.py", "pdg-wloc.service",
               "/var/lib/pdg-wloc/wloc.json", "/etc/mosdns/rules/wloc.txt",
               "wloc-presets.json", "adblock_mitm.py", "sync_adblock.py",
               "/var/lib/pdg-wloc/adblock.json", "/etc/mosdns/rules/adblock.txt",
               "/etc/mosdns/rules/force_proxy.txt", "adblock-sources.json"):
    assert marker in install, f"fresh install is missing {marker}"
    assert marker in pdg, f"update path is missing {marker}"

assert "[[ -f /var/lib/pdg-wloc/wloc.json ]]" in pdg, (
    "update must preserve the existing WLOC enabled/coordinate state"
)
assert "[[ -f /etc/mosdns/rules/wloc.txt ]]" in pdg, (
    "update must not clear an active WLOC DNS domain set"
)
assert "[[ -f /etc/mosdns/rules/wloc.txt ]]" in install, (
    "forced reinstall must not truncate the active WLOC DNS domain set"
)
assert "[[ -f /var/lib/pdg-wloc/adblock.json ]]" in pdg
assert "[[ -f /etc/mosdns/rules/adblock.txt ]]" in pdg
assert "[[ -f /etc/mosdns/rules/force_proxy.txt ]]" in pdg
assert "bot._wloc_write_domains(bot._wloc_active())" in install, (
    "install must synchronize the WLOC DNS domain set with the preserved state"
)
assert "bot._adblock_write_domains(bot._adblock_active())" in install
assert "bot._adblock_write_domains(bot._adblock_active())" in pdg
assert "systemctl start pdg-wloc" in install and "systemctl disable --now pdg-wloc" in install, (
    "fresh install should generate the CA but leave disabled WLOC stopped"
)
assert "systemctl try-restart pdg-wloc" in pdg, (
    "pdg restart should restart the sidecar only when it was already active"
)
assert "systemctl restart pdg-wloc" in pdg, (
    "pdg update must restart an enabled sidecar to load the new addon"
)
assert pdg.count("cmd_rollback 0; return 1") >= 6, (
    "WLOC dependency and migration failures must use the update rollback path"
)

for marker in ("pdg-wloc", "/var/lib/pdg-wloc", "userdel pdg-wloc"):
    assert marker in uninstall, f"purge path is missing {marker}"

assert "User=pdg-wloc" in unit and "Group=pdg-wloc" in unit
assert "127.0.0.1" in unit and "9080" in unit, "sidecar must only listen on localhost"
assert "NoNewPrivileges=true" in unit and "ProtectSystem=strict" in unit
assert "MemoryMax=256M" in unit
assert 'WLOC_STATE = "/var/lib/pdg-wloc/wloc.json"' in bot
assert 'CONFIG_PATH = "/var/lib/pdg-wloc/wloc.json"' in addon
assert "--scripts /opt/pdg-bot/wloc_mitm.py --scripts /opt/pdg-bot/adblock_mitm.py" in unit
assert 'STATE_PATH = "/var/lib/pdg-wloc/adblock.json"' in adblock_addon
assert 'RULES_PATH = "/var/lib/pdg-wloc/adblock-rules.json"' in adblock_addon
assert 'ADBLOCK_DOMAIN_PROVIDER_FILE = "/etc/mihomo/rs/__pdg_adblock_reject.mrs"' in bot
assert 'ADBLOCK_CLASSICAL_PROVIDER_FILE = ' \
       '"/etc/mihomo/rs/__pdg_adblock_reject_classical.yaml"' in bot
assert "--domain-output" in bot
assert "--classical-output" in bot
assert "_mitm_set_service(_mitm_active())" in bot
assert "_mitm_set_service(_wloc_active())" in bot or "_mitm_set_service(_mitm_active())" in bot
assert "refresh_adblock" in scheduled, "daily timer must refresh REJECT and MITM adblock sources"
assert "adblock_sources" in bot and "adblock_add_source" in bot and "adsrc_del:" in bot
assert "adblock_domain_sources" in bot and "adblock_add_domain_source" in bot
assert "adrej_del:" in bot and "--check-domain-url" in bot

print("wloc-lifecycle regression OK")
