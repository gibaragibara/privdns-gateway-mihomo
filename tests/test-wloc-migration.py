#!/usr/bin/env python3
"""Regression tests for old-install mosdns WLOC migration."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/wloc/migrate_wloc.py"
MOSDNS = ROOT / "deploy/mosdns/config.yaml"

spec = importlib.util.spec_from_file_location("migrate_wloc", MIGRATION)
migration = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(migration)

current = MOSDNS.read_text(encoding="utf-8")
ready, changed = migration.migrate_text(current)
assert not changed and ready == current

legacy = current.replace(migration.DOMAIN_PLUGIN, "", 1)
legacy = legacy.replace(migration.ADBLOCK_DOMAIN_PLUGIN, "", 1)
legacy = legacy.replace(migration.FORCE_PROXY_DOMAIN_PLUGIN, "", 1)
legacy = legacy.replace(migration.SEQUENCE_PLUGIN, "", 1)
legacy = legacy.replace(migration.ADBLOCK_DISPATCH, "", 1)
legacy = legacy.replace(migration.FORCE_PROXY_DISPATCH, "", 1)
legacy = legacy.replace(migration.DISPATCH, "", 1)
assert "geosite_wloc" not in legacy and "wloc_sequence" not in legacy

migrated, changed = migration.migrate_text(legacy)
assert changed
assert migrated == current, "migration should produce the current template exactly"

rendered_legacy = legacy.replace("__SERVER_IP__", "203.0.113.10")
rendered, changed = migration.migrate_text(rendered_legacy)
assert changed
assert "exec: black_hole 203.0.113.10" in rendered
assert "__SERVER_IP__" not in rendered

try:
    migration.migrate_text(legacy.replace(
        "  - tag: geosite_cn\n", migration.DOMAIN_PLUGIN + "  - tag: geosite_cn\n", 1))
except ValueError as exc:
    assert "partially present" in str(exc)
else:
    raise AssertionError("partial WLOC migration must be rejected")

wloc_only = current.replace(migration.ADBLOCK_DOMAIN_PLUGIN, "", 1)
wloc_only = wloc_only.replace(migration.ADBLOCK_DISPATCH, "", 1)
migrated, changed = migration.migrate_text(wloc_only)
assert changed and migrated == current

try:
    migration.migrate_text(wloc_only.replace(
        "  - tag: geosite_cn\n", migration.ADBLOCK_DOMAIN_PLUGIN + "  - tag: geosite_cn\n", 1))
except ValueError as exc:
    assert "adblock" in str(exc)
else:
    raise AssertionError("partial adblock migration must be rejected")

try:
    migration.migrate_text(legacy.replace(
        "  - tag: geosite_cn\n", migration.FORCE_PROXY_DOMAIN_PLUGIN + "  - tag: geosite_cn\n", 1))
except ValueError as exc:
    assert "force-proxy" in str(exc)
else:
    raise AssertionError("partial force-proxy migration must be rejected")

print("wloc-migration regression OK")
