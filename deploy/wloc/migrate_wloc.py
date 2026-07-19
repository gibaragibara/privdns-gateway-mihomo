#!/usr/bin/env python3
"""Idempotently add scoped WLOC/adblock MITM branches to mosdns."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import tempfile
import time

DOMAIN_PLUGIN = """  # WLOC 域名集由 bot 启停: 空文件=完全不劫持; 开启时仅含两个 Apple 网络定位主机。
  - tag: geosite_wloc
    type: domain_set
    args: { files: [\"/etc/mosdns/rules/wloc.txt\"] }
"""

ADBLOCK_DOMAIN_PLUGIN = """  # 声明式去广告精确主机集由 bot 同步；空文件=关闭，不扩大 MITM 范围。
  - tag: geosite_adblock
    type: domain_set
    args: { files: [\"/etc/mosdns/rules/adblock.txt\"] }
"""

FORCE_PROXY_DOMAIN_PLUGIN = """  # 强制网关透明转发域名(例如 APNs): 只引流, 不进入 MITM。
  - tag: geosite_force_proxy
    type: domain_set
    args: { files: [\"/etc/mosdns/rules/force_proxy.txt\"] }
"""

SEQUENCE_PLUGIN = """  - tag: wloc_sequence
    type: sequence
    args:
      - matches: qtype 28
        exec: reject 0
      - exec: jump has_resp
      - matches: qtype 65
        exec: reject 0
      - exec: jump has_resp
      - matches: qtype 1
        exec: black_hole __SERVER_IP__
      - exec: jump has_resp
      - exec: $ecs_neutral
      - exec: $remote_upstream
"""

DISPATCH = """      - matches: qname $geosite_wloc
        exec: goto wloc_sequence
"""

ADBLOCK_DISPATCH = """      - matches: qname $geosite_adblock
        exec: goto wloc_sequence
"""

FORCE_PROXY_DISPATCH = """      - matches: qname $geosite_force_proxy
        exec: goto wloc_sequence
"""


def migrate_text(text):
    markers = ("- tag: geosite_wloc", "- tag: wloc_sequence", "qname $geosite_wloc")
    present = [marker in text for marker in markers]
    if any(present):
        if not all(present):
            raise ValueError("mosdns WLOC migration is only partially present; refusing a mixed config")
        migrated = text
        changed = False
    else:
        if "__SERVER_IP__" in text:
            server_ip = "__SERVER_IP__"
        else:
            match = re.search(r"\bblack_hole\s+([0-9a-fA-F:.]+)", text)
            if not match:
                raise ValueError("cannot infer server IP from existing mosdns black_hole rule")
            server_ip = match.group(1)
        sequence_plugin = SEQUENCE_PLUGIN.replace("__SERVER_IP__", server_ip)
        replacements = (
            ("  - tag: geosite_cn\n", DOMAIN_PLUGIN + "  - tag: geosite_cn\n"),
            ("  - tag: internal_sequence\n", sequence_plugin + "  - tag: internal_sequence\n"),
            ("      - matches: qname $geosite_cn\n        exec: $ecs_china\n",
             DISPATCH + "      - matches: qname $geosite_cn\n        exec: $ecs_china\n"),
        )
        migrated = text
        for old, new in replacements:
            if migrated.count(old) != 1:
                raise ValueError(f"unexpected mosdns config marker count for {old.strip()!r}")
            migrated = migrated.replace(old, new, 1)
        changed = True

    adblock_markers = ("- tag: geosite_adblock", "qname $geosite_adblock")
    adblock_present = [marker in migrated for marker in adblock_markers]
    if any(adblock_present) and not all(adblock_present):
        raise ValueError("mosdns adblock migration is only partially present; refusing a mixed config")
    if not any(adblock_present):
        replacements = (
            ("  - tag: geosite_cn\n", ADBLOCK_DOMAIN_PLUGIN + "  - tag: geosite_cn\n"),
            (DISPATCH, ADBLOCK_DISPATCH + DISPATCH),
        )
        for old, new in replacements:
            if migrated.count(old) != 1:
                raise ValueError(f"unexpected mosdns config marker count for {old.strip()!r}")
            migrated = migrated.replace(old, new, 1)
        changed = True
    if not all(marker in migrated for marker in markers + adblock_markers):
        raise ValueError("mosdns MITM migration validation failed")
    force_markers = ("- tag: geosite_force_proxy", "qname $geosite_force_proxy")
    force_present = [marker in migrated for marker in force_markers]
    if any(force_present) and not all(force_present):
        raise ValueError("mosdns force-proxy migration is only partially present; refusing a mixed config")
    if not any(force_present):
        replacements = (
            (ADBLOCK_DOMAIN_PLUGIN, FORCE_PROXY_DOMAIN_PLUGIN + ADBLOCK_DOMAIN_PLUGIN),
            (ADBLOCK_DISPATCH, FORCE_PROXY_DISPATCH + ADBLOCK_DISPATCH),
        )
        for old, new in replacements:
            if migrated.count(old) != 1:
                raise ValueError(f"unexpected force-proxy config marker count for {old.strip()!r}")
            migrated = migrated.replace(old, new, 1)
        changed = True
    if not all(marker in migrated for marker in markers + adblock_markers + force_markers):
        raise ValueError("mosdns force-proxy migration validation failed")
    return migrated, changed


def migrate_file(path):
    with open(path, encoding="utf-8") as f:
        original = f.read()
    migrated, changed = migrate_text(original)
    if not changed:
        return None
    mode = os.stat(path).st_mode & 0o777
    backup = f"{path}.pre-wloc-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(prefix=".wloc-", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(migrated)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", default="/etc/mosdns/config.yaml")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with open(args.path, encoding="utf-8") as f:
            _, changed = migrate_text(f.read())
        print("migration required" if changed else "ready")
        return
    backup = migrate_file(args.path)
    print("already ready" if backup is None else f"migrated; backup={backup}")


if __name__ == "__main__":
    main()
