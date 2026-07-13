#!/usr/bin/env python3
"""Convert blackmatrix7 ChinaMax.list (Clash/Surge 同源) to mosdns domain_set.

用法: parse-chinamax.py <ChinaMax.list> <输出 geosite_cn.txt>

只转换域名类规则(DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD)。
IP-CIDR / PROCESS-NAME 等写到同目录旁注文件(可选), 不进 mosdns domain_set。
"""
from __future__ import annotations
import os
import sys

MAP = {
    "DOMAIN": "full:",
    "DOMAIN-SUFFIX": "domain:",
    "DOMAIN-KEYWORD": "keyword:",
}


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: parse-chinamax.py <ChinaMax.list> <geosite_cn.txt>", file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    n = 0
    ip_n = 0
    ip_path = os.path.join(os.path.dirname(os.path.abspath(dst)) or ".", "chinamax_ip.txt")
    tmp = dst + ".tmp"
    ip_tmp = ip_path + ".tmp"
    with open(src, encoding="utf-8", errors="ignore") as f, \
            open(tmp, "w", encoding="utf-8") as o, \
            open(ip_tmp, "w", encoding="utf-8") as ipo:
        o.write("# generated from blackmatrix7 ChinaMax.list — do not edit\n")
        ipo.write("# ChinaMax IP-CIDR (IPv4 only; for reference / future mihomo GEOIP)\n")
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "," not in line:
                continue
            typ, val = line.split(",", 1)
            typ_u = typ.strip().upper()
            val = val.strip()
            if not val:
                continue
            # strip trailing options like ,no-resolve
            if "," in val:
                val = val.split(",", 1)[0].strip()
            pref = MAP.get(typ_u)
            if pref:
                o.write(pref + val + "\n")
                n += 1
                continue
            if typ_u in ("IP-CIDR", "IP-CIDR6"):
                if ":" in val:  # skip IPv6 for our IPv4-only gateway
                    continue
                ipo.write(val + "\n")
                ip_n += 1
    if n < 1000:
        try:
            os.remove(tmp)
            os.remove(ip_tmp)
        except OSError:
            pass
        print(f"[x] ChinaMax 域名规则过少 ({n}), 拒绝覆盖", file=sys.stderr)
        return 1
    os.replace(tmp, dst)
    os.replace(ip_tmp, ip_path)
    print(f"geosite_cn.txt (ChinaMax) domains={n} ipv4_cidr={ip_n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
