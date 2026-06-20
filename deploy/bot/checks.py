#!/usr/bin/env python3
"""PrivDNS Gateway 只读检查库。doctor.py 跑全部, healthcheck.py 跑子集。
每个 check() 返回 (level, label, detail), level ∈ 'ok'|'warn'|'fail'。只读, 不改任何东西。"""
import os, re, json, ipaddress, subprocess

SB = "/etc/sing-box/config.json"
MOSDNS_CONF = "/etc/mosdns/config.yaml"
DOT_DOMAIN_FILE = "/opt/pdg-bot/dot-domain"

def _run(cmd, t=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)

def _mos():
    try:
        return open(MOSDNS_CONF).read()
    except Exception:  # noqa: BLE001
        return ""

def _server_ip():
    try:
        for r in json.load(open(SB)).get("route", {}).get("rules", []):
            if r.get("action") == "reject":
                for x in r.get("ip_cidr", []):
                    if x.endswith("/32") and not x.startswith("127."):
                        return x.split("/")[0]
    except Exception:  # noqa: BLE001
        pass
    return ""

def _cert_path():
    m = re.search(r'cert:\s*"([^"]+)"', _mos())
    return m.group(1) if m else os.environ.get("PDG_CERT", "/etc/mosdns/certs/fullchain.pem")

def _internal_cidr():
    m = re.search(r'ips:\s*\[\s*"([^"]+)"', _mos())
    return m.group(1) if m else ""

def _dot_domain():
    try:
        return open(DOT_DOMAIN_FILE).read().strip()
    except Exception:  # noqa: BLE001
        _, out, _ = _run(["openssl", "x509", "-in", _cert_path(), "-noout", "-subject"])
        m = re.search(r"CN\s*=\s*([A-Za-z0-9.*-]+)", out)
        return m.group(1) if m else ""

def check_services():
    bad = [s for s in ("mosdns", "sing-box", "pdg-bot", "pdg-probe81")
           if _run(["systemctl", "is-active", s])[1].strip() != "active"]
    return ("fail", "服务", "未运行: " + ", ".join(bad)) if bad \
        else ("ok", "服务", "mosdns/sing-box/pdg-bot/pdg-probe81 都在")

def check_singbox_version():
    _, out, _ = _run(["sing-box", "version"])
    m = re.search(r"version\s+(\d+)\.(\d+)", out)
    if not m:
        return ("warn", "sing-box 版本", "读不到版本")
    major, minor = int(m.group(1)), int(m.group(2)); v = f"{major}.{minor}"
    if (major, minor) == (1, 12):
        return ("ok", "sing-box 版本", v + ".x ✓")
    if (major, minor) >= (1, 13):
        return ("fail", "sing-box 版本", v + " 太新! 1.13+ 移除了 sniff_override_destination, 网关失效, 须降回 1.12.x")
    return ("warn", "sing-box 版本", v + " 偏旧, 建议 1.12.x")

def check_dot_arecord():
    d = _dot_domain(); sip = _server_ip()
    if not d or not sip:
        return ("warn", "DoT A 记录", "域名或本机 IP 读不到")
    _, out, _ = _run(["dig", "+short", "+time=3", "+tries=1", "@1.1.1.1", d, "A"])
    ips = [x for x in out.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", x)]
    if sip in ips:
        return ("ok", "DoT A 记录", f"{d} → {sip} ✓")
    if not ips:
        return ("warn", "DoT A 记录", f"{d} 解析不到 A 记录")
    return ("fail", "DoT A 记录", f"{d} → {ips[0]}, 不是本机 {sip}")

def check_internal_cidr():
    c = _internal_cidr()
    if not c:
        return ("fail", "内网卡段", "未配置(npn_clients 空)")
    try:
        net = ipaddress.ip_network(c, strict=False)
    except Exception:  # noqa: BLE001
        return ("fail", "内网卡段", f"{c} 不是合法 CIDR")
    if net.prefixlen == 0:
        return ("fail", "内网卡段", f"{c} 等于全网, 会劫持所有来源!")
    if not net.is_private:
        return ("fail", "内网卡段", f"{c} 是公网段, 危险")
    if net.prefixlen < 12:
        return ("warn", "内网卡段", f"{c} 偏宽(/{net.prefixlen}), 建议收到内网卡精确 /16")
    return ("ok", "内网卡段", c)

def check_nft():
    _, out, _ = _run(["nft", "list", "chain", "inet", "filter", "input"])
    if not out:
        return ("warn", "防火墙", "读不到 nftables")
    leaked = set()
    for ln in out.splitlines():
        s = ln.strip()
        if "saddr" in s or "accept" not in s:
            continue  # 限定来源的行 / 非 accept 行, 跳过
        m = re.search(r"dport\s*\{?\s*([0-9,\s]+)", s)
        if m:
            ports = {p.strip() for p in m.group(1).split(",") if p.strip().isdigit()}
            leaked |= ports & {"53", "80", "81", "443", "853"}
    if leaked:
        return ("fail", "防火墙", "这些口对全网开放(应只限内网卡): " + ", ".join(sorted(leaked)))
    return ("ok", "防火墙", "53/80/81/443/853 仅限内网卡来源")

def check_cert():
    p = _cert_path()
    if not os.path.exists(p):
        return ("fail", "证书", f"{p} 不存在")
    rc, _, _ = _run(["openssl", "x509", "-checkend", str(14 * 86400), "-noout", "-in", p])
    return ("warn", "证书", "14 天内过期, 查 certbot.timer") if rc != 0 else ("ok", "证书", "存在且 >14 天")

def check_dns():
    _, out, _ = _run(["dig", "+short", "+time=3", "+tries=1", "@127.0.0.1", "example.com", "A"])
    return ("ok", "本机DNS", "mosdns 应答正常") if out.strip() \
        else ("fail", "本机DNS", "127.0.0.1:53 不应答(mosdns?)")

def check_singbox_config():
    rc, out, err = _run(["sing-box", "check", "-c", SB], t=20)
    return ("ok", "sing-box 配置", "check 通过") if rc == 0 \
        else ("fail", "sing-box 配置", "check 失败: " + (out + err)[-200:])

ALL = [check_services, check_singbox_version, check_dot_arecord, check_internal_cidr,
       check_nft, check_cert, check_dns, check_singbox_config]
ALERT = [check_services, check_dns, check_cert]  # healthcheck 用的轻量子集(运行期故障)

def run(funcs=None):
    return [f() for f in (funcs or ALL)]
