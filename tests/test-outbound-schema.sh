#!/usr/bin/env bash
# 出站 schema 校验: 用项目锁定版 mihomo 对 parse_link + 渲染出的 config.yaml 跑 `mihomo -t`。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) fail "不支持的架构: $(uname -m)" ;;
esac

if command -v mihomo >/dev/null && { [[ "$(uname -s)" != "Linux" ]] || mihomo -v 2>/dev/null | grep -q "v${MIHOMO_VER}-${MIHOMO_PATCH_VER}"; }; then
  MIHOMO="$(command -v mihomo)"
else
  echo "[*] 下载锁定版 mihomo $MIHOMO_VER ($ARCH)…"
  curl -fsSL "$(pdg_mihomo_url "$ARCH")" \
       -o "$WORK/mihomo.gz" || fail "mihomo 下载失败"
  pdg_verify_sha256 "$WORK/mihomo.gz" "$(pdg_sha256 "mihomo-$ARCH")" "mihomo $MIHOMO_VER ($ARCH)" \
    || fail "mihomo SHA256 校验失败"
  gzip -dc "$WORK/mihomo.gz" > "$WORK/mihomo"
  chmod +x "$WORK/mihomo"
  MIHOMO="$WORK/mihomo"
fi
echo "[*] $("$MIHOMO" -v | head -1)"

python3 - "$ROOT" "$WORK" <<'PY'
import base64, json, sys, os, importlib.util
root, work = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("b", os.path.join(root, "deploy/bot/pdg-bot.py"))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
U = "11111111-2222-3333-4444-555555555555"
ss2022 = base64.b64encode(b"0123456789abcdef").decode()
ssui = base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
vm = base64.b64encode(json.dumps({"v": "2", "ps": "VM", "add": "vm.example.com", "port": "443",
     "id": U, "aid": "0", "net": "ws", "tls": "tls", "host": "vm.example.com", "path": "/p"}).encode()).decode()
links = [
    "ss://%s@1.2.3.4:8388#SS" % ssui,
    'HK = ss, 2.2.2.2, 11111, encrypt-method=2022-blake3-aes-128-gcm, password="%s"' % ss2022,
    "vmess://" + vm,
    "trojan://pw@t.example.com:443?sni=t.example.com#TROJAN",
    "vless://%s@r.example.com:443?security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    "&sid=ab12&fp=chrome&flow=xtls-rprx-vision&sni=www.microsoft.com#REALITY" % U,
    "vless://%s@g.example.com:443?security=tls&type=grpc&serviceName=mygrpc&sni=g.example.com#GRPC" % U,
    "hysteria2://hp@h2.example.com:8443?sni=h2.example.com&obfs=salamander&obfs-password=ob#HY2",
    "tuic://%s:tp@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr&alpn=h3#TUIC" % U,
    "anytls://ap@a.example.com:443?sni=a.example.com#ANYTLS",
    "socks5://u:p@1.2.3.4:1080#SOCKS",
    "http://u:p@1.2.3.4:8080#HTTP",
]
state = {
    "server_ip": "203.0.113.39",
    "outbounds": [b.parse_link(x) for x in links] + [{"type": "direct", "tag": "jp"}],
    "route": {"rules": [{"ip_cidr": ["203.0.113.39/32", "127.0.0.0/8"], "action": "reject"}], "final": "jp"},
}
b.STATE = os.path.join(work, "state.json")
b.MIHOMO_CFG = os.path.join(work, "config.yaml")
b.RS_DIR = os.path.join(work, "rs")
b.RS_META = os.path.join(work, "rulesets.json")
os.makedirs(work, exist_ok=True)
json.dump(state, open(b.STATE, "w"), ensure_ascii=False)
b._write(b.load())
print("[*] 出站类型:", [o["type"] for o in state["outbounds"]])
PY

[ -f "$WORK/config.yaml" ] || fail "生成 config.yaml 失败(parse_link/render 出错?)"
echo "[*] mihomo test(锁定版 $MIHOMO_VER)…"
"$MIHOMO" -t -d "$WORK" || fail "mihomo test 不过: parse_link 渲染出的配置与锁定版 schema 不符"
echo "✅ 各协议出站在锁定版 mihomo $MIHOMO_VER 下 schema 校验通过"
