#!/usr/bin/env bash
# 真功能测试(非静态): 本地起 mihomo mixed 入口, 用 HTTP CONNECT 域名触发规则,
# 再用 mock SOCKS5 出口日志断言流量去了正确出口。不需要 root/nft/TPROXY。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
WORK="$(mktemp -d)"; PIDS=()
cleanup(){
  local pid
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }
note(){ echo "[*] $*"; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) fail "不支持的架构: $(uname -m)" ;;
esac

if command -v mihomo >/dev/null; then
  MIHOMO="$(command -v mihomo)"
elif [[ -x /Users/gibara/mihomo/mihomo ]]; then
  MIHOMO=/Users/gibara/mihomo/mihomo
else
  note "下载锁定版 mihomo $MIHOMO_VER ($ARCH)…"
  curl -fsSL "$(pdg_mihomo_url "$ARCH")" \
       -o "$WORK/mihomo.gz" || fail "mihomo 下载失败"
  pdg_verify_sha256 "$WORK/mihomo.gz" "$(pdg_sha256 "mihomo-$ARCH")" \
    "mihomo $MIHOMO_VER ($ARCH)" || fail "mihomo SHA256 校验失败"
  gzip -dc "$WORK/mihomo.gz" > "$WORK/mihomo"
  chmod +x "$WORK/mihomo"
  MIHOMO="$WORK/mihomo"
fi
note "用 mihomo: $MIHOMO ($("$MIHOMO" -v 2>/dev/null | head -1))"

python3 "$HERE/mock_socks.py" 19081 "$WORK/a.log" >"$WORK/a.out" 2>&1 & PIDS+=($!)
python3 "$HERE/mock_socks.py" 19082 "$WORK/b.log" >"$WORK/b.out" 2>&1 & PIDS+=($!)
for port in 19081 19082; do
  ready=0
  for _ in $(seq 1 50); do
    if (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.1
  done
  [[ "$ready" == 1 ]] || fail "mock SOCKS :$port 未就绪"
done

printf '%s\n' '+.blocked.example' '*.wildblocked.example' > "$WORK/adblock-domain.txt"
"$MIHOMO" convert-ruleset domain text \
  "$WORK/adblock-domain.txt" "$WORK/adblock-domain.mrs" \
  || fail "MRS 规则转换失败"
cat > "$WORK/adblock-classical.yaml" <<'YAML'
payload:
  - DOMAIN-KEYWORD,blocked-keyword
YAML

cat > "$WORK/config.yaml" <<'YAML'
mixed-port: 18443
allow-lan: false
mode: rule
log-level: warning
external-controller: 127.0.0.1:19090
proxies:
  - name: a
    type: socks5
    server: 127.0.0.1
    port: 19081
  - name: b
    type: socks5
    server: 127.0.0.1
    port: 19082
rule-providers:
  adblock-domain:
    type: file
    behavior: domain
    format: mrs
    path: ./adblock-domain.mrs
  adblock-classical:
    type: file
    behavior: classical
    path: ./adblock-classical.yaml
rules:
  - RULE-SET,adblock-domain,REJECT
  - RULE-SET,adblock-classical,REJECT
  - DOMAIN-SUFFIX,ai.example,a
  - DOMAIN-SUFFIX,media.example,b
  - MATCH,a
YAML

"$MIHOMO" -t -d "$WORK" || fail "mihomo test 未通过(配置无效)"
"$MIHOMO" -d "$WORK" > "$WORK/mihomo.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do
  (echo > /dev/tcp/127.0.0.1/18443) >/dev/null 2>&1 && break
  sleep 0.1
done
(echo > /dev/tcp/127.0.0.1/18443) >/dev/null 2>&1 || { cat "$WORK/mihomo.out" >&2; fail "mihomo mixed 入口 :18443 未就绪"; }

connect_host(){
  local host="$1"
  python3 - "$host" <<'PY'
import socket, sys
host = sys.argv[1]
s = socket.create_connection(("127.0.0.1", 18443), timeout=5)
s.sendall((f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").encode())
try:
    s.recv(1024)
except OSError:
    pass
s.close()
PY
}

connect_host foo.ai.example
connect_host cdn.media.example
connect_host blocked.example
connect_host ads.blocked.example
connect_host cdn.wildblocked.example
connect_host cdn.blocked-keyword.example
for _ in $(seq 1 30); do
  [[ -f "$WORK/a.log" && -f "$WORK/b.log" ]] && break
  sleep 0.1
done

grep -q 'foo.ai.example:443' "$WORK/a.log" || { cat "$WORK/mihomo.out" >&2; fail "ai.example 未走出口 a"; }
grep -q 'cdn.media.example:443' "$WORK/b.log" || { cat "$WORK/mihomo.out" >&2; fail "media.example 未走出口 b"; }
if grep -qE 'blocked\.example:443|wildblocked\.example:443|blocked-keyword\.example:443' \
  "$WORK/a.log" "$WORK/b.log"; then
  cat "$WORK/mihomo.out" >&2
  fail "MRS/classical REJECT 未拦截测试域名"
fi
echo "✅ mihomo 域名分流与 MRS/classical REJECT 功能测试通过"
