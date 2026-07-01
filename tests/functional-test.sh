#!/usr/bin/env bash
# 真功能测试(非静态): 本地起 mihomo mixed 入口, 用 HTTP CONNECT 域名触发规则,
# 再用 mock SOCKS5 出口日志断言流量去了正确出口。不需要 root/nft/TPROXY。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"; PIDS=()
trap 'for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; rm -rf "$WORK"' EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }
note(){ echo "[*] $*"; }

if command -v mihomo >/dev/null; then
  MIHOMO="$(command -v mihomo)"
elif [[ -x /Users/gibara/mihomo/mihomo ]]; then
  MIHOMO=/Users/gibara/mihomo/mihomo
else
  fail "找不到 mihomo；安装后重跑，或把 mihomo 放进 PATH"
fi
note "用 mihomo: $MIHOMO ($("$MIHOMO" -v 2>/dev/null | head -1))"

python3 "$HERE/mock_socks.py" 19081 "$WORK/a.log" >"$WORK/a.out" 2>&1 & PIDS+=($!)
python3 "$HERE/mock_socks.py" 19082 "$WORK/b.log" >"$WORK/b.out" 2>&1 & PIDS+=($!)
sleep 0.3

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
rules:
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
sleep 0.5

grep -q 'foo.ai.example:443' "$WORK/a.log" || { cat "$WORK/mihomo.out" >&2; fail "ai.example 未走出口 a"; }
grep -q 'cdn.media.example:443' "$WORK/b.log" || { cat "$WORK/mihomo.out" >&2; fail "media.example 未走出口 b"; }
echo "✅ mihomo 域名分流功能测试通过"
