#!/usr/bin/env bash
# 更新国内/规则库:
#   1) blackmatrix7 ChinaMax → mosdns geosite_cn.txt (国内直连 DNS 主名单)
#   2) Loyalsoldier geosite.dat → apple / geolocation-!cn (补充)
# 依赖本机能出网下载 (不经过已挂的 53 时可用 resolv 上游)。
set -euo pipefail

RULES_DIR="${PDG_MOSDNS_RULES:-/etc/mosdns/rules}"
BOT_DIR="${PDG_BOT_DIR:-/opt/pdg-bot}"
MIHOMO_RS="${PDG_MIHOMO_RS:-/etc/mihomo/rs}"
MIHOMO_BIN="${PDG_MIHOMO_BIN:-$(command -v mihomo 2>/dev/null || true)}"
CHINAMAX_URL="${PDG_CHINAMAX_URL:-https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax.list}"
# 备用 CDN (raw 失败时)
CHINAMAX_URL_FALLBACK="${PDG_CHINAMAX_URL_FALLBACK:-https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax.list}"
GEOSITE_URL="${PDG_GEOSITE_URL:-https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat}"

mkdir -p "$RULES_DIR" "$MIHOMO_RS"
WORK="$(mktemp -d /tmp/pdg-rules.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
CHINA_OUTPUTS=(__pdg_china_domain.mrs __pdg_china_ip.mrs __pdg_china_classical.yaml)

backup_china_providers() {
  local name
  mkdir -p "$WORK/china-backup"
  for name in "${CHINA_OUTPUTS[@]}"; do
    if [[ -f "$MIHOMO_RS/$name" ]]; then
      cp -p "$MIHOMO_RS/$name" "$WORK/china-backup/$name"
    else
      : > "$WORK/china-backup/.absent-$name"
    fi
  done
}

restore_china_providers() {
  local name
  for name in "${CHINA_OUTPUTS[@]}"; do
    if [[ -f "$WORK/china-backup/$name" ]]; then
      install -m600 "$WORK/china-backup/$name" "$MIHOMO_RS/$name"
    elif [[ -f "$WORK/china-backup/.absent-$name" ]]; then
      rm -f "$MIHOMO_RS/$name"
    fi
  done
}

refresh_china_routes() {
  [[ -f "$BOT_DIR/bot.py" && -f /etc/mihomo/state.json ]] || return 0
  (
    cd "$BOT_DIR" || exit 1
    PDG_BOT_TOKEN='' /usr/bin/python3 -c \
      'import bot; ok, msg = bot.refresh_china_routes(); print(msg or "ChinaMax mihomo routes refreshed"); raise SystemExit(0 if ok else 1)'
  )
}

download() {
  local url="$1" out="$2"
  curl -fsSL --connect-timeout 15 --max-time 180 -o "$out" "$url"
}

echo "[*] 下载 ChinaMax.list (blackmatrix7)…"
if ! download "$CHINAMAX_URL" "$WORK/ChinaMax.list"; then
  echo "[!] raw 失败, 尝试 jsDelivr…"
  download "$CHINAMAX_URL_FALLBACK" "$WORK/ChinaMax.list"
fi
# 保留一份原始 list 便于对照版本
install -m644 "$WORK/ChinaMax.list" "$RULES_DIR/ChinaMax.list"
python3 "$BOT_DIR/parse-chinamax.py" "$WORK/ChinaMax.list" "$RULES_DIR/geosite_cn.txt"
[[ -n "$MIHOMO_BIN" && -x "$MIHOMO_BIN" ]] \
  || { echo "[x] 找不到 mihomo，无法编译 ChinaMax MRS" >&2; exit 1; }
[[ -f "$BOT_DIR/compile-china-rules.py" ]] \
  || { echo "[x] 缺少 compile-china-rules.py" >&2; exit 1; }
backup_china_providers
if ! python3 "$BOT_DIR/compile-china-rules.py" \
    "$WORK/ChinaMax.list" "$MIHOMO_RS" --converter "$MIHOMO_BIN"; then
  restore_china_providers
  exit 1
fi
if ! refresh_china_routes; then
  echo "[x] ChinaMax MRS 校验/加载失败，恢复旧规则" >&2
  restore_china_providers
  refresh_china_routes >/dev/null 2>&1 || true
  exit 1
fi

echo "[*] 下载 Loyalsoldier geosite.dat (apple / !cn 补充)…"
if download "$GEOSITE_URL" "$WORK/geosite.dat"; then
  # parse-geosite 会写 cn/apple/!cn; 我们只要 apple 与 !cn, 保护刚写的 ChinaMax cn
  python3 "$BOT_DIR/parse-geosite.py" "$WORK/geosite.dat" "$WORK/geosite_out"
  if [[ -f "$WORK/geosite_out/geosite_apple.txt" ]]; then
    install -m644 "$WORK/geosite_out/geosite_apple.txt" "$RULES_DIR/geosite_apple.txt"
  fi
  if [[ -f "$WORK/geosite_out/geosite_geolocation-!cn.txt" ]]; then
    install -m644 "$WORK/geosite_out/geosite_geolocation-!cn.txt" "$RULES_DIR/geosite_geolocation-!cn.txt"
  fi
  # 可选: 备份 geosite 版 cn 供对比, 不覆盖 ChinaMax
  if [[ -f "$WORK/geosite_out/geosite_cn.txt" ]]; then
    install -m644 "$WORK/geosite_out/geosite_cn.txt" "$RULES_DIR/geosite_cn.loyalsoldier.bak.txt"
  fi
else
  echo "[!] geosite.dat 下载失败, 保留现有 apple/!cn"
fi

if [[ ! -e "$RULES_DIR/custom_direct.txt" ]]; then
  install -m644 /dev/null "$RULES_DIR/custom_direct.txt"
fi

if systemctl is-active --quiet mosdns 2>/dev/null; then
  systemctl restart mosdns
  sleep 1
  if systemctl is-active --quiet mosdns; then
    echo "[OK] ChinaMax + geosite 已更新并重载 mosdns"
  else
    echo "[!] mosdns 重启后未 active, 请检查 journalctl -u mosdns" >&2
    exit 1
  fi
else
  echo "[OK] 规则文件已写入 $RULES_DIR (mosdns 未运行, 未重启)"
fi

# 摘要
wc -l "$RULES_DIR/geosite_cn.txt" "$RULES_DIR/geosite_apple.txt" 2>/dev/null || true
if head -5 "$RULES_DIR/ChinaMax.list" 2>/dev/null | grep -q UPDATED; then
  grep -E '^# (NAME|UPDATED|TOTAL)' "$RULES_DIR/ChinaMax.list" || true
fi
