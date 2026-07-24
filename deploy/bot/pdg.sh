#!/usr/bin/env bash
# PrivDNS Gateway 管理命令。直接 `sudo pdg` 进菜单, 或 pdg <子命令>。
#   pdg [menu] | status | update | token | restart | log [n] | uninstall [--purge]
# 设计: 生命周期(装/更新/卸载/token/状态/日志)走这里; 出口/分流/DNS上游 走 Telegram bot。
set -uo pipefail
REPO_URL="https://github.com/gibaragibara/privdns-gateway-mihomo.git"
REPO_DIR="/opt/privdns-gateway"
SVC="/etc/systemd/system/pdg-bot.service"
ENVD="/etc/privdns-gateway"
ENVF="$ENVD/bot.env"

c_g(){ echo -e "\033[1;32m$*\033[0m"; }
c_y(){ echo -e "\033[1;33m$*\033[0m"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "请用 root: sudo pdg $*"; exit 1; }; }

# 串行化"会写配置/重启服务"的操作(update/rollback/snapshot), 防 bot 更新按钮与命令行并发。
# 嵌套调用(update→snapshot)只锁一次。read-only 操作(status/doctor/report/log)不加锁。
LOCK="/run/privdns-gateway.lock"
PDG_LOCKED=""
_lock(){
  [[ -n "$PDG_LOCKED" ]] && return 0
  exec 9>"$LOCK" 2>/dev/null || return 0
  flock -n 9 || { echo "⛔ 已有 pdg 操作在运行, 请稍后再试 (锁: $LOCK)"; exit 1; }
  PDG_LOCKED=1
}

pdg_fetch_release_tags(){
  local dir="${1:-$REPO_DIR}"
  git -C "$dir" fetch -q --tags origin main || return 1
  if [[ "$(git -C "$dir" rev-parse --is-shallow-repository 2>/dev/null)" == "true" ]]; then
    git -C "$dir" fetch -q --unshallow --tags origin main || return 1
  fi
}

cmd_status(){
  c_g "== 服务 =="
  for s in mosdns mihomo pdg-bot pdg-probe81 pdg-wloc pdg-relay; do
    printf "  %-12s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
  echo "  timer        $(systemctl is-active pdg-rules-update.timer 2>/dev/null)"
  echo "  DoT 域名     $(cat /opt/pdg-bot/dot-domain 2>/dev/null || echo ?)"
  local ports
  ports=$(ss -lntu 2>/dev/null | grep -oE ':(53|80|81|443|853|8445|9080|9090|20443)\b' | sed 's/^://' | sort -u \
    | sed 's/^9080$/9080(local shared MITM)/; s/^9090$/9090(local clash_api)/; s/^20443$/20443(Apple Relay)/' | tr '\n' ' ')
  echo "  监听端口     $ports"
  if [[ -d "$REPO_DIR/.git" ]]; then echo "  代码版本     $(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)"; fi
}

cmd_doctor(){ python3 /opt/pdg-bot/doctor.py "$@"; }

# 旧装把 token 写在 unit 的 Environment= 里 → 迁到 bot.env(600), unit 改用 EnvironmentFile。幂等。
migrate_botenv(){
  [[ -f "$SVC" ]] || return 0
  local tok allow
  tok=$(grep -oP '^Environment=PDG_BOT_TOKEN=\K.*'   "$SVC" | head -1)
  allow=$(grep -oP '^Environment=PDG_BOT_ALLOWED=\K.*' "$SVC" | head -1)
  install -d -m700 "$ENVD"
  if [[ ! -f "$ENVF" && -n "$tok" ]]; then
    ( umask 077; printf 'PDG_BOT_TOKEN=%s\nPDG_BOT_ALLOWED=%s\n' "$tok" "$allow" > "$ENVF" )
    chmod 600 "$ENVF"
    c_g "已把 token 从 unit 迁移到 $ENVF (600)"
  fi
  grep -qE '^Environment=PDG_BOT_(TOKEN|ALLOWED)=' "$SVC" \
    && sed -i -E '/^Environment=PDG_BOT_(TOKEN|ALLOWED)=/d' "$SVC"
  grep -q '^EnvironmentFile=-\?/etc/privdns-gateway/bot.env' "$SVC" \
    || sed -i -E 's#^\[Service\]#[Service]\nEnvironmentFile=-/etc/privdns-gateway/bot.env#' "$SVC"
}

# 判断旧 /etc/nftables.conf 是不是本项目"原装"防火墙(无用户自定义)。
# 严格白名单(默认拒绝): 去注释/空行、收紧空白后, **每一行**都必须匹配下面某条已知原装规则;
# 只要出现一行不认识的(自定义来源/端口/动作/链/表等)就判"非原装" → 不自动重建, 以免静默丢规则。
# 白名单用正则, 因此兼容历史变体: forward/output 单行或多行写法、不同年代的内网端口子集
# ({53,80,81,443} → +853 → +8445)都算原装。
_fw_is_stock(){
  local f="$1" port="$2" cidr="$3" line norm matched pat
  local cre="${cidr//./\\.}"               # 内网段做正则(转义点)
  local pset='(53|80|81|443|853|8445)'     # 内网放行端口集(任意子集/顺序)
  local -a pats=(
    '^flush ruleset$'
    '^table inet filter [{]$'
    '^chain (input|forward|output) [{]$'
    '^chain (forward|output) [{] type filter hook (forward|output) priority 0; policy accept; [}]$'
    '^type filter hook input priority 0; policy drop;$'
    '^type filter hook (forward|output) priority 0; policy accept;$'
    '^iif "lo" accept$'
    '^ct state established,related accept$'
    "^tcp dport [{] ${port}(, 853)? [}] accept$"
    "^tcp dport ${port} accept$"
    "^ip saddr ${cre} tcp dport [{] ${pset}(, ${pset})* [}] accept$"
    "^ip saddr ${cre} udp dport [{] (53|443)(, (53|443))* [}] accept$"
    "^ip saddr ${cre} udp dport (53|443) accept$"
    "^ip saddr ${cre} udp dport 443 reject$"
    "^ip saddr ${cre} udp dport 443 drop$"
    '^ip protocol icmp accept$'
    '^ip6 nexthdr icmpv6 accept$'
    '^[}]$'
  )
  while IFS= read -r line; do
    norm="${line%%#*}"                                                  # 去行内/整行注释
    norm="$(printf '%s' "$norm" | tr -s ' \t' ' ' | sed 's/^ //; s/ $//')"  # 收紧空白+去首尾
    [[ -z "$norm" ]] && continue
    matched=0
    for pat in "${pats[@]}"; do printf '%s' "$norm" | grep -qE "$pat" && { matched=1; break; }; done
    [[ "$matched" == 1 ]] || return 1                                   # 出现白名单外的行 → 非原装
  done < "$f"
  return 0
}

# 旧装防火墙迁移: 把旧的 `flush ruleset` + `table inet filter` 迁到独立表 `inet pdg`。幂等。
# 不迁移则: 证书续期 pre-hook 进不了 inet pdg 开不了 80、doctor 读不到防火墙、且仍会 flush 掉别的表。
# 安全做法: 解析旧配置里的 SSH 端口/内网段 → 渲染新模板 → nft -c 校验 → 备份 → nft -f → 删旧表。
# 全程 SSH 不断(established + 新表放行 SSH; 加载新表时旧 inet filter 仍在 → 双重放行)。
migrate_firewall_to_pdg(){
  local f=/etc/nftables.conf
  [[ -f "$f" ]] || return 0
  # 已是新表(有 inet pdg 且无 inet filter)→ 无需迁移
  grep -q 'table inet pdg' "$f" && ! grep -q 'table inet filter' "$f" && return 0
  # 必须看起来像本项目的防火墙(含我们放行的端口特征), 否则不乱动用户的自定义规则
  grep -qE '\b(853|8445)\b' "$f" || return 0
  local port cidr server_ip tmp; tmp="$(mktemp)"
  port=$(grep -E 'tcp dport.*accept' "$f" | grep -v saddr | grep -oE '[0-9]+' | head -1)
  cidr=$(grep -oE 'ip saddr [0-9./]+' "$f" | head -1 | awk '{print $3}')
  server_ip=$(jq -r '.server_ip // empty' /etc/mihomo/state.json 2>/dev/null)
  [[ "$server_ip" =~ ^[0-9]+([.][0-9]+){3}$ ]] \
    || server_ip=$(grep -oE '"[0-9.]+/32"' /etc/mihomo/state.json 2>/dev/null \
         | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  if [[ -z "$port" || -z "$cidr" || -z "$server_ip" ]]; then
    c_y "检测到旧防火墙但解析不出 SSH端口/内网段/服务器IP, 跳过自动迁移(可手动重渲染)。"; rm -f "$tmp"; return 0
  fi
  # 迁移=用标准模板重建, 只保留 SSH端口+内网段; 若旧配置里有自定义端口/规则/额外表,
  # 重建会静默丢掉它们 → 检测到非原装就不自动迁移, 让用户手动并入(旧配置原样留在 $f)。
  if ! _fw_is_stock "$f" "$port" "$cidr"; then
    c_y "检测到旧防火墙含自定义规则/额外端口/额外表 → 不自动迁移(避免静默丢失你的规则)。"
    c_y "  迁移会用标准模板重建(只保留 SSH=$port + 内网段=$cidr)。请任选其一:"
    c_y "   • 把自定义规则并进 deploy/firewall/nftables.conf 同风格后手动 nft -f; 或"
    c_y "   • sudo pdg migrate-fw 先迁标准部分, 再把自定义规则补到 inet pdg。"
    c_y "  现状: 旧 inet filter 不动(证书 hook/doctor 已兼容它, 不迁也能正常用)。"
    rm -f "$tmp"; return 0
  fi
  c_g "检测到旧版(原装)防火墙 → 迁移到独立表 inet pdg (SSH=$port, 内网段=$cidr)…"
  sed -e "s/__SSH_PORT__/$port/g" -e "s#__INTERNAL_CIDR__#$cidr#g" \
      -e "s/__SERVER_IP__/$server_ip/g" \
      "$REPO_DIR/deploy/firewall/nftables.conf" > "$tmp"
  if ! nft -c -f "$tmp" >/dev/null 2>&1; then
    c_y "  新规则 nft -c 校验未过, 保留旧防火墙不动。"; rm -f "$tmp"; return 0
  fi
  # 必须先确认备份完整(cmp 逐字节相同)才敢覆盖现网配置; 磁盘满/cp 失败时中止, 不动现网。
  local bak; bak="$f.prepdg.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份 $f 失败/不完整(磁盘满?), 中止迁移、不改动现网。"; rm -f "$tmp" "$bak" 2>/dev/null; return 0
  fi
  # 写新配置; 若写失败/不完整(磁盘满), 用刚验证过的备份还原, 不动内核(尚未 nft -f)。
  if ! cp "$tmp" "$f" 2>/dev/null || ! cmp -s "$tmp" "$f"; then
    c_y "  写入新配置失败/不完整(磁盘满?), 已还原备份、不改动现网。"; cp -a "$bak" "$f" 2>/dev/null; rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"
  # 关键: 只有"新表加载成功且 inet pdg 确实在内核里"才删旧表; 否则绝不删 inet filter。
  # nft -f 是原子的, 失败则内核不变(旧 inet filter 仍在生效), 只需把 on-disk 配置还原回旧的。
  if nft -f "$f" 2>/dev/null && nft list table inet pdg >/dev/null 2>&1; then
    nft delete table inet filter 2>/dev/null || true   # 确认新表已载入, 再删旧表, 只留 inet pdg
    c_g "  ✅ 已迁移为 inet pdg。"
  else
    cp -a "$bak" "$f" 2>/dev/null                       # 还原 on-disk 配置=旧(内核里旧表仍在)
    c_y "  ⚠️ 新规则加载失败 → 保留旧防火墙、未删 inet filter、配置已还原(防火墙未中断)。"
  fi
}

# 已经使用 inet pdg 的旧安装可能缺少本机 :81/:8445 的 prerouting 豁免。
# 只在标准 TPROXY 行前插入一条精确 daddr 规则，不改写其它自定义防火墙内容。
migrate_fw_local_service_bypass(){
  local f=/etc/nftables.conf cidr server_ip tmp bak
  [[ -f "$f" ]] || return 0
  grep -q 'table inet pdg' "$f" || return 0
  grep -q 'tproxy ip to 127.0.0.1:7893' "$f" || return 0
  if awk '
    /chain prerouting[[:space:]]*[{]/ { inside=1 }
    inside && /accept/ && /dport/ {
      if ($0 ~ /(^|[^0-9])81([^0-9]|$)/) p81=1
      if ($0 ~ /(^|[^0-9])8445([^0-9]|$)/) p8445=1
    }
    inside && /^[[:space:]]*[}][[:space:]]*$/ { inside=0 }
    END { exit !(p81 && p8445) }
  ' "$f"; then
    return 0
  fi
  cidr=$(grep -oE 'ip saddr [0-9./]+' "$f" | head -1 | awk '{print $3}')
  server_ip=$(jq -r '.server_ip // empty' /etc/mihomo/state.json 2>/dev/null)
  [[ "$server_ip" =~ ^[0-9]+([.][0-9]+){3}$ ]] \
    || server_ip=$(grep -oE '"[0-9.]+/32"' /etc/mihomo/state.json 2>/dev/null \
         | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  if [[ -z "$cidr" || -z "$server_ip" ]]; then
    c_y "无法补 :81/:8445 防火墙豁免: 内网段或服务器 IP 缺失。"
    return 0
  fi
  tmp=$(mktemp); bak="$f.pre-local-bypass.$(date +%s)"
  if ! awk -v rule="        ip saddr $cidr ip daddr $server_ip tcp dport { 81, 8445 } accept" '
      !done && /tproxy ip to 127[.]0[.]0[.]1:7893/ { print rule; done=1 }
      { print }
      END { if (!done) exit 1 }
    ' "$f" > "$tmp" || ! nft -c -f "$tmp" >/dev/null 2>&1; then
    c_y "补 :81/:8445 防火墙豁免失败，保留原配置。"; rm -f "$tmp"; return 0
  fi
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak" \
      || ! cp "$tmp" "$f" 2>/dev/null || ! cmp -s "$tmp" "$f"; then
    cp -a "$bak" "$f" 2>/dev/null || true
    c_y "写入 :81/:8445 防火墙豁免失败，已保留原配置。"; rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"
  if nft -f "$f" 2>/dev/null; then
    c_g "  ✅ 已补本机 :81/:8445 的 TPROXY 前置豁免。"
  else
    cp -a "$bak" "$f" 2>/dev/null || true
    nft -f "$f" 2>/dev/null || true
    c_y "应用 :81/:8445 防火墙豁免失败，已回滚。"
  fi
}

# Render the project-owned UDP/443 policy to stdout. Legacy installs used a
# silent drop; that can leave QUIC-first apps waiting until their own timeout
# instead of falling back to TCP. Keep QUIC disabled, but fail it immediately.
_fw_render_quic_reject(){
  local f="$1" cidr="$2"
  local reject_re='^[[:space:]]*ip saddr [0-9./]+ (meta l4proto )?udp (th )?dport 443 reject([[:space:]]|$)'
  local drop_re='^[[:space:]]*ip saddr [0-9./]+ (meta l4proto )?udp (th )?dport 443 drop([[:space:]]|$)'
  if grep -Eq "$reject_re" "$f"; then
    cat "$f"
    return 0
  fi
  if grep -Eq "$drop_re" "$f"; then
    awk -v re="$drop_re" '
      $0 ~ re { sub(/dport 443 drop/, "dport 443 reject") }
      { print }
    ' "$f"
    return 0
  fi
  awk -v rule="        ip saddr $cidr udp dport 443 reject" '
    !done && /tproxy ip to 127[.]0[.]0[.]1:7893/ { print rule; done=1 }
    { print }
    END { if (!done) exit 1 }
  ' "$f"
}

# Existing inet-pdg installs are intentionally not re-rendered during update,
# so migrate only the exact project QUIC rule and preserve every other custom
# firewall line. This also repairs the short-lived template that allowed QUIC.
migrate_fw_quic_fast_reject(){
  local f="${1:-/etc/nftables.conf}" cidr tmp bak
  local reject_re='^[[:space:]]*ip saddr [0-9./]+ (meta l4proto )?udp (th )?dport 443 reject([[:space:]]|$)'
  [[ -f "$f" ]] || return 0
  grep -q 'table inet pdg' "$f" || return 0
  grep -q 'tproxy ip to 127.0.0.1:7893' "$f" || return 0
  grep -Eq "$reject_re" "$f" && return 0
  cidr=$(grep -oE 'ip saddr [0-9./]+' "$f" | head -1 | awk '{print $3}')
  if [[ -z "$cidr" ]]; then
    c_y "无法迁移 QUIC 快速回退: 内网段缺失。"
    return 0
  fi
  tmp=$(mktemp); bak="$f.pre-quic-reject.$(date +%s)"
  if ! _fw_render_quic_reject "$f" "$cidr" > "$tmp" \
      || ! grep -Eq "$reject_re" "$tmp" \
      || ! nft -c -f "$tmp" >/dev/null 2>&1; then
    c_y "生成 QUIC 快速 reject 规则失败，保留原配置。"; rm -f "$tmp"; return 0
  fi
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak" \
      || ! cp "$tmp" "$f" 2>/dev/null || ! cmp -s "$tmp" "$f"; then
    cp -a "$bak" "$f" 2>/dev/null || true
    c_y "写入 QUIC 快速 reject 规则失败，已保留原配置。"; rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"
  if nft -f "$f" 2>/dev/null; then
    c_g "  ✅ UDP/443 已改为快速 reject；QUIC 仍禁用，客户端可立即回落 TCP。"
  else
    cp -a "$bak" "$f" 2>/dev/null || true
    nft -f "$f" 2>/dev/null || true
    c_y "应用 QUIC 快速 reject 规则失败，已回滚。"
  fi
}

# 给 /etc/mosdns 里"缺 concurrent"的 forward args 行补上(单上游=1, 多上游=2)。幂等。读 $1 → stdout。
# (mosdns 默认 concurrent=1=随机选1个不故障转移; 单上游配 2 会把同一台并发查两次, 故按上游数定。)
_mosdns_add_concurrent(){
  awk '
    /args: \{ upstreams:/ {
      n = gsub(/addr:/, "addr:")        # 数本行上游个数
      c = (n <= 1) ? 1 : 2
      sub(/args: \{ upstreams:/, "args: { concurrent: " c ", upstreams:")
    }
    { print }
  ' "$1"
}

# 旧装迁移: 老的 /etc/mosdns/config.yaml 的 forward 块没有 concurrent(=默认随机单上游、不故障转移)。
# pdg update 不重渲染该文件, 故在此幂等补上(不动用户现有上游/顺序)。
migrate_mosdns_concurrent(){
  local f=/etc/mosdns/config.yaml
  [[ -f "$f" ]] || return 0
  grep -qE 'args: [{] upstreams:' "$f" || return 0     # 没有"缺 concurrent"的行 → 无需迁移
  c_g "检测到 mosdns forward 块缺 concurrent → 补上(单上游=1/多上游=2, 不动你的上游)…"
  local bak; bak="$f.preconc.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败(磁盘满?), 中止、不动现网。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  if ! _mosdns_add_concurrent "$f" > "$f.tmp" 2>/dev/null || ! grep -q concurrent "$f.tmp"; then
    c_y "  生成失败, 中止。"; rm -f "$f.tmp"; return 0
  fi
  mv "$f.tmp" "$f"
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ 已补 concurrent。"
  else
    c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
  fi
}

# 旧装迁移: 给 mosdns 补"WDA/流媒体解锁支"(常驻、平时休眠)。pdg update 不重渲染 config, 故在此幂等补。
# 加 unlock_upstream(22.22.22.22) + geosite_unlock(读 unlock.txt) 两个插件 + main_sequence 一条
# "本机查询命中解锁域名→解锁DNS"的支(带 jump has_resp 防被 remote_upstream 覆盖)+ 建空 unlock.txt。
# 空 unlock.txt = 不命中任何域名 = 休眠, 不改变现有行为; bot『🔓 解锁走 WDA』开启时才填充。
migrate_mosdns_unlock(){
  local f=/etc/mosdns/config.yaml
  [[ -f "$f" ]] || return 0
  grep -q 'unlock_upstream' "$f" && return 0                   # 已有 → 跳过
  grep -q 'tag: main_sequence' "$f" || return 0               # 不是本项目的 mosdns 配置 → 不动
  c_g "给 mosdns 补 WDA 解锁支(常驻休眠, 不改现有行为)…"
  local bak; bak="$f.preunlock.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败, 中止。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  python3 - "$f" <<'PY' || { c_y "  生成失败, 中止(已留备份)。"; return 0; }
import sys
f=sys.argv[1]; s=open(f).read()
plug='''  - tag: unlock_upstream
    type: forward
    args: { concurrent: 1, upstreams: [ {addr: "udp://22.22.22.22"} ] }
  - tag: geosite_unlock
    type: domain_set
    args: { files: ["/etc/mosdns/rules/unlock.txt"] }
  - tag: geosite_cn'''
assert s.count('  - tag: geosite_cn')==1
s=s.replace('  - tag: geosite_cn', plug, 1)
old='''      - matches: client_ip $npn_clients
        exec: goto internal_sequence
      - exec: $remote_upstream'''
new='''      - matches: client_ip $npn_clients
        exec: goto internal_sequence
      - matches: qname $geosite_unlock
        exec: $unlock_upstream
      - exec: jump has_resp
      - exec: $remote_upstream'''
assert old in s
open(f,'w').write(s.replace(old,new,1))
PY
  [[ -e /etc/mosdns/rules/unlock.txt ]] || : > /etc/mosdns/rules/unlock.txt
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ 已补解锁支(休眠)。bot『🌐 DNS 上游→🔓 解锁走 WDA』可启用。"
  else
    c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
  fi
}

# 老装迁移: 防火墙 853 对公网放行(安卓 Wi-Fi 私密 DNS) + 内网放行 5228-5230(GMS)。幂等。
# shellcheck disable=SC2120
migrate_fw_android_dot_gms(){
  local f="${1:-/etc/nftables.conf}"
  [[ -f "$f" ]] || return 0
  grep -q 'table inet pdg' "$f" || return 0
  if grep -qE 'tcp dport 853 accept' "$f" && grep -qE '5228' "$f"; then
    return 0
  fi
  c_g "检测到防火墙需补 853 公网 DoT / GMS 5228-5230 → 迁移…"
  local bak; bak="$f.preadot.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败, 中止。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  python3 - "$f" <<'PY'
import re, sys
path = sys.argv[1]
t = open(path).read()

def fix_portset(m):
    prefix, body, suffix = m.group(1), m.group(2), m.group(3)
    parts = [p.strip() for p in body.split(",") if p.strip() and p.strip() != "853"]
    if not any(p.startswith("5228") for p in parts):
        if "8445" in parts:
            parts.insert(parts.index("8445"), "5228-5230")
        else:
            parts.append("5228-5230")
    return prefix + ", ".join(parts) + suffix

t = re.sub(
    r"(ip saddr [0-9./]+ tcp dport \{\s*)([^}]+?)(\s*\} accept)",
    fix_portset, t, count=1)
if "tcp dport 853 accept" not in t:
    t = re.sub(r"(tcp dport \d+ accept\n)", r"\1        tcp dport 853 accept\n", t, count=1)
open(path, "w").write(t)
PY
  if ! nft -c -f "$f" >/dev/null 2>&1; then
    c_y "  nft -c 未过 → 还原。"; cp -a "$bak" "$f"; return 0
  fi
  if nft -f "$f" 2>/dev/null; then
    c_g "  ✅ 防火墙已补 853 公网 DoT / GMS 端口(若适用)。"
  else
    c_y "  加载失败 → 还原。"; cp -a "$bak" "$f"
  fi
}

migrate_mosdns_whatsapp(){
  local conf="/etc/mosdns/config.yaml"
  local rules="/etc/mosdns/rules"
  local repo="${REPO_DIR:-/opt/privdns-gateway}"
  [[ -f "$conf" ]] || return 0
  mkdir -p "$rules"
  if [[ ! -f "$rules/whatsapp.txt" ]]; then
    if [[ -f "$repo/deploy/mosdns/rules/whatsapp.txt" ]]; then
      install -m644 "$repo/deploy/mosdns/rules/whatsapp.txt" "$rules/whatsapp.txt"
    else
      printf '%s\n' 'domain:whatsapp.com' 'domain:whatsapp.net' 'domain:whatsapp.biz' \
        'domain:wa.me' 'full:g.whatsapp.net' 'full:v.whatsapp.net' > "$rules/whatsapp.txt"
    fi
    c_g "已写入 $rules/whatsapp.txt"
  fi
  grep -q 'geosite_wa' "$conf" && return 0
  grep -q 'black_hole' "$conf" || return 0
  c_g "检测到 mosdns 缺 WhatsApp 真实 IP 分支 → 补 geosite_wa…"
  local bak; bak="$conf.prewa.$(date +%s)"
  cp -a "$conf" "$bak" || return 0
  if ! python3 - "$conf" <<'PY'
import sys
p = sys.argv[1]
t = open(p).read()
if "geosite_wa" in t:
    raise SystemExit(0)
plugin = '''  - tag: geosite_wa
    type: domain_set
    args: { files: ["/etc/mosdns/rules/whatsapp.txt"] }
'''
j = t.find("  - tag: npn_clients")
if j < 0:
    j = t.find("  - tag: ecs_china")
if j < 0:
    raise SystemExit("no insert point")
t = t[:j] + plugin + t[j:]
wa_branch = '''      - matches: qname $geosite_wa
        exec: $ecs_neutral
      - matches: qname $geosite_wa
        exec: $remote_upstream
      - exec: jump has_resp
'''
bh = "      - matches: qtype 1\n        exec: black_hole"
if "geosite_wa" in t and "qname $geosite_wa" not in t.split("black_hole")[0][-500:]:
    if bh not in t:
        raise SystemExit("black_hole not found")
    t = t.replace(bh, wa_branch + bh, 1)
open(p, "w").write(t)
PY
  then
    c_y "  改写失败 → 还原。"; cp -a "$bak" "$conf"; return 0
  fi
  systemctl restart mosdns 2>/dev/null || true
  sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ mosdns WhatsApp 真实 IP 分支已启用。"
  else
    c_y "  mosdns 未起来 → 还原。"; cp -a "$bak" "$conf"
    systemctl restart mosdns 2>/dev/null || true
  fi
}

SNAP_DIR="/var/lib/privdns-gateway/backups"
_PDG_SNAP_CREATED=""

_pdg_wait_active(){
  local service="$1" attempts="${2:-6}" attempt
  for ((attempt = 0; attempt < attempts; attempt++)); do
    [[ "$(systemctl is-active "$service" 2>/dev/null)" == active ]] && return 0
    sleep 0.5
  done
  return 1
}

_pdg_apply_snapshot_tree(){
  local tree="$1" archive="$2"
  tar -C "$tree" -cf "$archive" . && tar -xf "$archive" -C /
}

cmd_snapshot(){
  need_root snapshot; _lock
  _PDG_SNAP_CREATED=""
  local ts d archive temporary path
  local -a candidates items
  ts=$(date +%Y%m%d-%H%M%S); d="$SNAP_DIR/$ts"
  install -d -m700 "$d" || { c_y "❌ 无法创建快照目录"; return 1; }
  # Include every file an update can replace, not only live configuration. A
  # rollback must restore the old program, unit files, and certificate hooks too.
  candidates=(
    etc/mosdns etc/mihomo etc/pdg-relay etc/privdns-gateway etc/nftables.conf
    opt/pdg-bot opt/pdg-relay opt/privdns-gateway var/lib/pdg-wloc
    etc/systemd/system/pdg-bot.service
    etc/systemd/system/pdg-probe81.service
    etc/systemd/system/pdg-wloc.service
    etc/systemd/system/pdg-relay.service
    etc/systemd/system/mosdns.service
    etc/systemd/system/mihomo.service
    etc/systemd/system/pdg-rules-update.service
    etc/systemd/system/pdg-rules-update.timer
    etc/systemd/system/pdg-health.service
    etc/systemd/system/pdg-health.timer
    etc/systemd/system/journald.conf.d/50-pdg.conf
    etc/systemd/journald.conf.d/50-pdg.conf
    etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
    usr/local/bin/pdg
    usr/local/bin/pdg-set-token
    usr/local/bin/pdg-mihomo-tproxy.sh
    usr/local/bin/pdg-relay-tproxy.sh
    usr/local/bin/pdg-relayctl
    usr/local/bin/proxy-gateway-open-cert-http.sh
    usr/local/bin/proxy-gateway-restore-firewall.sh
  )
  for path in "${candidates[@]}"; do
    [[ -e "/$path" ]] && items+=("$path")
  done
  [[ ${#items[@]} -gt 0 ]] || { c_y "❌ 没有可快照的 PrivDNS 文件"; rmdir "$d" 2>/dev/null; return 1; }
  archive="$d/snap.tar.gz"; temporary="$archive.tmp"
  if ! tar czf "$temporary" -C / "${items[@]}" 2>/dev/null \
      || [[ ! -s "$temporary" ]] \
      || ! chmod 600 "$temporary" \
      || ! mv -f "$temporary" "$archive"; then
    c_y "❌ 快照打包失败"
    rm -f "$temporary" "$archive"; rmdir "$d" 2>/dev/null
    return 1
  fi
  _PDG_SNAP_CREATED="$d"
  echo "✅ 快照: $archive"
  ls -1dt "$SNAP_DIR"/*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf   # 只留最近 10 份
}

cmd_rollback(){
  need_root rollback; _lock
  local idx="" dir="" git_ref="" target f tmp tree members restore_archive relay_wanted=0
  local relay_snapshot_present=0
  local i path
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir)
        [[ $# -ge 2 && -n "${2:-}" ]] || { echo "--dir 缺少快照目录"; return 1; }
        dir="$2"; shift 2;;
      --git)
        [[ $# -ge 2 && -n "${2:-}" ]] || { echo "--git 缺少提交引用"; return 1; }
        git_ref="$2"; shift 2;;
      *)
        [[ -z "$idx" ]] || { echo "只接受一个快照序号"; return 1; }
        idx="$1"; shift;;
    esac
  done
  if [[ -n "$dir" ]]; then
    target="$dir"
    [[ -d "$target" ]] || { echo "指定快照目录不存在: $target"; return 1; }
  else
    local snaps; mapfile -t snaps < <(ls -1dt "$SNAP_DIR"/*/ 2>/dev/null)
    [[ ${#snaps[@]} -gt 0 ]] || { echo "没有快照(先 pdg snapshot)"; return 1; }
    echo "可用快照(新→旧):"; i=0; for path in "${snaps[@]}"; do echo "  [$i] $(basename "$path")"; i=$((i+1)); done
    idx="${idx:-0}"
    [[ "$idx" =~ ^[0-9]+$ ]] || { echo "无效序号 $idx"; return 1; }
    idx=$((10#$idx))
    (( idx >= ${#snaps[@]} )) && { echo "无效序号 $idx"; return 1; }
    target="${snaps[$idx]}"
  fi
  f="$target/snap.tar.gz"
  [[ -f "$f" ]] || { echo "快照文件缺失: $f"; return 1; }
  # Read and validate the archive into a temporary tree before touching the
  # running system. Only project-owned paths may be restored.
  tmp=$(mktemp -d) || { echo "❌ 无法创建回滚临时目录"; return 1; }
  tree="$tmp/tree"; members="$tmp/members"; restore_archive="$tmp/restore.tar"
  if ! mkdir -p "$tree" \
      || ! tar tzf "$f" > "$members" 2>/dev/null \
      || [[ ! -s "$members" ]]; then
    echo "❌ 快照目录或成员清单读取失败, 中止"; rm -rf "$tmp"; return 1
  fi
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$members" \
      || grep -Evq '^(etc|opt|usr/local/bin|var/lib/pdg-wloc)(/|$)' "$members"; then
    echo "❌ 快照含越界或非 PrivDNS 路径, 中止"; rm -rf "$tmp"; return 1
  fi
  if ! tar xzf "$f" -C "$tree" 2>/dev/null; then
    echo "❌ 快照解包失败, 中止"; rm -rf "$tmp"; return 1
  fi
  if [[ -f "$tree/etc/privdns-gateway/relay.json" ]] \
      && jq -e '.enabled == true' "$tree/etc/privdns-gateway/relay.json" >/dev/null 2>&1; then
    relay_wanted=1
  fi
  if [[ -e "$tree/etc/privdns-gateway/relay.json" \
      || -e "$tree/etc/systemd/system/pdg-relay.service" \
      || -e "$tree/usr/local/bin/pdg-relayctl" \
      || -e "$tree/opt/pdg-relay" ]]; then
    relay_snapshot_present=1
  fi
  if [[ -f "$tree/etc/mihomo/config.yaml" ]]; then
    mihomo -t -d "$tree/etc/mihomo" -f "$tree/etc/mihomo/config.yaml" >/dev/null 2>&1 \
      || { echo "❌ 快照的 mihomo 配置 test 失败, 中止"; rm -rf "$tmp"; return 1; }
  fi
  [[ -f "$tree/etc/nftables.conf" ]] \
    && { nft -c -f "$tree/etc/nftables.conf" >/dev/null 2>&1 \
      || { echo "❌ 快照的 nftables 语法错, 中止"; rm -rf "$tmp"; return 1; }; }
  echo "回滚到 $(basename "$target") …"
  if ! _pdg_apply_snapshot_tree "$tree" "$restore_archive"; then
    echo "❌ 快照落盘失败，系统可能处于部分恢复状态"; rm -rf "$tmp"; return 1
  fi
  rm -rf "$tmp"
  systemctl daemon-reload
  local -a unrestored=()
  if [[ -f /etc/nftables.conf ]] && ! nft -f /etc/nftables.conf >/dev/null 2>&1; then
    unrestored+=(nftables)
  fi
  if ! systemctl restart mosdns >/dev/null 2>&1 || ! _pdg_wait_active mosdns; then
    unrestored+=(mosdns)
  fi
  if ! systemctl restart mihomo >/dev/null 2>&1 || ! _pdg_wait_active mihomo; then
    unrestored+=(mihomo)
  fi
  systemctl try-restart pdg-bot pdg-probe81 >/dev/null 2>&1 || unrestored+=(bot_or_probe)
  if jq -e '.enabled == true' /var/lib/pdg-wloc/wloc.json >/dev/null 2>&1 \
    || { jq -e '.enabled == true' /var/lib/pdg-wloc/adblock.json >/dev/null 2>&1 \
         && jq -e '.stats.host_count > 0' /var/lib/pdg-wloc/adblock-rules.json >/dev/null 2>&1; }; then
    if ! systemctl reset-failed pdg-wloc >/dev/null 2>&1 \
        || ! systemctl enable --now pdg-wloc >/dev/null 2>&1 \
        || ! _pdg_wait_active pdg-wloc; then
      unrestored+=(pdg-wloc)
    fi
  else
    systemctl disable --now pdg-wloc >/dev/null 2>&1 || unrestored+=(pdg-wloc)
  fi
  if [[ "$relay_wanted" == 1 ]]; then
    if ! systemctl reset-failed pdg-relay >/dev/null 2>&1 \
        || ! systemctl enable --now pdg-relay >/dev/null 2>&1 \
        || ! _pdg_wait_active pdg-relay; then
      unrestored+=(pdg-relay)
    fi
  else
    if [[ -x /usr/local/bin/pdg-relayctl ]]; then
      /usr/local/bin/pdg-relayctl disable >/dev/null 2>&1 || unrestored+=(pdg-relay)
    else
      systemctl disable --now pdg-relay >/dev/null 2>&1 || true
      /usr/local/bin/pdg-relay-tproxy.sh down >/dev/null 2>&1 || true
    fi
  fi
  # Overlay extraction cannot remove files introduced after an old snapshot.
  # If that snapshot predates Relay, remove the dormant component as well as
  # its routes so rollback restores the original software surface exactly.
  if [[ "$relay_snapshot_present" == 0 ]]; then
    systemctl disable --now pdg-relay >/dev/null 2>&1 || true
    /usr/local/bin/pdg-relay-tproxy.sh down >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/pdg-relay.service \
      /usr/local/bin/pdg-relayctl /usr/local/bin/pdg-relay-tproxy.sh \
      /etc/privdns-gateway/relay.json
    rm -rf /etc/pdg-relay /opt/pdg-relay
    userdel pdg-relay >/dev/null 2>&1 || true
    groupdel pdg-relay >/dev/null 2>&1 || true
    systemctl daemon-reload
  fi
  if [[ -n "$git_ref" ]]; then
    if [[ -d "$REPO_DIR/.git" ]] && git -C "$REPO_DIR" reset --hard -q "$git_ref" 2>/dev/null; then
      c_g "  仓库已复位到 ${git_ref:0:12}"
    else
      unrestored+=(repository_git)
    fi
  fi
  if [[ ${#unrestored[@]} -gt 0 ]]; then
    c_y "⚠️ 已恢复快照，但以下项目未完全恢复: ${unrestored[*]}"
    return 1
  fi
  echo "✅ 已回滚并重启服务"
}

cmd_update(){
  need_root update
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  if [[ "${1:-}" == "--dry-run" ]]; then
    [[ -d "$REPO_DIR/.git" ]] && pdg_fetch_release_tags "$REPO_DIR" 2>/dev/null
    local tgt; tgt=$(git -C "$REPO_DIR" tag -l 'v*' --sort=-v:refname 2>/dev/null | head -1)
    echo "当前: $(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)   最新发布: ${tgt:-(无 tag)}"
    local current
    current=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null || true)
    if [[ -n "$current" && -n "$tgt" ]] \
        && ! git -C "$REPO_DIR" merge-base --is-ancestor "$current" "$tgt" 2>/dev/null; then
      c_y "⚠️ 最新 tag 不是当前代码的后继版本；拒绝自动降级。请先发布当前代码的新版 tag。"
    fi
    [[ -n "$tgt" ]] && { echo "待更新提交(HEAD..$tgt):"; git -C "$REPO_DIR" --no-pager log --oneline "HEAD..$tgt" 2>/dev/null || echo "  (已是最新或无法比较)"; }
    return 0
  fi
  _lock
  c_g "拉取最新发布 tag…"
  [[ -d "$REPO_DIR/.git" ]] || { rm -rf "$REPO_DIR"; git clone -q "$REPO_URL" "$REPO_DIR"; }
  if ! pdg_fetch_release_tags "$REPO_DIR"; then
    c_y "拉取发布 tag 失败, 中止更新。"; return 1
  fi
  local tgt pre_sha snap_dir
  tgt=$(git -C "$REPO_DIR" tag -l 'v*' --sort=-v:refname | head -1)
  if [[ -z "$tgt" ]]; then
    c_y "仓库没有发布 tag(v*), 中止更新。"; return 1
  fi
  pre_sha=$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null) \
    || { c_y "无法读取当前代码提交，拒绝更新。"; return 1; }
  if ! git -C "$REPO_DIR" merge-base --is-ancestor "$pre_sha" "$tgt" 2>/dev/null; then
    c_y "最新发布 $tgt 不是当前 ${pre_sha:0:12} 的后继版本，拒绝自动降级。"
    c_y "请先完成当前代码的测试并发布新的 v* tag，再运行 pdg update。"
    return 1
  fi
  _PDG_SNAP_CREATED=""
  c_g "更新前留快照…"
  if ! cmd_snapshot >/dev/null 2>&1 \
      || [[ -z "$_PDG_SNAP_CREATED" || ! -s "$_PDG_SNAP_CREATED/snap.tar.gz" ]]; then
    c_y "❌ 更新前快照失败，拒绝在无法精确回滚的前提下继续。"
    return 1
  fi
  snap_dir="$_PDG_SNAP_CREATED"
  local -a rollback_args=(--dir "$snap_dir" --git "$pre_sha")
  if ! git -C "$REPO_DIR" reset --hard -q "$tgt"; then
    c_y "切换到发布 $tgt 失败，回滚到更新前快照…"
    cmd_rollback "${rollback_args[@]}"
    return 1
  fi
  c_g "→ 已切到发布 $tgt"
  c_g "刷新代码(配置/出口/token/证书均不动)…"
  install -m755 "$REPO_DIR"/deploy/bot/pdg-bot.py           /opt/pdg-bot/bot.py
  install -m755 "$REPO_DIR"/deploy/bot/parse-geosite.py     /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/parse-chinamax.py    /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/compile-china-rules.py /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/update-rules.sh      /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/scheduled-update.sh  /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/healthcheck.py      /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/checks.py           /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/doctor.py           /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/report.py           /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/ios/probe81.py           /opt/pdg-bot/
  if ! command -v mitmdump >/dev/null; then
    c_g "安装共享 MITM sidecar 依赖 mitmproxy…"
    if ! apt-get update -qq \
      || ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mitmproxy >/dev/null; then
      c_y "mitmproxy 安装失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  fi
  id -u pdg-wloc >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pdg-wloc --shell /usr/sbin/nologin pdg-wloc
  install -d -m755 /var/lib/pdg-wloc
  install -d -o pdg-wloc -g pdg-wloc -m700 /var/lib/pdg-wloc/mitmproxy
  [[ -f /var/lib/pdg-wloc/wloc.json ]] \
    || install -o pdg-wloc -g pdg-wloc -m600 "$REPO_DIR"/deploy/wloc/wloc.json /var/lib/pdg-wloc/wloc.json
  [[ -f /var/lib/pdg-wloc/adblock.json ]] \
    || install -o pdg-wloc -g pdg-wloc -m600 "$REPO_DIR"/deploy/mitm/adblock.json /var/lib/pdg-wloc/adblock.json
  [[ -f /etc/mosdns/rules/wloc.txt ]] || install -m644 /dev/null /etc/mosdns/rules/wloc.txt
  [[ -f /etc/mosdns/rules/adblock.txt ]] || install -m644 /dev/null /etc/mosdns/rules/adblock.txt
  [[ -f /etc/mosdns/rules/force_proxy.txt ]] || install -m644 /dev/null /etc/mosdns/rules/force_proxy.txt
  install -d -m700 /etc/privdns-gateway
  [[ -f /etc/privdns-gateway/wloc-presets.json ]] \
    || install -m600 "$REPO_DIR"/deploy/wloc/wloc-presets.json /etc/privdns-gateway/wloc-presets.json
  [[ -f /etc/privdns-gateway/adblock-sources.json ]] \
    || install -m600 "$REPO_DIR"/deploy/mitm/adblock-sources.json /etc/privdns-gateway/adblock-sources.json
  [[ -f /etc/privdns-gateway/relay.json ]] \
    || install -m600 "$REPO_DIR"/deploy/relay/relay.json /etc/privdns-gateway/relay.json
  install -m755 "$REPO_DIR"/deploy/wloc/wloc_mitm.py        /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/wloc/migrate_wloc.py     /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/mitm/adblock_mitm.py     /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/mitm/sync_adblock.py     /opt/pdg-bot/
  if ! python3 /opt/pdg-bot/sync_adblock.py \
      --sources /etc/privdns-gateway/adblock-sources.json \
      --merge-defaults "$REPO_DIR"/deploy/mitm/adblock-sources.json --merge-only; then
    c_y "去广告规则源迁移失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  if ! python3 /opt/pdg-bot/sync_adblock.py \
      --sources /etc/privdns-gateway/adblock-sources.json --pin-missing-modules; then
    c_y "现有 MITM 插件初始 SHA256 固定失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  install -m644 "$REPO_DIR"/deploy/wloc/pdg-wloc.service    /etc/systemd/system/
  if ! python3 /opt/pdg-bot/migrate_wloc.py /etc/mosdns/config.yaml; then
    c_y "mosdns 共享 MITM 分支迁移失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.service  /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.timer    /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/bot/pdg-rules-update.service /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/bot/pdg-rules-update.timer   /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl /opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  install -m644 "$REPO_DIR"/deploy/mosdns/rules/whatsapp.txt /etc/mosdns/rules/whatsapp.txt 2>/dev/null || true
  install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-open-cert-http.sh   /usr/local/bin/
  install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-restore-firewall.sh /usr/local/bin/
  install -m755 "$REPO_DIR"/deploy/cert/99-reload-cert.deploy-hook.sh     /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  install -m755 "$REPO_DIR"/deploy/mihomo/pdg-mihomo-tproxy.sh            /usr/local/bin/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/mihomo/mihomo.service                  /etc/systemd/system/ 2>/dev/null || true
  install -m755 "$REPO_DIR"/deploy/relay/pdg-relay-tproxy.sh              /usr/local/bin/
  install -m755 "$REPO_DIR"/deploy/relay/pdg-relayctl.py                  /usr/local/bin/pdg-relayctl
  install -m644 "$REPO_DIR"/deploy/relay/pdg-relay.service                /etc/systemd/system/
  install -m755 "$REPO_DIR"/deploy/bot/pdg-set-token.sh     /usr/local/bin/pdg-set-token
  install -m755 "$REPO_DIR"/deploy/bot/pdg.sh               /usr/local/bin/pdg
  migrate_botenv            # 老装: token 从 unit 迁到 bot.env
  migrate_firewall_to_pdg   # 老装: 防火墙 inet filter → 独立表 inet pdg(否则证书续期开不了 80)
  migrate_fw_local_service_bypass # 老装: 本机探测/Telegram 入口不能被 TPROXY 截走
  migrate_fw_quic_fast_reject # 老装: UDP/443 静默 drop 会让部分 App 无法回落 TCP
  migrate_fw_android_dot_gms  # 老装: 853 公网 DoT(安卓 Wi-Fi) + GMS 5228-5230
  migrate_mosdns_whatsapp     # 老装: WhatsApp 无 SNI 返回真实 IP

  if jq -e '.enabled == true' /var/lib/pdg-wloc/adblock.json >/dev/null 2>&1; then
    if ! python3 /opt/pdg-bot/sync_adblock.py; then
      c_y "去广告规则同步失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  fi
  if [[ -f /etc/mosdns/rules/ChinaMax.list ]]; then
    if ! python3 /opt/pdg-bot/compile-china-rules.py \
        /etc/mosdns/rules/ChinaMax.list /etc/mihomo/rs \
        --converter /usr/local/bin/mihomo; then
      c_y "ChinaMax MRS 编译失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  elif jq -e '.enabled == true' /etc/privdns-gateway/relay.json >/dev/null 2>&1; then
    c_y "Relay 已启用但缺少 ChinaMax.list, 拒绝让国内流量落入默认国际出口。"
    cmd_rollback "${rollback_args[@]}"; return 1
  fi
  if ! python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("pdg_bot", "/opt/pdg-bot/bot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)
bot._write(bot.load())
bot._wloc_write_domains(bot._wloc_active())
bot._adblock_write_domains(bot._adblock_active())
PY
  then
    c_y "共享 MITM 路由渲染失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi

  # ── 更新后校验门: 任一硬校验失败即回滚到更新前快照 ──
  c_g "校验新版本…"
  if ! python3 -m py_compile /opt/pdg-bot/*.py /usr/local/bin/pdg-relayctl 2>/dev/null; then
    c_y "Python 语法错误, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  if ! mihomo -t -d /etc/mihomo >/dev/null 2>&1; then
    c_y "mihomo 配置 test 失败, 回滚…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
    c_y "nftables 配置 check 失败, 回滚…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  local relay_enabled=0
  if jq -e '.enabled == true' /etc/privdns-gateway/relay.json >/dev/null 2>&1; then
    relay_enabled=1
    if ! /usr/local/bin/pdg-relayctl ensure-envoy \
        || ! /usr/local/bin/pdg-relayctl sync-cert \
        || ! /usr/local/bin/pdg-relayctl validate; then
      c_y "Relay 更新后校验失败, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  fi
  systemctl daemon-reload
  systemctl enable --now pdg-health.timer >/dev/null 2>&1 || true   # 老装升级时补上健康自检
  if jq -e '.enabled == true' /var/lib/pdg-wloc/wloc.json >/dev/null 2>&1 \
    || { jq -e '.enabled == true' /var/lib/pdg-wloc/adblock.json >/dev/null 2>&1 \
         && jq -e '.stats.host_count > 0' /var/lib/pdg-wloc/adblock-rules.json >/dev/null 2>&1; }; then
    systemctl enable pdg-wloc >/dev/null 2>&1 || true
    if ! systemctl restart pdg-wloc \
      || ! _pdg_wait_active pdg-wloc; then
      c_y "共享 MITM 更新后起不来, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  else
    systemctl disable --now pdg-wloc >/dev/null 2>&1 || true
  fi
  if ! systemctl restart mosdns mihomo 2>/dev/null \
      || ! _pdg_wait_active mosdns \
      || ! _pdg_wait_active mihomo; then
    c_y "核心服务更新后未稳定运行, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi
  if [[ "$relay_enabled" == 1 ]]; then
    if ! systemctl enable --now pdg-relay >/dev/null 2>&1 \
        || ! systemctl restart pdg-relay \
        || ! _pdg_wait_active pdg-relay; then
      c_y "Relay 更新后未稳定运行, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
    fi
  else
    systemctl disable --now pdg-relay >/dev/null 2>&1 || true
    /usr/local/bin/pdg-relay-tproxy.sh down >/dev/null 2>&1 || true
  fi
  systemctl try-restart pdg-bot pdg-probe81 >/dev/null 2>&1 || true

  # token 是否已配置(未配则 pdg-bot 不在跑属正常, 不据此回滚)
  local token_set=0
  [[ -f "$ENVF" ]] && grep -qE '^PDG_BOT_TOKEN=.+' "$ENVF" && grep -qE '^PDG_BOT_ALLOWED=.+' "$ENVF" && token_set=1
  if [[ "$token_set" == 1 && "$(systemctl is-active pdg-bot 2>/dev/null)" != "active" ]]; then
    c_y "pdg-bot 更新后起不来, 回滚到更新前快照…"; cmd_rollback "${rollback_args[@]}"; return 1
  fi

  # doctor 自检: 有 fail 回滚, warn 仅提示 (未配 token 时把"服务: 未运行: pdg-bot"这单一项排除, 避免误判)
  local j fails warns
  j=$(python3 /opt/pdg-bot/doctor.py --json 2>/dev/null || true)
  if [[ -n "$j" ]] && command -v jq >/dev/null; then
    fails=$(echo "$j" | jq -r --argjson t "$token_set" \
      '[ .[] | select(.level=="fail")
            | select( ($t==1) or (.check!="服务") or (.detail!="未运行: pdg-bot") ) ] | length' 2>/dev/null)
    warns=$(echo "$j" | jq -r '[ .[] | select(.level=="warn") ] | length' 2>/dev/null)
    if [[ "${fails:-0}" -gt 0 ]]; then
      c_y "自检发现 $fails 项失败, 回滚到更新前快照:"
      echo "$j" | jq -r '.[] | select(.level=="fail") | "  ❌ \(.check): \(.detail)"'
      cmd_rollback "${rollback_args[@]}"; return 1
    fi
    [[ "${warns:-0}" -gt 0 ]] && { c_y "自检有 $warns 项警告(不回滚, 仅提示):"
      echo "$j" | jq -r '.[] | select(.level=="warn") | "  ⚠️ \(.check): \(.detail)"'; }
  fi
  c_g "✅ 已更新。"
}

cmd_token(){ need_root token; pdg-set-token; }   # 不 exec, 设完/取消都回菜单

cmd_restart(){
  need_root restart
  systemctl restart mosdns mihomo pdg-bot pdg-probe81 2>/dev/null
  systemctl try-restart pdg-wloc 2>/dev/null || true
  if jq -e '.enabled == true' /etc/privdns-gateway/relay.json >/dev/null 2>&1; then
    _pdg_wait_active pdg-relay 20 \
      || systemctl restart pdg-relay 2>/dev/null \
      || c_y "pdg-relay 重启失败，请看 pdg log"
  fi
  echo "已重启 mosdns / mihomo / pdg-bot / pdg-probe81 (启用中的 MITM / Relay 一并重启)"
}

cmd_log(){ journalctl -u pdg-bot -u mosdns -u mihomo -u pdg-wloc -u pdg-relay -n "${1:-40}" --no-pager -o cat; }

cmd_relay(){
  need_root relay
  [[ -x /usr/local/bin/pdg-relayctl ]] \
    || { echo "缺少 pdg-relayctl，请先运行 sudo pdg update"; return 1; }
  /usr/local/bin/pdg-relayctl "$@"
}

cmd_traffic(){ command -v vnstat >/dev/null && vnstat || echo "vnstat 未装: sudo apt install -y vnstat && systemctl enable --now vnstat"; }

cmd_report(){ need_root report; python3 /opt/pdg-bot/report.py "$@"; }

# 抓包识别内网卡来源段, 检测到与现配不符时可一键写回 mosdns+nftables 并重启(装完随时跑, 比装机时从容)。
cmd_detect_cidr(){
  need_root detect-cidr
  local dur="${1:-30}" sip det cur
  sip=$(grep -oE '"[0-9.]+/32"' /etc/mihomo/state.json 2>/dev/null | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  det=$(bash "$REPO_DIR/lib/detect-internal-range.sh" "$dur" "${sip:-本机IP}" || true)
  if [[ -z "$det" ]]; then
    c_y "没抓到。确认手机走内网卡(关 WiFi), 或云安全组放行入站 80/ICMP, 再重试。"; return 1
  fi
  cur=$(grep -oE 'ip saddr [0-9./]+' /etc/nftables.conf 2>/dev/null | head -1 | awk '{print $3}')
  echo "  检测到内网卡段: $det"
  echo "  当前配置:       ${cur:-未知}"
  [[ "$det" == "$cur" ]] && { c_g "✅ 与当前一致, 无需改动。"; return 0; }
  read -rp "把内网卡段 ${cur:-?} → $det 并应用(写 mosdns+nftables 并重启)? [y/N]: " yn
  [[ "$yn" == [yY] ]] || { echo "已取消, 未改动。"; return 0; }
  _lock; _PDG_SNAP_CREATED=""; c_g "先留快照…"
  if ! cmd_snapshot >/dev/null 2>&1 \
      || [[ -z "$_PDG_SNAP_CREATED" || ! -s "$_PDG_SNAP_CREATED/snap.tar.gz" ]]; then
    c_y "快照失败，拒绝修改内网卡段。"
    return 1
  fi
  local snap_dir="$_PDG_SNAP_CREATED"
  [[ -n "$cur" ]] && sed -i "s#${cur//./\\.}#$det#g" /etc/nftables.conf
  sed -i -E "s#(ips:[[:space:]]*\[[[:space:]]*\")[0-9./]+(\")#\1$det\2#" /etc/mosdns/config.yaml
  if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then c_y "nft 校验失败, 回滚…"; cmd_rollback --dir "$snap_dir"; return 1; fi
  nft -f /etc/nftables.conf
  systemctl restart mosdns; sleep 2
  _pdg_wait_active mosdns || { c_y "mosdns 重启异常, 回滚…"; cmd_rollback --dir "$snap_dir"; return 1; }
  c_g "✅ 内网卡段已更新为 $det 并重启 mosdns。"
}

cmd_ios(){
  need_root ios
  local TMPL=/opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  [[ -f "$TMPL" ]] || { echo "缺少 $TMPL, 先装好 PrivDNS Gateway"; return 1; }
  command -v qrencode >/dev/null || { c_g "装 qrencode…"; apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qrencode; }
  # 取 DoT 主机名(证书 CN)/ 公网 IP / 内网卡段
  local CERT=/etc/mosdns/certs/fullchain.pem; [[ -f /etc/dnsdist/certs/fullchain.pem ]] && CERT=/etc/dnsdist/certs/fullchain.pem
  local HOST IP CIDR
  HOST=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | grep -oE 'CN *= *[A-Za-z0-9.*-]+' | sed 's/.*= *//')
  IP=$(grep -oE '"[0-9.]+/32"' /etc/mihomo/state.json 2>/dev/null | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  [[ -n "$IP" ]] || IP=$(curl -fsSL --max-time 6 https://api.ipify.org)
  CIDR=$(grep -oE 'ip saddr [0-9./]+' /etc/nftables.conf 2>/dev/null | head -1 | awk '{print $3}')
  [[ -n "$HOST" && -n "$IP" && -n "$CIDR" ]] || { echo "信息不全 (HOST=$HOST IP=$IP CIDR=$CIDR)"; return 1; }

  local PORT=8443 TOK U1 U2 WWW URL
  TOK=$(openssl rand -hex 6)
  U1=$(cat /proc/sys/kernel/random/uuid | tr a-z A-Z); U2=$(cat /proc/sys/kernel/random/uuid | tr a-z A-Z)
  WWW=$(mktemp -d)
  sed -e "s/__DOT_HOST__/$HOST/g" -e "s/__JP_IP__/$IP/g" -e "s/__UUID1__/$U1/g" -e "s/__UUID2__/$U2/g" \
      "$TMPL" > "$WWW/$TOK.mobileconfig"
  URL="http://$IP:$PORT/$TOK.mobileconfig"

  local SRV=""
  trap 'kill "$SRV" 2>/dev/null; nft -f /etc/nftables.conf 2>/dev/null; rm -rf "$WWW"; trap - INT TERM' INT TERM
  nft insert rule inet pdg input ip saddr "$CIDR" tcp dport "$PORT" accept 2>/dev/null
  ( cd "$WWW" && timeout 600 python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1 ) &
  SRV=$!
  qrencode -o /opt/pdg-bot/ios-qr.png "$URL" 2>/dev/null || true
  echo
  c_g "用手机(走【内网卡/蜂窝】, 关 WiFi)扫下面二维码 → Safari 打开 → 安装描述文件:"
  echo; qrencode -t ANSIUTF8 "$URL"; echo
  echo "  链接: $URL"
  echo "  DoT:  $HOST   (PNG 已存 /opt/pdg-bot/ios-qr.png)"
  c_y "装好后按回车收尾(10 分钟自动收)…"
  read -t 600 -r _ || true
  kill "$SRV" 2>/dev/null
  nft -f /etc/nftables.conf 2>/dev/null   # 撤掉临时放行
  rm -rf "$WWW"
  echo "已关闭临时下载服务。"
}

cmd_uninstall(){
  need_root uninstall
  if [[ -f "$REPO_DIR/uninstall.sh" ]]; then bash "$REPO_DIR/uninstall.sh" "${1:-}"
  else c_y "没找到 $REPO_DIR/uninstall.sh, 先 pdg update 拉取仓库"; fi
}

menu(){
  while true; do
    echo; c_g "===== PrivDNS Gateway 管理 ====="
    echo "  1) 状态"
    echo "  2) 自检 (doctor)"
    echo "  3) 更新"
    echo "  4) 快照备份"
    echo "  5) 回滚"
    echo "  6) 设置/更换 Bot Token 与 TG ID"
    echo "  7) 重启服务"
    echo "  8) 日志"
    echo "  9) 流量 (vnstat)"
    echo " 10) iOS 描述文件"
    echo " 11) 诊断报告 (脱敏)"
    echo " 12) 识别内网卡段"
    echo " 13) 全设备 Apple Relay"
    echo " 14) 卸载"
    echo "  0) 退出"
    echo "  下次打开本菜单命令: pdg"
    printf "选择: "
    read -r c || exit 0
    case "$c" in
      1) cmd_status;;
      2) cmd_doctor;;
      3) cmd_update && exec /usr/local/bin/pdg menu;;
      4) cmd_snapshot;;
      5) read -rp "回滚到第几个快照(默认 0=最近, 回车确认): " i; cmd_rollback "${i:-0}";;
      6) cmd_token;;
      7) cmd_restart;;
      8) cmd_log 60;;
      9) cmd_traffic;;
      10) cmd_ios;;
      11) cmd_report;;
      12) cmd_detect_cidr;;
      13) echo "用法: pdg relay status|enable|disable|profile|rotate-token"
          cmd_relay status;;
      14) read -rp "卸载: 留空取消 / yes 仅卸载 / purge 连配置一起删: " x
         case "$x" in yes) cmd_uninstall;; purge) cmd_uninstall --purge;; *) echo "已取消";; esac;;
      0|q) exit 0;;
      *) echo "无效选择";;
    esac
  done
}

# 老装升级"自愈": 旧版 pdg update 跑的是旧脚本, 不会调用迁移 → 装上新 pdg.sh 后,
# 下一次以 root 运行"管理类"命令(update/restart/menu/…)时幂等自动迁移防火墙(已迁移则首个 grep 秒退)。
# 只读命令(status/doctor/log/traffic/report)与卸载不触发, 以保持"只读命令不写任何东西"的语义;
# 只跑只读命令的用户可显式 `sudo pdg migrate-fw` 迁移(且证书 hook/doctor 已兼容旧 inet filter, 不迁也能用)。
if [[ $EUID -eq 0 ]]; then
  case "${1:-menu}" in
    status|st|doctor|dr|log|logs|traffic|tr|report|uninstall|rm) : ;;   # 只读/卸载: 不迁移
    *) migrate_firewall_to_pdg || true; migrate_mosdns_concurrent || true; migrate_mosdns_unlock || true
       migrate_fw_quic_fast_reject || true; migrate_fw_android_dot_gms || true
       migrate_mosdns_whatsapp || true ;;   # 管理类命令才迁移
  esac
fi

case "${1:-menu}" in
  menu|"")       menu;;
  status|st)     cmd_status;;
  doctor|dr)     shift || true; cmd_doctor "${1:-}";;
  update|up)     shift || true; cmd_update "${1:-}";;
  migrate-fw)    need_root migrate-fw; migrate_firewall_to_pdg; migrate_fw_quic_fast_reject;;
  snapshot|snap) cmd_snapshot;;
  rollback)      shift || true; cmd_rollback "${1:-0}";;
  token)         cmd_token;;
  restart)       cmd_restart;;
  log|logs)      shift || true; cmd_log "${1:-40}";;
  traffic|tr)    cmd_traffic;;
  ios)           cmd_ios;;
  relay)         shift || true; cmd_relay "$@";;
  report)        shift || true; cmd_report "$@";;
  detect-cidr|cidr) shift || true; cmd_detect_cidr "${1:-}";;
  uninstall|rm)  shift || true; cmd_uninstall "${1:-}";;
  *) echo "用法: pdg [menu|status|doctor [--json|--deep]|update [--dry-run]|snapshot|rollback [n]|token|restart|log [n]|traffic|ios|relay <status|enable|disable|profile|rotate-token>|report [--redact-ip|--full]|detect-cidr|migrate-fw|uninstall [--purge]]";;
esac
