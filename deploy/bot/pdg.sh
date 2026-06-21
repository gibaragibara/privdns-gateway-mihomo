#!/usr/bin/env bash
# PrivDNS Gateway 管理命令。直接 `sudo pdg` 进菜单, 或 pdg <子命令>。
#   pdg [menu] | status | update | token | restart | log [n] | uninstall [--purge]
# 设计: 生命周期(装/更新/卸载/token/状态/日志)走这里; 出口/分流/DNS上游 走 Telegram bot。
set -uo pipefail
REPO_URL="https://github.com/misaka-cpu/privdns-gateway.git"
REPO_DIR="/opt/privdns-gateway"

c_g(){ echo -e "\033[1;32m$*\033[0m"; }
c_y(){ echo -e "\033[1;33m$*\033[0m"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "请用 root: sudo pdg $*"; exit 1; }; }

cmd_status(){
  c_g "== 服务 =="
  for s in mosdns sing-box pdg-bot pdg-probe81; do
    printf "  %-12s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
  echo "  timer        $(systemctl is-active pdg-rules-update.timer 2>/dev/null)"
  echo "  DoT 域名     $(cat /opt/pdg-bot/dot-domain 2>/dev/null || echo ?)"
  echo "  监听端口     $(ss -lntu 2>/dev/null | grep -oE ':(53|80|81|443|853|9090)\b' | sort -u | tr '\n' ' ')"
  if [[ -d "$REPO_DIR/.git" ]]; then echo "  代码版本     $(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null)"; fi
}

cmd_doctor(){ python3 /opt/pdg-bot/doctor.py "$@"; }

SNAP_DIR="/var/lib/privdns-gateway/backups"

cmd_snapshot(){
  need_root snapshot
  local ts d; ts=$(date +%Y%m%d-%H%M%S); d="$SNAP_DIR/$ts"
  install -d -m700 "$d"
  # 整机配置 + 防火墙 + 含 token 的 service(相对 / 打包, 回滚直接 -C / 解开)
  tar czf "$d/snap.tar.gz" -C / \
    etc/mosdns etc/sing-box opt/pdg-bot \
    etc/nftables.conf etc/systemd/system/pdg-bot.service 2>/dev/null
  chmod 600 "$d/snap.tar.gz"
  echo "✅ 快照: $d/snap.tar.gz"
  ls -1dt "$SNAP_DIR"/*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf   # 只留最近 10 份
}

cmd_rollback(){
  need_root rollback
  local snaps; mapfile -t snaps < <(ls -1dt "$SNAP_DIR"/*/ 2>/dev/null)
  [[ ${#snaps[@]} -gt 0 ]] || { echo "没有快照(先 pdg snapshot)"; return 1; }
  echo "可用快照(新→旧):"; local i=0; for s in "${snaps[@]}"; do echo "  [$i] $(basename "$s")"; i=$((i+1)); done
  local idx="${1:-0}" target="${snaps[${1:-0}]}"
  [[ -n "$target" ]] || { echo "无效序号 $idx"; return 1; }
  local f="$target/snap.tar.gz"
  [[ -f "$f" ]] || { echo "快照文件缺失: $f"; return 1; }
  # 先校验快照里的 sing-box / nft 再动手(rule_set 路径临时指向解包目录)
  local tmp; tmp=$(mktemp -d); tar xzf "$f" -C "$tmp"
  if [[ -f "$tmp/etc/sing-box/config.json" ]]; then
    sed "s#/etc/sing-box/rs/#$tmp/etc/sing-box/rs/#g" "$tmp/etc/sing-box/config.json" > "$tmp/sb.chk"
    sing-box check -c "$tmp/sb.chk" >/dev/null 2>&1 || { echo "❌ 快照的 sing-box 配置 check 失败, 中止"; rm -rf "$tmp"; return 1; }
  fi
  [[ -f "$tmp/etc/nftables.conf" ]] && { nft -c -f "$tmp/etc/nftables.conf" >/dev/null 2>&1 || { echo "❌ 快照的 nftables 语法错, 中止"; rm -rf "$tmp"; return 1; }; }
  rm -rf "$tmp"
  echo "回滚到 $(basename "$target") …"
  tar xzf "$f" -C /
  systemctl daemon-reload
  nft -f /etc/nftables.conf 2>/dev/null || true
  systemctl restart mosdns sing-box pdg-bot pdg-probe81 2>/dev/null || true
  echo "✅ 已回滚并重启服务"
}

cmd_update(){
  need_root update
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  if [[ "${1:-}" == "--dry-run" ]]; then
    [[ -d "$REPO_DIR/.git" ]] && git -C "$REPO_DIR" fetch -q origin main 2>/dev/null
    echo "待更新的提交(HEAD..origin/main):"
    git -C "$REPO_DIR" log --oneline HEAD..origin/main 2>/dev/null || echo "  (已是最新, 或无法比较)"
    return 0
  fi
  c_g "更新前留快照…"; cmd_snapshot >/dev/null 2>&1 || true
  c_g "拉取最新代码…"
  if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" fetch -q origin main && git -C "$REPO_DIR" reset --hard -q origin/main
  else
    rm -rf "$REPO_DIR"; git clone -q --depth 1 "$REPO_URL" "$REPO_DIR"
  fi
  c_g "刷新代码(配置/出口/token/证书均不动)…"
  install -m755 "$REPO_DIR"/deploy/bot/pdg-bot.py           /opt/pdg-bot/bot.py
  install -m755 "$REPO_DIR"/deploy/bot/parse-geosite.py     /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/update-rules.sh      /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/scheduled-update.sh  /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/healthcheck.py      /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/checks.py           /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/doctor.py           /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/ios/probe81.py           /opt/pdg-bot/
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.service  /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.timer    /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl /opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-open-cert-http.sh   /usr/local/bin/
  install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-restore-firewall.sh /usr/local/bin/
  install -m755 "$REPO_DIR"/deploy/cert/99-reload-cert.deploy-hook.sh     /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  install -m755 "$REPO_DIR"/deploy/bot/pdg-set-token.sh     /usr/local/bin/pdg-set-token
  install -m755 "$REPO_DIR"/deploy/bot/pdg.sh               /usr/local/bin/pdg
  if ! python3 -m py_compile /opt/pdg-bot/bot.py 2>/dev/null; then
    c_y "新 bot.py 语法异常, 自动回滚到更新前快照…"; cmd_rollback 0; return 1
  fi
  systemctl daemon-reload
  systemctl enable --now pdg-health.timer >/dev/null 2>&1 || true   # 老装升级时补上健康自检
  systemctl restart pdg-bot pdg-probe81 2>/dev/null || true
  sleep 2
  if [[ "$(systemctl is-active pdg-bot 2>/dev/null)" != "active" ]]; then
    c_y "pdg-bot 更新后起不来, 自动回滚到更新前快照…"; cmd_rollback 0; return 1
  fi
  c_g "✅ 已更新。"
}

cmd_token(){ need_root token; pdg-set-token; }   # 不 exec, 设完/取消都回菜单

cmd_restart(){ need_root restart; systemctl restart mosdns sing-box pdg-bot pdg-probe81 2>/dev/null; echo "已重启 mosdns / sing-box / pdg-bot / pdg-probe81"; }

cmd_log(){ journalctl -u pdg-bot -u mosdns -u sing-box -n "${1:-40}" --no-pager -o cat; }

cmd_traffic(){ command -v vnstat >/dev/null && vnstat || echo "vnstat 未装: sudo apt install -y vnstat && systemctl enable --now vnstat"; }

cmd_ios(){
  need_root ios
  local TMPL=/opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  [[ -f "$TMPL" ]] || { echo "缺少 $TMPL, 先装好 PrivDNS Gateway"; return 1; }
  command -v qrencode >/dev/null || { c_g "装 qrencode…"; apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qrencode; }
  # 取 DoT 主机名(证书 CN)/ 公网 IP / 内网卡段
  local CERT=/etc/mosdns/certs/fullchain.pem; [[ -f /etc/dnsdist/certs/fullchain.pem ]] && CERT=/etc/dnsdist/certs/fullchain.pem
  local HOST IP CIDR
  HOST=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | grep -oE 'CN *= *[A-Za-z0-9.*-]+' | sed 's/.*= *//')
  IP=$(grep -oE '"[0-9.]+/32"' /etc/sing-box/config.json 2>/dev/null | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
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
  nft insert rule inet filter input ip saddr "$CIDR" tcp dport "$PORT" accept 2>/dev/null
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
    echo "  1) 状态        2) 自检(doctor)   3) 更新"
    echo "  4) 快照备份    5) 回滚            6) 设置/更换 token"
    echo "  7) 重启服务    8) 日志            9) 流量(vnstat)"
    echo " 10) iOS 描述文件   11) 卸载          0) 退出"
    read -rp "选择: " c || exit 0
    case "$c" in
      1) cmd_status;;
      2) cmd_doctor;;
      3) cmd_update;;
      4) cmd_snapshot;;
      5) read -rp "回滚到第几个快照(默认 0=最近, 回车确认): " i; cmd_rollback "${i:-0}";;
      6) cmd_token;;
      7) cmd_restart;;
      8) cmd_log 60;;
      9) cmd_traffic;;
      10) cmd_ios;;
      11) read -rp "卸载: 留空取消 / yes 仅卸载 / purge 连配置一起删: " x
         case "$x" in yes) cmd_uninstall;; purge) cmd_uninstall --purge;; *) echo "已取消";; esac;;
      0|q) exit 0;;
      *) echo "无效选择";;
    esac
  done
}

case "${1:-menu}" in
  menu|"")       menu;;
  status|st)     cmd_status;;
  doctor|dr)     shift || true; cmd_doctor "${1:-}";;
  update|up)     shift || true; cmd_update "${1:-}";;
  snapshot|snap) cmd_snapshot;;
  rollback)      shift || true; cmd_rollback "${1:-0}";;
  token)         cmd_token;;
  restart)       cmd_restart;;
  log|logs)      shift || true; cmd_log "${1:-40}";;
  traffic|tr)    cmd_traffic;;
  ios)           cmd_ios;;
  uninstall|rm)  shift || true; cmd_uninstall "${1:-}";;
  *) echo "用法: pdg [menu|status|doctor [--json]|update [--dry-run]|snapshot|rollback [n]|token|restart|log [n]|traffic|ios|uninstall [--purge]]";;
esac
