#!/usr/bin/env bash
# 卸载 PrivDNS Gateway (保留 certbot 证书与二进制; 加 --purge 一并删)。
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行"; exit 1; }

systemctl disable --now pdg-bot pdg-probe81 mosdns sing-box pdg-rules-update.timer pdg-health.timer 2>/dev/null || true
rm -f /etc/systemd/system/{pdg-bot,pdg-probe81,mosdns,sing-box,pdg-rules-update,pdg-health}.service \
      /etc/systemd/system/pdg-rules-update.timer /etc/systemd/system/pdg-health.timer \
      /etc/systemd/system/journald.conf.d/50-pdg.conf
systemctl daemon-reload

echo "已停止并移除 systemd 单元。防火墙规则仍在 /etc/nftables.conf — 如需恢复默认请自行处理。"
echo "保留: /etc/mosdns /etc/sing-box /opt/pdg-bot 与 Let's Encrypt 证书。"

if [[ "${1:-}" == "--purge" ]]; then
  echo "[--purge] 删除配置与数据…"
  rm -rf /etc/mosdns /etc/sing-box /opt/pdg-bot /etc/privdns-gateway   # /etc/privdns-gateway 含 bot.env(token)
  rm -f /usr/local/bin/mosdns /usr/local/bin/sing-box \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh \
        /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
  rm -rf /opt/privdns-gateway /var/lib/privdns-gateway   # 仓库副本 + 快照 (放最后, 脚本已载入内存, 删它安全)
  echo "已 purge。证书目录 /etc/letsencrypt 仍保留(含账户), 如需彻底清除请手动 certbot delete。"
fi
