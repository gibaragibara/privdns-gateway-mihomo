#!/bin/bash
# certbot --standalone pre-hook: 腾出 80 口 + 放行防火墙, 让 ACME HTTP-01 能验证。
# 注意: sing-box 占着 0.0.0.0:80, 必须先停它, 否则 certbot 绑不上 80 → 签发/续期都失败。
set -e
systemctl stop sing-box 2>/dev/null || true
if command -v nft >/dev/null 2>&1 && nft list table inet filter >/dev/null 2>&1; then
    nft insert rule inet filter input tcp dport 80 accept 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT 1 -p tcp --dport 80 -m comment --comment proxy-gateway-cert-http -j ACCEPT 2>/dev/null || true
fi
