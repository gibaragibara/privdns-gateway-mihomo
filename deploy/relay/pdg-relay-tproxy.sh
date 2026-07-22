#!/usr/bin/env bash
# Only Envoy's pdg-relay UID is returned to mihomo.  The legacy client-side
# 5GPN prerouting chain remains untouched and is still the rollback path.
set -euo pipefail

CONFIG=/etc/privdns-gateway/relay.json
STATE=/etc/mihomo/state.json
SERVICE_USER=pdg-relay
TABLE=10123
MARK=0x233
V6_OUTER_PREF=10121
V6_UID_PREF=10122

die(){ echo "pdg-relay-tproxy: $*" >&2; exit 1; }

down(){
  nft delete table inet pdg_relay 2>/dev/null || true
  while ip rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
  ip route flush table "$TABLE" 2>/dev/null || true
  while ip -6 rule del fwmark "$MARK" table "$TABLE" 2>/dev/null; do :; done
  while ip -6 rule del pref "$V6_OUTER_PREF" 2>/dev/null; do :; done
  while ip -6 rule del pref "$V6_UID_PREF" 2>/dev/null; do :; done
  ip -6 route flush table "$TABLE" 2>/dev/null || true
}

wait_mihomo(){
  local attempt
  for ((attempt = 0; attempt < 100; attempt++)); do
    if ss -lntH 2>/dev/null | grep -qE '(^|[[:space:]])[^[:space:]]*:7893[[:space:]]'; then
      return 0
    fi
    sleep 0.1
  done
  die "mihomo :7893 在 10 秒内未就绪"
}

up(){
  local check_only="${1:-0}" tmp port uid server_ip
  command -v jq >/dev/null || die "缺少 jq"
  [[ -r "$CONFIG" ]] || die "缺少 $CONFIG"
  port=$(jq -r '.listen_port // empty' "$CONFIG")
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1024 && port <= 65535 )) || die "Relay 端口无效"
  uid=$(id -u "$SERVICE_USER" 2>/dev/null) || die "缺少服务用户 $SERVICE_USER"
  server_ip=$(jq -r '
      [.route.rules[]? | select(.action == "reject") | .ip_cidr[]?
       | select(endswith("/32")) | split("/")[0]
       | select(test("^[0-9]+([.][0-9]+){3}$")) | select(startswith("127.") | not)]
      | first // empty' "$STATE")
  [[ -n "$server_ip" ]] || die "读不到本机公网 IP"
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' RETURN
  cat >"$tmp" <<EOF
table inet pdg_relay {
    # Mark only the Relay listener before the normal 5GPN prerouting TPROXY.
    # inet pdg then sees mark 1 and delivers the connection to Envoy unchanged.
    chain prerouting {
        type filter hook prerouting priority mangle - 10; policy accept;
        # Local Envoy upstream sockets are first marked in output, policy-routed
        # to lo, then transparently delivered to mihomo here. Linux only
        # supports the native nft tproxy statement in prerouting.
        meta mark $MARK meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:7893 counter accept
        meta mark $MARK meta l4proto { tcp, udp } tproxy ip6 to [::1]:7893 counter accept
        ip daddr $server_ip tcp dport $port counter meta mark set 1
    }

    # Mark Envoy's upstream sockets for a policy-route back through prerouting.
    # Their original destination stays unchanged for mihomo SNI/QUIC sniffing.
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark $MARK return
        # Outer HTTP/2 replies to the iPhone are also owned by pdg-relay. They
        # must leave normally; only Envoy's upstream sockets enter mihomo.
        meta skuid $uid tcp sport $port return
        meta skuid $uid ip daddr 127.0.0.0/8 return
        meta skuid $uid ip6 daddr ::1 return
        meta skuid $uid meta l4proto { tcp, udp } counter meta mark set $MARK
    }
}
EOF
  nft -c -f "$tmp" >/dev/null
  [[ "$check_only" == 1 ]] && return 0
  wait_mihomo
  nft delete table inet pdg_relay 2>/dev/null || true
  nft -f "$tmp"

  # A unique table/mark keeps this independent from mihomo's existing mark 1/table 100.
  ip rule show | grep -q "fwmark $MARK.*lookup $TABLE" \
    || ip rule add fwmark "$MARK" table "$TABLE"
  ip route replace local 0.0.0.0/0 dev lo table "$TABLE"
  ip -6 rule show | grep -q "fwmark $MARK.*lookup $TABLE" \
    || ip -6 rule add fwmark "$MARK" table "$TABLE"
  ip -6 route replace local ::/0 dev lo table "$TABLE"
  # A host without a native IPv6 default route rejects connect(2) before the
  # output mark can be applied. Route this UID's IPv6 sockets to lo on the
  # initial lookup; nft then marks and TPROXYs them into mihomo. Keep a higher
  # priority escape for future IPv6 clients connected to the outer listener.
  while ip -6 rule del pref "$V6_OUTER_PREF" 2>/dev/null; do :; done
  while ip -6 rule del pref "$V6_UID_PREF" 2>/dev/null; do :; done
  ip -6 rule add pref "$V6_OUTER_PREF" ipproto tcp sport "$port" table main
  ip -6 rule add pref "$V6_UID_PREF" uidrange "$uid-$uid" table "$TABLE"
}

case "${1:-}" in
  up) up ;;
  check) up 1 ;;
  down) down ;;
  *) echo "用法: $0 {up|check|down}" >&2; exit 2 ;;
esac
