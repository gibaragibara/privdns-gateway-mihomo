#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

eval "$(sed -n '/^_fw_render_quic_reject(){/,/^}/p' "$ROOT/deploy/bot/pdg.sh")"

base_config(){
  cat <<'EOF'
table inet pdg {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iif "lo" accept
    meta mark 1 accept
    PLACEHOLDER
    ip saddr 172.22.0.0/16 meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:7893 meta mark set 1
  }
}
EOF
}

# Legacy deployed form: preserve the line and only change the verdict.
base_config | sed 's#PLACEHOLDER#ip saddr 172.22.0.0/16 meta l4proto udp th dport 443 drop#' > "$WORK/drop.nft"
_fw_render_quic_reject "$WORK/drop.nft" 172.22.0.0/16 > "$WORK/drop.out"
grep -q 'meta l4proto udp th dport 443 reject' "$WORK/drop.out"
! grep -q 'dport 443 drop' "$WORK/drop.out"

# Older short form is migrated too.
base_config | sed 's#PLACEHOLDER#ip saddr 172.22.0.0/16 udp dport 443 drop#' > "$WORK/short.nft"
_fw_render_quic_reject "$WORK/short.nft" 172.22.0.0/16 > "$WORK/short.out"
grep -q 'udp dport 443 reject' "$WORK/short.out"
! grep -q 'dport 443 drop' "$WORK/short.out"

# Already-correct files are byte-for-byte unchanged.
base_config | sed 's#PLACEHOLDER#ip saddr 172.22.0.0/16 udp dport 443 reject#' > "$WORK/reject.nft"
_fw_render_quic_reject "$WORK/reject.nft" 172.22.0.0/16 > "$WORK/reject.out"
cmp -s "$WORK/reject.nft" "$WORK/reject.out"

# The short-lived QUIC-allowed template gets a reject directly before TPROXY.
base_config | sed '/PLACEHOLDER/d' > "$WORK/allowed.nft"
_fw_render_quic_reject "$WORK/allowed.nft" 172.22.0.0/16 > "$WORK/allowed.out"
reject_line=$(grep -n 'udp dport 443 reject' "$WORK/allowed.out" | cut -d: -f1)
tproxy_line=$(grep -n 'tproxy ip to 127.0.0.1:7893' "$WORK/allowed.out" | cut -d: -f1)
[[ -n "$reject_line" && "$reject_line" -lt "$tproxy_line" ]]

# Unknown files without the project TPROXY anchor fail closed.
printf 'table inet pdg { chain prerouting { accept } }\n' > "$WORK/unknown.nft"
if _fw_render_quic_reject "$WORK/unknown.nft" 172.22.0.0/16 > "$WORK/unknown.out"; then
  echo "expected unknown firewall rendering to fail" >&2
  exit 1
fi

grep -q 'ip saddr __INTERNAL_CIDR__ udp dport 443 reject' "$ROOT/deploy/firewall/nftables.conf"
grep -q 'migrate_fw_quic_fast_reject /etc/nftables.conf # 老装' "$ROOT/deploy/bot/pdg.sh"

echo "firewall QUIC fast-reject regression OK"
