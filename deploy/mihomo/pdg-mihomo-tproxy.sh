#!/usr/bin/env bash
set -euo pipefail

case "${1:-up}" in
  up)
    ip rule add fwmark 1 table 100 2>/dev/null || true
    ip route replace local 0.0.0.0/0 dev lo table 100
    ;;
  down)
    while ip rule del fwmark 1 table 100 2>/dev/null; do :; done
    ip route flush table 100 2>/dev/null || true
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
