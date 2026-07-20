#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=../../lib/versions.sh
source "$ROOT/lib/versions.sh"

ARCH=${1:-amd64}
OUTPUT=${2:-"$PWD/mihomo-linux-${ARCH}-v${MIHOMO_VER}-${MIHOMO_PATCH_VER}"}
PATCH="$ROOT/deploy/mihomo/patches/0001-force-parse-pure-ip-sniffing.patch"

if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$PWD/$OUTPUT"
fi

case "$ARCH" in
  amd64) arch_env=(GOARCH=amd64 GOAMD64=v1) ;;
  arm64) arch_env=(GOARCH=arm64) ;;
  *) echo "usage: $0 [amd64|arm64] [output]" >&2; exit 2 ;;
esac

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v go >/dev/null || { echo "Go 1.26 or newer is required" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git clone --quiet --depth 1 --branch "v${MIHOMO_VER}" \
  https://github.com/MetaCubeX/mihomo.git "$work/mihomo"

actual=$(git -C "$work/mihomo" rev-parse HEAD)
if [[ "$actual" != "$MIHOMO_SOURCE_COMMIT" ]]; then
  echo "mihomo source commit mismatch: expected $MIHOMO_SOURCE_COMMIT, got $actual" >&2
  exit 1
fi

git -C "$work/mihomo" apply --unidiff-zero --check "$PATCH"
git -C "$work/mihomo" apply --unidiff-zero "$PATCH"
(cd "$work/mihomo" && go test ./component/sniffer)

mkdir -p "$(dirname "$OUTPUT")"
(
  cd "$work/mihomo"
  env GOOS=linux CGO_ENABLED=0 "${arch_env[@]}" \
    go build -buildvcs=false -tags with_gvisor -trimpath \
      -ldflags "-X github.com/metacubex/mihomo/constant.Version=v${MIHOMO_VER}-${MIHOMO_PATCH_VER} -X github.com/metacubex/mihomo/constant.BuildTime=${MIHOMO_PATCH_BUILD_TIME} -w -s -buildid=" \
      -o "$OUTPUT" .
)
chmod 0755 "$OUTPUT"
sha256sum "$OUTPUT" 2>/dev/null || shasum -a 256 "$OUTPUT"
