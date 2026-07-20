#!/usr/bin/env bash
# shellcheck disable=SC2034  # 本文件供 source, 变量在 install.sh / tests 里用
# ─────────────────────────────────────────────────────────────────────────────
# 单一可信源: 二进制版本 + 钉死 SHA256(供应链校验)。install.sh 与 tests/ 共用。
#
# 升级版本步骤:
#   1) 改下面的 *_VER;
#   2) 下载对应 release 重算: sha256sum mosdns-linux-<arch>.zip / mihomo-linux-<arch>-<ver>-<patch>.gz
#   3) 把 4 个哈希同步到 PDG_SHA256(amd64 + arm64)。
# mosdns 使用上游官方 Release；mihomo 使用锁定上游提交加仓库补丁的 Release。
# 两者都在装机/测试时逐字节比对，不符即拒装。
# ─────────────────────────────────────────────────────────────────────────────
MOSDNS_VER="v5.3.4"
MIHOMO_VER="1.19.27"
MIHOMO_PATCH_VER="pdg1"
MIHOMO_SOURCE_COMMIT="5184081ac327394d9e15fa5d5f9f4a61e723fd94"
MIHOMO_PATCH_BUILD_TIME="2026-07-20T03:00:00Z"
MIHOMO_RELEASE_REPO="gibaragibara/privdns-gateway-mihomo"
MIHOMO_RELEASE_TAG="mihomo-v${MIHOMO_VER}-${MIHOMO_PATCH_VER}"

PDG_SHA256_mosdns_amd64="3abcc73080789eb1ccca78dab5049b85ac1e9b8f865ab60158a527b77cd72e85"
PDG_SHA256_mosdns_arm64="82d80a1a21606fca0bc6b65ac6f90d30cff6bb4a19a6ab6a246cf247dbb78bc0"
PDG_SHA256_mihomo_amd64="4e248938113fcddf3187ff2d8d2f8ca0495b3a757c37d073c6669b8785af896f"
PDG_SHA256_mihomo_arm64="f78893e15818a3f23388c581b4ab05978677156b17059756c8b28fa49eba3037"

pdg_mihomo_url(){
  local arch="$1"
  printf 'https://github.com/%s/releases/download/%s/mihomo-linux-%s-v%s-%s.gz' \
    "$MIHOMO_RELEASE_REPO" "$MIHOMO_RELEASE_TAG" "$arch" "$MIHOMO_VER" "$MIHOMO_PATCH_VER"
}

pdg_sha256(){
  local key="${1//-/_}" var
  var="PDG_SHA256_${key}"
  eval "printf '%s' \"\${$var:-}\""
}

# pdg_verify_sha256 <文件> <期望hash> [名称]  → 不符返回非 0 并打印期望/实际
pdg_verify_sha256(){
  local file="$1" exp="$2" name="${3:-$1}" got
  if [[ -z "$exp" ]]; then
    echo "[x] 缺少 $name 的钉死 SHA256(lib/versions.sh 未覆盖该版本/架构)" >&2
    return 1
  fi
  got=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  if [[ "$got" != "$exp" ]]; then
    echo "[x] SHA256 校验失败: $name" >&2
    echo "    期望 $exp" >&2
    echo "    实际 ${got:-<空: 文件不存在或读不出>}" >&2
    return 1
  fi
  return 0
}
