#!/usr/bin/env bash
# shellcheck disable=SC2034  # 本文件供 source, 变量在 install.sh / tests 里用
# ─────────────────────────────────────────────────────────────────────────────
# 单一可信源: 二进制版本 + 钉死 SHA256(供应链校验)。install.sh 与 tests/ 共用。
#
# 升级版本步骤:
#   1) 改下面的 *_VER;
#   2) 下载官方 release 重算: sha256sum mosdns-linux-<arch>.zip / sing-box-<ver>-linux-<arch>.tar.gz
#   3) 把 4 个哈希同步到 PDG_SHA256(amd64 + arm64)。
# 哈希取自上游官方 GitHub Release(信任锚 = 官方发布页),装机/测试时逐字节比对,不符即拒装。
# ─────────────────────────────────────────────────────────────────────────────
MOSDNS_VER="v5.3.4"
SINGBOX_VER="1.12.25"         # 必须 1.12.x —— 1.13 移除了 sniff_override_destination, 本网关会失效。1.12.25 = 当前 1.12.x 最高补丁版

# key = <name>-<arch>(arch: amd64 / arm64)
declare -A PDG_SHA256=(
  [mosdns-amd64]="3abcc73080789eb1ccca78dab5049b85ac1e9b8f865ab60158a527b77cd72e85"
  [mosdns-arm64]="82d80a1a21606fca0bc6b65ac6f90d30cff6bb4a19a6ab6a246cf247dbb78bc0"
  [singbox-amd64]="a1ec76e2b6b139eb747a1b1ebee7d14b8d4be5a833596cad8070a31ef960301f"
  [singbox-arm64]="719b76196c8b31efa636b2d8f669e314547e0da0a5ab38a75e1882d307bbd154"
)

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
