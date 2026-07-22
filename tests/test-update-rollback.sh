#!/usr/bin/env bash
# Regression coverage for exact update snapshots and rollback selection.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
ok(){ echo "[OK]   $1"; pass=$((pass + 1)); }
bad(){ echo "[FAIL] $1" >&2; fail=$((fail + 1)); }

SNAP="$WORK/snaps"
mkdir -p "$SNAP"
mksnap(){
  local name="$1" marker="$2" dir
  dir="$SNAP/$name"
  mkdir -p "$dir/tree/etc/privdns-gateway"
  printf '%s\n' "$marker" > "$dir/tree/etc/privdns-gateway/snapid"
  tar czf "$dir/snap.tar.gz" -C "$dir/tree" etc
  rm -rf "$dir/tree"
}
mksnap A OLD
sleep 1
mksnap B NEW

REPO="$WORK/repo"
mkdir -p "$REPO"
(
  cd "$REPO"
  git init -q
  git config user.email test@example.invalid
  git config user.name test
  printf 'v1\n' > version
  git add version
  git commit -qm first
  printf 'v2\n' > version
  git add version
  git commit -qm second
)
GOOD_REF=$(git -C "$REPO" rev-parse HEAD~1)
HEAD_REF=$(git -C "$REPO" rev-parse HEAD)

sed -n '/^cmd_rollback(){/,/^}$/p' "$ROOT/deploy/bot/pdg.sh" > "$WORK/rollback.sh"
cat > "$WORK/harness.sh" <<EOF
SNAP_DIR="$SNAP"
REPO_DIR="$REPO"
need_root(){ :; }
_lock(){ :; }
c_g(){ :; }
c_y(){ printf '%s\n' "\$*"; }
systemctl(){ return 0; }
nft(){ return 0; }
jq(){ return 1; }
rm(){ printf 'rm %s\n' "$*" >> "$WORK/cleanup.log"; }
userdel(){ printf 'userdel %s\n' "$*" >> "$WORK/cleanup.log"; }
groupdel(){ printf 'groupdel %s\n' "$*" >> "$WORK/cleanup.log"; }
_pdg_wait_active(){ return 0; }
# macOS still ships Bash 3.2, while the production script uses Bash 4's
# mapfile. This small compatibility shim lets the sandbox exercise index 0.
mapfile(){
  [[ "\${1:-}" == -t ]] && shift
  local variable="\${1:?}" line index=0
  eval "\$variable=()"
  while IFS= read -r line; do
    eval "\$variable[\$index]=\\\$line"
    index=\$((index + 1))
  done
}
APPLIED="$WORK/applied"
_pdg_apply_snapshot_tree(){ cat "\$1/etc/privdns-gateway/snapid" > "\$APPLIED"; }
EOF

run_rollback(){
  bash -c 'source "$1"; source "$2"; shift 2; cmd_rollback "$@"' \
    -- "$WORK/harness.sh" "$WORK/rollback.sh" "$@"
}

out=$(run_rollback --dir "$SNAP/A" --git "$GOOD_REF")
if [[ "$(cat "$WORK/applied")" == OLD ]] \
    && [[ "$(git -C "$REPO" rev-parse HEAD)" == "$GOOD_REF" ]]; then
  ok "--dir 精确恢复指定旧快照，并复位 Git 提交"
else
  bad "--dir/Git 精确回滚失败: $out"
fi

git -C "$REPO" reset --hard -q "$HEAD_REF"
out=$(run_rollback 0)
if [[ "$(cat "$WORK/applied")" == NEW ]]; then
  ok "无 --dir 时仍恢复最新快照"
else
  bad "默认快照选择错误: $out"
fi

rc=0
out=$(run_rollback --dir "$SNAP/A" --git deadbeefdeadbeef) || rc=$?
if [[ "$rc" == 1 && "$out" == *"未完全恢复"* && "$(cat "$WORK/applied")" == OLD ]]; then
  ok "Git 恢复失败会报未完全恢复且不伪报成功"
else
  bad "Git 恢复失败处理错误: rc=$rc out=$out"
fi

script="$ROOT/deploy/bot/pdg.sh"
if grep -q '_PDG_SNAP_CREATED' "$script" \
    && grep -q 'opt/privdns-gateway' "$script" \
    && grep -q 'usr/local/bin/pdg-set-token' "$script" \
    && grep -q '更新前快照失败，拒绝' "$script" \
    && grep -q 'merge-base --is-ancestor "\$pre_sha" "\$tgt"' "$script" \
    && grep -q 'cmd_rollback "\${rollback_args\[@\]}"' "$script" \
    && grep -q 'relay_snapshot_present' "$script" \
    && grep -q 'rm -rf /etc/pdg-relay /opt/pdg-relay' "$script" \
    && ! grep -q 'cmd_rollback 0' "$script"; then
  ok "更新链路使用完整快照、前进式 tag 校验和精确回滚"
else
  bad "更新链路缺少快照/降级/精确回滚保护"
fi

echo "通过 ${pass}，失败 ${fail}"
[[ "$fail" == 0 ]]
