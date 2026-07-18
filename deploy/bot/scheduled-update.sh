#!/usr/bin/env bash
# 定时刷新规则库: geosite + Surge 规则集 + 去广告 REJECT/MITM 来源。
# 由 pdg-rules-update.timer 每日触发。失败不致命, 保留旧规则。
set -uo pipefail
/bin/bash /opt/pdg-bot/update-rules.sh || echo "geosite 更新失败, 保留旧库"
# 空 token 前缀: 只导入 bot 模块刷规则集, 不需要也不连 Telegram
# shellcheck disable=SC1007
cd /opt/pdg-bot && PDG_BOT_TOKEN= /usr/bin/python3 -c \
  "import bot; print('rulesets refreshed:', bot.refresh_rulesets()); ok, msg = bot.refresh_adblock(); print(msg); raise SystemExit(0 if ok else 1)" \
  || echo "规则集或去广告规则刷新失败, 保留旧库"
