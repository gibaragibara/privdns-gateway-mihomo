# 上游同步策略

## 上游是谁

- 源项目:[misaka-cpu/privdns-gateway](https://github.com/misaka-cpu/privdns-gateway)(sing-box)
- 本仓:`gibaragibara/privdns-gateway-mihomo`(mihomo TPROXY)

GitHub 上本仓显示为 fork,但**运行时栈已分叉**,不能当「纯跟踪上游」的 fork 用。

## 不要做的事

- ❌ 网页上 **Sync fork / Update branch** 直接合 `upstream/main` 进 main  
  实测会冲突:bot、防火墙、文档、测试,以及 `deploy/singbox/*` 删除与上游修改冲突。
- ❌ 解决冲突时「全部 Accept upstream」——会恢复 sing-box 路径。

## 推荐做法

1. 看上游 [Releases](https://github.com/misaka-cpu/privdns-gateway/releases) / [Commits](https://github.com/misaka-cpu/privdns-gateway/commits/main)。
2. 判断是否与 **协议栈无关**(bot UX、文档、mosdns 策略、防火墙策略、测试)还是 **绑 sing-box 入站**。
3. 无关或可改写的:手工移植到本仓对应文件(多数在 `deploy/bot/`、`deploy/mosdns/`、`deploy/firewall/`、`tests/`)。
4. 绑 sing-box 的(如 `sniff_override` 入站、GMS listen_port 5228):改写成 **TPROXY 已覆盖 / nft 放行 / doctor 提示** 即可,不必抄入站块。
5. 移植后跑本地回归:`python3 tests/test-*.py`、`bash tests/test-*.sh`(需要的话),打本仓 `v*` tag。

## 已移植对照 (上游 → 本仓)

| 上游能力 | 本仓落点 |
|--|--|
| iOS Wi-Fi :81 + SSID | `deploy/ios/*.tmpl`, `pdg-bot._ios_profile` |
| 菜单清 state | `handle_cb` 开头 |
| 出口 rename 级联 | `rename_exit` |
| GMS 5228-5230 | nft 模板 + `check_gms` + 迁移(无 sing-box 入站) |
| doctor 区间泄露 | `checks.check_nft` |
| (本仓) bot 异步 | `run_bg` / `edit_bg` |
| (本仓) 853 公网 | nft + 迁移 |
| (本仓) WhatsApp 真 IP | `geosite_wa` + `whatsapp.txt` |

最后全量吸收上游功能点的整理版本:**v1.2.0 / v1.2.1**。
