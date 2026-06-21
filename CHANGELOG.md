# 更新日志

本项目无正式版本号,按日期记录主要变化;完整提交见 git 历史。

## 2026-06-20 — 首个公开版本

### 网关核心
- **DNS 层 mosdns**:国内直连 / 代理域名 A 记录劫持到本机 + AAAA·HTTPS 置空 / 按来源 IP 分支 / ECS 分治 / 响应缓存;DoT(853)。
- **流量层 sing-box 1.12**:`direct` 监听 + `sniff_override_destination`(不用 tproxy);多出口,urltest 故障切换;clash_api。
- **一键安装** `install.sh`(自动识别公网 IP / 内网卡段,DNS 那步留用户)、`uninstall.sh`。

### 管理
- **`pdg` CLI**:`status` / `doctor` / `update [--dry-run]` / `snapshot` / `rollback` / `token` / `restart` / `log` / `traffic` / `ios` / `uninstall`。
- **Telegram bot**:出口(ss/vmess/trojan/vless)、故障切换组、分流规则、Surge 规则集、🔎测域名、测出口、流量、DNS 上游、TFO、配置备份/恢复、iOS 描述文件下发、自定义 DoT 域名。改 sing-box 前 check + 自动回滚。

### 可靠性与运维
- **`pdg doctor`** 只读自检(服务 / sing-box 版本 / DoT A 记录 / dot-domain 一致性 / 内网卡段 / 防火墙 / 证书 / 本机 DNS / sing-box check),支持 `--json`。
- **健康自检告警**:`pdg-health.timer` 每 10 分钟跑,异常 Telegram 私信(仅状态变化)。
- **snapshot / rollback**:整机配置 + 防火墙 + service 快照到 `/var/lib/privdns-gateway/backups`(留最近 10 份);`pdg update` 更新前自动快照、失败自动回滚。
- **配置备份/恢复机器感知**:跨机导入只搬出口/分流/规则集,本机 IP/证书路径/内网卡段保留。
- **证书** Let's Encrypt 自动续期(已处理续期时 80 口被 sing-box 占用的问题);**vnstat** 网卡流量统计。

### 安全
- nftables 暴露面收敛:对全网仅 SSH;`53/80/81/443/853` 仅放行内网卡来源段。

> ⚠️ sing-box 必须 1.12.x:1.13+ 移除了 `sniff_override_destination`,本网关会失效。详见 [docs/INSTALL.md](docs/INSTALL.md)。
