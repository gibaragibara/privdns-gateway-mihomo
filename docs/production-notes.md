# 实战与架构说明 (mihomo 版)

本仓库是 **[misaka-cpu/privdns-gateway](https://github.com/misaka-cpu/privdns-gateway)** 的 fork,流量核心改为 **mihomo TPROXY**(上游默认是 sing-box 1.12 嗅探入站)。

## 和上游的关系

| | 上游 | 本仓 |
|--|--|--|
| DNS | mosdns | mosdns(同源,含 WhatsApp 真实 IP 支路等增强) |
| 流量 | sing-box direct+sniff | **mihomo `tproxy-port` + sniffer** |
| 更新策略 | 跟上游 `v*` tag | 本仓独立打 `v*` tag(`pdg update` 只跟本仓 tag) |

**不要用 GitHub「Sync fork」一键同步上游。** 架构已分叉,强合会冲突并把 sing-box 文件冲回来。需要上游新功能时:看上游 CHANGELOG / commit,再 cherry-pick 或手工移植到 mihomo 路径。详见 [UPSTREAM.md](UPSTREAM.md)。

## 本仓相对上游已吸收的能力 (截至 v1.2.x)

- iOS Wi-Fi `:81` 探测 + 可选 SSID 强制直连
- bot 返回菜单清待输入状态;出口真改名级联
- GMS/FCM `5228-5230` 放行与 doctor 项
- doctor 宽端口区间泄露判定
- **本仓增强**:bot 慢操作异步、853 公网 DoT(安卓 Wi-Fi)、WhatsApp 无 SNI 真实 IP

## 拓扑要点

1. 手机只设 DoT → mosdns:国内域名真实 IP;国际域名 A=网关(内网卡段才劫持)。
2. 流量从私网到达网关后,nftables **TPROXY** 进 mihomo `:7893`,sniffer 看 SNI/Host/QUIC 再分流。
3. 出口/规则在 Telegram bot 或 `/etc/mihomo/state.json`,改前 `mihomo -t`,失败回滚。
4. 证书续期时脚本会临时处理 80 口与防火墙(见 `deploy/cert/`)。

## 小内存

实测量级:mihomo + mosdns + pdg-bot 合计约百 MB 内,1GB 机器可跑。

更细的历史踩坑(旧 sniproxy / sing-box 时期)不必再跟;以本 README + INSTALL + 本文件为准。
