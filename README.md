# PrivDNS Gateway

**单入口、多出口的「私密 DNS 分流网关」** —— 手机端**只设系统私密 DNS(DoT)**,不装任何 VPN / 代理客户端;
服务端按域名把流量分到不同落地或直连。

> 🚀 **第一次部署?** 跟着 **[新手图文教程 →](docs/QUICKSTART.md)** 一步步来(从买 VPS 到手机连上,全程带图)。

```
 手机 (Android 私密DNS / iOS 描述文件, 仅 DoT)
   │  DoT :853
   ▼
 网关 VPS ── mosdns ──► 国内域名: 返回真实 IP (直连)
   │                   代理域名: A 记录劫持成「本机 IP」, AAAA/HTTPS 置空
   │  任意 tcp/udp 端口 TPROXY
   ▼
 mihomo ──► sniffer + 规则分流: AI/加密→落地A  其余国际→落地B  默认→本机直出
```

核心思想:**把 DNS 当策略引擎**。
代理域名的 A 记录被改写成网关自己的 IP,流量于是回到网关;
mihomo TPROXY 透明接入后嗅探 SNI/Host/QUIC 再决定走哪个落地。
手机全程只有一条「私密 DNS」设置,没有任何客户端、没有 tun。

---

## 与上游的关系

本仓 fork 自 [misaka-cpu/privdns-gateway](https://github.com/misaka-cpu/privdns-gateway),流量层改为 **mihomo TPROXY**。
上游新功能请按 [docs/UPSTREAM.md](docs/UPSTREAM.md) **手工移植**,不要用 GitHub Sync fork 强合同步。

当前版本已吸收上游 v1.1.x 适合本架构的改动,并对照 [5GPN-X](https://github.com/Xiuyixx/5GPN-X) 做了 bot 异步(含删凭据消息)、安卓 Wi-Fi DoT(853 公网)、iOS WhatsApp 真实 IP(TPROXY 适配,非 wa-shim)。

---

## ⚠️ 这个项目适合谁 / 前提

它**不是通用翻墙工具**,依赖一个特定拓扑:

- 一台**墙外 VPS**(网关 + DNS)。
- 一张运营商「**内网卡 / 定向内网 SIM**」—— 手机的移动流量经运营商私网到达你 VPS,且**源 IP 是固定私有段**(如 `172.x`)。
  网关靠这个私有源段来区分「该劫持的查询」和别人。
  - 没有这种内网卡 → DNS 劫持会影响到所有查询源,不适用本项目。
- 一个你能改 DNS 记录的**域名**(给 DoT 用,签 Let's Encrypt 证书)。
- 一个 **Telegram bot**(管理出口/分流)。
- 一个或多个**落地节点**,用来出国际流量(可选,默认其余国际从 VPS 直出)。出口跑在 mihomo 上;bot 能直接粘贴的链接见下。

---

## 一键安装 (Debian 12+ / Ubuntu 22+)

```bash
curl -fsSL https://raw.githubusercontent.com/gibaragibara/privdns-gateway-mihomo/main/install.sh | sudo bash
```

入口脚本只负责自举,实际安装会自动切到最新 `v*` 发布 tag,不安装 main 上未发布的中间提交。

或克隆后运行(便于先看代码):

```bash
git clone https://github.com/gibaragibara/privdns-gateway-mihomo.git
cd privdns-gateway-mihomo
git fetch --tags
git checkout "$(git tag -l 'v*' --sort=-v:refname | head -1)"
sudo ./install.sh
```

脚本会装好 mosdns、mihomo TPROXY、管理 bot、防火墙和证书,自动识别公网 IP 和内网卡段,再交互填 DoT 域名(**bot token 可留空**,装完随时 `sudo pdg-set-token` 再设并启用)。
域名 A 记录这步留给你自己做(脚本会等你确认指向本机后再签证书)。
详见 [docs/INSTALL.md](docs/INSTALL.md)。

卸载:`sudo ./uninstall.sh`(加 `--purge` 连配置一起删)。

## 装完之后

1. 手机【私密 DNS / DoT】填你的域名(如 `dot.example.com`)。
2. Telegram 给 bot 发 `/start`:
   - **📤 出口管理 → 添加**:直接粘贴节点链接。
     > **bot 能直接粘**:`ss:// / vmess:// / trojan:// / vless://(含 reality)/ hysteria2:// / tuic:// / anytls:// / socks5:// / http://`,以及 Surge 的 `名字 = ss, …` 行。
     > 其它 mihomo 支持但 bot 还没解析的协议,可手写 `/etc/mihomo/state.json` 后执行 `sudo pdg restart`,或开 issue 让 bot 加解析。
   - **📑 分流管理**:把域名、`.list` / `.txt` 等规则集指到出口(默认其余国际走 VPS 直出)。
   - **🔀 故障切换组**:多落地自动选最快 / 坏了自动切。
3. iOS:bot **📱 客户端 → iOS 描述文件**(可填强制直连的 Wi-Fi SSID);**不用 bot 的话** `sudo pdg ios` 会直接在终端打出二维码,手机(走内网卡)扫码 → Safari → 装。
   Wi-Fi/蜂窝均靠服务器 `:81` 探测判定是否启用 DoT(普通宽带 Wi-Fi 探不通则自动直连)。
4. iOS 网络虚拟定位(可选):主菜单 **📍 iOS 定位**或 `/wloc`。安装 Bot 下发的共享 CA 后，可直接点击服务器预置地点，不必发送 Telegram Location；也支持手工输入经纬度。服务端只对两个 Apple 定位域名启用 WLOC 改写，**无需 Egern/Surge/Loon**。详见 [WLOC 使用说明](docs/WLOC.md)。
5. MITM 去广告(可选):主菜单 **🛡 MITM 去广告**或 `/adblock`。它复用同一张 CA，只把声明式规则的精确主机送入 sidecar；关闭 WLOC 不会关闭仍被去广告使用的 MITM。详见 [MITM 去广告说明](docs/MITM-ADBLOCK.md)。
6. Android:系统**私密 DNS**填 DoT 域名即可。`853` 对公网开放,Wi-Fi 下不会因「私人 DNS 服务器无法访问」整网挂掉;只有内网卡段来源才会被 DNS 劫持进网关。
7. 换域名:bot **🌐 DoT 自定义域名**,自动签证书并切换。

## 日常管理

```bash
sudo pdg            # 进管理菜单
sudo pdg doctor     # 自检(只读); --json 可脚本化; --deep 加端到端检查(DoT握手/:81/DNS/clash)
sudo pdg status     # 状态
sudo pdg update     # 更新(更新前自动快照, 失败自动回滚; --dry-run 看待更新)
sudo pdg snapshot   # 手动留一份配置快照
sudo pdg rollback   # 回滚到最近快照
sudo pdg token      # 设置 / 更换 bot token
sudo pdg restart    # 重启服务
sudo pdg log [n]    # 看日志
sudo pdg traffic    # 网卡流量(vnstat)
sudo pdg ios        # 不用 bot, 直接出 iOS 描述文件二维码
sudo pdg report     # 脱敏诊断报告(隐藏 token/密码/uuid); --redact-ip 连IP/域名也隐藏; --full 不脱敏
sudo pdg detect-cidr # 抓包重新识别内网卡来源段, 与现配不符可一键写回并重启
sudo pdg uninstall [--purge]   # 卸载(--purge 连配置删)
```

> 健康自检每 10 分钟自动跑,服务挂 / DNS 不应答 / 证书快到期会 Telegram 私信你。

> 分工:`pdg` 管**生命周期**(装/更新/卸载/token/状态);**出口 / 分流 / DNS 上游**等运行时配置都在 Telegram bot 里。

## 组成

| 层 | 用什么 | 说明 |
|---|---|---|
| DNS | **mosdns v5** | 国内直连 / 代理域名 A 劫持到本机 + AAAA/HTTPS 置空 / 按来源 IP 分支 / ECS 分治 / 缓存。DoT(853 公网)。WhatsApp 等无 SNI 域名返回真实 IP(配合 TPROXY) |
| 流量 | **mihomo 1.19** | `tproxy-port: 7893` + sniffer;多出口 url-test 故障切换;external-controller 测速/流量 |
| 管理 | **Telegram bot**(纯标准库) | 出口/分流/规则集/测速/流量/备份恢复/iOS下发/WLOC/去广告/自定义域名,改 mihomo 前 `mihomo -t`+回滚 |
| 共享 MITM(可选) | **mitmproxy sidecar** | WLOC/去广告按功能独立启停并复用同一 CA；只监听本机 `:9080`，两项都关闭才停止 |
| 证书 | **certbot standalone** | Let's Encrypt,签发/续期时临时处理 80 口并自动恢复 |
| 防火墙 | **nftables** | 全网 SSH + **DoT 853**;53/80/81/443/5228-5230/8445 等仅内网卡;内网 tcp/udp TPROXY 到 mihomo |

## 文档

- [docs/INSTALL.md](docs/INSTALL.md) — 安装细节 / DNS 配置 / 端口 / 版本注意
- [docs/QUICKSTART.md](docs/QUICKSTART.md) — 新手图文
- [docs/TROUBLESHOOTING-PLAYBOOK.md](docs/TROUBLESHOOTING-PLAYBOOK.md) — 排障手册(症状 → 查 → 修)
- [docs/WLOC.md](docs/WLOC.md) — 无 Egern 的服务端 iOS WLOC、共享 CA 与恢复流程
- [docs/MITM-ADBLOCK.md](docs/MITM-ADBLOCK.md) — 声明式模块移植范围、共享生命周期与限制
- [docs/UPSTREAM.md](docs/UPSTREAM.md) — 与上游关系 / 如何吸收新提交
- [docs/production-notes.md](docs/production-notes.md) — 架构说明
- [CHANGELOG.md](CHANGELOG.md) — 更新日志

## 免责声明

本项目仅供**学习与合法网络管理**用途。请遵守你所在地的法律法规;使用者自行承担责任。作者不对任何使用后果负责。

## License

[MIT](LICENSE)
