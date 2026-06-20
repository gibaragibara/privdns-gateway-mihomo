# PrivDNS Gateway

**Android / iOS 私密 DNS 单入口多出口分流网关** — 口语版「私密 DNS 版 Surge 网关」。

手机端只设置系统级**私密 DNS / 加密 DNS**，不装任何 VPN / Clash / sing-box 客户端。
服务端 JP 作为唯一入口与分流中心：DNS 把需要代理的域名统一指向 JP 内网 IP，
JP 上的 sing-box 透明入口 sniff 出域名后，再分流到 HK / TW 现有 SS2022 出口或 JP 本地。

```
Android / iOS
  │  私密 DNS / DoH / DoT
  ▼
JP dnsdist ──► 命中代理域名: 返回 JP 唯一内网 IP
  │           DIRECT 域名: 返回真实 IP   BLOCK: NXDOMAIN
  ▼
JP sing-box (透明 tproxy 入口, sniff SNI/Host)
  ├── AI / Binance        → TW SS2022
  ├── YouTube/Netflix/X/IG → HK SS2022
  └── 默认                  → JP 直出
```

核心约束：**DNS 与 sing-box 必须由同一份 `rules.conf` 生成**，否则会出现
「DNS 认为某域名要代理、sing-box 却没有对应分流」的不一致。`pdg compile` 保证两者同源。

## 仓库结构

```
config/            配置样例 (装到 /etc/pdg)
  rules.conf         上层规则 (Surge 风格, 唯一规则源)
  policies.conf      策略 → 出口映射
  pdg.conf           主配置 (入口 IP / 端口 / SS2022 出口)
src/pdg/           Python 控制面 (零三方依赖, 仅标准库)
  rules/             解析 / 远程 RULE-SET 缓存 / 编译器
  generators/        dnsdist / sing-box / nftables 生成器
  cli.py             pdg 命令行
deploy/            install.sh / systemd / dnsdist 主配置 / iOS mobileconfig
docs/              架构 / 部署 / 客户端设置
```

## 快速开始 (开发机)

无需 root，仓库内直接跑（产物写到 `./var/out`）：

```bash
export PYTHONPATH=src
python3 -m pdg.cli compile --no-download   # 生成三件套到 var/out/
python3 -m pdg.cli test chatgpt.com        # 查某域名分流
python3 -m pdg.cli status                  # 查看配置与产物
```

## 部署 (JP, Debian 12)

```bash
sudo deploy/install.sh        # 装 pdg + 目录骨架 + systemd 单元
sudoedit /etc/pdg/pdg.conf    # 填 jp_internal_ip 与 HK/TW SS2022 凭据
# 放置 /etc/pdg/tls/{fullchain,privkey}.pem, 安装 dnsdist 与 sing-box
sudo pdg compile && sudo pdg reload
sudo systemctl enable --now dnsdist sing-box pdg-tproxy
sudo pdg doctor
```

详见 [docs/deployment.md](docs/deployment.md) 与 [docs/client-setup.md](docs/client-setup.md)。

## 命令速查

| 命令 | 作用 |
|---|---|
| `pdg compile [--no-download]` | 编译生成 dnsdist/sing-box/nftables 配置 (不 reload) |
| `pdg reload` | 编译 + 校验 + reload 服务 (校验失败自动回滚) |
| `pdg update-rules [--force]` | 刷新远程 RULE-SET 后 reload |
| `pdg rollback` | 回滚到上一次产物 |
| `pdg test <domain>` | 查域名命中的规则 / 策略 / 出口 / DNS 行为 |
| `pdg status` / `pdg doctor` | 查看配置 / 体检 |
| `pdg ruleset list \| refresh <name>` | 远程 RULE-SET 管理 |
| `pdg rule add\|del\|move ...` | 编辑 rules.conf |

## 现状（JP 实跑上线，Path B + TG bot）

- ✅ **DNS 层 = mosdns**：geosite「国内直连 + 其余全代理兜底」，AAAA/HTTPS 仅对代理域名置空、直连域名回真实，
  ECS 国内/海外分治；替换 5GPN 的 dnsdist（保留作回滚）。配置 [deploy/mosdns/config.yaml](deploy/mosdns/config.yaml)。
- ✅ **流量层 = sing-box 1.12**：`direct` 普通监听 + `sniff_override_destination`（80/443 TCP + 443 QUIC），
  多出口（AI·加密→TW，其余国际→HK），含 UDP 自环 reject 修复。
- ✅ **TG 管理 bot v3**：[deploy/bot/](deploy/bot)，管出口（ss/vmess/trojan/vless）、**故障切换组(urltest)**、
  分流规则、Surge 规则集、**端到端测出口/流量统计(clash_api)**、**iOS 描述文件下发**、**配置备份/恢复**、重启/更新。
- ✅ **mosdns 缓存** + 停用 5GPN 残留进程；**定时刷新规则库**（[pdg-rules-update.timer](deploy/bot/pdg-rules-update.timer)，每日）。
- ✅ **自定义 DoT 域名**：bot「🌐 DoT 自定义域名」`/setdot`，校验 A 记录→certbot 自动签证书→切换；不锁 ClouDNS，可换 Cloudflare 等任意 DNS。
  顺带修好了原 certbot 续期会被 sing-box 占 80 口拖垮的隐患（[deploy/cert/](deploy/cert)）。
- ✅ **iOS OnDemand :81 探测端点**：[probe81.py](deploy/ios/probe81.py) + nft 仅放行 172.22→81，实现双卡区分激活。
- ✅ **bot 二级菜单**：一级=状态/测出口/流量 + 出口/分流/客户端/运维四分类，点开二级，不再一屏按钮看花眼。
- ✅ 小内存友好：三件套常驻 ≈ 90MB，512MB 小鸡可跑。
- ✅ 实测全通：YouTube / ChatGPT / Google / Play / 国内直连。详见 [docs/production-notes.md](docs/production-notes.md)。
- ⬜ 已知限制：Telegram App（硬编码 IP，走日本，改不了）。

> 仓库里的 `src/pdg`（规则编译器内核）+ `deploy/singbox` 是早期 Path A 的实现与模板；线上现以 mosdns(Path B)
> + sing-box + bot 为准，见 [docs/production-notes.md](docs/production-notes.md)。

见 [ROADMAP.md](ROADMAP.md) 与 [docs/production-notes.md](docs/production-notes.md)。
