# 更新日志

本项目无正式版本号,按日期记录主要变化;完整提交见 git 历史。

## 2026-07-24 — v1.4.4(QUIC 快速回退兼容)

- 修复旧防火墙把手机源 UDP/443 静默 `drop` 后，NIKKE 等 QUIC-first App 无法及时回落 TCP、直接提示网络错误的问题；改为立即 `reject`，仍然禁止 QUIC 并保留 MITM 可见性。
- 新安装模板恢复 UDP/443 快速 `reject`；旧 `inet pdg` 配置只迁移项目精确规则并保留其它自定义行，支持 legacy `drop` 与短期 QUIC 放行模板。
- doctor 新增「QUIC 回退」检查，区分正确 `reject`、有害的静默 `drop` 和可能绕过 MITM 的放行状态。

## 2026-07-24 — v1.4.5(发布校验修正)

- 管理脚本的 QUIC 迁移调用显式传入防火墙路径，保持 ShellCheck 与发布流水线一致；运行行为不变。

## 2026-07-24 — v1.4.6(回归断言修正)

- 更新 QUIC 迁移回归断言以匹配显式配置路径调用；不改变运行时策略。

## 2026-07-23 — 未发布(MITM 审批事务与候选审计)

- MITM 插件更新确认改为仅限当前 Telegram 聊天管理员、10 分钟有效、一次性消费的随机审批令牌，并绑定候选 SHA256 与完整来源配置版本；插件、来源配置或候选内容变化后旧确认自动失效。
- 同步器现在记录候选插件的有限结构化规则差异；审批页展示新增/删除规则的动作、主机与 URL 匹配摘要，不再只显示重写总数。

## 2026-07-23 — 未发布(MITM 待批准更新体验)

- 去广告首页在存在待批准模块时直接显示「待批准更新」入口；无需在完整插件列表中查找。
- MITM 插件列表改为每页 10 个，并提供上一页/下一页导航；待批准更新页也支持相同分页。

## 2026-07-22 — 未发布(iOS 全设备 Apple Network Relay)

- 新增 iOS 17+ `com.apple.relay.managed` 全域名 profile；不设置 `MatchDomains`，仅排除 Relay 自身域名以避免递归。
- 新增 Envoy HTTP/2 CONNECT / CONNECT-UDP 入口；固定版本和双架构 SHA256，长连接关闭 5 分钟 idle timeout，避免 APNs 等安静连接被周期性切断。
- Envoy 以独立 `pdg-relay` 用户运行；专用 nft output TPROXY 只捕获该 UID，再送入现有 mihomo，继续复用分流、REJECT、共享 MITM 和 WLOC。
- ChinaMax 每日规则同时编译为 domain/ipcidr MRS；显式分流、REJECT、MITM 之后自动 KFC 直出，避免全量 Relay 把未命中的国内 App 送入默认国际出口。
- 无原生 IPv6 默认路由的 KFC 会按 Envoy UID 将 IPv6 目标先送入 mihomo，避免 iOS App 因立即 `ENETUNREACH` 反复回退；中国 IP MRS 仅含 IPv4，IPv6 继续由默认代理处理。
- Envoy 公网 listener 增加 1024 条全局下游连接上限与仅错误 access log；Relay 与 mihomo 绑定重启并等待 `:7893` 就绪，回滚到功能引入前的快照会移除新增文件、用户与路由。
- Relay 默认监听 `:20443` 且显式启用，保留旧 `:443` 5GPN TPROXY 作为回退；安装、更新、快照回滚、卸载、doctor、Bot 客户端菜单均接入生命周期。
- profile 可手工安装或由现有 MDM 下发；仓库不伪装提供 Apple MDM Push 证书、设备注册或 APNs 命令通道。

## 2026-07-22 — 未发布(WLOC 稳定性与更新回滚)

- WLOC 现在只改写 Apple 网络定位响应中的经纬度，保留 Apple 原始精度和未知字段；避免“瞬移 + 过低精度”被 iOS 判为异常后回退真实位置。
- WLOC 状态页和结果消息不再把预置配置的 `accuracy` 显示为 Apple 实际精度；旧配置字段仍兼容读取，但不再写回协议响应。
- `pdg update` 必须先生成完整、可恢复的快照；快照失败即中止。快照覆盖运行配置、代码仓库、systemd unit、已安装脚本、证书 hook 与共享 MITM 状态。
- 更新失败时按本次快照目录和更新前 Git SHA 精确回滚；手动回滚会校验归档路径与配置后再落盘，不完整恢复会明确返回失败。
- `pdg update` 只接受当前提交的后继发布 tag，拒绝把未发布代码自动重置到较旧 tag；新增对应 CI 回归测试。

## 2026-07-20 — 未发布(MITM 性能与嗅探稳定性)

- MITM 模块正文首次添加即固定 SHA256；每日变化只进入 Bot 待批准队列，运行时继续使用校验过的 last-known-good 缓存。
- 修复 `*.domain`、中间 glob 和 `-host` 的范围解析；只从 URL pattern 收敛精确 MITM 主机，并单列不可达规则。
- 修复 HTML 内嵌 JSON 重新序列化可产生 `</script>` 的问题；GitHub 默认去广告来源改为空清单，不再携带实际 URL 或规则。
- 修复每日更新/覆盖安装清空 `custom_direct.txt`、防火墙截走本机 `:81/:8445`、Bot 多线程共用 Telegram 连接及并发配置写入竞态。
- 修复 mihomo `parse-pure-ip` 流量共享目标地址时的嗅探失败缓存污染；安装器改用锁定上游提交、仓库补丁、双架构 SHA256 校验的 `1.19.27-pdg1` 构建。
- MITM 规则缓存增加逐主机索引，每个请求/响应只检查当前主机的规则；`upstream_cert=false` 配合 lazy 连接，合成广告响应不再先连接上游。
- 兼容当前 mitmproxy 的 `warn` 日志 API，避免格式异常在记录告警时二次抛错；固定证书或高频核心 API 可继续通过服务器私有 `mitm_exclude_hosts` 旁路。
- 新增服务器私有 `local_domain_rules`，紧急精确规则与远程列表一起去重并转换为 MRS，24 小时同步不会删除，实际条目不进入仓库。
- 新增服务器私有 `script_conversions` 与 `external_jq_pins`：远程脚本只校验 SHA256，不直接执行；安全转换支持受限 jq、请求头条件响应及本地 HTML 处理，哈希或模块匹配变化时自动停用。
- Bot 显示脚本转换总数、剩余声明、外部 jq 导入和固定资源失效数；实际转换清单继续不进入仓库。

## 2026-07-19 — 未发布(共享 MITM 去广告)

- WLOC 与去广告改为独立开关并共享同一个本地 mitmproxy sidecar 和 CA；关闭 WLOC 只恢复两个 Apple 定位域名直连，去广告开启时不会再停止 MITM。
- Telegram Bot 新增 `/adblock` 与 **去广告**菜单：同步原 Egern 配置中的 3 个普通 REJECT 规则源，并编译公开 Loon/Egern 模块中的声明式 reject、mock、JSON、受限 jq、正则替换及响应头规则。
- 新增 MITM 插件管理：按单个 Kelee/Loon 插件删除、通过 HTTPS URL 添加；普通 REJECT 与 MITM 来源统一由每日 timer 刷新，失败保留旧缓存。
- 规则只为模块声明的精确主机注入 mosdns/mihomo 分支；远程 JavaScript、外部 jq、ProtoBuf 脚本及通配主机不会执行或导入。
- 安装、tag-only 更新、快照/回滚、健康检查、mosdns 幂等迁移和 CI 已接入共享生命周期。

## 2026-07-18 — 未发布(服务端 WLOC，无需 Egern)

- 新增 `pdg-wloc` mitmproxy sidecar，只监听 `127.0.0.1:9080`，并只改写 Apple 两个网络定位主机的 `/clls/wloc` protobuf 响应。
- Telegram Bot 新增 `/wloc` 与客户端菜单：生成/下发专用 CA 描述文件、接收 Telegram 位置或 WGS84 经纬度、启停及恢复真实定位。
- 主菜单新增 WLOC 直达入口，并支持服务器端常用地点按钮；选择预置无需发送 Telegram Location，地点由可热更新的 `wloc-presets.json` 管理。
- WLOC 开启时才向 mosdns/mihomo 注入两个 Apple 定位域名；关闭后清空其独立 DNS 集合并删除对应规则。已开启时换坐标不重启 DNS/代理。
- 安装、tag-only 更新、快照/回滚、健康检查和卸载均接入 WLOC；CA 私钥只保存在服务器 `/var/lib/pdg-wloc/mitmproxy`。
- 新增 WLOC protobuf、Bot 事务、mosdns 老装迁移、健康检查和生命周期回归测试。

## 2026-07-13 — v1.2.3(国内名单改用 blackmatrix7 ChinaMax)

- 每日 `update-rules.sh` 拉取 [ChinaMax.list](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Clash/ChinaMax) → `geosite_cn.txt`(mosdns 国内直连主名单)。
- 新增 `parse-chinamax.py`; Loyalsoldier geosite 仍更新 apple / !cn, 不再覆盖 cn。
- 原始 `ChinaMax.list` 落盘 `/etc/mosdns/rules/` 便于核对版本时间戳。

## 2026-07-13 — v1.2.2(对齐 5GPN-X: bot 异步 UX / 凭据消息删除)

对照 [Xiuyixx/5GPN-X](https://github.com/Xiuyixx/5GPN-X) 的三项体验增强, 在 mihomo 架构下补齐:

### Bot 响应速度(5GPN-X tgbot 思路)
- 专用 callback 线程池 `answerCallbackQuery`; 慢操作期间同气泡再点提示「正在处理上一项」。
- 加出口: **后台解析 + 自动删除含节点密码的消息**(删失败会提示手动删)。
- 更多写配置路径异步: 删出口/默认出口/规则集/改规则出口/重启/更新 geosite/TFO/WDA/TG 出口/加规则/规则集/恢复备份等。

### 安卓 Wi-Fi 私密 DNS
- 维持 v1.2.0 的 **853 公网 DoT**(5GPN-X 同样公网 853); mosdns 仅内网段劫持。

### iOS WhatsApp
- 维持 TPROXY 适配方案: DNS **真实 IP**(非 5GPN-X 的 sniproxy+wa-shim 模型, 因本仓无 sniproxy)。
- 扩充 `whatsapp.txt` 域名列表(g/v/mmg/pps/web/fna/cdn 等)。

## 2026-07-13 — v1.2.1(整理:文档对齐 mihomo + 上游同步策略)

- **不 Sync fork**:文档明确与上游的关系与移植流程 → [docs/UPSTREAM.md](docs/UPSTREAM.md)。
- 上游 v1.1.11–v1.1.16 中需要的能力已在 v1.2.0 按 mihomo 架构吸收完毕,本版不再强合上游 main。
- 排障手册 / QUICKSTART / forum-post / production-notes 去掉 sing-box 表述,统一为 mihomo TPROXY。
- CI 文案与功能测试说明改为 mihomo;README 防火墙口径与 853 公网一致。

## 2026-07-13 — v1.2.0-mihomo(同步上游 + bot 加速 + 安卓 Wi-Fi DoT + iOS WhatsApp)

整合自上游 [misaka-cpu/privdns-gateway](https://github.com/misaka-cpu/privdns-gateway) 与 5GPN-X 思路,适配 **mihomo TPROXY** 版:

### Bot 响应速度
- 慢操作(测出口 / 自检 / 检查更新 / 签证书 / 加出口 / 备份 / iOS 描述文件)改后台线程执行,主 long-poll 不再卡住。
- 粘贴节点链接后立刻回「正在解析…」,`mihomo -t`+重启在后台完成。
- 返回主菜单 / 切子菜单时清空待输入状态与删规则勾选(修「下一条文字被旧流程误吃」)。
- 出口真**改名**:级联更新规则 / 故障组 / final / TG / 规则集元数据。

### 安卓 Wi-Fi 私密 DNS「无法访问」
- 防火墙 **853 DoT 对公网放行**;mosdns 仍只对内网卡段做 A 劫持。
- 手机在普通 Wi-Fi 下私密 DNS 可连上网关(拿真实解析、不劫持),不再整网 DNS 不可用。
- 老装 `pdg update` / 管理类命令幂等迁移 `migrate_fw_android_dot_gms`。

### iOS Wi-Fi / WhatsApp
- iOS 描述文件:Wi-Fi 改为与蜂窝一致的 **:81 探测**判定;bot 可填 SSID 强制直连名单。
- **WhatsApp 无 SNI**:`whatsapp.txt` + mosdns `geosite_wa` 返回真实 A,TPROXY 按目的 IP 出站(不再 black_hole 到本机导致嗅探失败)。
- GMS/FCM `5228-5230` 内网放行 + doctor 自检(TPROXY 全端口已覆盖数据面)。

### 其它
- CI 改校验 mihomo 模板;回归用例:iOS SSID / 出口改名 / doctor 防火墙 / bot 清状态。
- 老装迁移:`migrate_mosdns_whatsapp`、`migrate_fw_android_dot_gms`。

## 2026-06-27 — v1.1.10(删规则集结果显示名 + 清死代码)

- **修**:删除规则集后的「已删除规则集 rs_xxxx」**没用改过的显示名**;`del_ruleset` 现在删前取 `label` 用于结果消息(回归断言加进 `test-domain-label.py`)。
- 删掉成了死代码的 `exits` 回调(子菜单已改用 `exit_list`,无人再指向 `exits`)。
- 把漏挂的 `test-maintenance-polish.py` 补进 CI。

## 2026-06-27 — bot TFO 页面补主菜单

- bot「🚀 TFO」页面补上「🏠 主菜单」按钮,与 DNS 上游等运维三级页保持一致。

## 2026-06-27 — bot 更新/DNS 按钮与点击响应优化

- bot「🔄 更新」检查中的“检查更新中…”不再铺一级菜单,改为只显示返回主菜单按钮。
- bot「🌐 DNS 上游」页面补上「🏠 主菜单」按钮,与其它三级页一致。
- Telegram callback 先停止按钮转圈,再执行检查更新/测出口/自检等较慢动作,降低“点了不跟手”的体感延迟。

## 2026-06-27 — bot 测域名显示名与测出口键盘修正

- bot「🔎 测域名」命中规则集时改为显示用户改过的规则集名称,不再暴露内部 `rs_xxxx`。
- bot「🚦 测出口」等待中的“测试中…”不再铺一级菜单,改为只显示返回主菜单按钮。
- CI 增加测域名规则集显示名回归。

## 2026-06-27 — bot 三级返回与自检端口补齐

- bot 出口管理/分流管理里的三级页面与操作结果改为返回对应父菜单;一级「测出口」仍返回主菜单,避免复用 callback 造成跳错层级。
- 自检防火墙口径补上 Telegram SOCKS5 代理端口 `8445`,与 nftables 模板里的 `53/80/81/443/853/8445` 保持一致。
- CI 增加 bot 三级导航与自检防火墙端口回归。

## 2026-06-27 — 发布/更新链路补齐 + bot 运维结果返回按钮

- `install.sh` 自举也切到最新 `v*` 发布 tag,不再把 `/opt/privdns-gateway` 种成 main 的浅克隆;本地 clone 运行安装时也会重进最新发布 tag。
- `pdg update` 与 bot 更新检查对老浅克隆先 `fetch --unshallow --tags`,并区分 `merge-base` 的“不落后”和 git 错误,避免把浅历史异常误报成已最新。
- 安装文档清掉 sing-box `1.12.9` 残留,改成当前锁定版 `1.12.25` / 项目锁定版表达。
- bot 运维动作结果(TFO/重启/更新规则库,WDA 切换)改为返回运维/DNS 上游的小键盘,不再直接铺整个一级菜单。

## 2026-06-24 — v1.1.2(修「改出口」列表显示规则集旧名)

- 分流管理「✏️ 改出口」选规则的列表里,**规则集规则原先显示内部 tag `rs_xxxx`,没用你改过的显示名**;现 `editable_rules` 查 `_rs_meta` 的 `label`(没有才回退 `rs_xxxx`),与「📋 规则」列表一致。
- (说明:两个同地区节点想"自动测延迟、谁快用谁 + 故障切换",用「🔀 新建故障组」(urltest),不是规则集——规则集是域名集合。)

## 2026-06-24 — v1.1.1(`pdg update` 只跟发布 tag)

- `pdg update` / bot『🔄 更新』从「跟 `main` 最新提交」改为「**更新到最新发布 tag**」(`v*`,按版本号降序取最高)。外部用户只会拿到打了 tag 的发布版,不再拉到 main 上未发布的中间提交;仓库没 tag 时中止并提示。
- `--dry-run` 与更新检查显示「当前 vs 最新发布 tag」及其间提交;`reset --hard <tag>`。
- 适合「对外发布走 tag、main 随时迭代」:你推 main 不影响别人,打 tag 才算发布。

## 2026-06-24 — v1.1.0(版本显示改 git describe)

- `pdg status` 的「代码版本」与 bot『🔄 更新』检查里的「当前」从 commit hash 改为 **`git describe --tags`**:在 tag 上显示 `v1.1.0`,领先 tag 则 `v1.1.0-N-g<hash>`。`pdg update` 与检查更新的 `git fetch` 加 `--tags`,确保各机能拿到 tag 供 describe。
- **打 tag `v1.1.0`**。自 v1.0.0 起累计:WDA 流媒体/服务解锁开关、出口多协议解析(hysteria2/tuic/vless-reality/anytls/socks5/http + Surge ss 行)、防火墙独立表 `inet pdg` + 幂等迁移、mosdns 多厂商上游 + `concurrent` 故障转移、DNS 层/解析/迁移多项回归测试入 CI、sing-box 锁定 1.12.25,以及大量评审加固。

## 2026-06-24 — sing-box 锁定版升到 1.12.25(1.12.x 最高补丁版)

- **`lib/versions.sh`: `SINGBOX_VER` 1.12.9 → 1.12.25**(当前 1.12.x 最高;仍是 1.12.x,`sniff_override_destination` 在,**不碰 1.13**)。同步更新 amd64/arm64 SHA256。十几个补丁版的 bug/安全修复。
- 两台线上对齐到 1.12.25(`pdg update` 不动二进制,手动换 + 校验 SHA256 + 重启 + 回滚兜底);新装直接装 1.12.25;CI 的 schema 校验也对 1.12.25 跑。

## 2026-06-24 — 出口支持更多协议链接(hysteria2/tuic/vless-reality/anytls/socks5/http)

- **bot「📤 出口管理 → 添加」新增解析**:`hysteria2://`(含 sni/insecure/obfs)、`tuic://`(uuid:pass、alpn/congestion_control)、`anytls://`、`socks5://`、`http(s)://`,并**扩展 `vless://` 认 Reality**(`pbk`→`reality.public_key`、`sid`→`short_id`、`fp`→`utls.fingerprint`、`flow`)。`PROXY_TYPES` 同步扩容,新协议出口可正常选默认/进故障组/测出口/删除。
- **修 gRPC 服务名**:`_transport` 现从 `serviceName` / `service_name` / `path` 三者取 grpc service_name(原先只看 `path`;vless/vmess 的 grpc 分享链接多用 `serviceName=`,会丢导致连不上)。
- **验证(两层、都进 CI)**:`tests/test-parse-links.py` 断言各协议字段映射(含 gRPC serviceName);`tests/test-outbound-schema.sh` **下载项目锁定版 sing-box(`SINGBOX_VER`=1.12.9、钉死 SHA256)对 parse_link 生成的全部出站跑 `sing-box check`**——只测解析 dict 不够,字段名要跟锁定版 schema 对得上(常随版本小变)。⚠️ 连通性仍需各自拿真实节点测。
- 仍走手写 config 的:`shadowtls`(无标准链接)、`ssh`(无链接)、`wireguard`(1.12 是 `endpoints`)。

## 2026-06-24 — 出口支持粘贴 Surge 的 ss 行

- **「📤 出口管理 → 添加」除 `ss:// / vmess:// / trojan:// / vless://` 链接外,也认 Surge 代理行**:`名字 = ss, 服务器, 端口, encrypt-method=…, password="…", tfo=true, udp-relay=true`(`encrypt-method`→method、`tfo=true`→`tcp_fast_open`;SS2022 如 `2022-blake3-aes-128-gcm` OK;udp-relay 是 sing-box ss 出站默认行为)。其它类型仍用对应 URI。
- 加 `tests/test-parse-links.py`(进 CI):Surge ss 行 / `ss://` SIP002 / 非法输入 三类断言。
- **文档澄清**:README/QUICKSTART/forum-post 说明出口**协议 = sing-box 全部出站**;`ss://vmess://trojan://vless://` + Surge ss 行是 bot 能直接粘的,其它(hysteria2/tuic/vless-reality/shadowtls/anytls/ssh/socks/http/wireguard 等)手写 `config.json` 即可——避免误以为只支持这四种。

## 2026-06-24 — 流媒体/服务解锁开关(WDA)

- **bot『🌐 DNS 上游』新增解锁开关**:两个按钮在「🛬 解锁走落地出口」与「🔓 解锁走 WDA」之间整体切换。
  - 🔓 WDA:一批可解锁的服务域名(Netflix/Disney+/Prime/AppleTV/YouTube/Dazn/U-NEXT/iQiyi/TVBAnywhere/DMM + OpenAI/Claude/Gemini + Steam 等)整体 → **jp 直出**(从 VPS 被授权 IP 出)+ 经 mosdns 用**解锁 DNS `22.22.22.22`** 解析到中继。其余流量照常分流。
  - 🛬 落地:撤掉规则,这些域名回落各自现有出口(hk/tw)。
- **mosdns 加常驻"解锁支"**(平时休眠):`unlock_upstream`(22.22.22.22, concurrent 1) + `geosite_unlock`(读 `unlock.txt`) + main_sequence 一条「**本机查询**命中解锁域名 → 解锁 DNS」的支(带 `jump has_resp`,否则答案会被 `remote_upstream` 覆盖——实测踩过)。只对 sing-box 直出的本机查询生效,手机劫持路径不变。
- **开 WDA 前自检授权**:点 🔓 时先探测解锁 DNS 是否对本机返回中继(本机 IP 已在服务商后台加白),**没授权就拦下并提示去后台授权本机 IP**——避免"没授权却开 WDA → 拿不到中继、流媒体反而挂"。DNS 上游页也直接显示要授权的本机 IP。docs/INSTALL.md 加「流媒体/服务解锁(WDA)」节。
- **修:关 WDA 现在会清空 `unlock.txt`**。原先点 🛬 只撤 sing-box 规则、没清 mosdns 的 `unlock.txt`,导致"落地模式下本机解析这些域名仍走解锁 DNS"的残留(与配置注释"落地时 unlock.txt 留空"不符)。现 `set_wda_mode(False)` 撤规则后清空 `unlock.txt` 并重启 mosdns(解锁支彻底休眠);`_write_unlock_file([])` 可写空。dns-policy-test 加「空 unlock.txt → 解锁域名回落普通上游」回归。
- **旧装自动迁移** `migrate_mosdns_unlock`(随管理类 pdg 命令幂等补该支);install 建空 `unlock.txt`(空=休眠,不改现有行为)。
- **测试**:dns-policy-test 加「解锁域名经本机 → 解锁 DNS(非普通上游)」断言,正好回归 `jump has_resp`。
- 说明:解锁地区取决于厂商面板选的平台(VPS 在日本→JP 平台→日本区);解锁的价值在于**中继是干净 IP**,避开 Netflix 对机房 IP 的代理封锁。

## 2026-06-23 — 评审第九轮:concurrent 也给旧装自动迁移 + 单上游不重复查

- **旧装升级自动补 `concurrent`**:`pdg update` 不重渲染 `/etc/mosdns/config.yaml`,旧装升上来仍是默认随机单上游、无故障转移。新增 `migrate_mosdns_concurrent`(随管理类 `pdg` 命令幂等触发):只给**缺 concurrent** 的 forward 块补该字段、**不动用户现有上游**;备份 `cmp` 校验、重启 mosdns 失败自动还原。
- **单上游不再被查两次**:bot 与迁移都按**上游数定值**——单上游 `concurrent: 1`(否则 mosdns 取模会对同一台并发发两次相同查询)、≥2 才 `concurrent: 2`。
- 回归测试 [tests/test-mosdns-concurrent.sh](tests/test-mosdns-concurrent.sh)(进 CI):多上游→2 / 单上游→1 / 已有不动 / 二次幂等 / 上游顺序保留。

## 2026-06-23 — 评审第八轮:多上游真故障转移 + 测试去假阳性 + 探测发真查询

- **多上游=真故障转移(`concurrent: 2`)**:mosdns `forward` 默认 `concurrent=1` = **随机选 1 个上游、出错不换下一个**,多写上游并不会自动转移(查到挂的就直接失败)。两个 forward 块都显式设 `concurrent: 2`(并发查随机起点的 2 个、先返回的有效结果胜、出错的跳过)→ 任一上游挂掉查询仍成功。bot 改上游时也强制保留 `concurrent: 2`(否则退回默认 1,多上游形同虚设)。新增「一台上游故障仍可解析」回归用例(实证:改回 `concurrent:1` 该用例即失败)。
- **DNS 测试去假阳性**:`mock_dns.py` 现对 AAAA/HTTPS 返回**真实非空记录**——这样「代理域名 AAAA/HTTPS 被置空」断言验证的才是 mosdns 抑制逻辑(原先 mock 本就空,删掉抑制也会假阳性通过);并新增「国内域名 AAAA **不**被置空」断言。
- **上游探测发真实 DNS 查询**:`pdg doctor --deep` 的「DNS 上游探测」DoH 改为 POST `application/dns-message` 真查询并校验 HTTP200+应答(ID/RCODE/有回答),DoT 改为 TLS 握手 + DNS-over-TCP 查询并校验应答——不再「任意 HTTP 码 / 仅 TCP 连通」就算健康(CDN/反代/错服务占端口会被识破)。

## 2026-06-23 — 锦上添花:国内多厂商上游 / DNS 层功能测试 / 上游可观测

- **国内上游默认多厂商冗余**:`local_upstream` 默认加 `udp://119.29.29.29:53`(腾讯),与阿里 DoH+UDP 一起,阿里抽风/限速时异厂商顶上。想换/加仍用 bot『🌐 DNS 上游』。
- **DNS 层功能测试** [tests/dns-policy-test.sh](tests/dns-policy-test.sh)(并入 CI):真起 mosdns + 渲染真实 `config.yaml`,本地 mock 上游,断言「DNS as policy」核心——内网来源:代理域名 A 劫持到网关 IP、AAAA/HTTPS 置空、国内域名直连;**非内网来源不劫持**(按 `client_ip` 门控)。补上了此前只测流量层(SNI 分流)、DNS 层无测试的空白。
- **DNS 上游可观测性**:`pdg doctor --deep` 新增「DNS 上游探测」——逐个上游测可达性/延迟(UDP/TCP 发真实查询、DoH/DoT 测连通)、报每组 N/M 与最慢者,并统计**近 1h mosdns 上游错误次数**;整组不可达记 fail、部分挂记 warn。

## 2026-06-23 — 评审第七轮:原装识别改严格白名单(默认拒绝),收口

- **修漏检**:第六轮的语义判断只深查含 `dport` 的行,`ip saddr X accept` / `tcp accept` / `counter drop` 这类**不含 dport 的自定义规则会漏过**被当原装 → 迁移时静默删除。
- **改严格白名单(默认拒绝)**:`_fw_is_stock` 现要求去注释后**每一行都必须匹配某条已知原装规则**(用正则,兼容 forward/output 单行/多行、各年代端口子集);出现任何不认识的行即判自定义、跳过迁移。用全部 6 个历史模板(`144c865`~`8107b7f`,含 853 曾对全网开放、UDP 443 曾放行等早期形态)+ 真机备份验证均判原装;自定义一律跳过。
- **回归测试扩到 14 例**(6 原装变体 + 8 自定义,含上述三类无 dport 规则),并入 CI。

## 2026-06-23 — 评审第六轮:修第五轮"原装识别"误判 + 回归测试

- **修 bug**:第五轮的 `_fw_is_stock` 用逐行精确白名单,只认多行写法的 forward/output 链;而**真实老模板**(`62443ad`~`8107b7f`)的 forward/output 是**单行写法**,端口集也随年代不同({53,80,81,443}→+853→+8445)。结果**所有真·原装老配置都被误判为"自定义"**,自动迁移与 `pdg migrate-fw` 全部跳过 → 老机器永不迁移。
- **改为语义判断**:不再挑排版。只要"没有别的 table、hook 仅 input/forward/output、无 NAT 改写、无原装不用的匹配维度、每条 dport 规则的端口/来源都在允许范围"即判原装;单行/多行、各年代端口子集都正确识别;真有自定义(额外端口/额外表/额外来源/对全网开端口/转发规则)才跳过。
- **加回归测试** [tests/test-fw-migration.sh](tests/test-fw-migration.sh) 并入 CI:覆盖 4 种原装变体(含曾误判的单行写法)+ 5 种自定义,断言"原装应迁移、自定义应跳过";已验证它能抓到本次 bug。

## 2026-06-23 — 评审第五轮:迁移不静默丢用户自定义规则

- **迁移前先认"原装"**:`migrate_firewall_to_pdg` 用标准模板重建只保留 SSH端口+内网段,会丢掉用户在旧 `/etc/nftables.conf` 里手加的端口/规则/额外表。现新增 `_fw_is_stock` 白名单校验:**只有逐行全部落在已知原装行内才自动迁移**;检测到自定义端口/规则/别的 `table`(如 NAT)就**跳过并提示手动并入**,旧配置原样不动(hook/doctor 兼容旧表,不迁也能用)。

## 2026-06-23 — 评审第四轮:备份完整性 / 只读命令语义

- **迁移前确认备份完整才覆盖**:`migrate_firewall_to_pdg` 现 `cp` 后用 `cmp -s` 逐字节校验备份;备份失败/不完整(磁盘满)即**中止迁移、不动现网**;写新配置同样校验,失败则用已验证的备份还原。杜绝"备份没成、却已覆盖/截断 `/etc/nftables.conf`"。
- **只读命令不再触发迁移**:自动迁移只在**管理类**命令(`update`/`restart`/菜单等)触发;`status`/`doctor`/`log`/`traffic`/`report` 保持"只读不写"。只跑只读命令的可显式 `sudo pdg migrate-fw`(且不迁也能用:hook/doctor 兼容旧表)。[docs/INSTALL.md](docs/INSTALL.md) 增「升级」节说明。

## 2026-06-23 — 评审第三轮:迁移自愈 / 守卫删表 / active 防竞态

- **首次升级也能自动迁移**:`pdg update` 自更新时,当前进程跑的还是旧脚本、不会调用新迁移逻辑(要等下一次)。现新版 `pdg` **每次以 root 运行任意子命令时都幂等自检并迁移**(已迁移则首个 grep 秒退);另加显式命令 `sudo pdg migrate-fw`。
- **迁移加载失败绝不删旧表**:`migrate_firewall_to_pdg` 现 **只有 `nft -f` 成功且确认 `inet pdg` 已在内核** 才 `delete table inet filter`;失败则还原 on-disk 配置、保留旧表(`nft -f` 原子失败不改内核)→ 不会出现"新表没载入、旧表已删、防火墙消失"。
- **`active` 检查防竞态**:`_svc_active` 改为**要求连续多次保持 active**(flapping 的 failed/activating 会打断连击),不再"瞄到一次 active 就放行";安装的服务门同样改为连续 3 次保持。规则集回滚后**先确认旧服务恢复再删 `.bak`**,连旧档都起不来则保留 `.bak` 备查。

## 2026-06-23 — 评审第二轮:升级迁移 / 安装事务性 / 重启校验

- **`pdg update` 自动迁移旧防火墙**:老机器升级后,把旧的 `flush ruleset` + `table inet filter` 迁到独立表 `inet pdg`(解析旧配置里的 SSH 端口/内网段 → 渲染新模板 → `nft -c` 校验 → 备份 → `nft -f` → 删旧表,全程 SSH 不断、幂等)。不迁移则证书续期 pre-hook 进不了 `inet pdg`、开不了 80。
- **两种表名都兼容**:证书 pre-hook 与 `doctor` 的防火墙检查现同时认 `inet pdg`(新)和 `inet filter`(旧未迁移),避免老机器续期开不了 80 / 自检误报"读不到防火墙"。
- **已有部署不再用 install.sh 覆盖**:检测到既有部署时 `install.sh` **直接拒绝并引导 `pdg update`**(带快照+回滚);确需原机重装的显式 `PDG_FORCE_REINSTALL=1`,此时先打快照,失败用 `pdg rollback` 恢复。修掉了"已有部署回滚实为空操作、配置却已被改写"的问题。
- **安装成功门后移**:`systemd` 默认 `Type=simple`,`systemctl start` 返 0 不代表进程没随即崩溃。安装收尾改为**确认 mosdns/sing-box/probe81 真的 `active`** 才置"提交点",否则打印日志并触发回滚——不再"服务没起来也报装好"。
- **规则更新重启失败兜底**:`refresh_rulesets` 改为**重启 → 确认 `active` → 再删 `.bak`**;起不来则还原旧规则集并重启,不会断网后无可回滚。`apply_sb` 同样补 `is-active` 复核(同 `Type=simple` 隐患)。

## 2026-06-23 — 供应链/事务性/真功能测试(社区评审·可选项)

- **二进制 SHA256 校验(供应链)**:`install.sh` 下载 mosdns / sing-box 后,先比对**钉死的官方 SHA256**(amd64+arm64)再安装,不符即 `die` 拒装。版本号与 4 个哈希集中到单一可信源 [lib/versions.sh](lib/versions.sh),`install.sh` 与功能测试共用。
- **事务性安装·失败自动回滚**:`install.sh` 加 `trap … EXIT`,中途失败时——**全新安装**:停并清掉本次铺的单元/配置/二进制、`nft delete table inet pdg`、还原 `nftables.conf` / `resolv.conf` / `systemd-resolved` 到装前;**既有部署上升级失败**:不动其服务/配置/二进制(避免误伤),提示用 `pdg doctor` / `pdg rollback`。成功到防火墙应用后置"提交点",此后只剩打印、不再回滚。
- **真功能测试(非静态)**:新增 [tests/functional-test.sh](tests/functional-test.sh)——真起 sing-box(direct 入口开 sniff,与生产同款),用 3 个本地 mock SOCKS5 当出口,按不同 **TLS SNI** 发 ClientHello,断言被嗅探并路由到正确出口(域名规则 + `final` 兜底)。纯本地、`python3` + 官方 sing-box(钉死 SHA256 下载),CI 新增 `functional` job 跑它。

## 2026-06-22 — 安全与健壮性加固(社区评审采纳)

- **防火墙改独立表 `inet pdg`,不再 `flush ruleset`**:只 declare+delete 重建本表,不清掉 Docker / fail2ban / WireGuard 等其它表;install 备份原 `/etc/nftables.conf`、uninstall 删本表并还原。
- **收紧凭据权限**:`/etc/sing-box` 改 700,`config.json` / `.botbak` / 写入临时文件统一 600(含出口密码、uuid)。
- **规则集原子更新**:`refresh_rulesets` 改为 下临时文件 → 原子替换(留 .bak)→ `sing-box check` 通过才重启,坏档自动回滚、不重启,避免每日定时遇坏 `.srs` 断网。
- **卸载更干净**:uninstall 还原 systemd-resolved 与 `resolv.conf`(install 已备份)。
- **CI ShellCheck 改为阻断**(有 warning 即失败;systemd-analyze 仍 best-effort)。
- **修 bug**:① CGNAT `100.64.0.0/10` 被 `is_private` 误判为"危险公网"(检测已支持却自检报错)——现显式放行;② `PDG_SKIP_CERT=1` 后经 bot 首次签证书缺账户注册参数——补 `--register-unsafely-without-email`。

## 2026-06-21 — bot 分流/出口编辑

- **分流管理 → ✏️ 改出口**:选一条已有规则(域名组或规则集)直接改到别的出口,不用删了重加(同出口域名自动合并保持整洁)。
- **出口管理 → ↕️ 出口排序**:发一行新顺序即可重排出口列表。
- **出口管理 → ✏️ 改故障组**:选故障组→发新成员(空格分隔、按顺序),原地改、列表位置不变;`🔀 故障切换组` 改名为 `🔀 新建故障组`。
- **分流管理 → ✏️ 改规则集名**:给规则集起看得懂的显示名(如「币安」「OpenAI」),分流规则列表不再只显示 `rs_xxxx`;加规则集时也可在末尾直接带名称(`URL 出口 名称`)。加规则集提示改为「后缀 .list / .txt / .srs」。
- bot 发消息 HTML 解析失败时退回纯文本重试,避免出错信息(如 sing-box 报错含 `<`、`&`)导致消息+按钮静默丢失。
- **删规则改多选**:列出现有单域名(显示 `域名 → 出口`),勾选多个 → 点「✅ 确认删除(N)」**一次性删、只重启一次 sing-box**;留「✍️ 手动输入」兜底。
- **修复**:连续快速改配置(如连点删域名)会在 10 秒内多次 `restart sing-box`,撞上 systemd start-limit 把 sing-box 锁成 failed(配置本身没问题)。`apply_sb` 现在 restart 前先 `reset-failed`,且重启失败自动还原上一份配置重试,不会把代理留在挂掉状态。
- bot `answerCallbackQuery`(停按钮转圈)改后台异步,连点菜单不再每步叠加一个到 Telegram 的来回。

## 2026-06-21 — 工程化收口

不新增代理协议、不改分流语义,只做工程化与安全加固:

- **Token 迁移到 `bot.env`**:TG token / 允许 id 从 systemd unit 移到 `/etc/privdns-gateway/bot.env`(目录 700 / 文件 600),unit 改用 `EnvironmentFile=`。
  `pdg-set-token`、`healthcheck` 同步改读 bot.env;**旧装升级时自动迁移**(把 unit 里的明文 token 搬进 bot.env)。
- **`pdg update` 校验门加强**:更新前快照不变;更新后跑 `py_compile` + `sing-box check` + `nft -c` + `pdg doctor --json`。
  有 `fail` 自动回滚,`warn` 仅提示;未配置 token 时不把「pdg-bot 未运行」误判为失败。
- **新增 `pdg report`**:一条命令生成**脱敏**诊断快照(doctor / 服务 / 日志 / 版本 / 端口 / 证书 / A 记录 / 防火墙),自动隐藏 token、密码、uuid、出口链接,输出文件 600。
- **GitHub Actions CI**:`py_compile` + `bash -n` + JSON 模板渲染校验 + ShellCheck;另加 mobileconfig plist 校验 + `systemd-analyze verify`(best-effort)。纯静态,不启动服务。
- **文档**:README / INSTALL / 排障手册按句换行,便于阅读与 diff。
- **`pdg doctor --deep`**:在常规自检外追加慢速端到端检查(DoT 853 TLS 握手 / `:81` 探测 200 / mosdns 解析 / clash_api);代理劫持仅对内网卡来源生效,本机不可复现,如实标注。
- **`pdg report --redact-ip / --full`**:`--redact-ip` 连公网 IP、内网 CIDR、DoT 域名一并隐藏(贴公开 issue 用);`--full` 不脱敏仅本机看。默认行为与 600 权限不变。
- **bot 主菜单**:「📊 状态」按钮改为「🔄 更新」(检查→确认→后台 `systemd-run` 执行,不被自身重启打断)。
- **并发加锁**:`pdg update / rollback / snapshot` 用 `flock`(`/run/privdns-gateway.lock`)串行化,防 bot 更新按钮与命令行同时操作。
- **内网卡识别增强**:抓包过滤补 CGNAT `100.64.0.0/10`、改抓"打到网关服务的包"(不限 SYN,已连的 DoT 也能抓);新增 **`pdg detect-cidr`**——装完随时从容重测,与现配不符可一键写回 mosdns+nftables 并重启。安装时识别失败的提示改为引导用它。
- **防火墙拒 QUIC**:对内网卡来源的 **UDP/443 改为 `reject`**(原先放行),逼客户端回落 TCP/443(才能被嗅 SNI 分流),也避免 UDP 443 进 sing-box 自环。
- **Telegram 独立 SOCKS5**:sing-box 加一个仅内网卡可达的 `mixed` 入口(`:8445`),Telegram 内置代理填 `网关IP:8445` 即可(Telegram 走直连 IP、不吃 DNS+SNI 分流);出口可在 bot『📱客户端→✈️Telegram 出口』单独选(默认跟随「默认出口」)。
- **文档**:QUICKSTART 新增「局限与补丁」节(Speedtest/纯 UDP/直连 IP/Telegram 不走这套及兜底思路);新手图文教程(含示意配图)+ README 顶部入口。

## 2026-06-20 — 首个公开版本

### 网关核心
- **DNS 层 mosdns**:国内直连 / 代理域名 A 记录劫持到本机 + AAAA·HTTPS 置空 / 按来源 IP 分支 / ECS 分治 / 响应缓存;DoT(853)。
- **流量层 sing-box 1.12**:`direct` 监听 + `sniff_override_destination`(不用 tproxy);多出口,urltest 故障切换;clash_api。
- **一键安装** `install.sh`(自动识别公网 IP / 内网卡段,DNS 那步留用户)、`uninstall.sh`。

### 管理
- **`pdg` CLI**:`status` / `doctor` / `update [--dry-run]` / `snapshot` / `rollback` / `token` / `restart` / `log` / `traffic` / `ios` / `uninstall`。
- **Telegram bot**:出口(ss/vmess/trojan/vless)、故障切换组、分流规则、Surge 规则集、🔎测域名、测出口、流量、DNS 上游、TFO、配置备份/恢复、iOS 描述文件下发、自定义 DoT 域名。
  改 sing-box 前 check + 自动回滚。

### 可靠性与运维
- **`pdg doctor`** 只读自检(服务 / sing-box 版本 / DoT A 记录 / dot-domain 一致性 / 内网卡段 / 防火墙 / 证书 / 本机 DNS / sing-box check),支持 `--json`。
- **健康自检告警**:`pdg-health.timer` 每 10 分钟跑,异常 Telegram 私信(仅状态变化)。
- **snapshot / rollback**:整机配置 + 防火墙 + service 快照到 `/var/lib/privdns-gateway/backups`(留最近 10 份);
  `pdg update` 更新前自动快照、失败自动回滚。
- **配置备份/恢复机器感知**:跨机导入只搬出口/分流/规则集,本机 IP/证书路径/内网卡段保留。
- **证书** Let's Encrypt 自动续期(已处理续期时 80 口被 sing-box 占用的问题);**vnstat** 网卡流量统计。

### 安全
- nftables 暴露面收敛:对全网仅 SSH;`53/80/81/443/853` 仅放行内网卡来源段。

> ⚠️ sing-box 必须 1.12.x:1.13+ 移除了 `sniff_override_destination`,本网关会失效。详见 [docs/INSTALL.md](docs/INSTALL.md)。
