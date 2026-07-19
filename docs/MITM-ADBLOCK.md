# 服务端去广告

PrivDNS Gateway 在不运行 Egern、Loon 或 Surge 的情况下提供两层去广告：普通 `REJECT` 域名规则由 mihomo 直接拦截；需要修改响应的声明式规则复用 WLOC 的共享 CA 和本地 mitmproxy sidecar。

## 使用

1. Telegram Bot 主菜单点 `🛡 去广告`，也可发送 `/adblock`。
2. 如果此前已为 WLOC 安装并完全信任同一张 `mitmproxy` CA，不需要重复安装；否则点 `📜 安装共享 CA`，安装后在 iOS 的证书信任设置中开启完全信任。
3. 点 `✅ 同步并开启`。Bot 会先下载并编译允许列表中的模块，通过校验后才写入运行配置。
4. 以后点 `🔄 同步规则` 可原子更新。任一模块下载失败时会保留上一份缓存，不应用残缺规则。

在 `🧩 MITM 插件管理` 中，删除以单个 Kelee/Loon 插件 URL 为单位；点 `➕ 添加插件 URL` 后发送一个 HTTPS 插件地址即可。添加或删除时，如果去广告已开启，会自动重新编译剩余来源；关闭状态下只保存来源并在下次开启时应用。删除的插件不会在升级时自动恢复。

在 `📚 REJECT 规则源` 中，可以发送 HTTPS 的 Surge/Clash `.list`、纯域名/domain-set、Clash `payload:` YAML 或 JSON URL。服务器会自动识别、校验、合并去重并转换为 MRS；`DOMAIN-KEYWORD` 与 IP 规则进入小型 classical provider。列表中的删除操作以 URL 为唯一标识，删除后不会在升级时自动恢复。二进制 `.mrs/.srs` 和广告过滤器语法不会作为文本规则导入。

下载以 4 个来源为一批并行执行，每类来源最多 64 个。为避免第三方列表耗尽小型服务器内存，普通 REJECT 文本最多 50 万行、单源最多 40 万条唯一规则、全部来源合计最多 60 万条，JSON 输入另限制为约 8 MiB；超过限制时保留上一版。来源配置损坏或不可读时，Bot 会拒绝增删并保留原文件。

默认来源保存在 `/etc/privdns-gateway/adblock-sources.json`。普通层包含原 Egern 配置中的 Sukka Reject、Cats-Team AdRules、AWAvenue 三个公开规则源；MITM 层包含 25 个公开 Kelee/Loon 模块。页面分别显示普通 REJECT 与响应改写的实际编译数量。两类来源由 `pdg-rules-update.timer` 每日刷新一次（约 24 小时）；下载失败保留上一版。

普通域名规则在服务器运行时编译为 `/etc/mihomo/rs/__pdg_adblock_reject.mrs`，无法无损转换的少量关键字/IP 规则写入独立 classical provider。两者都优先于 MITM 域名规则匹配，不需要安装 CA。第三方规则、MITM 插件正文和所有编译结果只保存在服务器，不提交进仓库；仓库只保存来源 URL 元数据、转换器和运行时解释器。

## 与 WLOC 的关系

两个功能分别维护状态，但复用 `/var/lib/pdg-wloc/mitmproxy/` 中的 CA、`127.0.0.1:9080` sidecar 和 mihomo 本地 HTTP 出口。

| WLOC | 去广告 | Apple 定位 | 共享 sidecar |
|---|---|---|---|
| 关闭 | 关闭 | 原始直连 | 停止 |
| 开启 | 关闭 | 修改到目标位置 | 运行 |
| 关闭 | 开启 | 原始直连 | 运行，仅处理去广告主机 |
| 开启 | 开启 | 修改到目标位置 | 运行，同时处理两类精确主机 |

因此，WLOC 页面里的 `关闭定位改写` 不会删除 CA，也不会影响去广告。只有两个功能都关闭时，systemd 才停止 sidecar。

## 已移植范围

编译器目前支持以下 `[Rewrite]` 动作：

- `reject`、`reject-200`、`reject-dict`、`reject-img`
- `mock-response-body`
- `response-body-json-del`、`response-body-json-replace`
- 内联且受限的 `response-body-json-jq`
- `response-body-replace-regex`、`response-header-add`

不会下载或执行 `[Script]` 中的远程 JavaScript，也不会导入外部 `jq-path`、ProtoBuf 脚本和通配 MITM 主机。它不是 Egern/Loon 的完整替代品；Bot 页面中的“未移植脚本”和“未支持重写”是明确缺口，不代表执行成功。

## 数据路径与边界

启用后，编译器把模块声明的精确主机写入独立的 `adblock.txt`。只有这些 DNS 查询会返回网关 IP，mihomo 再按 TLS SNI 将对应连接送入本地 sidecar。普通流量、Apple 定位域名和原有 mosdns/mihomo 出口规则不会因去广告而改写。

sidecar 只监听 `127.0.0.1:9080`，CA 私钥不离开服务器，状态与规则缓存权限为 `600`，日志不记录响应正文。安装证书不等于所有 App 都能解密：采用证书固定的 App 仍可能拒绝连接，应从来源清单禁用相关模块或关闭去广告。

手机必须通过 5GPN 的 DoT 与数据路径才能命中这些规则。普通 Wi-Fi 若未接入该路径，去广告和 WLOC 都不会生效。

## 排查

```bash
sudo pdg doctor
sudo journalctl -u pdg-wloc -n 100 --no-pager
```

`pdg doctor` 会核对启用状态、共享服务、CA、编译缓存、mosdns 精确域名集和 mihomo 规则。关闭 WLOC 后 sidecar 仍为 `active`，只要去广告处于开启状态，就是预期行为。
