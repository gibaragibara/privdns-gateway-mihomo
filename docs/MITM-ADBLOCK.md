# 服务端去广告

PrivDNS Gateway 在不运行 Egern、Loon 或 Surge 的情况下提供两层去广告：普通 `REJECT` 域名规则由 mihomo 直接拦截；需要修改响应的声明式规则复用 WLOC 的共享 CA 和本地 mitmproxy sidecar。

## 使用

1. Telegram Bot 主菜单点 `🛡 去广告`，也可发送 `/adblock`。
2. 如果此前已为 WLOC 安装并完全信任同一张 `mitmproxy` CA，不需要重复安装；否则点 `📜 安装共享 CA`，安装后在 iOS 的证书信任设置中开启完全信任。
3. 点 `✅ 同步并开启`。Bot 会先下载并编译允许列表中的模块，通过校验后才写入运行配置。
4. 以后点 `🔄 同步规则` 可原子更新。任一模块下载失败时会保留上一份缓存，不应用残缺规则。

在 `🧩 MITM 插件管理` 中，删除以单个 Kelee/Loon 插件 URL 为单位；点 `➕ 添加插件 URL` 后发送一个 HTTPS 插件地址即可。首次添加会固定模块正文 SHA256。每日检查发现正文变化时，旧的 last-known-good 版本继续运行，插件页显示主机和规则差异；只有点“批准并应用”并再次核对完整 SHA 后才会切换。删除的插件不会在升级时自动恢复。

在 `📚 REJECT 规则源` 中，可以发送 HTTPS 的 Surge/Clash `.list`、纯域名/domain-set、Clash `payload:` YAML 或 JSON URL。服务器会自动识别、校验、合并去重并转换为 MRS；`DOMAIN-KEYWORD` 与 IP 规则进入小型 classical provider。列表中的删除操作以 URL 为唯一标识，删除后不会在升级时自动恢复。二进制 `.mrs/.srs` 和广告过滤器语法不会作为文本规则导入。

下载以 4 个来源为一批并行执行，每类来源最多 64 个。为避免第三方列表耗尽小型服务器内存，普通 REJECT 文本最多 50 万行、单源最多 40 万条唯一规则、全部来源合计最多 60 万条，JSON 输入另限制为约 8 MiB；超过限制时保留上一版。来源配置损坏或不可读时，Bot 会拒绝增删并保留原文件。

来源保存在服务器私有的 `/etc/privdns-gateway/adblock-sources.json`；仓库默认清单为空，不携带实际插件 URL、REJECT 来源或私有转换。页面分别显示普通 REJECT、可执行响应改写、不可达重写和待批准模块数量。`pdg-rules-update.timer` 每日检查一次（约 24 小时）；已批准模块下载失败时使用本机校验过的缓存，正文变化时只暂存差异。

模块中的远程 JavaScript 不会直接执行。可在同一服务器私有文件中用 `script_conversions` 将已审查脚本绑定到 SHA256 和原始脚本声明，再转换成受限动作；`external_jq_pins` 以相同方式导入已审查的 `jq-path`。实际转换条目、程序和固定哈希只存在服务器，仓库默认值为空：

```json
{
  "script_conversions": [{
    "name": "example",
    "script_url": "https://example.com/remove-ads.js",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "entries": [{
      "phase": "response",
      "pattern": "^https://api\\.example\\.com/feed",
      "rules": [{
        "action": "response-body-json-jq",
        "arguments": {"program": "del(.data.ad)"}
      }]
    }]
  }],
  "external_jq_pins": [{
    "name": "example jq",
    "url": "https://example.com/remove-ads.jq",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }]
}
```

每日同步会重新下载固定资源：网络失败时整次同步失败并保留上一份完整缓存；内容哈希变化时对应转换立即不进入新缓存，Bot 的“固定资源失效”计数会增加。模块改了 URL 匹配表达式但脚本未变时也不会误套旧转换，而会重新显示为“剩余”脚本。

临时抓到但公开列表尚未收录的规则可放进同一服务器私有文件的 `local_domain_rules`。它接受纯域名、`+.example.com` 后缀或 `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `IP-CIDR` 等 classical 行；删除时从数组移除对应行再同步。数组会随服务器配置备份与每日编译保留，但实际内容不会写回仓库：

```json
{
  "local_domain_rules": [
    "ads.example.com",
    "+.tracker.example.com",
    "DOMAIN-KEYWORD,example-ad-token"
  ]
}
```

普通域名规则在服务器运行时编译为 `/etc/mihomo/rs/__pdg_adblock_reject.mrs`，无法无损转换的少量关键字/IP 规则写入独立 classical provider。已移植插件的精确 MITM 主机优先于宽泛 REJECT，以便路径级规则返回正确的空响应；其他域名仍由 REJECT 直接拦截，不使用 CA。第三方规则、来源 URL、MITM 插件正文、固定 SHA 和所有编译结果只保存在服务器，不提交进仓库；仓库只保存配置格式、转换器和运行时解释器。

## App 兼容旁路

有些插件为了改少数接口，会把 App 的核心 API 整个加入 `[MitM]`。即使某个请求没有命中重写，它仍会由服务端重新建立 TLS，并使用服务器或代理出口；风控严格、证书固定或依赖原网络特征的 App 可能因此白屏。可在服务器私有的 `/etc/privdns-gateway/adblock-sources.json` 中配置精确 MITM 排除和高优先级路由：

```json
{
  "mitm_exclude_hosts": ["api.example.com"],
  "compatibility_routes": [
    {"type": "domain", "value": "api.example.com", "outbound": "residential"},
    {"type": "domain-suffix", "value": "cdn.example.com", "outbound": "residential"}
  ]
}
```

`mitm_exclude_hosts` 只接受精确主机名；编译后这些主机不会进入 mosdns 劫持表或共享 sidecar。`compatibility_routes` 只支持 `domain` 与 `domain-suffix`，出口必须已存在于 mihomo 状态中，并且会排在普通 REJECT、MITM 和常规分流规则之前。修改后通过 Bot 点一次 `同步规则` 即可原子重新编译并应用；服务器私有条目和实际域名不会被升级合并到仓库。

运行时会按主机索引声明式规则，并以 lazy 模式生成本地证书；本地 `204` / 空字典等合成响应不会为取得上游证书而先连接广告服务器。若日志持续出现某个主机的 `Client TLS handshake failed`，说明 App 很可能使用证书固定，应将该精确主机加入 `mitm_exclude_hosts`，而不是反复重试 MITM。

对于需要保持原始 TLS、但必须从网关出口访问的系统服务（例如 APNs），规则集元数据可以在服务器的 `rulesets.json` 中标记 `force_gateway: true`。Bot 会每日刷新该 URL，将其中的域名规则同步到 `force_proxy.txt`，并把域名/IP 规则置于普通 REJECT 和 MITM 之前；这类连接始终是 TLS 透传，不使用共享 CA。规则集正文和 URL 只保存在服务器。

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

服务器私有脚本转换还支持按请求头生成请求/响应、字面文本替换、按标记删除 HTML 元素以及修改 HTML 内嵌 JSON。这些动作与 jq 都有正文、规则数量、程序长度和运行超时限制；不提供文件、网络或进程 API。

不会执行 `[Script]` 中的远程 JavaScript，也不会执行未固定哈希的外部 `jq-path` 或 ProtoBuf 脚本。脚本正文只用于计算 SHA256，实际请求执行的是服务器私有声明式转换。`*.example.com` 只作为模块允许范围：编译器必须从 URL pattern 或私有 `hosts` 中安全得到精确主机，并应用 `-host` 排除项，才会把该主机送入 MITM；无法收敛的规则计为“不可达”而不会扩大到整个后缀。它不是 Egern/Loon 的完整替代品；Bot 页面分别显示脚本转换进度、剩余脚本、外部 jq、不可达规则和待批准更新。

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
