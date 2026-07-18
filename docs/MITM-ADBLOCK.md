# 服务端 MITM 去广告

PrivDNS Gateway 可以复用 WLOC 的共享 CA 和本地 mitmproxy sidecar，在不运行 Egern、Loon 或 Surge 的情况下执行一部分声明式去广告规则。

## 使用

1. Telegram Bot 主菜单点 `🛡 MITM 去广告`，也可发送 `/adblock`。
2. 如果此前已为 WLOC 安装并完全信任同一张 `mitmproxy` CA，不需要重复安装；否则点 `📜 安装共享 CA`，安装后在 iOS 的证书信任设置中开启完全信任。
3. 点 `✅ 同步并开启`。Bot 会先下载并编译允许列表中的模块，通过校验后才写入运行配置。
4. 以后点 `🔄 同步规则` 可原子更新。任一模块下载失败时会保留上一份缓存，不应用残缺规则。

默认来源保存在 `/etc/privdns-gateway/adblock-sources.json`。当前清单来自原 Egern 配置中的 25 个公开 Kelee/Loon 模块；页面显示每次实际编译出的模块、精确主机、规则和未移植脚本数量。

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
