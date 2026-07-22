# iOS 全设备 Apple Network Relay

## 目标架构

```text
iOS 17+（系统 Network Relay，全部域名）
  -> TLS / HTTP/2 :20443（X-Relay-Token）
  -> Envoy CONNECT / CONNECT-UDP（pdg-relay 用户）
  -> nft output TPROXY（只匹配 pdg-relay UID）
  -> mihomo :7893
       -> 现有出口与故障组
       -> 普通 REJECT 规则
       -> 精确主机 HTTP sidecar -> MITM 去广告 / WLOC
       -> ChinaMax domain/ipcidr MRS -> KFC DIRECT
```

Apple 的 Relay payload 在 `MatchDomains` 和 `MatchFQDNs` 都为空时会处理全部域名。
本项目不写这两个键，只把 Relay 自身域名放进 `ExcludedDomains`，避免连接 Relay 时再次套入
Relay。协议和 payload 定义见 [Apple Relay 文档](https://developer.apple.com/documentation/devicemanagement/relay)。

旧 DoT 模式下，ChinaMax 命中的国内请求在 DNS 层拿到真实 IP 后由手机直连，不会进入 mihomo。
全量 Relay 会把这些请求也送到网关，因此每日规则更新会额外把 ChinaMax 编译为 domain/ipcidr
MRS（少量关键词为 classical provider）。规则顺序是：精确 MITM / REJECT / 用户显式分流 →
ChinaMax `DIRECT` → 默认国际出口，避免京东等未显式配置的国内 App 绕到海外。

KFC 没有原生 IPv6 默认路由时，`pdg-relay` UID 的 IPv6 socket 会先通过专用策略路由回到
本机，再由 mihomo 交给默认代理；否则 Envoy 会在进入 nft 之前直接返回 `ENETUNREACH`，导致
iOS App 重试/回退而明显变慢。ChinaMax IP MRS 因此只编译 IPv4 CIDR，域名规则仍可通过
SNI/HTTP Host 将有 IPv4 节点的国内服务送到 `DIRECT`。

## 为什么使用 20443

现有 5GPN 旧链路把手机发往网关 `:443` 的普通 HTTPS/QUIC 透明送入 mihomo。如果 Envoy 直接
占用 `:443`，旧链路会立即失效。并行阶段使用 `:20443`，新 Relay 与旧 DoT/TPROXY 可以同时
存在；验证失败只需移除手机描述文件并停掉 Relay。

云厂商安全组需要允许公网入站 `20443/tcp`。服务器本机由 `pdg-relay` 启动时动态创建
`inet pdg_relay` 表，只放行这个入口并只捕获 Envoy 用户的出站。停服务会删除该表和专用策略路由。

## 启用与下发

```bash
sudo pdg relay enable
sudo pdg relay status
```

首次启用会下载锁定版 Envoy，校验 SHA256，复用当前 DoT 域名和 Let's Encrypt 证书。随后在
Telegram bot 打开 **客户端 -> iOS 全量 Relay -> 发送全量 Relay 描述文件**。

也可直接在服务器生成：

```bash
sudo pdg relay profile --output /tmp/PrivDNS-Full-Relay.mobileconfig
```

配置内含私有 `X-Relay-Token`，不要公开转发。轮换 token 会使旧描述文件立刻失效：

```bash
sudo pdg relay rotate-token
```

## MITM 与 WLOC

Relay 只负责把全设备 TCP/UDP 送到 mihomo，不会自动解密 HTTPS。普通 REJECT 仍不需要证书；
响应改写和 WLOC 继续使用现有共享 CA。已经安装并信任该 CA 的手机无需安装第二套 CA。

证书固定的 App 仍会绕不过 pinning；它们应通过 `mitm_exclude_hosts` 旁路。Relay 不改变这条限制。

## MDM 边界

生成的是标准 `com.apple.relay.managed` payload，可手工安装，也可以由 MDM 下发。手工安装可先
验证完整数据面，不要求先搭 MDM。

真正的 MDM 还需要 Apple MDM Push Certificate、设备注册、签名与 APNs 命令通道。这些凭据
不能由服务器自行生成，本项目当前不启动一个假的 MDM 服务。接入现有 MDM 后，应由 MDM 同时
下发 Relay payload 和共享 CA；MDM 下发的根证书可由系统按受管证书处理。

## 回退

1. 先从 iPhone 移除 **PrivDNS 全量 Relay** 描述文件。
2. 确认旧 DoT 描述文件仍在，需要时重新启用它。
3. 服务器运行 `sudo pdg relay disable`。
4. 运行 `sudo pdg doctor`；`mosdns`、`mihomo`、MITM 和 WLOC 状态不应被更改。

全量 Relay 会让国内直连也先经过 KFC，再从服务器直出，因此比旧模式多一段往返。若国内站
延迟明显增加，应根据实际体验选择继续全量，或回到旧 DoT 的“国内手机直连”路径。
