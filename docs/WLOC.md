# 无 Egern 的服务端 iOS WLOC

PrivDNS Gateway 可以在不运行 Egern、Surge、Loon 等客户端代理的情况下，对自有 iPhone 的 Apple 网络定位响应做定点修改。

它修改的是 Apple Wi-Fi / 基站网络定位，不是 GPS 硬件数据。室外 GPS 信号较强时，系统或 App 仍可能采用真实 GPS。

## 数据路径

```text
普通流量 → mosdns → mihomo → 原有出口

gs-loc.apple.com / gs-loc-cn.apple.com
  → mosdns 返回网关 IP
  → mihomo 从 TLS SNI 识别域名
  → 127.0.0.1:9080 pdg-wloc (mitmproxy)
  → 修改 /clls/wloc protobuf 响应
  → Apple
```

MITM 只在 WLOC 开启时运行，也只接收上述两个精确域名。其它流量不会进入 mitmproxy。

## 首次使用

1. Telegram Bot 主菜单点 `📍 iOS 定位`，也可发送 `/wloc`；这个入口始终可重新打开。
2. 点 `📜 安装专用 CA`，保存并安装 Bot 发来的 `PrivDNS-WLOC-CA.mobileconfig`。
3. 在 iOS 打开 `设置 → 通用 → 关于本机 → 证书信任设置`，对 `mitmproxy` 开启完全信任。描述文件名称是 `PrivDNS WLOC CA`，但证书列表显示的是证书自身名称 `mitmproxy`。
4. 回到 Bot，直接点服务器预置地点。按钮只提交预置 ID，不要求发送 Telegram Location。
5. 没有合适预置时可点 `✍️ 输入经纬度`，发送 WGS84 `纬度,经度`。
6. 首次完全信任 CA 并设置目标后重启 iPhone，让 `locationd` 重新建立 TLS 会话并重新获取 WLOC 数据。

首次设置会启动 sidecar，并各重载一次 mihomo、mosdns。以后切换坐标只原子更新 `/var/lib/pdg-wloc/wloc.json`，不会重启 DNS 或代理。

## 添加常用地点

常用地点保存在服务器 `/etc/privdns-gateway/wloc-presets.json`，Bot 每次打开 WLOC 页面都会重新读取，无需重启。每项需要唯一短 ID、显示名称、WGS84 纬度/经度和精度：

```json
{
  "presets": [
    {
      "id": "p001",
      "name": "香港西九龙站",
      "latitude": 22.303611,
      "longitude": 114.165,
      "accuracy": 25
    }
  ]
}
```

保存后重新打开 `/wloc` 即可看到按钮。无效坐标、重复 ID 和超过 40 字的名称会被忽略。

## 恢复真实定位

在 WLOC 页面点 `♻️ 关闭并恢复真实定位`。系统会按以下顺序撤销：

1. 清空 WLOC DNS 域名集并重启 mosdns，清除服务端缓存。
2. 从 mihomo 删除两个域名规则和本地 HTTP sidecar 出口。
3. 停止并禁用 `pdg-wloc.service`。

专用 CA 描述文件会留在 iPhone，方便下次使用。长期不用时可在 iOS 的 VPN 与设备管理中删除该描述文件。

## iOS 缓存与验证

- iOS 新版本可能长期缓存 `locationd` 结果。首次信任 CA、设置新位置或恢复真实位置后仍显示旧坐标时，重启 iPhone。
- 飞行模式或单独关闭定位服务不一定能清除该缓存。
- 建议先在室内或 GPS 信号较弱处验证 Apple 地图。
- 手机流量必须经过 5GPN 内网卡链路；普通 Wi-Fi 若没有到该网关的数据路径，服务端无法看到定位请求。

## 安全边界

- CA 私钥只保存在 `/var/lib/pdg-wloc/mitmproxy/`，目录权限 `700`，运行用户为无登录权限的 `pdg-wloc`。
- Bot 只发送公开 CA 证书，不发送私钥。
- sidecar 只监听 `127.0.0.1:9080`，防火墙不对外开放该端口。
- protobuf 插件只处理两个 Apple 主机的 `/clls/wloc` 响应，异常时原样透传。
- 目标坐标保存在服务器 `/var/lib/pdg-wloc/wloc.json`，属主 `pdg-wloc`、权限 `600`；响应内容不落盘。

## 排查

```bash
sudo pdg status
sudo pdg doctor
sudo journalctl -u pdg-wloc -n 80 --no-pager
```

`pdg doctor` 会检查 sidecar、CA、mosdns 域名集和 mihomo 精确域名规则。WLOC 关闭时，`pdg-wloc` 显示 `inactive` 是正常状态。
