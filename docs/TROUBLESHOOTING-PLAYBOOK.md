# 排障手册 (Playbook)

出问题先跑一条 **`sudo pdg doctor`** —— 只读检查会直接点出大部分故障(服务、mihomo 版本、DoT A 记录、dot-domain 一致性、内网卡段、防火墙、GMS、证书、本机 DNS、mihomo 配置)。
下面是按症状的细查。

---

## iOS 能连但上不了外网 / DoT 没激活
iOS 靠描述文件的 OnDemand「探测 `:81` 成功才启用 DoT」(Wi-Fi 与蜂窝同逻辑)。
- **查**:服务器 `:81` 必须返回 **HTTP 200**(不是 204,iOS 不认 204);手机抓不到 DoT(`:853`)说明没激活。
  服务器上:`curl -s -o /dev/null -w '%{http_code}' --interface <内网卡IP> http://<本机IP>:81/probe` 应为 `200`。
- **修**:① 确认 `pdg-probe81` 在跑、:81 返 200;② **手机删掉旧描述文件** → bot「📱 iOS 描述文件」或 `sudo pdg ios` 装新的 → 开关飞行模式。
- 普通宽带 Wi-Fi 探不通 `:81` 会自动不启用 DoT(预期行为);若某 Wi-Fi 误判,生成描述文件时填 SSID 强制直连。

## 安卓 Wi-Fi 下「私人 DNS 服务器无法访问」
- **根因**:旧版防火墙把 `853` 只放给内网卡段,手机在普通 Wi-Fi 源 IP 不是 `172.x` → DoT 被 drop,Android 整网 DNS 挂掉。
- **查**:`sudo pdg doctor` 防火墙项应提示「853 DoT 公网可达」;`nft list chain inet pdg input | grep 853` 应有**不带 saddr 限制**的 `tcp dport 853 accept`。
- **修**:`sudo pdg restart`(会触发迁移)或升级到 `v1.2.0+` 后跑管理类 `pdg` 命令。

## 手机完全没网(连国内都打不开)
多半是 mosdns 没在应答。
- **查**:`sudo pdg doctor` 看「服务 / 本机DNS」;`systemctl status mosdns`;`journalctl -u mosdns -n 30`。
- **常见根因**:mosdns 证书路径不对 → mosdns 崩溃重启。doctor 的「DoT A 记录 / mihomo 配置」也会连带异常。
- **修**:把 `/etc/mosdns/config.yaml` 的 `cert:` 指到真实存在的证书(`/etc/mosdns/certs/…`),`systemctl restart mosdns`。

## 流量没到本机 / 内网卡不通
- **查**:`tcpdump -ni any host <本机公网IP> and not port 22`,让手机(走内网卡,关 WiFi)访问网页,看有没有 `172.x → 本机` 的包。
- **没有包** = 内网卡没路由到这台(运营商侧的事,脚本管不了);确认手机私密 DNS 域名指向本机的 DoT 域名。

## 证书续期失败 / 快到期
- **查**:`sudo pdg doctor` 的「证书」;`certbot renew --dry-run`。
- **根因**:① 云厂商安全组挡了入站 **80**(Let's Encrypt HTTP-01 要从公网访问 80);
  ② `dot-domain` 文件与证书 CN 不一致(doctor 的「DoT 域名一致性」会警告)→ 续期会部署错证书。
- **修**:① 安全组放行 80;② `echo <证书CN域名> > /opt/pdg-bot/dot-domain`。

## mihomo 起不来 / 配置 test 失败
- **查**:`mihomo -t -d /etc/mihomo`;`journalctl -u mihomo -n 40`;`sudo pdg doctor` 的「mihomo 配置」。
- **修**:bot 改配置失败会自动回滚;也可 `sudo pdg rollback`。手改 `/etc/mihomo/state.json` 后务必 `mihomo -t` 再 `systemctl restart mihomo`。

## NIKKE / 部分 App 提示网络错误，但网页正常
- **根因**:旧安装可能对手机源 UDP/443 使用静默 `drop`；QUIC-first App 收不到失败响应，会持续重传并在回落 TCP 前先报错。
- **查**:`sudo pdg doctor` 的「QUIC 回退」应显示「UDP/443 快速 reject」；`nft list chain inet pdg prerouting` 不应出现 `udp dport 443 drop`。
- **修**:`sudo pdg restart` 触发幂等迁移，把项目精确规则从 `drop` 改为 `reject`。QUIC 仍被禁用，MITM 不会被 HTTP/3 绕过。

## iOS WhatsApp 发不出 / 一直转圈
- **根因**:WhatsApp Noise 无 SNI;若 DNS 把域名 black_hole 到本机,mihomo 嗅探不到真实目的。
- **查**:`grep geosite_wa /etc/mosdns/config.yaml`;`test -f /etc/mosdns/rules/whatsapp.txt`;从内网卡侧 dig `g.whatsapp.net` 应得到**公网真 IP**(不是网关 IP)。
- **修**:升级 `v1.2.0+` 或 `sudo pdg restart` 触发 `migrate_mosdns_whatsapp`。

## Google 推送慢 / GMS 连不上
- **查**:`sudo pdg doctor` 的「GMS 推送」;内网放行是否含 `5228-5230`(TPROXY 全端口时数据面已覆盖)。
- **修**:管理类 `pdg` 命令触发迁移,或防火墙内网段补 `5228-5230`。

## 代理域名走错出口 / 不确定某域名走哪
- 用 bot **📑 分流管理 → 🔎 测域名**,或思路:mosdns 先判直连(国内)还是劫持(其余),mihomo 再按规则首条匹配选出口。

## bot 按钮反应慢
- `v1.2.0+` 已把测出口/自检/加出口等慢操作放到后台线程;若仍慢,下限是本机到 `api.telegram.org` 的 RTT。
- 若**又慢又时灵时不灵**:大概率**两台机用同一个 bot token**在抢 getUpdates。一个 token 只能一个实例轮询。

## 流量统计"看着不准"
- bot 📈流量 的「实时」来自 mihomo external-controller = **本会话**(重启清零)且**只算经代理的流量**;不是机器总用量。
- 要准确的今日/本月/累计看「总用量(vnstat·网卡真实)」或 `sudo pdg traffic`。

## 改坏了想退回
- `sudo pdg rollback`(默认回最近一次快照;`pdg snapshot` 可手动留底)。`pdg update` 失败会自动回滚。

## 想把现场贴给别人排障
- `sudo pdg report`(脱敏);加 `--redact-ip` 连 IP/域名也藏;加 `--full` 不脱敏(慎用)。
