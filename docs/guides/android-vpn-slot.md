# Android 只有一个 VPN 槽位：hextet 与代理/其他 VPN 的取舍

状态：**前瞻文档**。Android 客户端（VpnService）尚未实现（M7 切片 D，见
`docs/superpowers/plans/2026-08-13-m7-android.md`）；本文档按设计 spec §2 / §5 已定的
DNS/路由姿态，提前写清 hextet 在 Android 上会撞上的「单一 VPN 槽位」限制与应对，
让客户端落地前就心里有数。文中所有「hextet 会/不会」都指**规划行为**，不是当前可用功能。

> 一句话：Android 系统**同一时刻只允许一个 VPN 应用**持有 tun。hextet 和 Clash/mihomo
> 系代理、Tailscale、公司 VPN 抢的是同一个槽位，谁后开谁把先开的那位挤掉。这不是
> hextet 的缺陷，是 Android 的硬限制，Tailscale 撞的也是它。

## 1. 单槽位是什么

Android 的 VPN 能力由 `VpnService` 这个系统 API 提供：应用调用 `establish()` 拿到一个
tun 设备，系统把「该走 VPN」的流量路由进这个 tun。关键是：**系统全局只认一个正在活动的
VpnService**。

- 你开启 hextet，之前开着的 Clash/mihomo TUN、Tailscale、公司 VPN 会被系统**自动断开**；
- 反过来，你开启任意一个代理或其他 VPN，正在跑的 hextet 会被挤下线。

两者**不能**同时在一台手机上活动。这是 Tailscale 用户早就熟悉的体验：Tailscale 和
其他 VPN App 互相踢，原因完全相同。

> 为什么不能做成「多槽位」？这是 Android 平台的设计决定，应用层绕不过去。系统的
> 「始终开启 VPN」与「按应用分流」也只是「哪个应用占用这唯一槽位」的排他策略，并不会
> 凭空多出一个 tun。

## 2. 和谁冲突

| 应用 | 冲突原因 |
|---|---|
| Clash / mihomo / 各类 mihomo 内核的 TUN 代理（Clash Verge、Clash Meta 等） | fake-IP 透明代理同样走 VpnService 的 tun 抢流量 |
| Tailscale（迁移期） | 同为 mesh VPN，抢同一槽位 |
| 其他 mesh VPN（NetBird / Netmaker / ZeroTier 等） | 同上 |
| 公司 VPN / 校园 VPN | 同上 |

## 3. hextet 特意「不做什么」，让冲突降到最轻

hextet 在 Android 上沿用 spec §5 定的两条硬姿态。它们**不消除**单槽位限制，但把
「路由/DNS 层面的打架」归零，让槽位成为**唯一**的冲突点：

- **永不接管系统 DNS**：不捕获 DNS 请求、不做 fake-IP、不改系统 DNS 设置。节点名解析
  用 MagicDNS-lite（生成 hosts 条目，见 [hosts](hosts.md)）。因此与 Clash 的 fake-IP、
  Tailscale 的 accept-dns 这些「DNS 争夺战」绝缘。
- **只加自己网络的 ULA /48 路由**：前缀具体、优先级明确，不接管默认路由。与 Clash TUN
  的分段默认路由（1/8、2/7…）、Tailscale 的 100.64/10 + fd7a::/48 在路由表层面本可共存
  （hextet 派生的前缀与 Tailscale 的 fd7a:115c:a1e0::/48 碰撞概率为零，安装时仍会校验）。

也就是说，**在路由层，hextet 和一个代理本来是能井水不犯河水的**：一个只管
`fdXX:XXXX:XX::/48`，一个只管默认/分流。但 Android 的 VpnService 只让一个应用握住 tun，
所以就算路由不冲突，它们**仍然无法在同一台手机上同时运行**。冲突点从「路由/DNS 打架」
收敛成了「谁占这个槽位」这一件事。

## 4. 推荐策略

### 4.1 在家/固定场景：把 hextet 放到路由器上，手机零客户端

这是设计 spec §2 明确的推荐（家庭场景优先靠路由器组网，让手机在家零客户端）：

- 在 OpenWrt 路由器（或一台常电 Linux 机器）上跑 hextet 作 site 网关，背后 LAN 设备
  经 RA/SLAAC 自动拿到 overlay ULA 地址，**无需安装客户端**。手机什么都不用装、什么都不
  用占槽位，照样访问 mesh 里的其他节点。
- 手机上的代理 App（Clash/mihomo）该怎么跑还怎么跑，互不影响。

上手见 [openwrt](openwrt.md)（路由器打包）与 [site-to-site](site-to-site.md)（子网路由）。

### 4.2 外出场景：接受单槽位，hextet 与代理二选一、按需切换

出门在外、够不着路由器时，手机要直连 mesh 就得自己装 hextet 客户端。此时：

- **要么**开 hextet（访问 mesh 节点），**要么**开代理（上外网），按当前要干什么切换；
- 切换就是「关一个、开一个」的几秒操作，状态不会丢：hextet 的 overlay 地址由密钥派生，
  重开即恢复，不需要重新入网。

这个「按需连接」定位正是 spec §2 对手机的定义（主动发起方 + 按需连接，不承诺被动可达）。

### 4.3 两个都要同时用：拆到两台设备

如果你确实需要**同时**「手机挂代理上外网」和「连回家里 mesh」，单台 Android 无解，
用两台设备分治：

- 一台手机/平板跑 hextet（连 mesh），另一台跑代理（上外网）；
- 或者反过来：家里的路由器跑 hextet（见 4.1），手机继续挂代理。这通常是最省事的做法。

## 5. 诚实的边界

- **VpnService 尚未实现**：Android 客户端是 M7 切片 D，本文档是**前瞻说明**，规划行为以
  spec §2（目标 8/9）、§5（DNS/路由姿态）为准。客户端落地后本文档会随实现修订。
- **单槽位是 Android 硬限制，无解**：hextet 不能、也不会去 hack 系统的单一 VPN 约束。
  我们做的只是让「路由/DNS 不打架」，把冲突收敛为「谁占槽位」。
- **手机不承诺被动可达**：无服务器 = 无推送唤醒通道，手机定位是主动发起方 + 按需连接
  （spec §2「诚实的边界」）。别人主动 ping 你的手机，不保证随时可达。
- **IPv6-only**：hextet 的一切（endpoint、子网路由）都是 IPv6。手机蜂窝若拿不到可用的
  公网 IPv6（如部分 CMCC 蜂窝），直连不可行，这正是 [relay](relay.md)（自有节点中继）
  存在的理由。

## 参考

- 设计 spec：`docs/superpowers/specs/2026-08-06-hextet-design.md` §2（目标 8/9、诚实的
  边界）、§5（DNS/路由姿态）、§8（M7 行）
- M7 实现计划（切片 F）：`docs/superpowers/plans/2026-08-13-m7-android.md`
- 路由器组网（家庭场景零客户端）：`docs/guides/openwrt.md`、`docs/guides/site-to-site.md`
- 自有节点中继：`docs/guides/relay.md`
- 按名访问（MagicDNS-lite）：`docs/guides/hosts.md`
