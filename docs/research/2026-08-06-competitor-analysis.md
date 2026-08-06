# 异地组网（Mesh VPN / Overlay Network）竞品调研报告

> 调研时间：2026-08。视角：为 hextet 项目做竞品分析。新项目定位：**IPv6-only、无中转（no relay）、尽量无协调服务器、P2P mesh VPN、支持路由器 site-to-site 组网**。
> 本文档是 hextet 项目三份立项调研之一，另见 [Rust 技术选型](2026-08-06-rust-stack-selection.md) 与 [IPv6 P2P 可行性](2026-08-06-ipv6-p2p-feasibility.md)。

---

## 一、逐产品档案

### 1. Tailscale（含 Headscale）

- **架构**：中心化控制平面 + P2P 数据平面。控制平面是闭源的 coordination server（login.tailscale.com），负责身份、密钥分发、ACL、endpoint 汇聚（[控制/数据平面文档](https://tailscale.com/docs/concepts/control-data-planes)）。数据平面为 WireGuard（wireguard-go 用户态）。直连失败时回落到 **DERP** 中继（Tailscale 全球托管，HTTPS/443 上跑加密转发）。**2025-10 新增 Peer Relays（beta→GA）**：用户可把 tailnet 内任意节点声明为中继，单 UDP 端口、客户自管、吞吐接近直连，优先于 DERP 使用（[Peer Relays blog](https://tailscale.com/blog/peer-relays-beta)、[docs](https://tailscale.com/docs/features/peer-relay)）——这是 Tailscale 对"DERP 慢"抱怨的正面回应。
- **语言**：Go（客户端开源；GUI 与协调服务器闭源）。
- **发现/会合**：全部经协调服务器：节点上报所有候选 endpoint（本地、STUN 发现的公网、port-mapping 结果），由控制面分发；`disco` 协议做路径探测与升级。对端地址变化后通过 DERP 上的 disco 消息重新协商。
- **NAT 穿透**：业界最强之一——STUN、UPnP/NAT-PMP/PCP、双向同时发包、针对 hard NAT 的生日悖论端口猜测；穿不透就走 DERP（参考经典文章 [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)）。
- **子网路由/site-to-site/exit node**：subnet router、exit node、app connector 全套支持，路由在 admin console 审批。
- **平台**：全平台 + Apple TV/Synology/QNAP；**OpenWrt 官方 packages feed 有 `net/tailscale`**（已验证），但 Go 二进制在 8/64 小路由器上体积与内存吃紧是社区常见抱怨。
- **UI**：CLI + 各平台 GUI + Web admin console；配置体验是标杆（SSO 登录即入网）。
- **安全模型**：身份 = SSO（任意 IdP）+ 节点密钥；ACL 用 HuJSON grants；**Tailnet Lock** 可去除对控制面密钥分发的信任（节点互签）。Overlay 地址：100.64.0.0/10 + IPv6 ULA `fd7a:115c:a1e0::/48`（原生双栈 overlay；underlay IPv6 直连优先，因为 IPv6 下基本不需要穿透）。
- **许可证/社区**：客户端 BSD-3；2025-04 完成 **$160M Series C，估值 $1.5B**，>10,000 家组织（[Series C blog](https://tailscale.com/blog/series-c)、[SiliconANGLE](https://siliconangle.com/2025/04/08/networking-startup-tailscale-raises-160m-1-5b-valuation/)）。
- **Headscale**：社区开源协调服务器（Go，BSD-3，42.5k stars，v0.29.3 2026-07），内嵌 DERP，可覆盖大部分核心功能，但新特性滞后——**Peer Relays 尚未支持**（[headscale issue #2841](https://github.com/juanfont/headscale/issues/2841)）。
- **痛点**：协调服务器闭源、设备元数据托管在别人家、按用户收费、DERP 吞吐低（Peer Relays 才刚缓解）、免费档 3 用户（[HN 讨论](https://news.ycombinator.com/item?id=29613625)、[开源替代品盘点](https://pinggy.io/blog/top_open_source_tailscale_alternatives/)）。

### 2. ZeroTier

- **架构**：分层：**VL1**（全球 P2P 加密寻址层，40-bit 节点 ID，自研协议，非 WireGuard）+ **VL2**（以太网仿真，L2 overlay，支持组播/桥接）。会合与兜底中继由 **root servers（"planet"，ZeroTier 官方运营，硬编码 planet 文件；用户可加 "moons"）** 承担；网络成员/规则由 **controller** 签发。1.16.0（2025-08）起 **core 改为 MPL-2.0、controller 改为商业 source-available 且不再打进默认二进制**（需 `ZT_NONFREE=1` 自行编译），社区反弹明显（[RELEASE-NOTES](https://raw.githubusercontent.com/zerotier/ZeroTierOne/master/RELEASE-NOTES.md)、[GPL→BSL 说明](https://www.zerotier.com/news/on-the-gpl-to-bsl-transition/)、[自托管 controller 讨论](https://discuss.zerotier.com/t/zerotier-1-16-0-self-hosted-controller/28269)、[license 矛盾 issue](https://github.com/zerotier/ZeroTierOne/issues/2206)）。最新 1.16.2（2026-05）。
- **语言**：C++（部分新组件 Rust 化尝试）。
- **发现/会合**：roots 做 rendezvous（转发首包 + 地址介绍），成员配置从 controller 拉取。
- **NAT 穿透**：UDP 打洞 + roots 协助；失败走 roots 中继（免费但慢）；1.16 新增 **network-specific relays（beta）**。对称 NAT 场景成功率一般，是老生常谈的抱怨。
- **子网路由/exit node**：支持 managed routes、全局路由（exit）、L2 桥接（这是它独有强项）。
- **平台**：全平台，**OpenWrt 官方 feed 有 `net/zerotier`**（已验证）。
- **UI**：Central（my.zerotier.com）Web 控制台，2025-11 全新改版并引入 ReBAC（[新 Central 发布稿](https://markets.financialcontent.com/stocks/article/bizwire-2025-11-5-zerotier-launches-new-central-release-unveils-redesigned-uiux-to-empower-users-with-faster-more-intuitive-network-control)）；CLI 完整。
- **安全模型**：C25519 身份、Salsa20/12-Poly1305 与 AES-GMAC-SIV；网络准入靠 controller 签发的 Certificate of Membership；规则引擎（tags/capabilities 的声明式过滤语言）非常强大但学习曲线陡。Overlay 双栈：IPv6 有 **RFC4193 与 6PLANE** 自动编址（6PLANE 把 node ID 嵌进 IPv6 地址并仿真 NDP，值得借鉴）。
- **痛点**：许可证反复横跳（GPL→BSL→MPL+商业 controller）、自托管路径被收窄、planet 依赖官方基础设施（root 挂了新连接建不起来）、ZeroTier 2.0 长期跳票。

### 3. Nebula（Slack / Defined Networking）

- **架构**：**无运行时控制平面**：静态 YAML 配置 + 自建 PKI（CA 签发含 IP/组信息的证书）。**Lighthouse** 节点（需公网 IP）承担节点发现与打洞协助；直连失败可走用户自配的 **relay 节点**。数据平面为基于 Noise 的自研协议（UDP），非 WireGuard。
- **语言**：Go。MIT，17.6k stars，v1.11.0（2026-07）。
- **重大更新**：**1.10（2025-12）终于支持 overlay IPv6** —— 新的 ASN.1 v2 证书格式，支持一主机多地址（v4+v6），官方称 2025 为 "Year of the IPv6 overlay network"（[官方博客](https://www.defined.net/blog/year-of-the-ipv6-overlay-network/)、[升级指南](https://nebula.defined.net/docs/guides/upgrade-to-cert-v2-and-ipv6/)、[PR #1216](https://github.com/slackhq/nebula/pull/1216)）。
- **发现/会合**：节点向 lighthouse 注册当前 endpoint，查询对端时由 lighthouse 返回候选地址并双向打洞。地址变化靠向 lighthouse 重新上报。
- **NAT 穿透**：UDP 打洞（lighthouse 协助），无 STUN/生日攻击级别的高级手段；对称 NAT 靠 relay 兜底。
- **子网路由**：`unsafe_routes` 支持子网路由（名字就暗示了官方态度——不如原生节点安全）；无内置 exit node 概念（可用 unsafe_routes 0.0.0.0/0 模拟）。
- **平台**：Linux/macOS/Win/iOS/Android/FreeBSD；**OpenWrt 官方 feed 有 `net/nebula`**（已验证）。
- **UI**：纯 CLI + 手工分发证书/配置；Defined Networking 提供托管控制台（免费 100 台）。
- **安全模型**：自持 CA 是最大卖点（信任根完全在自己手里）；防火墙规则基于证书里的 group，写在每台节点配置里。
- **痛点**（[2025-09 长文吐槽](https://blog.ewonchang.com/2025/09/27/nebula-mesh-vpn-still-disappointing-after-4-years/)）：小规模部署运维负担大（证书+每节点防火墙规则手工管理）、DNS 原始（lighthouse DNS 只解析节点名，不能接管系统 DNS）、iOS 客户端功能残缺（不能导入配置、不支持 relay、无 always-on）、对 homelab 用户不友好——"为大规模企业设计"。

### 4. NetBird

- **架构**：开源版 Tailscale 路线：**Management server（gRPC，开源可自托管）+ Signal server + Relay**。数据平面 WireGuard（**优先用内核 WireGuard**，比 Tailscale 用户态更快是其卖点）；NAT 穿透用 ICE（pion 库，WebRTC 语义）；v0.29 起用自研 **WebSocket relay 取代 coturn/TURN**（[How NetBird Works](https://docs.netbird.io/about-netbird/how-netbird-works)、[GitHub](https://github.com/netbirdio/netbird)）。
- **语言**：Go。BSD-3（客户端与管理面开源），28k stars，迭代极快（v0.76.1，2026-07）。
- **发现/会合**：Signal 服务转发 ICE offer/answer；地址变化重新走 ICE。
- **NAT 穿透**：ICE 全家桶（STUN/自研 relay 兜底）+ Rosenpass 后量子选项（[Rosenpass 集成](https://netbird.io/knowledge-hub/how-we-integrated-rosenpass)）。
- **子网路由/site-to-site**：Networks/Routes 模型，routing peer 可高可用成组，masquerade 默认开启；exit node 支持。**官方 site-to-site 文档明确支持两端路由器组网**（[Site-to-Site docs](https://docs.netbird.io/use-cases/remote-access/site-to-site)）。
- **IPv6**：**v0.71（2026）正式发布双栈 overlay**：每账户一个 ULA /64 前缀、AAAA/PTR、ACL 双栈自动生效、::/0 exit 路由（[IPv6 Overlay Addressing](https://docs.netbird.io/manage/settings/ipv6)、[发布说明](https://netbird.io/knowledge-hub/ipv6-overlay-addressing)）。此前 IPv4-only 是多年痛点（[issue #1167](https://github.com/netbirdio/netbird/issues/1167)）。
- **平台**：全平台；**OpenWrt 官方安装文档 + 官方 feed 包**，配置可跨 sysupgrade 保留（[OpenWrt 安装文档](https://docs.netbird.io/get-started/install/openwrt)）。
- **UI**：Web dashboard（自托管或云）+ CLI；SSO/MFA（任意 OIDC）、posture check、活动审计。
- **痛点**：自托管全家桶（management/signal/relay/dashboard/IdP）部署复杂；open issues 1500+，质量波动；德国公司，融资规模远小于 Tailscale。
- **对本项目启示**：它证明了"开源 + 可自托管 + 内核 WireGuard"有真实市场，但也展示了控制面全家桶的复杂度代价。

### 5. innernet（tonari）

- **架构**：极简 Tailscale 思路的 Rust 实现：**coordination server（Rust + SQLite）** 管理 peer 与 CIDR 树，客户端**通过 WireGuard 隧道本身**周期性拉取 peer 增量（server 在网内，控制面流量也走加密隧道——设计很优雅）。数据平面 = 内核 WireGuard。
- **语言**：**Rust**。关键库：自家的 **`wireguard-control`**（netlink 控制 WG，可复用！）、`innernet-client-core`（v2.0.0 新拆出的库化 API）。
- **发现/会合**：server 记录它看到的 peer 公网 endpoint 并分发候选（`override-peer-endpoint` 可手动指定）；NAT 打洞是"尽力而为"，**无 relay 兜底**——对称 NAT 下就是不通。
- **ACL 模型独特**：用 **CIDR 层级本身做 ACL 原语**——同 CIDR 默认互通，跨 CIDR 需显式 association；"infra" CIDR 全网可达（[README](https://github.com/tonarino/innernet)、[介绍博文](https://blog.tonari.no/introducing-innernet)）。
- **加入流程**：一次性 invite 文件，`innernet install` 后自动换密钥注册——邀请体验好。
- **平台**：Linux/macOS（OpenBSD 实验性）；**无 Windows、无移动端、无 OpenWrt 故事**。IPv6 CIDR 支持已落地（[issue #15 已关闭](https://github.com/tonarino/innernet/issues/15)）。
- **许可证/活跃度**：MIT，5.5k stars；v2.0.0（2026-07）主要是 Rust 库重构，**server/client 自 1.7.1 以来仅小修**——tonari 自用优先，功能演进慢，且明言"未经独立安全审计，视为实验性软件"。
- **痛点**：无中继兜底导致 NAT 环境可靠性差、平台覆盖窄、社区小。

### 6. EasyTier（中国开源，Rust）

- **架构**：**去中心化、全对等**：无强制服务器组件，任何节点都可以做入口/中继；官方与社区提供**公共共享节点**做会合与中继（如 `tcp://easytier.public.kkrainbow.top:11010`）。控制/数据分离：核心 daemon（easytier-core）+ CLI/Tauri GUI/Web Console（Axum REST）经 protobuf RPC 通信（[GitHub](https://github.com/EasyTier/EasyTier)、[DeepWiki 架构页](https://deepwiki.com/EasyTier/EasyTier/1.2-system-architecture)）。
- **语言/关键库**：**Rust + Tokio**；`ring`（AES-GCM）、`smoltcp`（用户态 TCP/IP 栈，用于 subnet proxy/KCP）、`zerocopy`（零拷贝管道）、protobuf RPC、Tauri（GUI）、Axum + Sea-ORM（Web console）。
- **发现/会合**：手动 peer 列表或连到公共共享节点即可入网；同一 network name+secret 的节点经由已连节点互相学习（peer 信息经 RPC 同步）。
- **NAT 穿透**（[DeepWiki NAT 章节](https://deepwiki.com/EasyTier/EasyTier/3.8-nat-traversal-and-hole-punching)，业界最激进之一）：STUN 分类（UDP+TCP+IPv6 各自独立探测）→ UPnP/NAT-PMP 显式映射 → cone-cone 直接交换端口、**symmetric-cone 定向打**、**symmetric-symmetric 用生日攻击端口碰撞**；TCP 同时打开也支持；全部失败走 peer 中继（OSPF 路由自动选路）。
- **路由**：**OSPF-like 链路状态 + Dijkstra**，按延迟优先智能选路；节点可为其他网络转发（`--relay-network-whitelist` 控制），`--private-mode` 关闭代人转发。
- **功能**：subnet proxy（site-to-site）、exit node/全局代理、Magic DNS、端口转发、SOCKS5、KCP/QUIC proxy（对抗运营商 UDP QoS——中国特色刚需）、**VPN portal（内置 WireGuard 服务端**，让 iOS/Android 用原生 WG 客户端接入）。
- **平台**：Win/macOS/Linux/FreeBSD/Android，x86/ARM/**MIPS**；**OpenWrt 支持（官方提供包 + 社区 luci-app-easytier，不在 openwrt 官方 feed）**。
- **安全模型（弱点）**：身份 = **network name + shared secret（对称信任）**，无每节点 PKI、无 ACL——拿到 secret 就是全权成员；加密 AES-GCM 或 WireGuard。
- **许可证/活跃度**：LGPL-3.0，**13k stars**，非常活跃（v2.6.4，2026-05），中文社区庞大、文档以中文为主。
- **痛点**：安全模型粗糙（无 ACL/PKI）、公共共享节点被滥用为免费中继的争议、休眠/网络切换后卡 relay 不恢复的 bug（[issue #1697](https://github.com/EasyTier/EasyTier/issues/1697)）、英文文档/国际社区弱。

### 7. Yggdrasil Network

- **架构**：**完全去中心化的全球 IPv6 overlay**，无任何控制面/中继角色之分——**每个节点都是路由器**，多跳转发是常态而非兜底。v0.5（2023-10）重写路由：全网生成**生成树（spanning tree）**，树坐标 + **贪婪路由**；目的地查找从 DHT 改为**沿树链路的 Bloom filter 查找**（类似 ARP/NDP），链路状态用 **CRDT** gossip 合并，每 peer 仅常数状态（[v0.5 设计博文](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)、[about](https://yggdrasil-network.github.io/about.html)）。当前 v0.5.14（2026-06）。
- **语言**：Go。LGPL-3.0，5.3k stars。
- **寻址**：ed25519 公钥派生 `200::/7` 内稳定 IPv6 地址 + 每节点一个可路由 /64 子网前缀——**密钥即地址，无 IPAM**。
- **发现/会合**：**链路本地组播自动发现**（局域网插网线即组网）+ 公共 peer 列表（GitHub 维护）；无打洞——只靠主动出站连接（tcp/tls/quic/ws/wss），彼此都在 NAT 后就通过公共 mesh 多跳。社区工具 **`yggdrasil-jumper`**（OpenWrt feed 里也有）在 ygg 连接之上协商直连打洞，弥补这一短板。
- **安全模型**：会话端到端加密；**无准入控制**——接入公共 mesh 意味着全网任何人可路由到你（主机防火墙自理）；私有 mesh 可用 peer 密码 + `AllowedPublicKeys`。无 ACL、无 exit node 概念（可自行配 route）。
- **平台**：极广，**OpenWrt 官方 feed 有 `net/yggdrasil`**（已验证）。
- **性能/痛点**：官方自认 **alpha research project**；GbE 下实测 ~928 Mbps 但不稳定（[FAQ](https://yggdrasil-network.github.io/faq.html)）；TCP peering 的队头阻塞、多链路选择差（宁走弱信号 wifi 不走 GbE）；公网乱加 peer 会拖累树上邻居性能（[Practical peering](https://yggdrasil-network.github.io/2019/03/25/peering.html)、[HN 讨论](https://news.ycombinator.com/item?id=42155780)）；不匿名、无 exit node。

### 8. Mycelium（ThreeFold，Rust）

- **架构**：端到端加密的 **IPv6-only overlay（`400::/7`）**，ThreeFold Grid v4 的网络层。**每节点都转发**（与 Yggdrasil 同哲学），无专职中继；公共节点 ~10 个（v4+v6 双栈）作为默认接入点（[README](https://github.com/threefoldtech/mycelium)、[官网](https://mycelium.threefold.io/)）。
- **语言/关键库**：**Rust**：tokio、**quinn + rustls（QUIC）**、openssl、跨平台 TUN 抽象、mobile FFI（[DeepWiki](https://deepwiki.com/threefoldtech/mycelium)）。
- **路由**：**Babel 派生的距离向量协议**：RoutingTable（无锁查表）+ SourceTable（feasibility 校验防环）+ 未知目的地触发 RouteRequest 的按需发现 + 路由发现期间包缓存队列；locality-aware，链路断自动重路由。
- **寻址/安全**：x25519 公钥 → `400::/7` 内 /64 子网 → IPv6 地址（**地址自证明**）；流量端到端 AES-GCM（x25519 ECDH 派生密钥），中间跳只见 36 字节明文头（保留位/长度/**hop limit**/源目 IPv6），格式见 [data_packet.md](https://github.com/threefoldtech/mycelium/blob/master/docs/data_packet.md)。
- **发现/会合**：静态 peer + 公共节点，**无 NAT 打洞**——纯出站 TCP/QUIC，穿防火墙靠"能出去就能被路由到"（多跳）。私有网络模式：网络名 + PSK。
- **附加能力**：**topic-based 可靠消息总线**（带截止时间、分块传输、Unix socket 转发）、SOCKS5、HTTP API——它不只是 VPN，是"网络 + 消息"底座。
- **平台**：Linux/macOS/Windows 二进制 + iOS/Android/macOS/Windows App（[下载页](https://www.mycelium.threefold.io/download/)）；**无 OpenWrt 官方故事**。
- **许可证/活跃度**：Apache-2.0；主仓库仅 ~200 stars 但持续迭代（v0.7.10，2026-06），本质是 ThreeFold 生态内部件；每网络 ~10 万节点的扩展性上限，官方称在解决中（[Forum](https://forum.threefold.io/t/introducing-mycelium/4082)）。
- **痛点**：社区极小、生态绑定 ThreeFold、无打洞导致两端都在受限网络时必走多跳（延迟）、文档中加密细节欠奉。

### 9. vpncloud（dswd）

- **架构**：Rust 写的 P2P full-mesh L2/L3 VPN（UDP），无中心服务器；**beacon 系统**做发现（把 endpoint 加密后发布到 DNS TXT/文件/自定义命令——很妙的无服务器 rendezvous 思路）（[README](https://github.com/dswd/vpncloud)、[官网](https://vpncloud.ddswd.de/)、[HN](https://news.ycombinator.com/item?id=26678723)）。
- **要点**：Curve25519 + AES-256；基础打洞 + UPnP；TUN/TAP + VLAN；YAML 配置 + 共享密钥；仅 Linux 稳定；GPL-3.0，2k stars。
- **状态**：**事实停滞——最后一次提交 2024-03**（经 GitHub API 验证）。单人维护项目的风险样本。

### 10. WireGuard 原生（baseline）

- **架构**：只有数据平面。Noise IK 握手、静态公钥即身份、`AllowedIPs` 同时充当路由表与准入控制（cryptokey routing）。**无发现、无会合、无 NAT 穿透**（仅 persistent-keepalive 维持映射 + 对端源地址漫游 roaming）、密钥分发纯手工。
- **IPv6**：underlay/overlay 原生双栈；IPv6-only 配置完全没问题——**两端有公网 IPv6 + 防火墙放行时，WireGuard 本身就是"无中转直连"的终极答案**，缺的只是配置分发与动态 endpoint 发现（官方的 wg-dynamic 项目多年停滞）。
- **路由器**：OpenWrt 一等公民（内核 WG + luci-proto-wireguard），site-to-site 是最成熟方案。
- **Rust 生态**（对新项目直接相关）：`boringtun`（Cloudflare，基本停更；[Firezone fork](https://github.com/firezone/boringtun) 在维护）、**`NepTUN`（NordSecurity 的 boringtun 后继 fork，BSD-3，2026-08 仍活跃提交**，已验证）、tonari 的 `wireguard-control`（netlink 管理内核 WG）、`defguard_wireguard_rs`。**在 Linux/OpenWrt 上直接驱动内核 WireGuard、桌面端用 NepTUN/boringtun 类用户态实现**是 Rust 项目的现实路线。

---

## 二、A. 功能矩阵

| | 控制平面 | 数据平面 | 中继依赖 | 语言 | NAT 穿透 | 子网路由/S2S | Exit node | Overlay IPv6 | OpenWrt | UI | ACL/身份 | 许可证 | 活跃度(2026-08) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Tailscale** | 中心化（闭源 SaaS） | WireGuard(用户态) | DERP + Peer Relays(2025) | Go | ★★★（STUN/PMP/生日攻击） | ✅ 需审批 | ✅ | ✅ 双栈 ULA | ✅ 官方 feed（偏重） | GUI+Web+CLI | SSO+HuJSON grants+Tailnet Lock | 客户端 BSD-3 | 极高（$1.5B） |
| **Headscale** | 自托管开源版控制面 | 同上 | 内嵌 DERP | Go | 同上 | ✅ | ✅ | ✅ | ✅ | CLI+第三方 Web | 同上（滞后） | BSD-3 | 高（42k★） |
| **ZeroTier** | Controller + 官方 roots | 自研 L2(VL1/VL2) | roots 兜底中继 | C++ | ★★（对称 NAT 弱） | ✅ + L2 桥接 | ✅ | ✅ 6PLANE/RFC4193 | ✅ 官方 feed | Web(Central)+CLI | Controller 签证书+规则引擎 | MPL-2.0(核心)+商业 controller | 高但争议 |
| **Nebula** | 无（PKI+静态配置） | Noise 自研(UDP) | 可选自建 relay | Go | ★★（lighthouse 协助） | ✅ unsafe_routes | ⚠️ 模拟 | ✅ 1.10 起(2025-12) | ✅ 官方 feed | CLI/手工 | 自建 CA+证书内组 | MIT | 中高（17.6k★） |
| **NetBird** | Mgmt+Signal（开源自托管） | WireGuard(优先内核) | 自研 WS relay | Go | ★★★（ICE/pion） | ✅ 含 HA 路由组 | ✅ | ✅ v0.71 起(2026) | ✅ 官方文档+feed | Web+CLI | SSO/OIDC+组策略+posture | BSD-3 | 极高（28k★） |
| **innernet** | 极简自托管 server | WireGuard(内核) | ❌ 无兜底 | **Rust** | ★（endpoint 交换） | ✅（CIDR） | ❌ | ✅（v6 CIDR 可用） | ❌ | CLI | CIDR 层级+邀请文件 | MIT | 低速维护 |
| **EasyTier** | **去中心化**（可选公共节点/Web console） | 自研多传输+AES-GCM 或 WG | 任意 peer 皆可中继 | **Rust** | ★★★（双端对称 NAT 生日攻击） | ✅ subnet proxy | ✅ 全局代理 | ⚠️ overlay 以 v4 为主；underlay v6 ✅ | ✅（自供包，非官方 feed） | GUI+Web+CLI | 网络名+共享密钥（**无 PKI/ACL**） | LGPL-3.0 | 极高（13k★） |
| **Yggdrasil** | **无**（全分布式） | 自研树路由+e2e 加密(TCP/TLS/QUIC/WS) | 每节点皆转发（多跳=隐式中继） | Go | ❌（jumper 补充） | ⚠️ 每节点 /64 | ❌ | **✅ v6-only 200::/7 密钥派生** | ✅ 官方 feed(+jumper) | CLI | 无准入（可选 peer 密码） | LGPL-3.0 | 稳定小众（alpha） |
| **Mycelium** | **无**（公共节点仅接入点） | 自研 Babel 派生+AES-GCM(TCP/QUIC) | 每节点皆转发 | **Rust** | ❌（纯出站） | ⚠️ 每节点 /64 | ❌ | **✅ v6-only 400::/7 密钥派生** | ❌ | CLI+App+HTTP API | 密钥即地址；私网 PSK | Apache-2.0 | 小而活（ThreeFold） |
| **vpncloud** | 无（beacon 发现） | 自研 UDP | ❌ | **Rust** | ★（基础+UPnP） | ✅ L2/L3 | ❌ | ⚠️ | ❌ | CLI | 共享密钥 | GPL-3.0 | **停滞(2024-03)** |
| **WireGuard** | 无 | WireGuard(内核) | ❌ | C | ❌（仅 keepalive+漫游） | ✅ AllowedIPs | ✅ 手工 | ✅ 原生双栈 | ✅ 一等公民 | CLI/LuCI | 公钥+AllowedIPs | GPL-2.0 | 基础设施级 |

---

## 三、B. 每个产品对本项目最有价值的设计洞察

**Tailscale**
1. **体验即产品**：登录即入网、MagicDNS、状态可观测（`tailscale status` 显示 direct/relay 路径）——竞争的本质是运维体验而非协议。
2. **Peer Relays 的教训**：即使有全球 DERP 舰队，用户还是要"自己的节点做中继以接近直连吞吐"——印证"托管中继永远是性能天花板"，"无中转"定位打的正是这个点。
3. **Tailnet Lock**：中心化控制面 + 节点互签消除密钥分发信任——如果保留任何轻量协调件，值得抄这个信任剥离设计。

**ZeroTier**
1. **6PLANE 编址**：把节点 ID 确定性嵌入 IPv6 地址并仿真 NDP——密钥/ID→IPv6 地址派生的工程先例。
2. **许可证反面教材**：GPL→BSL→MPL+商业 controller 的反复摧毁了社区信任；新项目应从第一天锁定宽松许可证（MIT/Apache-2.0）。
3. **roots 硬编码之弊**：官方 planet 成为单点与主权争议来源——rendezvous 端点必须可由用户完全替换。

**Nebula**
1. **自建 CA + 证书内嵌 IP/组**：控制面可以是"离线签发"而非"在线服务"——最接近"无协调服务器"的身份分发模型，非常适合借鉴。
2. **cert v2 教训**：v1 证书只留了一个 IPv4 字段，导致 IPv6 支持拖了 6 年、被迫换 ASN.1 全格式——**第一天就把地址族与多地址设计进身份格式**。
3. 运维反馈：纯静态配置在 10 台规模就令人痛苦——"无控制面"不等于"无自动化"，需要好的配置生成/分发工具链。

**NetBird**
1. **优先内核 WireGuard**（Go 用户态仅兜底）是明确的性能正确路线，路由器上尤其如此。
2. Networks/routing-peer 的 **HA 路由组**（同一子网多个 routing peer 自动故障切换）是 site-to-site 的必备进阶形态。
3. IPv6 落地方式值得抄：**双栈 ACL 自动等效、AAAA+PTR、::/0 与 0.0.0.0/0 exit 配对**——用户不应为地址族做两遍配置。

**innernet**
1. **控制面流量走隧道内**（server 是网内节点）——协调件不需要公网暴露面，安全模型漂亮。
2. **CIDR 层级即 ACL**：用寻址结构本身表达权限，省掉独立 ACL 引擎——与 IPv6 前缀天然契合（每站点一个 /64，前缀即策略）。
3. `wireguard-control` / `innernet-client-core` 是现成的 Rust WG 管理库；同时其"无中继兜底"的可靠性口碑教训提醒：直连失败时必须有明确的降级叙事（哪怕只是清晰报错）。

**EasyTier**
1. Rust 全栈工程范本：tokio + `ring` + `smoltcp` + `zerocopy` + protobuf RPC + Tauri/Axum——新项目技术选型可直接参考其依赖树。
2. **多传输抽象（Tunnel trait）**：TCP/UDP/WS/WSS/QUIC/WG 可插拔 + KCP/QUIC proxy 对抗 UDP QoS——中国网络环境的实战经验，IPv6-only 也可能遇到 ICMPv6/UDP 被限速的现实。
3. 反面镜鉴：network name+secret 的对称信任无法做 ACL/吊销——证明"简单入网"与"每节点密码学身份"必须兼得（Nebula/Ygg 的方式）而非二选一。

**Yggdrasil**
1. **密钥派生地址 + 每节点 /64 子网**：无 IPAM、无地址冲突、地址自认证——IPv6-only 项目的寻址正解。
2. v0.5 演进（DHT→生成树+Bloom filter+CRDT）显示全局路由收敛的复杂性极高——**如果只做直连不做多跳转发，可以砍掉整个这层复杂度**，这是新项目最大的减法机会。
3. 链路本地组播发现（"插网线即组网"）成本极低、体验极好，必抄。

**Mycelium**
1. 证明了 "Rust + IPv6-only overlay + 密钥派生地址" 技术栈完全可行；quinn(QUIC)+rustls+tokio 的传输组合可直接参考。
2. Babel 的 **feasibility 条件**（SourceTable 防环）是比链路状态更轻的路由正确性方案——若未来要做受限多跳，Babel 系比 OSPF 系更适合 mesh。
3. **网络之上叠加消息总线/API**（topic 消息、HTTP API）把"组网工具"升维成"分布式应用底座"——差异化方向的想象力样本。

**vpncloud**
1. **beacon 系统**：把加密的 endpoint 信息发布到 DNS TXT/文件——"无协调服务器的 rendezvous"最便宜的实现，与"尽可能少服务器"定位高度契合（IPv6 直连场景只需交换 `[addr]:port`+公钥）。
2. 单维护者停滞的风险：社区治理与 bus factor 从第一天规划。

**WireGuard 原生**
1. **cryptokey routing（AllowedIPs）**已经是"路由+ACL"二合一——新项目控制面的本质工作只是"自动化生成与更新 WireGuard 配置"，不要重造数据面。
2. **endpoint 漫游**：内置"对端换地址自动跟随"（以最新合法握手源地址为准）——IPv6 前缀轮换场景（家宽 PD 变化）的基础，但需要上层重新发现机制补全双端同时变址的情况。
3. 内核态性能与 OpenWrt 一等公民地位：路由器上直接驱动内核 WG 是唯一正确答案。

---

## 四、C. "IPv6-only 无中转"定位下的功能分层

### Table stakes（必须做）
1. **密钥即身份、身份派生 overlay 地址**（Yggdrasil/Mycelium 模式：pubkey → ULA 内地址/每站点 /64）——消灭 IPAM 与地址冲突。
2. **数据面直接用 WireGuard**（Linux/OpenWrt 内核态；桌面用用户态实现）——不要自研加密传输；所有成功者要么用 WG 要么花了数年成熟自研密码学。
3. **端点发现与重会合（rendezvous）**：对端 IPv6 地址/端口变化后的重新发现。哪怕"无服务器"，也至少要一种机制：mDNS/链路本地组播（LAN 内）、DNS 记录（vpncloud beacon 式）、或经由任一已连 peer 的 gossip 转告。**这是无协调服务器设计的核心难题，不可回避**。
4. **site-to-site 子网路由 + 路由传播**：路由器宣告 LAN 前缀、其余节点自动装路由；含冲突检测。IPv6 下应支持宣告 delegated prefix。
5. **OpenWrt 一等公民**：官方 feed 包 + LuCI 界面 + 低内存占用（Rust 无 GC，对 128MB 级设备是对 Go 系的真实优势）+ sysupgrade 幸存。
6. **邀请/入网流程**（innernet 式一次性 invite 或 Nebula 式离线签发）+ 节点吊销。
7. **防火墙打洞（非 NAT 打洞）**：IPv6-only ≠ 无穿透。家用路由器默认丢弃入站 IPv6，双向同时发包（simultaneous transmit）打状态防火墙洞仍然必需——好消息是无端口改写，成功率远高于 NAT 打洞，且**不需要 STUN**（自己的全球地址自己知道）。
8. **可观测性**：`status` 显示每对 peer 直连/失败原因、握手时间、路径 RTT。
9. 节点命名/DNS（哪怕只是 hosts 文件生成级别的 MagicDNS-lite）。

### 差异化亮点（值得做）
1. **零协调服务器叙事本身**：市场上"开源 Tailscale"已挤满（NetBird/Headscale/Netmaker），但"**无任何在线控制面 + 现代体验**"只有 Nebula 沾边且体验差——"Nebula 的信任模型 + Tailscale 的体验 + Rust 的资源占用"是空位。
2. **IPv6-first 的简洁性作为卖点**：无 CGNAT 地址池、无 STUN/TURN/DERP 舰队、无生日攻击——把省下的复杂度兑换成可审计性（"整个协议一页纸讲完"）。
3. **前缀即策略**：借 innernet 思路，用 IPv6 前缀层级表达站点/权限，ACL 编译为两端 WG AllowedIPs + nftables 规则。
4. **路由器场景纵深**：PD 前缀变化自动重宣告、多 WAN、与 OpenWrt firewall4 原生集成——Tailscale/NetBird 在路由器上都只是"能跑"。
5. **P2P gossip 作为控制面**（EasyTier/Ygg 模式）：peer 列表、endpoint 更新、路由宣告经已建立的 WG 隧道内 gossip 同步，只在冷启动时需要一个种子地址。
6. （可选后期）Mycelium 式 **网络内消息/API 底座**，服务于自动化与应用集成。

### 明确不做（IPv6-only 定位的减法红利）
1. **DERP/TURN/中继舰队及中继协议**——定位即承诺：打不通就明确报告，不静默降级到转发（最多允许用户显式指定自己的中继 peer，作为逃生舱且默认关闭）。
2. **IPv4 NAT 穿透全家桶**：STUN 分类、UPnP/NAT-PMP、对称 NAT 端口预测/生日攻击——EasyTier 为此付出的复杂度全部省掉。
3. **CGNAT IPv4 overlay 地址管理**（100.64/10 池、地址回收）——地址由密钥派生。
4. **L2 以太网仿真/组播/桥接**（ZeroTier 的包袱）：L3-only。
5. **多跳全局路由算法**（Yggdrasil 的树+Bloom filter、Mycelium 的 Babel）：不做任意拓扑转发就不需要收敛协议；site-to-site 只需一跳路由宣告。
6. **企业 SSO/IdP/posture check**（初期）：身份=密钥，把 OIDC 留给未来的托管产品线。
7. **自研加密协议**：Noise/WireGuard 之外不发明任何密码学。

**必须诚实面对的风险**：IPv6-only 排除了大量真实网络（无 v6 的宽带、只给 v4 的公司网、v6 被防火墙锁死的场景），且 NAT64/DNS64、运营商级 IPv6 防火墙不可控。建议定位表述为"IPv6 直连优先、v4 underlay 仅作显式可选出站传输"，或至少在文档里给出清晰的网络前提检查工具（`doctor` 命令：检测 v6 可达性/防火墙行为）。

---

## 五、D. EasyTier / Yggdrasil / Mycelium 深度对比

这三者与新项目同属"去中心化、（近）无专职服务器"阵营，但路线差异极大：

### 5.1 Wire protocol

| | EasyTier | Yggdrasil (v0.5) | Mycelium |
|---|---|---|---|
| 传输 | TCP/UDP/WS/WSS/QUIC/WireGuard 可插拔（Tunnel trait），KCP/QUIC proxy 抗 QoS | tcp:// tls:// quic:// ws:// wss:// unix://（QUIC 官方自认通常比 TCP/TLS 差） | TCP、QUIC（quinn+rustls）、vsock |
| 帧格式 | 自研零拷贝包管道 + protobuf RPC 控制消息；数据可 AES-GCM（ring）或整条走 WG | 树公告/链路 CRDT gossip + 会话层 e2e 加密；v0.5 移除 keepalive 泛滥，改按需 ack | **36 字节固定头**（保留 8b/长度 16b/**hop limit 8b**/src 16B/dst 16B）+ 加密体（≤64KB）；Babel TLV 做控制面（[data_packet.md](https://github.com/threefoldtech/mycelium/blob/master/docs/data_packet.md)） |
| 加密边界 | 逐隧道（peer↔peer 链路加密；中继 peer 可见明文内层？——以 WG 模式规避） | 端到端（中间节点只见密文与树头） | 端到端 AES-GCM（x25519 ECDH），**中间跳只读头部路由** |

### 5.2 路由算法

- **EasyTier：链路状态（OSPF-like）+ Dijkstra，延迟做权**。全网成员互知拓扑，peer 间经 RPC 同步路由/peer 信息；任何节点可为他人转发（可白名单限制）。适合几十~几百节点的"熟人网络"，不追求全球规模。
- **Yggdrasil：全局生成树 + 贪婪路由 + Bloom filter 目的地查找 + CRDT 链路状态**。为"百万级陌生人 mesh"设计：每 peer 常数状态、收敛时间 ∝ 树深；代价是路径非最优（受树形约束）、核心节点承担查找广播带宽、树根波动影响全网（[v0.5 博文](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)）。
- **Mycelium：Babel 派生距离向量**（feasibility 条件防环 + 按需 RouteRequest + 包缓存），locality-aware、断链自动重路由；官方承认单网 ~10 万节点上限。介于两者之间：比链路状态省状态，比树路由路径更优。

### 5.3 与"纯 IPv6 直连"定位的本质差异

1. **三者都是"转发型 mesh"**：Yggdrasil/Mycelium 的每个节点、EasyTier 的可选 relay peer 都会替别人转发流量——**多跳转发就是它们的"中继"**，只是去中心化了。因此它们必须携带路由算法这个最重的复杂度。新项目若坚持"直连或失败"，整个路由收敛层可以不存在——只需 (a) 身份→地址派生，(b) endpoint 发现/gossip，(c) 一跳的子网路由宣告。这是与三者最根本的架构分野，也是"小而可审计"的来源。
2. **寻址上应当直接继承 Ygg/Mycelium**：公钥派生 IPv6 地址 + 每节点（站点）/64。两者分别用 `200::/7`、`400::/7` 这类**非正式挪用的地址空间**（IANA 保留段），有合规瑕疵；新项目用 RFC4193 ULA（fd00::/8 内哈希前缀）更稳妥。
3. **NAT/防火墙姿态**：Ygg/Mycelium 干脆不打洞（出站连接 + 多跳绕行），EasyTier 打到生日攻击级别。IPv6-only 直连定位恰好落在中间的甜点上：**无需 NAT 打洞，但需要轻量的状态防火墙双向打洞**——三者都没有把"IPv6 防火墙穿透"做成一等公民，这是空白点。
4. **数据面**：EasyTier 自研加密可选 WG，Ygg/Mycelium 全自研。三者性能都受用户态转发拖累（Ygg ~900Mbps 上限，Mycelium 类似量级）。新项目用内核 WireGuard 做数据面 + Rust 只做控制面，能以更少代码拿到更高吞吐——这是对三者的直接工程优势。
5. **信任模型**：EasyTier=共享密钥（无 ACL）、Ygg=无准入（公网 mesh 人人可达你）、Mycelium=公开 overlay + 私网 PSK 模式。三者都缺"每节点身份 + 集中式策略但离线签发"的中间态——Nebula 式 CA + innernet 式 CIDR 策略嫁接到 IPv6 前缀上，就是新项目的安全模型差异化。

---

## 主要出处汇总

Tailscale：[Peer Relays](https://tailscale.com/blog/peer-relays-beta) · [连接类型](https://tailscale.com/docs/reference/connection-types) · [Series C](https://tailscale.com/blog/series-c) · [Headscale #2841](https://github.com/juanfont/headscale/issues/2841)；ZeroTier：[Release Notes](https://raw.githubusercontent.com/zerotier/ZeroTierOne/master/RELEASE-NOTES.md) · [BSL 说明](https://www.zerotier.com/news/on-the-gpl-to-bsl-transition/) · [1.16 controller 讨论](https://discuss.zerotier.com/t/zerotier-1-16-0-self-hosted-controller/28269)；Nebula：[IPv6 overlay 博客](https://www.defined.net/blog/year-of-the-ipv6-overlay-network/) · [cert-v2 升级指南](https://nebula.defined.net/docs/guides/upgrade-to-cert-v2-and-ipv6/) · [用户吐槽](https://blog.ewonchang.com/2025/09/27/nebula-mesh-vpn-still-disappointing-after-4-years/)；NetBird：[How it works](https://docs.netbird.io/about-netbird/how-netbird-works) · [IPv6 overlay](https://docs.netbird.io/manage/settings/ipv6) · [OpenWrt](https://docs.netbird.io/get-started/install/openwrt) · [Site-to-Site](https://docs.netbird.io/use-cases/remote-access/site-to-site)；innernet：[repo](https://github.com/tonarino/innernet) · [介绍博文](https://blog.tonari.no/introducing-innernet)；EasyTier：[repo](https://github.com/EasyTier/EasyTier) · [DeepWiki 架构](https://deepwiki.com/EasyTier/EasyTier/1.2-system-architecture) · [NAT 穿透](https://deepwiki.com/EasyTier/EasyTier/3.8-nat-traversal-and-hole-punching) · [共享节点文档](https://easytier.rs/en/guide/network/host-public-server.html)；Yggdrasil：[v0.5 设计](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html) · [about](https://yggdrasil-network.github.io/about.html) · [FAQ](https://yggdrasil-network.github.io/faq.html)；Mycelium：[repo/README](https://github.com/threefoldtech/mycelium) · [DeepWiki](https://deepwiki.com/threefoldtech/mycelium) · [data_packet.md](https://github.com/threefoldtech/mycelium/blob/master/docs/data_packet.md)；vpncloud：[repo](https://github.com/dswd/vpncloud) · [HN](https://news.ycombinator.com/item?id=26678723)；Rust WG：[NepTUN](https://github.com/NordSecurity/NepTUN) · [boringtun](https://github.com/cloudflare/boringtun)。版本/活跃度数据（stars、最新 release、最后提交时间）均于 2026-08-06 经 GitHub API 实时核验。
