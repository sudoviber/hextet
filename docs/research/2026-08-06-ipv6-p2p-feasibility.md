# IPv6-only 无服务器 Mesh VPN 可行性调研报告

> 调研时间：2026-08。场景：中国大陆家宽异地组网（兼顾国际），节点含 PC、手机、OpenWrt 路由器。
> 本文档是 hextet 项目三份立项调研之一，另见 [竞品分析](2026-08-06-competitor-analysis.md) 与 [Rust 技术选型](2026-08-06-rust-stack-selection.md)。

---

## 1. IPv6 防火墙打洞（关键难题）

### 【结论】
**可靠性高于 IPv4 打洞，是本项目成立的基础**。IPv6 无 NAT 意味着无端口映射不确定性：只要两端各自知道对方的 GUA 和端口，同时向对方发 UDP，各自防火墙先建出站 state，对方"迟到"的入站包命中 state 即放行——不存在 IPv4 symmetric NAT 那类算法性失败。剩下的失败模式全部是**策略性**的：(a) 防火墙对 UDP 有 state 也丢（少见）；(b) 非 endpoint-independent filtering（RFC 6092 推荐 EIF，实际 CPE conntrack 基本都是按五元组回包放行，同时发包场景仍成立）；(c) 蜂窝网入站策略。中国光猫默认**开启** IPv6 SPI 丢弃未经请求的入站——但这不阻碍打洞（打洞的本质就是先出站建 state），只阻碍"无打洞的裸入站监听"。

### 【依据】
- Tailscale《How NAT traversal works》：IPv6 下 hard NAT（对称 NAT/端口随机化）消失，但 stateful firewall 仍在（"Your office workstation may have a globally reachable IPv6 address, but I'll bet there's still a firewall enforcing outbound-only"）；同时双向发包可穿透 stateful firewall；仍建议保留兜底 relay。https://tailscale.com/blog/how-nat-traversal-works
- RFC 6092（住宅 IPv6 CPE 简单安全能力）：REC-11/REC-17 推荐 UDP 采用 **endpoint-independent filtering**；REC-14 UDP state 空闲超时 **MUST ≥ 2 分钟，默认 5 分钟**（远宽于 IPv4 NAT 的 ~30s）；REC-16 出站包 MUST 刷新 state；§3.2.4（REC-21/22）**默认不得禁止 IPsec AH/ESP**——注意："REC-49 = IPsec 例外"的说法不准确，**REC-49 实际是"必须提供易于开启的 transparent mode（全放行）配置项"**，IPsec 豁免在 REC-21/22。https://datatracker.ietf.org/doc/html/rfc6092
- RFC 4787（IPv4 UDP NAT 行为要求）/ RFC 6888（CGN 要求）是 IPv4 侧类比；RFC 6092 的 REC-17 即其 IPv6 防火墙对应物。
- 中国光猫实测（社区证据链）：光猫默认带 IPv6 SPI 防火墙、入站全丢是常态（[知乎：移动宽带关闭 IPv6 防火墙](https://zhuanlan.zhihu.com/p/441632909)、[V2EX：家宽默认禁用 IPv6 入站](https://www.v2ex.com/t/808068)、[知乎：IPv6 入站是否被三大运营商禁止](https://www.zhihu.com/question/544659938)）。移动光猫可在"安全→防火墙→攻击保护"取消 Ipv6Spi；部分地区联通光猫（如广州）**关不掉**，只能桥接+自己路由器拨号；烽火/华为/中兴光猫有 telnet+ip6tables 关防火墙的民间教程（[恩山教程](https://www.right.com.cn/forum/thread-8282065-1-1.html)、[烽火光猫关 IPv6 防火墙](https://www.cnblogs.com/libitum/p/18512702)）。"很多光猫默认无防火墙"的说法**不成立**——主流是默认有且开。
- 蜂窝网 IPv6 入站（[softs.im 三大运营商无线数据网络 IPv6 防火墙实测](https://softs.im/%E4%B8%AD%E5%9B%BD%E4%B8%89%E5%A4%A7%E8%BF%90%E8%90%A5%E5%95%86%E6%97%A0%E7%BA%BF%E6%95%B0%E6%8D%AE%E7%BD%91%E7%BB%9Cipv6%E9%98%B2%E7%81%AB%E5%A2%99/)、[V2EX：北京移动 IPv6 禁止入站](https://cn.v2ex.com/t/1047221)）：广东联通/电信 4G/5G 可 ping、TCP/UDP 入站可达；**移动（CMCC）蜂窝普遍丢弃入站**（广东移动 4G、河北移动 5G、北京移动均不可达）；另有移动 5G 高峰期 UDP 回包丢失（疑似 UDP QoS）的报告。
- 打洞成功率文献：IPv4 UDP 打洞 ~82–95%（[Grokipedia: UDP hole punching](https://grokipedia.com/page/UDP_hole_punching)）；IPv6 已知双方地址的 simultaneous-open 场景成功率上界更高，失败即策略拒绝。

### 【推荐方案】
- 打洞协议：两端通过会合渠道交换 (GUA, port) 后，**双向同时发签名握手包**（Noise/WireGuard 握手天然胜任），指数退避重试 ≤10s。因无 NAT，无需 birthday attack 式端口喷射。
- 探测与诊断内置化：启动时自测本机 IPv6 入站可达性（让对端或 DHT 邻居回探），把结果标注为 `open / stateful-firewall / inbound-blocked / no-ipv6`，指导连接策略并给用户明确的"光猫防火墙关闭指引"（附机型教程链接）。
- 移动蜂窝节点定位为"主动发起方 + 打洞参与方"，不承诺被动可达。

### 【风险与缓解】
- 少数光猫 UDP 有 state 也丢/超时极短 → 缓解：文档引导桥接模式或关 Ipv6Spi；保留 mesh 内 peer 中继作软兜底。
- 移动蜂窝双端都是 CMCC 且防火墙非对称丢包 → 打洞可能失败；缓解：peer 中继或提示用户换网络。
- 运营商 UDP QoS（高峰限速/丢包）→ 支持 TCP/QUIC 伪装传输作为备用通道（可后期迭代）。

---

## 2. 动态前缀问题

### 【结论】
中国家宽 IPv6 前缀是**事件驱动型动态**：每次 PPPoE 重拨/掉线/光猫重启后前缀大概率更换；**不掉线则 /56 前缀可稳定数周**。没有德国式 24h 强制重拨（德国多家 ISP Zwangstrennung 每 86400s 断一次并换前缀；Telekom 光纤已放宽到 ~180 天）。因此"两端同时换前缀"在中国场景下是低概率事件（通常由区域性维护、停电、用户同时重启触发），但**必须设计兜底**，因为一旦发生且无会合机制，网络将永久脑裂。

### 【依据】
- 中国家宽前缀行为：[V2EX：IPv6 前缀基本不变（不掉线时）](https://v2ex.com/t/672411)、[V2EX：动态前缀最佳实践](https://www.v2ex.com/t/955636)（每次重拨后前缀变化、LAN 侧所有地址随之全变）、[V2EX：各地 PD 前缀长度调查](https://v2ex.com/t/930849)（/56 主流，部分 /60、/64）、[NodeSeek：家宽获取固定 IPv6](https://www.nodeseek.com/post-238966-1)。
- RIPE-690 建议 ISP 给终端用户**持久前缀**，但中国运营商未跟进：https://www.ripe.net/publications/docs/ripe-690/
- 德国对比：[Telekom 社区：光纤 24h 强制断线讨论](https://telekomhilft.telekom.de/conversations/festnetz-internet/zwangstrennung-nach-24h-bei-glasfaser/68d8fd0b652f4e644119cc5b)。
- 前缀闪变对 SLAAC 的破坏：RFC 8978（Flash-Renumbering）https://datatracker.ietf.org/doc/html/rfc8978
- WireGuard roaming 语义：认证包到达即更新对端 endpoint → **单侧变化自愈，无需任何会合**；只有双侧在彼此失联窗口内同时变化才需要外部会合。

### 【推荐方案】
- 协议内置 roaming（同 WireGuard：以通过 AEAD 验证的包源地址为准更新 endpoint，天然防伪造）。
- 节点监听本机地址变化（netlink / RA 事件），前缀一变**立即**：向所有已知 peer 旧地址发新握手（对方没变就直接恢复）+ 推送 gossip 更新 + 重发布 DHT 记录。反应速度是关键指标（目标 <5s 恢复）。
- 保留 per-peer 历史地址列表并发试探（前缀变化后端口不变——无 NAT，端口是自己选的，这点比 IPv4 有利）。

### 【风险与缓解】
- 双端同时变化 → 见 §3 兜底链；N≥3 节点时靠"未变化的第三节点转介"在 mesh 内解决。
- 运营商静默换前缀（不掉 PPPoE，直接 RA/DHCPv6 推新前缀，旧地址未过期先失效）→ 监听 valid-lifetime=0 与新 PD 事件，勿只依赖拨号事件。

---

## 3. 无服务器会合机制对比（核心设计）

### 【结论】
**信息论上不存在"零外部依赖"的双端同变会合**：两个互相失联的端点必须有一个双方都能到达的公共汇合点。工程上最接近"无服务器"的是 **BitTorrent Mainline DHT + BEP44（pkarr 模式）**——汇合点是 1000 万+ 第三方 DHT 节点组成的公共网络，不是你运营的服务器。bootstrap 节点是弱依赖，可用节点缓存消除运行期依赖。**最重要的隐藏坑：Mainline DHT 实际是 IPv4 网络**（BEP32 IPv6 DHT 采纳率极低，pkarr 依赖的 `mainline` crate 只实现 BEP 5/42/43/44，未实现 BEP32）——所以"IPv6-only 数据面"项目，其 DHT 会合面**需要 IPv4 出站 UDP**（中国家宽 CGNAT 下出站 UDP 可用，此依赖成立但必须写进设计假设）。

### 【依据】
- pkarr：ed25519 公钥即域名，签名 DNS 记录（≤1000 字节）发布到 Mainline DHT（BEP44 mutable items）；记录数小时内被 DHT 节点丢弃，需**定期重发布**（发布者与解析者都应 re-put）；有 HTTP relay 供受限环境。https://github.com/pubky/pkarr 、https://pubky.github.io/pkarr/
- BEP44：节点保存条目 ≥2 小时，seq 递增更新，支持 salt 从同一 key 派生多个存储位置。https://www.bittorrent.org/beps/bep_0044.html
- BEP32（IPv6 DHT）为独立路由表、低采纳：https://bittorrent.org/beps/bep_0032.html ；`mainline` crate 实现列表无 BEP32：https://docs.rs/mainline
- 生产先例：iroh 的 DHT node discovery 正是 pkarr+mainline（`iroh-pkarr-node-discovery`），验证了"公钥→当前直连地址"这条路在生产可用。https://www.iroh.computer/docs/concepts/discovery 、https://docs.rs/iroh-pkarr-node-discovery
- bootstrap 依赖与自举缓存：常用 bootstrap 为 `router.bittorrent.com:6881`、`dht.transmissionbt.com:6881`、`router.utorrent.com:6881`、`dht.libtorrent.org:25401`；客户端普遍把路由表存盘、重启后直连旧节点，bootstrap 仅冷启动需要；Transmission 社区还讨论过 DoH 解析 bootstrap 域名 + 节点缓存以抗 DNS 污染。https://blog.libtorrent.org/2016/09/dht-bootstrap-node/ 、https://github.com/transmission/transmission/issues/8664
- DHT 在中国：GFW 未整体封锁 BT/DHT，但存在**区域性、事件性干扰**（广东某地 DHT 节点数掉 0、部分运营商 UDP QoS）；不可假设 100% 可用。https://github.com/XTLS/BBS/issues/18 、https://www.zhihu.com/question/538103730
- WireGuard roaming / mDNS：单侧变化自愈；mDNS 仅限同一 L2 网段，用于"两设备回到同一 LAN"的直连捷径。

### 【推荐方案】——分层会合策略（按序尝试，全部并发预热）
1. **LAN mDNS/组播发现**（同网直连，零成本）；
2. **缓存端点并发试探**（含历史地址；端口稳定）；
3. **协议内 roaming**（单侧变化自愈）；
4. **mesh peer 转介**（N≥3 时的杀手锏：任一存活连接的第三节点 gossip 双方新地址——纯 P2P 内解决，全网同时换前缀概率随节点数指数下降）；
5. **DHT/pkarr 发布**（每节点以派生 key 发布加密的当前端点记录；~1h 重发布 + 地址变化即时发布；DHT 节点表持久化到磁盘消除 bootstrap 运行期依赖，并允许用户配置"以任意 peer 为 bootstrap"）；
6. **可选自托管 DDNS**（用户自己的域名，客户端直接调注册商 API 更新 AAAA/TXT——属于"用户已拥有的第三方基础设施"而非项目方服务器；在中国可达性最好，作为 DHT 被干扰时的兜底）；
7. **手动输入端点**（终极 UX 兜底：任何一侧把 `[GUA]:port` 抄给对方即可重新缝合全网）。

### 【风险与缓解】
- DHT 被区域性干扰 → 6/7 层兜底；record 同时经 pkarr HTTP relay 发布（relay 也是公共基础设施，可配置多个/自建，默认可关）。
- bootstrap 域名 DNS 污染 → 内置 IP 直连列表 + 节点缓存 + DoH 兜底。
- IPv4 出站 UDP 被禁的极端网络 → DHT 层失效，退 DDNS/手动；文档明示"DHT 会合需要 IPv4 出站"。

---

## 4. 地址与寻址设计

### 【结论】
**必须要 overlay 稳定地址，选 ULA（fd00::/8, RFC 4193）从公钥派生**。"直接用底层 GUA + 传输模式加密（IPsec 式）"在动态前缀下不可用：GUA 一变，应用连接、ACL、DNS、路由通告全部作废——等于把 §2 的问题传导给所有上层。Yggdrasil（200::/7）和 Mycelium（400::/7）证明"公钥→IPv6 地址"派生成熟可行，但它们占用 IANA 未分配空间不合规；用 ULA 空间做同样的事完全合规。碰撞概率可忽略。

### 【依据】
- RFC 4193 碰撞公式 P = 1−exp(−N²/2^(L+1))，L=40：https://datatracker.ietf.org/doc/html/rfc4193 —— 家庭 mesh N<100 时 P < 10⁻⁸；若网络级 /48 由网络密钥派生、节点级 64-bit interface ID 由节点公钥哈希派生，网内碰撞概率 ~N²/2⁶⁵，实践为零（可在成员准入时做唯一性校验彻底排除）。
- Yggdrasil 地址 = 公钥哈希截断 + 前导 1 计数压缩，200::/7：https://github.com/yggdrasil-network/yggdrasil-go ；Mycelium 400::/7（Rust）：https://github.com/threefoldtech/mycelium
- WireGuard 默认 MTU 1420；IPv6 下 overhead = 40(IPv6) + 8(UDP) + 32(WG 数据封装) = **80 字节**（注意：常见的"60 字节"是 IPv4 数字：20+8+32）：https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95 、https://defguard.net/blog/mtu-mss-decision-tree/
- PMTUD 在公网不可靠（中间盒丢 ICMPv6），MSS clamp 必备：https://defguard.net/blog/mtu-mss-decision-tree/ 、https://github.com/luizluca/wireguard-ipv6-pmtu

### 【推荐方案】
- 网络地址：`fd00::/8` 内取 network_id = HKDF(network_key) 的 40 bit → 网络 /48；每节点 site 分配 /64（供子网路由），节点自身地址 interface ID = hash(node_pubkey) 截 64 bit。地址即身份的一部分，可从地址反查应有公钥做一致性校验（Yggdrasil 同款防伪）。
- 架构：overlay tun 设备 + ULA 内网 + 底层 GUA 仅作 endpoint（WireGuard 隧道模式语义）。不做 IPsec 传输模式架构。
- MTU：中国家宽 PPPoE 底层多为 1492 → 隧道 MTU 默认 **1400**（保守稳妥），可选自动探测到 1412（=1492−80）；tun 上对 TCP 做 MSS clamp；实现主动 MTU 探测（padding 探测包）而非依赖 PMTUD。

### 【风险与缓解】
- LAN 内已有其他 ULA（用户自配 fd::）→ 派生前缀随机性保证不撞；安装时检测本地已有 ULA 路由并告警。
- 应用希望"真公网直达"（低开销）→ 后期可加"旁路直连"优化（同网/可信路径下走裸 GUA + 轻加密），MVP 不做。

---

## 5. 路由器组网（site-to-site）

### 【结论】
OpenWrt 节点作 site 网关、代表整个家庭子网完全可行且是 IPv6 的甜点场景：**每家 LAN 网段冲突问题在 IPv6 下天然消解**（每家有全球唯一 GUA 前缀；overlay ULA 前缀亦按网络派生唯一）。推荐路由 **overlay ULA /64 per site**（而非对方动态 GUA），LAN 设备无需装客户端。**NPTv6 在推荐架构下不需要**，仅当用户坚持"LAN 设备之间用运营商 GUA 互访且要屏蔽前缀动态性"时才作为高级选项。

### 【依据】
- OpenWrt WireGuard IPv6 site-to-site 实践：wg 接口独立 firewall zone、显式 lan↔vpn forwarding（IPv6 默认 forward=drop）、纯路由无需 masq6、必要时 `sourcefilter=0`（避免 ULA 源地址被 RPF 丢弃）：https://forum.openwrt.org/t/wireguard-ipv6-routing/174421 、https://aparcar.org/openwrt-with-wireguard-vpn-ipv6/ 、http://www.makikiweb.com/ipv6/wireguard_on_openwrt.html
- NPTv6 = 无状态前缀翻译，用途是地址独立性/多宿主/动态外部前缀映射稳定内部前缀：RFC 6296 https://datatracker.ietf.org/doc/html/rfc6296 、https://docs.vyos.io/en/1.3/configuration/nat/nptv6.html

### 【推荐方案】
- 每 site 在成员记录中通告其 ULA /64（+可选额外前缀），各节点写入路由表/AllowedIPs 等价物；LAN 设备通过 OpenWrt RA 获得该 ULA /64 的 SLAAC 地址（与运营商 GUA 共存，多前缀是 IPv6 原生能力）。
- OpenWrt 交付形态：官方 feed 包 + luci 界面；daemon 管 tun、路由（netlink）与 nftables 片段（独立 table，不碰用户主防火墙规则）；与主线 kernel WireGuard 无冲突（不同接口/端口），甚至可选"数据面直接驱动 kernel wireguard，控制面自研"以白嫖内核性能。
- 互访源地址选择：设置 route/RA 优先级，使跨 site 流量源选 ULA（RFC 6724 默认 ULA↔ULA 匹配，天然正确）。

### 【风险与缓解】
- 光猫路由模式下 OpenWrt 是二级路由（拿到的是光猫 PD 的子前缀或仅 /64）→ 引导桥接；或 OpenWrt 仅作 mesh 网关不依赖上游 PD（ULA 不需要运营商）。
- 用户主防火墙误拦 overlay 转发 → 安装时自动注入 zone/forwarding 并提供一键诊断。

---

## 6. 控制平面去中心化

### 【结论】
分三层：**身份用逐节点 ed25519 公钥，成员资格用网络密钥派生的邀请体系，状态分发用签名 gossip（CRDT 语义）**。纯静态配置（WireGuard 式）作为 MVP 起点完全够用且最可审计；gossip 层解决 endpoint 动态更新与成员增删的传播（EasyTier/serf 已验证该路线，EasyTier 还是 Rust 同栈先例）。TOFU 不适合 VPN 信任模型。

### 【依据】
- EasyTier：Rust+Tokio 去中心 mesh VPN，节点对等、自动发现、可自建共享节点：https://github.com/EasyTier/EasyTier
- pkarr/BEP44 的 seq+签名模型即"单写者 LWW 寄存器"，gossip 成员表可建为签名条目的 OR-Set/LWW-Map（CRDT 常规做法，无需协调者）。
- WireGuard 的 cryptokey routing 证明"公钥=路由身份"模型的简洁性。

### 【推荐方案】
- **邀请机制**：admin 生成 invite token = {network_id, 引导端点列表, 一次性授权签名}；新节点用 token 连上任一现有节点，提交自己的公钥，由持 admin key（或被授权节点）签发成员证书，gossip 全网。
- **信任模型**：网络密钥（gate DHT key 派生与记录加密）+ 逐节点公钥（数据面 Noise 认证）双层——network key 泄露只泄露"谁在哪"，不破数据面机密性。
- **密钥轮换**：会话密钥由 Noise 自动 rekey（分钟级）；节点身份轮换 = 新 key 由旧 key 签名的 continuity 记录 gossip 全网；network key 轮换 = admin 签发新 epoch，节点渐进迁移 DHT 发布位置（新旧 epoch 双发布一段时间避免脑裂）。
- 配置分发顺序：MVP 静态文件（可 git 管理）→ v2 gossip 增量（endpoint/成员/前缀通告）→ CRDT 化冲突合并。

### 【风险与缓解】
- admin key 单点 → 支持多 admin 签名（阈值可后置）；admin key 冷存储，日常只用节点 key。
- gossip 分区后成员视图分裂 → 签名条目 + 单调 seq，重连后自动收敛；成员吊销用签名 revocation 条目 + 数据面立即拒绝该公钥。

---

## 7. 隐私与安全

### 【结论】
DHT 发布是最大隐私泄露面：默认 BEP44 下，任何知道你公钥的人可实时查到你家庭公网地址（= 粗粒度地理位置与在线状态）。**必须做两件事：DHT key 用网络密钥加盐派生（外人无法定位记录），record 载荷用网络密钥加密（DHT 节点看不懂内容）**。保活电量方面，IPv6 有真实红利：RFC 6092 要求 UDP state ≥2min（默认 5min），keepalive 可从 IPv4 NAT 时代的 25s 放宽到 ~100s+，手机耗电显著下降。

### 【依据】
- BEP44 storage key = SHA1(pubkey [+ salt])，salt 支持同 key 多记录：https://www.bittorrent.org/beps/bep_0044.html —— 用 salt=HMAC(network_key, node_pubkey) 后，不知 network_key 者无法从公钥算出记录位置。
- pkarr 记录 ≤1000 字节，足够放加密后的 {endpoints, timestamp, sig}：https://github.com/pubky/pkarr
- WireGuard keepalive 25s 的依据是 IPv4 NAT 超时下限 ~30s；包仅 ~32 字节，带宽可忽略，真实成本是蜂窝无线电周期性唤醒（实测额外 5–10% 电量）：https://www.vpnsmith.com/en/blog/wireguard-persistent-keepalive-2026 、https://primevpndefender.com/does-wireguard-vpn-drain-battery/
- RFC 6092 REC-14（UDP state ≥120s，默认 300s）：https://datatracker.ietf.org/doc/html/rfc6092

### 【推荐方案】
- DHT 记录：`put(key=HMAC(nk, pk), value=AEAD_nk({addrs, port, epoch}), seq=unix_min)`；随机抖动发布时间；可选经另一 peer 代发布以隐藏发布者源 IP（DHT put 会向邻居节点暴露源地址——这层泄露只能靠代发布/relay 缓解）。
- keepalive 策略分级：路由器/PC 常电节点 25s（兼容 IPv4 路径）；手机默认 **无 keepalive + 按需重连**（打洞 <1s，体验可接受），仅对活跃会话临时 25–110s；探测到纯 IPv6 路径时自动放宽至 ~110s。
- 在线状态隐私：DHT 记录带粗粒度 epoch 而非精确时间戳，避免精确刻画作息。

### 【风险与缓解】
- network key 泄露 → 位置隐私失效（数据面仍安全）；缓解：epoch 轮换 + 吊销。
- 手机后台被系统杀死（iOS/安卓省电）→ 无服务器意味着无推送唤醒通道，被动可达性在手机上本质受限；如实向用户声明"手机是发起端"。

---

## 最终裁决："完全无服务器"在两端前缀同时变化下是否可行？

**可行，但要诚实定义"无服务器"**：

1. **N≥3 节点的网络内，该问题大概率自愈**——只要任意一条边存活，未变化节点即可 gossip 转介双方新地址，纯 mesh 内解决，不碰任何外部设施。全网节点在彼此失联窗口内同时换前缀，在中国"事件驱动换前缀"（而非德国 24h 定时）的现实下是小概率事件。
2. **两节点网络（或全网同变）必须有外部汇合点，这是信息论必然**。最"无服务器"的汇合点是 Mainline DHT（1000 万第三方节点，非项目方运营；bootstrap 依赖可用节点缓存降为仅首次冷启动）。但要接受两个现实约束：**DHT 走 IPv4 出站**（BEP32 未普及，`mainline` crate 不支持）；中国存在区域性 DHT 干扰的历史记录。
3. **推荐兜底链**（自动逐层降级，全部无项目方服务器）：

```
LAN mDNS → 缓存端点并发试探 → 协议 roaming（单侧变化自愈）
→ mesh peer 转介（N≥3 核心机制）
→ Mainline DHT / pkarr（加密+加盐记录，~1h 重发布）
→ 用户自托管 DDNS（自己的域名，可选启用，中国可达性最佳的兜底）
→ 手动输入 [GUA]:port（终极 UX 兜底，任一侧粘贴即可重新缝合全网）
```

4. **中国场景三条硬约束**要写进产品假设：(a) 光猫 IPv6 SPI 默认开——打洞可行但"裸监听"不可行，产品必须以打洞为一等公民并内置光猫指引；(b) 移动（CMCC）宽带/蜂窝入站受限最严重，双 CMCC 蜂窝端点可能需要 peer 中继；(c) DHT 会合面需要 IPv4 出站 UDP（CGNAT 下成立）。

综合判断：**项目可行**。IPv6 消除了 NAT 打洞的算法性失败，把难题收敛为"防火墙策略 + 会合"两件工程上可控的事；上述兜底链在不引入任何项目方服务器的前提下，把"双端同变脑裂"压缩为可自动恢复或一次手动操作可恢复的事件。

---

## 主要来源

[Tailscale: How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works) · [RFC 6092](https://datatracker.ietf.org/doc/html/rfc6092) · [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193) · [RFC 6296](https://datatracker.ietf.org/doc/html/rfc6296) · [RFC 8978](https://datatracker.ietf.org/doc/html/rfc8978) · [BEP44](https://www.bittorrent.org/beps/bep_0044.html) · [BEP32](https://bittorrent.org/beps/bep_0032.html) · [pkarr](https://github.com/pubky/pkarr) · [mainline crate](https://docs.rs/mainline) · [iroh discovery](https://www.iroh.computer/docs/concepts/discovery) · [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go) · [Mycelium](https://github.com/threefoldtech/mycelium) · [EasyTier](https://github.com/EasyTier/EasyTier) · [softs.im 蜂窝 IPv6 防火墙实测](https://softs.im/%E4%B8%AD%E5%9B%BD%E4%B8%89%E5%A4%A7%E8%BF%90%E8%90%A5%E5%95%86%E6%97%A0%E7%BA%BF%E6%95%B0%E6%8D%AE%E7%BD%91%E7%BB%9Cipv6%E9%98%B2%E7%81%AB%E5%A2%99/) · [知乎：移动宽带关 IPv6 防火墙](https://zhuanlan.zhihu.com/p/441632909) · [V2EX 808068](https://www.v2ex.com/t/808068) · [V2EX 955636](https://www.v2ex.com/t/955636) · [V2EX 672411](https://v2ex.com/t/672411) · [V2EX 930849](https://v2ex.com/t/930849) · [V2EX 1047221](https://cn.v2ex.com/t/1047221) · [恩山：光猫放行 IPv6 入站](https://www.right.com.cn/forum/thread-8282065-1-1.html) · [RIPE-690](https://www.ripe.net/publications/docs/ripe-690/) · [Telekom Zwangstrennung](https://telekomhilft.telekom.de/conversations/festnetz-internet/zwangstrennung-nach-24h-bei-glasfaser/68d8fd0b652f4e644119cc5b) · [defguard MTU 决策树](https://defguard.net/blog/mtu-mss-decision-tree/) · [WireGuard optimal MTU](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95) · [libtorrent DHT bootstrap](https://blog.libtorrent.org/2016/09/dht-bootstrap-node/) · [Transmission #8664](https://github.com/transmission/transmission/issues/8664) · [XTLS/BBS #18（DHT 区域干扰）](https://github.com/XTLS/BBS/issues/18) · [OpenWrt WG IPv6 routing](https://forum.openwrt.org/t/wireguard-ipv6-routing/174421) · [aparcar OpenWrt WG IPv6](https://aparcar.org/openwrt-with-wireguard-vpn-ipv6/) · [Grokipedia: UDP hole punching](https://grokipedia.com/page/UDP_hole_punching) · [VPNSmith keepalive](https://www.vpnsmith.com/en/blog/wireguard-persistent-keepalive-2026)
