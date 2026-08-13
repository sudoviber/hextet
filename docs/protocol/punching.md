# hextet 打洞与端点管理（v1）

状态：已实现（`crates/engine/src/{fsm,candidates}.rs`、`crates/engine/src/daemon.rs` 与本文档同步维护）

## 为什么 IPv6 下打洞是可控的

IPv6 没有 NAT，也就没有端口改写与端口预测：端口永远由自己决定（默认 UDP 4193），
会合记录里**只有地址会变**。剩下的障碍是**状态防火墙**——出站包先建 state，对端
"迟到"的入站包命中 state 即放行。因此打洞不需要独立的信令协议：两端同时发
WireGuard 握手包，握手包本身就是打洞包（设计 spec §4）。

## 端点候选

每个 peer 维护一个有序候选列表，来源四处、按此顺序拼接后去重（归一化后比较），
上限 8 个：

1. `last_good`——端点缓存里最近一次被证实可用的 endpoint（重启后最快路径）；
2. **会合层当下发现的地址**（M3 起：LAN 组播公告；阶段 D 的 gossip 转介、
   阶段 E 的 DHT、阶段 F 的 DDNS 走同一路，按来源优先级 LAN → gossip → DHT → DDNS
   排序）。它排在配置之前，因为它是**活证据**——几十秒内
   亲耳听到对端在这个地址上；而配置是**静态声明**，可能是几个月前写下的；
3. 配置文件 `[[peers]] endpoints` 里的地址，**保持配置顺序**（用户手填的地址是
   设计 spec §3 D3 ⑦ 的终极兜底，必须优先于缓存）；
4. 端点缓存的历史地址，按 `last_seen_unix` 由新到旧。

截断发生在拼接过程中，因此靠前的来源永远不会被靠后的来源挤掉。

归一化 = 把 `SocketAddrV6` 的 `flowinfo`/`scope_id` 清零。跨来源（内核 / 配置 /
缓存）比较 endpoint 前必须归一化，否则这两个字段的差异会让"内核 endpoint ≠ 候选"
恒成立。

## 状态机

每个 peer 一个状态机，每秒 tick 一次，输入是内核 WireGuard 报告的
`(last_handshake, endpoint)`：

| 状态 | 条件 | 动作 |
|---|---|---|
| `Probing{i}` | 握手新鲜（<180s） | 转 `Connected`，把当前 endpoint 记入缓存 |
| `Probing{i}` | 距上次切换 ≥2.5s | 切到候选 `i+1`（回绕时轮次 +1），设置 endpoint + nudge |
| `Probing{i}` | 距上次切换 <2.5s | 无动作 |
| `Connected` | 握手过期（≥180s） | 退回 `Probing{0}`，设置 endpoint + nudge |
| `Connected` | 内核 endpoint 变了 | 跟随（对端 roaming），记入缓存 |
| `Connected` | 其余 | 无动作 |

- **2.5s 轮换间隔**：内核 WireGuard 的握手重试间隔是 5s（REKEY_TIMEOUT），2.5s
  保证每个候选在被换掉前至少收到一次我们主动触发的握手初始化。
- **只有一个候选时**「轮换」会回到自己，仍然重发 nudge——否则内核放弃握手后
  （约 90s，MAX_TIMER_HANDSHAKES）就再也不会重试。
- **nudge** = 向该 peer 的 overlay 地址（`[peer]:9`，RFC 863 discard）发一个 1 字节
  UDP 包。包本身会被丢弃，但它让内核 WireGuard 有东西可发：没有会话时触发握手，
  有会话时发出一个用**当前源地址**加密的已认证包。

## 本机地址变化响应（目标 <5s）

daemon 订阅 netlink `RTNLGRP_IPV6_IFADDR`（等价 `ip -6 monitor address`，含
valid-lifetime=0 的静默换前缀）。收到事件后：去抖 200ms 吞掉同一次重拨产生的
事件串 → 对**所有** peer 调 `kick`：

- `Connected` 的 peer 只发 nudge——对端 endpoint 不需要改，我们只要让对端收到一个
  来自新源地址的已认证包，WireGuard 的 roaming 语义就会把对端记录的 endpoint
  更新过来（这是"单侧变化自愈"，无需任何会合）；
- `Probing` 的 peer 重设当前候选并 nudge，重新计时。

因此单侧换前缀的恢复时间 ≈ netlink 事件延迟 + 200ms 去抖 + 一次握手往返，
远小于 5s；不依赖 keepalive（25s）也不依赖握手超时（180s）。

## 会合层送来新候选时

会合层（LAN 公告 / gossip 转介 / DHT）发现某个 peer 的新地址时，daemon 重算该 peer
的候选列表并交给状态机，规则：

- `Connected` 的 peer：**只换列表，不产生任何动作**——但有一个例外：若该 peer 当前
  连着的地址既不是配置里手填的、也不再被任何"权威"会合源在报，则主动离开旧地址去
  试新地址（`retry_from`）。**权威源指 LAN / DHT / DDNS，故意排除 gossip**：gossip 是
  转述、且要沿现有隧道传播，双端同时换前缀、隧道已断时它拿不到对端新地址，旧条目会
  一直留在表里——若不排除，gossip 在换址前就把旧地址喂给了对端，会让这条恢复路径
  变成"看运气"（取决于 gossip 有没有赶在换址前送达，netns-e2e-dht.sh 偶发超时的
  根因）。否则一条正常工作的连接绝不因为"听到了新地址"被打断；新列表会在将来握手
  失效时才起作用。这个例外正是"双侧同时换前缀、只剩 DHT 会合"能秒级恢复的关键——
  否则要等 180s 握手过期才退回 Probing。
- `Probing` 的 peer：列表里出现了旧列表没有的地址 → **立刻指向第一个新地址并重试**
  （新发现的地址是活证据，比继续磨完剩下的陈旧候选更值得先试），并重置 2.5s 轮换
  计时让新候选拿到完整一轮；没有新地址时尽量继续指向原来那个（跟随它的新下标），
  它也不在列表里了才回到下标 0。

## 双侧同时换前缀

M2 的本层不解决——两端的候选都失效时没有任何一方知道对方在哪。M3 起：

- **同一 LAN 内**：LAN 组播公告覆盖（见 `docs/protocol/lan-discovery.md`）——
  链路本地组播与公网前缀无关，一个公告周期（5s）内双方重新知道对方地址。
- **跨 LAN**：mesh peer 转介（阶段 D）/ DHT（阶段 E）/ DDNS 负责补上；
  在那之前的兜底是用户在任一侧重填 `[[peers]] endpoints`。

## 不做的事

- 不做端口预测、端口喷射、生日攻击（IPv4 NAT 才需要）；
- 不做 STUN 式地址发现（候选来自配置、缓存与会合层；DHT 在 M3 阶段 E）；
- 不引入任何路由协议或多跳转发（自有节点中继在 M3，且是显式单跳）。
