# hextet LAN 组播发现（v1）

状态：已实现（`crates/core/src/beacon.rs`、`crates/engine/src/lan.rs` 与本文档同步维护）

## 它解决什么问题

设计 spec §3 D3 的会合兜底链第 ① 层：**同一 LAN 内的两个节点不该需要任何配置、
任何服务器就能找到彼此**。

它同时覆盖一个 DHT 也难做的场景：同 LAN 的两台机器**同时**换了公网前缀
（家宽 PPPoE 重拨会让整个 LAN 一起换）。此时双方缓存里的地址都作废、
WireGuard roaming 也无从下手（谁都不知道往哪发第一个包），但链路本地组播不受
公网前缀影响——一个公告周期（5s）内双方就重新知道了对方的新地址。

## 端口与组播组

- 组播组 **`ff02::4193`**（链路本地 scope），UDP 端口 **4195**（`[node] lan_port`）。
- 选链路本地 scope 是刻意的：组播 hop limit 默认为 1，路由器不转发它，
  公告天然不会离开本链路。
- 组 ID `0x4193` 与 WireGuard 端口呼应，且不在 IANA 已分配的低号段里。
- daemon 在**每个** UP 且支持组播的非 loopback 接口上 join 并逐接口发送
  （链路本地组播必须逐接口发，靠 `sin6_scope_id` 选接口）。hextet 自己的 WG
  接口被排除——往隧道里发 LAN 公告没有意义。
- `[node] lan_discovery = false` 可完全关闭。

## 线格式

变长，总长恒为 `50 + 16×addr_count + 16` 字节（`addr_count ≤ 4`，即 ≤130 字节）。
大端。

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `HXTL` |
| 4 | 1 | version | 1 |
| 5 | 1 | kind | 1 = Announce（v1 只有这一种） |
| 6 | 1 | addr_count | 0..=4 |
| 7 | 1 | reserved | 必须为 0 |
| 8 | 2 | listen_port | 公告者的 WireGuard 监听端口 |
| 10 | 8 | seq | 发送时的 Unix 秒 |
| 18 | 32 | node_public_key | 公告者的 ed25519 公钥 |
| 50 | 16×n | addresses | 公告者声称可达的 IPv6 地址 |
| 50+16n | 16 | mac | `HMAC-SHA256(lan_key, bytes[0..50+16n])` 截断前 16 字节 |

- `lan_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("lan-beacon", 32)`
- MAC 校验用常量时间比较。
- **不接受尾随填充**：变长报文的长度必须与 `addr_count` 精确自洽，否则解析有歧义。
- 解析顺序：长度下界 → magic → version → kind → reserved → addr_count 上界 →
  长度自洽 → **MAC** → 公钥曲线点校验。公钥校验是这里最贵的一步，放在 MAC 之后，
  不给未认证的报文花这个钱。
- 冻结测试向量见 `crates/core/src/beacon.rs::tests::frozen_wire_vector`。

## 收到公告后做什么

1. **解码失败 → 静默丢弃。** 不回任何东西：LAN 上的观察者不该从我们的行为里读出
   "这里有个 hextet 节点"。
2. **公钥是自己 → 忽略**（组播会回环）。
3. **`|seq − 本地时间| > 300s → 忽略**（陈旧重放或时钟离谱的报文）。
4. **`seq` 比该节点已记录的更旧 → 整条丢弃**（重放保护，连 TTL 都不刷新）。
5. **过滤地址**：丢掉 ULA、链路本地、loopback、组播、未指定地址
   （`hextet_core::addr::is_usable_endpoint_addr`）。过滤后为空 → 忽略。
   这一步是必需的：地址是对端**声称**的，不过滤就等于允许成员让我们把握手包
   打到任意地址去。
6. **记表**：`公钥 → {endpoints, seq, last_seen}`，TTL 60s，最多 64 个节点。
   表满时先按 TTL 清理，仍满则**拒绝新条目**而不是驱逐已知节点——已知节点的价值
   高于一个可能是伪造的新条目。
7. **endpoint 集合有变化**时才通知 daemon；daemon 把它作为候选来源
   `discovered` 交给打洞状态机（优先级见 `docs/protocol/punching.md`）。

## 公告节奏

- 每 **5s** 一条；启动立即发一条。
- 本机 IPv6 地址变化（netlink 事件）后**立刻补发**一条——这样"换前缀"到"对端知道
  我的新地址"的延迟不受公告周期约束。
- 本机没有可用作 endpoint 的地址时**跳过**本次公告（发一条没有地址的公告没有信息量）。
- 一条公告最多带 4 个地址：多前缀主机（运营商 GUA + 临时地址 + 二级路由 PD）
  常有三四个全局地址，4 个够用且把报文压在 130 字节内。超量时由发送侧**显式截断**
  （编码函数拒绝超量，不做静默截断）。

## 安全性

| 威胁 | 结果 |
|---|---|
| LAN 上的任意设备伪造成员公告 | 挡住：没有 network key 就算不出合法 MAC |
| 重放捕获到的旧公告 | 挡住：`seq` 单调 + ±300s 窗口 |
| 重放**当前**的公告 | 只能把一条本就有效的记录的 TTL 续上，代价是一个候选位 |
| 成员谎报自己的地址 | 可以，但地址会被可用性过滤，且只影响它自己那条连接 |
| 被动观察者判断"这里在用 hextet" | **做不到隐藏**：公钥与地址是明文。标准 mDNS 方案同样如此 |
| 公告泄漏到 LAN 之外 | 挡住：链路本地 scope + hop limit 1 |

`lan_key` 与 doctor 探针密钥、（M3-E 的）DHT 记录密钥彼此独立派生：LAN 公告是
最容易被观察到的报文，它的密钥出问题不该牵连别的用途。

## 与状态文件的关系

`hextet status` 的 `endpoint_source == "lan"` 表示当前 endpoint 来自 LAN 公告；
`lan_endpoints` 是这一路当前给出的地址数量。语义细节见
`docs/dev/state-files.md`。

## 为什么不用标准 mDNS/DNS-SD

见 `docs/adr/ADR-0002-lan-beacon-instead-of-mdns.md`。
