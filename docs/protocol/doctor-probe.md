# hextet doctor 探针协议（v1）

状态：已实现（`crates/core/src/probe.rs`、`crates/engine/src/{probe_responder,doctor_client}.rs` 与本文档同步维护）

## 它解决什么问题

`hextet doctor` 要回答"本机的 IPv6 入站是开放的、只放行已请求流量的（状态防火墙）、
还是全被拦的"。这个判断**必须由外部视角给出**——本机自己看不见自己的入站策略。
而 hextet 没有任何项目方服务器（设计 spec §2 目标 2），所以外部视角只能来自
**同一网络里的另一个节点**。

## 端口

- 响应器监听 `[node] probe_port`（默认 **4194**）。
- 为什么不复用 WireGuard 的 4193：内核 WireGuard 独占那个 UDP 端口，用户态无法
  在同端口上收自己的包。
- 因此本协议测的是"任意 UDP 端口的入站策略"，而不是 4193 本身。住宅 CPE 与光猫
  的默认丢弃规则不区分端口，这个代理指标是可靠的；`doctor` 的输出会说明这一点。

## 线格式（32 字节定长，大端）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `HXTP` |
| 4 | 1 | version | 1 |
| 5 | 1 | kind | 1=Request, 2=Response, 3=Unsolicited |
| 6 | 8 | nonce | 每次探测随机；回包原样带回 |
| 14 | 2 | reply_port | Request：客户端收 Unsolicited 的端口；其余为 0 |
| 16 | 16 | mac | `HMAC-SHA256(probe_key, bytes[0..16])` 截断前 16 字节 |

- `probe_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("doctor-probe", 32)`
- MAC 校验用常量时间比较；校验失败的包**静默丢弃**，不回任何东西（不给探测者
  任何"这里有个 hextet 节点"的信号）。
- 长于 32 字节的数据报只解析前 32 字节。
- 冻结测试向量见 `crates/core/src/probe.rs::tests::{frozen_probe_key_vector, frozen_wire_vector}`。

## 交换流程

客户端（判定**自己**的入站策略）绑两个 UDP socket：

- `S1`：用来发 Request、收 Response；
- `S2`：**只收不发**，端口号写进 Request 的 `reply_port`。

```
客户端 A                                        对端 B（运行 daemon）
  S1 ─── Request{nonce=N, reply_port=P(S2)} ───────► :4194
  S1 ◄── Response{nonce=N}  （源端口 4194）──────── :4194      ① 已请求路径
  S2 ◄── Unsolicited{nonce=N}（源端口=另一个临时端口）──── 新 socket   ② 未经请求路径
```

- ① 之所以能回来，是因为 A 从 S1 发出的 Request 已经在 A 的防火墙上建了 state；
  它证明"A 的出站 + 回包"这条路通（也顺带证明 B 活着、密钥一致）。
- ② 从**另一个源端口**发向 A 从未发过包的 `reply_port`，因此不匹配 A 的任何
  conntrack 条目——只有 A 的防火墙放行未经请求的入站时才会到达。
- B 在收到 Request 后延迟 300ms 再发 ②，确保 A 已在 S2 上等待。
- 客户端每 700ms 重发 Request 直到收到 Response 或超时（默认 5s），容忍丢包。

## 分类

| 有全局 IPv6 | ② 到达 | ① 到达 | 结论 |
|---|---|---|---|
| 否 | — | — | `no-ipv6` |
| 是 | 是 | — | `open` |
| 是 | 否 | 是 | `stateful` |
| 是 | 否 | 否 | `blocked` |

`blocked` 是**合并结论**：可能是本机入站全被拦，也可能是对端没在跑 daemon、
网络密钥不一致、或对端不可达——单靠一个对端无法区分。`doctor` 的输出会如实
列出这三种可能，并建议换一个对端再试。

## 安全性

- **认证**：非网络成员发的包过不了 MAC 校验，直接丢弃。
- **放大**：1 个 Request（32B）最多触发 2 个 32B 回包 = 2× 放大，且需要有效 MAC；
  响应器另外对**每个源 IP 限速 1 次/秒**（表上限 64 项，超出时清理 60s 前的旧条目），
  把它压到可忽略。
- **隐私**：报文里没有公钥、没有节点名、没有 overlay 地址；nonce 是一次性随机数。
- **不放行入站**：响应器只是一个 UDP socket，不改任何防火墙规则。

## 不做的事

- 不做 STUN 式"告诉我我的公网地址"（M2 的候选 endpoint 全部来自配置与缓存）；
- 不做多对端交叉验证（需要 M3 的 gossip 才有节点列表）；
- 不测 TCP、不测 ICMP、不测 4193 本身。
