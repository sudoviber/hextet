# hextet 地址派生规范（v1）

状态：已实现（crates/core/src/{network,addr}.rs 与本文档同步维护）

## 输入
- `network_key`：32B 随机共享秘密（base64 存于配置）
- `node_pubkey`：节点 ed25519 公钥（32B）

## 派生
1. `network_id = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("network-id", 5)`
2. 网络前缀 = `0xfd || network_id`，即 ULA fd00::/8 内的一个 /48（RFC 4193）
3. `subnet_id = SHA-256("hextet-v1 subnet-id" || node_pubkey)[0..2]`（大端 u16）
4. 节点 site 前缀 = `网络前缀 || subnet_id`（/64，供 site-to-site 子网路由）
5. `iid = SHA-256("hextet-v1 iid" || node_pubkey)[0..8]`；全零非法（拒绝该公钥）
6. 节点地址 = `网络前缀(6B) || subnet_id(2B) || iid(8B)`（/128，位于其 site /64 内）

## WireGuard 密钥派生
- WG 私钥 = ed25519 `SigningKey::to_scalar_bytes()`（SHA-512 扩展后 clamp 的标量）
- WG 公钥 = ed25519 `VerifyingKey::to_montgomery()`（birational 映射到 Curve25519）
- 两者满足 `x25519(私钥, basepoint) == 公钥`（core 有 proptest 保证）

## 碰撞
- 网络间 /48 碰撞：RFC 4193 L=40，N 网络碰撞率 P≈N²/2⁴¹，可忽略
- 网内 subnet_id 为 16-bit：N 节点碰撞率 ≈ N²/2¹⁷（100 节点约 7%）——
  **必须**在配置加载/成员准入时校验（`check_subnet_collisions`），
  冲突时提示重新生成节点密钥
- 回归向量：全零 network_key → 前缀见 core 测试 `frozen_derivation_vector`

## 地址分类（哪些地址能当 endpoint）

overlay 地址是派生出来的，而**底层 endpoint 地址是从环境里拿到的**（本机枚举、
LAN 公告、配置、DHT），所以需要一个统一判定：`is_usable_endpoint_addr`
（`crates/core/src/addr.rs`）。排除四类，每一类都有具体的坑：

| 排除 | 判据 | 为什么 |
|---|---|---|
| ULA | `fc00::/7` | hextet 自己的 overlay 就是 ULA，拿它当 endpoint 会让隧道套隧道形成回环；LAN 上其他设备的 ULA 同理不可路由到公网 |
| 链路本地 | `fe80::/10` | 需要 scope id 才有意义，而 scope id 是**本机**的接口编号，跨节点传过去没有意义 |
| loopback / 未指定 | `::1` / `::` | 不是对端能到达的地址 |
| 组播 | `ff00::/8` | endpoint 必须是单播 |

文档前缀 `2001:db8::/32` **刻意不排除**——netns E2E 与所有文档示例都用它。

这个判定同时服务三处：`hextet doctor` 的本机地址枚举、`hextet invite new` 的
endpoint 推断、LAN 公告的地址过滤（收到的公告里的地址是对端**声称**的，
不过滤就等于允许成员让我们把握手包打到任意地址去）。

## 测试向量
见 `crates/core/src/network.rs::tests::frozen_derivation_vector`
与 `crates/core/src/addr.rs::tests::{ula_and_link_local_boundaries, usable_endpoint_addresses}`。
