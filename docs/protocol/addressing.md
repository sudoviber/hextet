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

## 测试向量
见 `crates/core/src/network.rs::tests::frozen_derivation_vector`。
