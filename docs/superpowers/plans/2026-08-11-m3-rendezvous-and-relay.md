# hextet M3（无服务器会合 + 中继逃生舱）实现计划

> **For agentic workers:** 本计划是规格级的——给接口签名、行为契约（编号可判定条目）、
> 测试清单与验收标准，**不给函数体**。实现时按 Task 顺序做，每个 Task 独立提交。

**Goal:** 让 hextet 在「双方都不知道对方现在在哪」时仍能自己找到彼此，并在
「怎么也直连不上」时经用户自有节点中继保持可用。M3 结束时 MVP（v0.1–v0.3）功能完备。

**设计依据:** `docs/superpowers/specs/2026-08-06-hextet-design.md`（已批准 v2）
§3 D3（会合兜底链）、§3 D4（控制面）、§3 D5（中继逃生舱）、§5（协议要点）、§8 M3 行。

**前序:** M0/M1（`docs/superpowers/plans/2026-08-06-m0-m1-skeleton-and-static-direct.md`）、
M2（`docs/superpowers/plans/2026-08-06-m2-dynamic-endpoints-and-doctor.md`）均已合入 main。

**M3 的验收（spec §8）:**
1. 双端同时换前缀后经 DHT 自动恢复；
2. 新节点凭 invite 一条命令入网；
3. netns 模拟双端入站全阻场景经第三节点中继连通，且 `status` 标示 relayed。

---

## Global Constraints

以下约束对**每一个** Task 生效：

- **IPv6-only**：地址一律用 `Ipv6Addr` / `SocketAddrV6`；解析到 IPv4 报错或跳过。
- **默认值**（`hextet-core::defaults`）：WG 端口 4193、探针 4194、**LAN 组播 4195**、
  **中继 4196**、**gossip 4197**、MTU 1400、接口 `hextet0`、状态目录 `/var/lib/hextet`。
- **密码学**：不自研密码学。所有子密钥走
  `HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand(<用途串>, 32)`，
  用途串已用掉 `"network-id"`、`"doctor-probe"`；M3 新增 `"lan-beacon"`、`"relay"`、
  `"gossip"`、`"dht-record"`。**一把密钥只干一件事**。
- **工程规范**：edition 2024、`#![deny(missing_docs)]`（core/wg/platform/engine 四个
  crate 已开）、`unsafe_code = "deny"`、clippy `-D warnings`。
- **文档同步**：每个 Task 的提交必须带自己那份文档更新（至少 `CHANGELOG.md` 一行；
  协议改动同步 `docs/protocol/`；偏离 spec 的决策写 ADR）。
- **TDD**：先写失败测试 → 跑一次确认失败 → 实现 → 跑通 → 提交。
  Conventional commits，末尾一行
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`。
- **不要打印密钥**：新增结构体若含 network key / seed / 派生子密钥，手写 `Debug` 打码
  （`Config`、`DeviceSpec` 已有先例）。
- **每个 Task 结束跑** `cargo xtask ci`，不绿不算完成。Linux-only 代码额外跑
  `cargo clippy --target x86_64-unknown-linux-gnu --workspace --all-targets -- -D warnings`
  （macOS 上 `linux.rs`/`daemon.rs` 根本不参与编译，本机全绿不代表它们对）。
- **E2E 只在 Linux 跑**：macOS 上跳过并在报告里写明"依赖 CI job X"。

---

## 阶段划分

> **进度**（2026-08-11）：阶段 A、B 已实现并全绿（含 netns E2E），阶段 F 的
> Task 28/29 与 Task 30 的 stable 版（属性测试）已落地。阶段 C 的两条设计约束已
> 算清并写进下面的「两个先算清楚再动手的约束」，实现待做。

| 阶段 | 状态 | Tasks | 交付 | 独立验收标准 |
|---|---|---|---|---|
| **A invite 入网** | ✅ 已完成 | 1–5 | invite token 编解码、`hextet invite new` / `join` / `peer add` | 一台机器签发 token，另一台 `hextet join <token>` 后 `inspect` 显示同一 /48，两侧 `peer add` 后能 `up` 互 ping |
| **B LAN 组播发现** | ✅ 已完成 | 6–10 | 组播 beacon 协议、`lan` 发现模块、候选来源多路化、daemon 接线 | netns：两节点配置里**互相没有 endpoint、也没有缓存**，仅靠 LAN beacon 在 15s 内互连，`status` 的 `endpoint_source` 为 `lan` |
| **C 自有节点中继** | 设计已定，待实现 | 11–16 | 中继帧协议、中继转发器、FSM `Relayed` 状态、`status` 标示 | netns 三节点：nftables 双向阻断 A↔B 直连，A/B 经 R 连通且 `punch_state == "relayed"`；解除阻断后自动升级回 direct |
| **D 隧道内 gossip** | 待做 | 17–22 | 签名条目 + LWW 收敛、endpoint 广播、peer 转介、成员/吊销 | netns 三节点：A、B 同时换前缀，仅靠与 R 的连接（转介）互相恢复 |
| **E DHT/pkarr 会合** | 待做 | 23–27 | 加盐派生 key + AEAD 载荷、发布/查询、节点表持久化 | 本地 mainline testnet：双端同时换前缀后经 DHT 恢复 |
| **F 工程规范补齐** | 部分完成 | 28–30 | CONTRIBUTING、PR 模板、CI 路径规则与 macOS check、fuzz 目标 | CI 上新增 job 全绿；改 `crates/core/src/addr*` 未动 `docs/protocol/addressing.md` 时 CI 提示 |

**阶段边界即可发布点**：每个阶段结束时代码是可发布状态，没有半成品裸露。
阶段顺序按「独立性 × 可本地验证性」排：A/B 全部可在开发机 `cargo test` 覆盖，
C 需要 netns，D 依赖 C 的三节点拓扑经验，E 依赖外部网络与新 crate（风险最高，放最后）。

---

# 阶段 A：invite 入网

**为什么先做它**：纯逻辑 + CLI，零平台依赖、零网络依赖，能在任何开发机上完整测试；
且它是 M3 唯一"用户立刻能感知"的功能（M2 结束后加一台机器仍要手抄 4 个字段）。

**阶段 A 的诚实边界**（必须写进文档，不许暗示做到了没做到的事）：
invite 在 M3-A 是**引导凭证**——它把「网络名 + network key + 引导节点公钥与 endpoint +
签发者身份 + 有效期」打成一个可粘贴的字符串。它**不能**让引导节点自动接纳新节点：
WireGuard 要求引导侧也知道新节点公钥，而 M3-A 还没有 gossip。因此 `join` 的输出里
直接给出引导侧要执行的 `hextet peer add ...` 命令。「一次性」的强制执行同样要等阶段 D。

### Task 1: core — invite token 编解码

**Files:** Create `crates/core/src/invite.rs`；Modify `crates/core/src/lib.rs`、
`crates/core/src/error.rs`、`crates/core/src/defaults.rs`

**线格式**（写进 `docs/protocol/invite.md`，Task 5）：

```
hxi1.<payload>.<sig>
```

- `hxi1` = hextet invite v1，明文前缀让人一眼认出且给未来留版本位；
- `payload` = base64url **无填充**（`URL_SAFE_NO_PAD`）的 JSON 字节；
- `sig` = base64url 无填充的 ed25519 签名，**签的是 `payload` 段的 ASCII 字节本身**
  （不是解码后的 JSON）——这样验签方验的就是它看到的字节，彻底绕开 JSON 规范化问题
  （JWT 同款做法）。

JSON payload 字段（未知字段一律**忽略**以便前向兼容；`v` 不等于 1 一律拒绝）：

| 字段 | 类型 | 含义 |
|---|---|---|
| `v` | u32 | 恒为 1 |
| `id` | string | base64url 无填充的 16 字节随机值，一次性 token 的标识（阶段 D 用它去重） |
| `network_name` | string | 网络名 |
| `network_key` | string | base64（标准字母表，与配置文件里一致）的 32 字节网络密钥 |
| `issuer` | string | base64 的签发者 ed25519 公钥 |
| `issued_unix` | u64 | 签发时刻 |
| `expires_unix` | u64 | 过期时刻 |
| `listen_port` | u16 | 网络约定的 WG 端口，写进新节点配置 |
| `bootstrap` | array | 引导节点，每项 `{name, public_key, endpoints[]}`，endpoints 是 `[v6]:port` 字符串 |

**Interfaces:**

```rust
pub const INVITE_PREFIX: &str = "hxi1";
pub const INVITE_VERSION: u32 = 1;
/// 一个 token 里最多允许的引导节点数（防止畸形 token 撑爆解析）。
pub const MAX_BOOTSTRAP: usize = 8;

pub struct BootstrapPeer {
    pub name: String,
    pub public_key: NodePublicKey,
    pub endpoints: Vec<SocketAddrV6>,
}

pub struct Invite {
    pub id: [u8; 16],
    pub network_name: String,
    pub network_key: NetworkKey,
    pub issuer: NodePublicKey,
    pub issued_unix: u64,
    pub expires_unix: u64,
    pub listen_port: u16,
    pub bootstrap: Vec<BootstrapPeer>,
}

impl Invite {
    /// 随机生成 `id`，其余字段由调用方给定。
    pub fn new(
        network_name: String, network_key: NetworkKey, issuer: NodePublicKey,
        issued_unix: u64, ttl_secs: u64, listen_port: u16, bootstrap: Vec<BootstrapPeer>,
    ) -> Self;
    /// 用签发者身份签名并编码为 token 字符串。
    pub fn encode(&self, issuer: &NodeIdentity) -> Result<String, InviteError>;
    /// 解析并验签（用 payload 里自带的 `issuer` 公钥）。
    pub fn decode(token: &str) -> Result<Self, InviteError>;
    /// 过期检查（单独一步，让调用方决定是否放宽）。
    pub fn check_not_expired(&self, now_unix: u64) -> Result<(), InviteError>;
    /// `id` 的 base64url 无填充表示（日志与阶段 D 的去重键）。
    pub fn id_string(&self) -> String;
}
```

`Invite` **手写 `Debug`**，`network_key` 输出 `<redacted>`（`NetworkKey` 刻意没有 `Debug`）。

`InviteError`（新增到 `crates/core/src/error.rs`）：
`BadPrefix`、`BadVersion(u32)`、`Malformed`（段数不对/base64 失败）、`BadJson(String)`、
`BadSignature`、`IssuerMismatch`、`Expired { expires_unix, now_unix }`、
`NoBootstrap`、`TooManyBootstrap(usize)`、`Ipv4Endpoint(String)`、`BadEndpoint(String)`、
`BadKey(IdentityError)`。

**行为契约（可判定）:**

1. `encode` 在 `self.issuer != issuer.public()` 时返回 `IssuerMismatch`，不产出 token。
2. `encode` 在 `bootstrap` 为空时返回 `NoBootstrap`；长度 > `MAX_BOOTSTRAP` 返回
   `TooManyBootstrap`。`decode` 同样检查（两侧都查，不信任对面）。
3. `decode(encode(x)) == x`（对全部字段，含 `id` 与 endpoints 顺序）。
4. token 里任何一个字节被改动 → `decode` 返回 `BadSignature`（或更早的
   `BadPrefix`/`Malformed`/`BadJson`，取决于改到哪段），**绝不返回 Ok**。
5. `v != 1` → `BadVersion`；前缀不是 `hxi1` → `BadPrefix`；段数不是 3 → `Malformed`。
6. `bootstrap[].endpoints` 里出现 IPv4 → `Ipv4Endpoint`；解析失败 → `BadEndpoint`。
7. `check_not_expired(now)`：`now > expires_unix` → `Expired`；等于不算过期。
8. token 是**单行**、不含空白字符，可安全放进 shell 单引号里。

**测试清单**（`crates/core/src/invite.rs` 的 `mod tests`）：

| 测试 | 断言什么 |
|---|---|
| `roundtrip_all_fields` | 两个 bootstrap（一个带 2 个 endpoint、一个不带）全字段往返相等 |
| `token_is_single_line_and_prefixed` | 以 `hxi1.` 开头、恰好 2 个 `.`、无空白 |
| `tampering_any_byte_is_rejected` | 逐字节翻转（至少覆盖三段各若干位置），全部 `is_err()` 且错误属于契约 4 列出的集合 |
| `wrong_issuer_key_cannot_sign` | 用另一把身份 `encode` → `IssuerMismatch` |
| `foreign_signature_is_rejected` | 手工拼装「A 的 payload + B 签的 sig」→ `BadSignature` |
| `expiry_boundary` | `now == expires_unix` 通过；`+1` 秒 `Expired` |
| `rejects_ipv4_endpoint` / `rejects_bad_endpoint` | 直接构造 JSON payload 后重签，确认对应错误 |
| `rejects_empty_and_oversized_bootstrap` | `NoBootstrap` / `TooManyBootstrap` |
| `unknown_json_fields_are_ignored` | payload JSON 里加 `"future_field": 1` 后重签仍能 decode |
| `debug_redacts_network_key` | `format!("{:?}", invite)` 含 `<redacted>`、不含 network key 的 base64 |
| `frozen_vector` | 固定 seed 身份 + 全零 network key + 固定 id/时间 → token 字符串钉扎（防止无意改格式） |

**Verify:** `cargo test -p hextet-core invite` 全绿；`cargo xtask ci` 全绿。

**CHANGELOG:** `hextet-core：invite token（hxi1 前缀、ed25519 签名、base64url 载荷）编解码与过期检查。`

---

### Task 2: core — peer 块渲染（join / peer add 共用）

**Files:** Modify `crates/core/src/config.rs`

**Interfaces:**

```rust
/// 渲染一个可直接追加到 hextet.toml 的 `[[peers]]` 块（含前导空行、尾随换行）。
pub fn render_peer_block(name: &str, public_key: &NodePublicKey, endpoints: &[SocketAddrV6]) -> String;
```

**行为契约:**

1. 输出以 `\n[[peers]]\n` 开头，以 `\n` 结尾——把它 `append` 到任何合法配置末尾后
   仍是合法 TOML（不管原文件有没有以换行结尾）。
2. `endpoints` 为空时**不输出** `endpoints = ` 这一行（而不是输出空数组），
   让配置读起来就是"这个 peer 的地址还不知道，等会合层去发现"。
3. name 与 base64 公钥都用双引号包裹；name 里出现 `"` 或 `\` 时转义
   （TOML 基本字符串规则；也可直接拒绝这类 name，但必须有测试说明选了哪条）。

**测试清单:**

| 测试 | 断言什么 |
|---|---|
| `block_appends_to_template_and_parses` | `render_template` + `render_peer_block` 拼起来写文件后 `Config::load` 成功且 peer 字段正确 |
| `no_endpoints_line_when_empty` | 输出里不含 `endpoints` |
| `multiple_blocks_append_cleanly` | 连接两个块后仍能解析出 2 个 peer |
| `special_chars_in_name` | 选定策略的行为被钉住（转义则解析回原值，拒绝则报错） |

---

### Task 3: cli — `hextet invite new`

**Files:** Create `crates/cli/src/commands/invite.rs`；Modify `crates/cli/src/commands/mod.rs`、
`crates/cli/src/main.rs`

**命令签名:**

```
hextet invite new [-c hextet.toml] [--name <bootstrap 名>] [--endpoint <[v6]:port>]...
                  [--ttl <时长>] [--json]
```

- `--name` 默认 `bootstrap`：它写进**新节点配置里那个 peer 的 name**，纯本地元数据，
  新节点可随意改。
- `--ttl` 接受 `30m` / `24h` / `7d` / `3600`（纯数字=秒），默认 `24h`；上限 `365d`。
  解析函数 `parse_ttl(&str) -> Result<u64>` 放在本文件，单测覆盖。
- `--endpoint` 可重复。**没给时**：调 `hextet_platform::list_global_ipv6(Some(interface))`
  枚举本机公网 IPv6，配 `listen_port` 组装；枚举失败（非 Linux 返回 `Unsupported`）或
  结果为空 → 报错并指明"请用 `--endpoint '[你的公网IPv6]:4193'` 显式给出"。
- 输出：token 单行打到 **stdout**（便于 `> token.txt`），人类提示打到 **stderr**。
  `--json` 时 stdout 是 `{ "token", "id", "expires_unix", "bootstrap": [...] }`。

**行为契约:**

1. token 里的 `issuer` = 本机身份公钥；`network_name`/`network_key`/`listen_port` 来自配置。
2. `--endpoint` 给了 IPv4 → 报错含 `IPv6-only`。
3. stderr 提示必须包含两句：①「token 含网络密钥，等同网络准入凭证，请走安全信道传递」；
   ②「对方 `hextet join` 后会打印一条 `hextet peer add ...`，在本机执行它才算双向接纳」。

**测试清单**（`crates/cli/tests/invite.rs`，用 `assert_cmd`）：

| 测试 | 断言什么 |
|---|---|
| `parse_ttl_*`（单测，放 invite.rs） | `30m`=1800、`24h`=86400、`7d`=604800、`3600`=3600；`0`/`abc`/`400d` 报错 |
| `invite_new_prints_token` | 有 `--endpoint` 时成功，stdout 单行以 `hxi1.` 开头 |
| `invite_new_without_endpoint_fails_clearly` | 无 `--endpoint` 且枚举不可用时 stderr 含 `--endpoint` |
| `invite_new_rejects_ipv4_endpoint` | stderr 含 `IPv6-only` |
| `invite_new_json_shape` | `--json` 输出能解析出 `token`/`expires_unix`/`bootstrap[0].public_key` |

---

### Task 4: cli — `hextet join` 与 `hextet peer add`

**Files:** Create `crates/cli/src/commands/join.rs`、`crates/cli/src/commands/peer.rs`；
Modify `commands/mod.rs`、`main.rs`

```
hextet join <TOKEN> [--key-file node.key] [--out hextet.toml] [--listen-port <p>]
                    [--state-dir <d>] [--json]
hextet peer add --name <n> --public-key <b64> [--endpoint <[v6]:port>]... [-c hextet.toml]
```

**`join` 步骤契约（顺序即安全边界）:**

1. `Invite::decode` → 验签失败立即退出（非零码），报错含"token 可能被篡改或不完整"。
2. `check_not_expired(now)` → 过期报错含过期时刻与"请让对方重新签发"。
3. 身份：`--key-file` 存在则**复用**（不覆盖！），否则**在内存里生成**。
4. **落盘前**先校验：把自身公钥与 token 里全部 bootstrap 公钥一起做
   `derive_node_addr` + `check_subnet_collisions`；碰撞则报错并提示"重新
   `hextet keygen` 换一把节点密钥"。**不留半个坏配置在磁盘上。**
5. 写文件：身份文件用 `NodeIdentity::save`（0600、`create_new`），配置用
   `render_template` + 每个 bootstrap 一个 `render_peer_block`，0600、`create_new`；
   任一目标已存在则报错退出（不覆盖），错误信息里给出该路径。
6. 打印（stdout）：本节点公钥、overlay 地址、网络 /48 前缀；并给出一行可直接复制的
   `hextet peer add --name <你的名字> --public-key <本节点公钥> --endpoint '[你的公网IPv6]:<port>'`
   供引导侧执行。`--json` 时输出 `{ public_key, address, prefix, config, key_file, peer_add_command }`。

**`peer add` 契约:**

1. 加载配置+身份；`--public-key` 解析失败 → 报错。
2. 已存在同一公钥 → 报错"该 peer 已存在"（退出码非零，不重复写）。
3. 已存在同名 peer → 报错（name 是人类用的主键，重名会让 `status` 无法辨认）。
4. 与既有 peer 或自身 subnet id 碰撞 → 报错，配置文件不变。
5. 通过后 `append` peer 块，然后**重新 `Config::load` 一次**确认可解析；
   不可解析则把文件恢复原样并报错（先读原文，失败时写回）。
6. 成功输出：该 peer 的 overlay 地址，以及提示"下一步跑 `hextet up`/重启 `hextet daemon`"。

**测试清单**（`crates/cli/tests/invite.rs` 续）：

| 测试 | 断言什么 |
|---|---|
| `join_writes_config_and_key` | 两文件存在、mode 0600、`inspect` 能跑通 |
| `join_prefix_matches_issuer` | 签发方与加入方 `inspect --json` 的 `network.prefix` 相同（**M3-A 主验收**） |
| `join_reuses_existing_key_file` | 预先 keygen 后 join，公钥不变、密钥文件内容不变 |
| `join_refuses_to_overwrite_config` | 已存在 hextet.toml 时失败且原文件内容不变 |
| `join_rejects_tampered_token` | 改 token 中间一个字符 → 失败，stderr 含"篡改" |
| `join_rejects_expired_token` | `--ttl 1` 签发后（用固定过期时间构造）→ 失败含"过期" |
| `join_prints_peer_add_command` | stdout 含 `hextet peer add` 且含自己的公钥 |
| `peer_add_then_inspect_lists_peer` | 加完 `inspect` 里出现该 peer 与其 overlay 地址 |
| `peer_add_rejects_duplicate_key_and_name` | 两种重复各自失败，且配置文件行数不变 |
| `peer_add_keeps_comments` | 原配置里的注释行在追加后仍存在（append 而非重写的证据） |
| `round_trip_two_nodes` | 端到端：A `invite new` → B `join` → 双方 `peer add` → 两侧 `inspect` 互相看到对方地址 |

---

### Task 5: 文档 — invite 协议与指引

**Files:** Create `docs/protocol/invite.md`、`docs/guides/joining.md`；
Modify `docs/guides/quickstart.md`、`README.md`、`README.zh-CN.md`、`CHANGELOG.md`

`docs/protocol/invite.md` 要覆盖：线格式逐字段表、为什么签 base64 段而不是 JSON、
`decode` 的验签只证明"未被篡改"而非"签发者可信"（信任来自你从谁手里拿到 token）、
一次性语义要等阶段 D、以及"token 含 network key ⇒ 走安全信道"。

`docs/guides/joining.md` 要覆盖：三条命令的完整时序（含引导侧 `peer add`）、
`--endpoint` 怎么填、常见错误（过期、被聊天软件截断、IPv4 endpoint）、
以及"为什么不是一条命令就完事"的诚实解释。

---

# 阶段 B：LAN 组播发现

**为什么它值得先于 DHT**：spec §3 D3 的兜底链第 ① 层，成本最低、收益最直接——
同一 LAN 内两台机器（很常见：家里的 NAS + PC）在**双端同时换前缀**时，
LAN 组播能在一个广告周期内让双方学到对方的新 GUA，而这正是 DHT 存在的理由场景之一。
它也把 daemon 的"候选来源多路化"管道搭好，阶段 D 的转介与阶段 E 的 DHT 直接复用。

**为什么不用标准 mDNS/DNS-SD**（写进 ADR-0002）：mDNS 要么自己实现一套 DNS 报文
编解码（还得处理 conflict/probing/known-answer suppression），要么引入一个新 crate；
而 hextet 需要广播的只有「公钥 + 若干 IPv6 + 端口」，且需要**网络密钥认证**
（避免任意 LAN 设备伪造成员的地址让我们去打洞）。一个 130 字节的定长 MAC 报文
用 ~150 行就写完，能被单测完整覆盖，也符合"协议一页纸讲完"的承诺。
代价：不能用 `avahi-browse`/`dns-sd` 观察——用 `hextet status` 与 `tcpdump` 替代。

### Task 6: core — 可用 endpoint 地址判定（去重复）

**Files:** Modify `crates/core/src/addr.rs`；Modify `crates/platform/src/linux.rs`、
`crates/platform/Cargo.toml`

**Interfaces:**

```rust
/// RFC 4193 ULA（fc00::/7）。
pub fn is_ula(addr: &Ipv6Addr) -> bool;
/// 链路本地单播（fe80::/10）。
pub fn is_link_local(addr: &Ipv6Addr) -> bool;
/// 能不能拿这个地址当 WireGuard endpoint 用。
///
/// 排除：ULA（hextet 自己的 overlay 就是 ULA，拿它当 endpoint 会形成回环）、
/// link-local（需要 scope id，跨节点传递没有意义）、loopback、multicast、unspecified。
pub fn is_usable_endpoint_addr(addr: &Ipv6Addr) -> bool;
```

`crates/platform/src/linux.rs` 原有的私有 `is_ula` 改为委托 `hextet_core::addr::is_ula`
（platform 新增 `hextet-core` 依赖），删掉重复实现，**保留**原有的 `ula_detection` 测试。

**测试清单:** `2001:db8::1` 可用；`fd00::1`/`fc00::1`/`fe80::1`/`::1`/`ff02::1`/`::` 不可用；
`is_ula`/`is_link_local` 的边界（`fdff:ffff::1` 是 ULA、`febf::1` 是 link-local、
`fec0::1` 不是）。

**注意:** 改了 platform 的 Linux 代码，必须跑
`cargo clippy --target x86_64-unknown-linux-gnu --workspace --all-targets -- -D warnings`。

---

### Task 7: core — LAN beacon 报文编解码

**Files:** Create `crates/core/src/beacon.rs`；Modify `crates/core/src/lib.rs`、
`error.rs`、`network.rs`（加 `derive_lan_key`）、`defaults.rs`

**线格式**（写进 `docs/protocol/lan-discovery.md`，Task 10）：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | magic `HXTL` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind（1 = Announce；v1 只有这一种） |
| 6 | 1 | addr_count（0..=4） |
| 7 | 1 | reserved，必须为 0 |
| 8 | 2 | WG 监听端口（大端） |
| 10 | 8 | seq = 发送时的 Unix 秒（大端） |
| 18 | 32 | 节点 ed25519 公钥 |
| 50 | 16×n | IPv6 地址（网络字节序，n = addr_count） |
| 50+16n | 16 | `HMAC-SHA256(lan_key, bytes[0..50+16n])` 截断左 16 字节 |

总长恒为 `50 + 16n + 16`（n ≤ 4 → ≤ 130 字节）。**不接受尾随填充**（变长报文里
长度必须自洽，否则解析有歧义）。

```rust
pub const BEACON_MAGIC: [u8; 4] = *b"HXTL";
pub const BEACON_VERSION: u8 = 1;
pub const BEACON_MAX_ADDRS: usize = 4;
pub const BEACON_MAX_LEN: usize = 130;

pub struct Beacon {
    pub node_public_key: NodePublicKey,
    pub listen_port: u16,
    pub seq: u64,
    pub addresses: Vec<Ipv6Addr>,
}

impl Beacon {
    pub fn encode(&self, lan_key: &[u8; 32]) -> Result<Vec<u8>, BeaconError>;
    pub fn decode(bytes: &[u8], lan_key: &[u8; 32]) -> Result<Self, BeaconError>;
    /// 过滤掉不可用地址（见 Task 6）后组装成 endpoint。
    pub fn endpoints(&self) -> Vec<SocketAddrV6>;
}

// network.rs
pub fn derive_lan_key(key: &NetworkKey) -> [u8; 32];  // expand("lan-beacon")
// defaults.rs
pub const DEFAULT_LAN_PORT: u16 = 4195;
pub const LAN_MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02,0,0,0,0,0,0,0x4193);
```

`BeaconError`: `TooShort`、`BadMagic`、`BadVersion(u8)`、`BadKind(u8)`、`BadReserved`、
`TooManyAddrs(usize)`、`LengthMismatch { expected, got }`、`BadMac`、`BadPublicKey`。

**行为契约:**

1. `decode` 顺序：长度下界 → magic → version → kind → reserved → addr_count 上界 →
   总长自洽 → **MAC**（`verify_truncated_left`，常量时间）→ 解析公钥。
   MAC 之前不做任何昂贵操作，公钥合法性在 MAC 之后才验。
2. `encode` 在 `addresses.len() > BEACON_MAX_ADDRS` 时返回 `TooManyAddrs`（**不静默截断**——
   截断会让"我到底广告了哪些地址"不可预测；截断由调用方显式做）。
3. 任一字节被翻转 → `decode` 报错（错误类型可以是 MAC 之前的任一种）。
4. `endpoints()` 丢弃 `!is_usable_endpoint_addr` 的地址，端口用 `listen_port`；
   `listen_port == 0` 时返回空（0 端口不是合法 endpoint）。

**测试清单:** 逐字节翻转全拒绝、0/1/4 个地址的往返、5 个地址 `TooManyAddrs`、
长度多一字节/少一字节 `LengthMismatch`、reserved≠0 拒绝、错 lan_key 拒绝、
`endpoints()` 过滤 ULA/link-local/loopback、`listen_port=0` 返回空、
`derive_lan_key` 与 `derive_probe_key` 互不相等且都不等于 network key、
`frozen_wire_vector`（全零 network key + 固定公钥/seq/地址 → 十六进制钉扎）、
proptest 往返。

---

### Task 8: engine — LAN 发现表与报文处理（纯逻辑）

**Files:** Create `crates/engine/src/lan.rs`（本 Task 只做纯逻辑部分）；
Modify `crates/engine/src/lib.rs`

```rust
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
pub const ENTRY_TTL: Duration = Duration::from_secs(60);
pub const MAX_TRACKED: usize = 64;
pub const SEQ_SKEW_TOLERANCE_SECS: u64 = 300;

/// 一条"LAN 上看到某节点"的记录。
pub struct LanTable { /* 私有 */ }

/// 通知 daemon：某个 peer 的 LAN endpoint 集合有更新。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanUpdate { pub peer_key: String, pub endpoints: Vec<SocketAddrV6> }

impl LanTable {
    pub fn new() -> Self;
    pub fn tracked(&self) -> usize;
    /// 记录一次公告。返回 `true` 表示 endpoint 集合**发生了变化**（新节点或集合不同）。
    pub fn record(&mut self, peer_key: String, endpoints: Vec<SocketAddrV6>, seq: u64, now_unix: u64) -> bool;
    pub fn endpoints_for(&self, peer_key: &str) -> &[SocketAddrV6];
    pub fn prune(&mut self, now_unix: u64);
}

/// 校验 + 记表 + 决定是否要通知 daemon。返回 `Some` 表示有变化。
pub fn handle_datagram(
    buf: &[u8], own_key_b64: &str, lan_key: &[u8; 32],
    table: &mut LanTable, now_unix: u64,
) -> Option<LanUpdate>;
```

**行为契约:**

1. `handle_datagram` 丢弃：解码失败、`node_public_key` 等于自己（组播会回环）、
   `endpoints()` 为空、`|seq - now_unix| > SEQ_SKEW_TOLERANCE_SECS`（陈旧/未来包）、
   `seq < 已记录的 seq`（重放）。全部**静默**丢弃（不给 LAN 上的观察者任何反馈）。
2. `seq == 已记录 seq` 且内容相同：刷新 `last_seen` 但返回 `None`（不制造无谓的重算）。
3. `record` 只在集合**内容**变化时返回 `true`；顺序不同视为不同（保留发送方的偏好顺序）。
4. `prune` 删掉 `now - last_seen > ENTRY_TTL` 的条目；`record` 在表满
   （`MAX_TRACKED`）时先 `prune`，仍满则拒绝新条目并返回 `false`
   （**不驱逐已知节点**——已知节点的价值高于一个可能是伪造的新条目；配置里的 peer
   数量远小于 64，正常网络永不触发）。
5. `endpoints_for` 对未知 key 返回空 slice（不 panic）。

**测试清单:** 自己的公告被忽略、坏 MAC 被忽略、重放（seq 回退）被忽略、
seq 超前 301s 被忽略、同 seq 同内容返回 None 但刷新 TTL、endpoint 集合变化返回
`Some`、TTL 到期后 `endpoints_for` 为空、表满时行为符合契约 4、
`endpoints_for` 未知 key 为空。

---

### Task 9: engine + platform — 候选来源多路化，FSM 支持运行时换候选

**Files:** Modify `crates/engine/src/candidates.rs`、`crates/engine/src/fsm.rs`、
`crates/engine/src/state.rs`；Modify `crates/platform/src/lib.rs`、`linux.rs`

**候选来源结构（替换现有 3 参数函数）:**

```rust
pub struct CandidateSources<'a> {
    /// 上次被证实可用的 endpoint（端点缓存）。
    pub last_good: Option<SocketAddrV6>,
    /// 会合层**当下**发现的 endpoint（阶段 B：LAN；阶段 D：转介；阶段 E：DHT），
    /// 调用方按新鲜度排好序。
    pub discovered: &'a [SocketAddrV6],
    /// 配置文件里手填的 endpoint（保持配置顺序）。
    pub configured: &'a [SocketAddrV6],
    /// 端点缓存的历史条目。
    pub cached: &'a [CachedEndpoint],
}
pub fn build_candidates(sources: &CandidateSources<'_>) -> Vec<SocketAddrV6>;
```

**顺序契约:** `last_good` → `discovered` → `configured` → `cached`（按 `last_seen` 新到旧），
去重（归一化后比较），截断到 `MAX_CANDIDATES`。
**为什么 `discovered` 在 `configured` 之前**：discovered 是**活证据**（60s 内亲耳听到），
configured 是**静态声明**（可能几个月前写的）。活证据优先能让"同 LAN 双端同时换前缀"
在一个广告周期内恢复。

**FSM 新增:**

```rust
/// 会合层带来新候选时更新列表。
pub fn set_candidates(&mut self, candidates: Vec<SocketAddrV6>, now: SystemTime) -> Vec<Action>;
```

契约：
1. 入参归一化去重后存下（调用方已排好序、已截断）。
2. `Connected` 状态：只换列表，返回 `[]`——绝不打扰一条正常连接。
3. `Probing` 状态：计算"新指向的 endpoint" = ①若新列表里存在旧列表没有的 endpoint，
   取**第一个新出现的**；②否则若当前指向的 endpoint 仍在列表里，跟随它的新下标；
   ③否则取下标 0。新指向 ≠ 旧指向 → 返回 `[SetEndpoint(新), Nudge]` 并重置
   `last_transition`（给新候选完整的 2.5s）；相同 → 返回 `[]`。
4. 空列表：状态回到 `Probing { candidate_index: 0, rounds: 0 }`，返回 `[]`，不 panic。

**state.rs:**
- `endpoint_source` 签名加一个 `discovered: &[SocketAddrV6]` 参数，判定顺序
  `config → discovered("lan") → cache → roamed`；
  返回值集合变为 `"none" | "config" | "lan" | "cache" | "roamed"`。
  （阶段 D/E 引入更多来源时改成带标签的来源表，届时再动。）
- `PeerState` 新增 `pub lan_endpoints: usize`；`STATE_VERSION` 提到 **2**
  （`scripts/netns-e2e-dynamic.sh` 里 `.version == 1` 的断言同步改）。

**platform 新增（Linux 实现 + 非 Linux 桩）:**

```rust
/// 可用于链路本地组播的接口列表（index, name）。
///
/// 过滤：loopback、未 UP、不支持组播、以及 `exclude` 指定的接口（hextet0 自己）。
pub async fn list_multicast_interfaces(exclude: Option<&str>) -> Result<Vec<(u32, String)>, PlatformError>;
```

**测试清单:** `build_candidates` 现有 7 个测试改用新结构体后全部保留 + 新增
「discovered 排在 configured 之前」「discovered 与 configured 重复只出现一次」；
FSM 新增 5 个测试覆盖契约 2/3①/3②/3③/4；`endpoint_source` 新增 `"lan"` 分类测试；
platform 非 Linux 桩返回 `Unsupported`（Linux 侧由 E2E 覆盖）。

---

### Task 10: engine + cli + E2E — LAN 发现接线与验收

**Files:** Modify `crates/engine/src/lan.rs`（加 `serve`）、`crates/engine/src/daemon.rs`、
`crates/core/src/config.rs`（`lan_discovery`/`lan_port`）、`crates/cli/src/commands/status.rs`；
Create `scripts/netns-e2e-lan.sh`、`docs/protocol/lan-discovery.md`、
`docs/adr/ADR-0002-lan-beacon-instead-of-mdns.md`；Modify `xtask/src/main.rs`、
`.github/workflows/ci.yml`、`docs/dev/state-files.md`、`docs/dev/e2e-matrix.md`、
`docs/guides/quickstart.md`、`CHANGELOG.md`

**配置新增:**

```toml
[node]
# lan_discovery = true    # 默认开：同 LAN 内自动发现同网节点
# lan_port = 4195
```

**`lan::serve` 签名:**

```rust
pub struct LanConfig {
    pub port: u16,
    pub group: Ipv6Addr,
    pub interfaces: Vec<u32>,
    pub own_public_key: NodePublicKey,
    pub lan_key: [u8; 32],
    pub listen_port: u16,
    /// 枚举本机地址时要排除的接口（hextet0）。
    pub exclude_interface: String,
}
/// 常驻：周期公告 + 收包。收到 `kick_rx` 的信号时立刻补发一次公告
/// （daemon 在本机地址变化时踢它）。返回只发生在 socket 出错或 `tx` 关闭。
pub async fn serve(
    cfg: LanConfig,
    tx: mpsc::Sender<LanUpdate>,
    kick_rx: mpsc::Receiver<()>,
) -> std::io::Result<()>;
```

契约：
1. 绑 `[::]:port`，对 `interfaces` 里每个 index 调 `join_multicast_v6`；
   一个接口 join 失败只 warn 并继续（容器里常有奇怪接口）；**全部失败**则返回错误。
2. `set_multicast_loop_v6(false)`（自己的包也会被公钥检查挡掉，这里只是省流量）。
3. 每 `ANNOUNCE_INTERVAL` 与每次 kick：调 `list_global_ipv6(Some(exclude_interface))`，
   取前 `BEACON_MAX_ADDRS` 个，`seq` = 当前 Unix 秒，向每个接口
   `send_to(SocketAddrV6::new(group, port, 0, if_index))`。地址列表为空则**跳过本次公告**。
4. 收到包 → `handle_datagram` → `Some` 时 `tx.send`；`tx` 关闭即正常返回。
5. 每次公告前 `table.prune(now)`。

**daemon 接线:**
- `PeerRuntime` 加 `discovered: Vec<SocketAddrV6>`；候选一律经 `CandidateSources` 组装。
- `cfg.node.lan_discovery` 为真时：`list_multicast_interfaces(Some(interface))` →
  spawn `lan::serve`；接口列表为空或枚举失败 → warn 并跳过（**不致命**）。
- select 分支新增 `Some(update) = lan_rx.recv()`：按 `update.peer_key` 找 peer
  （未知公钥 = 同网但不在本机配置里的节点 → `debug!` 记一条「发现未配置的节点 X，
  用 `hextet peer add` 加入」，这是给用户的可操作提示），命中则更新 `discovered`、
  重算候选、`fsm.set_candidates`、`apply_actions`。
- 地址变化分支里额外 `lan_kick_tx.try_send(())`（满了就算了，公告周期兜底）。
- `peer_state_of` 填 `lan_endpoints`，`endpoint_source` 传 `discovered`。

**`status` 变更:** `StatusRow` 加 `lan_endpoints: Option<usize>`，人类表格加一列 `lan`。

**E2E `scripts/netns-e2e-lan.sh`（M3-B 验收）:**
1. 两 netns + veth，同一 `2001:db8:1e::/64`（同一"LAN"），双方各一个 GUA。
2. `keygen`/`init`（各自 state_dir），互相 `peer add` 但**不给 endpoint**
   （配置里没有任何 endpoint，state_dir 里没有缓存）。
3. 起两侧 `daemon -v`，20s 内两侧 `status --json` 均满足
   `.peers[0].state == "connected" and .peers[0].punch_state == "connected"`。
4. **核心断言**：`.peers[0].endpoint_source == "lan"` 且 `.peers[0].lan_endpoints >= 1`。
5. overlay 双向 ping 通。
6. 关掉 B 的 daemon，等 `ENTRY_TTL + 5s`，A 的 `lan_endpoints` 归零
   （证明 TTL 生效，不会永久积累幽灵候选）。
7. 收尾 `down`，确认 `hextet0` 消失。
   失败时 `dump_diagnostics`（沿用 dynamic 脚本的模式，额外 dump
   `tcpdump -c 5 -i any 'ip6 and udp port 4195'` 的抓包尝试与两侧日志）。

`xtask e2e` 场景加 `lan`；CI 加 job `e2e-lan`。

---

# 阶段 C：自有节点中继（spec D5）

> 目标：双端入站全阻时，经**用户自己的**常电节点单跳转发加密 WG 包。
> 默认关闭、显式启用、状态永远透明。中继只在 UDP 层转发，不解密、不终结会话。

## 两个先算清楚再动手的约束

写实现之前必须先接受这两条事实，否则会做出一个看起来能用、实际有坑的中继。

### C-1：透明中继只能按「socket + 源地址」解复用 ⇒ 每对会话一个端口

内核 WireGuard 自己持有 UDP socket，收发的是**裸 WG 报文**——中继无法要求它给报文
加上"这包发给谁"的外层封装。因此中继只能做透明转发：收到裸 WG 包，按某种规则决定
转给谁。可用的规则只有「这包从哪来」。

于是问题来了：若 A 同时经 R 中继到 B 和 C，A 的两条流**共用同一个 WG socket**，
源地址完全相同，R 无法区分该转给 B 还是 C。

**结论：R 必须为每一对会话分配一个独立的 UDP 端口。** 会话 {A,B} 有自己的
`[R]:port_AB`，A 与 B 都把对方的 endpoint 设成它。R 在该 socket 上按源地址二选一：
来自 A 的转给 B，来自 B 的转给 A——无歧义，且 A 可以同时中继任意多个 peer
（每个 peer 一个目标端口）。

推论：`Register` 必须有 `RegisterAck` 回带分配到的端口；客户端在拿到 ack 之前
不知道该把 endpoint 设成什么。**不要**设计成"固定端口 4196 直接转发"——那样
每个节点同时只能中继一条连接，而这个限制会在用户最需要中继的时候（多个难连的
peer）暴露。

### C-2：内核 WG 一个 peer 只有一个 endpoint ⇒ 中继期间无法"顺便"探测直连

`wg` 的每个 peer 只有一个 endpoint 字段。中继期间要试直连，只能把 endpoint 临时改成
直连候选；若直连不成，这段时间中继路径也是断的。也就是说**"边中继边探测直连"在
内核 WG 上做不到**（Tailscale 能做是因为它用用户态 WG，可以同时对多个地址发 disco
探测；我们在 M4 引入 gotatun 后才有这个可能）。

因此"直连升级"的策略只能在两种里选，**建议按下面这条落地**：

- **（推荐）事件驱动升级**：只在"有理由相信情况变了"时才中断中继去试直连——
  会合层送来新的直连候选（LAN 公告 / 阶段 D 的转介 / 阶段 E 的 DHT）、本机地址变化、
  或用户显式 `hextet up` / 重启 daemon。没有新证据就不动，中继保持稳定。
- （备选）定时盲试：每 N 分钟中断中继试一轮直连。代价是每 N 分钟有几秒不通；
  若采用，N 必须可配且默认足够大（≥10min），并在文档里写明这个代价。

事件驱动的缺点要如实写进文档：**对端搬到了一个可直连的网络、而本机毫无察觉**时，
不会自动升级——需要等一次 LAN/gossip/DHT 事件，或用户手动重启 daemon。
阶段 D 的 gossip 落地后这个缺口基本被填上（对端换地址会主动广播）。

### Task 11: core — 中继帧协议

**Files:** Create `crates/core/src/relay.rs`；Modify `lib.rs`、`error.rs`、`network.rs`
（`derive_relay_key`）、`defaults.rs`（`DEFAULT_RELAY_PORT: u16 = 4196`）

线格式（96 字节定长，大端；写进 `docs/protocol/relay.md`）：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | magic `HXTR` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind：1=Register, 2=RegisterAck, 3=Unregister |
| 6 | 2 | `session_port`（RegisterAck 里是 R 分配的端口；其余为 0） |
| 8 | 8 | seq = Unix 秒（抗重放） |
| 16 | 32 | `self_pubkey` |
| 48 | 32 | `peer_pubkey` |
| 80 | 16 | `HMAC-SHA256(relay_key, bytes[0..80])` 截断左 16 字节 |

```rust
pub const RELAY_MAGIC: [u8; 4] = *b"HXTR";
pub const RELAY_FRAME_LEN: usize = 96;
pub enum RelayKind { Register, RegisterAck, Unregister }
pub struct RelayFrame {
    pub kind: RelayKind,
    pub session_port: u16,
    pub seq: u64,
    pub self_key: NodePublicKey,
    pub peer_key: NodePublicKey,
}
impl RelayFrame {
    pub fn encode(&self, relay_key: &[u8; 32]) -> Vec<u8>;
    pub fn decode(bytes: &[u8], relay_key: &[u8; 32]) -> Result<Self, RelayError>;
    /// 无序会话键：两端算出同一个值。
    pub fn session_key(&self) -> [[u8; 32]; 2];
}
pub fn is_relay_frame(bytes: &[u8]) -> bool;   // 首 4 字节 == RELAY_MAGIC
// network.rs
pub fn derive_relay_key(key: &NetworkKey) -> [u8; 32];   // expand("relay")
```

**关键判据（必须有测试钉住）：** 中继端口上收到的数据报**不以 `HXTR` 开头就是要
转发的 WireGuard 包**。这条判据安全，因为 WireGuard 报文首 4 字节是小端 u32 的
消息类型 1..=4，即 `01 00 00 00`..`04 00 00 00`，与 ASCII `HXTR`
（`48 58 54 52`）不可能相同。测试要显式构造这 4 种首部并断言 `!is_relay_frame`。

**行为契约:** `self_key == peer_key` 非法（`RelayError::SelfPair`）；
`|seq − now| > 300s` 由调用方判定（协议层只解析）；`session_key()` 对
(A,B) 与 (B,A) 返回同一个数组（按字节序排序）。

**测试清单:** 往返（三种 kind）、逐字节翻转全拒绝、错密钥拒绝、长度不对拒绝、
`self_key == peer_key` 拒绝、`session_key` 交换律、WireGuard 首部不被误认、
`frozen_wire_vector`、任意字节不 panic 的 proptest。

### Task 12: engine — 中继转发器（服务端）

**Files:** Create `crates/engine/src/relay_server.rs`

架构（按 C-1 的结论）：

```
控制 socket（[::]:4196）              每会话一个 socket（[::]:0，端口由内核分配）
  收 Register(self,peer) from X  →      转发任务：
    key = session_key                    select {
    若无会话：bind 新 socket             更新地址的 mpsc → 记下 A/B 的当前地址
              spawn 转发任务             socket.recv_from → 源地址是 A 就发给 B，
    把 X 记成该会话的一侧地址                                是 B 就发给 A，
    回 RegisterAck{ session_port }                            都不是就丢
  收 Unregister → 关掉会话             }
  周期 prune → TTL 内没再 Register 的会话关掉（drop 发送端，任务自然退出）
```

```rust
pub const SESSION_TTL: Duration = Duration::from_secs(180);
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(30);  // 客户端续期节奏
pub const MAX_SESSIONS: usize = 256;

pub enum RelayPolicy { AnyMember, Allowlist(Vec<[u8; 32]>) }
pub async fn serve(control: UdpSocket, relay_key: [u8; 32], policy: RelayPolicy)
    -> std::io::Result<()>;
```

**行为契约:**
1. 只有 MAC 合法、`|seq − now| ≤ 300s`、且策略允许的 `Register` 才能建/续会话；
   其余**静默丢弃**。
2. 会话两侧地址都还不知道时不转发任何东西（只有一侧注册过 = 半开会话）。
3. 每个会话独占一个 UDP 端口；`RegisterAck` 回带该端口。同一会话的第二次
   `Register`（另一侧、或续期）返回**同一个**端口。
4. 一侧换了地址（换前缀）→ 它的下一次 `Register` 把该侧地址更新掉，转发继续。
5. 会话数达 `MAX_SESSIONS` 时先 prune，仍满则拒绝新会话（返回不了 ack，客户端会
   超时并如实报告"中继不可用"）；**不驱逐已有会话**。
6. 每个会话有转发速率上限（默认按 20 Mbps 等价包速，可配）——中继是别人的机器，
   必须有上限。超限时丢包并按会话记一条 warn（**不要**每包都记）。
7. 绝不解析被转发数据报的内容；日志里绝不出现载荷。

**测试清单:** 纯逻辑（会话表：建/续/双侧/TTL/满/注销/换地址）用单测；
`serve` 用 loopback 端到端测：两个 socket 各自 Register 拿到同一个端口 →
互发任意字节 → 收到对方原样的载荷；半开会话不转发；坏 MAC 不建会话；
限速触发后丢包但会话不断。

### Task 13: core/config — 中继配置

- `[node] relay = false`：本机是否**提供**中继服务（默认关，spec D5 要求显式启用）。
- `[node] relay_port = 4196`、`[node] relay_allow = ["<pubkey>", ...]`（可选白名单）。
- `[[peers]] relay = true`：标记该 peer 可以**当中继用**；它的 `endpoints` 提供中继
  地址，端口用 `[[peers]] relay_port`（默认 4196）。
- 校验：`relay = true` 的 peer 必须有至少一个 `endpoints`（中继地址未知等于没配），
  否则 `ConfigError::RelayWithoutEndpoint`。
- 测试：解析默认值、显式值、缺 endpoints 报错、多个 relay peer 的顺序保留。

### Task 14: engine — 中继客户端与升级策略

**Files:** Create `crates/engine/src/relay_client.rs`；Modify `fsm.rs`、`candidates.rs`

- `relay_client::register(peer_relay_addr, self_key, peer_key, relay_key) -> Result<SocketAddrV6>`：
  发 `Register`、等 `RegisterAck`（700ms 重发、5s 超时），返回 `[R]:session_port`。
  之后每 `REGISTER_INTERVAL` 续一次（续期同时兼作 R 侧的 TTL 刷新与本机地址变化的通报）。
- `CandidateSources` 新增 `relay: Option<SocketAddrV6>`，**排在所有直连来源之后**
  （最后手段）。于是 FSM 的轮换天然会试到它，不需要新状态。
- FSM 需要知道"当前 endpoint 是不是中继"以便对外报告与实施升级策略：
  给 `PeerFsm` 加 `relay_endpoint: Option<SocketAddrV6>` 与查询方法
  `is_relayed(&self) -> bool`（`Connected{endpoint} == relay_endpoint`）。
- **升级策略按 C-2 的推荐做事件驱动**：`set_candidates` 时若出现新的**直连**候选
  且当前 `is_relayed()`，则立刻指向那个新候选（这正是现有 `set_candidates` 契约 4
  的行为，只需确保 relay 候选不被当成"新候选"触发自己）。
- 进入中继时 `info!` 一条含原因（"直连候选轮换 N 轮未握手，改走中继 via X"），
  离开时 `info!` 一条（"已升级为直连"）。**绝不静默降级。**

### Task 15: daemon 接线 + status

- `[node] relay = true` → 绑 `relay_port` 并 spawn `relay_server::serve`。
- 对每个"有 relay peer 可用"的 peer：直连候选轮换满 `RELAY_AFTER_ROUNDS = 2` 轮
  仍未握手 → 走 `relay_client::register` 拿到中继 endpoint → 塞进
  `CandidateSources::relay` → 重算候选。
- 状态文件：`punch_state` 新增 `"relayed"`，`PeerState` 新增
  `relay_via: Option<String>`（中继节点公钥 base64）与 `endpoint_source` 的
  `"relay"` 取值；`STATE_VERSION` +1。
- `status` 人类输出把 relayed 显示成 `relayed via <name>`，`--json` 带 `relay_via`。

### Task 16: E2E + 文档

`scripts/netns-e2e-relay.sh`：三个 netns（A、B、R）接在同一个 veth bridge 上，
nftables 在 A、B 上互相 drop（放行与 R 的双向），R 开 `[node] relay = true`。
断言：
1. A/B 在 40s 内 `punch_state == "relayed"` 且 overlay 双向 ping 通；
2. `status` 人类输出含 `relayed via r`；
3. R 上的会话数为 1（一对），且 A/B 看到的中继端口相同且**不是** 4196；
4. 解除 A↔B 阻断并触发一次事件（LAN 公告或重启 A 的 daemon）后升级为
   `connected` 且 `endpoint_source != "relay"`；
5. 关掉 R 之后 A/B 如实变成 `probing`（不假装还连着）。

文档：`docs/protocol/relay.md`（线格式 + C-1/C-2 两条约束的结论 + 安全性表格）、
`docs/guides/relay.md`（中继是你自己的机器、默认关闭、怎么确认自己没被中继、
带宽与隐私影响）、`ADR-0003`（记录 C-1 的每对一端口设计与 C-2 的事件驱动升级策略，
以及"为什么不做自动选中继"）。


# 阶段 D：隧道内 gossip（endpoint 更新 + peer 转介 + 成员）

### Task 17: ADR-0004 — 用签名 UDP 报文而不是 QUIC

spec §3 D4 写的是"控制面走隧道内 QUIC(quinn)"。**建议偏离**并写进 ADR，理由：
① 隧道内已由 WireGuard 认证加密，QUIC 的 TLS 层在此是重复；
② gossip 条目本身带 ed25519 签名 + 单调 seq，是幂等的小状态同步，不需要流、
不需要拥塞控制、不需要连接生命周期；
③ 引入 quinn 就引入 rustls 与 crypto provider 选择（spec §13 已列为风险项：
aws-lc-rs 交叉编译坑），对 OpenWrt/Android 目标是实打实的成本；
④ 报文小于 MTU 时"发三次、幂等接收"比重传逻辑更简单也更可测。
代价与再评估条件也要写清：若未来需要传大对象（成员全量快照 > 1 KB），
再引入 QUIC 或自己做分片，届时用新 ADR 覆盖本决策。

### Task 18–22（规格要点）

- **条目模型**（`crates/core/src/gossip.rs`，纯逻辑）：
  `Entry::Endpoint { node, endpoints, port, seq, sig }`、
  `Entry::Member { node, name, site, seq, sig, issued_by, invite_id }`、
  `Entry::Revocation { node, seq, sig, issued_by }`。
  签名覆盖"除 sig 外的规范编码"；`seq` 单调，收敛规则 LWW（同 node 取 seq 大者，
  seq 相同取字节序小者以保证确定性）。
- **`GossipStore`**：`merge(entry) -> MergeOutcome { Applied, Stale, Invalid }`，
  必须是幂等的、可测的纯逻辑；表大小有界（每 node 各类型只留最新一条）。
- **传输**：`[node] gossip_port = 4197`，只监听 **overlay 地址**（隧道内），
  隧道外收到的包直接丢（源地址不在网络 /48 内 → 丢）。周期 30s 与"变化即发"两条路径。
- **peer 转介**：收到某 node 的 `Endpoint` 条目 → 喂给阶段 B 建好的
  `discovered` 通道（`LanUpdate` 泛化为 `DiscoveredEndpoints { source: Source, .. }`，
  `Source::{Lan, Gossip, Dht}`，`endpoint_source` 随之返回 `"gossip"`）。
- **成员/吊销**：`Member` 条目让 daemon 在**运行时**新增 peer（无需改配置文件），
  `Revocation` 立刻从 WG 设备移除该 peer 并拒绝其后续条目；两者都要落盘到
  `<state_dir>/members.json`（原子写，格式与端点缓存同风格）。
- **invite 闭环**：`Member` 条目带 `invite_id`；引导节点验证 invite 签名与未用过的
  `invite_id` 后签发 `Member` 条目，gossip 全网 → 这才是"一条命令入网"的完成态。
- **E2E**：`scripts/netns-e2e-gossip.sh`——三节点，A 与 B 都只与 R 有 endpoint 知识，
  A、B 同时换前缀后靠 R 的转介互相恢复（<15s）；另一场景：新节点 join 后经
  gossip 自动出现在第三个节点的 `status` 里。

---

# 阶段 E：DHT/pkarr 会合

### Task 23–27（规格要点）

- **crate 选择**：`mainline`（Mainline DHT 客户端）+ AEAD 用 `chacha20poly1305`。
  **锁定精确版本**并全部封装在新 crate `crates/discovery`（spec §10 已规划该 crate；
  隔离"API 快速 break"风险，见 spec §13）。引入前先跑 `cargo deny check` 确认许可与
  RUSTSEC 干净，并在计划报告里贴输出。
- **记录格式**（`docs/protocol/dht-record.md`）：
  `key = HMAC-SHA256(HKDF(network_key,"dht-record"), node_pubkey)[..20]`（DHT infohash 20 字节）；
  `value = AEAD_ChaCha20Poly1305(key=HKDF(network_key,"dht-record"), nonce=随机12B,
  plaintext=CBOR/JSON{endpoints, port, epoch, seq})`。外人既定位不到记录也读不懂内容。
- **粗粒度 epoch**：`epoch = unix_secs / 3600`，保护作息隐私（spec §5）。
- **发布节奏**：启动即发、地址变化即发、之后每 ~55min 重发（BEP44 的 2h 过期前）。
- **节点表持久化**：`<state_dir>/dht-nodes.json`，bootstrap 仅首次冷启动用。
- **诚实边界**：Mainline 是 IPv4 网络 → **控制面弱依赖 IPv4 出站 UDP**，
  数据面仍纯 IPv6。中国网络下可能被干扰 → 文档指向兜底链 ⑥⑦。
- **测试**：本地 mainline testnet（crate 自带）而非真实 DHT；
  加密/派生全部纯逻辑单测；E2E 双端同时换前缀经 DHT 恢复。

---

# 阶段 F：工程规范补齐（spec §11 的执行机制）

### Task 28: CONTRIBUTING + PR 模板

`CONTRIBUTING.md`：构建、测试分层（单测/属性/netns E2E）、commit 规范、
"每个改行为的 PR 必须同步 docs 与 CHANGELOG"、Linux-only 代码的交叉 target 检查命令。
`.github/pull_request_template.md`：文档同步、CHANGELOG、测试、E2E 影响四项 checklist。

### Task 29: CI — 文档同步路径规则 + macOS check

- 新 job `docs-sync`：用 `git diff --name-only origin/main...HEAD` 判断——
  改了 `crates/core/src/addr*` 未改 `docs/protocol/addressing.md`、
  改了 `crates/core/src/probe*` 未改 `docs/protocol/doctor-probe.md`、
  改了 `crates/core/src/{beacon,relay,gossip}*` 未改对应协议文档 → **警告**（不 fail，
  避免纯重构被卡；用 `::warning` 注解让人在 PR 页面看得见）。
- 新 job `check-macos`（`macos-latest`）：`cargo check --workspace --all-targets` +
  `cargo test -p hextet-core -p hextet-engine`。理由：非 Linux 的 `stub`/`daemon` 占位
  代码目前**只在开发机上编译**，CI 里根本没覆盖；一次改动漏改桩函数签名要等到有人在
  macOS 上构建才发现。

### Task 30: fuzz 目标（spec §12）

**已落地的一半（stable 工具链）**：`probe::ProbePacket::decode` 与
`beacon::Beacon::decode` 各有一条 proptest「任意字节输入不 panic」，
且 beacon 另有一条「头部合法、尾部随机」的变体，专门把随机字节压到长度自洽检查与
MAC 校验那条路径上。这是 CI 上常开的第一道防线，成本为零。

**仍待做**：`fuzz/`（cargo-fuzz，需要 nightly）覆盖所有从网络解析的格式，
新增格式时同步加目标（`relay::RelayFrame::decode`、`gossip::Entry`、DHT 记录解密）。
CI 里跑短时（60s/目标）作为 smoke，长时留给手动或定时任务。
引入 nightly 工具链前先确认 `cargo-deny` 与缓存策略不受影响。

---

## 风险与缓解（M3 特有）

| 风险 | 缓解 |
|---|---|
| 组播在容器/CI 环境行为诡异（join 失败、hop limit 被吃） | `serve` 对单接口 join 失败只 warn；E2E 用 veth 直连最小拓扑；失败时抓包 dump |
| LAN beacon 被同网恶意设备重放，撑住幽灵候选 | MAC + 单调 seq + ±300s 窗口 + TTL；候选表有界；最坏后果只是浪费一个候选位 |
| 中继带宽被滥用（别人的机器） | 按源地址限速 + 会话数上限 + 默认关闭 + 白名单可选 |
| 中继让"无服务器"承诺看起来打折 | 文档与 UI 永远显式标 relayed 及原因；中继只能是本网络成员节点 |
| gossip 偏离 spec 的 QUIC 决策 | ADR-0004 写清理由与再评估条件 |
| mainline/pkarr API 变动 | 锁版本 + 全部封装在 `crates/discovery` |
| M3 体量大，一次做完风险高 | 六个阶段各自可发布；A/B 无平台依赖先落地，E 风险最高放最后 |

## 完成标准（整个 M3）

- `cargo xtask ci` 全绿；`cargo xtask e2e all` 在 Linux 上全绿
  （static/dynamic/doctor/lan/relay/gossip）。
- spec §8 M3 三条验收全部有**自动化脚本**证明（不接受手动截图）。
- 文档：`docs/protocol/` 下 invite/lan-discovery/relay/gossip/dht-record 齐备；
  `docs/guides/` 下 joining/relay 齐备；ADR-0002..0004 齐备；CHANGELOG 逐条对应。
- README 的 Status 行更新为 `M3 complete`。
