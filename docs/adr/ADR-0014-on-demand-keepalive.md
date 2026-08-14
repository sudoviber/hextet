# ADR-0014 按需连接模式的 keepalive 分级：`[node] keepalive` 配置开关

- **状态**：已接受（文档 + 决策；实现随 M7 切片 E 落地）
- **日期**：2026-08-13
- **相关**：`docs/superpowers/specs/2026-08-06-hextet-design.md` §5「keepalive 分级」/ §8 M7 行、
  `crates/core/src/defaults.rs`（`DEFAULT_KEEPALIVE_SECS`）、
  `crates/core/src/config.rs`（`RawNode`/`NodeSettings`/`Config::load`/`render_template`）、
  `crates/engine/src/spec.rs`（`build_device_spec`）、
  `crates/engine/src/daemon.rs`（`Ctx` + gossip 准入路径）

## 背景

spec §5 定义了 keepalive 分级策略：**常电节点 25s**；探测到**纯 IPv6 路径**（防火墙 state
≥2min，RFC 6092）后**自动放宽至 ~110s**；**移动设备按需连接**。§8 的 M7 行进一步要求
「按需连接模式：打洞 <1s，无常驻 keepalive 省电」。

实现前，`persistent_keepalive` 在两处**硬编码为 25**：

- `crates/engine/src/spec.rs` 的 `build_device_spec`——每个配置 peer 都写死 `Some(25)`；
- `crates/engine/src/daemon.rs` 的 gossip 准入路径——运行时新准入成员也写死 `Some(25)`。

移动端要「无常驻 keepalive」就必须把这两个硬编码换成可配置值，且让 `0` 表达「关闭」。

## 决策

### D1：`[node] keepalive` 是 `u16`，默认 25，`0` = 关闭（`persistent_keepalive = None`）

- 新增 `[node] keepalive` 配置项（`u16`，默认 `defaults::DEFAULT_KEEPALIVE_SECS = 25`），与既有
  `[node]` 可选字段（`relay`/`dht`/`lan_discovery`/`http_addr` 等）同一条
  `RawNode → NodeSettings → Config::load → render_template` 链路落地。
- 语义：`keepalive = 0` 时 `build_device_spec` 产出 `persistent_keepalive: None`（即
  `(cfg.node.keepalive != 0).then_some(cfg.node.keepalive)`），WireGuard 不再发常驻
  keepalive 包——移动端按需连接模式在空闲时彻底静默省电。
- 默认路径**行为不变**：缺省仍是 25，所有常电节点体验与现在完全一致。

### D2：gossip 准入路径不再硬编码 25，改走 `Ctx.keepalive`

- `Ctx` 增加 `keepalive: u16`（从 `cfg.node.keepalive` 填充，与既有 `listen_port` 等
  「节点派生字段进 `Ctx`」的模式一致）。
- daemon 里 gossip 准入新成员的那处 `persistent_keepalive: Some(25)` 改为
  `(ctx.keepalive != 0).then_some(ctx.keepalive)`，与配置 peer 的 keepalive 一致，避免
  运行时准入的成员在移动端被悄悄塞回 25s keepalive（那会抵消省电效果）。

### D3：~110s 自动分级**延期**，本片只交付配置开关

- spec §5 的「纯 IPv6 路径自动放宽 ~110s」需要**运行时路径探测**（区分「中间盒 state
  ≥2min」与「NAT 映射短寿命」）+ **真机验证**，二者都不在本切片范围内。
- 本片只交付**分级策略最底层的配置原语**——`keepalive` 由「常量」变「用户可调的标量」。
  常电 25s（缺省）与移动端 0（关闭）由用户/App 显式选择；「探测后自动放宽」是后续片在
  这条配置之上叠加的**自动**行为，不改变本片的配置语义。

### D4：诚实边界——「打洞 <1s」是本片无法验证的运行时目标

- 「打洞 <1s」是 M7 的运行时验收目标，依赖打洞状态机、会合层与真机蜂窝网络，**不是**
  一个配置开关能保证的。本片交付的只是「无常驻 keepalive」这一**前提条件**（省电那半句），
  不声称、也不验证「打洞 <1s」（性能那半句）。
- 「纯 IPv6 路径自动放宽 ~110s」同理：需要路径探测 + 真机，本片不假装实现。

## 备选与理由

- **keepalive 用 `Option<u16>` 而非 `u16` 直通**：`NodeSettings` 层用 `u16`（0 = 关闭）而非
  `Option`，因为「0 = None」是 WireGuard 生态的既有惯例（`persistent_keepalive_interval=0`
  即关闭），在 TOML 里写 `keepalive = 0` 比 `keepalive = none` 更直观；到
  `DeviceSpec` 层才映射成 `Option<u16>`（`PeerSpec.persistent_keepalive` 的类型要求）。
- **在 `spec.rs` 里再引入一个 `KEEPALIVE_SECS` 常量**：被否。常量的唯一消费者就是
  `build_device_spec`，而值现在来自配置，保留常量只会制造「两个真相源」。
- **gossip 准入路径保留硬编码 25**：被否。移动端节点若靠 gossip 动态准入成员，硬编码 25
  会让「0 = 省电」在运行时被偷偷覆盖，省电承诺落空。
- **本片直接实现 ~110s 自动分级**：被否。没有路径探测与真机数据就放宽 keepalive，等于在
  没有证据的情况下假设所有 IPv6 路径都满足 RFC 6092 长 state——双 CMCC/中间盒回收映射时
  会静默断连，比「保守 25s」更糟。

## 后果

- 常电节点默认路径零行为变化（keepalive 25 处处一致），`cargo test --workspace` 既有
  `cli/tests/spec.rs` 的 `Some(25)` 断言继续成立。
- 移动端省电是**用户/App 的显式选择**（`keepalive = 0`），不是自动探测——诚实：hextet 第一
  片不做「它自己也不确定路径质量」的自动放宽。
- 配置模板多一行注释示例 `# keepalive = 25 ...`，文档与配置语义同步（spec §11 纪律）。

## 重新评估触发条件

1. **路径探测落地**（能可靠区分「纯 IPv6 长 state 路径」与「中间盒短寿命映射」）→ 在
   `keepalive` 之上叠加「~110s 自动放宽」，另立 ADR 记录探测算法与真机验证矩阵。
2. **打洞性能达标验证**（M7 真机「打洞 <1s」）→ 回填本 ADR 的 D4「未验证」项。
3. **需要按 peer 而非按节点分级 keepalive**（不同 peer 路径质量不同）→ **已落地**：
   `[[peers]] keepalive` 每 peer 覆盖（`spec::peer_keepalive_secs`，`None` 回落节点默认），
   手动把纯 IPv6 路径对端放宽到 ~110s；自动探测放宽仍是剩余工作。

## 未能验证（落地前须确认）

- **「打洞 <1s」**：运行时目标，需 M7 真机 + 蜂窝网络验证，本片（纯配置层）无法验证。
- **「纯 IPv6 路径自动放宽 ~110s」**：延期，需路径探测 + 真机；本片明确未实现。
- **`keepalive = 0` 在真实中间盒下的被动可达退化程度**：理论预期「映射可能被回收、被动
  可达变差」，但具体退化窗口（分钟级？小时级？）取决于运营商/光猫，需真机 E2E 矩阵记录。
