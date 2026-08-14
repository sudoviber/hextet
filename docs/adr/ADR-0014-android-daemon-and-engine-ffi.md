# ADR-0014：Android daemon 架构——跳过 platform 地址/路由、fd 注入时序、engine-FFI 控制面

- **状态**：已接受（文档 + 决策；实现随 M7 切片 D/E 落地）
- **日期**：2026-08-13
- **相关**：`docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M7 / §9 Android 行、
  `docs/superpowers/plans/2026-08-13-m7-android.md` 切片 B/D/E、
  `docs/adr/ADR-0012-android-ffi-boundary.md`（FFI 边界、runtime 归属决策 6）、
  `docs/adr/ADR-0013-gotatun-android-data-plane.md`（gotatun 后端、D4 fd 注入、D5 同步/异步桥）、
  `crates/engine/src/daemon.rs`（`run`/`spawn_on`/`DaemonHandle`/`run_async`）、
  `crates/engine/src/backend.rs`（`platform_default()`，仅 linux/macos）、
  `crates/wg-userspace/src/lib.rs`（`GotatunBackend`，已含 `set_tun_fd`）、
  `crates/platform/src/lib.rs`（非 linux/macos 走 `stub` 返回 `Unsupported`）、
  `crates/core-ffi/src/api.rs`（现有 FFI 面，只覆盖 core 纯逻辑）

## 背景

M7 切片 C-impl 已落地 gotatun Android 后端（`GotatunBackend` + `set_tun_fd` + UAPI 同步桥），
切片 B 补完已落地 `DaemonHandle`（`spawn_on` 返回 stop/wait 控制句柄）。但要让 Android 上
`hextet daemon` 真正跑起来，还有三个**架构分叉**没有被任何 ADR 裁定，直接写代码会埋坑：

1. **`run_async` 里的 platform 调用在 Android 上会失败**。`setup_interface`（配 overlay
   地址）是**致命**调用（`.context(...)?`），而 `crates/platform` 在 Android 上是 `stub`
   （返回 `PlatformError::Unsupported`）。但 Android 的 `VpnService.Builder` 已经做了
   `addAddress`/`addRoute`——地址与路由由系统 VpnService 接管，daemon **不该**再经 platform
   配一遍。这是「platform 抽象」与「VpnService 托管」的根本语义冲突。
2. **`platform_default()` 没有 Android 分支**。`crates/engine/src/backend.rs` 只对 linux/macos
   定义，Android 上编译 `daemon` 会因缺 `platform_default` 失败。且 engine 对
   `hextet-wg-userspace` 的依赖目前是 `[target.'cfg(target_os = "macos")']` 门控，Android
   需要加对应 target 依赖。
3. **fd 注入时序 + engine-FFI 面缺位**。`GotatunBackend::set_tun_fd(fd)` 必须在 `apply()`
   之前调用，而 `apply()` 发生在 `run_async` 内部（`platform_default()` → `apply`）。Kotlin
   侧 `VpnService.Builder.establish()` 拿到 fd 后，必须先把 fd 交给后端、再启动 daemon——这
   需要一条「预注入 fd 再 spawn」的路径，以及把 `spawn_on`/`set_tun_fd`/`DaemonHandle::stop`
   暴露成 UniFFI 的 **engine-FFI 面**（现有 `core-ffi` 只覆盖 core 纯逻辑，不碰 engine）。

本 ADR 裁定这三件事，为切片 D（VpnService 壳 + JNI fd 接线）与切片 E（按需连接）铺平。

## 决策

### D1：Android 上 daemon 跳过 platform 地址/路由，由 VpnService 托管

- **`setup_interface` / `add_route` 在 Android 上不走 platform**。`run_async` 里这两处调用
  用 `#[cfg(not(target_os = "android"))]` 门控掉；Android 上 overlay 地址与 `/48` 路由由
  `VpnService.Builder.addAddress(overlay_addr/128).addRoute(overlay/48)` 配置（切片 D 的
  Kotlin 侧负责），daemon 只做「数据面 WG 握手 + 打洞 + 会合」。
- **`list_global_ipv6` / `list_multicast_interfaces` / `watch_ipv6_addresses` 在 Android 上**
  ：VpnService 场景下本机「公网 IPv6」是蜂窝/底层接口的地址，与 WG 数据面的 endpoint 语义
  分离；且 VpnService 生命周期由系统管理、无「前缀重拨换地址」的 netlink 事件。第一片
  **诚实降级**：`list_global_ipv6` 在 Android 上返回空（打洞候选仍由会合层 LAN/DHT/gossip/
  配置提供），`list_multicast_interfaces` 返回空（Android 无 LAN 组播语义，会合第 ① 层降级），
  `watch_ipv6_addresses` 降级为「无事件」——这些都已走 daemon 既有的「这一路不可用就 warn +
  跳过」路径，不致命。**这继承 ADR-0013 D4 的诚实度**：VpnService 下的 endpoint 枚举/监听
  是后续片（E 按需连接）重新审视的独立项，本片不假装支持。
- **代价（诚实）**：Android 第一片的打洞候选**不**包含本机公网 IPv6（不主动发「我在这」），
  手机定位本就是「主动发起方 + 按需连接」（spec §2「不承诺被动可达」），出站打洞不需要
  本机地址做候选。被动可达（对端先找到手机）留到切片 E。

### D2：`platform_default()` 加 Android 分支返回 `GotatunBackend`

- `crates/engine/src/backend.rs` 加 `#[cfg(target_os = "android")]` 分支，返回
  `hextet_wg_userspace::GotatunBackend::new()`。
- `crates/engine/Cargo.toml` 的 `hextet-wg-userspace` 依赖从 `[target.'cfg(target_os = "macos")']`
  扩为 `[target.'cfg(any(target_os = "macos", target_os = "android"))']`（两个平台都用用户态
  后端，仅 Linux 走内核后端）。
- `daemon` 模块的 `#[cfg(any(target_os = "linux", target_os = "macos"))]` 门控扩为
  `#[cfg(any(target_os = "linux", target_os = "macos", target_os = "android"))]`，占位桩只留
  给其余真正未支持的平台（如 iOS）。
- 镜像 boringtun 后端在 macOS 的「共享同一实例」纪律：Android 上 daemon 用
  `Arc<dyn WgBackend + Send + Sync>` 包 `GotatunBackend`（不可 `Clone`，含 `Arc<Runtime>` +
  `pending_fd`）。

### D3：fd 注入时序——预注入再 spawn，engine-FFI 面暴露三条控制入口

- **时序**（Kotlin 侧，切片 D）：`GotatunBackend::new()` → `set_tun_fd(fd)` → `spawn_on(handle, config)`。
  因为 `run_async` 内部 `platform_default()` 会 `new()` 一个新的后端实例，而 `set_tun_fd` 必须
  作用在**同一个**实例上，所以**不能让 daemon 内部自己 `new()` 后端再期望外部注入 fd**。
  裁定：daemon 增加一条「接受外部已注入 fd 的后端实例」的路径——具体做法见 D4。
- **engine-FFI 面**（新，挂在 `crates/core-ffi` 里，还是新 crate？裁定：**新 crate
  `crates/engine-ffi`**）。理由：`core-ffi` 只依赖 `hextet-core`（纯逻辑、无 tokio），
  engine-ffi 要依赖 `hextet-engine`（含 tokio、daemon、gotatun 后端），依赖树与 lint 面
  完全不同；且 ADR-0012 已明确「callback interface / async export 会引入 `unsafe` 胶水，
  需加收窄 `#![allow(unsafe_code)]`」——把这条收窄隔离在独立 crate 里，不污染 `core-ffi`
  的「零 unsafe」承诺。
- **engine-FFI 暴露的三条入口**（同步、无 callback interface 的第一片）：
  1. `create_backend() -> u64`（或等价句柄）：`new()` 一个 `GotatunBackend`，塞进进程内
     注册表，返回句柄 id。
  2. `backend_set_tun_fd(handle, fd: i32)`：把 JNI 传进来的 fd 转 `RawFd`，调
     `set_tun_fd`。（`RawFd` 跨 FFI 映射为 `i32`，ADR-0012 决策 4 的类型映射纪律。）
  3. `spawn_daemon(handle, config_path) -> DaemonHandleFFI`：用**已注入 fd 的那个后端**
     启动 daemon。这里需要 daemon 侧新增「用外部后端实例」的入口（见 D4）。
  4. `stop_daemon(handle)` / `wait_daemon(handle)`：包一层 `DaemonHandle::stop`/`wait`
     （`wait` 是 async，第一片用 `block_on` 或让 Kotlin 侧不 await、只 `stop` 后由
     runtime 收尾——裁定：第一片只暴露 `stop`，`wait` 由 Kotlin 侧持有 runtime 收尾，
     避免跨 FFI 阻塞）。
- **状态回调（status）**：第一片**不做** callback interface。手机 UI 的状态展示走既有的
  HTTP 状态服务（`[node] http_addr`/`http_port`，Android 上监听 loopback）或后续片加
  callback interface（届时按 ADR-0012 决策 5 加收窄 `#![allow(unsafe_code)]`）。

### D4：daemon 增加「用外部后端实例」入口，不改现有 `run`/`spawn_on` 签名

- 现有 `spawn_on(handle, config_path) -> DaemonHandle` 内部 `run_async` 会 `platform_default()`
  `new()` 后端。为支持 fd 预注入，daemon 新增一条**不破坏现有签名**的路径：
  - `run_async` 拆出「后端已就位」后的主体（打洞循环 + 会合 + HTTP），或加一个
    `pub fn spawn_with_backend(handle, config_path, backend: Arc<dyn WgBackend + Send + Sync>)`
    变体，`spawn_on` 成为它的薄封装（`spawn_on` = `spawn_with_backend(..., platform_default())`）。
  - `run_async` 里 `setup_interface`/`add_route` 的 Android 门控（D1）在两条路径下都生效。
- 这样 engine-FFI 的 `spawn_daemon(handle, ...)` 走 `spawn_with_backend`，把 `create_backend()`
  里 `set_tun_fd` 过的那个 `Arc<dyn WgBackend>` 传进去，fd 时序闭环。

### D5：UniFFI 的 `unsafe` 边界——engine-ffi 独立 crate 加收窄 allow

- `crates/engine-ffi` 是独立 `cdylib` crate，`#![allow(unsafe_code)]`（或模块级收窄）+ 顶部
  `# SAFETY` 文档，说明：UniFFI 为跨 FFI 传递 `Arc<dyn WgBackend>` 句柄、`RawFd`、`JoinHandle`
  生成的胶水含 `unsafe`，收窄隔离在本 crate（镜像 `crates/platform/src/macos.rs` 与
  `crates/wg-userspace/src/lib.rs` 的 `wg_tun_name` 先例）。`core-ffi` 保持「零 unsafe」承诺不变。
- **句柄传递**：`Arc<dyn WgBackend>` 无法直接跨 UniFFI（dyn trait 无 Record 映射），裁定用
  **进程内注册表**（`static`/`OnceLock<Mutex<HashMap<u64, Arc<dyn WgBackend>>>>`）+ `u64` 句柄。
  `create_backend()` 返回自增 id，其余入口按 id 取回 `Arc`。这是 FFI 边界处理「不可序列化资源」
  的标准手法，把 `unsafe` 圈在注册表与 id 转换的几行里。

## 与 spec / 既有 ADR 的偏离记录

- **spec §10 项目结构**列的是 `apps/android/`（Kotlin 壳），本 ADR 新增 `crates/engine-ffi`
  （Rust 侧的 engine 控制面 FFI crate）——是结构补全，不是偏离。
- **ADR-0012 决策 6**说「FFI 只暴露同步控制面、无 callback interface」，本 ADR 的 D3/D5 遵守
  此线（第一片只 `create_backend`/`set_tun_fd`/`spawn_daemon`/`stop`，全同步；`wait` 不跨 FFI）。
- **ADR-0012 决策 5**说「callback/async export 会引入 unsafe 胶水，届时加收窄 allow」——本 ADR
  D5 兑现这条预案，把它落在 `engine-ffi` 独立 crate。

## 代价与再评估

- **`platform` 抽象在 Android 上「空转」**：`setup_interface`/`list_global_ipv6`/`watch_*` 在
  Android 上要么跳过、要么返回空，`crates/platform` 的 Android 分支仍是 stub。诚实记录：
  platform 的「接口/地址/路由」抽象与 Android VpnService 托管模型不兼容，VpnService 侧的
  地址/路由是切片 D 的 Kotlin 职责，不在 platform crate 内。若未来要 iOS，也走同一路线
  （NEPacketTunnelProvider 托管，platform 不碰）。
- **fd 注入的「先 create 后 spawn」两步 API** 比「一次 spawn 全包」多一步，但这是 VpnService
  fd 语义的必然：fd 必须先经 `establish()` 拿到、`protect()` 标记，才能交给后端。两步 API
  是忠实表达，不是妥协。
- **`Arc<dyn WgBackend>` 句柄注册表**引入进程内全局状态：生命周期由 Kotlin 侧配对
  `create_backend`/`stop_daemon` 管理；泄漏（Kotlin 忘了停）会导致后端常驻——切片 D 的
  VpnService `onDestroy` 必须无条件 `stop_daemon`。这是 FFI 资源管理的已知代价。

### 重新评估触发条件

1. **需要 callback interface 的 status 推送**（切片 E 或 UI 打磨）→ 按 ADR-0012 决策 5 在
   `engine-ffi` 加收窄 allow，重估 D3 的「第一片无 callback」。
2. **VpnService 下 endpoint 枚举/监听有真实需求**（切片 E 按需连接的被动可达部分）→ 重估
   D1 的「list_global_ipv6 返回空」降级。
3. **`platform` crate 出现 Android 语义**（如果 Android 需要非 VpnService 的 root 直配路径）
   → 重估 D1 的「跳过 platform」。
4. **iOS 落地** → 复用本 ADR 的「VpnService/NEPacketTunnelProvider 托管、platform 不碰、
   engine-ffi 控制面」三件套，另立 ADR。

## 未能验证（落地前须确认）

- **engine-ffi 的 UniFFI 句柄注册表 + `unsafe` 收窄**：本 ADR 只定方案，实现时验证
  `Arc<dyn WgBackend>` 句柄在 UniFFI 下是否真需要 `unsafe`（若 UniFFI 0.32 对 `u64` 句柄 +
  自定义 opaque type 有更优路径，实现时择优）。
- **Kotlin 侧 VpnService 时序**（`establish` → `protect` → JNI fd → `create_backend` →
  `set_tun_fd` → `spawn_daemon`）：属于切片 D，真机验证。
- **`spawn_with_backend` 的重构是否真不改 `run`/`spawn_on` 行为**：实现时以
  `cargo test --workspace` + 既有 netns/单元测试回归确认。
- **Android daemon 的 `watch_ipv6_addresses` 降级是否影响打洞**：第一片诚实接受「无地址
  变化事件」，切片 E 重新评估。

## 后续实现步骤

1. `crates/engine/src/backend.rs`：加 `#[cfg(target_os = "android")]` 分支返回
   `GotatunBackend::new()`。
2. `crates/engine/Cargo.toml`：`hextet-wg-userspace` 依赖扩到 macos+android target。
3. `crates/engine/src/daemon.rs`：`run_async` 里 `setup_interface`/`add_route` 加
   `#[cfg(not(target_os = "android"))]` 门控；`daemon` 模块 cfg 扩到含 android；新增
   `spawn_with_backend`（`spawn_on` 薄封装）。
4. `crates/engine-ffi`（新 cdylib crate）：UniFFI 面 `create_backend`/`backend_set_tun_fd`/
   `spawn_daemon`/`stop_daemon`，句柄注册表 + 收窄 `#![allow(unsafe_code)]`。
5. `cargo check --target aarch64-linux-android -p hextet-engine -p hextet-engine-ffi` +
   生成 Kotlin 绑定（`uniffi-bindgen generate --library ... --language kotlin`）编译验证。
6. 切片 D：`apps/android/` Gradle 工程 + VpnService 壳 + JNI fd 接线，按本 ADR 时序落地。
