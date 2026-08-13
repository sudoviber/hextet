//! engine 控制面 FFI（UniFFI）：Android `VpnService` 壳的 fd 预注入 + daemon 启停。
//!
//! 与 [`hextet_core_ffi`]（只依赖 `hextet-core` 纯逻辑、零 unsafe）不同，本 crate 依赖
//! [`hextet_engine`]（含 tokio、daemon 主循环、gotatun 后端），把 ADR-0014 D3/D4 的三条
//! 控制入口暴露给 Kotlin：
//!
//! - [`api::create_backend`] → `u64` 句柄（进程内注册表登记一个后端实例）
//! - [`api::backend_set_tun_fd`] → 注入 `VpnService.Builder.establish()` 拿到的 tun fd
//! - [`api::spawn_daemon`] → 用**已注入 fd 的同一后端实例**启动 daemon
//! - [`api::stop_daemon`] → 请求 daemon 停机（非阻塞、幂等）
//!
//! 全部函数同步、无 callback interface、无 async export（ADR-0012 决策 6 的线）。
//!
//! # `unsafe_code` 收窄（ADR-0014 D5）
//!
//! 工作区 `[workspace.lints.rust] unsafe_code = "deny"`。本片 surface 是**同步 + 基本类型
//! （`u64`/`i32`/`String`）+ 扁平错误枚举**，与 `core-ffi` 同形——`core-ffi` 实测在同构
//! surface 下 `setup_scaffolding!` 展开进 crate 的胶水**零 `unsafe`**。但 ADR-0014 D5 的
//! 预案要求：一旦后续片引入 callback interface / async export，UniFFI 为跨 FFI 传递
//! `Arc<dyn WgBackend>` 句柄、`RawFd`、`JoinHandle` 生成的胶水**会**把 `unsafe` 展开进
//! 本 crate。因此这里**预先**在 crate 根加收窄 `#![allow(unsafe_code)]`，把这条收窄隔离
//! 在本 crate 内（镜像 `crates/platform/src/macos.rs` 与 `crates/wg-userspace/src/lib.rs`
//! 的 `wg_tun_name` 先例），`core-ffi` 保持「零 unsafe」承诺不变。
//!
//! # SAFETY
//! 本 crate 自身**不写任何 `unsafe`**。`#![allow(unsafe_code)]` 是 ADR-0014 D5 的**预置
//! 安全阀**：它只在 UniFFI 未来为 callback/async export 生成的胶水里放行 `unsafe`（那类
//! 胶水的 `unsafe` 由 UniFFI 保证正确性），不是本 crate 手写 `unsafe` 的许可证。若当前
//! slice 的胶水实际零 `unsafe`（与 `core-ffi` 同构），本 allow 是无害空操作。
//!
//! # 生成 Kotlin 绑定
//!
//! 与 `core-ffi` 同法（library 模式，从编译产物嵌入元数据生成，无需 .udl）：
//!
//! ```text
//! uniffi-bindgen generate --library target/aarch64-linux-android/release/libhextet_engine_ffi.so \
//!     --language kotlin --out-dir <android-src>/uniffi
//! ```
//!
//! **诚实边界**：本 crate 当前仅 `cargo check --target aarch64-linux-android` 编译验证，
//! 未真机运行（与 `crates/wg-userspace` 的 gotatun 后端同态）。
#![allow(unsafe_code)]
#![deny(missing_docs)]

pub mod api;
pub mod error;

uniffi::setup_scaffolding!();
