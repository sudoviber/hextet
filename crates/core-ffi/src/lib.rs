//! hextet 的 Android FFI 边界（M7 第一片）：`hextet-core` 纯逻辑的同步、安全 FFI 面。
//!
//! 本 crate 只依赖 [`hextet_core`]（纯逻辑，无 tokio、无平台依赖），经 UniFFI 把
//! Android 首次启动 onboarding 需要的最小能力暴露给 Kotlin：
//!
//! - 身份生成/反序列化（[`api::generate_identity`] / [`api::identity_public_key`]）
//! - 网络前缀与节点地址派生（[`api::derive_network_prefix`] / [`api::derive_node_address`]）
//! - 配置模板渲染与加载/校验（[`api::render_config`] / [`api::load_config`]）
//!
//! 全部函数**同步**、**无 I/O 主循环**、**无进程假设**。异步 engine（`serve()` 循环、
//! `platform_default()` 后端、`daemon::run`）不在本片范围内，见
//! `docs/adr/ADR-0012-android-ffi-boundary.md`。
//!
//! # `unsafe_code = "deny"` 与 UniFFI（ADR-0012 决策 5 的实证结论）
//!
//! 工作区 `[workspace.lints.rust] unsafe_code = "deny"`，本 crate 因此**不带**任何
//! `#![allow(unsafe_code)]`——这是刻意且经实证的：
//!
//! - 本片 surface 是**纯同步 + record + 扁平错误枚举**，不含 callback interface、不含
//!   async export。实测 `cargo check` 在 deny 下**不加任何 allow 也通过**，即
//!   [`setup_scaffolding!`] 与 `#[uniffi::export]` 展开进本 crate 的胶水**零 `unsafe`**。
//! - FFI 路径里的 `unsafe`（如 `unsafe impl LowerReturn<...> for Result<...>`）位于
//!   `uniffi_core`（第三方、预编译依赖），**不在**本 crate 的 lint 范围内。
//! - 当后续 engine-FFI 片引入 callback interface 或 async export 时，生成胶水**会**把
//!   `unsafe` 展开进本 crate——届时按 ADR-0012 的预案，加一处带 `# SAFETY` 文档的
//!   收窄 `#![allow(unsafe_code)]`（镜像 `crates/platform/src/macos.rs` /
//!   `crates/wg-userspace/src/lib.rs` 的 `wg_tun_name` 先例），并在 ADR 里记录。
//!
//! # 生成 Kotlin 绑定
//!
//! 见 `docs/dev/build.md` 的 "Android FFI (core-ffi)" 一节。简言之（library 模式，从
//! 编译产物里的嵌入元数据生成，无需 .udl）：
//!
//! ```text
//! uniffi-bindgen generate --library target/<triple>/release/libhextet_core_ffi.so \
//!     --language kotlin --out-dir <android-src>/uniffi
//! ```
#![deny(missing_docs)]

pub mod api;
pub mod error;

uniffi::setup_scaffolding!();
