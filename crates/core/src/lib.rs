//! hextet 核心逻辑：身份、地址派生、配置模型。
//!
//! 本 crate 是纯逻辑层（无 I/O 主循环、无平台依赖），
//! 为 daemon/CLI/移动端 FFI（M7）共同复用。
#![deny(missing_docs)]

pub mod defaults;
pub mod error;
pub mod identity;
