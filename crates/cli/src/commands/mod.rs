//! CLI command implementations

use std::path::Path;

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

pub mod daemon;
pub mod down;
pub mod init;
pub mod inspect;
pub mod keygen;
pub mod status;
pub mod up;

/// 读配置 + 载身份（实现见 [`hextet_core::config::load_config_and_identity`]）。
///
/// M2 起 daemon 也要做同样的事，逻辑因此上移到 core；这里保留薄封装，
/// 让既有子命令的调用点不必改动。
pub fn load_config_and_identity(config_path: &Path) -> anyhow::Result<(Config, NodeIdentity)> {
    Ok(hextet_core::config::load_config_and_identity(config_path)?)
}
