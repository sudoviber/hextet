//! CLI command implementations

use std::path::Path;

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

pub mod down;
pub mod init;
pub mod inspect;
pub mod keygen;
pub mod status;
pub mod up;

/// 读配置 → 解析 `key_file` 相对路径 → 载身份 → 带 own_pubkey 重载配置。
///
/// 配置里的 `own_pubkey` 校验（subnet id 碰撞检测）需要先知道本节点公钥，
/// 而公钥又要从 `key_file` 指向的身份文件读出——因此第一次加载不带
/// `own_pubkey`，仅用来拿到 `key_file` 路径，载入身份后再重新加载一次配置。
pub fn load_config_and_identity(config_path: &Path) -> anyhow::Result<(Config, NodeIdentity)> {
    let cfg = Config::load(config_path, None)?;
    let key_path = if cfg.node.key_file.is_relative() {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&cfg.node.key_file)
    } else {
        cfg.node.key_file.clone()
    };
    let id = NodeIdentity::load(&key_path)?;
    let cfg = Config::load(config_path, Some(&id.public()))?;
    Ok((cfg, id))
}
