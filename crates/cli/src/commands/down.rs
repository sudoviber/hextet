//! `hextet down`：删除接口。

use std::path::PathBuf;

/// Arguments for the down command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
}

/// Run the down command.
///
/// 非 Linux 平台没有单独的 bail：`hextet_platform::delete_interface` 自身在
/// 非 Linux 上返回 `PlatformError::Unsupported`，经 `?` 原样传播即可。
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(hextet_platform::delete_interface(&cfg.node.interface))?;
    println!("down: {}", cfg.node.interface);
    Ok(())
}
