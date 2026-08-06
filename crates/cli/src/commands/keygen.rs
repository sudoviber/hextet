//! `hextet keygen`

use std::path::PathBuf;

use anyhow::{Context, bail};
use hextet_core::identity::NodeIdentity;

/// Arguments for the keygen command.
#[derive(clap::Args)]
pub struct Args {
    /// 密钥文件输出路径
    #[arg(long, default_value = "node.key")]
    pub out: PathBuf,
    /// 覆盖已存在的文件
    #[arg(long)]
    pub force: bool,
}

/// Run the keygen command.
pub fn run(args: Args) -> anyhow::Result<()> {
    if args.out.exists() {
        if !args.force {
            bail!("{} 已存在（用 --force 覆盖）", args.out.display());
        }
        std::fs::remove_file(&args.out)
            .with_context(|| format!("删除旧密钥 {}", args.out.display()))?;
    }
    let id = NodeIdentity::generate();
    id.save(&args.out)?;
    println!("public-key: {}", id.public().to_base64());
    println!("key-file: {}", args.out.display());
    Ok(())
}
