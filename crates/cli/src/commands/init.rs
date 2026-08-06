//! `hextet init`

use std::path::PathBuf;

use anyhow::bail;
use hextet_core::config::Config;
use hextet_core::network::NetworkKey;

/// Arguments for the init command.
#[derive(clap::Args)]
pub struct Args {
    /// 网络名
    #[arg(long)]
    pub name: String,
    /// 节点密钥文件路径（须已由 keygen 生成）
    #[arg(long, default_value = "node.key")]
    pub key_file: PathBuf,
    /// WireGuard 监听端口
    #[arg(long, default_value_t = hextet_core::defaults::DEFAULT_PORT)]
    pub listen_port: u16,
    /// 加入既有网络：提供其 network key（缺省则新建网络）
    #[arg(long)]
    pub network_key: Option<String>,
    /// 配置输出路径
    #[arg(long, default_value = "hextet.toml")]
    pub out: PathBuf,
}

/// Run the init command.
pub fn run(args: Args) -> anyhow::Result<()> {
    if args.out.exists() {
        bail!("{} 已存在", args.out.display());
    }
    if !args.key_file.exists() {
        bail!(
            "密钥文件 {} 不存在，先运行 hextet keygen",
            args.key_file.display()
        );
    }
    let key = match &args.network_key {
        Some(s) => NetworkKey::from_base64(s)?,
        None => NetworkKey::generate(),
    };
    let text = Config::render_template(&args.name, &key, &args.key_file, args.listen_port);
    std::fs::write(&args.out, text)?;
    println!("wrote {}", args.out.display());
    Ok(())
}
