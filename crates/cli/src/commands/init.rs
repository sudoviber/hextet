//! `hextet init`

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context, bail};
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

    // hextet.toml 含网络密钥，权限须与 keygen 的密钥文件一致（0600）。用
    // create_new 原子性地拒绝覆盖已存在文件，避免 exists() 检查与写入之间的
    // TOCTOU 竞态（参考 hextet_core::identity::NodeIdentity::save）。
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&args.out).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} 已存在", args.out.display())
        } else {
            anyhow::Error::from(e).context(format!("写入 {} 失败", args.out.display()))
        }
    })?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("写入 {} 失败", args.out.display()))?;
    println!("wrote {}", args.out.display());
    Ok(())
}
