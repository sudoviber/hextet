//! `hextet init`
//!
//! 编排逻辑已下沉到 `hextet_core::bootstrap::init_network`（CLI 与 FFI 共用）。
//! CLI 侧保持原语义：密钥文件必须先由 `hextet keygen` 生成（`require_existing_key = true`）。

use std::path::PathBuf;

use hextet_core::bootstrap;

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
    /// daemon 的状态目录（端点缓存与运行时状态文件）；缺省用 /var/lib/hextet
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// 加入既有网络：提供其 network key（缺省则新建网络）
    #[arg(long)]
    pub network_key: Option<String>,
    /// 配置输出路径
    #[arg(long, default_value = "hextet.toml")]
    pub out: PathBuf,
}

/// Run the init command.
pub fn run(args: Args) -> anyhow::Result<()> {
    // `--key-file`/`--out` 原样透传（完整路径），跨目录密钥不做文件名/目录拆分。
    let opts = bootstrap::InitOptions {
        listen_port: args.listen_port,
        state_dir: args.state_dir.as_deref(),
        require_existing_key: true,
    };

    bootstrap::init_network(
        &args.name,
        &args.key_file,
        &args.out,
        args.network_key.as_deref(),
        &opts,
    )?;
    println!("wrote {}", args.out.display());
    Ok(())
}
