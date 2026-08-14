//! `hextet join`：用 invite token 加入既有网络（协议规范：docs/protocol/invite.md）。
//!
//! 编排逻辑已下沉到 `hextet_core::bootstrap::join_network`（CLI 与 FFI 共用），
//! 这里只负责把 clap 参数映射过去、把结果渲染成人类可读或 JSON 输出。

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use hextet_core::bootstrap;

/// Arguments for the join command.
#[derive(clap::Args)]
pub struct Args {
    /// invite token（`hxi1.` 开头的单行字符串，来自对方的 `hextet invite new`）
    pub token: String,
    /// 节点密钥文件：已存在则复用，不存在则生成
    #[arg(long, default_value = "node.key")]
    pub key_file: PathBuf,
    /// 配置输出路径
    #[arg(long, default_value = "hextet.toml")]
    pub out: PathBuf,
    /// 本机 WireGuard 监听端口（缺省用 token 里的网络约定端口）
    #[arg(long)]
    pub listen_port: Option<u16>,
    /// daemon 的状态目录（端点缓存与运行时状态文件）
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// 打印出来的 `peer add` 命令里建议给本节点起的名字
    #[arg(long, default_value = "new-node")]
    pub name: String,
    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// `--json` 输出结构。
#[derive(serde::Serialize)]
struct JoinReport {
    network_name: String,
    prefix: String,
    public_key: String,
    address: String,
    site: String,
    config: String,
    key_file: String,
    peers: Vec<String>,
    peer_add_command: String,
}

/// Run the join command.
pub fn run(args: Args) -> anyhow::Result<()> {
    // `--key-file`/`--out` 原样透传（完整路径），跨目录密钥不做文件名/目录拆分。
    let opts = bootstrap::JoinOptions {
        name: &args.name,
        listen_port: args.listen_port,
        state_dir: args.state_dir.as_deref(),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let outcome = bootstrap::join_network(&args.token, &args.key_file, &args.out, now, &opts)?;

    if args.json {
        let report = JoinReport {
            network_name: outcome.network_name,
            prefix: outcome.prefix,
            public_key: outcome.public_key,
            address: outcome.node_address,
            site: outcome.site,
            config: args.out.display().to_string(),
            key_file: args.key_file.display().to_string(),
            peers: outcome.bootstrap_peers,
            peer_add_command: outcome.peer_add_command,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "joined   {} （prefix {}）",
        outcome.network_name, outcome.prefix
    );
    println!("node     {}  {}", outcome.node_address, outcome.public_key);
    println!("config   {}", args.out.display());
    println!("key-file {}", args.key_file.display());
    for (name, endpoints) in outcome
        .bootstrap_peers
        .iter()
        .zip(&outcome.bootstrap_endpoints)
    {
        println!("peer     {name:12} endpoints {endpoints:?}");
    }
    println!();
    println!("还差一步：引导节点也要知道本节点的公钥（WireGuard 是双向认证的）。");
    println!("在**引导节点**上执行：");
    println!("  {}", outcome.peer_add_command);
    println!("然后两侧 `hextet up`（或重启 `hextet daemon`）即可。");
    Ok(())
}
