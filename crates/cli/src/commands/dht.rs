//! `hextet dht node`：前台运行一个本地（离线）Mainline DHT 会合节点，netns E2E 用。
//!
//! 生产 daemon 的 DHT 会合面向真实 Mainline DHT（IPv4 公网出站 UDP）。netns E2E 要求
//! 确定性、离线、秒级收敛，于是提供这个 server-mode、no_bootstrap 的单节点 DHT，让
//! 测试里的 daemon 都 bootstrap 到它、经它发布/查询会合记录。这与 spec M3 阶段 E
//! 「测试：本地 mainline testnet 而非真实 DHT」是同一纪律（见
//! `docs/protocol/dht-record.md` §5）。本命令是隐藏的（`hextet --help` 不展示），
//! 仅 `scripts/netns-e2e-dht.sh` 与 CI 使用。

use std::net::Ipv4Addr;

use anyhow::Context as _;

/// Arguments for the `dht` command.
#[derive(clap::Args)]
pub struct Args {
    /// 子命令
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// `dht` 子命令。
#[derive(clap::Subcommand)]
pub enum Cmd {
    /// 前台运行一个本地 DHT 会合节点（阻塞直到 SIGINT/SIGTERM）
    Node(NodeArgs),
}

/// Arguments for `hextet dht node`.
#[derive(clap::Args)]
pub struct NodeArgs {
    /// 监听 IPv4 地址——须是测试拓扑里可达的具体地址（如网桥地址），不能用 0.0.0.0，
    /// 否则对端无从构造 bootstrap 地址
    #[arg(long)]
    pub bind: Ipv4Addr,
    /// 监听端口
    #[arg(long)]
    pub port: u16,
}

/// Run the dht command.
pub fn run(args: Args) -> anyhow::Result<()> {
    match args.cmd {
        Cmd::Node(n) => run_node(n),
    }
}

fn run_node(n: NodeArgs) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    // 先起节点再打印就绪：构建失败（端口被占等）时进程直接以非零码退出，
    // 脚本据此立刻发现，而不是等后面的断言超时。
    let node =
        hextet_discovery::node::LocalDhtNode::spawn(n.bind, n.port).map_err(anyhow::Error::msg)?;
    tracing::info!(bind = %n.bind, port = n.port, "本地 DHT 会合节点已就绪");
    wait_for_shutdown()?;
    drop(node);
    Ok(())
}

/// 阻塞直到收到 SIGINT/SIGTERM（与 daemon 的收尾语义一致：信号即退出）。
fn wait_for_shutdown() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    rt.block_on(async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("注册 SIGTERM handler")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
        Ok(())
    })
}
