//! `hextet ddns node`：前台运行一个本地（离线）DDNS 会合 mock，netns E2E 用。
//!
//! 生产 daemon 的 DDNS 会合面向「webhook/Cloudflare 更新 TXT + 公网 DNS 查询」。
//! netns E2E 要求确定性、离线，于是提供这个进程内服务：webhook HTTP 接收端 + DNS
//! TXT 服务器，让测试里的 daemon 经它发布/查询会合记录，走完真实 HTTP + 真实 DNS
//! 的闭环。这与 `hextet dht node`（本地 DHT 会合点）同一纪律。本命令是隐藏的
//! （`hextet --help` 不展示），仅 `scripts/netns-e2e-ddns.sh` 与 CI 使用。

use std::net::Ipv4Addr;

use anyhow::Context as _;

/// Arguments for the `ddns` command.
#[derive(clap::Args)]
pub struct Args {
    /// 子命令
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// `ddns` 子命令。
#[derive(clap::Subcommand)]
pub enum Cmd {
    /// 前台运行一个本地 DDNS mock（阻塞直到 SIGINT/SIGTERM）
    Node(NodeArgs),
}

/// Arguments for `hextet ddns node`.
#[derive(clap::Args)]
pub struct NodeArgs {
    /// 监听 IPv4 地址——须是测试拓扑里可达的具体地址（如网桥地址），不能用 0.0.0.0，
    /// 否则对端无从构造 webhook URL / nameserver 地址
    #[arg(long)]
    pub bind: Ipv4Addr,
    /// webhook HTTP 端口
    #[arg(long)]
    pub http_port: u16,
    /// DNS（UDP）端口
    #[arg(long)]
    pub dns_port: u16,
}

/// Run the ddns command.
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
    // 先起服务再打印就绪：端口被占等构建失败时进程直接以非零码退出，脚本据此立刻
    // 发现，而不是等后面的断言超时。
    let mock = hextet_discovery::ddns::node::LocalDdnsMock::spawn(n.bind, n.http_port, n.dns_port)
        .map_err(anyhow::Error::msg)?;
    tracing::info!(
        bind = %n.bind,
        http_port = n.http_port,
        dns_port = n.dns_port,
        "本地 DDNS mock 已就绪"
    );
    wait_for_shutdown()?;
    drop(mock);
    Ok(())
}

/// 阻塞直到收到 SIGINT/SIGTERM（与 daemon 的收尾语义一致：信号即退出）。
fn wait_for_shutdown() -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    rt.block_on(async {
        #[cfg(unix)]
        let terminate = {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = signal(SignalKind::terminate()).context("注册 SIGTERM handler")?;
            async move { sig.recv().await }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::pin!(terminate);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = &mut terminate => {},
        }
        Ok(())
    })
}
