//! `hextet daemon`：前台运行守护进程（动态端点自愈）。

use std::path::PathBuf;

/// Arguments for the daemon command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 输出 DEBUG 级日志（默认 INFO）
    #[arg(short, long)]
    pub verbose: bool,
}

/// Run the daemon command.
///
/// 前台阻塞运行，收到 SIGINT/SIGTERM 后退出且**不拆除接口**——拆除是
/// `hextet down` 的职责。M4 的 systemd/procd 单元直接调用本命令。
pub fn run(args: Args) -> anyhow::Result<()> {
    let level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();
    hextet_engine::daemon::run(&args.config)
}
