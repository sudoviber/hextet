use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hextet", version, about = "IPv6-only serverless mesh VPN")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成节点身份密钥
    Keygen(hextet_cli::commands::keygen::Args),
    /// 初始化节点配置（新建网络或以 --network-key 加入既有网络）
    Init(hextet_cli::commands::init::Args),
    /// 查看派生的网络前缀、本节点与 peers 的 overlay 地址
    Inspect(hextet_cli::commands::inspect::Args),
    /// 建接口、配置 WireGuard 与地址、拉起（M1 仅 Linux）
    Up(hextet_cli::commands::up::Args),
    /// 删除接口
    Down(hextet_cli::commands::down::Args),
    /// 查看 peer 连接状态（M1 仅 Linux）
    Status(hextet_cli::commands::status::Args),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => hextet_cli::commands::keygen::run(a),
        Cmd::Init(a) => hextet_cli::commands::init::run(a),
        Cmd::Inspect(a) => hextet_cli::commands::inspect::run(a),
        Cmd::Up(a) => hextet_cli::commands::up::run(a),
        Cmd::Down(a) => hextet_cli::commands::down::run(a),
        Cmd::Status(a) => hextet_cli::commands::status::run(a),
    }
}
