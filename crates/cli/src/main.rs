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
    /// 签发入网邀请（`hextet invite new`）
    Invite(hextet_cli::commands::invite::Args),
    /// 用 invite token 加入既有网络：生成身份、写好配置
    Join(hextet_cli::commands::join::Args),
    /// 维护 peer 列表（`hextet peer add`）
    Peer(hextet_cli::commands::peer::Args),
    /// 签发成员准入/吊销的 gossip 条目（`hextet member add` / `revoke`）
    Member(hextet_cli::commands::member::Args),
    /// 把 peer 名映射到 overlay IPv6 地址，输出标准 hosts 行（MagicDNS-lite）
    Hosts(hextet_cli::commands::hosts::Args),
    /// 建接口、配置 WireGuard 与地址、拉起（仅 Linux）
    Up(hextet_cli::commands::up::Args),
    /// 删除接口
    Down(hextet_cli::commands::down::Args),
    /// 查看 peer 连接状态（仅 Linux）
    Status(hextet_cli::commands::status::Args),
    /// 前台运行守护进程：地址变化监听 + 候选 endpoint 轮换打洞（仅 Linux）
    Daemon(hextet_cli::commands::daemon::Args),
    /// Windows 服务入口（`hextet service run`，仅 Windows；其他平台用 launchd/systemd）
    Service(hextet_cli::commands::service::Args),
    /// 判定本机 IPv6 入站可达性（open/stateful/blocked），或用 --serve 当回探响应器
    Doctor(hextet_cli::commands::doctor::Args),
    /// 本地（离线）DHT 会合节点（netns E2E 专用，隐藏）
    #[command(hide = true)]
    Dht(hextet_cli::commands::dht::Args),
    /// 本地（离线）DDNS 会合 mock（netns E2E 专用，隐藏）
    #[command(hide = true)]
    Ddns(hextet_cli::commands::ddns::Args),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => hextet_cli::commands::keygen::run(a),
        Cmd::Init(a) => hextet_cli::commands::init::run(a),
        Cmd::Inspect(a) => hextet_cli::commands::inspect::run(a),
        Cmd::Invite(a) => hextet_cli::commands::invite::run(a),
        Cmd::Join(a) => hextet_cli::commands::join::run(a),
        Cmd::Peer(a) => hextet_cli::commands::peer::run(a),
        Cmd::Member(a) => hextet_cli::commands::member::run(a),
        Cmd::Hosts(a) => hextet_cli::commands::hosts::run(a),
        Cmd::Up(a) => hextet_cli::commands::up::run(a),
        Cmd::Down(a) => hextet_cli::commands::down::run(a),
        Cmd::Status(a) => hextet_cli::commands::status::run(a),
        Cmd::Daemon(a) => hextet_cli::commands::daemon::run(a),
        Cmd::Service(a) => hextet_cli::commands::service::run(a),
        Cmd::Doctor(a) => hextet_cli::commands::doctor::run(a),
        Cmd::Dht(a) => hextet_cli::commands::dht::run(a),
        Cmd::Ddns(a) => hextet_cli::commands::ddns::run(a),
    }
}
