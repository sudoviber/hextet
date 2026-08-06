//! `hextet doctor`：判定本机 IPv6 入站可达性（协议见 docs/protocol/doctor-probe.md）。

use std::net::{SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use hextet_core::config::Config;
use hextet_core::network::derive_probe_key;

/// Arguments for the doctor command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 请哪个 peer 回探（配置里只有一个 peer 时可省略）
    #[arg(long)]
    pub peer: Option<String>,
    /// 直接指定对端探针地址，形如 `[2001:db8::b]:4194`（优先于 --peer）
    #[arg(long)]
    pub probe_endpoint: Option<String>,
    /// 等待回包的秒数
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
    /// 前台运行探针响应器，供对端探测（daemon 已在跑时不需要）
    #[arg(long)]
    pub serve: bool,
}

/// 解析要探测的对端探针地址。
///
/// 优先级：`--probe-endpoint` → peer 当前的内核 endpoint（Linux，best-effort）
/// → peer 配置里的第一个 endpoint。端口一律用本机 `[node] probe_port`
/// （假设全网用同一个探针端口；不一致时用 `--probe-endpoint` 覆盖）。
fn resolve_target(cfg: &Config, args: &Args) -> anyhow::Result<SocketAddrV6> {
    if let Some(raw) = &args.probe_endpoint {
        return match raw.parse::<SocketAddr>() {
            Ok(SocketAddr::V6(v6)) => Ok(v6),
            Ok(SocketAddr::V4(_)) => {
                bail!("--probe-endpoint {raw} 是 IPv4 地址；hextet 是 IPv6-only 的")
            }
            Err(_) => bail!("--probe-endpoint {raw} 不是合法的 `[IPv6]:端口`"),
        };
    }

    if cfg.peers.is_empty() {
        bail!(
            "配置里没有任何 peer，无法请对端回探；\
             用 --probe-endpoint '[对端IPv6]:{}' 手动指定",
            cfg.node.probe_port
        );
    }
    let peer = match &args.peer {
        Some(name) => cfg
            .peers
            .iter()
            .find(|p| &p.name == name)
            .with_context(|| format!("配置里没有名为 {name} 的 peer"))?,
        None if cfg.peers.len() == 1 => &cfg.peers[0],
        None => bail!(
            "配置里有 {} 个 peer，用 --peer <名字> 指定请谁回探",
            cfg.peers.len()
        ),
    };

    #[allow(unused_mut)]
    let mut ip = None;
    // 内核当前记录的 endpoint 比配置更新（对端可能已经 roaming 过）
    #[cfg(target_os = "linux")]
    {
        use hextet_wg::WgBackend as _;
        let backend = hextet_wg::kernel::KernelBackend;
        if let Ok(statuses) = backend.status(&cfg.node.interface) {
            let want = peer.public_key.wg_public_bytes();
            ip = statuses
                .iter()
                .find(|s| s.wg_public == want)
                .and_then(|s| match s.endpoint {
                    Some(SocketAddr::V6(v6)) => Some(*v6.ip()),
                    _ => None,
                });
        }
    }
    let ip = ip.or_else(|| peer.endpoints.first().map(|e| *e.ip()));
    let Some(ip) = ip else {
        bail!(
            "peer {} 没有可用的探针地址：配置里没写 endpoint，内核也还没学到；\
             用 --probe-endpoint '[对端IPv6]:{}' 手动指定",
            peer.name,
            cfg.node.probe_port
        );
    };
    Ok(SocketAddrV6::new(ip, cfg.node.probe_port, 0, 0))
}

#[derive(serde::Serialize)]
struct DoctorReport {
    reachability: hextet_core::doctor::Reachability,
    target: String,
    evidence: hextet_core::doctor::ProbeEvidence,
    global_addresses: Vec<String>,
}

/// Run the doctor command.
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let probe_key = derive_probe_key(&cfg.network_key);
    let rt = tokio::runtime::Runtime::new()?;

    if args.serve {
        let bind = SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, cfg.node.probe_port, 0, 0);
        println!("探针响应器监听 {bind}（Ctrl-C 退出）");
        return rt.block_on(async move {
            let socket = tokio::net::UdpSocket::bind(bind)
                .await
                .with_context(|| format!("绑定探针端口 {}", cfg.node.probe_port))?;
            hextet_engine::probe_responder::serve(socket, probe_key)
                .await
                .context("探针响应器退出")
        });
    }

    let target = resolve_target(&cfg, &args)?;
    let outcome = rt.block_on(async {
        // 排除 hextet 自己的接口：它上面的 overlay 地址是 ULA，不是公网 endpoint
        let global = hextet_platform::list_global_ipv6(Some(&cfg.node.interface))
            .await
            .context("枚举本机公网 IPv6 地址")?;
        hextet_engine::doctor_client::probe_peer(
            target,
            &probe_key,
            Duration::from_secs(args.timeout),
            global,
        )
        .await
        .context("执行探针交换")
    })?;

    if args.json {
        let report = DoctorReport {
            reachability: outcome.reachability,
            target: outcome.target.to_string(),
            evidence: outcome.evidence,
            global_addresses: outcome
                .global_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("探针对端   {}", outcome.target);
    println!(
        "公网 IPv6  {}",
        if outcome.global_addresses.is_empty() {
            "（无）".to_string()
        } else {
            outcome
                .global_addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "已请求回包 {}",
        if outcome.evidence.solicited_ok {
            "到达"
        } else {
            "未到达"
        }
    );
    println!(
        "未请求入站 {}",
        if outcome.evidence.unsolicited_ok {
            "到达"
        } else {
            "未到达"
        }
    );
    println!("结论       {}", outcome.reachability.as_str());
    println!();
    match outcome.reachability {
        hextet_core::doctor::Reachability::Open => {
            println!("入站开放：本机可被动可达，打洞与裸监听都成立。")
        }
        hextet_core::doctor::Reachability::Stateful => println!(
            "状态防火墙（住宅 CPE / 光猫 IPv6 SPI 的常态）：\n\
             打洞成立（双向同时发包即可），裸入站监听不成立。这是正常且够用的状态。"
        ),
        hextet_core::doctor::Reachability::Blocked => println!(
            "拿不到任何回包。三种可能，请逐一排除：\n\
             1. 对端没在跑 hextet daemon（或没跑 `hextet doctor --serve`）；\n\
             2. 两侧网络密钥不一致（校验失败的探针包会被静默丢弃）；\n\
             3. 本机出站 UDP 或对端入站被拦。\n\
             换一个对端再试一次能区分 1/2 与 3。"
        ),
        hextet_core::doctor::Reachability::NoIpv6 => println!(
            "本机没有可用的公网 IPv6（GUA）。hextet 依赖双端各自有 GUA，\n\
             先解决这个：检查 `ip -6 addr`、光猫/路由器的 IPv6 与 PD 配置。"
        ),
    }
    println!("详细指引（含中国光猫 IPv6 SPI 关闭教程）：docs/guides/doctor.md");
    Ok(())
}
