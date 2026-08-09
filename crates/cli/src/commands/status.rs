//! `hextet status`：peer 连接状态（内核 WireGuard + daemon 状态文件）。

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// 状态文件多久没更新就认为 daemon 已停。
///
/// daemon 每秒重写一次，10s 容忍度足够覆盖负载抖动，又能让"daemon 挂了"
/// 在 10s 内被 status 如实报出来。
const DAEMON_FRESH_SECS: u64 = 10;

/// 按最近握手时间归类连接状态（<180s = connected）。
pub fn classify(last_handshake: Option<SystemTime>, now: SystemTime) -> &'static str {
    match last_handshake {
        Some(t) => match now.duration_since(t) {
            Ok(d) if d < Duration::from_secs(180) => "connected",
            _ => "stale",
        },
        None => "no-handshake",
    }
}

/// 由状态文件时间戳判断 daemon 是否在跑，以及"多久之前更新的"。
///
/// 时间戳比当前时间新（时钟回拨、或 daemon 与 CLI 看到的时钟有偏差）时按 0 秒前
/// 处理，而不是让 `u64` 减法回绕成一个巨大的数字把 daemon 误报成已停。
pub fn daemon_freshness(updated_unix: u64, now_unix: u64) -> (bool, u64) {
    let secs_ago = now_unix.saturating_sub(updated_unix);
    (secs_ago <= DAEMON_FRESH_SECS, secs_ago)
}

/// Arguments for the status command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// daemon 存活信息（`--json` 的 `daemon` 字段）。
#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct DaemonInfo {
    running: bool,
    updated_secs_ago: u64,
    state_file: String,
}

/// 一行 peer 状态。
#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct StatusRow {
    peer: String,
    address: String,
    endpoint: Option<String>,
    last_handshake_secs: Option<u64>,
    rx_bytes: u64,
    tx_bytes: u64,
    state: &'static str,
    // 以下四项来自 daemon 状态文件，没有 daemon 时为 None
    endpoint_source: Option<String>,
    punch_state: Option<String>,
    candidates: Option<usize>,
    candidate_index: Option<usize>,
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct StatusReport {
    daemon: Option<DaemonInfo>,
    peers: Vec<StatusRow>,
}

/// Run the status command.
pub fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("M2 仅支持 Linux");
    }

    #[cfg(target_os = "linux")]
    {
        use hextet_wg::WgBackend as _;

        let (cfg, _id) = super::load_config_and_identity(&args.config)?;
        let backend = hextet_wg::kernel::KernelBackend;
        let statuses = backend.status(&cfg.node.interface)?;
        let now = SystemTime::now();
        let now_unix = hextet_engine::state::unix_secs(now);

        let state_path = cfg.node.state_dir.join("state.json");
        let engine_state = hextet_engine::state::read(&state_path).ok();
        let daemon = engine_state.as_ref().map(|s| {
            let (running, updated_secs_ago) = daemon_freshness(s.updated_unix, now_unix);
            DaemonInfo {
                running,
                updated_secs_ago,
                state_file: state_path.display().to_string(),
            }
        });

        let rows: Vec<StatusRow> = statuses
            .iter()
            .map(|s| {
                let peer = cfg
                    .peers
                    .iter()
                    .find(|p| p.public_key.wg_public_bytes() == s.wg_public);
                let key_b64 = peer.map(|p| p.public_key.to_base64());
                let engine_peer = engine_state
                    .as_ref()
                    .zip(key_b64.as_ref())
                    .and_then(|(state, key)| state.peers.iter().find(|ps| &ps.public_key == key));
                StatusRow {
                    peer: peer.map_or_else(|| "<unknown>".to_string(), |p| p.name.clone()),
                    address: peer.map_or_else(String::new, |p| p.addr.address.to_string()),
                    endpoint: s.endpoint.map(|e| e.to_string()),
                    last_handshake_secs: s
                        .last_handshake
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs()),
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    state: classify(s.last_handshake, now),
                    endpoint_source: engine_peer.map(|p| p.endpoint_source.clone()),
                    punch_state: engine_peer.map(|p| p.punch_state.clone()),
                    candidates: engine_peer.map(|p| p.candidates),
                    candidate_index: engine_peer.map(|p| p.candidate_index),
                }
            })
            .collect();

        let report = StatusReport {
            daemon,
            peers: rows,
        };

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            match &report.daemon {
                Some(d) if d.running => {
                    println!("daemon   running（状态更新于 {}s 前）", d.updated_secs_ago)
                }
                Some(d) => println!(
                    "daemon   not running（状态文件 {} 停留在 {}s 前）",
                    d.state_file, d.updated_secs_ago
                ),
                None => println!("daemon   not running（无状态文件；动态端点自愈未启用）"),
            }
            println!(
                "{:<12} {:<28} {:<32} {:<8} {:<10} {:>10} {:>8} {:>8}  state",
                "peer", "address", "endpoint", "source", "punch", "handshake", "rx", "tx"
            );
            for r in &report.peers {
                println!(
                    "{:<12} {:<28} {:<32} {:<8} {:<10} {:>10} {:>8} {:>8}  {}",
                    r.peer,
                    r.address,
                    r.endpoint.clone().unwrap_or_default(),
                    r.endpoint_source.clone().unwrap_or_else(|| "-".to_string()),
                    r.punch_state.clone().unwrap_or_else(|| "-".to_string()),
                    r.last_handshake_secs
                        .map_or_else(|| "-".to_string(), |s| format!("{s}s")),
                    r.rx_bytes,
                    r.tx_bytes,
                    r.state
                );
            }
        }
        Ok(())
    }
}
