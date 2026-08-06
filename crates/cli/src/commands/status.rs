//! `hextet status`：peer 连接状态（M1 仅 Linux）。

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[cfg(target_os = "linux")]
use hextet_wg::WgBackend as _;

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

/// 一行 peer 状态（供表格与 `--json` 复用）。
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
}

/// Run the status command.
pub fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("M1 仅支持 Linux");
    }

    #[cfg(target_os = "linux")]
    {
        let (cfg, _id) = super::load_config_and_identity(&args.config)?;
        let backend = hextet_wg::kernel::KernelBackend;
        let statuses = backend.status(&cfg.node.interface)?;
        let now = SystemTime::now();
        let rows: Vec<StatusRow> = statuses
            .iter()
            .map(|s| {
                let peer = cfg
                    .peers
                    .iter()
                    .find(|p| p.public_key.wg_public_bytes() == s.wg_public);
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
                }
            })
            .collect();
        if args.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else {
            println!(
                "{:<12} {:<28} {:<32} {:>10} {:>8} {:>8}  state",
                "peer", "address", "endpoint", "handshake", "rx", "tx"
            );
            for r in &rows {
                println!(
                    "{:<12} {:<28} {:<32} {:>10} {:>8} {:>8}  {}",
                    r.peer,
                    r.address,
                    r.endpoint.clone().unwrap_or_default(),
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
