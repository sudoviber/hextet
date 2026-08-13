//! `hextet status`：peer 连接状态（内核 WireGuard + daemon 状态文件）。
//!
//! 状态报告组装逻辑（`build_report`）与共享 serde 类型已上移到
//! [`hextet_engine::status`] 与 [`hextet_proto`]，本文件只保留终端的展示层
//! （`daemon_header` 与各列格式化 helper）与命令接线。

use std::path::PathBuf;

use hextet_proto::{DaemonInfo, StatusRow};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use hextet_engine::status::build_report;
#[cfg(not(target_os = "linux"))]
use hextet_engine::status::build_report_from_state;

/// Arguments for the status command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
    /// 交互式表格视图（`q`/`Esc`/`Ctrl-C` 退出）
    #[arg(long)]
    pub tui: bool,
}

/// 人类表格与 TUI 共用的 daemon 存活头部行。
pub(crate) fn daemon_header(daemon: Option<&DaemonInfo>) -> String {
    match daemon {
        Some(d) if d.running => {
            format!("daemon   running（状态更新于 {}s 前）", d.updated_secs_ago)
        }
        Some(d) => format!(
            "daemon   not running（状态文件 {} 停留在 {}s 前）",
            d.state_file, d.updated_secs_ago
        ),
        None => "daemon   not running（无状态文件；动态端点自愈未启用）".to_string(),
    }
}

/// punch 列：走中继时把中继节点名一起显示出来——绝不让用户以为是直连。
pub(crate) fn punch_column(row: &StatusRow) -> String {
    match (&row.punch_state, &row.relay_via) {
        (Some(state), Some(via)) if state == "relayed" => format!("relayed via {via}"),
        (Some(state), _) => state.clone(),
        (None, _) => "-".to_string(),
    }
}

/// handshake 列：距最近握手的秒数（无握手时 `-`）。
pub(crate) fn handshake_column(row: &StatusRow) -> String {
    row.last_handshake_secs
        .map_or_else(|| "-".to_string(), |s| format!("{s}s"))
}

/// routes 列：逗号拼接（无路由时 `-`）。
pub(crate) fn routes_column(row: &StatusRow) -> String {
    if row.routes.is_empty() {
        "-".to_string()
    } else {
        row.routes.join(",")
    }
}

/// Run the status command.
pub fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = args;
        anyhow::bail!("hextet status 仅支持 Linux、macOS 与 Windows");
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let (cfg, _id) = super::load_config_and_identity(&args.config)?;

        if args.tui {
            // TUI（ratatui）三个桌面平台都可编译；macOS/Windows 走 state.json（同 --json）。
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                if args.json {
                    anyhow::bail!(
                        "--tui 与 --json 不能同时使用：TUI 是交互视图，--json 是一次性输出"
                    );
                }
                return super::status_tui::run(&cfg);
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                anyhow::bail!("--tui 仅支持 Linux、macOS 与 Windows");
            }
        }

        // Linux：内核后端（netlink，完整 peer 列表）；macOS/Windows：state.json
        // （跨进程拿不到 gotatun 进程内后端，但 state.json v7 已含完整 WG 统计）。
        #[cfg(target_os = "linux")]
        let report = {
            let backend = super::backend::platform_default();
            build_report(&cfg, &backend, SystemTime::now())?
        };
        #[cfg(not(target_os = "linux"))]
        let report = build_report_from_state(&cfg, SystemTime::now())?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("{}", daemon_header(report.daemon.as_ref()));
            println!(
                "{:<12} {:<28} {:<32} {:<8} {:>4} {:<20} {:>10} {:>8} {:>8}  routes",
                "peer", "address", "endpoint", "source", "lan", "punch", "handshake", "rx", "tx"
            );
            for r in &report.peers {
                println!(
                    "{:<12} {:<28} {:<32} {:<8} {:>4} {:<20} {:>10} {:>8} {:>8}  {}",
                    r.peer,
                    r.address,
                    r.endpoint.clone().unwrap_or_default(),
                    r.endpoint_source.clone().unwrap_or_else(|| "-".to_string()),
                    r.lan_endpoints
                        .map_or_else(|| "-".to_string(), |n| n.to_string()),
                    punch_column(r),
                    handshake_column(r),
                    r.rx_bytes,
                    r.tx_bytes,
                    routes_column(r)
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_header_reflects_running_and_stale() {
        let running = DaemonInfo {
            running: true,
            updated_secs_ago: 3,
            state_file: "/s".into(),
        };
        let running_header = daemon_header(Some(&running));
        assert!(running_header.starts_with("daemon   running"));
        assert!(running_header.contains("3s"));

        let stale = DaemonInfo {
            running: false,
            updated_secs_ago: 100,
            state_file: "/var/lib/hextet/state.json".into(),
        };
        let stale_header = daemon_header(Some(&stale));
        assert!(stale_header.starts_with("daemon   not running"));
        assert!(stale_header.contains("/var/lib/hextet/state.json"));

        assert_eq!(
            daemon_header(None),
            "daemon   not running（无状态文件；动态端点自愈未启用）"
        );
    }

    #[test]
    fn helpers_format_columns() {
        let row = StatusRow {
            peer: "nas".into(),
            address: "fd::2".into(),
            endpoint: Some("[2001:db8::9]:4193".into()),
            last_handshake_secs: Some(42),
            rx_bytes: 0,
            tx_bytes: 0,
            state: "connected".into(),
            endpoint_source: Some("config".into()),
            punch_state: Some("relayed".into()),
            candidates: Some(1),
            candidate_index: Some(0),
            lan_endpoints: None,
            gossip_endpoints: None,
            ddns_endpoints: None,
            relay_via: Some("r".into()),
            routes: vec!["a/64".into(), "b/48".into()],
        };
        assert_eq!(punch_column(&row), "relayed via r");
        assert_eq!(handshake_column(&row), "42s");
        assert_eq!(routes_column(&row), "a/64,b/48");

        // 非中继的 punch 直接显示状态；无 handshake/无 routes 回落到占位符
        let bare = StatusRow {
            punch_state: Some("probing".into()),
            relay_via: None,
            last_handshake_secs: None,
            routes: vec![],
            ..row
        };
        assert_eq!(punch_column(&bare), "probing");
        assert_eq!(handshake_column(&bare), "-");
        assert_eq!(routes_column(&bare), "-");
    }
}
