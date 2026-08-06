//! `hextet inspect`

use std::path::PathBuf;

use hextet_core::addr::derive_node_addr;
use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

/// Machine-readable inspect report.
#[derive(serde::Serialize)]
pub struct InspectReport {
    /// Network information.
    pub network: NetworkReport,
    /// This node.
    pub node: NodeReport,
    /// List of peers.
    pub peers: Vec<PeerReport>,
}

/// Network information in the report.
#[derive(serde::Serialize)]
pub struct NetworkReport {
    /// Network name.
    pub name: String,
    /// Network prefix (ULA).
    pub prefix: String,
}

/// Node information in the report.
#[derive(serde::Serialize)]
pub struct NodeReport {
    /// Node's public key (base64).
    pub public_key: String,
    /// Node's overlay address.
    pub address: String,
    /// Node's site prefix with subnet size.
    pub site: String,
}

/// Peer information in the report.
#[derive(serde::Serialize)]
pub struct PeerReport {
    /// Peer name.
    pub name: String,
    /// Peer's public key (base64).
    pub public_key: String,
    /// Peer's overlay address.
    pub address: String,
    /// Peer's endpoints (if any).
    pub endpoints: Vec<String>,
}

/// Arguments for the inspect command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// Run the inspect command.
pub fn run(args: Args) -> anyhow::Result<()> {
    // 先读配置拿 key_file，再载身份，最后带 own_pubkey 重新校验
    let cfg = Config::load(&args.config, None)?;
    let key_path = if cfg.node.key_file.is_relative() {
        args.config
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(&cfg.node.key_file)
    } else {
        cfg.node.key_file.clone()
    };
    let id = NodeIdentity::load(&key_path)?;
    let cfg = Config::load(&args.config, Some(&id.public()))?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    let report = InspectReport {
        network: NetworkReport {
            name: cfg.network_name.clone(),
            prefix: cfg.prefix.to_string(),
        },
        node: NodeReport {
            public_key: id.public().to_base64(),
            address: own.address.to_string(),
            site: format!("{}/64", own.site),
        },
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerReport {
                name: p.name.clone(),
                public_key: p.public_key.to_base64(),
                address: p.addr.address.to_string(),
                endpoints: p.endpoints.iter().map(|e| e.to_string()).collect(),
            })
            .collect(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "network  {}  prefix {}",
            report.network.name, report.network.prefix
        );
        println!(
            "node     {}  {}",
            report.node.address, report.node.public_key
        );
        for p in &report.peers {
            println!(
                "peer {:12} {}  endpoints {:?}",
                p.name, p.address, p.endpoints
            );
        }
    }
    Ok(())
}
