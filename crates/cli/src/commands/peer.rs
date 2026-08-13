//! `hextet peer`：维护配置里的 peer 列表。

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use hextet_core::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use hextet_core::config::{Config, render_peer_block};
use hextet_core::identity::NodePublicKey;
use hextet_core::route::Ipv6Route;

/// Arguments for the peer command.
#[derive(clap::Args)]
pub struct Args {
    /// 子命令
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// peer 子命令。
#[derive(clap::Subcommand)]
pub enum Cmd {
    /// 往配置末尾追加一个 peer（原有注释与格式原样保留）
    Add(AddArgs),
}

/// Arguments for `hextet peer add`.
#[derive(clap::Args)]
pub struct AddArgs {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// peer 名（本地元数据，`status` 里用它指代这个 peer）
    #[arg(long)]
    pub name: String,
    /// peer 的 ed25519 公钥 base64（对方 `hextet keygen` / `hextet join` 的输出）
    #[arg(long)]
    pub public_key: String,
    /// peer 的 IPv6 endpoint，可重复；不给则等会合层（LAN/DHT/转介）去发现
    #[arg(long)]
    pub endpoint: Vec<String>,
    /// 这个 peer 背后可达的 IPv6 子网（`前缀/长度`），可重复；连上后会把流量送进隧道
    #[arg(long)]
    pub route: Vec<String>,
}

/// Run the peer command.
pub fn run(args: Args) -> anyhow::Result<()> {
    match args.cmd {
        Cmd::Add(a) => add(a),
    }
}

fn add(args: AddArgs) -> anyhow::Result<()> {
    let (cfg, id) = super::load_config_and_identity(&args.config)?;
    let public_key = NodePublicKey::from_base64(&args.public_key)
        .context("--public-key 不是合法的 ed25519 公钥 base64")?;
    let endpoints = args
        .endpoint
        .iter()
        .map(|s| super::parse_endpoint(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let routes = args
        .route
        .iter()
        .map(|s| {
            s.parse::<Ipv6Route>().with_context(|| {
                format!("--route {s} 不是合法的 IPv6 子网（形如 2001:db8:abcd::/64）")
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if public_key == id.public() {
        bail!("这是本节点自己的公钥；peer 列表里只放**别的**节点");
    }
    if let Some(existing) = cfg.peers.iter().find(|p| p.public_key == public_key) {
        bail!("该公钥已经是 peer「{}」了（配置未改动）", existing.name);
    }
    // name 是人类用的主键：重名会让 status 的输出无法辨认谁是谁
    if cfg.peers.iter().any(|p| p.name == args.name) {
        bail!(
            "已存在名为「{}」的 peer，请换个 --name（配置未改动）",
            args.name
        );
    }

    let new_addr = derive_node_addr(cfg.prefix, &public_key)?;
    let mut all: Vec<(String, NodeAddr)> = cfg
        .peers
        .iter()
        .map(|p| (p.name.clone(), p.addr.clone()))
        .collect();
    all.push(("<self>".into(), derive_node_addr(cfg.prefix, &id.public())?));
    all.push((args.name.clone(), new_addr.clone()));
    check_subnet_collisions(&all).context(
        "新 peer 与既有节点派生出了相同的 subnet id（概率约 1/65536）。\
         让对方重新 `hextet keygen` 换一把节点密钥即可",
    )?;

    // 追加而不是重写：用户配置里的注释、字段顺序、自己写的说明必须原样保留。
    // 写坏了就把原文写回去——绝不留下一个解析不了的配置文件。
    let original = std::fs::read_to_string(&args.config)
        .with_context(|| format!("读取 {}", args.config.display()))?;
    let block = render_peer_block(&args.name, &public_key, &endpoints, &routes);
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&args.config)
            .with_context(|| format!("打开 {} 追加", args.config.display()))?;
        f.write_all(block.as_bytes())
            .with_context(|| format!("写入 {}", args.config.display()))?;
    }
    if let Err(e) = Config::load(&args.config, Some(&id.public())) {
        std::fs::write(&args.config, &original).with_context(|| {
            format!(
                "追加 peer 后配置无法解析（{e}），且恢复 {} 原文也失败",
                args.config.display()
            )
        })?;
        return Err(anyhow::Error::from(e).context(format!(
            "追加 peer 后配置无法解析，已恢复 {} 原文",
            args.config.display()
        )));
    }

    println!("added peer {} {}", args.name, new_addr.address);
    if endpoints.is_empty() {
        println!("（没给 endpoint：靠 LAN 发现或对方主动打洞连上；也可以随时手工补上）");
    }
    if !routes.is_empty() {
        println!(
            "已声明 site-to-site 子网：{}（连上后流量会送进隧道；注意网关节点要开 IPv6 转发）",
            routes
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("下一步：`hextet up` 应用配置，或重启 `hextet daemon` 让它接管这个 peer。");
    Ok(())
}
