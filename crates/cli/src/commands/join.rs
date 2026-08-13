//! `hextet join`：用 invite token 加入既有网络（协议规范：docs/protocol/invite.md）。

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use hextet_core::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use hextet_core::config::{Config, render_peer_block};
use hextet_core::identity::NodeIdentity;
use hextet_core::invite::Invite;
use hextet_core::network::NetworkPrefix;

/// Arguments for the join command.
#[derive(clap::Args)]
pub struct Args {
    /// invite token（`hxi1.` 开头的单行字符串，来自对方的 `hextet invite new`）
    pub token: String,
    /// 节点密钥文件：已存在则复用，不存在则生成
    #[arg(long, default_value = "node.key")]
    pub key_file: PathBuf,
    /// 配置输出路径
    #[arg(long, default_value = "hextet.toml")]
    pub out: PathBuf,
    /// 本机 WireGuard 监听端口（缺省用 token 里的网络约定端口）
    #[arg(long)]
    pub listen_port: Option<u16>,
    /// daemon 的状态目录（端点缓存与运行时状态文件）
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// 打印出来的 `peer add` 命令里建议给本节点起的名字
    #[arg(long, default_value = "new-node")]
    pub name: String,
    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// `--json` 输出结构。
#[derive(serde::Serialize)]
struct JoinReport {
    network_name: String,
    prefix: String,
    public_key: String,
    address: String,
    site: String,
    config: String,
    key_file: String,
    peers: Vec<String>,
    peer_add_command: String,
}

/// Run the join command.
pub fn run(args: Args) -> anyhow::Result<()> {
    let invite = Invite::decode(args.token.trim()).map_err(|e| {
        anyhow::anyhow!(
            "无法使用这个 invite token：{e}。\
             token 可能被篡改、被聊天软件换行截断，或复制时漏了字符——请让对方重发原文。"
        )
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    invite
        .check_not_expired(now)
        .context("这个 invite token 已过期，请让对方重新签发一张")?;

    // 身份：已有就复用（绝不覆盖用户的密钥），没有就先在内存里生成
    let (id, generated) = if args.key_file.exists() {
        (
            NodeIdentity::load(&args.key_file)
                .with_context(|| format!("读取已有密钥 {}", args.key_file.display()))?,
            false,
        )
    } else {
        (NodeIdentity::generate(), true)
    };

    // 落盘之前先把能算的都算完、能查的都查完：宁可什么都不写，
    // 也不要留半个坏配置在磁盘上
    let prefix = NetworkPrefix::derive(&invite.network_key);
    let own = derive_node_addr(prefix, &id.public())?;
    let mut all: Vec<(String, NodeAddr)> = Vec::with_capacity(invite.bootstrap.len() + 1);
    for b in &invite.bootstrap {
        all.push((b.name.clone(), derive_node_addr(prefix, &b.public_key)?));
    }
    all.push(("<self>".into(), own.clone()));
    check_subnet_collisions(&all).context(
        "本节点与引导节点派生出了相同的 subnet id（概率约 1/65536）。\
         重新跑 `hextet keygen` 换一把节点密钥即可",
    )?;

    if args.out.exists() {
        bail!(
            "{} 已存在。join 不会覆盖既有配置——换个 --out，或先把旧配置移开",
            args.out.display()
        );
    }

    if generated {
        id.save(&args.key_file)
            .with_context(|| format!("写入密钥 {}", args.key_file.display()))?;
    }
    let listen_port = args.listen_port.unwrap_or(invite.listen_port);
    let mut text = Config::render_template(
        &invite.network_name,
        &invite.network_key,
        &args.key_file,
        listen_port,
        args.state_dir.as_deref(),
    );
    for b in &invite.bootstrap {
        text.push_str(&render_peer_block(
            &b.name,
            &b.public_key,
            &b.endpoints,
            &[],
        ));
    }
    if let Err(e) = write_new_0600(&args.out, &text) {
        // 配置没写成，就不要留下一把刚生成的孤儿密钥
        if generated {
            let _ = std::fs::remove_file(&args.key_file);
        }
        return Err(e);
    }

    let peer_add_command = format!(
        "hextet peer add --name {} --public-key '{}' --endpoint '[你的公网IPv6]:{}'",
        args.name,
        id.public().to_base64(),
        listen_port
    );
    if args.json {
        let report = JoinReport {
            network_name: invite.network_name.clone(),
            prefix: prefix.to_string(),
            public_key: id.public().to_base64(),
            address: own.address.to_string(),
            site: format!("{}/64", own.site),
            config: args.out.display().to_string(),
            key_file: args.key_file.display().to_string(),
            peers: invite.bootstrap.iter().map(|b| b.name.clone()).collect(),
            peer_add_command,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("joined   {} （prefix {}）", invite.network_name, prefix);
    println!("node     {}  {}", own.address, id.public().to_base64());
    println!("config   {}", args.out.display());
    println!("key-file {}", args.key_file.display());
    for b in &invite.bootstrap {
        println!(
            "peer     {:12} endpoints {:?}",
            b.name,
            b.endpoints
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }
    println!();
    println!("还差一步：引导节点也要知道本节点的公钥（WireGuard 是双向认证的）。");
    println!("在**引导节点**上执行：");
    println!("  {peer_add_command}");
    println!("然后两侧 `hextet up`（或重启 `hextet daemon`）即可。");
    Ok(())
}

/// 以 0600 新建文件写入；已存在则报错（不覆盖）。
fn write_new_0600(path: &Path, text: &str) -> anyhow::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} 已存在", path.display())
        } else {
            anyhow::Error::from(e).context(format!("写入 {} 失败", path.display()))
        }
    })?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("写入 {} 失败", path.display()))?;
    Ok(())
}
