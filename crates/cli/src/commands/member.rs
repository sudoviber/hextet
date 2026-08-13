//! `hextet member`：签发成员准入/吊销的 gossip 条目（协议规范：docs/protocol/gossip.md）。
//!
//! 这是阶段 D「成员/吊销」的签发侧：管理员（或授权节点）用本节点身份给某个 node 签一条
//! `Member`（准入）或 `Revocation`（吊销）条目，然后广播进隧道内 gossip 网络。收到条目的
//! daemon 据此在**运行时**新增/移除 peer，无需改配置文件——这才是「一条命令入网」在
//! N≥3 网络里的完成态（`docs/guides/joining.md` 里说的「双向接纳」之外，第三方节点也能
//! 自动学到新成员）。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use hextet_core::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use hextet_core::gossip::Entry;
use hextet_core::identity::NodePublicKey;

/// Arguments for the member command.
#[derive(clap::Args)]
pub struct Args {
    /// 子命令
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// member 子命令。
#[derive(clap::Subcommand)]
pub enum Cmd {
    /// 准入一个成员：签名 `Member` 条目并广播进 gossip 网络
    Add(AddArgs),
    /// 吊销一个成员：签名 `Revocation` 条目并广播进 gossip 网络
    Revoke(RevokeArgs),
}

/// Arguments for `hextet member add`.
#[derive(clap::Args)]
pub struct AddArgs {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 成员名（人类可读，`status` 里指代这个节点）
    #[arg(long)]
    pub name: String,
    /// 成员（新节点）的 ed25519 公钥 base64
    #[arg(long)]
    pub public_key: String,
}

/// Arguments for `hextet member revoke`.
#[derive(clap::Args)]
pub struct RevokeArgs {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 被吊销节点的 ed25519 公钥 base64
    #[arg(long)]
    pub public_key: String,
}

/// Run the member command.
pub fn run(args: Args) -> anyhow::Result<()> {
    match args.cmd {
        Cmd::Add(a) => add(a),
        Cmd::Revoke(r) => revoke(r),
    }
}

/// 把一条条目广播给配置里所有 peer 的 overlay 地址（gossip 端口）。
///
/// 广播是尽力而为的：某个 peer 还没连上、端口不对都无所谓，gossip 的周期重发
/// 与「收到即转播」会兜底。它**只发不读**——本机 daemon 也会收到自己的广播吗？
/// 不会：gossip 只监听 overlay 地址，而这里发的是**对端**的 overlay 地址，本机
/// 收不到自己发出去的包。
async fn broadcast_to_peers(
    bytes: &[u8],
    peers: &[Ipv6Addr],
    gossip_port: u16,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        .await
        .context("绑定 gossip 广播 socket 失败")?;
    for addr in peers {
        let target = SocketAddrV6::new(*addr, gossip_port, 0, 0);
        socket
            .send_to(bytes, SocketAddr::V6(target))
            .await
            .with_context(|| format!("向 {target} 广播 gossip 条目失败"))?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn add(args: AddArgs) -> anyhow::Result<()> {
    let (cfg, id) = super::load_config_and_identity(&args.config)?;
    let public_key = NodePublicKey::from_base64(&args.public_key)
        .context("--public-key 不是合法的 ed25519 公钥 base64")?;

    if public_key == id.public() {
        bail!("这是本节点自己的公钥；成员准入的对象必须是**别的**节点");
    }
    if cfg.peers.iter().any(|p| p.public_key == public_key) {
        bail!(
            "该公钥已经在配置里是 peer「{}」了；无需再发 member 条目",
            {
                cfg.peers
                    .iter()
                    .find(|p| p.public_key == public_key)
                    .map(|p| p.name.clone())
                    .unwrap_or_default()
            }
        );
    }

    // 派生其地址与 site subnet id，并做碰撞预检（与 peer add 同一套规则）
    let new_addr = derive_node_addr(cfg.prefix, &public_key)?;
    let mut all: Vec<(String, NodeAddr)> = cfg
        .peers
        .iter()
        .map(|p| (p.name.clone(), p.addr.clone()))
        .collect();
    all.push(("<self>".into(), derive_node_addr(cfg.prefix, &id.public())?));
    all.push((args.name.clone(), new_addr.clone()));
    check_subnet_collisions(&all).context(
        "新成员与既有节点派生出了相同的 subnet id（概率约 1/65536）。\
         让对方重新 `hextet keygen` 换一把节点密钥即可",
    )?;

    // invite_id 目前是随机的：真正的「一次性」强制要等引导节点验证 invite 签名与
    // 未用过的 invite_id（阶段 D 的 invite 闭环）；这里先带上一个标识供未来审计与去重。
    let mut invite_id = [0u8; 16];
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(&mut invite_id);

    let entry = Entry::sign_member(
        &id,
        public_key.clone(),
        args.name.clone(),
        new_addr.subnet_id,
        now_unix(),
        invite_id,
    )?;
    let bytes = entry.encode()?;

    let targets: Vec<Ipv6Addr> = cfg.peers.iter().map(|p| p.addr.address).collect();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(broadcast_to_peers(&bytes, &targets, cfg.node.gossip_port))?;

    println!(
        "admitted member {} {} (广播到 {} 个 peer)",
        args.name,
        new_addr.address,
        targets.len()
    );
    println!("收到该条目的节点会在运行时自动加入此 peer，无需改配置文件。");
    Ok(())
}

fn revoke(args: RevokeArgs) -> anyhow::Result<()> {
    let (cfg, id) = super::load_config_and_identity(&args.config)?;
    let public_key = NodePublicKey::from_base64(&args.public_key)
        .context("--public-key 不是合法的 ed25519 公钥 base64")?;

    if public_key == id.public() {
        bail!("这是本节点自己的公钥；吊销的对象必须是**别的**节点");
    }

    let entry = Entry::sign_revocation(&id, public_key, now_unix())?;
    let bytes = entry.encode()?;

    let targets: Vec<Ipv6Addr> = cfg.peers.iter().map(|p| p.addr.address).collect();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(broadcast_to_peers(&bytes, &targets, cfg.node.gossip_port))?;

    println!(
        "revoked {} (广播到 {} 个 peer)",
        args.public_key,
        targets.len()
    );
    println!("收到该条目的节点会立即从数据面移除该 peer 并拒绝其后续条目。");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::identity::NodeIdentity;

    /// 签发 → 编码 → 解码，确认 `member add` 核心路径的产物能被网络另一端正确解析。
    /// （广播是 I/O，这里只测可判定的签名/编解码部分，与 `hextet_core::gossip` 的
    /// 单测互补——那边测编解码本身，这里测「命令用到的签发路径」。）
    #[test]
    fn signed_member_entry_roundtrips() {
        let admin = NodeIdentity::from_seed(&[1u8; 32]);
        let node = NodeIdentity::from_seed(&[2u8; 32]);
        let entry =
            Entry::sign_member(&admin, node.public(), "nas".into(), 7, 1000, [0xaa; 16]).unwrap();
        let back = Entry::decode(&entry.encode().unwrap()).unwrap();
        assert_eq!(back, entry);
        assert!(back.is_valid());
    }

    #[test]
    fn signed_revocation_entry_roundtrips() {
        let admin = NodeIdentity::from_seed(&[1u8; 32]);
        let node = NodeIdentity::from_seed(&[2u8; 32]);
        let entry = Entry::sign_revocation(&admin, node.public(), 1000).unwrap();
        let back = Entry::decode(&entry.encode().unwrap()).unwrap();
        assert_eq!(back, entry);
        assert!(back.is_valid());
    }

    /// member 条目必须由「别人」签发：用 node 自己的身份签自己的准入应被 `is_valid` 拒绝。
    #[test]
    fn self_issued_member_is_invalid() {
        let node = NodeIdentity::from_seed(&[2u8; 32]);
        let entry =
            Entry::sign_member(&node, node.public(), "self".into(), 7, 1000, [0xaa; 16]).unwrap();
        assert!(!entry.is_valid());
    }
}
