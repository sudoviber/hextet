//! `hextet invite`：签发入网邀请（协议规范：docs/protocol/invite.md）。

use std::net::{SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use hextet_core::invite::{BootstrapPeer, Invite};

/// Arguments for the invite command.
#[derive(clap::Args)]
pub struct Args {
    /// 子命令
    #[command(subcommand)]
    pub cmd: Cmd,
}

/// invite 子命令。
#[derive(clap::Subcommand)]
pub enum Cmd {
    /// 签发一张邀请：token 打到 stdout，人类提示打到 stderr
    New(NewArgs),
}

/// Arguments for `hextet invite new`.
#[derive(clap::Args)]
pub struct NewArgs {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 引导节点（=本机）在新节点配置里的 peer 名
    #[arg(long, default_value = "bootstrap")]
    pub name: String,
    /// 本机的公网 endpoint（形如 `[2001:db8::1]:4193`），可重复；
    /// 不给时尝试枚举本机公网 IPv6
    #[arg(long)]
    pub endpoint: Vec<String>,
    /// 有效期：`30m` / `24h` / `7d`，或纯数字（秒）
    #[arg(long, default_value = "24h")]
    pub ttl: String,
    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// `--json` 输出结构。
#[derive(serde::Serialize)]
struct InviteReport {
    token: String,
    id: String,
    network_name: String,
    issuer: String,
    issued_unix: u64,
    expires_unix: u64,
    bootstrap: Vec<BootstrapReport>,
}

#[derive(serde::Serialize)]
struct BootstrapReport {
    name: String,
    public_key: String,
    endpoints: Vec<String>,
}

/// 有效期上限：一年。
///
/// 邀请是"引导凭证"而不是长期证书；给它一个上限是为了让"忘了自己发过一张永久 token"
/// 这种事根本不可能发生。
const MAX_TTL_SECS: u64 = 365 * 24 * 3600;

/// 解析有效期：`900`（秒）/ `30m` / `24h` / `7d`。
pub fn parse_ttl(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("有效期不能为空");
    }
    let (digits, mult) = match s.as_bytes()[s.len() - 1] {
        b's' => (&s[..s.len() - 1], 1),
        b'm' => (&s[..s.len() - 1], 60),
        b'h' => (&s[..s.len() - 1], 3600),
        b'd' => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .with_context(|| format!("无法解析有效期 {s}（例：30m / 24h / 7d / 3600）"))?;
    let secs = n
        .checked_mul(mult)
        .with_context(|| format!("有效期 {s} 太大"))?;
    if secs == 0 {
        bail!("有效期必须大于 0");
    }
    if secs > MAX_TTL_SECS {
        bail!("有效期 {s} 超过上限 365d");
    }
    Ok(secs)
}

/// 解析一个命令行给的 endpoint，拒绝 IPv4。
fn parse_endpoint(s: &str) -> anyhow::Result<SocketAddrV6> {
    match s.parse::<SocketAddr>() {
        Ok(SocketAddr::V6(v6)) => Ok(v6),
        Ok(SocketAddr::V4(_)) => bail!("endpoint {s} 是 IPv4；hextet 是 IPv6-only 的"),
        Err(_) => bail!("无法解析 endpoint {s}（形如 [2001:db8::1]:4193）"),
    }
}

/// Run the invite command.
pub fn run(args: Args) -> anyhow::Result<()> {
    match args.cmd {
        Cmd::New(a) => new(a),
    }
}

fn new(args: NewArgs) -> anyhow::Result<()> {
    let (cfg, id) = super::load_config_and_identity(&args.config)?;
    let ttl = parse_ttl(&args.ttl)?;

    let endpoints = if args.endpoint.is_empty() {
        discover_own_endpoints(&cfg.node.interface, cfg.node.listen_port)?
    } else {
        args.endpoint
            .iter()
            .map(|s| parse_endpoint(s))
            .collect::<anyhow::Result<Vec<_>>>()?
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let invite = Invite::new(
        cfg.network_name.clone(),
        cfg.network_key,
        id.public(),
        now,
        ttl,
        cfg.node.listen_port,
        vec![BootstrapPeer {
            name: args.name.clone(),
            public_key: id.public(),
            endpoints: endpoints.clone(),
        }],
    );
    let token = invite.encode(&id)?;

    if args.json {
        let report = InviteReport {
            token,
            id: invite.id_string(),
            network_name: invite.network_name.clone(),
            issuer: invite.issuer.to_base64(),
            issued_unix: invite.issued_unix,
            expires_unix: invite.expires_unix,
            bootstrap: invite
                .bootstrap
                .iter()
                .map(|b| BootstrapReport {
                    name: b.name.clone(),
                    public_key: b.public_key.to_base64(),
                    endpoints: b.endpoints.iter().map(|e| e.to_string()).collect(),
                })
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // token 走 stdout（`hextet invite new > token.txt` 要能直接用），
    // 其余全部走 stderr
    println!("{token}");
    eprintln!("network   {}", invite.network_name);
    eprintln!("issuer    {}", invite.issuer.to_base64());
    eprintln!(
        "bootstrap {} {:?}",
        args.name,
        endpoints.iter().map(|e| e.to_string()).collect::<Vec<_>>()
    );
    eprintln!(
        "expires   unix {}（{} 后过期）",
        invite.expires_unix, args.ttl
    );
    eprintln!();
    eprintln!("1) 这个 token 含**网络密钥**，等同于网络准入凭证：请走安全信道");
    eprintln!("   （密码管理器 / 端到端加密聊天）交给对方，不要贴进公开群或工单。");
    eprintln!("2) 对方执行 `hextet join <token>` 后会打印一条 `hextet peer add ...`；");
    eprintln!("   在本机执行它，双向接纳才算完成（WireGuard 需要双方都知道对方公钥）。");
    Ok(())
}

/// 枚举本机可用作 endpoint 的公网 IPv6，配上 WG 监听端口。
fn discover_own_endpoints(interface: &str, listen_port: u16) -> anyhow::Result<Vec<SocketAddrV6>> {
    let hint = "请用 --endpoint '[你的公网IPv6]:4193' 显式给出（可重复）";
    let rt = tokio::runtime::Runtime::new()?;
    let addrs = rt
        .block_on(hextet_platform::list_global_ipv6(Some(interface)))
        .map_err(|e| anyhow::anyhow!("枚举本机公网 IPv6 失败：{e}。{hint}"))?;
    if addrs.is_empty() {
        bail!("本机没有可用作 endpoint 的公网 IPv6。{hint}");
    }
    Ok(addrs
        .into_iter()
        .map(|a| SocketAddrV6::new(a, listen_port, 0, 0))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ttl_accepts_suffixes_and_plain_seconds() {
        assert_eq!(parse_ttl("3600").unwrap(), 3600);
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("30m").unwrap(), 1800);
        assert_eq!(parse_ttl("24h").unwrap(), 86_400);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert_eq!(parse_ttl(" 24h ").unwrap(), 86_400);
    }

    #[test]
    fn parse_ttl_rejects_bad_input() {
        for bad in ["", "0", "0h", "abc", "12x", "-1", "400d", "h"] {
            assert!(parse_ttl(bad).is_err(), "{bad} 应该被拒绝");
        }
    }

    #[test]
    fn parse_ttl_rejects_overflow() {
        assert!(parse_ttl(&format!("{}d", u64::MAX)).is_err());
    }

    #[test]
    fn parse_endpoint_rejects_ipv4_and_garbage() {
        assert!(
            parse_endpoint("1.2.3.4:4193")
                .unwrap_err()
                .to_string()
                .contains("IPv6-only")
        );
        assert!(parse_endpoint("nope").is_err());
        assert_eq!(
            parse_endpoint("[2001:db8::1]:4193").unwrap(),
            "[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()
        );
    }
}
