//! `hextet hosts`：把配置里的 peer 名映射到 overlay IPv6 地址（MagicDNS-lite）。
//!
//! 不做真 DNS 解析器，只生成静态 hosts 行，方便 `sudo tee -a /etc/hosts` 或
//! `--out` 原子写入。hextet 是 IPv6-only 的：配置里本就没有 IPv4，因此 hosts 行
//! 只有 IPv6 地址，无需任何 IPv4 兼容处理。
//!
//! 只映射 **peer** 的名 → overlay 地址；本节点自己的名 → 地址不在此列（需要从
//! 身份推导本机地址，超出本切片范围）。未来可加 `--self` 标志补上。

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use hextet_core::config::Peer;
use tracing::warn;

/// Arguments for the hosts command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 输出到文件（原子写入，0644）；缺省打印到 stdout
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// 把 peer 名净化为合法主机名：小写、只保留 `[a-z0-9-]`、连续 `-` 折叠成一个、
/// 去掉首尾 `-`。纯函数，便于单测。
pub fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        let keep = matches!(c, 'a'..='z' | '0'..='9');
        let ch = if keep { c } else { '-' };
        if ch == '-' {
            if last_was_dash {
                continue;
            }
            last_was_dash = true;
        } else {
            last_was_dash = false;
        }
        out.push(ch);
    }
    out.trim_matches('-').to_string()
}

/// 由 peer 列表渲染 hosts 行（每行不含末尾换行）。
///
/// 策略：名字净化 → 空名跳过 → 超 63 字符截断 → 撞名确定性去重（`-2`/`-3`…）。
/// 跳过、截断与去重都只 `warn!`、绝不静默覆盖。
pub fn render_hosts(peers: &[Peer]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut seen: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for peer in peers {
        let base = sanitize_name(&peer.name);
        if base.is_empty() {
            warn!(peer = %peer.name, "peer 名净化后为空，跳过（未生成 hosts 行）");
            continue;
        }
        let base = if base.len() > 63 {
            warn!(peer = %peer.name, "peer 名净化后超过 63 字符，截断到 63");
            base.chars()
                .take(63)
                .collect::<String>()
                .trim_end_matches('-')
                .to_string()
        } else {
            base
        };
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        let hostname = if *count == 1 {
            base
        } else {
            warn!(peer = %peer.name, "peer 名净化后与既有 peer 撞名，追加 -{count} 后缀");
            format!("{base}-{count}")
        };
        let address = peer.addr.address;
        lines.push(format!("{address}  {hostname}  {hostname}.hextet"));
    }
    lines
}

/// Run the hosts command.
pub fn run(args: Args) -> anyhow::Result<()> {
    // 让 skip/截断/撞名的 warn! 真正可见，且必须写到 stderr——stdout 只能是
    // 纯 hosts 行（`sudo tee -a /etc/hosts` 直接吃 stdout，混入日志会写坏 /etc/hosts）。
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let lines = render_hosts(&cfg.peers);

    match &args.out {
        Some(path) => {
            let mut contents = String::new();
            for line in &lines {
                contents.push_str(line);
                contents.push('\n');
            }
            write_atomic(path, &contents)?;
        }
        None => {
            for line in &lines {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// 原子写入文本文件（临时文件 → fsync → rename，权限 0644）。
///
/// 与 `hextet_engine::atomic` 同一套「同目录临时文件 + rename」的原子替换思路，
/// 只是这里是纯文本且权限为 0644（hosts 不是秘密）。
fn write_atomic(path: &Path, contents: &str) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "hosts".to_string());
    let tmp = dir.join(format!(".{stem}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o644);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("打开临时文件 {}", tmp.display()))?;
    // 临时文件可能是上次崩溃留下的，mode() 对已存在文件不生效，显式再设一次
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    f.write_all(contents.as_bytes())
        .with_context(|| format!("写入 {}", tmp.display()))?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path).with_context(|| format!("重命名到 {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hextet_core::addr::NodeAddr;
    use hextet_core::identity::NodeIdentity;

    fn peer(name: &str, addr: std::net::Ipv6Addr) -> Peer {
        Peer {
            name: name.to_string(),
            public_key: NodeIdentity::generate().public(),
            endpoints: vec![],
            addr: NodeAddr {
                subnet_id: 0,
                site: addr,
                address: addr,
            },
            relay: false,
            relay_port: 0,
            routes: vec![],
            ddns: None,
            keepalive: None,
        }
    }

    #[test]
    fn sanitize_lowercases_maps_special_chars_and_collapses_dashes() {
        assert_eq!(sanitize_name("My NAS"), "my-nas");
        assert_eq!(sanitize_name("UPPER_case.123"), "upper-case-123");
        assert_eq!(sanitize_name("a--b"), "a-b");
        assert_eq!(sanitize_name("-foo-"), "foo");
        assert_eq!(sanitize_name("already-valid-1"), "already-valid-1");
    }

    #[test]
    fn empty_after_sanitize_is_skipped() {
        let p = peer("___", "fd00::1".parse().unwrap());
        assert_eq!(render_hosts(&[p]), Vec::<String>::new());
    }

    #[test]
    fn name_longer_than_63_is_truncated() {
        let long = "a".repeat(70);
        let p = peer(&long, "fd00::1".parse().unwrap());
        let lines = render_hosts(&[p]);
        assert_eq!(lines.len(), 1);
        let expected_name = "a".repeat(63);
        assert_eq!(
            lines[0],
            format!("fd00::1  {expected_name}  {expected_name}.hextet")
        );
    }

    #[test]
    fn collision_gets_deterministic_suffix() {
        let a = peer("My NAS", "fd00::1".parse().unwrap());
        let b = peer("My_NAS", "fd00::2".parse().unwrap());
        let c = peer("my-nas", "fd00::3".parse().unwrap());
        let lines = render_hosts(&[a, b, c]);
        assert_eq!(
            lines,
            vec![
                "fd00::1  my-nas  my-nas.hextet".to_string(),
                "fd00::2  my-nas-2  my-nas-2.hextet".to_string(),
                "fd00::3  my-nas-3  my-nas-3.hextet".to_string(),
            ]
        );
    }

    #[test]
    fn ipv6_line_format() {
        let p = peer("nas", "fd12:3456:7890::42".parse().unwrap());
        let lines = render_hosts(&[p]);
        assert_eq!(
            lines,
            vec!["fd12:3456:7890::42  nas  nas.hextet".to_string()]
        );
    }
}
