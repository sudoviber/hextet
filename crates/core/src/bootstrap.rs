//! 引导编排：`hextet join` / `hextet init` 的共享逻辑，供 CLI 与 FFI（M7 Android）复用。
//!
//! 这里只做「纯编排」：解码 invite、加载或生成身份、派生地址、渲染并原子写入配置。
//! 所有错误统一成 [`BootstrapError`]，`Display` 即用户可读的中文文案（与 CLI 原措辞
//! 一致），CLI 转成 `anyhow`、FFI 转成 `{"error": ...}` JSON 都只需 stringify。

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::addr::{NodeAddr, check_subnet_collisions, derive_node_addr};
use crate::config::{Config, render_peer_block};
use crate::error::{AddrError, IdentityError, InviteError};
use crate::identity::NodeIdentity;
use crate::invite::Invite;
use crate::network::{NetworkKey, NetworkPrefix};

/// 引导过程错误。`Display` 即用户可读文案，CLI 与 FFI 共用。
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// invite token 无法解析或验签失败。
    #[error(
        "无法使用这个 invite token：{0}。token 可能被篡改、被聊天软件换行截断，或复制时漏了字符——请让对方重发原文。"
    )]
    BadInvite(#[source] InviteError),
    /// invite token 已过期。
    #[error("这个 invite token 已过期，请让对方重新签发一张")]
    InviteExpired,
    /// 已有密钥文件读取失败。
    #[error("读取已有密钥 {path}: {source}")]
    LoadKey {
        /// 密钥文件路径。
        path: PathBuf,
        /// 底层身份错误。
        #[source]
        source: IdentityError,
    },
    /// 新生成的密钥写入失败。
    #[error("写入密钥 {path}: {source}")]
    SaveKey {
        /// 密钥文件路径。
        path: PathBuf,
        /// 底层身份错误。
        #[source]
        source: IdentityError,
    },
    /// init 要求密钥已存在（`hextet keygen` 先行）但没找到。
    #[error("密钥文件 {0} 不存在，先运行 hextet keygen")]
    KeyMissing(PathBuf),
    /// 节点地址派生失败（退化 IID，概率 2^-64）。
    #[error("派生地址失败: {0}")]
    DeriveAddr(#[source] AddrError),
    /// 本节点与引导节点派生出了相同的 subnet id。
    #[error(
        "本节点与引导节点派生出了相同的 subnet id（概率约 1/65536）。重新跑 `hextet keygen` 换一把节点密钥即可"
    )]
    SubnetCollision,
    /// join 的配置输出已存在，拒绝覆盖。
    #[error("{0} 已存在。join 不会覆盖既有配置——换个 --out，或先把旧配置移开")]
    JoinConfigExists(PathBuf),
    /// 配置输出已存在（init 或写盘时的 TOCTOU 竞态）。
    #[error("{0} 已存在")]
    ConfigExists(PathBuf),
    /// 配置写入失败。
    #[error("写入 {path} 失败: {source}")]
    WriteConfig {
        /// 配置文件路径。
        path: PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },
    /// network key 解析失败（`init --network-key`）。
    #[error(transparent)]
    BadNetworkKey(IdentityError),
}

/// [`join_network`] 的可选覆盖参数（名字、端口、状态目录）。
///
/// 密钥与配置的**完整路径**直接作为函数参数传入（不做文件名/目录拆分），
/// CLI 的 `--key-file`/`--out` 原样透传，跨目录密钥因此不会被静默改写。
pub struct JoinOptions<'a> {
    /// 打印出的 `peer add` 命令里建议给本节点起的名字。
    pub name: &'a str,
    /// 本机 WireGuard 监听端口覆盖；`None` = 用 invite 里约定的端口。
    pub listen_port: Option<u16>,
    /// daemon 状态目录覆盖；`None` = 模板里只写注释（运行时走默认）。
    pub state_dir: Option<&'a Path>,
}

impl Default for JoinOptions<'_> {
    fn default() -> Self {
        Self {
            name: "new-node",
            listen_port: None,
            state_dir: None,
        }
    }
}

/// [`init_network`] 的可选覆盖参数。
pub struct InitOptions<'a> {
    /// WireGuard 监听端口。
    pub listen_port: u16,
    /// daemon 状态目录覆盖；`None` = 模板里只写注释（运行时走默认）。
    pub state_dir: Option<&'a Path>,
    /// `true` = 密钥必须已存在（CLI init，`keygen` 先行）；`false` = 自动生成（FFI）。
    pub require_existing_key: bool,
}

impl Default for InitOptions<'_> {
    fn default() -> Self {
        Self {
            listen_port: crate::defaults::DEFAULT_PORT,
            state_dir: None,
            require_existing_key: true,
        }
    }
}

/// [`join_network`] 的结果（serde 序列化；FFI 成功即序列化此结构）。
#[derive(Debug, serde::Serialize)]
pub struct JoinOutcome {
    /// 网络名。
    pub network_name: String,
    /// 网络 ULA /48 前缀（形如 `fdxx:...::/48`）。
    pub prefix: String,
    /// 本节点 overlay 地址。
    pub node_address: String,
    /// 本节点公钥 base64。
    pub public_key: String,
    /// 写出的配置文件路径。
    pub config_path: String,
    /// 密钥文件路径。
    pub key_file: String,
    /// 引导节点名（与 invite 里的顺序一致）。
    pub bootstrap_peers: Vec<String>,
    /// 每个引导节点的 endpoint 字符串列表（与 [`Self::bootstrap_peers`] 对齐，供 CLI 展示）。
    pub bootstrap_endpoints: Vec<Vec<String>>,
    /// 本节点 site /64（`format!("{}/64", site)`，来自 [`NodeAddr::site`]）。
    pub site: String,
    /// 实际写进配置的监听端口（invite 端口或覆盖后的值）。
    pub listen_port: u16,
    /// 建议在引导节点执行的 `hextet peer add ...` 命令。
    pub peer_add_command: String,
}

/// [`init_network`] 的结果。
#[derive(Debug, serde::Serialize)]
pub struct InitOutcome {
    /// 网络名。
    pub network_name: String,
    /// 网络 ULA /48 前缀。
    pub prefix: String,
    /// 本节点 overlay 地址。
    pub node_address: String,
    /// 本节点公钥 base64。
    pub public_key: String,
    /// 写出的配置文件路径。
    pub config_path: String,
    /// 密钥文件路径。
    pub key_file: String,
    /// 本次使用的 network key base64（新建或解析的）。
    pub network_key_base64: String,
}

/// 用 invite token 加入既有网络：解码、验期、加载或生成身份、派生地址、渲染并写配置。
///
/// `key_path`/`config_path` 是**完整路径**（不做文件名拆分）。身份语义与 CLI 一致：
/// `key_path` 已存在则复用（绝不覆盖用户的密钥），否则生成并保存；配置写盘失败时
/// 移除刚生成的孤儿密钥。配置里的 `key_file =` 写相对路径（当密钥落在配置目录下）
/// 或绝对路径（跨目录），与 [`crate::config::load_config_and_identity`] 的解析规则一致。
pub fn join_network(
    token: &str,
    key_path: &Path,
    config_path: &Path,
    now_unix: u64,
    opts: &JoinOptions,
) -> Result<JoinOutcome, BootstrapError> {
    let invite = Invite::decode(token.trim()).map_err(BootstrapError::BadInvite)?;
    invite
        .check_not_expired(now_unix)
        .map_err(|_| BootstrapError::InviteExpired)?;

    // 身份：已有就复用（绝不覆盖用户的密钥），没有就先在内存里生成。
    let (id, generated) = load_or_generate_identity(key_path, false)?;

    // 落盘之前先把能算的都算完、能查的都查完：宁可什么都不写，也不要留半个坏配置。
    let prefix = NetworkPrefix::derive(&invite.network_key);
    let own = derive_node_addr(prefix, &id.public()).map_err(BootstrapError::DeriveAddr)?;
    let mut all: Vec<(String, NodeAddr)> = Vec::with_capacity(invite.bootstrap.len() + 1);
    for b in &invite.bootstrap {
        all.push((
            b.name.clone(),
            derive_node_addr(prefix, &b.public_key).map_err(BootstrapError::DeriveAddr)?,
        ));
    }
    all.push(("<self>".into(), own.clone()));
    check_subnet_collisions(&all).map_err(|_| BootstrapError::SubnetCollision)?;

    if config_path.exists() {
        return Err(BootstrapError::JoinConfigExists(config_path.to_owned()));
    }

    if generated {
        id.save(key_path)
            .map_err(|source| BootstrapError::SaveKey {
                path: key_path.to_owned(),
                source,
            })?;
    }

    let listen_port = opts.listen_port.unwrap_or(invite.listen_port);
    let key_file_ref = key_file_ref_for_config(config_path, key_path);
    let mut text = Config::render_template(
        &invite.network_name,
        &invite.network_key,
        &key_file_ref,
        listen_port,
        opts.state_dir,
    );
    for b in &invite.bootstrap {
        text.push_str(&render_peer_block(
            &b.name,
            &b.public_key,
            &b.endpoints,
            &[],
        ));
    }
    if let Err(e) = write_new_0600(config_path, &text) {
        // 配置没写成，就不要留下一把刚生成的孤儿密钥。
        if generated {
            let _ = std::fs::remove_file(key_path);
        }
        return Err(e);
    }

    let peer_add_command = format!(
        "hextet peer add --name {} --public-key '{}' --endpoint '[你的公网IPv6]:{}'",
        opts.name,
        id.public().to_base64(),
        listen_port
    );

    Ok(JoinOutcome {
        network_name: invite.network_name.clone(),
        prefix: prefix.to_string(),
        node_address: own.address.to_string(),
        public_key: id.public().to_base64(),
        config_path: config_path.display().to_string(),
        key_file: key_path.display().to_string(),
        bootstrap_peers: invite.bootstrap.iter().map(|b| b.name.clone()).collect(),
        bootstrap_endpoints: invite
            .bootstrap
            .iter()
            .map(|b| b.endpoints.iter().map(|e| e.to_string()).collect())
            .collect(),
        site: format!("{}/64", own.site),
        listen_port,
        peer_add_command,
    })
}

/// 初始化节点配置：新建网络（或按 `network_key` 加入既有网络），加载或生成身份并写配置。
///
/// `key_path`/`config_path` 是**完整路径**。身份语义：`require_existing_key = true`（CLI）
/// 时密钥必须已存在，否则报 [`BootstrapError::KeyMissing`]；`false`（FFI）时密钥不存在则
/// 生成并保存。配置写盘失败时移除刚生成的孤儿密钥。
pub fn init_network(
    name: &str,
    key_path: &Path,
    config_path: &Path,
    network_key: Option<&str>,
    opts: &InitOptions,
) -> Result<InitOutcome, BootstrapError> {
    let (id, generated) = load_or_generate_identity(key_path, opts.require_existing_key)?;

    let key = match network_key {
        Some(s) => NetworkKey::from_base64(s).map_err(BootstrapError::BadNetworkKey)?,
        None => NetworkKey::generate(),
    };

    // 派生地址（InitOutcome 需要 prefix 与 node_address）。
    let prefix = NetworkPrefix::derive(&key);
    let own = derive_node_addr(prefix, &id.public()).map_err(BootstrapError::DeriveAddr)?;

    // 若身份是刚生成的，先落盘（0600），再写配置；配置写失败则移除孤儿密钥。
    if generated {
        id.save(key_path)
            .map_err(|source| BootstrapError::SaveKey {
                path: key_path.to_owned(),
                source,
            })?;
    }

    let key_file_ref = key_file_ref_for_config(config_path, key_path);
    let text = Config::render_template(name, &key, &key_file_ref, opts.listen_port, opts.state_dir);
    if let Err(e) = write_new_0600(config_path, &text) {
        if generated {
            let _ = std::fs::remove_file(key_path);
        }
        return Err(e);
    }

    Ok(InitOutcome {
        network_name: name.to_owned(),
        prefix: prefix.to_string(),
        node_address: own.address.to_string(),
        public_key: id.public().to_base64(),
        config_path: config_path.display().to_string(),
        key_file: key_path.display().to_string(),
        network_key_base64: key.to_base64(),
    })
}

/// 配置里要写入的 `key_file =` 值：密钥落在配置目录下写相对路径，否则写绝对路径。
///
/// 与 [`crate::config::load_config_and_identity`] 的解析规则一致：相对 `key_file` 按
/// 配置所在目录解析，绝对路径原样使用。
fn key_file_ref_for_config(config_path: &Path, key_path: &Path) -> PathBuf {
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    match key_path.strip_prefix(config_dir) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.to_owned(),
        _ => key_path.to_owned(),
    }
}

/// 加载或生成身份：已存在则加载（返回 `generated = false`）；不存在时按
/// `require_existing` 决定报错（`true`）还是生成（`false`，返回 `generated = true`）。
fn load_or_generate_identity(
    key_path: &Path,
    require_existing: bool,
) -> Result<(NodeIdentity, bool), BootstrapError> {
    if key_path.exists() {
        let id = NodeIdentity::load(key_path).map_err(|source| BootstrapError::LoadKey {
            path: key_path.to_owned(),
            source,
        })?;
        Ok((id, false))
    } else if require_existing {
        Err(BootstrapError::KeyMissing(key_path.to_owned()))
    } else {
        Ok((NodeIdentity::generate(), true))
    }
}

/// 以 0600 新建文件写入；已存在则报错（不覆盖，`create_new` 原子拒绝覆盖避免 TOCTOU）。
fn write_new_0600(path: &Path, text: &str) -> Result<(), BootstrapError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            BootstrapError::ConfigExists(path.to_owned())
        } else {
            BootstrapError::WriteConfig {
                path: path.to_owned(),
                source: e,
            }
        }
    })?;
    f.write_all(text.as_bytes())
        .map_err(|e| BootstrapError::WriteConfig {
            path: path.to_owned(),
            source: e,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::invite::BootstrapPeer;
    use std::net::SocketAddrV6;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn make_token(issuer: &NodeIdentity) -> String {
        let bootstrap = NodeIdentity::generate();
        let invite = Invite::new(
            "home".into(),
            NetworkKey::generate(),
            issuer.public(),
            now(),
            3600,
            4193,
            vec![BootstrapPeer {
                name: "router".into(),
                public_key: bootstrap.public(),
                endpoints: vec!["[2001:db8::1]:4193".parse::<SocketAddrV6>().unwrap()],
            }],
        );
        invite.encode(issuer).unwrap()
    }

    #[test]
    fn join_writes_config_and_key_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::generate();
        let token = make_token(&issuer);
        let cfg_path = dir.path().join("hextet.toml");
        let key_path = dir.path().join("node.key");

        let opts = JoinOptions::default();
        let outcome = join_network(&token, &key_path, &cfg_path, now(), &opts).unwrap();

        assert_eq!(outcome.network_name, "home");
        assert!(
            outcome.prefix.starts_with("fd"),
            "prefix = {}",
            outcome.prefix
        );
        assert!(
            outcome.node_address.starts_with("fd"),
            "node_address = {}",
            outcome.node_address
        );
        assert_eq!(outcome.bootstrap_peers, vec!["router".to_string()]);
        assert_eq!(outcome.listen_port, 4193);
        assert!(outcome.peer_add_command.contains("hextet peer add"));
        assert!(outcome.peer_add_command.contains(&outcome.public_key));

        assert!(cfg_path.exists() && key_path.exists());
        // 同目录：配置里的 key_file 写成相对名，load_config_and_identity 才能解析。
        let text = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(text.contains("key_file = \"node.key\""), "got:\n{text}");
    }

    #[test]
    fn join_reuses_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::generate();
        let token = make_token(&issuer);
        let cfg_path = dir.path().join("hextet.toml");
        let key_path = dir.path().join("node.key");

        let existing = NodeIdentity::generate();
        existing.save(&key_path).unwrap();
        let before = existing.public().to_base64();

        let outcome =
            join_network(&token, &key_path, &cfg_path, now(), &JoinOptions::default()).unwrap();
        assert_eq!(outcome.public_key, before, "join 不该覆盖已有密钥");
    }

    #[test]
    fn join_rejects_garbage_token() {
        let dir = tempfile::tempdir().unwrap();
        let err = join_network(
            "nope",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            now(),
            &JoinOptions::default(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("无法使用这个 invite token"), "msg = {msg}");
        assert!(msg.contains("篡改"), "msg = {msg}");
    }

    #[test]
    fn join_rejects_expired_token() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::generate();
        let token = make_token(&issuer);
        // 用一个远超过期的 now。
        let err = join_network(
            &token,
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            now() + 1_000_000,
            &JoinOptions::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("已过期"), "msg = {}", err);
    }

    #[test]
    fn join_refuses_overwrite_and_removes_orphan_key() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = NodeIdentity::generate();
        let token = make_token(&issuer);
        let cfg_path = dir.path().join("hextet.toml");
        let key_path = dir.path().join("node.key");

        // 预先放一个已存在的配置。
        std::fs::write(&cfg_path, "# mine\n").unwrap();
        let err =
            join_network(&token, &key_path, &cfg_path, now(), &JoinOptions::default()).unwrap_err();
        assert!(err.to_string().contains("已存在"), "msg = {}", err);
        // 配置没写成，就不该留下一把孤儿密钥。
        assert!(!key_path.exists());
    }

    #[test]
    fn init_writes_config_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let opts = InitOptions {
            require_existing_key: false,
            ..InitOptions::default()
        };
        let outcome = init_network(
            "home",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            None,
            &opts,
        )
        .unwrap();

        assert_eq!(outcome.network_name, "home");
        assert!(outcome.prefix.starts_with("fd"));
        assert!(outcome.node_address.starts_with("fd"));
        assert!(!outcome.network_key_base64.is_empty());
        assert!(dir.path().join("hextet.toml").exists());
        assert!(dir.path().join("node.key").exists());
        let text = std::fs::read_to_string(dir.path().join("hextet.toml")).unwrap();
        assert!(text.contains("key_file = \"node.key\""));
    }

    #[test]
    fn init_requires_existing_key_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        // 默认 require_existing_key = true → 密钥缺失必须报错。
        let err = init_network(
            "home",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            None,
            &InitOptions::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("不存在，先运行 hextet keygen"),
            "msg = {}",
            err
        );
    }

    #[test]
    fn init_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let opts = InitOptions {
            require_existing_key: false,
            ..InitOptions::default()
        };
        init_network(
            "home",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            None,
            &opts,
        )
        .unwrap();
        let err = init_network(
            "home",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            None,
            &opts,
        )
        .unwrap_err();
        assert!(err.to_string().contains("已存在"), "msg = {err}");
    }

    /// 跨目录密钥：身份写在用户指定的 `key_path`，配置里的 `key_file =` 写绝对路径，
    /// 且 `load_config_and_identity` 能据此解析出同一把公钥。
    #[test]
    fn init_cross_dir_key_writes_absolute_key_file_and_resolves() {
        let keys_dir = tempfile::tempdir().unwrap();
        let cfg_dir = tempfile::tempdir().unwrap();
        let key_path = keys_dir.path().join("node.key");
        let config_path = cfg_dir.path().join("hextet.toml");

        let opts = InitOptions {
            require_existing_key: false,
            ..InitOptions::default()
        };
        let outcome = init_network("home", &key_path, &config_path, None, &opts).unwrap();

        // (a) 身份写在精确的 key_path（不在配置目录下）。
        assert!(key_path.exists(), "身份应写在 {key_path:?}");
        assert!(!cfg_dir.path().join("node.key").exists());

        // (b) 配置里的 key_file = 写绝对路径，load_config_and_identity 能解析出同一公钥。
        let text = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            text.contains(&format!("key_file = \"{}\"", key_path.display())),
            "got:\n{text}"
        );
        let (cfg, id) = crate::config::load_config_and_identity(&config_path).unwrap();
        assert_eq!(id.public().to_base64(), outcome.public_key);
        assert_eq!(cfg.network_name, "home");
    }

    /// 同目录密钥：配置里的 `key_file =` 写相对名 `"node.key"`。
    #[test]
    fn init_same_dir_key_writes_relative_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let opts = InitOptions {
            require_existing_key: false,
            ..InitOptions::default()
        };
        init_network(
            "home",
            &dir.path().join("node.key"),
            &dir.path().join("hextet.toml"),
            None,
            &opts,
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.path().join("hextet.toml")).unwrap();
        assert!(text.contains("key_file = \"node.key\""), "got:\n{text}");
        // 相对路径能按配置目录解析出身份。
        let (_cfg, id) =
            crate::config::load_config_and_identity(&dir.path().join("hextet.toml")).unwrap();
        let saved = NodeIdentity::load(&dir.path().join("node.key")).unwrap();
        assert_eq!(id.public(), saved.public());
    }
}
