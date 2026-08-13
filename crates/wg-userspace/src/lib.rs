//! hextet 用户态 WireGuard 后端（boringtun，ADR-0007 决策 1 的过渡后端）。
//!
//! 本 crate 实现 [`hextet_wg::WgBackend`] trait，用 boringtun 0.7.1 的
//! [`DeviceHandle`] 作为运行时数据面（真实 utun/TUN + UDP socket，macOS/Linux）。
//! boringtun 类型**不**暴露到 crate 之外——对外只有 [`UserspaceBackend`]。
//!
//! ## 与 ADR-0007 决策 2 的偏差（必须诚实记录）
//!
//! ADR-0007 决策 2 提到 boringtun 暴露「`Tun` trait + `udp` trait」，并设想写一个
//! 适配器把 [`hextet_platform::tun::TunHandle`] 接到 boringtun 的 `Tun` trait 上。
//! **查证 0.7.1 源码后确认这两个 trait 并不存在**：boringtun 的 `Device` 内部硬编码
//! 平台 `TunSocket`（`device/tun_darwin.rs` / `device/tun_linux.rs`）与
//! `socket2::Socket`，没有可注入的 TUN/UDP 抽象。因此本 crate 没有（也无法）写
//! `TunHandle` 适配器；`hextet-platform` 的 `tun` 能力仍按决策 2 落地，供将来切换
//! gotatun（它有自己的 `gotatun::tun` trait）时写适配器用。boringtun 后端本身完全
//! 同步，不依赖 tokio，依赖集保持最小（`hextet-wg` + `boringtun`）。
//!
//! ## 运行时控制面
//!
//! boringtun 的 `DeviceHandle` 对外的唯一控制接口是 Unix socket 文本协议
//! （`/var/run/wireguard/{name}.sock` 上的 `set=1`/`get=1`，与 boringtun-cli 用同一
//! 套）。本 crate 的五个 `WgBackend` 方法都映射到这套协议上。**这套路径需要 root**
//! （创建 utun/TUN + 绑 `/var/run/wireguard`），因此在本机 macOS 上无法无 root 测试；
//! 进程内可测的证明（握手 + 数据往返）放在 `mod tests`，用 boringtun 的 `noise::Tunn`
//! 抽象直跑（不碰真实网卡、不碰 root），见 [`tests`]。
//!
//! ## boringtun 0.7.1 的语义缺口（诚实边界，逐条记录）
//!
//! - `Device::update_peer` 对**已存在**的 peer 直接 `panic!`（"Modifying existing
//!   peers is not yet supported. Remove and add again instead."），且 `set=1` 协议里
//!   没有"只改 endpoint"的增量操作。因此 [`WgBackend::set_peer_endpoint`] 用
//!   **remove + 完整 re-add** 实现（先从 `peer_specs` 注册表取回完整 `PeerSpec`，
//!   remove 后以新 endpoint 重加）：功能正确，但比内核后端真正的增量更新重——每次
//!   endpoint 轮换是两次 `set=1` 往返。**诚实边界**：真实 socket 路径需 root，本机
//!   仅 `cargo build` 编译验证，未真机跑。
//! - 同理 [`WgBackend::add_peer`] 只对**新增** peer 有效：先查一次现有 peer 集合，
//!   若 peer 已存在则返回错误，避免触发 boringtun 的 panic。
//! - [`WgBackend::status`] 的 `last_handshake` 字段：boringtun 只暴露"距上次握手
//!   的时长"（`last_handshake_time_sec`/`_nsec`，相对值），内核 netlink 后端给的是
//!   绝对 `SystemTime`。这里用 `SystemTime::now() - 时长` 做 best-effort 换算（见
//!   `finish_peer`），不是伪造——文档已标注其近似性。
//! - macOS 上 boringtun 的 utun 命名要求 `utun`/`utunN`；hextet 的接口名是
//!   `hextet0`。ADR-0009 决策 2 已落地这一层映射：macOS 上把配置名 `hextet0` 映射为
//!   裸 `utun`（内核选最低可用 index），经 `WG_TUN_NAME_FILE` 读回真实 `utunN`，并以
//!   真实名作为 `devices` 注册表键与 `api_set` 的目标。**诚实边界**：这条真实设备
//!   运行时路径需要 root + 真实 utun，本开发机（macOS 无 `sudo`）未真机验证，仅
//!   `cargo build` 编译验证；Linux 上仍是恒等路径（逻辑名 == 真实名），行为不变。

#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, SocketAddrV6};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use boringtun::device::{DeviceConfig, DeviceHandle};
use hextet_wg::WgBackend;
use hextet_wg::types::{DeviceSpec, PeerSpec, PeerStatus, WgError};

/// boringtun 的 API socket 目录（与 boringtun-cli 一致）。
const SOCK_DIR: &str = "/var/run/wireguard";

/// 用户态 WireGuard 后端（boringtun）。
///
/// 内部维护"接口名 → [`DeviceHandle`]"注册表：`apply` 幂等地创建/复用设备，其余
/// 方法经 Unix API socket 下发运行时操作。设备句柄必须常驻（`DeviceHandle` 的 Drop
/// 会触发退出），所以不能在下发配置后立刻丢弃。
///
/// `devices` 以**真实设备名**为键（Linux 上 == 配置名；macOS 上是读回的 `utunN`）；
/// `aliases` 维护**逻辑名（`spec.interface`，如 `hextet0`）→ 真实名**的幂等映射
/// （ADR-0009 决策 2），Linux 上两者恒等（仍登记，保证两条路径对称、无未读字段）。
pub struct UserspaceBackend {
    devices: Mutex<HashMap<String, DeviceHandle>>,
    /// 逻辑名 → 真实设备名（macOS 上 `hextet0` → `utunN`；Linux 上恒等）。
    aliases: Mutex<HashMap<String, String>>,
    /// peer 公钥 → 该 peer 的完整 [`PeerSpec`]（allowed_ips / keepalive）。
    ///
    /// 后端必须记住每个 peer 的完整 `PeerSpec`，因为 [`WgBackend::set_peer_endpoint`]
    /// 只收到 `(wg_public, endpoint)`，而 boringtun 0.7.1 改 endpoint 只能「remove +
    /// 完整 re-add」——重建时需要用这里存的 allowed_ips / keepalive 补齐完整配置。
    ///
    /// **锁纪律**：`peer_specs` 独立获取、绝不与 `aliases`/`devices` 同时持有（各方法
    /// 内用独立短作用域），避免与既有「先 aliases 后 devices」顺序产生死锁路径。
    peer_specs: Mutex<HashMap<[u8; 32], PeerSpec>>,
}

impl Default for UserspaceBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl UserspaceBackend {
    /// 构造一个空的用户态后端。
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(HashMap::new()),
            aliases: Mutex::new(HashMap::new()),
            peer_specs: Mutex::new(HashMap::new()),
        }
    }

    /// 创建并登记一个设备，返回 OS 层真实设备名。
    ///
    /// Linux：`interface` 即真实名（恒等，ADR-0009 决策 3），幂等——已存在则复用。
    #[cfg(target_os = "linux")]
    fn create_device(
        &self,
        devices: &mut HashMap<String, DeviceHandle>,
        interface: &str,
    ) -> Result<String, WgError> {
        if !devices.contains_key(interface) {
            let handle = DeviceHandle::new(interface, DeviceConfig::default())
                .map_err(|e| WgError::Backend(format!("boringtun 创建设备失败: {e}")))?;
            devices.insert(interface.to_owned(), handle);
        }
        Ok(interface.to_owned())
    }

    /// 创建并登记一个设备，返回 OS 层真实设备名。
    ///
    /// macOS：请求裸 `utun`（内核选最低可用 index，避开 Tailscale 等既有 utun），
    /// 创建前把 `WG_TUN_NAME_FILE` 指向临时文件、创建后读回真实 `utunN`（ADR-0009
    /// 决策 2）。`_interface`（配置名 `hextet0`）不用于请求名——它只作为 `aliases`
    /// 的键，映射到读回的 `utunN`。**诚实边界**：需要 root + 真实 utun，本机未真机
    /// 验证，仅编译验证。
    #[cfg(target_os = "macos")]
    fn create_device(
        &self,
        devices: &mut HashMap<String, DeviceHandle>,
        _interface: &str,
    ) -> Result<String, WgError> {
        let tmp = std::env::temp_dir().join(format!("hextet-wg-tun-{}.txt", std::process::id()));
        // 离开本函数时无论成败都清掉临时文件与全局环境变量，不留指向已删文件的陈旧
        // `WG_TUN_NAME_FILE`（见 ADR-0009「代价与再评估」）。
        struct Cleanup<'a>(&'a std::path::Path);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0);
                wg_tun_name::unset();
            }
        }
        let _cleanup = Cleanup(&tmp);

        wg_tun_name::set(&tmp);
        let handle = DeviceHandle::new("utun", DeviceConfig::default())
            .map_err(|e| WgError::Backend(format!("boringtun 创建设备失败: {e}")))?;
        let real_name = std::fs::read_to_string(&tmp)
            .map(|s| s.trim().to_owned())
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                WgError::Backend(format!(
                    "读取 WG_TUN_NAME_FILE 失败（{}），无法读回真实 utunN",
                    tmp.display()
                ))
            })?;
        devices.insert(real_name.clone(), handle);
        Ok(real_name)
    }

    /// 把「接口名」解析为真实设备名（ADR-0009 决策 2 的映射层）。
    ///
    /// `interface` 既可能是逻辑名（配置里的 `hextet0`）也可能是真实名（`apply` 读回的
    /// `utunN`）。`aliases` 里查得到逻辑名就用映射后的真实名；查不到（已是真实名，或
    /// Linux 恒等路径 `hextet0 → hextet0`）则原样返回。这样 `status`/`set_peer_endpoint`/
    /// `add_peer`/`remove_peer` 对外都能同时接受两种名字，与 [`WgBackend::down`] 一致。
    fn resolve(&self, interface: &str) -> Result<String, WgError> {
        let aliases = self
            .aliases
            .lock()
            .map_err(|_| WgError::Backend("aliases 注册表锁中毒".into()))?;
        Ok(aliases
            .get(interface)
            .cloned()
            .unwrap_or_else(|| interface.to_owned()))
    }
}

/// macOS 上读回真实 utun 名字的最小安全封装（ADR-0009 决策 2 的收窄 `unsafe` 点）。
///
/// `std::env::set_var` 在 Rust 2024 + 工具链 ≥1.88 下是 `unsafe fn`，而本工作区
/// `edition = "2024"` 且 `unsafe_code = "deny"`。这里把 `set_var` 收窄到唯一一处，
/// 镜像 `crates/platform/src/macos.rs` 对 `SIOCAIFADDR_IN6`/`SIOCDIFADDR_IN6` 的
/// 「最小安全封装」先例（ADR-0008 决策 1）。一旦出现维护中的安全替代（或改走
/// ADR-0009 决策 2 备选「编排层挑空闲 `utunN`」、零 unsafe），即删除本模块
/// （ADR-0009「代价与再评估」触发条件 2）。
///
/// # SAFETY
/// 只在 [`UserspaceBackend::apply`] 的**单线程**路径上、boringtun spawn 任何线程
/// **之前**被调用：`DeviceHandle::new("utun", …)` 会在创建时同步读取该环境变量并
/// 写回真实名字，随后 `apply` 立即读文件。不存在并发读写环境变量的竞态
/// （见 ADR-0009「代价与再评估」）。
#[cfg(target_os = "macos")]
mod wg_tun_name {
    #![allow(unsafe_code)]

    /// 把 `WG_TUN_NAME_FILE` 指向 `path`（供 boringtun 写回真实 utun 名）。
    pub fn set(path: &std::path::Path) {
        // SAFETY: 见模块级文档——单线程 apply 路径、boringtun spawn 线程前调用。
        unsafe {
            std::env::set_var("WG_TUN_NAME_FILE", path);
        }
    }

    /// 撤销 [`set`]，避免把指向已删临时文件的陈旧环境变量留在进程全局状态里。
    pub fn unset() {
        // SAFETY: 见模块级文档——单线程 apply 路径、无并发读写。
        unsafe {
            std::env::remove_var("WG_TUN_NAME_FILE");
        }
    }
}

/// 十六进制编码（64 字符）一个 32 字节 WG 密钥，对应 boringtun `KeyBytes` 的 hex 线格式。
fn key_to_hex(k: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in k {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// 解码 64 字符 hex 为 32 字节；非法返回 `None`。
fn hex_to_key(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = nib(bytes[i * 2])?;
        let lo = nib(bytes[i * 2 + 1])?;
        *o = (hi << 4) | lo;
    }
    Some(out)
}

fn api_sock_path(interface: &str) -> String {
    format!("{SOCK_DIR}/{interface}.sock")
}

/// 连接指定接口的 API socket；接口不存在（socket 路径不存在）时映射为
/// `WgError::NotFound`，与内核后端 `status` 的语义一致。
fn api_connect(interface: &str) -> Result<UnixStream, WgError> {
    let path = api_sock_path(interface);
    UnixStream::connect(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            WgError::NotFound(interface.to_owned())
        } else {
            WgError::Backend(format!("连接 API socket {path} 失败: {e}"))
        }
    })
}

fn parse_errno(resp: &str) -> Result<i32, WgError> {
    for line in resp.lines() {
        if let Some(v) = line.trim().strip_prefix("errno=") {
            return v
                .trim()
                .parse::<i32>()
                .map_err(|_| WgError::Backend(format!("无法解析 errno 行: {line:?}")));
        }
    }
    Err(WgError::Backend(format!("响应缺少 errno 行: {resp:?}")))
}

/// 下发一次 `set=1` 配置（`body` 不含 `set=1` 头与终止空行，这两者由本函数补齐）。
fn api_set(interface: &str, body: &str) -> Result<(), WgError> {
    let mut stream = api_connect(interface)?;
    let mut request = String::with_capacity(8 + body.len() + 1);
    request.push_str("set=1\n");
    request.push_str(body);
    request.push('\n'); // 空行终止 peer 段
    stream
        .write_all(request.as_bytes())
        .map_err(|e| WgError::Backend(format!("写 API socket 失败: {e}")))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| WgError::Backend(format!("读 API socket 失败: {e}")))?;
    let errno = parse_errno(&resp)?;
    if errno == 0 {
        Ok(())
    } else {
        Err(WgError::Backend(format!(
            "boringtun set=1 返回 errno={errno}"
        )))
    }
}

/// 读取一次 `get=1` 的原始响应文本（含 `errno=` 收尾行）。
fn api_get(interface: &str) -> Result<String, WgError> {
    let mut stream = api_connect(interface)?;
    stream
        .write_all(b"get=1\n")
        .map_err(|e| WgError::Backend(format!("写 API socket 失败: {e}")))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| WgError::Backend(format!("读 API socket 失败: {e}")))?;
    Ok(resp)
}

/// 把一个 peer 的完整配置追加到 `set=1` 命令体（`public_key=` 开始一个 peer 段）。
fn append_peer_config(out: &mut String, p: &PeerSpec) {
    out.push_str(&format!("public_key={}\n", key_to_hex(&p.wg_public)));
    if let Some(ep) = &p.endpoint {
        out.push_str(&format!("endpoint={}\n", SocketAddr::V6(*ep)));
    }
    for (addr, len) in &p.allowed_ips {
        out.push_str(&format!("allowed_ip={addr}/{len}\n"));
    }
    if let Some(ka) = p.persistent_keepalive {
        out.push_str(&format!("persistent_keepalive_interval={ka}\n"));
    }
}

/// 构造 `set_peer_endpoint` 的「remove + 完整 re-add」两条 `set=1` 命令体。
///
/// boringtun 0.7.1 没有「只改 endpoint」的增量操作，改 endpoint 只能先 `remove=true`
/// 删掉、再以完整配置重加。`remove_body` 填成 `public_key={hex}\nremove=true\n`；
/// `readd_body` 用 `stored` 的完整配置（allowed_ips / keepalive）但把 endpoint 换成
/// `new_endpoint`。纯函数（不碰 socket、不碰锁），可无 root 单测。
fn peer_replacement(
    remove_body: &mut String,
    readd_body: &mut String,
    stored: &PeerSpec,
    new_endpoint: SocketAddrV6,
) {
    remove_body.clear();
    remove_body.push_str(&format!(
        "public_key={}\nremove=true\n",
        key_to_hex(&stored.wg_public)
    ));
    readd_body.clear();
    let mut updated = stored.clone();
    updated.endpoint = Some(new_endpoint);
    append_peer_config(readd_body, &updated);
}

/// 收尾一个 peer 状态：把"距上次握手的时长"换算成近似绝对 `SystemTime`。
///
/// boringtun 的 `get=1` 只给 `last_handshake_time_sec`/`_nsec`（相对时长），没有
/// 内核 netlink 后端那种绝对时间戳；这里用 `SystemTime::now() - 时长` 做 best-effort
/// 换算。无握手记录时（`secs == None`）`last_handshake` 保持 `None`。
fn finish_peer(mut p: PeerStatus, secs: Option<u64>, nsecs: Option<u32>) -> PeerStatus {
    if let Some(secs) = secs {
        let dur = Duration::new(secs, nsecs.unwrap_or(0));
        p.last_handshake = SystemTime::now().checked_sub(dur);
    }
    p
}

/// 解析 `get=1` 响应为 peer 状态列表。
fn parse_status(resp: &str) -> Result<Vec<PeerStatus>, WgError> {
    let mut peers: Vec<PeerStatus> = Vec::new();
    let mut current: Option<PeerStatus> = None;
    let mut hs_secs: Option<u64> = None;
    let mut hs_nsecs: Option<u32> = None;

    for line in resp.lines() {
        let line = line.trim_end();
        if let Some(v) = line.strip_prefix("errno=") {
            let errno = v
                .trim()
                .parse::<i32>()
                .map_err(|_| WgError::Backend(format!("无法解析 errno 行: {line:?}")))?;
            if errno != 0 {
                return Err(WgError::Backend(format!(
                    "boringtun get=1 返回 errno={errno}"
                )));
            }
            break;
        }
        if let Some(hex) = line.strip_prefix("public_key=") {
            if let Some(p) = current.take() {
                peers.push(finish_peer(p, hs_secs, hs_nsecs));
            }
            let key = hex_to_key(hex)
                .ok_or_else(|| WgError::Backend(format!("非法 public_key 十六进制: {hex:?}")))?;
            current = Some(PeerStatus {
                wg_public: key,
                endpoint: None,
                last_handshake: None,
                rx_bytes: 0,
                tx_bytes: 0,
            });
            hs_secs = None;
            hs_nsecs = None;
        } else if let Some(addr) = line.strip_prefix("endpoint=") {
            if let Some(p) = current.as_mut() {
                p.endpoint = addr.parse::<SocketAddr>().ok();
            }
        } else if let Some(s) = line.strip_prefix("last_handshake_time_sec=") {
            hs_secs = s.trim().parse().ok();
        } else if let Some(s) = line.strip_prefix("last_handshake_time_nsec=") {
            hs_nsecs = s.trim().parse().ok();
        } else if let Some(s) = line.strip_prefix("rx_bytes=") {
            if let Some(p) = current.as_mut() {
                p.rx_bytes = s.trim().parse().unwrap_or(0);
            }
        } else if let Some(s) = line.strip_prefix("tx_bytes=") {
            if let Some(p) = current.as_mut() {
                p.tx_bytes = s.trim().parse().unwrap_or(0);
            }
        }
        // 其余行（own_public_key / listen_port / preshared_key / allowed_ip /
        // persistent_keepalive_interval）与本状态无关，忽略。
    }
    if let Some(p) = current.take() {
        peers.push(finish_peer(p, hs_secs, hs_nsecs));
    }
    Ok(peers)
}

/// 读取当前已存在的 peer 公钥集合（用于在 `add_peer` 前规避 boringtun 的 panic）。
fn peer_keys(interface: &str) -> Result<HashSet<[u8; 32]>, WgError> {
    let resp = api_get(interface)?;
    Ok(parse_status(&resp)?
        .into_iter()
        .map(|p| p.wg_public)
        .collect())
}

impl WgBackend for UserspaceBackend {
    /// 幂等创建/复用 boringtun 设备并整体重放配置，返回 OS 层真实设备名。
    ///
    /// **ADR-0009 决策 2/3 已落地**：Linux 恒等返回 `spec.interface.clone()`（内核 WG
    /// 设备名即配置名）；macOS 把配置名 `hextet0` 映射为裸 `utun`、经
    /// `WG_TUN_NAME_FILE` 读回真实 `utunN`，并以真实名作为注册表键与 `api_set` 目标。
    /// 第二次 `apply` 同一逻辑名会复用已登记的真实名，不再创建第二个设备（幂等）。
    ///
    /// **诚实边界**：macOS 的真实设备运行时路径需要 root + 真实 utun，本开发机未
    /// 真机验证，仅 `cargo build` 编译验证；Linux 路径行为不变。
    fn apply(&self, spec: &DeviceSpec) -> Result<String, WgError> {
        // 锁顺序约定（避免死锁）：永远先 `aliases` 后 `devices`，两个锁都在本作用域
        // 内获取并释放，绝不跨下面的 `api_set` 调用持有。
        let real_name = {
            let mut aliases = self
                .aliases
                .lock()
                .map_err(|_| WgError::Backend("aliases 注册表锁中毒".into()))?;
            let mut devices = self
                .devices
                .lock()
                .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;

            // 幂等：逻辑名已映射过 → 复用真实名，不再创建第二个设备。
            if let Some(real) = aliases.get(&spec.interface) {
                real.clone()
            } else {
                let real = self.create_device(&mut devices, &spec.interface)?;
                aliases.insert(spec.interface.clone(), real.clone());
                real
            }
        };

        // `replace_peers=true` 让 boringtun 先 clear_peers 再重加——这正是内核后端
        // `replace_peers()` 的语义，也绕开"修改已有 peer 会 panic"的限制。每次 apply
        // 都重放，保证幂等收敛到 spec 状态；真实名（macOS 上是 utunN）用于 `api_set`。
        //
        // 同步 `peer_specs` 注册表：apply 之后设备 peer 集合 == spec.peers，注册表也
        // 须精确等于 spec.peers，否则后续 `set_peer_endpoint` 的 remove+re-add 会拿到
        // 过期的 allowed_ips/keepalive。独立短作用域获取 `peer_specs`，绝不与上面已
        // 释放的 `aliases`/`devices` 同时持有。
        {
            let mut specs = self
                .peer_specs
                .lock()
                .map_err(|_| WgError::Backend("peer_specs 注册表锁中毒".into()))?;
            specs.clear();
            for p in &spec.peers {
                specs.insert(p.wg_public, p.clone());
            }
        }

        let mut cmd = String::new();
        cmd.push_str(&format!("private_key={}\n", key_to_hex(&spec.wg_secret)));
        cmd.push_str(&format!("listen_port={}\n", spec.listen_port));
        cmd.push_str("replace_peers=true\n");
        for p in &spec.peers {
            append_peer_config(&mut cmd, p);
        }
        api_set(&real_name, &cmd)?;
        Ok(real_name)
    }

    fn down(&self, interface: &str) -> Result<(), WgError> {
        // macOS 的 utun 在所有 fd 关闭时自动销毁：从注册表移除（含逻辑名映射）即
        // drop `DeviceHandle`、关闭 utun。幂等：不在册也返回 Ok（ADR-0009 决策 5）。
        // `interface` 既可能是逻辑名（hextet0）也可能是真实名（utunN）；两者都清理。
        let mut aliases = self
            .aliases
            .lock()
            .map_err(|_| WgError::Backend("aliases 注册表锁中毒".into()))?;
        let mut devices = self
            .devices
            .lock()
            .map_err(|_| WgError::Backend("devices 注册表锁中毒".into()))?;
        let real = aliases
            .get(interface)
            .cloned()
            .unwrap_or_else(|| interface.to_owned());
        aliases.remove(interface);
        // 反向清理：任何映射到同一真实名的逻辑名都一并移除（保证 aliases/devices 同步）。
        aliases.retain(|_, v| v != &real);
        devices.remove(&real);
        Ok(())
    }

    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        let name = self.resolve(interface)?;
        let resp = api_get(&name)?;
        parse_status(&resp)
    }

    /// 更新单个 peer 的 endpoint，走「remove + 完整 re-add」重建路径。
    ///
    /// boringtun 0.7.1 没有「只改 endpoint」的增量操作（`update_peer` 对已存在 peer
    /// 直接 `panic!`），所以这里先从 `peer_specs` 注册表取回该 peer 的完整
    /// [`PeerSpec`]（allowed_ips / keepalive），`remove=true` 删掉后用新 endpoint 完整
    /// 重加。功能正确，但比内核后端真正的增量更新重（每次 endpoint 轮换是两次
    /// `set=1` 往返）。要求该 peer 已先经 `apply`/`add_peer` 登记，否则诚实返回
    /// `WgError::Backend`。
    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError> {
        // 先解析逻辑名/真实名（`resolve` 映射 `hextet0 → utunN`），再查注册表。
        let name = self.resolve(interface)?;
        // 查注册表、克隆出完整 PeerSpec 再放锁——绝不跨下面的 socket 调用持有
        // `peer_specs`。未跟踪（尚未 apply/add_peer）的 peer 直接诚实报错，不碰 socket。
        let stored = {
            let specs = self
                .peer_specs
                .lock()
                .map_err(|_| WgError::Backend("peer_specs 注册表锁中毒".into()))?;
            specs.get(wg_public).cloned().ok_or_else(|| {
                WgError::Backend(format!(
                    "boringtun 后端未跟踪该 peer（须先 apply/add_peer）：{}",
                    key_to_hex(wg_public)
                ))
            })?
        };

        // remove + re-add：先删，再以完整配置 + 新 endpoint 重加。
        let mut remove_body = String::new();
        let mut readd_body = String::new();
        peer_replacement(&mut remove_body, &mut readd_body, &stored, endpoint);
        api_set(&name, &remove_body)?;
        api_set(&name, &readd_body)?;

        // 回写最新 endpoint，让后续轮换反映当前值。
        let mut specs = self
            .peer_specs
            .lock()
            .map_err(|_| WgError::Backend("peer_specs 注册表锁中毒".into()))?;
        if let Some(s) = specs.get_mut(wg_public) {
            s.endpoint = Some(endpoint);
        }
        Ok(())
    }

    fn add_peer(&self, interface: &str, spec: &PeerSpec) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        // 先查现有 peer 集合：boringtun 对已存在 peer 的 update_peer 会 panic，这里
        // 提前拦截（gossip 重复准入时返回明确错误，而非崩）。
        let existing = peer_keys(&name)?;
        if existing.contains(&spec.wg_public) {
            return Err(WgError::Backend(format!(
                "boringtun 0.7.1 不能修改已存在的 peer：{}（remove + re-add 才行）",
                key_to_hex(&spec.wg_public)
            )));
        }
        let mut cmd = String::new();
        append_peer_config(&mut cmd, spec);
        api_set(&name, &cmd)?;
        // 成功后登记完整 PeerSpec，供后续 `set_peer_endpoint` 重建用。
        self.peer_specs
            .lock()
            .map_err(|_| WgError::Backend("peer_specs 注册表锁中毒".into()))?
            .insert(spec.wg_public, spec.clone());
        Ok(())
    }

    fn remove_peer(&self, interface: &str, wg_public: &[u8; 32]) -> Result<(), WgError> {
        let name = self.resolve(interface)?;
        // `remove=true` 走 update_peer 的 remove 分支，不 panic。
        let cmd = format!("public_key={}\nremove=true\n", key_to_hex(wg_public));
        api_set(&name, &cmd)?;
        // 同步注册表，避免 `set_peer_endpoint` 用已删除的 peer 重建。
        self.peer_specs
            .lock()
            .map_err(|_| WgError::Backend("peer_specs 注册表锁中毒".into()))?
            .remove(wg_public);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::{Tunn, TunnResult};
    use boringtun::x25519::{PublicKey, StaticSecret};

    #[test]
    fn hex_roundtrip() {
        let key = [
            0x00, 0x01, 0x7f, 0x80, 0xff, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        let encoded = key_to_hex(&key);
        assert_eq!(encoded.len(), 64);
        assert_eq!(hex_to_key(&encoded), Some(key));
        assert_eq!(hex_to_key("zz"), None);
        assert_eq!(hex_to_key(&encoded[..63]), None);
    }

    #[test]
    fn resolve_maps_logical_name_to_real_device() {
        let backend = UserspaceBackend::new();
        backend
            .aliases
            .lock()
            .unwrap()
            .insert("hextet0".to_owned(), "utun3".to_owned());
        // 逻辑名 → 真实名；真实名 → 原样；未知名 → 原样（Linux 恒等 / 尚未 apply）。
        assert_eq!(backend.resolve("hextet0").unwrap(), "utun3");
        assert_eq!(backend.resolve("utun3").unwrap(), "utun3");
        assert_eq!(backend.resolve("unknown").unwrap(), "unknown");
    }

    #[test]
    fn peer_config_line_format() {
        let peer = PeerSpec {
            wg_public: [0xab; 32],
            endpoint: Some("[2001:db8::9]:4193".parse().unwrap()),
            allowed_ips: vec![
                ("fd00::1".parse().unwrap(), 128),
                ("fd00::2".parse().unwrap(), 64),
            ],
            persistent_keepalive: Some(25),
        };
        let mut cmd = String::new();
        append_peer_config(&mut cmd, &peer);
        assert!(cmd.starts_with("public_key="));
        assert!(cmd.contains("endpoint=[2001:db8::9]:4193\n"));
        assert!(cmd.contains("allowed_ip=fd00::1/128\n"));
        assert!(cmd.contains("allowed_ip=fd00::2/64\n"));
        assert!(cmd.contains("persistent_keepalive_interval=25\n"));
        // 私钥绝不能以明文 hex 形式混进 peer 段以外的地方——这里只有公钥。
        assert_eq!(cmd.matches("public_key=").count(), 1);
    }

    #[test]
    fn peer_replacement_bodies() {
        let stored = PeerSpec {
            wg_public: [0xab; 32],
            endpoint: Some("[2001:db8::1]:51820".parse().unwrap()),
            allowed_ips: vec![("fd00::1".parse().unwrap(), 128)],
            persistent_keepalive: Some(25),
        };
        let new_endpoint: SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();

        let mut remove_body = String::new();
        let mut readd_body = String::new();
        peer_replacement(&mut remove_body, &mut readd_body, &stored, new_endpoint);

        // remove body：public_key= 开头 + remove=true。
        assert!(remove_body.starts_with("public_key="));
        assert!(remove_body.contains(&key_to_hex(&stored.wg_public)));
        assert!(remove_body.contains("remove=true\n"));

        // re-add body：新 endpoint + 保留 allowed_ips / keepalive。
        assert!(readd_body.contains("endpoint=[2001:db8::9]:4193\n"));
        assert!(!readd_body.contains("[2001:db8::1]:51820"));
        assert!(readd_body.contains("allowed_ip=fd00::1/128\n"));
        assert!(readd_body.contains("persistent_keepalive_interval=25\n"));
        assert_eq!(readd_body.matches("public_key=").count(), 1);
    }

    #[test]
    fn set_peer_endpoint_unknown_peer_errs_without_socket() {
        // 空后端（无 peer_specs）——查表即失败，绝不触碰任何 socket / 不需要 root。
        let backend = UserspaceBackend::new();
        let result =
            backend.set_peer_endpoint("hextet0", &[9u8; 32], "[2001:db8::9]:4193".parse().unwrap());
        assert!(result.is_err(), "未跟踪的 peer 必须返回 Err");
    }

    #[test]
    fn status_parses_get_response() {
        let resp = concat!(
            "own_public_key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "listen_port=4193\n",
            "public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            "endpoint=[2001:db8::9]:4193\n",
            "allowed_ip=fd00::1/128\n",
            "last_handshake_time_sec=3\n",
            "last_handshake_time_nsec=500000000\n",
            "rx_bytes=100\n",
            "tx_bytes=200\n",
            "errno=0\n",
        );
        let peers = parse_status(resp).unwrap();
        assert_eq!(peers.len(), 1);
        let p = &peers[0];
        assert_eq!(p.wg_public, [0xaa; 32]);
        assert_eq!(p.endpoint, Some("[2001:db8::9]:4193".parse().unwrap()));
        assert_eq!(p.rx_bytes, 100);
        assert_eq!(p.tx_bytes, 200);
        // 相对时长被换算成"过去的某个时刻"（近似绝对时间）。
        let hs = p.last_handshake.expect("有握手记录");
        let elapsed = SystemTime::now().duration_since(hs).unwrap();
        assert!(elapsed >= Duration::from_secs(3), "elapsed={elapsed:?}");
        assert!(elapsed < Duration::from_secs(60), "elapsed={elapsed:?}");
    }

    /// 构造一个最小的合法 IPv6 包：40 字节头 + payload（version=6、payload 长度、
    /// 源/目的地址都填对，供 `Tunn` 的 `validate_decapsulated_packet` 解析）。
    fn ipv6_packet(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload.len()];
        p[0] = 0x60; // version 6，traffic class / flow label 高位为 0
        p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        p[6] = 17; // next header = UDP（真实感，供长度校验）
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..].copy_from_slice(payload);
        p
    }

    /// 用 boringtun 的 `noise::Tunn` 抽象在进程内完成一次 WireGuard 握手 + 一个 IPv6
    /// 数据包从 A 的"隧道"到 B 的"隧道"的完整往返。
    ///
    /// 这是 ADR-0007 决策 4 要求、且在本机 macOS 上**可测**的运行时证明：全程只碰
    /// `Tunn`（点对点 noise 隧道）的内存缓冲，不碰真实 utun/TUN、不碰 UDP socket、
    /// 不需要 root。`Device`/`DeviceHandle`（真实数据面）需要 root，无法在本机测，
    /// 但二者的数据面核心正是这个 `Tunn`——同一份握手/加解密代码。
    #[test]
    fn in_process_handshake_and_ipv6_roundtrip() {
        // 固定测试密钥（避免引入 rand 依赖；生产密钥由 config/身份派生，与这里无关）。
        let a_secret = StaticSecret::from([0x11u8; 32]);
        let b_secret = StaticSecret::from([0x22u8; 32]);
        let a_public = PublicKey::from(&a_secret);
        let b_public = PublicKey::from(&b_secret);

        let mut a = Tunn::new(a_secret, b_public, None, None, 1, None);
        let mut b = Tunn::new(b_secret, a_public, None, None, 2, None);

        // 1. 握手：init → resp → keepalive。
        let mut buf = vec![0u8; 2048];
        let init = match a.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("预期握手 init，得到 {other:?}"),
        };
        let resp = match b.decapsulate(None, &init, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("预期握手 response，得到 {other:?}"),
        };
        let keepalive = match a.decapsulate(None, &resp, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("预期 keepalive，得到 {other:?}"),
        };
        match b.decapsulate(None, &keepalive, &mut buf) {
            TunnResult::Done => {}
            other => panic!("预期 keepalive 收尾为 Done，得到 {other:?}"),
        }

        // 2. 数据往返：A → B。
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let packet = ipv6_packet(src, dst, b"hello hextet overlay");

        let wg_pkt = match a.encapsulate(&packet, &mut buf) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("预期数据包封装，得到 {other:?}"),
        };
        let (recv, src_addr) = match b.decapsulate(None, &wg_pkt, &mut buf) {
            TunnResult::WriteToTunnelV6(p, addr) => (p.to_vec(), addr),
            other => panic!("预期 WriteToTunnelV6，得到 {other:?}"),
        };
        assert_eq!(recv, packet, "A→B 数据包必须逐字节完整到达");
        assert_eq!(
            src_addr,
            std::net::Ipv6Addr::from(src),
            "源地址应被正确解析"
        );
    }
}
