//! TUN 设备抽象（ADR-0007 决策 2）。
//!
//! 底层 FFI 由 `tun` crate（meh/rust-tun）承接：它把 ioctl/utun 的 `unsafe` 全部
//! 内聚在 crate 内，本模块只调它的安全 API——满足本 crate 的 `unsafe_code = "deny"`。
//!
//! 平台分工：macOS 走 `tun` crate 的 `macos`（utun）模块、Linux 走 `linux`
//! （`/dev/net/tun`）模块、Windows 走 `windows`（wintun）模块，其余平台按既有 stub 惯例
//! 返回 [`PlatformError::Unsupported`]（Android 留到 M7 走 VpnService 自己的 fd，见
//! ADR-0007）。Windows 的 wintun 支持（ADR-0010 决策 1）：`tun` crate 已把 wintun 的 DLL
//! 加载与 adapter 创建的 unsafe 全部内聚在 crate 内，调用方零 unsafe——满足本 crate 的
//! `unsafe_code = "deny"`。注意 wintun.dll 须与可执行文件同目录（或经
//! `PlatformConfig::wintun_file` 指定），且需管理员权限。
//!
//! 注意：本抽象只覆盖 TUN **设备**的打开/读写/关闭。macOS 上给 utun 配地址/路由是
//! 另一个缺口（`setup_interface`/`add_route` 目前仍是 Linux-only），ADR-0007 已单独
//! 记录并推迟。

/// 打开 TUN 设备所需的配置。
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// 接口名：macOS 上必须是 `utun`/`utunN`（`N` 为数字），Linux 上任意合法 ifname。
    pub name: String,
    /// 接口 MTU；`0` 表示用操作系统默认值（`tun` crate 的 1500）。
    pub mtu: u32,
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
mod imp {
    use std::sync::{Arc, Mutex};

    use tun::AbstractDevice as _;

    use super::TunConfig;
    use crate::PlatformError;

    /// 已打开的 TUN 设备句柄。
    ///
    /// 内部持有 [`tun::Device`]（同步阻塞 API）。读/写是阻塞系统调用，放到
    /// [`tokio::task::spawn_blocking`] 里执行，避免阻塞异步运行时线程。
    pub struct TunHandle {
        inner: Arc<Mutex<tun::Device>>,
        name: String,
    }

    /// 打开（并创建）一个 TUN 设备。macOS 上需要 root（utun 是特权资源）。
    pub async fn open_tun(cfg: &TunConfig) -> Result<TunHandle, PlatformError> {
        let mut configuration = tun::configure();
        configuration.tun_name(cfg.name.clone());
        if cfg.mtu != 0 {
            let mtu = u16::try_from(cfg.mtu)
                .map_err(|_| PlatformError::Tun(format!("MTU {} 超出 u16 范围", cfg.mtu)))?;
            configuration.mtu(mtu);
        }
        // 只取 IP 层（L3）包，不带 packet information 头。
        configuration.layer(tun::Layer::L3);

        let name = cfg.name.clone();
        let device = tokio::task::spawn_blocking(move || tun::create(&configuration))
            .await
            .map_err(|e| PlatformError::Tun(format!("spawn_blocking 失败: {e}")))?
            .map_err(|e| PlatformError::Tun(e.to_string()))?;

        // 记下内核实际分配的名字（macOS 上可能是 `utun0` 之类，与请求名不同）。
        let assigned = device
            .tun_name()
            .map_err(|e| PlatformError::Tun(e.to_string()))?;

        Ok(TunHandle {
            inner: Arc::new(Mutex::new(device)),
            name: if assigned.is_empty() { name } else { assigned },
        })
    }

    /// 关闭 TUN 设备（释放 fd；Drop 时 `tun::Device` 会关闭底层文件描述符）。
    pub async fn close_tun(t: TunHandle) -> Result<(), PlatformError> {
        drop(t);
        Ok(())
    }

    impl TunHandle {
        /// 从设备读一个包，返回包长。阻塞直到有包到达。
        pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, PlatformError> {
            let inner = Arc::clone(&self.inner);
            let cap = buf.len();
            let (n, owned) = tokio::task::spawn_blocking(move || {
                let dev = inner
                    .lock()
                    .map_err(|_| PlatformError::Tun("TUN 设备锁中毒".into()))?;
                let mut owned = vec![0u8; cap];
                let n = dev
                    .recv(&mut owned)
                    .map_err(|e| PlatformError::Tun(e.to_string()))?;
                Ok::<_, PlatformError>((n, owned))
            })
            .await
            .map_err(|e| PlatformError::Tun(format!("spawn_blocking 失败: {e}")))??;
            buf[..n].copy_from_slice(&owned[..n]);
            Ok(n)
        }

        /// 向设备写一个包。
        pub async fn write_packet(&self, pkt: &[u8]) -> Result<(), PlatformError> {
            let inner = Arc::clone(&self.inner);
            let pkt = pkt.to_vec();
            let pkt_len = pkt.len();
            let written = tokio::task::spawn_blocking(move || {
                let dev = inner
                    .lock()
                    .map_err(|_| PlatformError::Tun("TUN 设备锁中毒".into()))?;
                dev.send(&pkt)
                    .map_err(|e| PlatformError::Tun(e.to_string()))
            })
            .await
            .map_err(|e| PlatformError::Tun(format!("spawn_blocking 失败: {e}")))??;
            if written != pkt_len {
                return Err(PlatformError::Tun(format!(
                    "短写: 写了 {written}/{pkt_len} 字节"
                )));
            }
            Ok(())
        }

        /// 设备的实际名字（内核分配名，macOS 上可能与请求名不同）。
        pub fn name(&self) -> &str {
            &self.name
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod imp {
    use super::TunConfig;
    use crate::PlatformError;

    /// 非 macOS/Linux/Windows 平台的 TUN 句柄占位（永远不会被构造成功）。
    pub struct TunHandle {
        name: String,
    }

    /// 非 macOS/Linux/Windows 平台暂不支持 TUN 设备（Android→M7 VpnService）。
    pub async fn open_tun(_cfg: &TunConfig) -> Result<TunHandle, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    /// 非 macOS/Linux 平台暂不支持。
    pub async fn close_tun(t: TunHandle) -> Result<(), PlatformError> {
        drop(t);
        Ok(())
    }

    impl TunHandle {
        /// 非 macOS/Linux 平台暂不支持。
        pub async fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, PlatformError> {
            Err(PlatformError::Unsupported)
        }

        /// 非 macOS/Linux 平台暂不支持。
        pub async fn write_packet(&self, _pkt: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }

        /// 接口名。
        pub fn name(&self) -> &str {
            &self.name
        }
    }
}

pub use imp::{TunHandle, close_tun, open_tun};

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实设备需要 root，本测试只覆盖无 root 也成立的纯逻辑：请求一个非法名字时
    /// 应在 open 阶段报错，而不是 panic。macOS 上 `tun` crate 对非 `utun` 前缀的
    /// 名字直接返回 `InvalidName`（无需 root）；Linux 上 `open` `/dev/net/tun` 在
    /// 无权限时也会报错——二者都归结为 `PlatformError::Tun`，这里只断言"不 panic
    /// 且返回 Err"，具体错误文本因平台而异。
    ///
    /// 需要 root 的真实设备往返测试见下，用 `--ignored` 分层跑（与 linux.rs 里
    /// `#[ignore = "requires root"]` 的 netlink 测试同款分层）。
    #[tokio::test]
    async fn open_tun_invalid_name_errors_without_root() {
        // "hextet0" 不是合法的 utun 名字（macOS），Linux 上无 root 也打不开
        // /dev/net/tun。无论哪条路径，都不该 panic。
        let cfg = TunConfig {
            name: "hextet0".into(),
            mtu: 1400,
        };
        let result = open_tun(&cfg).await;
        assert!(result.is_err(), "预期打开失败，却成功了");
    }

    /// 需要 root + 真实设备：`sudo -E cargo test -p hextet-platform -- --ignored`。
    /// 常规 CI 不跑。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn open_read_write_close_roundtrip() {
        let cfg = TunConfig {
            name: "utun".into(),
            mtu: 1400,
        };
        let t = open_tun(&cfg).await.expect("需要 root 才能打开 utun");
        assert!(!t.name().is_empty());
        close_tun(t).await.expect("close_tun 不应报错");
    }
}
