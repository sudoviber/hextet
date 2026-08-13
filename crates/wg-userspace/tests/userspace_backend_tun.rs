//! `UserspaceBackend` 真实 TUN 数据面冒烟：`apply → status → set_peer_endpoint →
//! add_peer → remove_peer → down` 全链路。
//!
//! 这是 `WgBackend` 用户态后端的**运行时**验证缺口（ADR-0012 决策 4 的「真实数据面
//! 运行时验证留真机/CI」）：`tests/gotatun_noise.rs` 只碰内存缓冲（不碰真实 TUN），
//! 本测试则开真实 TUN（Linux `/dev/net/tun` / macOS `utun`），验证 gotatun `Device` +
//! `TunDevice` 这一层确实能建起设备、读回 peer、增量改 endpoint、运行时增删 peer、并
//! 干净拆除。
//!
//! 需要 root，否则**跳过**（不失败）：
//! - Linux：由 `scripts/e2e-docker.sh` 的 `--privileged` 容器（linuxkit 内核带
//!   `/dev/net/tun`、进程是 root）真正跑起来；
//! - macOS：`sudo cargo test -p hextet-wg-userspace --test userspace_backend_tun`
//!   真机 root 跑（`apply` 在 macOS 上请求裸 `utun` 并读回真实 `utunN`）。

#![allow(unsafe_code)] // 只此一处：libc::geteuid 探测 root，无副作用

use std::net::{SocketAddr, SocketAddrV6};

use hextet_wg::WgBackend;
use hextet_wg::types::{DeviceSpec, PeerSpec, WgError};
use hextet_wg_userspace::UserspaceBackend;

/// 是否具备跑真实 TUN 的条件：root（Linux 还要 `/dev/net/tun` 存在）。
fn can_touch_tun() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid 是 libc 的只读调用，无副作用。
        std::path::Path::new("/dev/net/tun").exists() && unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: geteuid 是 libc 的只读调用，无副作用。
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// 一个最小 peer（AllowedIPs 用文档前缀内的一个 /64）。
fn peer(pk: u8) -> PeerSpec {
    PeerSpec {
        wg_public: [pk; 32],
        endpoint: None,
        allowed_ips: vec![("2001:db8::2".parse().unwrap(), 64)],
        persistent_keepalive: Some(25),
    }
}

#[test]
fn apply_status_endpoint_add_remove_down_with_real_tun() {
    if !can_touch_tun() {
        eprintln!("跳过：需要 Linux root + /dev/net/tun（在 scripts/e2e-docker.sh 容器里跑）");
        return;
    }

    let backend = UserspaceBackend::new();
    let spec = DeviceSpec {
        interface: "hextet0".into(),
        listen_port: 41930,
        wg_secret: [0x42u8; 32],
        peers: vec![peer(0xab)],
    };

    // 1. apply：真实开 TUN（Linux /dev/net/tun），返回 OS 层真实设备名。
    let real_name = backend
        .apply(&spec)
        .expect("apply 应成功（root + /dev/net/tun）");
    eprintln!("apply → 真实设备名: {real_name}");
    assert!(!real_name.is_empty(), "apply 应返回非空真实设备名");

    // 2. status：能看到 apply 时配进去的那个 peer（公钥逐字节一致）。
    let status = backend.status("hextet0").expect("status 应成功");
    assert_eq!(status.len(), 1, "apply 配了一个 peer，status 应读回一个");
    assert_eq!(status[0].wg_public, [0xab; 32]);

    // 3. set_peer_endpoint：增量更新 endpoint，status 能读回新 endpoint。
    let ep: SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();
    backend
        .set_peer_endpoint("hextet0", &[0xab; 32], ep)
        .expect("set_peer_endpoint 应成功");
    let status = backend.status("hextet0").expect("status 应成功");
    assert_eq!(
        status[0].endpoint,
        Some(SocketAddr::V6(ep)),
        "set_peer_endpoint 后 status 应读回新 endpoint"
    );

    // 4. add_peer / remove_peer：运行时增删 peer。
    backend
        .add_peer("hextet0", &peer(0xcd))
        .expect("add_peer 应成功");
    let status = backend.status("hextet0").expect("status 应成功");
    assert_eq!(status.len(), 2, "add_peer 后应有两个 peer");
    backend
        .remove_peer("hextet0", &[0xcd; 32])
        .expect("remove_peer 应成功");
    let status = backend.status("hextet0").expect("status 应成功");
    assert_eq!(status.len(), 1, "remove_peer 后应回到一个 peer");

    // 5. down：干净拆除，之后 status 应 NotFound。
    backend.down("hextet0").expect("down 应成功");
    assert!(matches!(
        backend.status("hextet0"),
        Err(WgError::NotFound(_))
    ));
}
