//! 裸 fd 的 TUN 传输（M7 切片 C 的 Android 数据面核心，见
//! docs/superpowers/plans/2026-08-14-m7-android.md）。
//!
//! Android 的 `VpnService.Builder.establish()` 返回一个 fd：read 出 IP 包、write 进
//! IP 包——与 Linux TUN 同语义，但**不是** `tun` crate 能开的设备。gotatun 的
//! `DeviceBuilder::with_ip` 只要求一个 `IpSend + IpRecv`，本模块把这个 fd 包成满足
//! 该约束的传输，让 `UserspaceBackend::apply` 未来能经它吃 VpnService fd（不经
//! `TunDevice::from_name`）。
//!
//! 本模块是纯 Rust、平台无关到 `cfg(unix)`（Android/Linux/macOS 都是 Unix 系 fd）；
//! Windows 走 `tun` crate 的 wintun 分支（`TunDevice::from_name`），不用这个适配器。

// unsafe 只存在于 fcntl/read/write 这三处 fd 系统调用（收窄封装，无副作用）；
// workspace 默认 deny unsafe_code，这里与 platform::macos / engine-ffi 同款放行。
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// 非拥有式的裸 fd 包装：实现 [`AsRawFd`] 供 `AsyncFd` 用，`Drop` 时**不**关闭 fd
/// （fd 由调用方——Android 的 VpnService / 测试的 socketpair——持有）。
struct BorrowedFd(RawFd);

impl AsRawFd for BorrowedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// 把裸 fd 上的 IP 包流适配成 gotatun 的 [`IpSend`] + [`IpRecv`]。
pub struct RawFdTun {
    fd: Arc<AsyncFd<BorrowedFd>>,
    mtu: u16,
}

impl RawFdTun {
    /// 包装一个裸 fd：置非阻塞 + 注册进 tokio reactor。
    ///
    /// `mtu` 是该 fd 承载的 IP 包上限（Android 的 VpnService 由系统决定，Linux TUN
    /// 由创建时决定）；传给 gotatun 的 `MtuWatcher` 作为常数。
    pub fn from_fd(fd: RawFd, mtu: u16) -> io::Result<Self> {
        set_nonblocking(fd)?;
        let fd = AsyncFd::with_interest(BorrowedFd(fd), Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self {
            fd: Arc::new(fd),
            mtu,
        })
    }
}

/// 把 fd 置为非阻塞（`AsyncFd` 要求 fd 非阻塞，否则 reactor 的 epoll/kqueue 会
/// 等不到边缘事件）。unsafe 圈在 fcntl 这一处，无副作用。
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl 只读写本 fd 的 flags。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl 只写本 fd 的 flags。
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl IpSend for RawFdTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        let buf: &[u8] = &bytes;
        let mut written = 0;
        while written < buf.len() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                // SAFETY: write 到调用方给的 fd；BorrowedFd 语义不 close。
                let ret = unsafe {
                    libc::write(
                        inner.as_raw_fd(),
                        buf[written..].as_ptr() as *const libc::c_void,
                        (buf.len() - written) as libc::size_t,
                    )
                };
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(ret as usize)
                }
            }) {
                Ok(Ok(n)) => written += n,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

impl IpRecv for RawFdTun {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut packet = pool.get();
        let n = {
            let buf: &mut [u8] = &mut packet;
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|inner| {
                    // SAFETY: read 到调用方给的 fd；BorrowedFd 语义不 close。
                    let ret = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len() as libc::size_t,
                        )
                    };
                    if ret < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(ret as usize)
                    }
                }) {
                    Ok(Ok(n)) => break n,
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        };
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(std::iter::once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use bytes::BytesMut;

    /// 构造一个最小合法 IPv6 包（40 字节头 + payload；与 gotatun_noise.rs 同款）。
    fn ipv6_packet(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload.len()];
        p[0] = 0x60; // version 6
        p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        p[6] = 17; // next header = UDP
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p[40..].copy_from_slice(payload);
        p
    }

    /// 经 socketpair 验证 send（write）与 recv（read + 解析 IP）两个方向都通。
    #[tokio::test]
    async fn send_and_recv_roundtrip_over_socketpair() {
        // socketpair：写 a 读 b、写 b 读 a。把 b 交给 RawFdTun，a 当"对端 app"。
        let (mut app, b) = UnixStream::pair().unwrap();
        let mut tun = RawFdTun::from_fd(b.as_raw_fd(), 1500).unwrap();

        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let bytes = ipv6_packet(src, dst, b"hello raw-fd tun");

        // 1) send：IpSend 把 IP 包写进 fd（→ socketpair 的 app 端）
        let packet = Packet::from_bytes(BytesMut::from(&bytes[..]))
            .try_into_ip()
            .expect("IPv6 包应能解析成 Packet<Ip>");
        tun.send(packet).await.unwrap();

        let mut buf = [0u8; 1500];
        let n = app.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &bytes[..], "send 应把完整 IP 包写进 fd");

        // 2) recv：app 端写一个 IP 包，IpRecv 从 fd 读回并解析
        app.write_all(&bytes).unwrap();
        let mut pool = PacketBufPool::new(4);
        let recv = tun.recv(&mut pool).await.unwrap().collect::<Vec<_>>();
        assert_eq!(recv.len(), 1, "recv 应返回一个包");
        let recv_bytes: &[u8] = &recv.into_iter().next().unwrap().into_bytes();
        assert_eq!(recv_bytes, &bytes[..], "recv 应读回并解析出原 IP 包");
    }
}
