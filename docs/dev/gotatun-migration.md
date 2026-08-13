# gotatun 迁移计划（boringtun → gotatun，ADR-0012 落地）

> 方向依据：ADR-0007（boringtun 过渡）、ADR-0011（boringtun Unix-only 核实）、
> ADR-0012（抬 MSRV 1.95 + 定方向 gotatun）。本文档把 gotatun 0.8.1 的 API 摸清并
> 映射到 `hextet_wg::WgBackend` trait，作为 `crates/wg-userspace` 迁移的实现规格。

## 0. 已核实的事实（2026-08-14）

- gotatun **0.8.1** 在本机 macOS（stable 1.97）+ `default-features = false,
  features = ["device", "ring", "tun"]` 下 **编译通过**（scratch build 实测）。
- gotatun 是 async（tokio）实现，`Device` 内部 `Arc<RwLock<DeviceState>>`。
- gotatun 支持**运行时 peer 增删/更新**（`configure` 模块的 `add_peer`/`add_peers`/
  `update_peer`/`remove_peer`），与 `WgBackend` 的 `add_peer`/`remove_peer`/`set_peer_endpoint`
  一一对应——gossip 准入/吊销与 endpoint roaming 可以映射过去，无需重启设备。
- gotatun 暴露 peer 状态/统计：`configure` 模块产出 `Stats { rx_bytes, tx_bytes, ... }`
  与 `time_since_last_handshake`，覆盖 `WgBackend::status` 所需的 `last_handshake`/`rx`/`tx`。

## 1. gotatun API 地图（关键符号）

| 用途 | gotatun 符号 |
|---|---|
| 构建设备 | `gotatun::device::{Device, DeviceBuilder, Peer}`；`DeviceBuilder::with_private_key(StaticSecret)` → `with_peers(...)` → `with_default_udp()` / `with_udp(factory)` → `create_tun(...)` / `with_ip(...)` → `build()` → `Device<DefaultDeviceTransports>` |
| peer 配置 | `Peer { endpoint, allowed_ips, .. }`；`Peer::with_endpoint(SocketAddr)` / `with_allowed_ips(...)` / `with_persistent_keepalive(...)` |
| 运行时改 peer | `Device`（或 `configure` 句柄）的 `add_peer` / `add_peers` / `update_peer` / `remove_peer(public_key)` |
| endpoint 更新（roaming） | `configure` 的 `set_endpoint(addr)`（或 `update_peer` 重建 peer） |
| 状态/统计 | `configure` 产出 `Stats { rx_bytes, tx_bytes, .. }` + `time_since_last_handshake()` |
| 停止 | `Device::stop(self).await` / `Device::suspend` / `Device::resume` |

## 2. WgBackend → gotatun 映射

| `WgBackend` 方法 | gotatun 对应 |
|---|---|
| `apply(spec)` | 用 `spec`（interface/listen_port/peers）构建 `Device`：`with_private_key(spec.private_key 对应 x25519 StaticSecret)` + `with_peers(Peer { endpoint, allowed_ips, keepalive })` + UDP transport 绑 `listen_port` + TUN transport 用 `platform::tun` 或 `tun` crate；`build().await` 后登记进 `devices: Mutex<HashMap<String, Device>>`，返回真实接口名 |
| `status(interface)` | 经 `configure` 取每个 peer 的 `Stats`/`time_since_last_handshake`/`endpoint` → `PeerStatus` |
| `set_peer_endpoint(interface, wg_pub, ep)` | `configure` 的 `set_endpoint` / `update_peer` |
| `add_peer` / `remove_peer` | `configure` 的 `add_peer` / `remove_peer(public_key)` |
| `down(interface)` | `Device::stop(self).await` + 从注册表移除 |

## 3. 迁移切片（每片一个 commit，均可 `cargo test`/clippy 验证）

1. **依赖与 MSRV**：`crates/wg-userspace/Cargo.toml` 去掉 boringtun、加 gotatun
   `=0.8.1`（`default-features = false, features = ["device", "tun", "ring"]`）；
   根 `Cargo.toml` `rust-version = "1.95"`（ADR-0012 决策 3：与迁移同 PR 落地）。
2. **进程内噪声冒烟**（先证 gotatun 数据面可用）：仿 boringtun 的 `noise::Tunn` 测试，
   用 gotatun 的 `Device` + loopback 传输入口，证明握手 + IPv6 包往返（无真实网卡、无 root）。
3. **`UserspaceBackend::apply` + `status`**：重写核心两方法，`MockBackend` 不变。
4. **`set_peer_endpoint`/`add_peer`/`remove_peer`/`down`**：映射到 `configure`，补增量
   endpoint 更新的单测（这是 ADR-0007 记录的 boringtun `set_peer_endpoint` 缺口的收敛点）。
5. **文档同步**：CHANGELOG、ADR-0007/0011/0012 的「已落地」标注、README 状态行。

## 4. 关键风险与诚实边界

- **transports 接线**是最大不确定点：gotatun 的 `DefaultDeviceTransports` 默认 UDP socket +
  TUN 设备；hextet 需要 UDP 绑**固定 `listen_port`**（IPv6）且 TUN 走 `tun` crate 的
  wintun/utun/TUN 分支。若 `DefaultDeviceTransports` 不支持定制监听端口/接口名，需自写
  `DeviceTransports` 实现（`with_udp`/`with_ip` 的定制 factory）。
- **`status` 的 peer 键匹配**：gotatun 用 x25519 `PublicKey`（32 字节），与 `WgBackend::status`
  返回的 `wg_public`（32 字节）直接对齐；按公钥 join 即可。
- **验证姿态**：macOS/Linux 编译 + 进程内噪声测试可本机全绿；Windows/Android 的 wintun/
  VpnService 运行时仍需 CI/真机（ADR-0012 决策 4）。gotatun 是 pre-1.0，锁死 `=0.8.1` +
  `cargo deny` 常开。
- **迁移不影响 Linux 内核后端**：Linux 仍走 `KernelBackend`；gotatun 只替换 macOS 的
  boringtun，并成为 Windows/Android 的数据面。
