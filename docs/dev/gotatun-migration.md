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

## 5. slice 3-4 实现要点（2026-08-14 源码核实）

以下 API 均已在 gotatun 0.8.1 源码中核实（`src/device/{builder,mod,configure}.rs`、
`src/udp/mod.rs`），是后端重写的精确规格。

**a. sync→async 桥**：`WgBackend` trait 是**同步**的（`fn apply(...) -> Result<...>`），
gotatun 的 `Device` 是**异步**（tokio）的。桥接方案：`UserspaceBackend` 持有
`tokio::runtime::Runtime`（`new()` 时建一个多线程 runtime），每个 `WgBackend` 方法用
`self.rt.block_on(async { ... })` 包裹。`DeviceBuilder::build().await` 内部会
`Connection::set_up(inner).await` 并 **spawn 后台任务**（TUN 出站/入站、定时器）到
**当前 runtime**；只要 build 与后续 read/write 都走**同一个** runtime 的 `block_on`，
后台任务就持续跑在该 runtime 的 worker 上。这是「在同步库里内嵌 runtime」的标准姿势。

**b. 构建设备（`apply`）**：
```rust
let dev = DeviceBuilder::default()
    .with_private_key(static_secret)          // x25519 StaticSecret
    .with_peers(vec![Peer { endpoint, allowed_ips, persistent_keepalive, .. }])
    .with_listen_port(spec.listen_port)       // 固定 UDP 端口（IPv6）
    .with_default_udp()                       // UdpSocketFactory（绑 [::]:port + 0.0.0.0:port）
    .create_tun(interface)?                   // tun crate 的 TunDevice（utun/wintun/TUN）
    .build().await?;                          // 内部已 set_up + spawn 后台任务
```
`Peer` 字段：`endpoint: Option<SocketAddr>`、`allowed_ips: Vec<IpNetwork>`、`persistent_keepalive`
（`Peer::with_endpoint`/`with_allowed_ips`/`with_persistent_keepalive` 构造）。

**c. 状态/配置（`status`/`add_peer`/`remove_peer`/`set_peer_endpoint`）**：`Device` 提供
**异步闭包访问器**（configure.rs:435/460）：
```rust
// 读：peer 状态 + 统计
let peers: Vec<PeerStats> = dev.read(|r| async { r.peers().await }).await?;
//   PeerStats { peer: Peer, stats: Stats { last_handshake: Option<Duration>, rx_bytes, tx_bytes } }
// 写：运行时增删/改 peer
dev.write(|w| async { w.add_peer(peer).await }).await?;      // Result<bool, Error>
dev.write(|w| async { w.remove_peer(&pubkey).await }).await?; // Result<bool, Error>
dev.write(|w| async { w.modify_peer(&pubkey, |p| { p.set_endpoint(Some(addr)); }).await }).await?;
```
`WgBackend::status` 的 `wg_public`（32 字节 x25519 公钥）与 `Peer.public_key` 直接对齐；
`rx/tx_bytes` 从 `Stats` 取、`last_handshake` 从 `Stats.last_handshake` 取。

**d. 停止（`down`）**：`dev.stop().await`（`Device` 也实现 `Drop`，drop 即停）。从
`devices: Mutex<HashMap<String, Device>>` 取出并 `block_on(stop)`。

**e. 数据面密钥**：`DeviceSpec` 里的私钥（32 字节）→ `x25519::StaticSecret::from(bytes)`；
peer 公钥 → `x25519::PublicKey::from(bytes)`。gotatun 的 `x25519` 从 `gotatun::x25519`
re-export（`StaticSecret`/`PublicKey`）。

**f. 保留的既有语义**：`aliases`（逻辑名→真实 utun 名映射，ADR-0009 决策 2）在新后端仍
需要——`apply` 后读回真实接口名并登记；`set_peer_endpoint` 改用 `modify_peer` 的**增量**
endpoint 更新（收敛 ADR-0007 记录的 boringtun remove+re-add 缺口）。

