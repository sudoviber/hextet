# 在 Docker 里跑 Linux-only netns E2E

`scripts/netns-e2e*.sh` 需要 Linux + root + `ip netns`（veth）+ 内核 WireGuard +
nftables + jq。macOS 上无法直接跑，但可以用一个 privileged Linux 容器完整复现。
本页记录在 Docker Desktop（macOS，aarch64）上验证过的一键流程。

## 前提

- Docker Desktop 已启动，且**容器能出网**（`docker pull` 与容器内 `apt`/`cargo`
  都能联网）。注意：Docker Desktop 的 proxy 设置若指向一个没在跑的本地代理
  （例如 Clash Verge 的 `127.0.0.1:7897`），`docker pull` 会报
  `connect: connection refused`——先修好 proxy 再继续。
- 宿主机 **不需要**装 Rust；构建在容器里做，不污染宿主机 cargo 状态。

## 关于内核 WireGuard

Docker Desktop 的 LinuxKit 内核（本机验证版本 `6.12.76-linuxkit`）把 wireguard
**编进了内核**（不是可加载模块）。所以 `modprobe wireguard` 会报
`Module wireguard not found`，但 `ip link add dev wg0 type wireguard` 能成功——
netns E2E 依赖的内核 WireGuard 是**可用**的，`modprobe` 的报错可以无视。

## 一键复现

```bash
# 1) 起一个 privileged 容器，挂只读源码 + 一个独立的 target 目录
docker run -d --name hextet-e2e --privileged \
  -v "$PWD:/ws:ro" \
  -v hextet-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e HEXTET_BIN=/target/debug/hextet \
  rust:1-bookworm sleep infinity

# 2) 装运行时依赖（脚本需要 ip/wg/nft/jq/ping，诊断需要 conntrack/tcpdump）
docker exec hextet-e2e bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    iproute2 wireguard-tools nftables jq iputils-ping kmod procps conntrack tcpdump iptables
'

# 3) 在容器里构建 Linux 二进制（落到 /target，不碰宿主机 cargo）
docker exec hextet-e2e bash -c 'cd /ws && cargo build --workspace'

# 4) 跑单个场景（或全部）
docker exec hextet-e2e bash -c 'bash /ws/scripts/netns-e2e.sh'
docker exec hextet-e2e bash -c 'bash /ws/scripts/netns-e2e-dht.sh'
# 全部八个场景：
docker exec hextet-e2e bash -c '
  cd /tmp
  for s in netns-e2e.sh netns-e2e-dynamic.sh netns-e2e-doctor.sh netns-e2e-lan.sh \
           netns-e2e-relay.sh netns-e2e-gossip.sh netns-e2e-dht.sh netns-e2e-site.sh; do
    bash /ws/scripts/$s && echo "PASS $s" || echo "FAIL $s"
  done
'

# 5) 用完清理
docker rm -f hextet-e2e
docker volume rm hextet-target
```

## 关键点

- **必须 `--privileged`**：脚本要 `ip netns add`、`ip link add veth`、`nft` 装
  状态防火墙、创建 WireGuard 接口。仅 `--cap-add=NET_ADMIN` 不够（netns 的
  mount 隔离也需要特权）。
- **源码只读挂载（`/ws:ro`）+ 独立 target（`/target`）**：构建产物与 cargo
  缓存都不落在宿主机，满足「不修改宿主机 cargo 状态」。`rust-toolchain.toml`
  指定 `stable`，容器里的 rustup 首次会拉对应工具链（需出网）。
- **`HEXTET_BIN` 指向绝对路径**：脚本默认找 `target/debug/hextet`（相对路径），
  容器里要显式指到 `/target/debug/hextet`。二进制在 netns 里也能执行（netns 只
  换网络命名空间，不换 mount 命名空间）。
- **改源码后重建**：`cargo build --workspace` 走增量，很快；脚本本身改动无需重建
  （脚本是运行时读的）。
- 场景耗时：static/dynamic/doctor/lan/site 各 ~10-30s；relay/gossip ~60s；
  dht 最慢（首次会合 60s + 换址恢复 90s 预算，实际 ~40-60s）。全套约 3 分钟。

## 验证结果（2026-08-13，Docker v29.7.2 / Docker Desktop 6.12.76-linuxkit）

八个场景全部通过（gossip 见下方「已知间歇性问题」）：

| 场景 | 结果 |
|---|---|
| static（netns-e2e.sh） | PASS |
| dynamic（netns-e2e-dynamic.sh） | PASS |
| doctor（netns-e2e-doctor.sh） | PASS |
| lan（netns-e2e-lan.sh） | PASS |
| relay（netns-e2e-relay.sh） | PASS |
| gossip（netns-e2e-gossip.sh） | PASS（间歇，见下） |
| dht（netns-e2e-dht.sh） | PASS |
| site（netns-e2e-site.sh） | PASS |

本次验证修掉了这些让「最重要的测试层」从未通过过的 bug：

1. **hextet-engine `on_discovered`（真 bug）**：会合层听到与当前连接**不同**的新地址
   时，之前 FSM 因 `Connected` 状态「不打扰」而不切换 endpoint，导致双端同时换
   前缀后 gossip/DHT 会合无法在秒级恢复（peer 卡在旧地址、`endpoint_source=cache`）。
2. **hextet-engine gossip `broadcast`（真 bug）**：收到新条目后转播时也会推进自己的
   `seq`，两个已连节点把对方带新 seq 的条目反复 Applied → 再转播 → 再推进 seq，形成
   永不收敛的 ping-pong 放大（日志狂刷「会合层更新了该 peer 的地址」、流量/CPU 无限）。
   修复后只有周期 tick 与本机地址变化才推进 seq。
3. **`netns-e2e-dht.sh`（脚本 bug）**：拓扑解析用 `:` 当分隔符，被 IPv6 地址里的
   冒号劈开，`ip addr add 2001/64` 直接报错。
4. **`netns-e2e-gossip.sh`（脚本 bug）**：没关 LAN 组播发现，三节点同 L2 时 LAN
   直连掩盖了待测的 gossip 转介路径。
5. **`netns-e2e-dynamic.sh`（脚本 bug）**：state.json 版本断言 `.version == 3` 没随
   `STATE_VERSION` 升到 5 而同步，导致 daemon 状态文件正确写入却误报「未报 connected」。

## 已知间歇性问题（未修复，非本次引入）

`netns-e2e-gossip.sh` 的**首次转介**步骤偶发失败（约 1/6 概率，重跑即过）：A↔B 经 R
转介学到彼此地址、`wg show` 也显示 endpoint 已正确设为 `[::b]`/`[::a]`，但内核
WireGuard 在部分运行里**从不发出 A↔B 的握手包**（tcpdump 4193 端口只看到 A↔R 与
B↔R 的握手，A↔B 零包），导致 30s 超时。换址恢复步骤不受影响。现象指向 Docker
Desktop LinuxKit 内核 WireGuard 在 bridge 拓扑下「无 endpoint 的 peer 被
`set_peer_endpoint` 增量更新后偶发不发起握手」的内核层时序问题，而非 hextet 代码
缺陷——同样的拓扑在直连 veth（static/dynamic/site）与 relay 场景下稳定。重跑一次
即可通过；正式 CI 建议给 gossip 场景一次重试或调大首次转介预算。

## 已知环境差异（非 bug）

- `cargo test --workspace` 在 privileged 容器里会有一个平台层测试失败：
  `hextet-platform::tun::tests::open_tun_invalid_name_errors_without_root`
  ——该测试断言「非 root 下打开 TUN 应失败」，而 privileged 容器以 root 运行、打开
  成功，属环境预期，与 netns E2E 无关。
