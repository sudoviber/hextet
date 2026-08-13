#!/usr/bin/env bash
# hextet M3 阶段 E E2E：A、B 的配置里**没有对方的 endpoint、也没有端点缓存**，
# 仅靠一个本地（离线）Mainline DHT 会合节点互相发现并连通；随后 A、B **同时**
# 换地址（换端点），仍只靠 DHT 查询到对方的新地址在秒级自动恢复。
# 这是 spec §8 M3 验收第 1 条「双端同时换前缀后经 DHT 自动恢复」的自动化证明。
#
# 为什么是本地 DHT 而不是真实 DHT：spec M3 阶段 E 明确「测试：本地 mainline testnet
# 而非真实 DHT」（docs/protocol/dht-record.md §5）。netns 里跑一个 server-mode、
# no_bootstrap 的单节点 DHT（`hextet dht node`，隐藏子命令），A、B 的 daemon 都
# bootstrap 到它、经它发布/查询会合记录——确定性、离线、秒级收敛。
#
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

BR=br-hxt6
NS_A=hxt6-a
NS_B=hxt6-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)

# IPv6 数据面：A、B 挂在同一个 L2（同一 /64 当"同一网络"）；换地址即换端点
NET=2001:db8:30
ADDR_A="${NET}::a"
ADDR_B="${NET}::b"
# 换地址后 A、B 的新地址（仍在同一 /64——netns 的 veth bridge 是单 L2，换地址即换端点）
ADDR_A2="${NET}::aa"
ADDR_B2="${NET}::bb"

# IPv4 控制面：DHT 是 IPv4 网络（spec §5「控制面弱依赖 IPv4 出站」）。网桥拿一个
# IPv4 地址当"会合点"，A、B 的 veth 各拿一个同网段 IPv4，好让 daemon 的 DHT 客户端
# 能出站到本地 DHT 节点。换前缀只动 IPv6 数据面，IPv4 控制面全程稳定。
BRIP=172.18.0.1
DHT_PORT=6881
IP_A=172.18.0.2
IP_B=172.18.0.3

# 首次会合：DHT 查询周期 30s（启动即查 + 收到即喂候选），但两侧都要靠 DHT 学到对方、
# 且要让"非发起侧"也跑过一次查询才能把 endpoint_source 从 roamed 收敛成 dht——
# 60s 给足两个查询周期 + 握手。
INITIAL_TIMEOUT=60
# 换址恢复：地址变化即重发（不依赖 30s 周期），但对方要等下一次 30s 查询才拿到新地址；
# 两侧都收敛成 dht 再给一个查询周期，90s 给 CI 抖动留足余量。
RECOVERY_TIMEOUT=90

A_PID=""
B_PID=""
DHT_PID=""

cleanup() {
  for pid in "$A_PID" "$B_PID" "$DHT_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for ns in "$NS_A" "$NS_B"; do ip netns del "$ns" 2>/dev/null || true; done
  for v in veth6-a veth6-b; do ip link del "$v" 2>/dev/null || true; done
  ip link del "$BR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

status_json() { ip netns exec "$1" "$BIN" status --json -c "$2" 2>/dev/null; }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  echo "--- dht node log (tail) ---" >&2
  tail -n 60 "$TMP/dht.log" >&2 2>&1 || true
  for pair in "a:$NS_A:$TMP/a.toml:$TMP/a-state" "b:$NS_B:$TMP/b.toml:$TMP/b-state"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; rest=${rest#*:}; cfg=${rest%%:*}; state=${rest#*:}
    echo "--- $label: status --json ---" >&2
    status_json "$ns" "$cfg" >&2 || true
    echo "--- $label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || true
    echo "--- $label: ip -6 addr ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    echo "--- $label: ip -4 addr ---" >&2
    ip netns exec "$ns" ip -4 addr >&2 2>&1 || true
    echo "--- $label: dht-nodes.json ---" >&2
    cat "$state/dht-nodes.json" >&2 2>&1 || echo "(missing)" >&2
    echo "--- $label: endpoints.json ---" >&2
    cat "$state/endpoints.json" >&2 2>&1 || echo "(missing)" >&2
    echo "--- $label: daemon log (tail) ---" >&2
    tail -n 80 "$TMP/$label.log" >&2 2>&1 || true
    echo "--- $label: 抓一下 DHT 包（2s，udp ${DHT_PORT}） ---" >&2
    timeout 2 ip netns exec "$ns" tcpdump -n -c 5 -i any "udp port ${DHT_PORT}" >&2 2>&1 \
      || echo "(tcpdump 不可用或没抓到包)" >&2
  done
  echo "===== END DIAGNOSTICS =====" >&2
}

# 轮询直到某侧 status 的 peer（按名字选）满足给定 jq 条件
wait_for_peer() {
  ns=$1; cfg=$2; peer=$3; cond=$4; budget=$5; label=$6
  for i in $(seq 1 "$budget"); do
    if status_json "$ns" "$cfg" \
      | jq -e --arg p "$peer" "(.peers[] | select(.peer == \$p)) | ${cond}" >/dev/null 2>&1; then
      echo "$label: 满足 ${cond}（${i}s）"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 ${cond} 超时（${budget}s）" >&2
  return 1
}

# 1) 拓扑：两个 netns 挂在同一个 bridge 上；bridge 带 IPv4 给 DHT 控制面，veth 带
#    IPv6（数据面）+ IPv4（控制面）。
ip link add "$BR" type bridge
ip link set "$BR" up
ip addr add "${BRIP}/24" dev "$BR"
for spec in "a|$NS_A|$ADDR_A|$IP_A" "b|$NS_B|$ADDR_B|$IP_B"; do
  # 用 `|` 而非 `:` 当分隔符：IPv6 地址自带冒号，用 `:` 会把 `2001:db8:30::a`
  # 切成 `2001` + 一堆碎段，进而拼出 `2001/64` 这种非法前缀（netns E2E 实跑发现的坑）。
  IFS='|' read -r tag ns addr ip4 <<< "$spec"
  ip netns add "$ns"
  ip link add "veth6-$tag" type veth peer name "veth6-$tag-p"
  ip link set "veth6-$tag" master "$BR" up
  ip link set "veth6-$tag-p" netns "$ns"
  ip -n "$ns" addr add "${addr}/64" dev "veth6-$tag-p" nodad
  ip -n "$ns" addr add "${ip4}/24" dev "veth6-$tag-p"
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "veth6-$tag-p" up
done

# 2) 身份与配置（各自独立 state_dir，保证端点缓存是空的）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-dht --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-dht --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

# 关掉 LAN 组播发现：本脚本的两个 netns 挂在同一 L2 上，LAN 组播（默认开）会直接把
# 新地址喂给对端，把「DHT 会合」这条待测路径整段掩盖掉——与 netns-e2e-dynamic.sh
# 同一理由。gossip 无需关：它是隧道内（目标是 overlay 地址），A↔B 没连上、或换址后
# 隧道断掉时它够不到对端，天然帮不上忙，不会污染 DHT 这条路径。
disable_lan_discovery() {
  awk '{ print } /^\[node\]$/ { print "lan_discovery = false" }' "$1" >"$1.tmp"
  mv "$1.tmp" "$1"
}
disable_lan_discovery "$TMP/a.toml"
disable_lan_discovery "$TMP/b.toml"

# 关键：用 `hextet peer add` 互加对端，**不给任何 endpoint**——只能靠 DHT 会合去发现
"$BIN" peer add -c "$TMP/a.toml" --name b --public-key "$PK_B"
"$BIN" peer add -c "$TMP/b.toml" --name a --public-key "$PK_A"

# 预写 DHT 节点表：让 daemon 冷启动时 bootstrap 到本地 DHT 节点，而不是公开 DHT。
# 格式与 hextet-discovery::nodes::DhtNodesFile 一致（version=1，nodes 为 "ip:port"）。
for state in "$TMP/a-state" "$TMP/b-state"; do
  printf '{"version":1,"nodes":["%s:%s"]}\n' "$BRIP" "$DHT_PORT" >"$state/dht-nodes.json"
done

# 3) 前置断言：DHT 是本测试**唯一**的会合路径，其余会合来源必须全被排除。
for cfg in "$TMP/a.toml" "$TMP/b.toml"; do
  if grep -q '^endpoints = ' "$cfg"; then
    echo "ERROR: $cfg 里竟然有 endpoints，本测试的前提被破坏" >&2; exit 1
  fi
  grep -q '^lan_discovery = false$' "$cfg" \
    || { echo "ERROR: $cfg 没有关掉 LAN 发现，DHT 路径会被掩盖" >&2; exit 1; }
done
for d in "$TMP/a-state" "$TMP/b-state"; do
  if [ -e "$d/endpoints.json" ]; then
    echo "ERROR: $d 里已有端点缓存，本测试的前提被破坏" >&2; exit 1
  fi
done

OVERLAY_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
OVERLAY_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$OVERLAY_A b=$OVERLAY_B（配置里没有任何 endpoint，仅 DHT 会合）"

# 4) 起本地 DHT 节点（根 netns，绑在网桥 IPv4 上）+ 两侧 daemon
"$BIN" dht node --bind "$BRIP" --port "$DHT_PORT" >"$TMP/dht.log" 2>&1 &
DHT_PID=$!
sleep 1
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

# 5) 核心验收（初始）：A、B 仅靠 DHT 会合连上，且 endpoint_source == "dht"
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint_source == "dht"' \
     "$INITIAL_TIMEOUT" "a→b 会合"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint_source == "dht"' \
     "$INITIAL_TIMEOUT" "b→a 会合"; then dump_diagnostics; exit 1; fi

# 6) overlay 双向连通（数据真的通了，不是状态文件自嗨）
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败（DHT 会合没通）" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败（DHT 会合没通）" >&2; dump_diagnostics; exit 1
fi
echo "经 DHT 会合的 overlay 双向连通 ✓"

# 7) 换址：A、B **同时**换地址（删旧加新），仅靠 DHT 查询到对方的新地址恢复。
#    注意只动 IPv6 数据面地址，IPv4 控制面（到 DHT 节点的出站）保持不变。
ip -n "$NS_A" addr del "${ADDR_A}/64" dev veth6-a-p
ip -n "$NS_A" addr add "${ADDR_A2}/64" dev veth6-a-p nodad
ip -n "$NS_B" addr del "${ADDR_B}/64" dev veth6-b-p
ip -n "$NS_B" addr add "${ADDR_B2}/64" dev veth6-b-p nodad
echo "--- A、B 已同时换地址：a=${ADDR_A2} b=${ADDR_B2} ---"

# 恢复后仍应连上，且 A/B 看到的对方 endpoint 是对方的新地址（DHT 查来的，不是旧地址），
# endpoint_source 仍是 dht。
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint == "[2001:db8:30::bb]:4193" and .endpoint_source == "dht"' \
     "$RECOVERY_TIMEOUT" "a→b 换址恢复"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint == "[2001:db8:30::aa]:4193" and .endpoint_source == "dht"' \
     "$RECOVERY_TIMEOUT" "b→a 换址恢复"; then dump_diagnostics; exit 1; fi

if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: 换址后 a→b overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: 换址后 b→a overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "换址后经 DHT 会合恢复 ✓"

# 8) 收尾
for pid_var in A_PID B_PID DHT_PID; do
  pid=${!pid_var}
  [ -n "$pid" ] && { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
done
A_PID=""; B_PID=""; DHT_PID=""
for spec in "$NS_A:$TMP/a.toml" "$NS_B:$TMP/b.toml"; do
  ns=${spec%%:*}; cfg=${spec#*:}
  ip netns exec "$ns" "$BIN" down -c "$cfg"
  if ip -n "$ns" link show hextet0 >/dev/null 2>&1; then
    echo "ERROR: hextet0 still exists in $ns after down" >&2
    exit 1
  fi
done

echo "DHT E2E OK"
