#!/usr/bin/env bash
# hextet M3 阶段 D E2E：三节点 A、B、R。A 与 B 的配置里**只有 R 的 endpoint**，
# 互不知道对方的地址；仅靠与 R 的连接（gossip 转介）学到彼此地址并连通。
# 随后 A、B 同时换地址，仍靠 R 的转介在 <15s 内恢复。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

BR=br-hxt5
NS_A=hxt5-a
NS_B=hxt5-b
NS_R=hxt5-r
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# 三个节点挂在同一个 L2（同一个 /64 当"同一网络"）；A↔B 之间没有任何 endpoint 知识
NET=2001:db8:2f
ADDR_A="${NET}::a"
ADDR_B="${NET}::b"
ADDR_R="${NET}::c"
# 换前缀后 A、B 的新地址（仍在同一 /64——netns 的 veth bridge 是单 L2，换地址即换端点）
ADDR_A2="${NET}::aa"
ADDR_B2="${NET}::bb"
# 首次转介：gossip 周期 30s，但启动即发 + 收到即转播，30s 给足余量
REFERRAL_TIMEOUT=30
# 换前缀恢复：地址变化即广播（不依赖 30s 周期），30s 给 CI 抖动留足余量
RECOVERY_TIMEOUT=30

A_PID=""
B_PID=""
R_PID=""

cleanup() {
  for pid in "$A_PID" "$B_PID" "$R_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for ns in "$NS_A" "$NS_B" "$NS_R"; do ip netns del "$ns" 2>/dev/null || true; done
  for v in veth5-a veth5-b veth5-r; do ip link del "$v" 2>/dev/null || true; done
  ip link del "$BR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

status_json() { ip netns exec "$1" "$BIN" status --json -c "$2" 2>/dev/null; }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml" "r:$NS_R:$TMP/r.toml"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; cfg=${rest#*:}
    echo "--- $label: status --json ---" >&2
    status_json "$ns" "$cfg" >&2 || true
    echo "--- $label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || true
    echo "--- $label: ip -6 addr ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    echo "--- $label: daemon log (tail) ---" >&2
    tail -n 80 "$TMP/$label.log" >&2 2>&1 || true
    echo "--- $label: 抓一下 gossip 包（2s） ---" >&2
    timeout 2 ip netns exec "$ns" tcpdump -n -c 5 -i any "udp port 4197" >&2 2>&1 \
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

# 本脚本要测的是「gossip 转介」这一条路径：A、B 互不认识，只靠与 R 的连接学地址。
# 但三个 netns 挂在同一个 L2 bridge 上，LAN 组播发现（默认开）会直接把对方地址喂给
# A/B，把 gossip 这条待测路径整段掩盖掉——于是这个测试会在 gossip 坏掉时依然通过
# （与 netns-e2e-dynamic.sh / netns-e2e-dht.sh 必须关 LAN 是同一理由）。LAN 发现
# 有自己的 netns E2E（scripts/netns-e2e-lan.sh），这里显式关掉它。
disable_lan_discovery() {
  awk '{ print } /^\[node\]$/ { print "lan_discovery = false" }' "$1" >"$1.tmp"
  mv "$1.tmp" "$1"
}

# 1) 拓扑：三个 netns 挂在同一个 bridge 上（单 L2，模拟"同一网络内"）
ip link add "$BR" type bridge
ip link set "$BR" up
for spec in "a:$NS_A:$ADDR_A" "b:$NS_B:$ADDR_B" "r:$NS_R:$ADDR_R"; do
  tag=${spec%%:*}; rest=${spec#*:}; ns=${rest%%:*}; addr=${rest#*:}
  ip netns add "$ns"
  ip link add "veth5-$tag" type veth peer name "veth5-$tag-p"
  ip link set "veth5-$tag" master "$BR" up
  ip link set "veth5-$tag-p" netns "$ns"
  ip -n "$ns" addr add "${addr}/64" dev "veth5-$tag-p" nodad
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "veth5-$tag-p" up
done

# 2) 身份与配置
mkdir -p "$TMP/a-state" "$TMP/b-state" "$TMP/r-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
PK_R=$("$BIN" keygen --out "$TMP/r.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-gossip --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
for tag in b r; do
  "$BIN" init --name e2e-gossip --key-file "$TMP/$tag.key" --network-key "$NETKEY" \
    --state-dir "$TMP/$tag-state" --out "$TMP/$tag.toml"
done
disable_lan_discovery "$TMP/a.toml"
disable_lan_discovery "$TMP/b.toml"

# A：认识 R（有 endpoint）+ B（**无 endpoint**，靠 gossip 转介）
cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "r"
public_key = "$PK_R"
endpoints = ["[${ADDR_R}]:4193"]

[[peers]]
name = "b"
public_key = "$PK_B"
EOF

# B：认识 R（有 endpoint）+ A（**无 endpoint**）
cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "r"
public_key = "$PK_R"
endpoints = ["[${ADDR_R}]:4193"]

[[peers]]
name = "a"
public_key = "$PK_A"
EOF

# R：认识 A 和 B（都有 endpoint）——它是转介的枢纽
cat >>"$TMP/r.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${ADDR_A}]:4193"]

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${ADDR_B}]:4193"]
EOF

# 关掉 LAN 组播发现：三个 netns 挂在同一 L2 bridge 上，LAN 组播（默认开）会直接把
# A↔B 的地址互相喂给对方，把「gossip 转介」这条待测路径整段掩盖掉——与
# netns-e2e-dht.sh 同一理由。A↔R、B↔R 靠的是配置里的 endpoint，不依赖 LAN。
disable_lan_discovery() {
  awk '{ print } /^\[node\]$/ { print "lan_discovery = false" }' "$1" >"$1.tmp"
  mv "$1.tmp" "$1"
}
for cfg in "$TMP/a.toml" "$TMP/b.toml" "$TMP/r.toml"; do
  disable_lan_discovery "$cfg"
done

# 3) 前置断言：A、B 的配置里**确实没有对方的 endpoint**，且 LAN 发现已关掉，
#    否则转介测试的前提被破坏（netns E2E 实跑发现：不关 LAN，A↔B 会经 LAN 直连，
#    endpoint_source 变成 "lan"，gossip 转介这条路径被完全掩盖）。
for cfg in "$TMP/a.toml" "$TMP/b.toml"; do
  if grep -A1 'name = "[ab]"' "$cfg" | grep -q '^endpoints = '; then
    echo "ERROR: $cfg 里给 A/B 配了 endpoint，本测试的前提被破坏" >&2; exit 1
  fi
  grep -q '^lan_discovery = false$' "$cfg" \
    || { echo "ERROR: $cfg 没有关掉 LAN 发现，gossip 路径会被掩盖" >&2; exit 1; }
done
for cfg in "$TMP/a.toml" "$TMP/b.toml" "$TMP/r.toml"; do
  grep -q '^lan_discovery = false$' "$cfg" \
    || { echo "ERROR: $cfg 没有关掉 LAN 发现，gossip 路径会被掩盖" >&2; exit 1; }
done

OVERLAY_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
OVERLAY_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$OVERLAY_A b=$OVERLAY_B（A/B 互不知道对方地址）"

# 4) 起三侧 daemon
ip netns exec "$NS_R" "$BIN" daemon -v -c "$TMP/r.toml" >"$TMP/r.log" 2>&1 &
R_PID=$!
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

# 5) 核心验收：A↔B 经 R 的 gossip 转介连上（endpoint_source=gossip）
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint_source == "gossip" and .gossip_endpoints >= 1' \
     "$REFERRAL_TIMEOUT" "a→b 转介"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint_source == "gossip" and .gossip_endpoints >= 1' \
     "$REFERRAL_TIMEOUT" "b→a 转介"; then dump_diagnostics; exit 1; fi

# 6) overlay 双向连通（数据真的通了，不是状态文件自嗨）
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败（转介没通）" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败（转介没通）" >&2; dump_diagnostics; exit 1
fi
echo "经 gossip 转介的 overlay 双向连通 ✓"

# 7) 转介的前提是 A、B 都与 R 保持着直连（R 是枢纽）
if ! wait_for_peer "$NS_R" "$TMP/r.toml" a '.punch_state == "connected"' 15 "r→a"; then
  dump_diagnostics; exit 1
fi
if ! wait_for_peer "$NS_R" "$TMP/r.toml" b '.punch_state == "connected"' 15 "r→b"; then
  dump_diagnostics; exit 1
fi

# 8) 换前缀：A、B 同时换地址（删旧加新），仅靠与 R 的转介恢复
ip -n "$NS_A" addr del "${ADDR_A}/64" dev veth5-a-p
ip -n "$NS_A" addr add "${ADDR_A2}/64" dev veth5-a-p nodad
ip -n "$NS_B" addr del "${ADDR_B}/64" dev veth5-b-p
ip -n "$NS_B" addr add "${ADDR_B2}/64" dev veth5-b-p nodad
echo "--- A、B 已同时换地址：a=${ADDR_A2} b=${ADDR_B2} ---"

# 恢复后仍应连上，且 A 看到的 B endpoint 是 B 的新地址（转介来的，不是旧地址）
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint == "[2001:db8:2f::bb]:4193"' \
     "$RECOVERY_TIMEOUT" "a→b 换址恢复"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint == "[2001:db8:2f::aa]:4193"' \
     "$RECOVERY_TIMEOUT" "b→a 换址恢复"; then dump_diagnostics; exit 1; fi

if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: 换址后 a→b overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: 换址后 b→a overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "换址后经 gossip 转介恢复 ✓"

# 9) 收尾
for pid_var in A_PID B_PID R_PID; do
  pid=${!pid_var}
  [ -n "$pid" ] && { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
done
A_PID=""; B_PID=""; R_PID=""
for spec in "$NS_A:$TMP/a.toml" "$NS_B:$TMP/b.toml" "$NS_R:$TMP/r.toml"; do
  ns=${spec%%:*}; cfg=${spec#*:}
  ip netns exec "$ns" "$BIN" down -c "$cfg"
  if ip -n "$ns" link show hextet0 >/dev/null 2>&1; then
    echo "ERROR: hextet0 still exists in $ns after down" >&2
    exit 1
  fi
done

echo "GOSSIP E2E OK"
