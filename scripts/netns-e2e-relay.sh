#!/usr/bin/env bash
# hextet M3 阶段 C E2E：A 与 B 直连被防火墙全阻时，经第三个节点 R 中继连通；
# 随后出现一个可直连的新地址时自动升级回直连并注销中继会话。
# 需要：Linux、root、内核 wireguard 模块、nftables、jq。
set -euo pipefail

BR=br-hxt4
NS_A=hxt4-a
NS_B=hxt4-b
NS_R=hxt4-r
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# 三个节点都挂在同一个 L2 上（模拟"都有公网 IPv6"），A↔B 的直连由 nftables 掐断
NET=2001:db8:1f
ADDR_A="${NET}::a"
ADDR_B="${NET}::b"
ADDR_R="${NET}::c"
# B 后来新增的地址：它给 A 带来一个**新的**候选，从而触发直连升级
ADDR_B2="${NET}::bb"
# 直连轮换 2 轮（≤5s）+ 注册 + 握手；30s 给足余量
RELAY_TIMEOUT=30
UPGRADE_TIMEOUT=30

A_PID=""
B_PID=""
R_PID=""

cleanup() {
  for pid in "$A_PID" "$B_PID" "$R_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for ns in "$NS_A" "$NS_B" "$NS_R"; do ip netns del "$ns" 2>/dev/null || true; done
  for v in veth4-a veth4-b veth4-r; do ip link del "$v" 2>/dev/null || true; done
  ip link del "$BR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v nft >/dev/null || { echo "nftables required" >&2; exit 1; }

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
    echo "--- $label: nft ruleset ---" >&2
    ip netns exec "$ns" nft list ruleset >&2 2>&1 || true
    echo "--- $label: daemon log (tail) ---" >&2
    tail -n 80 "$TMP/$label.log" >&2 2>&1 || true
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

# 1) 拓扑：三个 netns 挂在同一个 bridge 上
ip link add "$BR" type bridge
ip link set "$BR" up
for spec in "a:$NS_A:$ADDR_A" "b:$NS_B:$ADDR_B" "r:$NS_R:$ADDR_R"; do
  tag=${spec%%:*}; rest=${spec#*:}; ns=${rest%%:*}; addr=${rest#*:}
  ip netns add "$ns"
  ip link add "veth4-$tag" type veth peer name "veth4-$tag-p"
  ip link set "veth4-$tag" master "$BR" up
  ip link set "veth4-$tag-p" netns "$ns"
  # nodad：合成链路无重复地址风险，跳过 DAD 免得地址卡在 tentative
  ip -n "$ns" addr add "${addr}/64" dev "veth4-$tag-p" nodad
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "veth4-$tag-p" up
done

# 2) 身份与配置
mkdir -p "$TMP/a-state" "$TMP/b-state" "$TMP/r-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
PK_R=$("$BIN" keygen --out "$TMP/r.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-relay --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
for tag in b r; do
  "$BIN" init --name e2e-relay --key-file "$TMP/$tag.key" --network-key "$NETKEY" \
    --state-dir "$TMP/$tag-state" --out "$TMP/$tag.toml"
done

# R 提供中继服务（spec D5：默认关闭，这里显式打开）
awk '{ print } /^\[node\]$/ { print "relay = true" }' "$TMP/r.toml" >"$TMP/r.toml.tmp"
mv "$TMP/r.toml.tmp" "$TMP/r.toml"
grep -q '^relay = true$' "$TMP/r.toml" || { echo "ERROR: r 没打开中继" >&2; exit 1; }

# A 认识 B（直连会被阻断）与 R（可当中继）
cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${ADDR_B}]:4193"]

[[peers]]
name = "r"
public_key = "$PK_R"
endpoints = ["[${ADDR_R}]:4193"]
relay = true
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${ADDR_A}]:4193"]

[[peers]]
name = "r"
public_key = "$PK_R"
endpoints = ["[${ADDR_R}]:4193"]
relay = true
EOF

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

OVERLAY_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
OVERLAY_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$OVERLAY_A b=$OVERLAY_B"

# 3) 掐断 A↔B 的直连（单播），保留与 R 的双向以及组播（LAN 公告照常）
block_peer() {
  ip netns exec "$1" nft -f - <<EOF
table inet hxtblock {
  chain output { type filter hook output priority 0; policy accept; ip6 daddr $2 drop; }
  chain input  { type filter hook input  priority 0; policy accept; ip6 saddr $2 drop; }
}
EOF
}
block_peer "$NS_A" "$ADDR_B"
block_peer "$NS_B" "$ADDR_A"
# 前置断言：直连真的不通（否则后面"relayed"可能只是巧合）
if ip netns exec "$NS_A" ping -6 -c 1 -W 2 "$ADDR_B" >/dev/null 2>&1; then
  echo "ERROR: A→B 的直连没有被阻断，本测试前提被破坏" >&2; exit 1
fi
echo "A↔B 直连已阻断（与 R 的路径保留）"

# 4) 起三侧 daemon
ip netns exec "$NS_R" "$BIN" daemon -v -c "$TMP/r.toml" >"$TMP/r.log" 2>&1 &
R_PID=$!
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

# 5) 核心验收：A、B 都经 R 中继连上
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "relayed" and .relay_via == "r" and .endpoint_source == "relay"' \
     "$RELAY_TIMEOUT" "a→b"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "relayed" and .relay_via == "r" and .endpoint_source == "relay"' \
     "$RELAY_TIMEOUT" "b→a"; then dump_diagnostics; exit 1; fi

# 人类可读输出必须明确标出经过了谁——绝不能让用户以为是直连
if ! ip netns exec "$NS_A" "$BIN" status -c "$TMP/a.toml" | grep -q "relayed via r"; then
  echo "ERROR: status 没有显示 relayed via r" >&2
  ip netns exec "$NS_A" "$BIN" status -c "$TMP/a.toml" >&2 || true
  dump_diagnostics; exit 1
fi

# 中继会话端口是中继临时分配的，既不是 4193 也不是 4196
EP=$(status_json "$NS_A" "$TMP/a.toml" | jq -r '.peers[] | select(.peer == "b") | .endpoint')
case "$EP" in
  "[${ADDR_R}]:4193"|"[${ADDR_R}]:4196")
    echo "ERROR: 中继 endpoint $EP 用的是固定端口，应是每对会话独占的临时端口" >&2
    dump_diagnostics; exit 1 ;;
  "[${ADDR_R}]:"*) echo "a 看到 b 的 endpoint = $EP（经 r 的会话端口）" ;;
  *) echo "ERROR: a 看到 b 的 endpoint 是 $EP，期望指向中继 ${ADDR_R}" >&2
     dump_diagnostics; exit 1 ;;
esac

# 6) overlay 双向连通（数据真的穿过了中继）
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败（中继没通）" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败（中继没通）" >&2; dump_diagnostics; exit 1
fi
echo "经中继的 overlay 双向连通 ✓"

# 中继侧日志应有会话建立的记录
if ! grep -q "中继会话已建立" "$TMP/r.log"; then
  echo "ERROR: r 的日志里没有中继会话建立的记录" >&2; dump_diagnostics; exit 1
fi

# 7) 直连升级：解除阻断 + 给 B 加一个新地址。
#
# 两件事都要做，各有分工：解除阻断让直连**可行**；新地址让 A 从 LAN 公告里拿到一个
# **新的**候选，从而立刻去试直连（内核 WireGuard 一个 peer 只有一个 endpoint，
# 中继期间无法顺便探测直连，所以升级是事件驱动的——见 docs/protocol/relay.md C-2）。
ip netns exec "$NS_A" nft delete table inet hxtblock
ip netns exec "$NS_B" nft delete table inet hxtblock
ip -n "$NS_B" addr add "${ADDR_B2}/64" dev veth4-b-p nodad
echo "--- 已解除阻断并给 b 加了新地址 ${ADDR_B2} ---"

if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint_source != "relay" and .relay_via == null' \
     "$UPGRADE_TIMEOUT" "a→b 升级直连"; then dump_diagnostics; exit 1; fi

# 升级后仍然通，且日志里有"已升级为直连"的记录
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: 升级为直连后 ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! grep -q "已升级为直连" "$TMP/a.log"; then
  echo "ERROR: a 的日志里没有升级为直连的记录" >&2; dump_diagnostics; exit 1
fi
echo "已升级为直连并注销中继会话 ✓"

# 8) 收尾
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

echo "RELAY E2E OK"
