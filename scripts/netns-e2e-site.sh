#!/usr/bin/env bash
# hextet M4 第一片 E2E：site-to-site 子网路由。
# B 通告一个假子网 2001:db8:dead::/64（写在 A 配置里指向 B 的 peer 块），
# A 连上 B 后应把该前缀装进 hextet0 的路由表，且 overlay ping 仍通。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt4-a
NS_B=hxt4-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# 与 netns-e2e.sh 一致的"公网"网段
LAN=2001:db8
# B 通告的假子网（本测试要验证 A 会为它装路由）
ADVERTISED=2001:db8:dead::/64
CONNECT_TIMEOUT=25

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  ip link del veth4-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; cfg=${rest#*:}
    echo "--- $label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $label: hextet.toml ---" >&2
    cat "$cfg" >&2 2>&1 || true
    echo "--- $label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
    echo "--- $label: ip -6 route ---" >&2
    ip netns exec "$ns" ip -6 route >&2 2>&1 || true
  done
  echo "--- a: daemon log (tail) ---" >&2
  tail -n 100 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2
  tail -n 100 "$TMP/b.log" >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

# 等到某侧 status 同时报内核 connected 与 daemon 的 punch_state=connected
wait_for_connected() {
  ns=$1; cfg=$2; label=$3
  for i in $(seq 1 "$CONNECT_TIMEOUT"); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.peers[0].state == "connected" and .peers[0].punch_state == "connected"' \
        >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 connected 超时（${CONNECT_TIMEOUT}s）" >&2
  return 1
}

# 1) 拓扑：ns-a <-veth-> ns-b，2001:db8::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth4-a type veth peer name veth4-b
ip link set veth4-a netns "$NS_A"; ip link set veth4-b netns "$NS_B"
ip -n "$NS_A" addr add "${LAN}::a/64" dev veth4-a nodad
ip -n "$NS_B" addr add "${LAN}::b/64" dev veth4-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth4-a up; ip -n "$NS_B" link set veth4-b up

# 2) 身份与配置（各自独立 state_dir）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-site --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-site --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

# 关键：A 指向 B 的 peer 块里声明 B 通告的假子网；B 指向 A 的 peer 块不声明。
# 语义 = "B 在 2001:db8:dead::/64 背后可达，A 连上 B 后把该前缀送进隧道"。
"$BIN" peer add -c "$TMP/a.toml" --name b --public-key "$PK_B" \
  --endpoint "[${LAN}::b]:4193" --route "$ADVERTISED"
"$BIN" peer add -c "$TMP/b.toml" --name a --public-key "$PK_A" \
  --endpoint "[${LAN}::a]:4193"

# 3) 前置断言：A 的配置里确实声明了路由，B 的配置里没有
if ! grep -q '^routes = \[' "$TMP/a.toml"; then
  echo "ERROR: a.toml 里没有 routes，本测试的前提被破坏" >&2; exit 1
fi
if grep -q '^routes = \[' "$TMP/b.toml"; then
  echo "ERROR: b.toml 里竟然有 routes，本测试的前提被破坏" >&2; exit 1
fi

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B（B 通告 $ADVERTISED）"

# 4) 起两侧 daemon
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b"; then dump_diagnostics; exit 1; fi

# 5) 核心断言：A 为 B 通告的子网装了 OS 路由（oif=hextet0）
#    给 route 管理器一个 tick 的时间生效（daemon 每秒 tick 一次）
for i in $(seq 1 5); do
  if ip netns exec "$NS_A" ip -6 route show dev hextet0 | grep -q "$ADVERTISED"; then
    break
  fi
  sleep 1
done
if ! ip netns exec "$NS_A" ip -6 route show dev hextet0 | grep -q "$ADVERTISED"; then
  echo "ERROR: A 的 hextet0 上没有 $ADVERTISED 路由" >&2
  dump_diagnostics; exit 1
fi
echo "A: 已为 B 通告的子网装上 OS 路由 ✓"

# 6) A 的 status --json 反映通告路由
if ! ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" \
  | jq -e --arg r "$ADVERTISED" '.peers[0].routes | index($r) != null' >/dev/null; then
  echo "ERROR: A 的 status --json 没有反映通告路由 $ADVERTISED" >&2
  dump_diagnostics; exit 1
fi
echo "A: status --json 反映通告路由 ✓"

# 7) B 不应该为它自己装任何通告路由（它没声明）
if ip netns exec "$NS_B" "$BIN" status --json -c "$TMP/b.toml" \
  | jq -e '.peers[0].routes | length == 0' >/dev/null; then
  echo "B: 无通告路由 ✓"
else
  echo "ERROR: B 竟然装了自己的通告路由" >&2; dump_diagnostics; exit 1
fi

# 8) overlay 双向连通不受影响
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "overlay ping 双向连通 ✓"

# 9) 收尾：停 daemon、拆接口
kill -TERM "$A_PID" 2>/dev/null || true; wait "$A_PID" 2>/dev/null || true; A_PID=""
kill -TERM "$B_PID" 2>/dev/null || true; wait "$B_PID" 2>/dev/null || true; B_PID=""
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"
for ns in "$NS_A" "$NS_B"; do
  if ip -n "$ns" link show hextet0 >/dev/null 2>&1; then
    echo "ERROR: hextet0 still exists in $ns after down" >&2
    exit 1
  fi
done

echo "site E2E OK"
