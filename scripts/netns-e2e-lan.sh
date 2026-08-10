#!/usr/bin/env bash
# hextet M3 阶段 B E2E：同 LAN 两节点在**配置里没有任何 endpoint、缓存也是空的**前提下，
# 仅靠 LAN 组播公告互相发现并连通。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt3-a
NS_B=hxt3-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# 同一个 "LAN" 网段：两侧都在这个 /64 上，公告靠链路本地组播 ff02::4193 传播
LAN=2001:db8:1e
# 公告周期 5s + 握手 + daemon tick：25s 给足余量
CONNECT_TIMEOUT=25

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # veth 是一对：删任一端即删整对，两端都已转移/已删时是幂等 no-op
  ip link del veth3-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    label=${pair%%:*}
    rest=${pair#*:}
    ns=${rest%%:*}
    cfg=${rest#*:}
    echo "--- $label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $label: hextet.toml ---" >&2
    cat "$cfg" >&2 2>&1 || true
    echo "--- $label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
    echo "--- $label: ip -6 addr / maddr ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    ip netns exec "$ns" ip -6 maddr show >&2 2>&1 || true
  done
  echo "--- a: state.json ---" >&2
  cat "$TMP/a-state/state.json" >&2 2>&1 || echo "(missing)" >&2
  echo "--- a: daemon log (tail) ---" >&2
  tail -n 100 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2
  tail -n 100 "$TMP/b.log" >&2 2>&1 || true
  echo "--- a: 抓一下组播包（2s） ---" >&2
  timeout 2 ip netns exec "$NS_A" tcpdump -n -c 5 -i any "udp port 4195" >&2 2>&1 \
    || echo "(tcpdump 不可用或没抓到包)" >&2
  echo "===== END DIAGNOSTICS =====" >&2
}

# 等到某侧 status 同时报内核 connected 与 daemon 的 punch_state=connected
# （只等前者会与随后的 state.json 断言构成竞态，详见 netns-e2e-dynamic.sh 的说明）
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

# 1) 拓扑：ns-a <-veth-> ns-b，同一个 /64 当 "LAN"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth3-a type veth peer name veth3-b
ip link set veth3-a netns "$NS_A"; ip link set veth3-b netns "$NS_B"
# nodad：veth 是自建合成链路无重复地址风险；跳过 DAD 避免地址卡在 tentative
# （tentative 地址不可作出站源地址，会让 WG 用 overlay 地址当源地址造成黑洞）
ip -n "$NS_A" addr add "${LAN}::a/64" dev veth3-a nodad
ip -n "$NS_B" addr add "${LAN}::b/64" dev veth3-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth3-a up; ip -n "$NS_B" link set veth3-b up

# 2) 身份与配置（各自独立 state_dir，保证缓存是空的）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-lan --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-lan --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

# 关键：用 `hextet peer add` 互加对端，**不给任何 endpoint**
"$BIN" peer add -c "$TMP/a.toml" --name b --public-key "$PK_B"
"$BIN" peer add -c "$TMP/b.toml" --name a --public-key "$PK_A"

# 3) 前置断言：配置里确实没有 endpoint，state_dir 里确实没有缓存。
#    否则这个测试可能在"用配置连上了"却看起来像 LAN 发现成功。
for cfg in "$TMP/a.toml" "$TMP/b.toml"; do
  if grep -q '^endpoints = ' "$cfg"; then
    echo "ERROR: $cfg 里竟然有 endpoints，本测试的前提被破坏" >&2; exit 1
  fi
done
for d in "$TMP/a-state" "$TMP/b-state"; do
  if [ -e "$d/endpoints.json" ]; then
    echo "ERROR: $d 里已有端点缓存，本测试的前提被破坏" >&2; exit 1
  fi
done

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B（配置里没有任何 endpoint）"

# 4) 起两侧 daemon
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b"; then dump_diagnostics; exit 1; fi

# 5) 核心断言：endpoint 来自 LAN 发现，且确实收到了对端公告的地址
for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
  label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; cfg=${rest#*:}
  if ! ip netns exec "$ns" "$BIN" status --json -c "$cfg" \
     | jq -e '.peers[0].endpoint_source == "lan" and .peers[0].lan_endpoints >= 1' \
       >/dev/null; then
    echo "ERROR: $label 的 endpoint 来源不是 lan" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 || true
    dump_diagnostics; exit 1
  fi
  echo "$label: endpoint_source=lan ✓"
done

# 6) endpoint 必须落在 LAN 网段上（而不是碰巧从别处学到的）
EP_A_SEEN_BY_B=$(ip netns exec "$NS_B" "$BIN" status --json -c "$TMP/b.toml" \
  | jq -r '.peers[0].endpoint')
case "$EP_A_SEEN_BY_B" in
  "[${LAN}::a]:4193") echo "b 看到 a 的 endpoint = $EP_A_SEEN_BY_B ✓" ;;
  *) echo "ERROR: b 看到的 a endpoint 是 $EP_A_SEEN_BY_B，期望 [${LAN}::a]:4193" >&2
     dump_diagnostics; exit 1 ;;
esac

# 7) overlay 双向连通
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败" >&2; dump_diagnostics; exit 1
fi

# 8) LAN 学到的 endpoint 应被证实可用并写进端点缓存（下次启动不必再等公告）
if ! jq -e 'any(.peers[]; .last_good != null)' "$TMP/a-state/endpoints.json" >/dev/null; then
  echo "ERROR: a 的 endpoints.json 没有 last_good" >&2; dump_diagnostics; exit 1
fi

# 9) 日志里应有 LAN 发现的痕迹（证明是这条路径起作用，而不是别的巧合）
if ! grep -q "LAN 发现" "$TMP/a.log"; then
  echo "ERROR: a 的日志里没有 LAN 发现的记录" >&2; dump_diagnostics; exit 1
fi

# 10) 收尾：停 daemon、拆接口
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

echo "LAN E2E OK"
