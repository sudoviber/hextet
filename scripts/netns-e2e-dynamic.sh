#!/usr/bin/env bash
# hextet M2 阶段 A E2E：daemon 常驻 → 一侧换前缀 <5s 恢复 → 仅靠端点缓存重连。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt2-a
NS_B=hxt2-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# "公网"前缀：A 会从 PREFIX_1 换到 PREFIX_2（模拟 PPPoE 重拨换前缀）
PREFIX_1=2001:db8:1
PREFIX_2=2001:db8:2
# 设计 spec §8 M2 验收：一侧换前缀 <5s 恢复
RECOVERY_BUDGET_MS=5000

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # veth 是一对：删任一端即删整对，两端都已转移/已删时是幂等 no-op
  ip link del veth2-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    local_label=${pair%%:*}
    rest=${pair#*:}
    ns=${rest%%:*}
    cfg=${rest#*:}
    echo "--- $local_label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $local_label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
    echo "--- $local_label: ip -6 addr / route ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    ip netns exec "$ns" ip -6 route >&2 2>&1 || true
  done
  echo "--- a: state.json ---" >&2
  cat "$TMP/a-state/state.json" >&2 2>&1 || echo "(missing)" >&2
  echo "--- a: endpoints.json ---" >&2
  cat "$TMP/a-state/endpoints.json" >&2 2>&1 || echo "(missing)" >&2
  echo "--- a: daemon log (tail) ---" >&2
  tail -n 80 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2
  tail -n 80 "$TMP/b.log" >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

# 等待某侧 status 报 connected（上限 20s：daemon 启动即 nudge，正常 1-3s 内握手）
#
# 必须同时要求 state 与 punch_state：
# - `.peers[0].state` 来自**内核**的 last_handshake，握手完成的瞬间就为真；
# - `.peers[0].punch_state` 来自 daemon 每秒 tick 写盘的 state.json。
# 只等前者会与紧随其后的 `state.json` 断言构成竞态——CI runner 快的时候，内核已报
# connected 而 daemon 还没写下一次 tick，步骤 4 直接读 state.json 就会看到 probing。
wait_for_connected() {
  ns=$1; cfg=$2; label=$3
  for i in $(seq 1 20); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.peers[0].state == "connected" and .peers[0].punch_state == "connected"' \
        >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 connected 超时" >&2
  return 1
}

# 轮询直到 status 里的 peer endpoint 落在指定前缀上；stdout 只输出耗时(ms)
wait_for_endpoint_prefix() {
  ns=$1; cfg=$2; want=$3; budget_ms=$4; start_ms=$5
  while :; do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e --arg want "[$want" '(.peers[0].endpoint // "") | startswith($want)' \
        >/dev/null 2>&1; then
      echo $(( $(now_ms) - start_ms ))
      return 0
    fi
    if [ $(( $(now_ms) - start_ms )) -gt "$budget_ms" ]; then
      return 1
    fi
    sleep 0.1
  done
}

# 1) 拓扑：ns-a <-veth-> ns-b，PREFIX_1::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth2-a type veth peer name veth2-b
ip link set veth2-a netns "$NS_A"; ip link set veth2-b netns "$NS_B"
# nodad：veth 是自建合成链路无重复地址风险；跳过 DAD 避免地址卡在 tentative
# （tentative 地址不可作出站源地址，会让 WG 用 overlay 地址当源地址造成黑洞，
#   详见 scripts/netns-e2e.sh 里的同一处说明）
ip -n "$NS_A" addr add "${PREFIX_1}::a/64" dev veth2-a nodad
ip -n "$NS_B" addr add "${PREFIX_1}::b/64" dev veth2-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth2-a up; ip -n "$NS_B" link set veth2-b up
# B 预先知道怎么到达 A 未来的前缀（真实网络里这由上游路由器负责）
ip -n "$NS_B" -6 route replace "${PREFIX_2}::/64" dev veth2-b

# 2) 身份与配置（各自独立 state_dir）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-dyn --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-dyn --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${PREFIX_1}::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${PREFIX_1}::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B"

# 3) 启动两侧 daemon（前台进程放后台跑，日志落文件）
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b"; then dump_diagnostics; exit 1; fi

# 4) daemon 状态文件内容正确
if ! jq -e '.version == 2 and .peers[0].punch_state == "connected"' \
     "$TMP/a-state/state.json" >/dev/null; then
  echo "ERROR: a 的 state.json 未报 connected" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" \
     | jq -e '.daemon.running == true' >/dev/null; then
  echo "ERROR: status 未识别到运行中的 daemon" >&2; dump_diagnostics; exit 1
fi

# 5) 基线连通
if ! ip netns exec "$NS_A" ping -6 -c 2 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 基线 ping 失败" >&2; dump_diagnostics; exit 1
fi

# 6) 核心验收：A 换前缀，B 必须在 5s 内把 endpoint 跟到新前缀上
echo "--- 换前缀：a 从 ${PREFIX_1}::a 换到 ${PREFIX_2}::a ---"
T0=$(now_ms)
ip -n "$NS_A" addr add "${PREFIX_2}::a/64" dev veth2-a nodad
ip -n "$NS_A" addr del "${PREFIX_1}::a/64" dev veth2-a
# 删掉旧地址会带走内核自动生成的 on-link 路由，补回到 B 的可达性
# （真实网络里 A 到上游的默认路由不会因为换前缀而消失）
ip -n "$NS_A" -6 route replace "${PREFIX_1}::/64" dev veth2-a

# 轮询预算给到 15s，以便超预算时能报出真实耗时而不是只说"超时"
if ! ELAPSED_MS=$(wait_for_endpoint_prefix "$NS_B" "$TMP/b.toml" "$PREFIX_2" 15000 "$T0"); then
  echo "ERROR: b 在 15s 内未把 a 的 endpoint 更新到 ${PREFIX_2}" >&2
  dump_diagnostics; exit 1
fi
echo "b 观察到 a 的新 endpoint，耗时 ${ELAPSED_MS}ms（预算 ${RECOVERY_BUDGET_MS}ms）"
if [ "$ELAPSED_MS" -gt "$RECOVERY_BUDGET_MS" ]; then
  echo "ERROR: 恢复耗时 ${ELAPSED_MS}ms 超出 ${RECOVERY_BUDGET_MS}ms 预算" >&2
  dump_diagnostics; exit 1
fi

# 恢复后双向仍然通
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: 换前缀后 b→a ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 换前缀后 a→b ping 失败" >&2; dump_diagnostics; exit 1
fi

# 7) 端点缓存已落盘
if ! jq -e 'any(.peers[]; .last_good != null)' "$TMP/a-state/endpoints.json" >/dev/null; then
  echo "ERROR: a 的 endpoints.json 没有 last_good" >&2; dump_diagnostics; exit 1
fi

# 8) SIGTERM 优雅退出（3s 内）
kill -TERM "$A_PID"
for _ in $(seq 1 30); do
  kill -0 "$A_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$A_PID" 2>/dev/null; then
  echo "ERROR: a 的 daemon 未在 3s 内响应 SIGTERM" >&2; dump_diagnostics; exit 1
fi
wait "$A_PID" 2>/dev/null || true
A_PID=""

# 9) 仅靠端点缓存重连：把配置里 peer 的 endpoints 整行删掉后重启 daemon
grep -v '^endpoints = ' "$TMP/a.toml" >"$TMP/a2.toml"
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a2.toml" >"$TMP/a2.log" 2>&1 &
A_PID=$!
if ! wait_for_connected "$NS_A" "$TMP/a2.toml" "a(仅缓存)"; then
  echo "--- a2 daemon log ---" >&2; tail -n 80 "$TMP/a2.log" >&2 || true
  dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a2.toml" \
     | jq -e '.peers[0].endpoint_source == "cache"' >/dev/null; then
  echo "ERROR: 重连的 endpoint 来源不是 cache" >&2
  ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a2.toml" >&2 || true
  dump_diagnostics; exit 1
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

echo "DYNAMIC E2E OK"
