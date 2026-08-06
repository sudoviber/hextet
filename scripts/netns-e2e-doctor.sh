#!/usr/bin/env bash
# hextet M2 阶段 B E2E：双侧状态防火墙下仍能打洞互连 + doctor 三分类正确。
# 需要：Linux、root、内核 wireguard 模块、nftables（nft）、jq。
set -euo pipefail

NS_A=hxt3-a
NS_B=hxt3-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
PREFIX=2001:db8:3

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  ip link del veth3-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft (nftables) required" >&2; exit 1; }

# 状态防火墙：住宅 CPE / 光猫 IPv6 SPI 的常态——只放行已请求流量。
#
# 两个关键细节：
# - 用 iifname（字符串匹配）而不是 iif（索引匹配）：规则在 hextet0 存在之前就要
#   装上，iif 会因为查不到接口而加载失败。
# - 必须放行 iifname "hextet0"：只防火墙"公网"侧。解密后的 overlay 流量会再走一遍
#   input hook，若不放行，对端主动发起的 ping 会被当成 ct state new 丢掉。
apply_stateful_fw() {
  ip netns exec "$1" nft -f - <<'EOF'
table inet hxt {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "hextet0" accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    ct state established,related accept
  }
}
EOF
}

# 入站全拦：连自己请求的回包都不放行（部分光猫关不掉防火墙时的最坏情况）。
apply_blocked_fw() {
  ip netns exec "$1" nft -f - <<'EOF'
table inet hxt {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "hextet0" accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}
EOF
}

clear_fw() {
  ip netns exec "$1" nft delete table inet hxt 2>/dev/null || true
}

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; cfg=${rest#*:}
    echo "--- $label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $label: nft list ruleset ---" >&2
    ip netns exec "$ns" nft list ruleset >&2 2>&1 || true
    echo "--- $label: conntrack (udp) ---" >&2
    ip netns exec "$ns" conntrack -L -p udp >&2 2>&1 || echo "(conntrack tool unavailable)" >&2
  done
  echo "--- a: daemon log (tail) ---" >&2; tail -n 60 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2; tail -n 60 "$TMP/b.log" >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

wait_for_connected() {
  ns=$1; cfg=$2; label=$3
  for i in $(seq 1 25); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.peers[0].state == "connected"' >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 connected 超时" >&2
  return 1
}

assert_reachability() {
  ns=$1; cfg=$2; peer=$3; want=$4; label=$5
  if ! out=$(ip netns exec "$ns" "$BIN" doctor -c "$cfg" --peer "$peer" \
              --timeout 4 --json 2>"$TMP/doctor.err"); then
    echo "ERROR: doctor 执行失败（$label）" >&2
    cat "$TMP/doctor.err" >&2
    return 1
  fi
  got=$(echo "$out" | jq -r .reachability)
  if [ "$got" != "$want" ]; then
    echo "ERROR: $label 期望 $want，实际 $got" >&2
    echo "$out" >&2
    return 1
  fi
  echo "$label: reachability=$got"
}

# 1) 拓扑
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth3-a type veth peer name veth3-b
ip link set veth3-a netns "$NS_A"; ip link set veth3-b netns "$NS_B"
ip -n "$NS_A" addr add "${PREFIX}::a/64" dev veth3-a nodad
ip -n "$NS_B" addr add "${PREFIX}::b/64" dev veth3-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth3-a up; ip -n "$NS_B" link set veth3-b up

# 2) 身份与配置
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-doc --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-doc --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${PREFIX}::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${PREFIX}::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)

# 3) 验收一：双侧状态防火墙**先**装上，再启动 daemon —— 必须靠打洞连通
echo "--- 双侧装状态防火墙，然后启动 daemon ---"
apply_stateful_fw "$NS_A"
apply_stateful_fw "$NS_B"

ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a(防火墙后)"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b(防火墙后)"; then dump_diagnostics; exit 1; fi
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 防火墙后 a→b ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: 防火墙后 b→a ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "验收一通过：双侧状态防火墙下打洞互连成功"

# 4) 验收二之一：doctor 在状态防火墙下应报 stateful
if ! assert_reachability "$NS_A" "$TMP/a.toml" b stateful "stateful 场景"; then
  dump_diagnostics; exit 1
fi

# 5) 验收二之二：撤掉 a 的防火墙 → open
clear_fw "$NS_A"
if ! assert_reachability "$NS_A" "$TMP/a.toml" b open "open 场景"; then
  dump_diagnostics; exit 1
fi

# 6) 验收二之三：a 入站全拦 → blocked
#（这会同时打断 a 的隧道，所以放最后）
apply_blocked_fw "$NS_A"
if ! assert_reachability "$NS_A" "$TMP/a.toml" b blocked "blocked 场景"; then
  dump_diagnostics; exit 1
fi

# 7) 收尾
clear_fw "$NS_A"; clear_fw "$NS_B"
kill -TERM "$A_PID" 2>/dev/null || true; wait "$A_PID" 2>/dev/null || true; A_PID=""
kill -TERM "$B_PID" 2>/dev/null || true; wait "$B_PID" 2>/dev/null || true; B_PID=""
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"

echo "DOCTOR E2E OK"
