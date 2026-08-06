#!/usr/bin/env bash
# hextet M1 E2E：两个 netns 经 veth 模拟公网 IPv6，静态配置直连互 ping。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt-a
NS_B=hxt-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)

cleanup() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # veth 是一对：ip link add 之后、两个 `ip link set ... netns` 完成前失败时，
  # 未转移的一端仍留在根 netns（另一端已随对应 netns 一起被上面删掉）。
  # 删 veth-a 这一端即删掉整对，且在两端都已转移/已删除时也是幂等的 no-op。
  ip link del veth-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

# 失败诊断：dump 双侧 hextet status/wg show/地址/路由，方便排查握手失败原因。
dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  echo "--- a: hextet status --json ---" >&2
  ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" >&2 2>&1 || true
  echo "--- b: hextet status --json ---" >&2
  ip netns exec "$NS_B" "$BIN" status --json -c "$TMP/b.toml" >&2 2>&1 || true
  echo "--- a: wg show all ---" >&2
  ip netns exec "$NS_A" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
  echo "--- b: wg show all ---" >&2
  ip netns exec "$NS_B" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
  echo "--- a: ip -6 addr ---" >&2
  ip netns exec "$NS_A" ip -6 addr >&2 2>&1 || true
  echo "--- b: ip -6 addr ---" >&2
  ip netns exec "$NS_B" ip -6 addr >&2 2>&1 || true
  echo "--- a: ip -6 route ---" >&2
  ip netns exec "$NS_A" ip -6 route >&2 2>&1 || true
  echo "--- b: ip -6 route ---" >&2
  ip netns exec "$NS_B" ip -6 route >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

# 轮询等待 peer 握手建立（hextet status 的 connected 阈值是 180s；这里等待上限
# 只给 15s——首次握手应在 up 后数秒内由 persistent-keepalive/首个数据包触发）。
wait_for_connected() {
  local ns=$1 cfg=$2 label=$3 i
  for i in $(seq 1 15); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.[0].state == "connected"' >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: timed out waiting for connected state (${i}s)" >&2
  return 1
}

# 1) 拓扑：ns-a <-veth-> ns-b，2001:db8::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"; ip link set veth-b netns "$NS_B"
# nodad：veth 是我们自建的合成链路，没有真实重复地址风险；跳过 DAD 避免地址
# 在某些内核/容器环境下长期卡在 tentative——tentative 地址不可用作出站源地址，
# 源地址选择会转而落到 hextet0 自己的 overlay 地址（POINTOPOINT/NOARP 设备不
# 跑 DAD，天然可用），导致 WG 握手包带着错误的公网源地址发出、对端据此"学习"
# 到错误 endpoint，双方互相把对方地址当 endpoint、包在本机 /48 直连路由上被
# 打回 hextet0 造成黑洞（CI 里 100% packet loss 的实际根因，详见 fix report）。
ip -n "$NS_A" addr add 2001:db8::a/64 dev veth-a nodad
ip -n "$NS_B" addr add 2001:db8::b/64 dev veth-b nodad
for ns in "$NS_A" "$NS_B"; do
  ip -n "$ns" link set lo up
done
ip -n "$NS_A" link set veth-a up; ip -n "$NS_B" link set veth-b up

# 2) 身份与配置
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e --key-file "$TMP/a.key" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e --key-file "$TMP/b.key" --network-key "$NETKEY" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[2001:db8::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[2001:db8::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B"

# 3) 拉起
ip netns exec "$NS_A" "$BIN" up -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" up -c "$TMP/b.toml"

# 3.5) 等待首次握手（早于 ping 发起，超时则 dump 诊断后失败退出）
if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a"; then
  dump_diagnostics
  exit 1
fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b"; then
  dump_diagnostics
  exit 1
fi

# 4) 验收：互 ping overlay 地址
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B"; then
  dump_diagnostics
  exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A"; then
  dump_diagnostics
  exit 1
fi

# 5) status 显示 connected
ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" | jq -e '.[0].state == "connected"'

# 6) down 清理干净
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"
! ip -n "$NS_A" link show hextet0 2>/dev/null

echo "E2E OK"
