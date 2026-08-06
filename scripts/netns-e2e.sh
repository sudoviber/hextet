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
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

# 1) 拓扑：ns-a <-veth-> ns-b，2001:db8::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"; ip link set veth-b netns "$NS_B"
ip -n "$NS_A" addr add 2001:db8::a/64 dev veth-a
ip -n "$NS_B" addr add 2001:db8::b/64 dev veth-b
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

# 4) 验收：互 ping overlay 地址
ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B"
ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A"

# 5) status 显示 connected
ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" | jq -e '.[0].state == "connected"'

# 6) down 清理干净
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"
! ip -n "$NS_A" link show hextet0 2>/dev/null

echo "E2E OK"
