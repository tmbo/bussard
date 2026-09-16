#!/usr/bin/env bash
#
# Create an isolated network namespace + veth pair so the thelsing knx-linux-ip
# virtual device and bussard can exchange KNXnet/IP *routing multicast* on one
# host — the setup the CI interop ladder needs.
#
# WHY THIS EXISTS (the root cause it works around)
# ------------------------------------------------
# thelsing's Linux platform hard-codes IP_MULTICAST_LOOP = 0 on its one multicast
# socket (src/linux_platform.cpp, `loop = 0; setsockopt(... IP_MULTICAST_LOOP)`).
# On Linux that flag is a property of the *sending* socket and decides whether a
# multicast datagram is delivered to group members ON THE SAME HOST. With it off,
# the device's ROUTING_INDICATION replies never reach a bussard process sharing
# the host, so `bussard assign`'s programming-mode discovery finds nothing and
# times out. That is exactly the first-run CI failure.
#
# We cannot change thelsing's socket options (we run its unmodified pinned
# binary, never link it). So instead we make "same host" no longer true for the
# kernel's multicast-loop check: we put the DEVICE in its own network namespace
# connected to the root namespace by a veth pair. Its multicast now physically
# egresses veth-dev and arrives at veth-host as ordinary *inbound* multicast —
# IP_MULTICAST_LOOP is irrelevant to inbound delivery across a real link. bussard
# stays in the root namespace and joins/sends on veth-host.
#
# Requires sudo (GitHub ubuntu runners allow passwordless sudo). Idempotent:
# re-running tears down a previous instance first.
#
# Usage:
#   sudo tests-support/virtual-device/netns-setup.sh            # create
#   sudo tests-support/virtual-device/netns-setup.sh --teardown # remove
#
# It prints, to stdout, two `export`-able lines the caller should `eval`:
#   BUSSARD_VIRTUAL_DEVICE_WRAP='ip netns exec knxdev'  # how the test spawns the device
#   BUSSARD_ROUTING_IFACE_HINT=10.213.0.1               # the veth-host address (informational)
#
# Names/addresses are fixed and namespaced enough to avoid clashing with a
# runner's real config (10.213.0.0/24 is in RFC1918 space, unlikely to be used).

set -euo pipefail

NS="knxdev"
VETH_HOST="knxveth0"
VETH_DEV="knxveth1"
HOST_IP="10.213.0.1"
DEV_IP="10.213.0.2"
PREFIX="24"
MGROUP="224.0.23.12"

teardown() {
    # Order matters: deleting the namespace removes veth-dev; delete veth-host
    # too in case it leaked into the root ns. Ignore errors (idempotent).
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
}

if [ "${1:-}" = "--teardown" ]; then
    teardown
    echo "[netns] torn down $NS / $VETH_HOST" >&2
    exit 0
fi

# Fresh start.
teardown

echo "[netns] creating namespace $NS and veth pair $VETH_HOST<->$VETH_DEV" >&2
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_DEV"
ip link set "$VETH_DEV" netns "$NS"

# Root-side (bussard) endpoint.
ip addr add "$HOST_IP/$PREFIX" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip link set "$VETH_HOST" multicast on
# Route the KNX routing group out veth-host so bussard's INADDR_ANY join/send
# (local_interface 0.0.0.0) resolves to this link rather than the runner's eth0.
ip route add "$MGROUP/32" dev "$VETH_HOST" 2>/dev/null || \
    ip route replace "$MGROUP/32" dev "$VETH_HOST"

# Device-side endpoint, inside the namespace.
ip netns exec "$NS" ip addr add "$DEV_IP/$PREFIX" dev "$VETH_DEV"
ip netns exec "$NS" ip link set "$VETH_DEV" up
ip netns exec "$NS" ip link set "$VETH_DEV" multicast on
# The namespace also needs loopback up (some stacks touch it) and a multicast
# route so the device's INADDR_ANY send egresses veth-dev.
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add "$MGROUP/32" dev "$VETH_DEV" 2>/dev/null || \
    ip netns exec "$NS" ip route replace "$MGROUP/32" dev "$VETH_DEV"

echo "[netns] ready: device runs in $NS on $DEV_IP, bussard on $HOST_IP (veth-host)" >&2
echo "[netns] host maddr:" >&2
ip maddr show dev "$VETH_HOST" >&2 || true

# Emit the eval-able knobs for the caller.
printf "BUSSARD_VIRTUAL_DEVICE_WRAP='ip netns exec %s'\n" "$NS"
printf "BUSSARD_ROUTING_IFACE_HINT=%s\n" "$HOST_IP"
