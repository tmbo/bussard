#!/usr/bin/env bash
#
# Fetch and build thelsing/knx's Linux KNXnet/IP demo device as an EXTERNAL test
# peer for bussard's integration tests.
#
# License framing: thelsing/knx is GPL-3.0. This script and the harness around it
# are bussard's own (MIT). We never link, vendor, or port any of that code into
# bussard — we clone it at test time, build it into a standalone executable, and
# run it as a separate process that bussard talks to over the wire (KNXnet/IP
# routing multicast). That is ordinary "run an independent program over a network
# socket" interop, not derivation.
#
# What gets built: the `knx-linux-ip` binary (CMake target in
# examples/knx-linux/CMakeLists.txt, compiled with MASK_VERSION=0x57B0). That is
# the ONLY one of thelsing's three Linux demo binaries that speaks KNXnet/IP
# routing over multicast 224.0.23.12 — the `-tp` and `-rf` variants drive a serial
# TP-UART / CC1101 radio and need real hardware (/dev/ttyUSB0, SPI GPIO), which CI
# does not have. See README.md in this directory for the mask-version consequence
# (57B0 vs the 07B0 bussard's reconstruct/apply gate on).
#
# Platform: LINUX ONLY. thelsing's src/linux_platform.cpp is wrapped top-to-bottom
# in `#ifdef __linux__` with no macOS branch, and pulls in Linux-only facilities
# (linux/* headers, sysfs GPIO, /dev/spidev, /dev/ttyUSB). It will NOT compile on
# macOS. A Docker container does not rescue local macOS use either: KNXnet/IP
# routing is multicast, and Docker Desktop on macOS runs the engine in a VM whose
# host-network multicast does not bridge to the macOS host, so bussard on the Mac
# could not exchange multicast with a containerised device. The honest verdict is:
# this harness runs on native Linux (developer box or CI). On macOS the script
# stops early with this explanation and a non-zero exit.
#
# Usage:
#   tests-support/virtual-device/build.sh            # clone + build into ./target/virtual-device
#   VD_DIR=/somewhere tests-support/virtual-device/build.sh
#
# On success it prints the absolute path of the built binary as the LAST line of
# stdout, and also writes it to "$VD_DIR/binary-path.txt", so callers (the CI job,
# a developer) can capture it for BUSSARD_VIRTUAL_DEVICE_BIN.

set -euo pipefail

# --- Pinned upstream: change these two together on a deliberate bump ---
KNX_REPO="${KNX_REPO:-https://github.com/thelsing/knx.git}"
# thelsing/knx master @ 2025-11-04 ("Merge PR #327 ... subgroup0-warning").
# Pinned so a CI build is reproducible and an upstream force-push cannot silently
# change what the interop tests run against.
KNX_COMMIT="${KNX_COMMIT:-980c047ad7fc5e27bf2fae95e48acde5d5e0b4fd}"

# Where everything lands. Defaults under the workspace target/ dir (gitignored),
# so a local run leaves no untracked files behind.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VD_DIR="${VD_DIR:-$REPO_ROOT/target/virtual-device}"
SRC_DIR="$VD_DIR/knx"
BUILD_DIR="$VD_DIR/build"
BIN_NAME="knx-linux-ip"
BIN_PATH="$BUILD_DIR/$BIN_NAME"

log() { printf '[virtual-device] %s\n' "$*" >&2; }

# --- Platform gate: Linux only ---
os="$(uname -s)"
if [ "$os" != "Linux" ]; then
    cat >&2 <<EOF
[virtual-device] Unsupported platform: $os

The thelsing/knx Linux demo is guarded by #ifdef __linux__ and only builds on
Linux (it uses Linux-only headers, sysfs GPIO and serial device paths). The
virtual-device harness therefore runs on native Linux only: in CI (the
'virtual-device' job on ubuntu) or on a Linux developer machine.

macOS note: a Docker container does not help, because KNXnet/IP routing is
multicast and Docker Desktop for Mac cannot bridge host-network multicast between
the macOS host and the Linux VM. Use a real/virtual Linux host instead.
EOF
    exit 3
fi

# --- Toolchain check ---
missing=()
command -v git   >/dev/null 2>&1 || missing+=("git")
command -v cmake >/dev/null 2>&1 || missing+=("cmake")
if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
    missing+=("g++ or clang++")
fi
if [ "${#missing[@]}" -ne 0 ]; then
    log "missing required tools: ${missing[*]}"
    log "on Debian/Ubuntu: sudo apt-get install -y git cmake build-essential"
    exit 4
fi

mkdir -p "$VD_DIR"

# --- Clone (or reuse) the pinned source ---
if [ -d "$SRC_DIR/.git" ]; then
    log "reusing existing clone at $SRC_DIR"
    git -C "$SRC_DIR" fetch --depth 1 origin "$KNX_COMMIT" >/dev/null 2>&1 || \
        git -C "$SRC_DIR" fetch origin >/dev/null 2>&1 || true
else
    log "cloning $KNX_REPO"
    rm -rf "$SRC_DIR"
    # Fetch just the pinned commit where the server supports it; fall back to a
    # full clone + checkout otherwise.
    if ! git clone --filter=blob:none "$KNX_REPO" "$SRC_DIR" >/dev/null 2>&1; then
        git clone "$KNX_REPO" "$SRC_DIR"
    fi
fi

log "checking out pinned commit $KNX_COMMIT"
git -C "$SRC_DIR" checkout -q "$KNX_COMMIT"
actual="$(git -C "$SRC_DIR" rev-parse HEAD)"
if [ "$actual" != "$KNX_COMMIT" ]; then
    log "WARNING: HEAD is $actual, expected $KNX_COMMIT"
fi

# --- Build knx-linux-ip only ---
log "configuring CMake ($BUILD_DIR)"
cmake -S "$SRC_DIR/examples/knx-linux" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release >&2

log "building target $BIN_NAME"
cmake --build "$BUILD_DIR" --target "$BIN_NAME" -j "$(nproc)" >&2

if [ ! -x "$BIN_PATH" ]; then
    log "ERROR: expected binary not found at $BIN_PATH"
    exit 5
fi

# Record and print the path (last stdout line = the binary path, for capture).
printf '%s\n' "$BIN_PATH" > "$VD_DIR/binary-path.txt"
log "built $BIN_NAME"
log "commit:   $actual"
log "binary:   $BIN_PATH"
log "run tests with:"
log "  export BUSSARD_VIRTUAL_DEVICE=1"
log "  export BUSSARD_VIRTUAL_DEVICE_BIN=$BIN_PATH"
log "  cargo test -p bussard-cli --test virtual_device -- --ignored"
printf '%s\n' "$BIN_PATH"
