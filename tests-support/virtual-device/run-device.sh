#!/usr/bin/env bash
#
# Boot wrapper for the thelsing knx-linux-ip virtual device.
#
# The demo persists its non-volatile state to a memory-mapped file named
# "flash.bin" in its CURRENT WORKING DIRECTORY (thelsing LinuxPlatform:
# `std::string _flashFilePath = "flash.bin"`, mmap'd, 64 KiB, header 0xAF 0xFE).
# There is no CLI flag for the path on the pinned commit, so we control it purely
# by choosing the process's working directory.
#
# Two start modes:
#   fresh   (default) — run in a clean, empty directory with NO flash.bin, so the
#                       device boots unconfigured. main.cpp does:
#                           if (knx.individualAddress() == 0) knx.progMode(true);
#                       i.e. a factory-fresh device auto-enters programming mode,
#                       which is exactly what `bussard assign` looks for.
#   seed <file>       — copy an existing flash.bin into the working dir first, so
#                       the device boots already-configured (for table tests).
#
# The device joins KNXnet/IP routing multicast 224.0.23.12:3671 on the default
# interface (thelsing binds INADDR_ANY). bussard connects with `--routing`.
#
# Usage:
#   run-device.sh <binary> [--fresh]           # factory-fresh (prog mode)
#   run-device.sh <binary> --seed <flash.bin>  # pre-seeded state
#   run-device.sh <binary> --workdir <dir> ... # explicit working dir (else a mktemp)
#
# Runs in the FOREGROUND and execs the device, so the caller can manage its
# lifetime (background it, capture its PID, kill it). Prints the working dir it
# chose to stderr.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: run-device.sh <binary> [--fresh | --seed <flash.bin>] [--workdir <dir>]" >&2
    exit 2
fi

BIN="$1"; shift
MODE="fresh"
SEED_FILE=""
WORKDIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --fresh)   MODE="fresh"; shift ;;
        --seed)    MODE="seed"; SEED_FILE="${2:-}"; shift 2 ;;
        --workdir) WORKDIR="${2:-}"; shift 2 ;;
        *) echo "run-device.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ ! -x "$BIN" ]; then
    echo "run-device.sh: binary not found or not executable: $BIN" >&2
    exit 2
fi

if [ -z "$WORKDIR" ]; then
    WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/bussard-vdev.XXXXXX")"
fi
mkdir -p "$WORKDIR"

if [ "$MODE" = "seed" ]; then
    if [ -z "$SEED_FILE" ] || [ ! -f "$SEED_FILE" ]; then
        echo "run-device.sh: --seed needs an existing flash.bin (got '$SEED_FILE')" >&2
        exit 2
    fi
    cp "$SEED_FILE" "$WORKDIR/flash.bin"
    echo "[virtual-device] seeded state from $SEED_FILE" >&2
else
    # Ensure a clean, unconfigured boot: no flash.bin means prog mode.
    rm -f "$WORKDIR/flash.bin"
    echo "[virtual-device] factory-fresh boot (no flash.bin -> programming mode)" >&2
fi

echo "[virtual-device] working dir: $WORKDIR" >&2
echo "[virtual-device] starting $BIN (KNXnet/IP routing 224.0.23.12:3671)" >&2

# Resolve the binary to an absolute path before we cd, then exec from WORKDIR so
# flash.bin lands there.
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
cd "$WORKDIR"
exec "$BIN_ABS"
