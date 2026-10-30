#!/usr/bin/env bash
# Cross-build knx-sim for Windows (x86_64-pc-windows-gnu) in Docker, for the
# ETS sweep: the sim runs INSIDE the Windows VM so ETS reaches it on 127.0.0.1
# (the Mac's managed firewall drops the ping ETS insists on). The source is
# mounted read-only; the target dir and CARGO_HOME live on the host so a second
# build is incremental. Output: knx-sim/target-win/x86_64-pc-windows-gnu/release/knx-sim.exe
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_HOME_DIR="${KNX_SIM_WIN_CARGO_HOME:-$REPO/knx-sim/target-win/cargo-home}"
mkdir -p "$REPO/knx-sim/target-win" "$CARGO_HOME_DIR"
docker run --rm \
  -v "$REPO/knx-sim:/src:ro" \
  -v "$REPO/knx-sim/target-win:/target" \
  -v "$CARGO_HOME_DIR:/usr/local/cargo-host" \
  -e CARGO_HOME=/usr/local/cargo-host \
  -e CARGO_TARGET_DIR=/target \
  -w /src \
  rust:latest bash -c '
    set -e
    export PATH=/usr/local/cargo-host/bin:/usr/local/cargo/bin:$PATH
    [ -x /usr/local/cargo-host/bin/cargo ] || cp -r /usr/local/cargo/. /usr/local/cargo-host/
    apt-get update -qq >/dev/null && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null
    rustup target add x86_64-pc-windows-gnu >/dev/null
    cargo build --release --locked --target x86_64-pc-windows-gnu 2>&1 | tail -5
  '
EXE="$REPO/knx-sim/target-win/x86_64-pc-windows-gnu/release/knx-sim.exe"
# The commit the exe was built from, for the synthetic capture manifest
# (tools/ets-sweep/synthetic/capture.py); `-dirty` when knx-sim/ had changes.
sha="$(git -C "$REPO" rev-parse HEAD)"
git -C "$REPO" diff --quiet HEAD -- knx-sim || sha="$sha-dirty"
printf '%s\n' "$sha" >"$EXE.git"
ls -la "$EXE"
