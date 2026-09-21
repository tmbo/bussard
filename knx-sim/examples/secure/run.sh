#!/usr/bin/env bash
#
# End-to-end demo of the KNX Data Secure (Phase A) conformance loop: build both
# projects, start the knx-sim gateway with one security-ACTIVATED device and one
# plain device, then drive `bussard flash` against it.
#
# Devices (both KNX Virtual DA.tp, mask 07B0):
#   1.1.2  security-ACTIVATED (synthetic tool key, see sim.yaml)
#   1.1.3  plain
#
# What it asserts:
#   POSITIVE  flash 1.1.2 with the right tool key, CCM auth+encrypt  -> verified Loaded
#   POSITIVE  flash 1.1.2 with the right tool key, CCM auth-only     -> verified Loaded
#   POSITIVE  flash 1.1.3 plain (no tool key)                        -> verified Loaded
#   NEGATIVE  flash 1.1.2 with a WRONG tool key  -> fails, sim refuses the MAC, nothing written
#   NEGATIVE  flash 1.1.2 with NO tool key       -> fails, sim refuses plain access, nothing written
#   NEGATIVE  flash 1.1.3 (plain device) WITH a tool key -> fails, sim refuses (not activated)
#
# The negatives are checked on both sides: bussard must exit non-zero with an
# actionable message, and the simulator's event log must show the refusal reason.
#
# Exits non-zero if any assertion fails. Run from anywhere:
#   knx-sim/examples/secure/run.sh
#
# The KNX Virtual `.knxprod` is vendor data and git-ignored; place it at
# knx-sim/tests/fixtures/KNX_Virtual_M-00FA.knxprod (the same fixture the sim's
# ETS calibration tests use).
#
# ALL key material here is SYNTHETIC (spec §12.3): the tool key lives in sim.yaml
# and is passed to bussard with `--tool-key`, the test/bench escape hatch. A real
# installation uses `--keyring <file.knxkeys>` with BUSSARD_KEYRING_PASSWORD.

set -uo pipefail

# --- Locate the repo, the example, and the two binaries ---------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../examples/secure
SIM_DIR="$(cd "$HERE/../.." && pwd)"                           # .../knx-sim
REPO="$(cd "$SIM_DIR/.." && pwd)"                              # repo root
SIM_YAML="$HERE/sim.yaml"
MODEL="$HERE/model"
GATEWAY="127.0.0.1:13693"
PRODUCT="$SIM_DIR/tests/fixtures/KNX_Virtual_M-00FA.knxprod"
APP="M-00FA_A-2500-10-51CB"

# The synthetic tool key of the activated device, mirroring sim.yaml.
TOOL_KEY="0102030405060708090a0b0c0d0e0f10"
WRONG_KEY="ffffffffffffffffffffffffffffffff"

BUSSARD="$REPO/target/debug/bussard"
SERVE="$SIM_DIR/target/debug/serve"

# A tiny reboot wait keeps the after-restart verify fast against the local sim.
export BUSSARD_FLASH_REBOOT_WAIT_MS=200
# The negatives end in a device that deliberately says nothing; a short L4 budget
# makes them fail in a second instead of the full 3 s ACK-retransmit wait.
NEG_TIMEOUT_MS=400

pass=0
fail=0
say()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }

# --- Build both projects ----------------------------------------------------
say "build"
( cd "$REPO" && cargo build --bin bussard ) || { echo "bussard build failed"; exit 1; }
( cd "$SIM_DIR" && cargo build --bin serve ) || { echo "knx-sim build failed"; exit 1; }
ok "built bussard and knx-sim"

# --- Ensure the product fixture is present ----------------------------------
if [[ ! -f "$PRODUCT" ]]; then
  echo "  missing product fixture: $PRODUCT"
  echo "    place the KNX Virtual .knxprod there (git-ignored vendor data)."
  exit 1
fi
ok "product fixture present"

# --- A bare (empty) model dir for the flashes -------------------------------
say "model"
mkdir -p "$MODEL"
cat > "$MODEL/bussard.yaml" <<EOF
connection:
  transport: tunnel
  gateway: $GATEWAY
EOF
printf 'project: secure\ngroups: {}\n' > "$MODEL/groups.yaml"
printf 'links: {}\n'                   > "$MODEL/links.yaml"
ok "bare model at $MODEL"

# --- Start the simulator ----------------------------------------------------
say "start simulator"
SIM_LOG="$(mktemp -t knxsimsec.XXXXXX)"
pkill -f "$SERVE" 2>/dev/null
# info + knx_sim=debug so every REJECTED reason (wrong MAC, replay, plain access)
# lands in the log: that log is the oracle for every negative below.
RUST_LOG=${RUST_LOG:-info,knx_sim=debug} "$SERVE" "$SIM_YAML" >"$SIM_LOG" 2>&1 &
SIM_PID=$!
# Tear the simulator down on interrupt, and again at the end (explicit kill
# before exit). We deliberately do NOT trap EXIT: an EXIT trap also fires when a
# $(...) command-substitution subshell finishes, which would kill the simulator
# after the very first captured command.
trap 'kill "$SIM_PID" 2>/dev/null; exit 130' INT TERM
sleep 2
if ! kill -0 "$SIM_PID" 2>/dev/null; then
  echo "simulator did not start:"; cat "$SIM_LOG"; exit 1
fi
ok "simulator listening on $GATEWAY (pid $SIM_PID)"

# --- Helpers ----------------------------------------------------------------
# flash <ia> [extra bussard args...]
flash() {
  local ia=$1; shift
  "$BUSSARD" flash "$ia" \
    --product "$PRODUCT" --application "$APP" --bcu-key FFFFFFFF \
    --dir "$MODEL" --yes --gateway "$GATEWAY" "$@" 2>&1
}

# The number of lines the simulator has logged so far, so each case only greps
# the frames it caused.
log_mark() { wc -l < "$SIM_LOG" | tr -d ' '; }
log_since() { tail -n "+$(( $1 + 1 ))" "$SIM_LOG"; }
# Does the log since <mark> contain <pattern>? `grep -c` (not `grep -q`) because
# `-q` exits at the first match, which SIGPIPEs the `tail` feeding it and, under
# `set -o pipefail`, turns a match into a failing pipeline.
log_has() { log_since "$1" | grep -c -- "$2" >/dev/null; }

# --- POSITIVE: the activated device, both CCM modes -------------------------
say "positive: secure flash to verified Loaded"

mark=$(log_mark)
out="$(flash 1.1.2 --tool-key "$TOOL_KEY")"
if grep -q "is Loaded on 1.1.2" <<<"$out"; then
  ok "1.1.2 (activated) flashed to verified Loaded via A_SecureData [auth+enc]"
else
  bad "secure flash of 1.1.2 failed [auth+enc]"; tail -6 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE recv scf=0x90\[auth+enc,tool=true\]"; then
  ok "every management APDU rode A_SecureData with SCF 0x90 (tool-access, auth+enc)"
else
  bad "the simulator saw no tool-access auth+enc secure frames"
fi
if log_has "$mark" "REJECTED"; then
  bad "the simulator refused a frame during the happy path"
  log_since "$mark" | grep "REJECTED" | head -3 | sed 's/^/      /'
else
  ok "no frame was refused during the happy path"
fi

# The same flash in CCM authentication-only mode (spec §12.2 asks for both).
mark=$(log_mark)
out="$(BUSSARD_SECURE_ALGORITHM=auth flash 1.1.2 --tool-key "$TOOL_KEY")"
if grep -q "is Loaded on 1.1.2" <<<"$out"; then
  ok "1.1.2 (activated) flashed to verified Loaded via A_SecureData [auth-only]"
else
  bad "secure flash of 1.1.2 failed [auth-only]"; tail -6 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE recv scf=0x80\[auth,tool=true\]"; then
  ok "auth-only mode used SCF 0x80 (tool-access, MAC only)"
else
  bad "the simulator saw no tool-access auth-only secure frames"
fi

# --- POSITIVE: the plain device is untouched by KNX Secure ------------------
say "positive: the plain path is unchanged"
mark=$(log_mark)
out="$(flash 1.1.3)"
if grep -q "is Loaded on 1.1.3" <<<"$out"; then
  ok "1.1.3 (plain) flashed to verified Loaded with no tool key"
else
  bad "plain flash of 1.1.3 failed"; tail -6 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE"; then
  bad "the plain path emitted secure frames"
else
  ok "the plain path emitted no A_SecureData at all"
fi

# --- NEGATIVES --------------------------------------------------------------
say "negatives"
export BUSSARD_FLASH_L4_TIMEOUT_MS=$NEG_TIMEOUT_MS

# 1. A wrong tool key: the device cannot authenticate the frame and drops it.
mark=$(log_mark)
out="$(flash 1.1.2 --tool-key "$WRONG_KEY")"
rc=$?
if [[ $rc -ne 0 ]] && grep -q "SECURED management access" <<<"$out"; then
  ok "wrong tool key: bussard failed with the secure-cause message (exit $rc)"
else
  bad "wrong tool key did not fail with an actionable message (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "MAC verification failed"; then
  ok "wrong tool key: the device refused the MAC"
else
  bad "the simulator did not report a MAC refusal"
fi
if log_since "$mark" | grep -cE "MemoryWrite|PropertyValueWrite" >/dev/null; then
  bad "a wrong-key run wrote to the device"
else
  ok "wrong tool key: nothing was written (no memory/property write reached the device)"
fi

# 2. No tool key at all against an activated device: plain access is refused.
mark=$(log_mark)
out="$(flash 1.1.2)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q -- "--keyring" <<<"$out"; then
  ok "no tool key: bussard failed and pointed at --keyring/--tool-key (exit $rc)"
else
  bad "a keyless flash of an activated device did not give actionable guidance (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "plain access refused"; then
  ok "no tool key: the device refused the plain management access"
else
  bad "the simulator did not report a plain-access refusal"
fi

# 3. A tool key against a PLAIN device: it has no tool key, so it drops the
#    frame (spec §6.4's converse direction — refused explicitly, not silently).
mark=$(log_mark)
out="$(flash 1.1.3 --tool-key "$TOOL_KEY")"
rc=$?
if [[ $rc -ne 0 ]] && grep -q "SECURED management access" <<<"$out"; then
  ok "tool key against a plain device: bussard failed with the secure-cause message (exit $rc)"
else
  bad "a secure flash of a plain device did not fail cleanly (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "NOT security-activated"; then
  ok "tool key against a plain device: the device refused (not security-activated)"
else
  bad "the simulator did not report the not-activated refusal"
fi

unset BUSSARD_FLASH_L4_TIMEOUT_MS

# --- Verdict ----------------------------------------------------------------
kill "$SIM_PID" 2>/dev/null
say "result"
printf '  %d passed, %d failed\n' "$pass" "$fail"
if [[ $fail -ne 0 ]]; then
  echo "  simulator log: $SIM_LOG"
  exit 1
fi
rm -f "$SIM_LOG"
echo "  KNX Data Secure conformance loop OK: tool-access flash to verified Loaded,"
echo "  both CCM modes, negatives refused on both sides, plain path unchanged"
