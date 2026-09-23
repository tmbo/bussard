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
#   POSITIVE  flash + apply 1.1.10 with --keyring (synthetic.knxkeys) -> the
#             security object is unloaded, reloaded with the IA-table clear,
#             the group key table and the GO security flags, and completed
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
# 1.1.2 and 1.1.3 have no links (a bare vendor-default flash). 1.1.10, the
# keyring peer, links object 1 to the keyed 1/2/3 (group key in
# synthetic.knxkeys, `secure: true` as an import records it) and object 2 to
# plain GAs.
mkdir -p "$MODEL/devices"
cat > "$MODEL/groups.yaml" <<'EOF'
project: secure
groups:
  1/2/1:
    name: Plain early
    dpt: '5.001'
  1/2/3:
    name: Secured dimming
    dpt: '3.007'
    secure: true
  1/2/4:
    name: Plain value
    dpt: '5.001'
EOF
cat > "$MODEL/devices/1.1.10-secure-dimmer.yaml" <<'EOF'
address: 1.1.10
name: Secure dimmer
product:
  manufacturer_ref: M-00FA
  application_ref: M-00FA_A-2500-10-51CB
  mask: 07B0
com_objects:
  1:
    dpt: '3.007'
    flags: CW
    secure: true
  2:
    dpt: '5.001'
    flags: CW
security:
  secure_capable: true
  activated: true
EOF
# write_links <GA...>: 1.1.10 object 1 listens on 1/2/3, object 2 on the GAs given.
write_links() {
  {
    printf 'links:\n  1.1.10:\n    - object: 1\n      listen:\n        - 1/2/3\n'
    printf '    - object: 2\n      listen:\n'
    for ga in "$@"; do printf '        - %s\n' "$ga"; done
  } > "$MODEL/links.yaml"
}
write_links 1/2/4
ok "model at $MODEL (1.1.10 linked to the keyed 1/2/3)"

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

# --- POSITIVE: --keyring programs the security object (issue #156) ----------
say "positive: --keyring flash and apply program the security object"
KEYRING="$HERE/synthetic.knxkeys"
export BUSSARD_KEYRING_PASSWORD="synthetic-keyring-pw"   # SYNTHETIC

out="$(flash 1.1.10 --keyring "$KEYRING" --dry-run -v)"
if grep -qF "Data Secure: write group key table (PID 53, 1 key(s) for 1/2/3@1" <<<"$out" \
   && grep -qF "Data Secure: write group-object security flags (PID 61" <<<"$out" \
   && grep -qF "secured: 1)" <<<"$out"; then
  ok "dry run lists the security-object steps (PID 53 key for 1/2/3 at index 1, PID 61 flags object 1)"
else
  bad "the dry run did not list the expected security-object steps"
  grep -i "data secure" <<<"$out" | sed 's/^/      /'
fi

mark=$(log_mark)
out="$(flash 1.1.10 --keyring "$KEYRING")"
if grep -q "is Loaded on 1.1.10" <<<"$out"; then
  ok "1.1.10 flashed to verified Loaded with --keyring"
else
  bad "keyring flash of 1.1.10 failed"; tail -8 <<<"$out" | sed 's/^/      /'
fi
for want in \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=Unload rc=0x00 state=Unloaded" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=StartLoading rc=0x00 state=Loading" \
  "SECOBJ WriteCon iot=17/1 pid=54 start=0 count=1 rc=0x00" \
  "SECOBJ WriteCon iot=17/1 pid=53 start=1 count=1 rc=0x00" \
  "SECOBJ WriteCon iot=17/1 pid=61 start=1 count=" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=LoadCompleted rc=0x00 state=Loaded"; do
  if log_has "$mark" "$want"; then
    ok "flash: sim saw '${want#SECOBJ }'"
  else
    bad "flash: sim did not see '$want'"
  fi
done
if log_since "$mark" | grep -E "SECOBJ .* rc=0x[fF]" >/dev/null; then
  bad "flash: the security object refused an operation"
  log_since "$mark" | grep -E "SECOBJ .* rc=0x[fF]" | head -3 | sed 's/^/      /'
else
  ok "flash: every security-object operation answered rc=0x00"
fi

# A link change moves the keyed GA to address-table index 2 (1/2/1 sorts
# first): apply must reprogram the key table next to the tables.
write_links 1/2/1 1/2/4
mark=$(log_mark)
out="$("$BUSSARD" apply 1.1.10 --dir "$MODEL" --yes --gateway "$GATEWAY" --keyring "$KEYRING" 2>&1)"
if grep -q "verified" <<<"$out" && grep -qF "Data Secure: the security object is reprogrammed" <<<"$out"; then
  ok "apply --keyring verified and announced the security-object reprogramming"
else
  bad "apply --keyring failed"; tail -8 <<<"$out" | sed 's/^/      /'
fi
for want in \
  "SECOBJ ValueRead iot=17/1 pid=61 start=0" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=Unload rc=0x00" \
  "SECOBJ WriteCon iot=17/1 pid=53 start=1 count=1 rc=0x00" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=LoadCompleted rc=0x00 state=Loaded"; do
  if log_has "$mark" "$want"; then
    ok "apply: sim saw '${want#SECOBJ }'"
  else
    bad "apply: sim did not see '$want'"
  fi
done
unset BUSSARD_KEYRING_PASSWORD
write_links 1/2/4

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

# 4. describe (issue #155): with the tool key the secured walk reports objects;
#    without it bussard must exit non-zero and point at --keyring, never exit 0
#    with an empty object list.
out="$("$BUSSARD" describe 1.1.2 --json --dir "$MODEL" --gateway "$GATEWAY" --tool-key "$TOOL_KEY" 2>/dev/null)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q '"secured_management": "used"' <<<"$out" && grep -q '"object_type"' <<<"$out"; then
  ok "describe 1.1.2 with the tool key: secured walk returned objects"
else
  bad "describe 1.1.2 with the tool key did not report a secured walk (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
out="$("$BUSSARD" describe 1.1.2 --json --dir "$MODEL" --gateway "$GATEWAY" 2>&1)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q -- "--keyring" <<<"$out"; then
  ok "describe 1.1.2 without a key: exit $rc with the --keyring hint"
else
  bad "describe 1.1.2 without a key did not fail with the --keyring hint (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
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
