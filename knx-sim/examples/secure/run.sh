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
#   POSITIVE  the security individual address table (PID 54, issue #181): the
#             flash lists the secured sender 1.1.20 (a model-only device that
#             sends on 1/2/3); a secured `write` from bussard's tunnel address
#             1.0.0 is dropped by the sim until `apply --secure-sender 1.0.0`
#             adds it
#   POSITIVE  secured group communication on 1/2/3 (issue #172): `write` and
#             `read --keyring` ride A_SecureData under the group key, the sim
#             answers the read secured, and `monitor --keyring` decrypts the
#             sim's secured stimulus write (secured: true)
#   NEGATIVE  `read 1/2/3` without --keyring -> refused with the --keyring hint, nothing sent
#   NEGATIVE  flash 1.1.2 with a WRONG tool key  -> fails, sim refuses the MAC, nothing written
#   NEGATIVE  flash 1.1.2 with NO tool key       -> fails, sim refuses plain access, nothing written
#   NEGATIVE  flash 1.1.3 (plain device) WITH a tool key -> fails, sim refuses (not activated)
#   POSITIVE  reconstruct 1.1.2 with the tool key -> secured read: mask 07B0, tables and
#             the parameter read-back (issue #170)
#   NEGATIVE  reconstruct 1.1.2 with NO tool key  -> fails with the --keyring hint
#
# KNXnet/IP Secure (Phase B, issue #71; sim-ipsecure.yaml, a secure-only
# interface on port 13694):
#   NEGATIVE  scan without credentials -> refused at once, names KNXnet/IP Secure (#182)
#   POSITIVE  flash 1.1.10 --keyring   -> secure tunnel picked from the keyring, Data
#             Secure inside it, verified Loaded
#   POSITIVE  describe 1.1.3 --secure-user 2 --secure-password-env -> explicit user
#   NEGATIVE  a wrong tunnelling password -> refused, the sim reports the failed auth
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
    # R and T so the secured group object answers a read and transmits the
    # sim's stimulus (issue #172).
    flags: CRWT
    secure: true
  2:
    dpt: '5.001'
    flags: CW
security:
  secure_capable: true
  activated: true
EOF
# write_links <GA...>: 1.1.10 object 1 listens on 1/2/3, object 2 on the GAs
# given. 1.1.20 (in the model only, not on the sim bus) sends on the secured
# 1/2/3, so it is a secured sender of 1.1.10 (PID 54, issue #181).
write_links() {
  {
    printf 'links:\n  1.1.10:\n    - object: 1\n      listen:\n        - 1/2/3\n'
    printf '    - object: 2\n      listen:\n'
    for ga in "$@"; do printf '        - %s\n' "$ga"; done
    printf '  1.1.20:\n    - object: 1\n      send: 1/2/3\n'
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
if grep -qF "Data Secure: write security individual address table (PID 54, 1 secured sender(s): 1.1.20 seq 0)" <<<"$out"; then
  ok "dry run lists the secured sender 1.1.20 (PID 54, sequence 0: not in the keyring)"
else
  bad "the dry run did not list the PID 54 entry for 1.1.20"
  grep -i "PID 54" <<<"$out" | sed 's/^/      /'
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
  "SECOBJ WriteCon iot=17/1 pid=54 start=1 count=1 rc=0x00" \
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

# --- NEGATIVE: bussard's own address is not a secured sender (issue #181) ---
# The flash listed only 1.1.20 in PID 54, so the device drops a secured write
# from bussard's tunnel address (1.0.0, the sim's CRD) although the MAC is good.
mark=$(log_mark)
"$BUSSARD" write 1/2/3 on --dpt 1.001 --yes --dir "$MODEL" --gateway "$GATEWAY" \
  --keyring "$KEYRING" >/dev/null 2>&1
if log_has "$mark" "REJECTED SECURE group recv 1.0.0 -> 1/2/3: sender not in the security individual address table (PID 54)"; then
  ok "a secured write from an unlisted sender (1.0.0) is dropped by the device (PID 54)"
else
  bad "the sim did not drop the secured write from the unlisted 1.0.0"
  log_since "$mark" | grep -i "secure group\|REJECTED" | head -3 | sed 's/^/      /'
fi

# A link change moves the keyed GA to address-table index 2 (1/2/1 sorts
# first): apply must reprogram the key table next to the tables.
# `--secure-sender 1.0.0` adds bussard's tunnel address to PID 54 (issue #181),
# so the secured group writes below are accepted.
write_links 1/2/1 1/2/4
mark=$(log_mark)
out="$("$BUSSARD" apply 1.1.10 --dir "$MODEL" --yes --gateway "$GATEWAY" --keyring "$KEYRING" \
  --secure-sender 1.0.0 2>&1)"
if grep -q "verified" <<<"$out" && grep -qF "Data Secure: the security object is reprogrammed" <<<"$out"; then
  ok "apply --keyring verified and announced the security-object reprogramming"
else
  bad "apply --keyring failed"; tail -8 <<<"$out" | sed 's/^/      /'
fi
if grep -qF "2 secured sender(s) 1.0.0 seq 0, 1.1.20 seq 0" <<<"$out"; then
  ok "apply --secure-sender 1.0.0 announces PID 54 entries 1.0.0 and 1.1.20 (ascending)"
else
  bad "apply did not announce the PID 54 entries"; grep -i "data secure" <<<"$out" | sed 's/^/      /'
fi
for want in \
  "SECOBJ ValueRead iot=17/1 pid=61 start=0" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=Unload rc=0x00" \
  "SECOBJ WriteCon iot=17/1 pid=54 start=1 count=2 rc=0x00" \
  "SECOBJ WriteCon iot=17/1 pid=53 start=1 count=1 rc=0x00" \
  "SECOBJ FunctionCommand iot=17/1 pid=5 event=LoadCompleted rc=0x00 state=Loaded"; do
  if log_has "$mark" "$want"; then
    ok "apply: sim saw '${want#SECOBJ }'"
  else
    bad "apply: sim did not see '$want'"
  fi
done

# --- POSITIVE: secured group communication on 1/2/3 (issue #172) -----------
# 1.1.10 is now loaded with the group key of 1/2/3 (PID 53) and object 1
# flagged secured (PID 61). A plain telegram on 1/2/3 would be ignored.
say "positive: secured group read / write / monitor (issue #172)"
group_args=(--dir "$MODEL" --gateway "$GATEWAY" --keyring "$KEYRING")

mark=$(log_mark)
out="$("$BUSSARD" write 1/2/3 on --dpt 1.001 --yes "${group_args[@]}" 2>&1)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q "secured: KNX Data Secure group write" <<<"$out"; then
  ok "write 1/2/3 --keyring: sent as a secured group write"
else
  bad "write 1/2/3 --keyring failed (exit $rc)"; tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "-> 1/2/3 scf=0x10\[auth+enc\] seq=[0-9]* inner=GroupValueWrite ok"; then
  ok "the sim verified and accepted the secured GroupValueWrite (SCF 0x10)"
else
  bad "the sim did not accept a secured GroupValueWrite on 1/2/3"
  log_since "$mark" | grep -i "secure group\|REJECTED" | head -3 | sed 's/^/      /'
fi

mark=$(log_mark)
out="$("$BUSSARD" read 1/2/3 "${group_args[@]}" 2>&1)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q "secured: KNX Data Secure response from 1.1.10 verified" <<<"$out"; then
  ok "read 1/2/3 --keyring: secured response from 1.1.10 verified ($(tail -1 <<<"$out"))"
else
  bad "read 1/2/3 --keyring failed (exit $rc)"; tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "inner=GroupValueRead ok" \
   && log_has "$mark" "SECURE group send 1.1.10 -> 1/2/3 scf=0x10\[auth+enc\] seq=[0-9]* inner=GroupValueResponse"; then
  ok "the sim verified the secured read and answered with a secured GroupValueResponse"
else
  bad "the sim did not answer the secured read secured"
  log_since "$mark" | grep -i "secure group\|REJECTED\|IGNORED" | head -3 | sed 's/^/      /'
fi

mark=$(log_mark)
out="$(BUSSARD_KEYRING_PASSWORD= "$BUSSARD" read 1/2/3 --dir "$MODEL" --gateway "$GATEWAY" 2>&1)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q -- "--keyring" <<<"$out"; then
  ok "read 1/2/3 without --keyring: refused with the --keyring hint (exit $rc)"
else
  bad "read of a secured GA without a key was not refused (exit $rc)"; tail -3 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE group recv\|IGNORED PLAIN"; then
  bad "a keyless read of a secured GA still put a telegram on the bus"
else
  ok "read 1/2/3 without --keyring: nothing reached the bus"
fi

# The sim's stimulus re-sends object 1 as a secured GroupValueWrite every 5 s.
MON_OUT="$(mktemp -t knxsimmon.XXXXXX)"
"$BUSSARD" monitor --json "${group_args[@]}" >"$MON_OUT" 2>/dev/null &
MON_PID=$!
sleep 7
kill "$MON_PID" 2>/dev/null; wait "$MON_PID" 2>/dev/null
if grep '"destination":"1/2/3"' "$MON_OUT" | grep '"source":"1.1.10"' | grep -q '"secured":true'; then
  ok "monitor --keyring decrypted the sim's secured stimulus write (secured: true)"
else
  bad "monitor --keyring showed no verified secured telegram from 1.1.10 on 1/2/3"
  head -3 "$MON_OUT" | sed 's/^/      /'
fi
if grep -q '"secure_status":"mac_failed"' "$MON_OUT"; then
  bad "monitor --keyring reported a MAC failure"
else
  ok "monitor --keyring: no MAC failures"
fi
rm -f "$MON_OUT"

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

# 5. reconstruct (issue #170): with the tool key every read, the descriptor
#    included, rides A_SecureData, so the device reports its real mask and the
#    table reads and the parameter read-back run on the secured session.
mark=$(log_mark)
out="$("$BUSSARD" reconstruct 1.1.2 --json --dir "$MODEL" --gateway "$GATEWAY" \
  --product "$PRODUCT" --application "$APP" --tool-key "$TOOL_KEY" 2>/dev/null)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q '"mask": "07B0"' <<<"$out" && grep -q '"addresses"' <<<"$out" \
   && grep -q '"parameters"' <<<"$out"; then
  ok "reconstruct 1.1.2 with the tool key: secured read returned mask 07B0, tables and parameters"
else
  bad "reconstruct 1.1.2 with the tool key did not read the device back (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE recv scf=0x90"; then
  ok "reconstruct: the reads rode A_SecureData"
else
  bad "reconstruct: the simulator saw no secured frames"
fi
if log_has "$mark" "REJECTED"; then
  bad "reconstruct: the simulator refused a frame on the secured read"
  log_since "$mark" | grep "REJECTED" | head -3 | sed 's/^/      /'
else
  ok "reconstruct: no frame was refused on the secured read"
fi
# Without the key the sim drops every plain frame, so this waits out the
# default L4 budget (about 12 s) before it fails.
out="$("$BUSSARD" reconstruct 1.1.2 --dir "$MODEL" --gateway "$GATEWAY" 2>&1)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q -- "--keyring" <<<"$out"; then
  ok "reconstruct 1.1.2 without a key: exit $rc with the --keyring hint"
else
  bad "reconstruct 1.1.2 without a key did not fail with the --keyring hint (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi

unset BUSSARD_FLASH_L4_TIMEOUT_MS
kill "$SIM_PID" 2>/dev/null

# --- KNXnet/IP Secure (Phase B, issue #71) ------------------------------------
say "KNXnet/IP Secure: a secure-only interface"
GATEWAY2="127.0.0.1:13694"
SIM_LOG="$(mktemp -t knxsimipsec.XXXXXX)"
RUST_LOG=${RUST_LOG:-info,knx_sim=debug} "$SERVE" "$HERE/sim-ipsecure.yaml" >"$SIM_LOG" 2>&1 &
SIM_PID=$!
trap 'kill "$SIM_PID" 2>/dev/null; exit 130' INT TERM
sleep 2
if ! kill -0 "$SIM_PID" 2>/dev/null; then
  echo "secure simulator did not start:"; cat "$SIM_LOG"; exit 1
fi
ok "secure-only simulator listening on $GATEWAY2 (UDP + TCP, pid $SIM_PID)"
export BUSSARD_KEYRING_PASSWORD="synthetic-keyring-pw"   # SYNTHETIC
export SIM_TUNNEL_PW="tunnel-user-pw"                    # SYNTHETIC
export SIM_WRONG_PW="not-the-tunnel-password"

mark=$(log_mark)
started=$SECONDS
out="$("$BUSSARD" scan 1.1 --from 3 --to 3 --dir "$MODEL" --gateway "$GATEWAY2" 2>&1)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q "requires KNXnet/IP Secure" <<<"$out" \
   && ! grep -q "retrying" <<<"$out" && (( SECONDS - started < 10 )); then
  ok "scan without credentials: refused at once, names KNXnet/IP Secure (exit $rc)"
else
  bad "scan against the secure-only interface did not fail fast and clearly (exit $rc)"
  tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "plain CONNECT refused"; then
  ok "the sim refused the plain CONNECT (0x22)"
else
  bad "the sim did not see a refused plain CONNECT"
fi

mark=$(log_mark)
out="$("$BUSSARD" flash 1.1.10 --product "$PRODUCT" --application "$APP" --bcu-key FFFFFFFF \
  --dir "$MODEL" --yes --gateway "$GATEWAY2" --keyring "$KEYRING" 2>&1)"
if grep -q "is Loaded on 1.1.10" <<<"$out"; then
  ok "flash 1.1.10 --keyring over the secure tunnel: verified Loaded"
else
  bad "flash 1.1.10 over the secure tunnel failed"; tail -8 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE session authenticated" && log_has "$mark" "SECURE recv scf=0x90"; then
  ok "the sim authenticated the keyring's user 2 and saw Data Secure inside the session"
else
  bad "the sim saw no authenticated secure session or no Data Secure frames"
  log_since "$mark" | grep -i "secure" | head -5 | sed 's/^/      /'
fi

mark=$(log_mark)
out="$("$BUSSARD" describe 1.1.3 --json --dir "$MODEL" --gateway "$GATEWAY2" \
  --secure-user 2 --secure-password-env SIM_TUNNEL_PW 2>/dev/null)"
rc=$?
if [[ $rc -eq 0 ]] && grep -q '"object_type"' <<<"$out"; then
  ok "describe 1.1.3 with --secure-user 2: read the plain device through the secure tunnel"
else
  bad "describe 1.1.3 with an explicit secure user failed (exit $rc)"; tail -4 <<<"$out" | sed 's/^/      /'
fi

mark=$(log_mark)
out="$("$BUSSARD" describe 1.1.3 --dir "$MODEL" --gateway "$GATEWAY2" \
  --secure-user 2 --secure-password-env SIM_WRONG_PW 2>&1)"
rc=$?
if [[ $rc -ne 0 ]] && grep -q "refused tunnelling user 2" <<<"$out"; then
  ok "a wrong tunnelling password: refused with the user named (exit $rc)"
else
  bad "a wrong tunnelling password did not fail cleanly (exit $rc)"; tail -4 <<<"$out" | sed 's/^/      /'
fi
if log_has "$mark" "SECURE authentication refused"; then
  ok "the sim refused the authentication"
else
  bad "the sim did not report the refused authentication"
fi
unset BUSSARD_KEYRING_PASSWORD SIM_TUNNEL_PW SIM_WRONG_PW

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
echo "  both CCM modes, negatives refused on both sides, plain path unchanged,"
echo "  secured group read/write/monitor on 1/2/3, PID 54 secured senders,"
echo "  KNXnet/IP Secure tunnelling (keyring and explicit user, secure-only"
echo "  refusal, wrong password)"
