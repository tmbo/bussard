#!/usr/bin/env bash
#
# End-to-end demo of the small-installation example: build both projects, start
# the knx-sim gateway with four simulated System B devices, then drive bussard
# against it to (a) scan the line, (b) flash every device to Loaded, (c) read a
# typed value served by a device, and (d) monitor live stimulus traffic and
# assert the expected group addresses / DPT values appear.
#
# Exits non-zero if any step fails. Run from anywhere:
#   knx-sim/examples/small-installation/run.sh
#
# The four vendor `.knxprod` products are copyrighted and git-ignored. This
# script resolves them from (in order): this example's local `products/` dir, or
# the product-corpus cache under the repo's `tests-support/product-corpus/cache`,
# plus the DA.tp fixture under `knx-sim/tests/fixtures`. If a product is missing
# it prints where to place it and exits non-zero.
#
# CI therefore cannot run this script — no vendor products on the runner. The
# `sim-conformance` job in .github/workflows/ci.yml runs the fixture-backed
# equivalent of both sides of this loop instead: the sim's calibration and
# capture-replay suites, and bussard's mock-gateway flash suites. Keep this
# script working, but do not rely on it to catch a regression: the CI job is what
# guards the loop on every push.

set -uo pipefail

# --- Locate the repo, the example, and the two binaries ---------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../small-installation
SIM_DIR="$(cd "$HERE/../.." && pwd)"                           # .../knx-sim
REPO="$(cd "$SIM_DIR/.." && pwd)"                              # repo root
EX="$HERE"
MODEL="$EX/knx"
SIM_YAML="$EX/sim.yaml"
PRODUCTS="$EX/products"
GATEWAY="127.0.0.1:13671"

BUSSARD="$REPO/target/debug/bussard"
# Hermetic: never pick up the repository's .env (issue #251).
export BUSSARD_NO_DOTENV=1
SERVE="$SIM_DIR/target/debug/serve"

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

# --- Ensure the four products are present -----------------------------------
declare -a NEEDED=(
  "KNX_Virtual_M-00FA.knxprod"
  "MDT_KP_AKK_03_Switch_Actuator_V23.knxprod"
  "MDT_KP_AKI_AKS_03_Switch_Actuator_V32d.knxprod"
  "MDT_KP_AKH_03_Heating_Actuator_V34.knxprod"
)
CORPUS="$REPO/tests-support/product-corpus/cache/vendor"
FIXTURE="$SIM_DIR/tests/fixtures"
mkdir -p "$PRODUCTS"
missing=0
for f in "${NEEDED[@]}"; do
  if [[ -f "$PRODUCTS/$f" ]]; then continue; fi
  if   [[ -f "$CORPUS/$f"  ]]; then cp "$CORPUS/$f"  "$PRODUCTS/$f"
  elif [[ -f "$FIXTURE/$f" ]]; then cp "$FIXTURE/$f" "$PRODUCTS/$f"
  else
    echo "  missing product: $f"
    echo "    place it in $PRODUCTS/ (git-ignored vendor data), e.g. from the"
    echo "    product corpus (tests-support/product-corpus/fetch.sh) or the KNX-Virtual export."
    missing=1
  fi
done
[[ $missing -eq 0 ]] || { echo "cannot run without the vendor products"; exit 1; }
ok "products present"

# --- Start the simulator ----------------------------------------------------
say "start simulator"
SIM_LOG="$(mktemp -t knxsim.XXXXXX)"
pkill -f "$SERVE" 2>/dev/null
RUST_LOG=${RUST_LOG:-warn} "$SERVE" "$SIM_YAML" >"$SIM_LOG" 2>&1 &
SIM_PID=$!
# Tear the simulator down on an interrupt, and again at the end of the script
# (see the explicit kill before `exit`). We deliberately do NOT trap EXIT: an
# EXIT trap also fires when a `$(...)` command-substitution subshell finishes,
# which would kill the simulator after the very first captured command.
trap 'kill "$SIM_PID" 2>/dev/null; exit 130' INT TERM
sleep 2
if ! kill -0 "$SIM_PID" 2>/dev/null; then
  echo "simulator did not start:"; cat "$SIM_LOG"; exit 1
fi
ok "simulator listening on $GATEWAY (pid $SIM_PID)"

# --- (a) scan the line ------------------------------------------------------
say "scan"
SCAN="$(BUSSARD_SCAN_DISCOVERY_MS=400 "$BUSSARD" scan 1.0 --from 0 --to 5 --dir "$MODEL" 2>/dev/null)"
echo "$SCAN"
for ia in 1.0.1 1.0.2 1.0.3 1.0.4; do
  if grep -q "^$ia " <<<"$SCAN"; then ok "scan found $ia"; else bad "scan did not find $ia"; fi
done

# --- (b) flash every device to Loaded (verified) ----------------------------
say "flash"
flash_dev() {
  local ia=$1 prod=$2 app=$3
  local out
  out="$("$BUSSARD" flash "$ia" --product "$PRODUCTS/$prod.knxprod" \
          --application "$app" --dir "$MODEL" --yes 2>&1)"
  if grep -q "is Loaded on $ia" <<<"$out"; then
    ok "flashed $ia -> Loaded ($app)"
  else
    bad "flash $ia failed"
    echo "$out" | tail -3 | sed 's/^/      /'
  fi
}
flash_dev 1.0.1 KNX_Virtual_M-00FA                    M-00FA_A-2500-10-51CB
flash_dev 1.0.2 MDT_KP_AKK_03_Switch_Actuator_V23     M-0083_A-0007-23-78E9
flash_dev 1.0.3 MDT_KP_AKI_AKS_03_Switch_Actuator_V32d M-0083_A-0004-32-A137
flash_dev 1.0.4 MDT_KP_AKH_03_Heating_Actuator_V34    M-0083_A-013A-34-3E87

# --- (c) read a typed value served by a device ------------------------------
say "read"
for ga in 1/0/2 1/1/2; do
  val="$("$BUSSARD" read "$ga" --dir "$MODEL" 2>/dev/null)"
  if grep -qE '\(1\.001\)$' <<<"$val"; then
    ok "read $ga served a typed DPT 1.001 value: $val"
  else
    bad "read $ga did not return a typed value (got: '${val:-<none>}')"
  fi
done

# --- (d) monitor live stimulus traffic --------------------------------------
say "monitor (15s, --json)"
MON="$(mktemp -t knxmon.XXXXXX)"
timeout 15 "$BUSSARD" monitor --json --dir "$MODEL" 2>/dev/null >"$MON"
echo "  captured $(wc -l <"$MON" | tr -d ' ') telegram(s); sample:"
head -3 "$MON" | sed 's/^/    /'
# Assert the expected stimulus GAs / DPTs appeared.
assert_seen() {
  local ga=$1 dpt=$2
  if grep -q "\"destination\":\"$ga\"" "$MON" && grep -q "\"dpt\":\"$dpt\"" "$MON"; then
    ok "monitor saw $ga (DPT $dpt) stimulus"
  else
    bad "monitor did not see $ga (DPT $dpt)"
  fi
}
assert_seen 1/0/2 1.001    # kitchen switch status heartbeat
assert_seen 1/1/2 1.001    # hallway switch status heartbeat
assert_seen 3/0/1 9.001    # heating room-temperature heartbeat
# A DPT 9.001 temperature value must decode to a plausible reading.
if grep -qE '"value":"2[12](\.[0-9])? °C"' "$MON"; then
  ok "monitor decoded a plausible temperature value"
else
  bad "monitor did not decode a temperature value"
fi

rm -f "$MON" "$SIM_LOG"

# --- Verdict ----------------------------------------------------------------
kill "$SIM_PID" 2>/dev/null
say "result"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
echo "  small-installation end-to-end run OK"
