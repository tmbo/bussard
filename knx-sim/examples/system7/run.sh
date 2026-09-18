#!/usr/bin/env bash
#
# End-to-end demo of the System 7 (mask 0705) conformance loop: build both
# projects, start the knx-sim gateway with three simulated System 7 devices, then
# drive `bussard flash` against it to program every device to a verified
# `Loaded` — exercising BOTH LsmAccess realisations (memory-mapped and
# property-based) and the Jung MCB / TaskCtrl1 download path.
#
# Devices (all mask 0705):
#   1.1.5  MDT  M-0083_A-000E   memory-mapped LSM
#   1.1.6  MDT  M-0083_A-000E   property (PID-5) LSM   [BUSSARD_FLASH_SYS7_LSM=property]
#   1.1.7  Jung M-0004_A-A011   per-object MCB (PID 27) + TaskCtrl1
#
# Exits non-zero if any device does not reach a verified Loaded. Run from
# anywhere:
#   knx-sim/examples/system7/run.sh
#
# The vendor `.knxprod` products are copyrighted and git-ignored. This script
# resolves them from the product-corpus cache under
# tests-support/product-corpus/cache/vendor. If a product is missing it prints
# where to place it and exits non-zero.

set -uo pipefail

# --- Locate the repo, the example, and the two binaries ---------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # .../examples/system7
SIM_DIR="$(cd "$HERE/../.." && pwd)"                           # .../knx-sim
REPO="$(cd "$SIM_DIR/.." && pwd)"                              # repo root
SIM_YAML="$HERE/sim.yaml"
PRODUCTS="$HERE/products"
MODEL="$HERE/model"
GATEWAY="127.0.0.1:13691"

BUSSARD="$REPO/target/debug/bussard"
SERVE="$SIM_DIR/target/debug/serve"

# A tiny reboot wait keeps the after-restart verify fast against the local sim;
# in production the flash waits the full generous reboot interval.
export BUSSARD_FLASH_REBOOT_WAIT_MS=200

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

# --- Ensure the products are present ----------------------------------------
declare -a NEEDED=(
  "MDT_KP_AKK_03_Switch_Actuator_V23.knxprod"
  "de_3361-1m_V1.3_2020-05.knxprod"
)
CORPUS="$REPO/tests-support/product-corpus/cache/vendor"
mkdir -p "$PRODUCTS"
missing=0
for f in "${NEEDED[@]}"; do
  if [[ -f "$PRODUCTS/$f" ]]; then continue; fi
  if [[ -f "$CORPUS/$f" ]]; then cp "$CORPUS/$f" "$PRODUCTS/$f"
  else
    echo "  missing product: $f"
    echo "    place it in $PRODUCTS/ (git-ignored vendor data), e.g. from the"
    echo "    product corpus (tests-support/product-corpus/fetch.sh)."
    missing=1
  fi
done
[[ $missing -eq 0 ]] || { echo "cannot run without the vendor products"; exit 1; }
ok "products present"

# --- A bare (empty) model dir for the flashes -------------------------------
# The flash needs a model with a connection block; an empty groups/links model
# programs the vendor-default application (no group addresses), which is all this
# conformance loop asserts. It is regenerated here (git-ignored).
say "model"
mkdir -p "$MODEL"
cat > "$MODEL/bussard.yaml" <<EOF
connection:
  transport: tunnel
  gateway: $GATEWAY
EOF
printf 'project: system7\ngroups: {}\n'   > "$MODEL/groups.yaml"
printf 'links: {}\n'                       > "$MODEL/links.yaml"
ok "bare model at $MODEL"

# --- Start the simulator ----------------------------------------------------
say "start simulator"
SIM_LOG="$(mktemp -t knxsim7.XXXXXX)"
pkill -f "$SERVE" 2>/dev/null
RUST_LOG=${RUST_LOG:-warn} "$SERVE" "$SIM_YAML" >"$SIM_LOG" 2>&1 &
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

# --- Flash every device to verified Loaded ----------------------------------
say "flash"
# flash_dev <ia> <product-basename> <application-id> [extra-env]
flash_dev() {
  local ia=$1 prod=$2 app=$3 extra=${4:-}
  local out
  out="$(env $extra "$BUSSARD" flash "$ia" \
          --product "$PRODUCTS/$prod.knxprod" \
          --application "$app" --bcu-key FFFFFFFF \
          --dir "$MODEL" --yes --gateway "$GATEWAY" 2>&1)"
  if grep -q "is Loaded on $ia" <<<"$out"; then
    ok "flashed $ia -> verified Loaded ($app)"
  else
    bad "flash $ia failed"
    echo "$out" | tail -4 | sed 's/^/      /'
  fi
}

# 1.1.5 — memory-mapped LSM (the product-driven default).
flash_dev 1.1.5 MDT_KP_AKK_03_Switch_Actuator_V23 M-0083_A-000E-23-2274
# 1.1.6 — property (PID-5) LSM: the same product, bussard's realisation switch
# flipped to property so the property device side is exercised.
flash_dev 1.1.6 MDT_KP_AKK_03_Switch_Actuator_V23 M-0083_A-000E-23-2274 BUSSARD_FLASH_SYS7_LSM=property
# 1.1.7 — Jung: per-object MCB (LoadImageProp PID 27) + TaskCtrl1.
flash_dev 1.1.7 de_3361-1m_V1.3_2020-05 M-0004_A-A011-13-60BC-O000A

rm -f "$SIM_LOG"

# --- Verdict ----------------------------------------------------------------
kill "$SIM_PID" 2>/dev/null
say "result"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
echo "  System 7 conformance loop OK: both LSM realisations + Jung MCB reached verified Loaded"
