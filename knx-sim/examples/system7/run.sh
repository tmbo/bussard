#!/usr/bin/env bash
#
# End-to-end demo of the System 7 (mask 0705) conformance loop: build both
# projects, start the knx-sim gateway with four simulated System 7 devices, then
# drive `bussard flash` against it to program every device to a verified
# `Loaded` — exercising BOTH LsmAccess realisations (memory-mapped and
# property-based) and the Jung MCB / TaskCtrl1 download path.
#
# Then the incremental link path (issue #91): `bussard plan` -> `apply` ->
# `reconstruct` against the 0705 property device (1.1.6) and the 0701
# memory-mapped device (1.1.8). That path reads the live tables straight out of
# the absolute 0x4000 / 0x4201 regions, diffs them against the model, and
# rewrites ONLY the two table load-state machines — no parameter reset, no
# restart. Every device must still answer on the bus afterwards.
#
# Devices (all mask 0705):
#   1.1.5  MDT   M-0083_A-000E  memory-mapped LSM      [BUSSARD_FLASH_SYS7_LSM=memory]
#   1.1.6  MDT   M-0083_A-000E  property (PID-5) LSM    (bussard's 0705 default)
#   1.1.7  Jung  M-0004_A-A011  per-object MCB (PID 27) + TaskCtrl1, property (0705 default)
#   1.1.8  Theben M-0048_A-4947 (0701) memory-mapped 11-octet records (0701 default)
#
# Property is bussard's default LSM realisation (M2 Jung 0705 capture, issue #70):
# 1.1.6 and 1.1.7 are flashed with no env override; 1.1.5 is pointed at the
# memory-mapped side with BUSSARD_FLASH_SYS7_LSM=memory.
#
# Exits non-zero if any device does not reach a verified Loaded. Run from
# anywhere:
#   knx-sim/examples/system7/run.sh
#
# The vendor `.knxprod` products are copyrighted and git-ignored. This script
# resolves them from the product-corpus cache under
# tests-support/product-corpus/cache/vendor. If a product is missing it prints
# where to place it and exits non-zero.
#
# CI therefore cannot run this script — no vendor products on the runner. The
# `sim-conformance` job in .github/workflows/ci.yml runs the fixture-backed
# equivalent of both sides of this loop instead: the sim's sys7 calibration and
# the two capture replays (Jung M2 property LSM, Theben 0701 memory-mapped), plus
# bussard's mock-gateway flash suites and the matching plan suites. Keep this
# script working, but do not rely on it to catch a regression: the CI job is what
# guards the loop on every push.

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
  "T4940275_KNX_FIX2_Dimmaktor_V1.0_ETS4.knxprod"
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
cat > "$MODEL/bussard.toml" <<EOF
[connection]
transport = "tunnel"
gateway = "$GATEWAY"
EOF
printf 'project = "system7"\n' > "$MODEL/groups.toml"
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

# 1.1.5 — memory-mapped LSM: the same product with bussard's realisation switch
# flipped to memory so the memory-mapped device side is exercised.
flash_dev 1.1.5 MDT_KP_AKK_03_Switch_Actuator_V23 M-0083_A-000E-23-2274 BUSSARD_FLASH_SYS7_LSM=memory
# 1.1.6 — property (PID-5) LSM: bussard's default realisation, no env override.
flash_dev 1.1.6 MDT_KP_AKK_03_Switch_Actuator_V23 M-0083_A-000E-23-2274
# 1.1.7 — Jung: per-object MCB (LoadImageProp PID 27) + TaskCtrl1, property (default).
flash_dev 1.1.7 de_3361-1m_V1.3_2020-05 M-0004_A-A011-13-60BC-O000A
# 1.1.8 — Theben 0701: memory-mapped 11-octet records. bussard picks memory-mapped
# from its 0701 mask-family default (no env override).
flash_dev 1.1.8 T4940275_KNX_FIX2_Dimmaktor_V1.0_ETS4 M-0048_A-4947-10-4918

# --- Incremental link change: plan -> apply -> reconstruct -------------------
# The flash above programmed the vendor default application with NO group links.
# This is the differential path a link edit takes in practice: read, diff, and
# write back only the two table LSMs. Run it against both LSM realisations —
# 1.1.6 (MDT 0705, property PID-5) and 1.1.8 (Theben 0701, memory-mapped).
say "incremental link change"
LINKED="$HERE/model-linked"
mkdir -p "$LINKED"
cat > "$LINKED/bussard.toml" <<EOF
[connection]
transport = "tunnel"
gateway = "$GATEWAY"
EOF
cat > "$LINKED/groups.toml" <<'EOF'
project = "system7-links"

groups = [
  { address = "1/0/1", name = "S7 Property Device",      dpt = "1.001" },
  { address = "1/0/2", name = "S7 Memory Mapped Device", dpt = "1.001" },
]
EOF
mkdir -p "$LINKED/devices"
# 1.1.6: MDT 0705, property (PID-5) LSM.
cat > "$LINKED/devices/1.1.6.toml" <<'EOF'
address = "1.1.6"
name = "S7 Property Device"

[links]
1.listen = ["1/0/1"]
1.name = "Switch"
EOF
# 1.1.8: Theben 0701, memory-mapped 11-octet LSM records.
cat > "$LINKED/devices/1.1.8.toml" <<'EOF'
address = "1.1.8"
name = "S7 Memory Mapped Device"

[links]
1.listen = ["1/0/2"]
1.name = "Switch"
EOF
ok "link model at $LINKED"

# link_cycle <ia> <ga>: plan offers the link, apply writes and verifies it,
# reconstruct agrees with the model, and a re-plan is a no-op.
link_cycle() {
  local ia=$1 ga=$2 out

  out="$("$BUSSARD" plan "$ia" --dir "$LINKED" --gateway "$GATEWAY" 2>&1)"
  if grep -q "add:.*$ga" <<<"$out"; then
    ok "plan $ia offers + $ga"
  else
    bad "plan $ia did not offer $ga"
    echo "$out" | tail -6 | sed 's/^/      /'
    return
  fi

  out="$("$BUSSARD" apply "$ia" --dir "$LINKED" --yes --gateway "$GATEWAY" 2>&1)"
  if grep -q "apply verified" <<<"$out"; then
    ok "apply $ia -> verified"
  else
    bad "apply $ia failed"
    echo "$out" | tail -8 | sed 's/^/      /'
    return
  fi

  out="$("$BUSSARD" reconstruct "$ia" --dir "$LINKED" --gateway "$GATEWAY" 2>&1)"
  if grep -q "device tables and model links agree" <<<"$out"; then
    ok "reconstruct $ia agrees with the model"
  else
    bad "reconstruct $ia disagrees with the model"
    echo "$out" | tail -8 | sed 's/^/      /'
  fi

  out="$("$BUSSARD" plan "$ia" --dir "$LINKED" --gateway "$GATEWAY" 2>&1)"
  if grep -q "nothing to do" <<<"$out"; then
    ok "re-plan $ia is a no-op"
  else
    bad "re-plan $ia is not idempotent"
    echo "$out" | tail -6 | sed 's/^/      /'
  fi
}

link_cycle 1.1.6 1/0/1
link_cycle 1.1.8 1/0/2

# --- Every device still answers on the bus ----------------------------------
# A table-only apply must never brick a device: the two it rewrote and the two it
# never touched all still answer a full management read.
say "still responding"
for ia in 1.1.5 1.1.6 1.1.7 1.1.8; do
  if "$BUSSARD" reconstruct "$ia" --dir "$MODEL" --gateway "$GATEWAY" >/dev/null 2>&1; then
    ok "$ia still answers on the bus"
  else
    bad "$ia stopped answering"
  fi
done

rm -f "$SIM_LOG"

# --- Verdict ----------------------------------------------------------------
kill "$SIM_PID" 2>/dev/null
say "result"
printf '  %d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]] || exit 1
echo "  System 7 conformance loop OK: both LSM realisations + Jung MCB reached verified"
echo "  Loaded, and the incremental plan/apply/reconstruct path round-tripped a link"
echo "  change on both realisations with every device still answering."
