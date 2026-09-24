#!/usr/bin/env bash
# One campaign step against one device, wrapped in evidence.
#
#   scripts/campaign/20-per-device.sh <IA> <PHASE> [--go] [-- <bussard args>]
#
# PHASE is one of: plan, apply, flash, flash-force, assign, describe, custom.
# It picks the default command and names the output directory; `-- ...` replaces
# the command entirely, keeping the wrapper.
#
#   scripts/campaign/20-per-device.sh 1.1.5 apply --go --allow-remote-gateway
#   scripts/campaign/20-per-device.sh 1.1.5 flash --go --allow-remote-gateway \
#       -- flash 1.1.5 --product products/foo.knxprod --yes
#
# Loopback dry run against knx-sim:
#
#   scripts/campaign/20-per-device.sh 1.0.1 plan --go --dry-run \
#       --dir knx-sim/examples/small-installation/knx
#
# Around the step it records, per issue #89's "data per device":
#   - describe --json and reconstruct BEFORE
#   - the step itself with -vv and BUSSARD_WIRE_TRACE=1
#   - a per-step pcap (or, when tcpdump cannot run, the time window to slice the
#     campaign-wide capture with)
#   - describe --json and reconstruct AFTER
#   - a row appended to the baseline findings.md
#
# This step can write, so it refuses a non-loopback gateway without the opt-in.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

IA=""
PHASE=""
CUSTOM=()
seen_dashdash=0
args=()
for a in "$@"; do
  if [ "$seen_dashdash" -eq 1 ]; then CUSTOM[${#CUSTOM[@]}]="$a"; continue; fi
  case "$a" in
    --) seen_dashdash=1 ;;
    -*) args[${#args[@]}]="$a" ;;
    *)  if   [ -z "$IA" ];    then IA="$a"
        elif [ -z "$PHASE" ]; then PHASE="$a"
        else args[${#args[@]}]="$a"; fi ;;
  esac
done
parse_common_args ${args+"${args[@]}"}

[ -n "$IA" ]    || die "usage: $0 <IA> <PHASE> [--go] [-- <bussard args>]"
[ -n "$PHASE" ] || die "usage: $0 <IA> <PHASE> [--go] [-- <bussard args>]"
case "$IA" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "'$IA' is not an individual address (expected area.line.device, e.g. 1.1.5)" ;;
esac

ROOT="$(campaign_root)"
[ -f "$ROOT/session.env" ] && . "$ROOT/session.env"
resolve_gateway

# --- What this phase runs ---------------------------------------------------
if [ "${#CUSTOM[@]}" -gt 0 ]; then
  CMD=(${CUSTOM+"${CUSTOM[@]}"})
else
  case "$PHASE" in
    plan)        CMD=(plan "$IA") ;;
    apply)       CMD=(apply "$IA" --yes) ;;
    flash)       die "phase 'flash' needs the product file: add -- flash $IA --product <file> --yes" ;;
    flash-force) die "phase 'flash-force' needs the product file: add -- flash $IA --product <file> --yes --force" ;;
    assign)      CMD=(assign "$IA" --yes) ;;
    describe)    CMD=(describe "$IA" --json) ;;
    custom)      die "phase 'custom' needs the command: add -- <bussard args>" ;;
    *)           die "unknown phase '$PHASE' (plan, apply, flash, flash-force, assign, describe, custom)" ;;
  esac
fi
# A step against a Data Secure device carries `--keyring <file>`; the
# before/after probes need the same keyring or they cannot sync with the device
# (issue #166). BUSSARD_KEYRING_PASSWORD is already in the environment.
SNAP_KEYRING=()
prev=""
for a in ${CMD+"${CMD[@]}"}; do
  case "$a" in
    --keyring=*) SNAP_KEYRING=(--keyring "${a#--keyring=}") ;;
    *) [ "$prev" = "--keyring" ] && SNAP_KEYRING=(--keyring "$a") ;;
  esac
  prev="$a"
done
CMD=(${CMD+"${CMD[@]}"} --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv)
if ! is_loopback; then CMD=(${CMD+"${CMD[@]}"} --allow-remote-gateway); fi

STEP_TS="$(date +%Y%m%d-%H%M%S)"
OUT="$ROOT/devices/$IA/$PHASE-$STEP_TS"

# --- The plan ---------------------------------------------------------------
say "Campaign step: $IA / $PHASE"
rule
note "date          $CAMPAIGN_DATE"
note "device        $IA"
note "model         $MODEL_DIR"
note "gateway       $GATEWAY_RESOLVED  $(is_loopback && echo '(loopback)' || echo '(REAL BUS)')"
note "output        $OUT"
echo
note "It will:"
note "  1. describe --json and reconstruct $IA  (before)"
note "  2. start a per-step tcpdump (or record the window to slice later)"
note "  3. run: bussard ${CMD[*]}"
note "     with BUSSARD_WIRE_TRACE=1"
note "  4. describe --json and reconstruct $IA  (after)"
note "  5. append a row to $ROOT/baseline/findings.md"
echo
case "$PHASE" in
  apply|flash|flash-force|assign)
    printf '\033[33m  Step 3 WRITES to %s. bussard will still ask for its own confirmation.\033[0m\n' "$IA"
    ;;
esac
rule

require_gateway_optin
require_go

ensure_dir "$OUT"

# The before/after reads deliberately run WITHOUT the wire trace: they are
# context, and the trace belongs to the step itself.
# The keyring goes to `reconstruct` only when this binary's reconstruct accepts
# the flag; an unknown flag would fail the probe outright.
RECON_KEYRING=()
if [ "${#SNAP_KEYRING[@]}" -gt 0 ] && [ -x "$BUSSARD_BIN" ] \
    && "$BUSSARD_BIN" reconstruct --help 2>/dev/null | grep -q -- '--keyring'; then
  RECON_KEYRING=(${SNAP_KEYRING+"${SNAP_KEYRING[@]}"})
fi
snapshot() {
  local when="$1"
  printf '  %-6s describe ... ' "$when"
  if WIRE_TRACE=0 run_bussard_json "$OUT/$when-describe.json" "$OUT/$when-describe.log" \
      describe "$IA" --json --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" \
      ${SNAP_KEYRING+"${SNAP_KEYRING[@]}"}; then
    printf 'ok  '
  else
    printf 'failed  '
  fi
  printf 'reconstruct ... '
  if WIRE_TRACE=0 run_bussard "$OUT/$when-reconstruct.log" reconstruct "$IA" \
      --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" \
      ${RECON_KEYRING+"${RECON_KEYRING[@]}"}; then
    printf 'ok\n'
  else
    printf 'failed or refused\n'
  fi
}

say "1/5  before"
snapshot before

say "2/5  capture"
START="$(now_utc)"
start_tcpdump "$OUT/step.pcap" || note "no per-step pcap; the window file will let you slice the campaign capture"

say "3/5  the step"
note "bussard ${CMD[*]}"
WIRE_TRACE=1 run_bussard "$OUT/step.log" ${CMD+"${CMD[@]}"}
STEP_RC=$?
END="$(now_utc)"
stop_tcpdump
write_window "$OUT/window.txt" "$START" "$END"
if [ "$STEP_RC" -eq 0 ]; then note "step exited 0"; else warn "step exited $STEP_RC (recorded in $OUT/step.log)"; fi

# The wire trace goes to stderr, which run_bussard folded into the transcript.
# Split it out so the step log stays readable.
grep -E '\[wire\]' "$OUT/step.log" >"$OUT/wire.log" 2>/dev/null || true
note "$(grep -c . "$OUT/wire.log" 2>/dev/null || echo 0) wire-trace line(s) in $OUT/wire.log"

say "4/5  after"
snapshot after

say "5/5  findings"
FINDINGS="$ROOT/baseline/findings.md"
if [ -f "$FINDINGS" ]; then
  EXPECTED="exit 0, verified"
  OBSERVED="exit $STEP_RC"
  if grep -qi "refus" "$OUT/step.log" 2>/dev/null; then
    OBSERVED="$OBSERVED, REFUSED — record the message verbatim"
  fi
  printf '| %s | %s | %s | `%s` | %s | %s | _fill in_ |\n' \
    "$STEP_TS" "$IA" "$PHASE" "bussard ${CMD[*]}" "$EXPECTED" "$OBSERVED" >>"$FINDINGS"
  note "row appended to $FINDINGS"
else
  warn "no findings.md at $FINDINGS (run 10-baseline.sh first); step data is still in $OUT"
fi

rule
say "Step recorded in $OUT"
note "diff it against an ETS capture of the same device with:"
note "  uv run tools/knxtrace/knxtrace.py diff <ets.pcap> $OUT/step.pcap --device $IA"
note "functional check now, then power-cycle and re-verify (issue #89 ground rules)."
exit "$STEP_RC"
