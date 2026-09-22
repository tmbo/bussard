#!/usr/bin/env bash
# Phase 0 of issue #89: the read-only baseline.
#
#   scripts/campaign/10-baseline.sh --go --line 1.1
#
# Loopback dry run against knx-sim (fast: no ten-minute waits, a short sweep):
#
#   scripts/campaign/10-baseline.sh --go --dry-run --fast --line 1.0 \
#       --dir knx-sim/examples/small-installation/knx
#
# Everything here reads. `scan`, `describe` and `reconstruct` never transmit
# device programming, so this phase is not gated on the real-gateway opt-in; it
# still prints the resolved gateway, because knowing which bus you are pointed at
# is the campaign's first habit.
#
# What it records, per issue #89 Phase 0:
#   1. three `scan --json` runs (ten minutes apart) with -vv timing
#   2. `describe --json` for every device in the model
#   3. `reconstruct` for every device in the model
#   4. a findings.md with one row per device and the classification legend

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

LINE=""
SCAN_GAP=600
args=()
i=1
while [ $i -le $# ]; do
  eval "a=\${$i}"
  case "$a" in
    --line)   i=$((i+1)); eval "LINE=\${$i}" ;;
    --line=*) LINE="${a#*=}" ;;
    --gap)    i=$((i+1)); eval "SCAN_GAP=\${$i}" ;;
    --gap=*)  SCAN_GAP="${a#*=}" ;;
    *)        args[${#args[@]}]="$a" ;;
  esac
  i=$((i+1))
done
parse_common_args ${args+"${args[@]}"}
resolve_gateway

ROOT="$(campaign_root)"
OUT="$ROOT/baseline"
[ -f "$ROOT/session.env" ] && . "$ROOT/session.env"
[ -n "$LINE" ] || LINE="$(model_devices | head -1 | sed 's/\.[0-9]*$//')"
[ -n "$LINE" ] || die "no devices in $MODEL_DIR/devices/: pass --line explicitly"

DEVICES="$(model_devices)"
DEVICE_COUNT="$(printf '%s\n' "$DEVICES" | grep -c . || true)"

SCAN_ARGS="--from 0 --to 255"
if [ "$FAST" -eq 1 ]; then
  SCAN_ARGS="--from 0 --to 15"
  SCAN_GAP=2
  export BUSSARD_SCAN_DISCOVERY_MS="${BUSSARD_SCAN_DISCOVERY_MS:-400}"
fi

say "Phase 0 baseline (issue #89)"
rule
note "date          $CAMPAIGN_DATE"
note "model         $MODEL_DIR  ($DEVICE_COUNT device(s))"
note "gateway       $GATEWAY_RESOLVED  $(is_loopback && echo '(loopback)' || echo '(REAL BUS)')"
note "line          $LINE"
note "output        $OUT"
echo
note "It will:"
note "  1. bussard scan $LINE --json $SCAN_ARGS, three times, ${SCAN_GAP}s apart, with -vv timing"
note "  2. bussard describe --json for each of $DEVICE_COUNT device(s)"
note "  3. bussard reconstruct for each of $DEVICE_COUNT device(s)"
note "  4. write $OUT/findings.md with one row per device"
echo
note "Every command here is read-only: no device is programmed."
rule
require_go

ensure_dir "$OUT/devices"

# Turns a recorded exit code (and, for a non-zero one, the transcript) into the
# word that belongs in the findings table. A refusal is not a failure: bussard
# refusing an unsupported mask is the documented behaviour, and the table has to
# say so, or every System 7 device reads as broken.
status_of() {
  local rc_file="$1" log="$2" rc
  [ -f "$rc_file" ] || { printf 'not run'; return; }
  rc="$(cat "$rc_file")"
  if [ "$rc" = "0" ]; then printf 'ok'; return; fi
  if grep -qiE 'refus|supports .* only|unsupported' "$log" 2>/dev/null; then
    printf 'refused'
  else
    printf 'FAILED (%s)' "$rc"
  fi
}

# --- 1. three scans ---------------------------------------------------------
say "1/4  scan x3"
n=1
while [ $n -le 3 ]; do
  note "scan $n of 3 ..."
  # -vv puts the per-address timing (what #45 needs) on stderr, in the log;
  # the JSON stays clean on stdout.
  run_bussard_json "$OUT/scan-$n.json" "$OUT/scan-$n.log" scan "$LINE" --json $SCAN_ARGS \
      --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv
  if [ -s "$OUT/scan-$n.json" ]; then
    note "  -> $OUT/scan-$n.json"
  else
    warn "  scan $n produced no JSON; see $OUT/scan-$n.log"
  fi
  if [ $n -lt 3 ]; then
    note "  waiting ${SCAN_GAP}s (issue #89 wants the runs spread out)"
    sleep "$SCAN_GAP"
  fi
  n=$((n+1))
done

# --- 2 and 3. describe and reconstruct, per device --------------------------
say "2/4  describe, per device"
for ia in $DEVICES; do
  ensure_dir "$OUT/devices/$ia"
  printf '  %-9s describe ... ' "$ia"
  run_bussard_json "$OUT/devices/$ia/describe.json" "$OUT/devices/$ia/describe.log" \
      describe "$ia" --json --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv
  rc=$?
  printf '%d\n' "$rc" >"$OUT/devices/$ia/describe.rc"
  [ "$rc" -eq 0 ] && printf 'ok\n' || printf 'FAILED (exit %d, recorded)\n' "$rc"
done

say "3/4  reconstruct, per device"
for ia in $DEVICES; do
  printf '  %-9s reconstruct ... ' "$ia"
  run_bussard "$OUT/devices/$ia/reconstruct.log" reconstruct "$ia" \
      --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv
  rc=$?
  printf '%d\n' "$rc" >"$OUT/devices/$ia/reconstruct.rc"
  [ "$rc" -eq 0 ] && printf 'ok\n' || printf 'FAILED or refused (exit %d, recorded)\n' "$rc"
done

# --- 4. the findings table --------------------------------------------------
say "4/4  findings.md"
FINDINGS="$OUT/findings.md"
{
  cat <<EOF
# Campaign findings — baseline, $CAMPAIGN_DATE

Model \`$MODEL_DIR\`, line \`$LINE\`, gateway \`$GATEWAY_RESOLVED\`.
Generated by \`scripts/campaign/10-baseline.sh\`. Fill the blanks in by hand as
you work; \`20-per-device.sh\` appends a row per step below the table.

## Classification legend (issue #89 deliverables)

| Code | Meaning |
| --- | --- |
| \`match\` | bussard and the reference (ETS, or the model) agree byte for byte. |
| \`benign\` | They differ only in ordering, connection cycling, chunking or timing. \`knxtrace diff\` says BENIGN. |
| \`bug\` | A real divergence in bussard. Open an issue with the pcap excerpt. |
| \`corpus gap\` | bussard refused for missing product data, not for a code reason. |
| \`cal confirmed\` | A capture settled an \`S7-CAL\` / \`SEC-CAL\` marker; retire it in code. |
| \`refusal ok\` | bussard refused and was right to. Record the message verbatim. |
| \`refusal wrong\` | bussard refused when it should not have, or wrote when it should have refused. Always a finding. |

## Baseline, one row per device

| Device | Mask | Answered scan | describe | reconstruct | Notes |
| --- | --- | --- | --- | --- | --- |
EOF
  for ia in $DEVICES; do
    mask="?"
    if [ -s "$OUT/devices/$ia/describe.json" ]; then
      mask="$(sed -n 's/.*"mask"[: ]*"\([^"]*\)".*/\1/p' "$OUT/devices/$ia/describe.json" | head -1)"
      [ -n "$mask" ] || mask="?"
    fi
    seen="no"
    grep -q "\"$ia\"" "$OUT"/scan-*.json 2>/dev/null && seen="yes"
    desc="$(status_of "$OUT/devices/$ia/describe.rc" "$OUT/devices/$ia/describe.log")"
    recon="$(status_of "$OUT/devices/$ia/reconstruct.rc" "$OUT/devices/$ia/reconstruct.log")"
    printf '| %s | %s | %s | %s | %s |  |\n' "$ia" "$mask" "$seen" "$desc" "$recon"
  done
  cat <<EOF

A device whose \`describe\` walk stops early, errors or disconnects is a finding
even when the row above says \`ok\`: check \`devices/<ia>/describe.log\`. A device
whose tables cannot be read is a finding too (issue #89 Phase 0, steps 2 and 3).

## Per-step findings

| When | Device | Phase | Command | Expected | Observed | Class |
| --- | --- | --- | --- | --- | --- | --- |
EOF
} >"$FINDINGS"
note "wrote $FINDINGS"

rule
say "Baseline done."
note "data:  $OUT"
note "next:  scripts/campaign/20-per-device.sh <ia> <phase> --go"
