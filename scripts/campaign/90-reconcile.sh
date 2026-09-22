#!/usr/bin/env bash
# Phase 6 of issue #89: re-baseline and diff against Phase 0.
#
#   scripts/campaign/90-reconcile.sh --go
#   scripts/campaign/90-reconcile.sh --go --dry-run --fast --line 1.0 \
#       --dir knx-sim/examples/small-installation/knx
#
# Read-only, like the baseline. It re-runs the Phase 0 reads into
# captures/campaign/<date>/reconcile/ and diffs every artefact against
# captures/campaign/<date>/baseline/, so the end state of the campaign is a diff
# rather than a claim.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

LINE=""
args=()
i=1
while [ $i -le $# ]; do
  eval "a=\${$i}"
  case "$a" in
    --line)   i=$((i+1)); eval "LINE=\${$i}" ;;
    --line=*) LINE="${a#*=}" ;;
    *)        args[${#args[@]}]="$a" ;;
  esac
  i=$((i+1))
done
parse_common_args ${args+"${args[@]}"}
resolve_gateway

ROOT="$(campaign_root)"
[ -f "$ROOT/session.env" ] && . "$ROOT/session.env"
BASE="$ROOT/baseline"
OUT="$ROOT/reconcile"
[ -d "$BASE" ] || die "no baseline at $BASE: run 10-baseline.sh first (there is nothing to reconcile against)"
[ -n "$LINE" ] || LINE="$(model_devices | head -1 | sed 's/\.[0-9]*$//')"

DEVICES="$(model_devices)"
DEVICE_COUNT="$(printf '%s\n' "$DEVICES" | grep -c . || true)"
SCAN_ARGS="--from 0 --to 255"
if [ "$FAST" -eq 1 ]; then
  SCAN_ARGS="--from 0 --to 15"
  export BUSSARD_SCAN_DISCOVERY_MS="${BUSSARD_SCAN_DISCOVERY_MS:-400}"
fi

say "Phase 6 reconciliation (issue #89)"
rule
note "date          $CAMPAIGN_DATE"
note "model         $MODEL_DIR  ($DEVICE_COUNT device(s))"
note "gateway       $GATEWAY_RESOLVED  $(is_loopback && echo '(loopback)' || echo '(REAL BUS)')"
note "baseline      $BASE"
note "output        $OUT"
echo
note "It will:"
note "  1. bussard scan $LINE --json $SCAN_ARGS"
note "  2. bussard describe --json and reconstruct for each device"
note "  3. diff every artefact against the Phase 0 baseline into $OUT/diff.md"
echo
note "Read-only: no device is programmed."
rule
require_go

ensure_dir "$OUT/devices"

# The wrapper's own bookkeeping (the invocation line, the timestamps) is not part
# of what the device reported, so it must not turn a clean reconciliation into a
# page of noise.
report_body() { grep -vE '^(#|\$ bussard )' "$1"; }

say "1/3  scan"
run_bussard_json "$OUT/scan.json" "$OUT/scan.log" scan "$LINE" --json $SCAN_ARGS \
    --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv

say "2/3  describe and reconstruct"
for ia in $DEVICES; do
  ensure_dir "$OUT/devices/$ia"
  printf '  %-9s ' "$ia"
  if run_bussard_json "$OUT/devices/$ia/describe.json" "$OUT/devices/$ia/describe.log" \
      describe "$ia" --json --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv; then
    printf 'describe ok  '
  else
    printf 'describe FAILED  '
  fi
  if run_bussard "$OUT/devices/$ia/reconstruct.log" reconstruct "$ia" \
      --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" -vv; then
    printf 'reconstruct ok\n'
  else
    printf 'reconstruct failed or refused\n'
  fi
done

say "3/3  diff against the baseline"
DIFF="$OUT/diff.md"
changed=0
{
  echo "# End-state reconciliation — $CAMPAIGN_DATE"
  echo
  echo "Phase 6 of issue #89: the reads of \`$OUT\` against the Phase 0 baseline in"
  echo "\`$BASE\`. A device that reads back differently is not automatically a"
  echo "problem — the campaign deliberately reprograms devices — but every"
  echo "difference belongs in the findings log with a classification."
  echo
  echo "## Scan"
  echo
  if [ -s "$BASE/scan-1.json" ] && [ -s "$OUT/scan.json" ]; then
    if diff -u "$BASE/scan-1.json" "$OUT/scan.json" >/dev/null 2>&1; then
      echo "The line scans identically to the baseline."
    else
      echo '```diff'
      diff -u "$BASE/scan-1.json" "$OUT/scan.json" 2>&1 | head -200
      echo '```'
      changed=$((changed+1))
    fi
  else
    echo "_No comparable scan JSON on one side; compare \`scan-1.log\` by hand._"
  fi
  echo
  echo "## Per device"
  echo
  echo "| Device | describe | reconstruct |"
  echo "| --- | --- | --- |"
  for ia in $DEVICES; do
    d="same"; r="same"
    if [ -s "$BASE/devices/$ia/describe.json" ] && [ -s "$OUT/devices/$ia/describe.json" ]; then
      diff -q "$BASE/devices/$ia/describe.json" "$OUT/devices/$ia/describe.json" >/dev/null 2>&1 || d="**differs**"
    else
      d="missing one side"
    fi
    if [ -s "$BASE/devices/$ia/reconstruct.log" ] && [ -s "$OUT/devices/$ia/reconstruct.log" ]; then
      diff -q <(report_body "$BASE/devices/$ia/reconstruct.log") \
              <(report_body "$OUT/devices/$ia/reconstruct.log") >/dev/null 2>&1 || r="**differs**"
    else
      r="missing one side"
    fi
    printf '| %s | %s | %s |\n' "$ia" "$d" "$r"
  done
  echo
  for ia in $DEVICES; do
    if [ -s "$BASE/devices/$ia/describe.json" ] && [ -s "$OUT/devices/$ia/describe.json" ] \
       && ! diff -q "$BASE/devices/$ia/describe.json" "$OUT/devices/$ia/describe.json" >/dev/null 2>&1; then
      echo "### $ia describe"
      echo '```diff'
      diff -u "$BASE/devices/$ia/describe.json" "$OUT/devices/$ia/describe.json" 2>&1 | head -120
      echo '```'
      echo
    fi
  done
  echo "## Still to do by hand (issue #89 Phase 6)"
  echo
  echo "- Full ETS download of the installation while capturing; that capture is"
  echo "  also the campaign's rollback."
  echo "- A second 24-hour \`bussard capture\`, diffed against the baseline traffic."
  echo "- For a sample of devices, byte-diff ETS's download against what bussard"
  echo "  wrote: \`uv run tools/knxtrace/knxtrace.py diff <ets.pcap> <bussard.pcap> --device <ia>\`."
} >"$DIFF"
note "wrote $DIFF"

rule
say "Reconciliation done."
note "data:  $OUT"
note "stop the recorders: scripts/campaign/00-preflight.sh --stop"
