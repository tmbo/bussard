#!/usr/bin/env bash
# Offline conformance oracle for the physical campaign (issue #89).
#
#   scripts/campaign/95-offline-oracle.sh --rows rows.txt [--dir knx] [--out DIR]
#   scripts/campaign/95-offline-oracle.sh --row '1.1.5|ets.pcapng|vendor.knxprod|M-0001_A-...'
#
# Before a real device is flashed, compare the memory images bussard WOULD
# write to it against what ETS actually wrote to the same device in an existing
# ETS download capture. Nothing touches the bus: bussard runs
# `flash --dry-run --dump-images` (no gateway is resolved, no connection is
# opened) and knxtrace composes the ETS image from the capture offline.
#
# A row is `device|capture|product|application|note`, one per line in the rows
# file (`#` starts a comment, blank lines are skipped):
#
#   device       the individual address, e.g. 1.1.5
#   capture      the ETS download capture (.pcap/.pcapng) that programs it
#   product      the vendor .knxprod; `wrapper.zip!inner/path.knxprod` picks an
#                inner file out of a ZIP wrapper; `-` means there is no product
#                data (the row is reported as not comparable, with the note)
#   application  optional --application ref (empty: the sole application)
#   note         optional free text, shown when the row is not comparable
#
# Per device the result is identical / differs (octets, first differing
# offset, both hex excerpts, per region) / not comparable (why). Everything is
# written under captures/campaign/<date>/offline-oracle/ (gitignored) unless
# --out says otherwise; the rows file and the results stay local.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ROWS_FILE=""
SINGLE_ROW=""
OUT=""
PYTHON="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --rows)    ROWS_FILE="${2:?--rows needs a file}"; shift ;;
    --rows=*)  ROWS_FILE="${1#*=}" ;;
    --row)     SINGLE_ROW="${2:?--row needs device|capture|product[|application]}"; shift ;;
    --row=*)   SINGLE_ROW="${1#*=}" ;;
    --dir)     MODEL_DIR="${2:?--dir needs a directory}"; shift ;;
    --dir=*)   MODEL_DIR="${1#*=}" ;;
    --out)     OUT="${2:?--out needs a directory}"; shift ;;
    --out=*)   OUT="${1#*=}" ;;
    --date)    CAMPAIGN_DATE="${2:?--date needs YYYY-MM-DD}"; shift ;;
    --date=*)  CAMPAIGN_DATE="${1#*=}" ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *)         die "unknown argument: $1" ;;
  esac
  shift
done

[ -n "$ROWS_FILE" ] || [ -n "$SINGLE_ROW" ] || die "pass --rows FILE or --row 'device|capture|product[|application]'"
[ -n "$OUT" ] || OUT="$(campaign_root)/offline-oracle"
[ -x "$BUSSARD_BIN" ] || die "no bussard binary at $BUSSARD_BIN (cargo build, or export BUSSARD_BIN)"
ensure_dir "$OUT"

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s%"${s##*[![:space:]]}"}"; }

# Records a not-comparable verdict for a device that never reached the diff.
not_comparable() {
  local dir="$1" device="$2" reason="$3"
  "$PYTHON" - "$dir/diff.json" "$device" "$reason" <<'EOF'
import json, sys
path, device, reason = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"device": device, "application": None, "system": None,
               "verdict": "not-comparable", "reason": reason, "regions": [],
               "ets_only_octets": 0, "ets_only_ranges": []}, fh, indent=2)
EOF
  note "$device: not comparable ($reason)"
}

# Resolves `wrapper.zip!inner` to an extracted file under $OUT/.products.
resolve_product() {
  local spec="$1"
  case "$spec" in
    *'!'*)
      local zip="${spec%%!*}" inner="${spec#*!}"
      local dest
      dest="$OUT/.products/$(basename "$zip")"
      "$PYTHON" - "$zip" "$inner" "$dest" <<'EOF' || return 1
import os, sys, zipfile
zpath, inner, dest = sys.argv[1:4]
target = os.path.join(dest, inner)
if not os.path.exists(target):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with zipfile.ZipFile(zpath) as zf, zf.open(inner) as src, open(target, "wb") as out:
        out.write(src.read())
print(target)
EOF
      ;;
    *) printf '%s\n' "$spec" ;;
  esac
}

run_row() {
  local line="$1" device capture product application note_text
  IFS='|' read -r device capture product application note_text <<<"$line"
  device="$(trim "$device")"; capture="$(trim "${capture:-}")"
  product="$(trim "${product:-}")"; application="$(trim "${application:-}")"
  note_text="$(trim "${note_text:-}")"
  [ -n "$device" ] || return 0
  local dir="$OUT/$device"
  rm -rf "$dir"; ensure_dir "$dir"
  say "$device"

  if [ -z "$product" ] || [ "$product" = "-" ]; then
    not_comparable "$dir" "$device" "no product data${note_text:+: $note_text}"
    return 0
  fi
  if [ ! -f "$capture" ]; then
    not_comparable "$dir" "$device" "capture not found"
    return 0
  fi

  # 1. What ETS wrote.
  if ! "$PYTHON" "$KNXTRACE" image "$capture" --device "$device" --out "$dir/ets" \
       >"$dir/ets.log" 2>&1; then
    not_comparable "$dir" "$device" "capture: $(tail -1 "$dir/ets.log")"
    return 0
  fi
  note "$(tail -1 "$dir/ets.log")"

  # 2. What bussard would write. --dry-run opens no connection.
  local prod
  if ! prod="$(resolve_product "$product")" || [ ! -f "$prod" ]; then
    not_comparable "$dir" "$device" "product file not found"
    return 0
  fi
  local app_args=()
  [ -n "$application" ] && app_args=(--application "$application")
  if ! "$BUSSARD_BIN" flash "$device" --product "$prod" ${app_args+"${app_args[@]}"} \
       --dir "$MODEL_DIR" --dry-run --dump-images "$dir/bussard" --json \
       >"$dir/plan.log" 2>"$dir/plan.err"; then
    not_comparable "$dir" "$device" "bussard refused to plan: $(grep -v '^\s*$' "$dir/plan.err" | tail -1 | cut -c1-160)"
    return 0
  fi

  # 3. The per-region diff.
  "$PYTHON" "$KNXTRACE" imgdiff "$dir/bussard" "$dir/ets" --json >"$dir/diff.json"
  "$PYTHON" "$KNXTRACE" imgdiff "$dir/bussard" "$dir/ets" >"$dir/diff.txt"
  sed 's/^/  /' "$dir/diff.txt"
  if [ -n "$note_text" ]; then
    "$PYTHON" - "$dir/diff.json" "$note_text" <<'EOF'
import json, sys
path, text = sys.argv[1:3]
with open(path, encoding="utf-8") as fh:
    report = json.load(fh)
report["note"] = text
with open(path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
EOF
  fi
}

DEVICES_RUN=()
if [ -n "$SINGLE_ROW" ]; then
  run_row "$SINGLE_ROW"
  DEVICES_RUN[${#DEVICES_RUN[@]}]="$(trim "${SINGLE_ROW%%|*}")"
else
  [ -f "$ROWS_FILE" ] || die "no rows file at $ROWS_FILE"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    [ -n "$(trim "$line")" ] || continue
    run_row "$line"
    DEVICES_RUN[${#DEVICES_RUN[@]}]="$(trim "${line%%|*}")"
  done <"$ROWS_FILE"
fi

rule
say "Summary ($OUT)"
"$PYTHON" - "$OUT" ${DEVICES_RUN+"${DEVICES_RUN[@]}"} <<'EOF'
import json, os, sys
out, devices = sys.argv[1], sys.argv[2:]
short = {"address table": "addr", "association table": "assoc",
         "group-object table": "gobj", "parameters": "par"}
print("%-9s %-6s %-15s %s" % ("device", "system", "verdict", "regions (differing/compared octets)"))
for dev in devices:
    try:
        with open(os.path.join(out, dev, "diff.json"), encoding="utf-8") as fh:
            r = json.load(fh)
    except (OSError, ValueError):
        print("%-9s %-6s %-15s %s" % (dev, "?", "error", "no result"))
        continue
    parts = []
    for reg in r.get("regions", []):
        name = short.get(reg["region"], reg["region"].replace("app segment ", "seg").replace("application ", "app"))
        if reg["verdict"] == "identical":
            parts.append("%s=ok(%d)" % (name, reg["compared"]))
        elif reg["verdict"] == "differs":
            parts.append("%s=%d/%d@+0x%X" % (name, reg["diff_octets"], reg["compared"], reg["first_offset"]))
        else:
            parts.append("%s=n/c" % name)
    detail = " ".join(parts) if parts else r.get("reason", "")
    if r.get("ets_only_octets"):
        detail += "  [ets-only %d]" % r["ets_only_octets"]
    print("%-9s %-6s %-15s %s" % (dev, r.get("system") or "-", r["verdict"], detail))
EOF
