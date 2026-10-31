#!/usr/bin/env bash
# Offline conformance oracle for the physical campaign (issue #89).
#
#   scripts/campaign/95-offline-oracle.sh --rows rows.txt [--dir knx] [--out DIR] [--check]
#   scripts/campaign/95-offline-oracle.sh --row '1.1.5|ets.pcapng|vendor.knxprod|M-0001_A-...'
#   scripts/campaign/95-offline-oracle.sh \
#       --keyring project.knxkeys --row '1.1.12|secure.pcapng|project.knxproj|M-0004_A-...'
#
# Options: --dir MODEL (default knx), --out DIR, --keyring FILE (repeatable), --no-admit,
# --min-coverage PERCENT (default 50), --check, --date YYYY-MM-DD.
#
# Before a real device is flashed, compare the memory images bussard WOULD
# write to it against what ETS actually wrote to the same device in an existing
# ETS download capture. Nothing touches the bus: bussard runs
# `flash --dry-run --dump-images` (no gateway is resolved, no connection is
# opened) and knxtrace composes the ETS image from the capture offline.
#
# The device state ETS read before its download (the application objects'
# load states, PID_PROGRAM_VERSION, the MCB entries) is what bussard's
# pre-flight probe reads live: knxtrace writes it as `resident.json` and the
# dry run plans against it (`--resident`, issue #490), so a device that
# already holds the application gets the product's `par` load procedure and
# an object whose MCB already matches is skipped, as on the bus. A capture
# in which ETS ran its Unload command before the download (knxtrace's
# `unload_pass`) is planned with `flash --full`, bussard's equivalent, which
# keeps the System 7 pre-download pass (issue #488).
#
# A row is `device|capture|product|application|note|coverage|options`, one per
# line in the rows file (a line starting with `#` is a comment, blank lines are
# skipped; the last two fields are optional):
#
#   device       the individual address, e.g. 1.1.5
#   capture      the ETS download capture (.pcap/.pcapng) that programs it
#   product      the vendor .knxprod, or a .knxproj project export (it carries
#                the product data of every device in the project, so name the
#                application); `wrapper.zip!inner/path.knxprod` picks an inner
#                file out of a ZIP wrapper; a directory is the product XML of a
#                synthetic product (`tests-support/synthetic-products/<name>/xml`,
#                epic #596), zipped with the stub `knx_master.xml` (`<KNX/>`)
#                into $OUT/.products/<name>.knxprod before the dry run. Its
#                application is the rendered id (`..._A-2700-10-0000`), not the
#                signed one ETS imported (`..._A-2700-10-D80E`): the signer's
#                fingerprint never reaches the wire, PID_PROGRAM_VERSION
#                carries the manufacturer, the application number and the
#                version only (checked against the syn-minimal capture,
#                2026-10-30); `-` means there is no product data
#                (the row is reported as not comparable, with the note). Paths
#                may contain spaces (ETS names exports `Name  Project_date`);
#                only the `|` separators and the ends of a field are trimmed.
#   application  optional --application ref (empty: the sole application)
#   note         optional free text, shown when the row is not comparable
#   coverage     optional: the coverage percent recorded for the row (see
#                below); a later run below it is a coverage drop
#   options      optional, space-separated:
#                expect=VERDICT  the verdict the row is known to give
#                                on the written octets (identical, differs or
#                                not-comparable; default identical), e.g. for a
#                                capture that predates a model change
#                confirmed=VERDICT  the verdict the row must give on the
#                                read-confirmed octets (identical, differs or
#                                not-comparable); unchecked when absent. For a
#                                read-compare download (mask 0701) whose
#                                written octets are thin by design
#                props=VERDICT   the verdict the property-write parity must
#                                give (identical, differs or not-comparable);
#                                unchecked when absent. For a property-only
#                                plan (a KNX IP interface, mask 0021), whose
#                                memory verdict is always not-comparable,
#                                and for a row with a known property
#                                difference (props=differs, the note names
#                                the issue or decision, #683).
#                                Without this option the headline verdict
#                                counts the property writes: a row whose
#                                memory is identical but whose property
#                                writes differ is `differs` (issue #669).
#                                With it the headline is the memory verdict
#                                and the property verdict is checked here.
#                                ETS-only writes of the security object's
#                                mode, tool key and send sequence (type 17
#                                PIDs 51, 56, 59) and of PID_PROGMODE are
#                                listed as not compared, never counted
#                loadctl=VERDICT the verdict the load-control parity must give
#                                (identical, differs or not-comparable);
#                                unchecked when absent. For a row whose
#                                load-control records are known to differ
#                state=fresh     the capture programs a factory-fresh device
#                                (a synthetic or ETS-sweep knx-sim capture).
#                                ETS reads no load state on System 7 before
#                                its download, so knxtrace records none; the
#                                dry run then plans against a record with LSMs
#                                1 to 4 Unloaded, as the pre-flight probe reads
#                                a fresh device (the freshness verdict; the
#                                pre-download pass follows --full alone, issue
#                                #488). A resident.json knxtrace wrote wins.
#                                For System 7 rows
#                state=loaded    the capture programs a device that already
#                                holds an application (the `reload` and
#                                `other-app` run variants of a synthetic
#                                System 7 product, epic #596): the dry run
#                                plans against a record with LSMs 1 to 3
#                                Loaded and LSM 4 Unloaded, as the pre-flight
#                                probe reads a programmed device. A
#                                resident.json knxtrace wrote wins
#                dir=MODEL       without run=: the model the dry run plans
#                                with instead of --dir (a run variant whose
#                                device carries links or a parameter value,
#                                epic #596). A directory with no bussard.lock
#                                is a model template (bussard.toml, devices/,
#                                groups.toml): it is copied under the row's
#                                output, the row's product imported into the
#                                copy and the device pinned to the row's
#                                application. The same holds for run=apply's
#                                dir=
#                run=secure-on|secure-off  compare `bussard interface secure
#                                on|off --dry-run` (issue #398) instead of a
#                                flash: the KNXnet/IP Secure property writes
#                                (type 17 PIDs 51/56/59, type 11 PIDs 91-97)
#                                against the capture's, key material by hash.
#                                The product field is `-`; the verdict is the
#                                property parity
#                run=apply       a partial download (issue #469): knx-sim
#                                ($KNX_SIM_BIN, default knx-sim/target/debug/
#                                knx-sim) starts from ETS's state before the
#                                step (base=, replayed), `bussard apply` runs
#                                against it on loopback with the model in dir=,
#                                and `knxtrace statediff` compares the device
#                                state after it, and the load-control records,
#                                with the capture's (ETS's partial download).
#                                Not frame by frame: ETS rewrites a table in
#                                12-octet chunks where bussard writes an octet.
#                                run=apply-line: the same through line mode
#                                (`apply --line <area.line>`)
#                                run=params: the same with `bussard flash
#                                --parameters-only` (the download `apply`
#                                runs for a parameter change, issue #543), for
#                                ETS's partial download after a parameter
#                                change into a device with no links, which
#                                `apply` refuses (the `partial` run variant of
#                                a synthetic product, epic #596)
#                                base=A,B      the captures that led to the step,
#                                              in order (comma-separated)
#                                dir=MODEL     the model of the step (its links)
#                                lsm=memory|property  the sim's load-state
#                                              realisation (default property;
#                                              memory for mask 0701)
#                phase=fdsk|tool with run=: compare only bussard's writes under
#                                that key (the decoded half of a capture whose
#                                other half ran in a KNXnet/IP Secure session)
#                scope=R1,R2     the regions the verdict and coverage judge
#                                (addr, assoc, gobj, par, seg0x4800, ...), for a
#                                capture that by design downloads only part of
#                                the device: a security change rewrites the
#                                tables, not the parameters
#
# A line `#@ <options>` in a rows file sets options for that file: --keyring,
# --dir, --no-admit, --min-coverage. An option on the command line wins.
#
# Coverage (issue #347): of the octets bussard places (the octets a parameter
# placement wrote, or every written octet of a table or code image), the share
# the capture holds a value for, per segment and per 256-octet page. ETS
# read-compares or skips what a device already holds, so a capture can match
# while covering almost nothing. A row whose images match but whose coverage is
# below --min-coverage, or that has a page with placed octets and none
# compared, is "not comparable" (thin), never "identical". The summary shows
# the figure per row.
#
# Read-confirmed octets (issue #384): on a mask 0701 device that already holds
# an image, ETS reads the memory and writes only the octets that differ, so
# the written coverage stays thin however the download is recorded. An octet
# ETS read and never wrote in the capture equals ETS's image; knxtrace compares
# bussard's planned octets against those separately and reports their own
# coverage and verdict (`confirmed` column; same thin rule). A written octet is
# never a confirmed one, even when ETS read it first. When none of a row's
# read-confirmed octets differs, they also count toward the row's coverage
# (issue #422): a page whose placed octets ETS only read and kept (the 0701
# association table) is compared, not blind.
#
# --check turns the run into a gate (the corpus-gated CI test uses it): every
# row whose capture and product exist must give its expected verdict (the
# headline: the memory verdict, turned `differs` when the memory is identical
# and the property writes differ, issue #669, unless the row pins props=), its
# confirmed= verdict when the row names one, and at least its recorded
# coverage, else the script exits 1. Rows without a capture
# or product data are skipped.
#
# --keyring FILE names the ETS .knxkeys export for KNX Data Secure captures. It
# is passed to `knxtrace image` only, which then verifies and decrypts the
# secured frames (without it a Secure download composes to nothing). The
# bussard dry run plans with the model's own key material, as a flash would:
# the key store `bussard.keys` in --dir (else the model's connection.keyring);
# $BUSSARD_KEYRING is cleared for it, so an ETS keyring never re-adds a key the
# model removed (issue #336). The password comes from
# $BUSSARD_KEYRING_PASSWORD (exported, or from the model's .env, see
# load_dotenv in common.sh), never the command line. `knxtrace imgdiff` reads
# the already decrypted image directory and needs no keyring.
#
# The dry run honours `[connection] admit_tunnel_senders` of the model, as a
# flash does; the script prints the setting. --no-admit plans as if it were
# false (a shadow of --dir under $OUT/.model with only bussard.toml changed),
# for a capture ETS made without the tunnelling senders in PID 54.
#
# Per device the result is identical / differs (octets, first differing
# offset, both hex excerpts, per region) / not comparable (why), plus the
# property-write parity against `properties.json` (security-object key
# material redacted to a hash), plus the load-control parity (issue #419):
# every record bussard sends a load-state machine (PID 5, or the System 7
# memory-mapped record at 0x0104) against ETS's, per object in order, an
# immediate repeat counted once (tools/knxtrace/image.py has the rule). PID 54 (the security individual address table)
# is compared by sender address, set and order; its sequence numbers are a
# note. PID 53 (the group key table) is compared per entry and names the group
# addresses whose key differs or is missing on one side: both sides hash each
# key with a random salt drawn per run ($BUSSARD_ORACLE_SALT, exported to
# `knxtrace image` and the bussard dry run, never written to disk). Everything is written under
# captures/campaign/<date>/offline-oracle/ (gitignored) unless --out says
# otherwise; the rows file and the results stay local.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

ROWS_FILE=""
SINGLE_ROW=""
OUT=""
KEYRING=""
# Further keyrings for knxtrace (--keyring given again, issue #398): the export
# from before a key rotation decodes the frames under the old keys.
EXTRA_KEYRINGS=()
CLI_KEYRING=0
NO_ADMIT=0
MIN_COVERAGE=""
CHECK=0
CLI_DIR=0
PYTHON="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --rows)    ROWS_FILE="${2:?--rows needs a file}"; shift ;;
    --rows=*)  ROWS_FILE="${1#*=}" ;;
    --row)     SINGLE_ROW="${2:?--row needs device|capture|product[|application]}"; shift ;;
    --row=*)   SINGLE_ROW="${1#*=}" ;;
    --dir)     MODEL_DIR="${2:?--dir needs a directory}"; CLI_DIR=1; shift ;;
    --dir=*)   MODEL_DIR="${1#*=}"; CLI_DIR=1 ;;
    --out)     OUT="${2:?--out needs a directory}"; shift ;;
    --out=*)   OUT="${1#*=}" ;;
    --date)    CAMPAIGN_DATE="${2:?--date needs YYYY-MM-DD}"; shift ;;
    --date=*)  CAMPAIGN_DATE="${1#*=}" ;;
    --keyring)
      CLI_KEYRING=1
      if [ -z "$KEYRING" ]; then KEYRING="${2:?--keyring needs a .knxkeys file}"
      else EXTRA_KEYRINGS+=("${2:?--keyring needs a .knxkeys file}"); fi
      shift ;;
    --keyring=*)
      CLI_KEYRING=1
      if [ -z "$KEYRING" ]; then KEYRING="${1#*=}"; else EXTRA_KEYRINGS+=("${1#*=}"); fi ;;
    --no-admit) NO_ADMIT=1 ;;
    --min-coverage) MIN_COVERAGE="${2:?--min-coverage needs a percent}"; shift ;;
    --min-coverage=*) MIN_COVERAGE="${1#*=}" ;;
    --check)   CHECK=1 ;;
    -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         die "unknown argument: $1" ;;
  esac
  shift
done

# Per-run salt for the per-entry group key hashes (issue #378).
BUSSARD_ORACLE_SALT="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export BUSSARD_ORACLE_SALT

[ -n "$ROWS_FILE" ] || [ -n "$SINGLE_ROW" ] || die "pass --rows FILE or --row 'device|capture|product[|application]'"

# `#@ <options>` lines of the rows file: defaults for options the command line
# did not give.
if [ -n "$ROWS_FILE" ] && [ -f "$ROWS_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '#@'*) ;; *) continue ;; esac
    read -r -a directive <<<"${line#\#@}"
    set -- ${directive+"${directive[@]}"}
    while [ $# -gt 0 ]; do
      case "$1" in
        --keyring)
          # The command line wins; several #@ lines give several keyrings.
          if [ "$CLI_KEYRING" = 1 ]; then :
          elif [ -z "$KEYRING" ]; then KEYRING="${2:?#@ --keyring needs a file}"
          else EXTRA_KEYRINGS+=("${2:?#@ --keyring needs a file}"); fi
          shift ;;
        --dir)          [ "$CLI_DIR" = 1 ] || MODEL_DIR="${2:?#@ --dir needs a directory}"; shift ;;
        --min-coverage) [ -n "$MIN_COVERAGE" ] || MIN_COVERAGE="${2:?#@ --min-coverage needs a percent}"; shift ;;
        --no-admit)     NO_ADMIT=1 ;;
        *)              die "$ROWS_FILE: unknown #@ option: $1" ;;
      esac
      shift
    done
  done <"$ROWS_FILE"
fi
MIN_COVERAGE="${MIN_COVERAGE:-50}"

load_dotenv
[ -n "$OUT" ] || OUT="$(campaign_root)/offline-oracle"
[ -x "$BUSSARD_BIN" ] || die "no bussard binary at $BUSSARD_BIN (cargo build, or export BUSSARD_BIN)"
[ -d "$MODEL_DIR" ] || die "no model directory at $MODEL_DIR"
ensure_dir "$OUT"

KEYRING_ARGS=()
if [ -n "$KEYRING" ]; then
  [ -f "$KEYRING" ] || die "no keyring at $KEYRING"
  [ -n "${BUSSARD_KEYRING_PASSWORD:-}" ] || die "--keyring needs the keyring password in \$BUSSARD_KEYRING_PASSWORD (export it or put it in the model's .env)"
  KEYRING_ARGS=(--keyring "$KEYRING")
  for extra in ${EXTRA_KEYRINGS+"${EXTRA_KEYRINGS[@]}"}; do
    [ -f "$extra" ] || die "no keyring at $extra"
    KEYRING_ARGS+=(--keyring "$extra")
  done
fi

# The bussard side's key material and admission (issue #347): the model's key
# store, never the capture's keyring.
if [ -f "$MODEL_DIR/bussard.keys" ]; then
  note "bussard side: key store $MODEL_DIR/bussard.keys${KEYRING:+ (the keyring only decodes the capture)}"
else
  note "bussard side: no key store in $MODEL_DIR (connection.keyring of the model, if any)"
fi

# `[connection] admit_tunnel_senders` of a bussard.toml: true or false.
admit_setting() {
  "$PYTHON" - "$1" <<'PY'
import re, sys
section, value = None, "false"
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        lines = fh.read().splitlines()
except OSError:
    lines = []
for line in lines:
    line = line.split("#", 1)[0].strip()
    m = re.match(r"^\[\s*([^\]]+?)\s*\]$", line)
    if m:
        section = m.group(1)
        continue
    m = re.match(r"^admit_tunnel_senders\s*=\s*(true|false)$", line)
    if section == "connection" and m:
        value = m.group(1)
print(value)
PY
}

PLAN_DIR="$MODEL_DIR"
ADMIT="$(admit_setting "$MODEL_DIR/bussard.toml")"
if [ "$ADMIT" = "true" ] && [ "$NO_ADMIT" = 1 ]; then
  # A shadow of the model: every entry linked, bussard.toml copied with the
  # setting off. The model itself is never written.
  PLAN_DIR="$OUT/.model"
  rm -rf "$PLAN_DIR"; ensure_dir "$PLAN_DIR"
  abs_model="$(cd "$MODEL_DIR" && pwd)"
  for entry in "$abs_model"/* "$abs_model"/.[!.]*; do
    [ -e "$entry" ] || continue
    [ "$(basename "$entry")" = "bussard.toml" ] && continue
    ln -s "$entry" "$PLAN_DIR/$(basename "$entry")"
  done
  sed -E 's/^([[:space:]]*admit_tunnel_senders[[:space:]]*=[[:space:]]*)true/\1false/' \
    "$abs_model/bussard.toml" >"$PLAN_DIR/bussard.toml"
  note "admit_tunnel_senders = true in the model; --no-admit plans without it ($PLAN_DIR)"
elif [ "$NO_ADMIT" = 1 ]; then
  note "admit_tunnel_senders = false in the model (--no-admit changes nothing)"
else
  note "admit_tunnel_senders = $ADMIT (from the model; --no-admit plans without it)"
fi

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

# Marks a row --check skips (no capture or product data to run it with).
mark_skipped() {
  "$PYTHON" - "$1/row.json" "$2" <<'PY'
import json, sys
path, why = sys.argv[1:3]
with open(path, encoding="utf-8") as fh:
    row = json.load(fh)
row["skipped"] = why
with open(path, "w", encoding="utf-8") as fh:
    json.dump(row, fh)
PY
}

# Resolves `wrapper.zip!inner` to an extracted file under $OUT/.products, and
# a product XML directory (a synthetic product's committed `xml/`) to a
# .knxprod zipped from it with the stub master, also under $OUT/.products.
resolve_product() {
  local spec="$1"
  if [ -d "$spec" ]; then
    local name dest
    name="$(basename "$(dirname "$(cd "$spec" && pwd)")")"
    dest="$OUT/.products/$name.knxprod"
    "$PYTHON" - "$spec" "$dest" <<'EOF' || return 1
import os, sys, zipfile
src, dest = sys.argv[1:3]
entries = sorted(
    os.path.relpath(os.path.join(root, f), src).replace(os.sep, "/")
    for root, _, files in os.walk(src) for f in files
)
if not any(e.endswith(".xml") and "/" in e for e in entries):
    sys.exit(f"{src}: no <manufacturer>/*.xml product files")
os.makedirs(os.path.dirname(dest), exist_ok=True)
# The stub master data (tests-support/synthetic-products/README.md): bussard
# reads no master data and plans the mask procedure from its built-in
# template (#607).
stamp = (1980, 1, 1, 0, 0, 0)
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(zipfile.ZipInfo("knx_master.xml", stamp), "<KNX/>")
    for e in entries:
        if e != "knx_master.xml":
            with open(os.path.join(src, e), "rb") as fh:
                zf.writestr(zipfile.ZipInfo(e, stamp), fh.read())
print(dest)
EOF
    return
  fi
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

# The model a row with dir= plans with (epic #596). A directory that holds a
# bussard.lock is a model and is used as it is. Any other is a template
# (bussard.toml, devices/, groups.toml, as a run variant of a synthetic product
# commits it): copied to <row>/model, the product imported into the copy
# (`bussard import-product`) and the device pinned to the application in its
# lock, as tools/ets-sweep/oracle_model.py builds a sweep row's model. Prints
# the model directory; the import's output goes to <row>/model.log.
row_model() {
  local src="$1" prod="$2" application="$3" device="$4" dir="$5"
  if [ -f "$src/bussard.lock" ]; then
    printf '%s\n' "$src"
    return 0
  fi
  [ -d "$src" ] || { echo "no model template at $src" >"$dir/model.log"; return 1; }
  local dest="$dir/model"
  rm -rf "$dest"
  cp -R "$src" "$dest"
  env -u BUSSARD_KEYRING BUSSARD_NO_DOTENV=1 "$BUSSARD_BIN" import-product --dir "$dest" "$prod" \
    >"$dir/model.log" 2>&1 || return 1
  "$PYTHON" - "$dest/bussard.lock" "$prod" "$application" "$device" <<'PY' >>"$dir/model.log" 2>&1 || return 1
import hashlib, sys
lock, prod, app, device = sys.argv[1:5]
if not app:
    sys.exit("a model template needs the row's application")
with open(prod, "rb") as fh:
    sha = hashlib.sha256(fh.read()).hexdigest()
with open(lock, encoding="utf-8") as fh:
    text = fh.read()
with open(lock, "w", encoding="utf-8") as fh:
    fh.write(text.rstrip("\n") + f'\n\n[[device]]\naddress = "{device}"\napplication = "{app}"\nproduct_sha256 = "{sha}"\n')
PY
  printf '%s\n' "$dest"
}

# A run=apply row (issue #469): knx-sim starts from ETS's state before the
# step (the base captures replayed into the device), `bussard apply` runs
# against it on loopback, and knxtrace compares the device state after it with
# the state after ETS's partial download (the row's capture). The sim records
# bussard's session as $dir/sim/bussard.pcap.
apply_row() {
  local dir="$1" device="$2" capture="$3" product="$4" application="$5" base="$6" model="$7" lsm="$8" how="${9:-apply}"
  local sim_bin="${KNX_SIM_BIN:-$REPO/knx-sim/target/debug/knx-sim}"
  if [ ! -x "$sim_bin" ]; then
    not_comparable "$dir" "$device" "no knx-sim at $sim_bin (cargo build in knx-sim/, or export KNX_SIM_BIN)"
    return 0
  fi
  if [ -z "$model" ] || [ ! -d "$model" ]; then
    not_comparable "$dir" "$device" "run=apply needs dir=<model of the step>${model:+ ($model not found)}"
    return 0
  fi
  local prod
  if ! prod="$(resolve_product "$product")" || [ ! -f "$prod" ]; then
    not_comparable "$dir" "$device" "product file not found"
    return 0
  fi
  if ! model="$(row_model "$model" "$prod" "$application" "$device" "$dir")"; then
    not_comparable "$dir" "$device" "model dir=$7: $(tail -1 "$dir/model.log" 2>/dev/null | cut -c1-160)"
    return 0
  fi
  local b base_args=()
  IFS=',' read -r -a bases <<<"$base"
  for b in ${bases+"${bases[@]}"}; do
    [ -f "$b" ] || { not_comparable "$dir" "$device" "base capture not found: $b"; return 0; }
    base_args+=(--base "$b")
  done
  local sim="$dir/sim" port pid
  ensure_dir "$sim"
  port="$("$PYTHON" -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
  # JSON is YAML: the sim reads it as its config.
  "$PYTHON" - "$sim/sim.yaml" "$port" "$device" "$prod" "$application" "${lsm:-property}" "$base" <<'PY'
import json, os, sys
path, port, device, prod, app, lsm, base = sys.argv[1:8]
dev = {"address": device, "knxprod": os.path.abspath(prod), "initial_state": "unloaded", "lsm_access": lsm}
if app:
    dev["application"] = app
cfg = {"gateway": {"host": "127.0.0.1", "port": int(port), "tunnel_address": "1.1.254", "pcap": "bussard.pcap"},
       "devices": [dev], "replay": [os.path.abspath(p) for p in base.split(",") if p]}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=1)
PY
  RUST_LOG=info NO_COLOR=1 "$sim_bin" "$sim/sim.yaml" >"$sim/sim.log" 2>&1 &
  pid=$!
  local waited=0
  while ! grep -q "gateway listening" "$sim/sim.log" 2>/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null || [ "$waited" -ge 600 ]; then
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      not_comparable "$dir" "$device" "knx-sim did not start: $(grep -v '^\s*$' "$sim/sim.log" | tail -1 | cut -c1-160)"
      return 0
    fi
    sleep 0.2; waited=$((waited + 1))
  done
  note "knx-sim on 127.0.0.1:$port, $(grep -c 'replayed' "$sim/sim.log") capture(s) replayed"
  # run=apply-line goes through line mode (`apply --line`), which has its own
  # path to the tables (#478); the model holds the one device.
  local target=(apply "$device")
  [ "$how" = apply-line ] && target=(apply --line "${device%.*}")
  # run=params: the parameters-only download (issue #543).
  [ "$how" = params ] && target=(flash "$device" --parameters-only)
  local rc=0
  env -u BUSSARD_KEYRING BUSSARD_NO_DOTENV=1 "$BUSSARD_BIN" --gateway "127.0.0.1:$port" \
    "${target[@]}" --dir "$model" --yes >"$dir/apply.log" 2>"$dir/apply.err" || rc=$?
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  # A refused apply writes nothing; the state comparison then says so.
  [ "$rc" = 0 ] || note "bussard ${target[0]} exited $rc: $(grep -v '^\s*$' "$dir/apply.err" | tail -1 | cut -c1-160)"
  "$PYTHON" "$KNXTRACE" statediff ${base_args+"${base_args[@]}"} --ets "$capture" \
    --bussard "$sim/bussard.pcap" --device "$device" --json >"$dir/diff.json" || true
  "$PYTHON" "$KNXTRACE" statediff ${base_args+"${base_args[@]}"} --ets "$capture" \
    --bussard "$sim/bussard.pcap" --device "$device" >"$dir/diff.txt" || true
  sed 's/^/  /' "$dir/diff.txt"
}

# Runs one row into $OUT/<key> (the device address, with ~2, ~3 for a device
# that has more than one row).
run_row() {
  local line="$1" key="$2" device capture product application note_text recorded options
  IFS='|' read -r device capture product application note_text recorded options <<<"$line"
  device="$(trim "$device")"; capture="$(trim "${capture:-}")"
  product="$(trim "${product:-}")"; application="$(trim "${application:-}")"
  note_text="$(trim "${note_text:-}")"; recorded="$(trim "${recorded:-}")"
  options="$(trim "${options:-}")"
  local expect="" confirmed="" props="" loadctl="" scope="" run="" phase="" base="" rowdir="" lsm="" devstate="" word
  for word in $options; do
    case "$word" in
      expect=*)    expect="${word#expect=}" ;;
      confirmed=*) confirmed="${word#confirmed=}" ;;
      props=*)     props="${word#props=}" ;;
      loadctl=*)   loadctl="${word#loadctl=}" ;;
      run=*)       run="${word#run=}" ;;
      phase=*)     phase="${word#phase=}" ;;
      scope=*)     scope="${word#scope=}" ;;
      base=*)      base="${word#base=}" ;;
      dir=*)       rowdir="${word#dir=}" ;;
      lsm=*)       lsm="${word#lsm=}" ;;
      state=*)     devstate="${word#state=}" ;;
      *)           die "$device: unknown row option: $word (expect=..., confirmed=..., props=..., loadctl=..., run=..., phase=..., scope=..., base=..., dir=..., lsm=..., state=...)" ;;
    esac
  done
  local scope_args=()
  [ -n "$scope" ] && scope_args=(--scope "$scope")
  [ -n "$phase" ] && scope_args+=(--phase "$phase")
  case "$devstate" in
    ""|fresh|loaded) ;;
    *) die "$device: unknown state=$devstate (fresh or loaded)" ;;
  esac
  case "$run" in
    ""|secure-on|secure-off|apply|apply-line|params) ;;
    *) die "$device: unknown run=$run (secure-on, secure-off, apply, apply-line or params)" ;;
  esac
  [ -n "$device" ] || return 0
  local dir="$OUT/$key"
  rm -rf "$dir"; ensure_dir "$dir"
  say "$key${note_text:+  ($note_text)}"

  # The row's recorded coverage and expected verdict, for the summary and
  # --check (written next to the result, whatever the result is).
  "$PYTHON" - "$dir/row.json" "$recorded" "$expect" "$confirmed" "$props" "$loadctl" <<'PY'
import json, sys
path, recorded, expect, confirmed, props, loadctl = sys.argv[1:7]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"recorded_coverage": float(recorded.rstrip("% ")) if recorded else None,
               "expect": expect or "identical", "expect_confirmed": confirmed or None,
               "expect_props": props or None,
               "expect_loadctl": loadctl or None,
               "skipped": None}, fh)
PY
  if [ -z "$run" ] && { [ -z "$product" ] || [ "$product" = "-" ]; }; then
    not_comparable "$dir" "$device" "no product data${note_text:+: $note_text}"
    mark_skipped "$dir" "no product data"
    return 0
  fi
  if [ ! -f "$capture" ]; then
    not_comparable "$dir" "$device" "capture not found"
    mark_skipped "$dir" "capture not found"
    return 0
  fi
  if [ "$run" = apply ] || [ "$run" = apply-line ] || [ "$run" = params ]; then
    apply_row "$dir" "$device" "$capture" "$product" "$application" "$base" "$rowdir" "$lsm" "$run"
    return 0
  fi

  # 1. What ETS wrote.
  if ! "$PYTHON" "$KNXTRACE" image "$capture" --device "$device" --out "$dir/ets" \
       ${KEYRING_ARGS+"${KEYRING_ARGS[@]}"} >"$dir/ets.log" 2>&1; then
    not_comparable "$dir" "$device" "capture: $(tail -1 "$dir/ets.log")"
    return 0
  fi
  note "$(tail -1 "$dir/ets.log")"

  # 2. What bussard would write. --dry-run opens no connection.
  if [ -n "$run" ]; then
    # `interface secure on|off --dry-run` (issue #398): the key store's
    # credentials, hashed into plan.json, never printed.
    if ! env -u BUSSARD_KEYRING "$BUSSARD_BIN" interface secure "${run#secure-}" "$device" \
         --dir "$PLAN_DIR" --dry-run --dump-images "$dir/bussard" \
         >"$dir/plan.log" 2>"$dir/plan.err"; then
      not_comparable "$dir" "$device" "bussard refused to plan: $(grep -v '^\s*$' "$dir/plan.err" | tail -1 | cut -c1-160)"
      return 0
    fi
  else
    local prod
    if ! prod="$(resolve_product "$product")" || [ ! -f "$prod" ]; then
      not_comparable "$dir" "$device" "product file not found"
      return 0
    fi
    local app_args=()
    [ -n "$application" ] && app_args=(--application "$application")
    # The device state ETS read before its download (issue #490): bussard
    # plans against it as a live flash plans against its pre-flight probe.
    # state=fresh (issue #488): a factory-fresh System 7 device, whose LSMs the
    # probe would read Unloaded; ETS read none, so knxtrace recorded none.
    if [ -f "$dir/ets/resident.json" ]; then
      app_args+=(--resident "$dir/ets/resident.json")
    elif [ "$devstate" = fresh ]; then
      printf '%s\n' '{"objects": [{"index": 1, "state": 0}, {"index": 2, "state": 0}, {"index": 3, "state": 0}, {"index": 4, "state": 0}]}' \
        >"$dir/fresh.json"
      app_args+=(--resident "$dir/fresh.json")
    elif [ "$devstate" = loaded ]; then
      # state=loaded (issue #488): a System 7 device a download already
      # programmed, LSMs 1 to 3 Loaded (the procedure's own), LSM 4 Unloaded.
      printf '%s\n' '{"objects": [{"index": 1, "state": 1}, {"index": 2, "state": 1}, {"index": 3, "state": 1}, {"index": 4, "state": 0}]}' \
        >"$dir/loaded.json"
      app_args+=(--resident "$dir/loaded.json")
    fi
    # ETS ran its Unload command ahead of the download (issue #488: an
    # unload of LSM 4 and a 0x0060 read before the first restart, knxtrace's
    # `unload_pass`): bussard's equivalent is `flash --full`, which keeps
    # the System 7 pre-download pass a plain flash drops.
    if "$PYTHON" -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1])).get("unload_pass") else 1)' \
         "$dir/ets/regions.json" 2>/dev/null; then
      app_args+=(--full)
      note "ETS unloaded the device before its download: planned with --full"
    fi
    # dir= (a run variant's model template, epic #596): the row's own model.
    local plan_dir="$PLAN_DIR"
    if [ -n "$rowdir" ]; then
      if ! plan_dir="$(row_model "$rowdir" "$prod" "$application" "$device" "$dir")"; then
        not_comparable "$dir" "$device" "model dir=$rowdir: $(tail -1 "$dir/model.log" 2>/dev/null | cut -c1-160)"
        return 0
      fi
    fi
    # No --keyring and no $BUSSARD_KEYRING: the model's key store decides.
    if ! env -u BUSSARD_KEYRING "$BUSSARD_BIN" flash "$device" --product "$prod" \
         ${app_args+"${app_args[@]}"} \
         --dir "$plan_dir" --dry-run --dump-images "$dir/bussard" --json \
         >"$dir/plan.log" 2>"$dir/plan.err"; then
      not_comparable "$dir" "$device" "bussard refused to plan: $(grep -v '^\s*$' "$dir/plan.err" | tail -1 | cut -c1-160)"
      return 0
    fi
  fi

  # 3. The per-region diff.
  "$PYTHON" "$KNXTRACE" imgdiff "$dir/bussard" "$dir/ets" --min-coverage "$MIN_COVERAGE" \
    ${scope_args+"${scope_args[@]}"} --json >"$dir/diff.json"
  "$PYTHON" "$KNXTRACE" imgdiff "$dir/bussard" "$dir/ets" --min-coverage "$MIN_COVERAGE" \
    ${scope_args+"${scope_args[@]}"} >"$dir/diff.txt"
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
# A result key per row: the device, made unique within this run.
row_key() {
  local device="$1" key="$1" n=1 seen
  while :; do
    seen=0
    for k in ${DEVICES_RUN+"${DEVICES_RUN[@]}"}; do [ "$k" = "$key" ] && seen=1; done
    [ "$seen" = 0 ] && break
    n=$((n + 1)); key="$device~$n"
  done
  printf '%s' "$key"
}
if [ -n "$SINGLE_ROW" ]; then
  key="$(row_key "$(trim "${SINGLE_ROW%%|*}")")"
  run_row "$SINGLE_ROW" "$key"
  DEVICES_RUN[${#DEVICES_RUN[@]}]="$key"
else
  [ -f "$ROWS_FILE" ] || die "no rows file at $ROWS_FILE"
  while IFS= read -r line || [ -n "$line" ]; do
    # A comment is a whole line (a note may hold `#331`).
    case "$(trim "$line")" in ''|'#'*) continue ;; esac
    key="$(row_key "$(trim "${line%%|*}")")"
    run_row "$line" "$key"
    DEVICES_RUN[${#DEVICES_RUN[@]}]="$key"
  done <"$ROWS_FILE"
fi

rule
say "Summary ($OUT)"
"$PYTHON" - "$OUT" "$CHECK" ${DEVICES_RUN+"${DEVICES_RUN[@]}"} <<'EOF'
import json, os, sys
out, check, devices = sys.argv[1], sys.argv[2] == "1", sys.argv[3:]
failures = []
short = {"address table": "addr", "association table": "assoc",
         "group-object table": "gobj", "parameters": "par"}
FMT = "%-9s %-6s %-15s %-16s %-24s %s"
print(FMT % ("device", "system", "verdict", "coverage", "confirmed",
             "regions (differing/compared octets)"))
for dev in devices:
    try:
        with open(os.path.join(out, dev, "diff.json"), encoding="utf-8") as fh:
            r = json.load(fh)
    except (OSError, ValueError):
        print(FMT % (dev, "?", "error", "-", "-", "no result"))
        failures.append("%s: no result" % dev)
        continue
    try:
        with open(os.path.join(out, dev, "row.json"), encoding="utf-8") as fh:
            row = json.load(fh)
    except (OSError, ValueError):
        row = {"recorded_coverage": None, "expect": "identical", "skipped": None}
    cov = r.get("coverage") or {}
    cov_text = "%.1f%%%s" % (cov["percent"], " thin" if cov.get("thin") else "") if cov else "-"
    recorded = row.get("recorded_coverage")
    if recorded is not None:
        cov_text += " (%g)" % recorded
    conf = r.get("confirmed") or {}
    if conf.get("octets"):
        conf_text = "%.1f%% %s" % (conf["percent"], {
            "identical": "ok", "differs": "%d differ" % conf["diff_octets"],
        }.get(conf["verdict"], "thin" if conf.get("thin") else "n/c"))
    else:
        conf_text = "-"
    parts = []
    for reg in r.get("regions", []):
        name = short.get(reg["region"], reg["region"].replace("app segment ", "seg").replace("application ", "app"))
        if not reg.get("in_scope", True):
            name = "(%s)" % name
        if reg["verdict"] == "identical":
            parts.append("%s=ok(%d)" % (name, reg["compared"]))
        elif reg["verdict"] == "differs":
            parts.append("%s=%d/%d@+0x%X" % (name, reg["diff_octets"], reg["compared"], reg["first_offset"]))
        else:
            parts.append("%s=n/c" % name)
    detail = " ".join(parts) if parts else r.get("reason", "")
    if r.get("ets_only_octets"):
        detail += "  [ets-only %d]" % r["ets_only_octets"]
    props = r.get("properties") or {}
    if props.get("verdict") == "identical":
        detail += "  props=ok(%d)" % len(props.get("matched", []))
    elif props.get("verdict") == "differs":
        detail += "  props=differs(bussard-only %d, ets-only %d, value %d)" % (
            len(props.get("bussard_only", [])), len(props.get("ets_only", [])),
            props.get("value_counts", {}).get("differs", 0))
    elif props.get("verdict") == "not-comparable" and props.get("reason") and "matched" in props:
        detail += "  props=n/c(bussard %d, ETS ran no procedure write)" % len(
            props.get("bussard_only", []))
    if props.get("commissioning"):
        detail += " [ETS commissioning %d, not counted]" % len(props["commissioning"])
    if props.get("not_compared"):
        detail += " [ETS-only not compared: %s]" % ", ".join(
            "%s PID %s" % (e["key"][0], e["key"][1]) for e in props["not_compared"])
    lc = r.get("load_controls") or {}
    if lc.get("verdict") == "identical":
        detail += "  loadctl=ok(%d)" % lc.get("ets_records", 0)
    elif lc.get("verdict") == "differs":
        first = lc.get("first") or {}
        detail += "  loadctl=differs(%d, first obj%s#%s %s)" % (
            lc.get("difference_count", 0), first.get("object"), first.get("position"),
            first.get("event"))
    elif lc:
        detail += "  loadctl=n/c"
    if r.get("verdict") == "not-comparable" and parts and not r.get("reason", "").startswith("thin"):
        detail += "  (%s)" % (r.get("reason") or "nothing compared")
    # The headline counts the property writes (issue #669): identical memory
    # with a property write ETS made and bussard did not (or with another
    # value) is a difference in what the device holds. A row that pins the
    # property verdict with props= is judged on it there instead, so a known
    # property difference (issue #683) does not hide a memory difference.
    verdict = r["verdict"]
    if verdict == "identical" and props.get("verdict") == "differs" and not row.get("expect_props"):
        verdict = "differs"
        detail += "  (property writes differ)"
    print(FMT % (dev, r.get("system") or "-", verdict, cov_text, conf_text, detail))
    shown = conf.get("mismatches", [])
    for m in shown[:20]:
        print("%-9s   confirmed mismatch 0x%06X (%s+0x%X): bussard %s, ETS/device %s" % (
            "", m["address"], short.get(m["region"], m["region"].replace("app segment ", "seg")
                                        .replace("application ", "app")),
            m["offset"], m["bussard"], m["ets"]))
    if len(shown) > 20:
        print("%-9s   ... %d more in %s" % ("", conf["diff_octets"] - 20,
                                            os.path.join(out, dev, "diff.txt")))
    if row.get("skipped"):
        continue
    if verdict != row.get("expect", "identical"):
        failures.append("%s: %s, expected %s" % (dev, verdict, row.get("expect")))
    want_props = row.get("expect_props")
    if want_props and props.get("verdict", "not-comparable") != want_props:
        failures.append("%s: property writes %s, expected %s" % (
            dev, props.get("verdict", "not-comparable"), want_props))
    want_lc = row.get("expect_loadctl")
    if want_lc and lc.get("verdict", "not-comparable") != want_lc:
        failures.append("%s: load control %s, expected %s" % (
            dev, lc.get("verdict", "not-comparable"), want_lc))
    want = row.get("expect_confirmed")
    if want and conf.get("verdict", "not-comparable") != want:
        failures.append("%s: confirmed %s, expected %s" % (
            dev, conf.get("verdict", "not-comparable"), want))
    if recorded is not None and cov.get("percent", 0.0) + 0.05 < recorded:
        failures.append("%s: coverage %.1f %% dropped below the recorded %g %%" % (
            dev, cov.get("percent", 0.0), recorded))
if check:
    if failures:
        print("check failed:")
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("check passed")
EOF
