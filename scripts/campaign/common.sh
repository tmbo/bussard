#!/usr/bin/env bash
# Shared plumbing for the physical-device campaign scripts (issues #89, #90).
#
# Sourced, never run. It gives every campaign script the same three habits:
#
#   1. Print the plan, then stop unless --go was passed.
#   2. Resolve the gateway once, print it, and refuse a real bus without the
#      explicit opt-in (the same rule bussard itself applies to writes).
#   3. Write everything under captures/campaign/<date>/, which is gitignored.
#
# Nothing here writes to a device. The scripts that do call bussard, which runs
# its own confirmation and its own gateway gate; these wrappers are belt and
# braces, not a replacement.

set -uo pipefail

# --- Locations --------------------------------------------------------------

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUSSARD_BIN="${BUSSARD_BIN:-$REPO/target/debug/bussard}"
KNXTRACE="$REPO/tools/knxtrace/knxtrace.py"

# --- Options every script shares --------------------------------------------

GO=0
MODEL_DIR="knx"
GATEWAY=""
ALLOW_REMOTE=0
DRY_RUN=0
FAST=0
CAMPAIGN_DATE="$(date +%Y-%m-%d)"
IFACE=""
EXTRA_ARGS=()

say()   { printf '\033[1m%s\033[0m\n' "$*"; }
note()  { printf '  %s\n' "$*"; }
warn()  { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
rule()  { printf '%s\n' "----------------------------------------------------------------"; }

# Parses the flags common to every campaign script. Unknown flags are collected
# into EXTRA_ARGS for the calling script to interpret.
parse_common_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --go)                    GO=1 ;;
      --dry-run)               DRY_RUN=1 ;;
      --fast)                  FAST=1 ;;
      --dir)                   MODEL_DIR="${2:?--dir needs a directory}"; shift ;;
      --dir=*)                 MODEL_DIR="${1#*=}" ;;
      --gateway)               GATEWAY="${2:?--gateway needs host[:port]}"; shift ;;
      --gateway=*)             GATEWAY="${1#*=}" ;;
      --iface)                 IFACE="${2:?--iface needs an interface}"; shift ;;
      --iface=*)               IFACE="${1#*=}" ;;
      --date)                  CAMPAIGN_DATE="${2:?--date needs YYYY-MM-DD}"; shift ;;
      --date=*)                CAMPAIGN_DATE="${1#*=}" ;;
      --allow-remote-gateway)  ALLOW_REMOTE=1 ;;
      *)                       EXTRA_ARGS[${#EXTRA_ARGS[@]}]="$1" ;;
    esac
    shift
  done
  [ "${BUSSARD_ALLOW_REAL_GATEWAY:-0}" = "1" ] && ALLOW_REMOTE=1
  return 0
}

# --- The gateway, and the one rule ------------------------------------------

# Resolves the gateway the same way bussard does: --gateway wins, otherwise
# connection.gateway from the model's bussard.toml. Sets GATEWAY_RESOLVED and
# GATEWAY_HOST.
resolve_gateway() {
  if [ -z "$GATEWAY" ] && [ -f "$MODEL_DIR/bussard.toml" ]; then
    GATEWAY="$(sed -n 's/^[[:space:]]*gateway[[:space:]]*=[[:space:]]*//p' "$MODEL_DIR/bussard.toml" | sed 's/[[:space:]]*#.*//' \
                | head -1 | tr -d '"'"'"' \r')"
  fi
  [ -n "$GATEWAY" ] || die "no gateway: pass --gateway host[:port] or set connection.gateway in $MODEL_DIR/bussard.toml"
  case "$GATEWAY" in
    *:*) GATEWAY_HOST="${GATEWAY%:*}" ;;
    *)   GATEWAY_HOST="$GATEWAY" ;;
  esac
  case "$GATEWAY" in
    *:*) GATEWAY_RESOLVED="$GATEWAY" ;;
    *)   GATEWAY_RESOLVED="$GATEWAY:3671" ;;
  esac
}

is_loopback() {
  case "$GATEWAY_HOST" in
    127.*|::1|localhost) return 0 ;;
    *) return 1 ;;
  esac
}

# Refuses a real bus without the opt-in. Call from any script that can cause a
# write, directly or by arming a session.
require_gateway_optin() {
  if is_loopback; then
    note "gateway $GATEWAY_RESOLVED is loopback: a simulator or a test bus, no opt-in needed"
    return 0
  fi
  if [ "$ALLOW_REMOTE" -eq 1 ]; then
    printf '\033[31m  gateway %s is NOT loopback: this is a real KNX bus.\033[0m\n' "$GATEWAY_RESOLVED"
    note "proceeding because --allow-remote-gateway (or BUSSARD_ALLOW_REAL_GATEWAY=1) was given"
    return 0
  fi
  die "refusing to arm against non-loopback gateway $GATEWAY_RESOLVED: this looks like a real KNX bus.
       If you really mean it, re-run with --allow-remote-gateway or set BUSSARD_ALLOW_REAL_GATEWAY=1.
       For a dry run, point at the simulator instead: --gateway 127.0.0.1:13671 --dry-run"
}

# The --go gate. Everything above this line only printed; nothing has run.
require_go() {
  if [ "$GO" -eq 1 ]; then
    rule
    return 0
  fi
  rule
  say "This was the plan only. Nothing has run."
  note "Re-run with --go to execute it."
  exit 0
}

# --- Data layout ------------------------------------------------------------

campaign_root() { printf '%s/captures/campaign/%s' "$REPO" "$CAMPAIGN_DATE"; }

ensure_dir() { mkdir -p "$1" || die "cannot create $1"; }

# --- Devices in the model ---------------------------------------------------

# Prints one individual address per line, in model order.
model_devices() {
  local d
  for d in "$MODEL_DIR"/devices/*.toml; do
    [ -f "$d" ] || continue
    sed -n 's/^address[[:space:]]*=[[:space:]]*//p' "$d" | head -1 | tr -d '"'"'"' \r'
  done
}

# --- Running bussard --------------------------------------------------------

bussard_flags() {
  printf -- '--dir %s --gateway %s' "$MODEL_DIR" "$GATEWAY_RESOLVED"
}

# BUSSARD_WIRE_TRACE is deliberately opt-in. Issue #89 asks for it on every
# write; switching it on for the read-only phases as well would bury a 46-device
# baseline in megabytes of hex for no gain. 20-per-device.sh sets WIRE_TRACE=1.
WIRE_TRACE="${WIRE_TRACE:-0}"

_bussard_header() {
  local log="$1"; shift
  printf '$ bussard %s\n' "$*" >>"$log"
  printf '# gateway %s, wire trace %s, at %s\n' \
    "$GATEWAY_RESOLVED" "$WIRE_TRACE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$log"
}

_bussard_footer() {
  printf '# exit %d at %s\n\n' "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$1"
}

# Runs bussard and appends the whole transcript, stdout and stderr, to one log.
# Usage: run_bussard <logfile> <args...>
run_bussard() {
  local log="$1"; shift
  [ -x "$BUSSARD_BIN" ] || die "bussard binary not found at $BUSSARD_BIN (cargo build --bin bussard)"
  _bussard_header "$log" "$@"
  BUSSARD_WIRE_TRACE="$WIRE_TRACE" "$BUSSARD_BIN" "$@" >>"$log" 2>&1
  local rc=$?
  _bussard_footer "$log" "$rc"
  return $rc
}

# The same, but keeping stdout apart so a --json run yields parseable JSON.
# bussard writes its data to stdout and every log line (the wire trace included)
# to stderr, so the split is the only thing that makes the JSON usable.
# Usage: run_bussard_json <jsonfile> <logfile> <args...>
run_bussard_json() {
  local out="$1" log="$2"; shift 2
  [ -x "$BUSSARD_BIN" ] || die "bussard binary not found at $BUSSARD_BIN (cargo build --bin bussard)"
  _bussard_header "$log" "$@"
  BUSSARD_WIRE_TRACE="$WIRE_TRACE" "$BUSSARD_BIN" "$@" >"$out" 2>>"$log"
  local rc=$?
  _bussard_footer "$log" "$rc"
  return $rc
}

# --- Packet capture ---------------------------------------------------------

TCPDUMP_PID=""

# Starts tcpdump into <file>, or explains why it could not and carries on. A
# capture is evidence, not a precondition: a missing one must never stop a step
# the operator is standing in front of.
start_tcpdump() {
  local out="$1"
  local iface="${IFACE:-any}"
  if ! command -v tcpdump >/dev/null 2>&1; then
    warn "tcpdump not installed: no packet capture for this step"
    return 1
  fi
  tcpdump -i "$iface" -s 0 -U -w "$out" "udp port 3671 or tcp port 3671 or udp port ${GATEWAY_RESOLVED##*:} or tcp port ${GATEWAY_RESOLVED##*:}" \
    >/dev/null 2>"$out.err" &
  TCPDUMP_PID=$!
  sleep 1
  if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    warn "tcpdump did not start (usually: needs sudo). See $out.err"
    TCPDUMP_PID=""
    return 1
  fi
  note "tcpdump $TCPDUMP_PID -> $out (interface $iface)"
  return 0
}

stop_tcpdump() {
  [ -n "$TCPDUMP_PID" ] || return 0
  kill "$TCPDUMP_PID" 2>/dev/null
  wait "$TCPDUMP_PID" 2>/dev/null
  TCPDUMP_PID=""
}

# Records the wall-clock window of a step so the campaign-wide capture can be
# sliced later, whether or not a per-step tcpdump was possible:
#   editcap -A "<start>" -B "<end>" campaign.pcap step.pcap
write_window() {
  local file="$1" start="$2" end="$3"
  cat >"$file" <<EOF
start=$start
end=$end
# Slice the campaign-wide capture down to this step with:
#   editcap -A "$start" -B "$end" <campaign.pcap> <step.pcap>
EOF
}

now_utc() { date -u +"%Y-%m-%d %H:%M:%S"; }
