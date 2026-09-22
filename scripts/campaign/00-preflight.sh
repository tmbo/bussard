#!/usr/bin/env bash
# Campaign preflight: arm the recorders and prove the safety net exists.
#
#   scripts/campaign/00-preflight.sh --i-have-an-ets-backup --go \
#       --allow-remote-gateway --iface en0
#
# Loopback dry run (no opt-in needed, no sudo needed):
#
#   scripts/campaign/00-preflight.sh --i-have-an-ets-backup --dry-run --go \
#       --dir knx-sim/examples/small-installation/knx
#
# It does not touch a device. It:
#   - refuses without --i-have-an-ets-backup (issue #89's first ground rule)
#   - resolves and prints the gateway, and refuses a real bus without the opt-in
#   - starts tcpdump and `bussard capture` into captures/campaign/<date>/
#   - writes a session file the other scripts read
#
# Stop the recorders with: scripts/campaign/00-preflight.sh --stop

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

HAVE_BACKUP=0
STOP=0
args=()
for a in "$@"; do
  case "$a" in
    --i-have-an-ets-backup) HAVE_BACKUP=1 ;;
    --stop)                 STOP=1 ;;
    *)                      args[${#args[@]}]="$a" ;;
  esac
done
parse_common_args ${args+"${args[@]}"}

ROOT="$(campaign_root)"
SESSION="$ROOT/session.env"
PIDS="$ROOT/recorders.pid"

# --- --stop: tear the recorders down ----------------------------------------
if [ "$STOP" -eq 1 ]; then
  [ -f "$PIDS" ] || die "no recorders recorded at $PIDS"
  while IFS='=' read -r name pid; do
    [ -n "${pid:-}" ] || continue
    if kill "$pid" 2>/dev/null; then note "stopped $name (pid $pid)"; else note "$name (pid $pid) was not running"; fi
  done <"$PIDS"
  rm -f "$PIDS"
  say "recorders stopped."
  exit 0
fi

# --- The plan ---------------------------------------------------------------
resolve_gateway

say "Campaign preflight (issue #89, ground rules)"
rule
note "date          $CAMPAIGN_DATE"
note "model         $MODEL_DIR"
note "gateway       $GATEWAY_RESOLVED  $(is_loopback && echo '(loopback)' || echo '(REAL BUS)')"
note "capture root  $ROOT"
note "interface     ${IFACE:-any}"
note "mode          $([ "$DRY_RUN" -eq 1 ] && echo 'dry run (no real bus expected)' || echo 'live')"
echo
note "It will:"
note "  1. verify the ETS backup was confirmed (--i-have-an-ets-backup)"
note "  2. check the bussard binary and the model parse"
note "  3. start tcpdump into $ROOT/preflight/campaign-<ts>.pcap"
note "  4. start 'bussard capture' into $ROOT/preflight/bus.db"
note "  5. write $SESSION for the later scripts"
echo
note "It will NOT write to any device."
rule

if [ "$HAVE_BACKUP" -ne 1 ]; then
  die "refusing to start without --i-have-an-ets-backup.
       Issue #89's first ground rule: take a full ETS project backup AND confirm
       an ETS full download of one device works, before bussard touches anything.
       ETS is the only recovery path for a device this campaign reprograms."
fi

if [ "$DRY_RUN" -eq 1 ] && ! is_loopback; then
  die "--dry-run with a non-loopback gateway ($GATEWAY_RESOLVED) is a contradiction.
       Point at the simulator: --gateway 127.0.0.1:13671"
fi

require_gateway_optin
require_go

# --- Execute ----------------------------------------------------------------
ensure_dir "$ROOT/preflight"

say "1/5  ETS backup"
note "confirmed by the operator via --i-have-an-ets-backup"

say "2/5  binary and model"
[ -x "$BUSSARD_BIN" ] || die "bussard binary not found at $BUSSARD_BIN (cargo build --bin bussard)"
note "$("$BUSSARD_BIN" --version 2>/dev/null || echo 'bussard (version unknown)')"
if "$BUSSARD_BIN" validate --dir "$MODEL_DIR" >"$ROOT/preflight/validate.txt" 2>&1; then
  note "model validates: $(model_devices | wc -l | tr -d ' ') device(s) in $MODEL_DIR"
else
  warn "model validation reported problems; see $ROOT/preflight/validate.txt"
fi
model_devices >"$ROOT/preflight/devices.txt"

say "3/5  tcpdump"
PCAP="$ROOT/preflight/campaign-$(date +%Y%m%d%H%M%S).pcap"
: >"$PIDS"
if start_tcpdump "$PCAP"; then
  printf 'tcpdump=%s\n' "$TCPDUMP_PID" >>"$PIDS"
  TCPDUMP_PID=""   # hand it to the session; do not tear it down on exit
else
  note "continuing without a campaign-wide capture; per-step captures may still work"
fi

say "4/5  bussard capture"
CAPTURE_DB="$ROOT/preflight/bus.db"
"$BUSSARD_BIN" capture --to "$CAPTURE_DB" --dir "$MODEL_DIR" --gateway "$GATEWAY_RESOLVED" \
  >"$ROOT/preflight/capture.log" 2>&1 &
CAPTURE_PID=$!
sleep 2
if kill -0 "$CAPTURE_PID" 2>/dev/null; then
  printf 'capture=%s\n' "$CAPTURE_PID" >>"$PIDS"
  note "bussard capture $CAPTURE_PID -> $CAPTURE_DB"
else
  warn "bussard capture exited immediately; see $ROOT/preflight/capture.log"
fi

say "5/5  session"
cat >"$SESSION" <<EOF
# Written by 00-preflight.sh on $(now_utc) UTC. Sourced by the later scripts.
CAMPAIGN_DATE=$CAMPAIGN_DATE
MODEL_DIR=$MODEL_DIR
GATEWAY_RESOLVED=$GATEWAY_RESOLVED
IFACE=${IFACE:-any}
DRY_RUN=$DRY_RUN
CAMPAIGN_PCAP=$PCAP
CAPTURE_DB=$CAPTURE_DB
EOF
note "wrote $SESSION"

rule
say "Preflight done. The recorders are running."
note "next:  scripts/campaign/10-baseline.sh --go$([ "$DRY_RUN" -eq 1 ] && echo ' --dry-run --fast')"
note "stop:  scripts/campaign/00-preflight.sh --stop"
