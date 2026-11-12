#!/usr/bin/env bash
# Refuse tracked files that identify the maintainer's installation or machine.
# Runs in CI (the lint job) over the tracked tree; one `git grep` per rule, no
# hook and no hashing, so it costs nothing at commit time.
#
#   scripts/check-no-private-data.sh
#
# Use documentation values instead: 192.0.2.x (RFC 5737) for an address,
# 00:00:5E:00:53:xx (RFC 7042) for a MAC, /home/me or /Users/nadia for a home.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
fail=0
self=':!scripts/check-no-private-data.sh'

# 1. Paths: raw installation, vendor and capture data is never tracked. The
#    synthetic products' captures and keyrings are ours and public.
paths=$(git ls-files | grep -E '^(knx[^/]*/|scratchpad/|shared-with-windows/|fixtures/private/|captures/)|\.(knxproj|knxprod|knxkeys|pcap|pcapng|etl)$|(^|/)\.env(\..*)?$' \
  | grep -vE '^captures/synthetic/|^knx-sim/|^tests-support/product-corpus/fixtures/')
if [ -n "$paths" ]; then
  echo "REFUSED path (private installation, vendor or capture data):"; echo "$paths" | head -20; fail=1
fi

report() { # <label> <matches>
  if [ -n "$2" ]; then echo "REFUSED $1:"; echo "$2" | cut -c1-200 | head -20; fail=1; fi
}

# 2. A 192.168.x.x address outside the generic examples the tests and docs use.
report "LAN address (use 192.0.2.x)" "$(git grep -nIE '192\.168\.[0-9]+\.[0-9]+' -- . "$self" ':!Cargo.lock' \
  | grep -vE '192\.168\.(1\.(1|2|10|80)|27\.21|255\.255|0\.[0-9]+)([^0-9]|$)')"

# 3. A home directory that is not a documented placeholder.
report "home directory (use /home/me)" "$(git grep -nIE '(/Users/|/home/|C:\\+Users\\+)[A-Za-z0-9._-]+' -- . "$self" ':!Cargo.lock' \
  | grep -vE '(/Users/|/home/|C:\\+Users\\+)(me|you|user|name|nadia|runner|someone|vmuser|ets|<user>|\{)([^A-Za-z0-9._-]|$)')"

# 4. A MAC address outside the documentation range.
report "MAC address (use 00:00:5E:00:53:xx)" "$(git grep -nIE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' -- . "$self" ':!Cargo.lock' ':!data/' \
  | grep -viE '00:00:5E:00:53:[0-9A-F]{2}|([0-9A-F]{2}:){6}')"

[ "$fail" = 0 ] && echo "no private data in tracked files"
exit "$fail"
