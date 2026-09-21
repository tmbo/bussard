#!/usr/bin/env bash
# Refuse to commit (or, in CI, to pass) anything that identifies the maintainer's
# private KNX installation.
#
#   scripts/check-no-house-data.sh --staged   # pre-commit: staged files only
#   scripts/check-no-house-data.sh --tracked  # CI: every tracked file
#
# Three layers:
#   1. forbidden PATHS: raw installation data must never be tracked at all
#   2. forbidden LITERALS: the private LAN and gateway address
#   3. hashed MARKERS: sha256 of room/device/floor names from the private model,
#      matched against quoted strings and YAML/JSON values (no plaintext in repo)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
mode="${1:---staged}"
case "$mode" in
  --staged)  files=$(git diff --cached --name-only --diff-filter=ACMR) ;;
  --tracked) files=$(git ls-files) ;;
  *) echo "usage: $0 [--staged|--tracked]" >&2; exit 2 ;;
esac
[ -z "$files" ] && exit 0
fail=0

# 1. Forbidden paths (raw installation / vendor / capture data).
forbidden_path='^(knx/|scratchpad/|shared-with-windows/|captures/|tests-support/product-corpus/cache)|\.(knxproj|knxprod|knxkeys|pcap|pcapng|etl)$|(^|/)\.env(\..*)?$'
while IFS= read -r f; do
  if printf '%s' "$f" | grep -Eq "$forbidden_path"; then
    echo "REFUSED path: $f (private installation / vendor / capture data must never be committed)"; fail=1
  fi
done <<< "$files"

# 2. Forbidden literals (private LAN). Exclude this script and the marker file.
lit_pat='192\.168\.1\.[0-9]+'
while IFS= read -r f; do
  case "$f" in scripts/check-no-house-data.sh|.house-markers.sha256) continue;; esac
  [ -f "$f" ] || continue
  if grep -nE "$lit_pat" "$f" >/dev/null 2>&1; then
    echo "REFUSED literal (private LAN address) in $f:"; grep -nE "$lit_pat" "$f" | head -3; fail=1
  fi
done <<< "$files"

# 3. Hashed markers: hash every quoted string and YAML/JSON value; compare.
if [ -f .house-markers.sha256 ]; then
  markers=$(grep -vE '^\s*(#|$)' .house-markers.sha256)
  while IFS= read -r f; do
    case "$f" in .house-markers.sha256) continue;; esac
    [ -f "$f" ] || continue
    # text files only
    if file -b --mime "$f" 2>/dev/null | grep -qv 'charset=binary'; then
      hits=$(python3 - "$f" <<'PY'
import sys,re,hashlib
f=sys.argv[1]; markers=set(l.strip() for l in open('.house-markers.sha256') if l.strip() and not l.startswith('#'))
try: text=open(f,encoding='utf-8',errors='replace').read()
except Exception: sys.exit(0)
cands=set()
for m in re.finditer(r'"([^"\n]{4,120})"|\x27([^\x27\n]{4,120})\x27',text): cands.add((m.group(1) or m.group(2)).strip())
for m in re.finditer(r'^\s*[\w.-]+\s*:\s*(.+?)\s*$',text,re.M): cands.add(m.group(1).strip().strip('"\x27'))
for c in cands:
    if hashlib.sha256(c.encode()).hexdigest() in markers: print(c)
PY
)
      if [ -n "$hits" ]; then
        echo "REFUSED private-installation marker(s) in $f:"; printf '%s\n' "$hits" | sed 's/^/   /' | head -5; fail=1
      fi
    fi
  done <<< "$files"
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Commit refused: it would publish information about a private KNX installation."
  echo "Use synthetic names/addresses (see docs/SAFETY.md, 'Private data')."
  exit 1
fi
exit 0
