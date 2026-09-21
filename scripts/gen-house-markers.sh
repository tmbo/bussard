#!/usr/bin/env bash
# Regenerate .house-markers.sha256 from the gitignored local knx/ model.
# Only sha256 hashes are written; the plaintext never enters the repo.
#
# Markers are the strings that identify THIS installation: every room / floor /
# location / building value, plus each device's top-level custom `name:` unless
# that name is a vendor product name (present in the product index or corpus
# list), plus the private gateway address from knx/bussard.yaml.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import glob,hashlib,re,os
vals=set()
place=re.compile(r'^\s*(room|floor|location|building)\s*:\s*(.+?)\s*$')
topname=re.compile(r'^name\s*:\s*(.+?)\s*$')
vendor_text=""
for f in ('data/product-index.json','tests-support/product-corpus/corpus.txt'):
    if os.path.exists(f): vendor_text+=open(f,encoding='utf-8',errors='replace').read()
def clean(v): return v.strip().strip('"\'')
for f in glob.glob('knx/devices/*.yaml'):
    for line in open(f,encoding='utf-8',errors='replace'):
        m=place.match(line)
        if m: vals.add(clean(m.group(2))); continue
        m=topname.match(line)
        if m:
            v=clean(m.group(1))
            if v not in vendor_text: vals.add(v)
for f in glob.glob('knx/*.yaml'):
    for line in open(f,encoding='utf-8',errors='replace'):
        m=re.search(r'gateway\s*:\s*"?([\d.]+)',line)
        if m: vals.add(m.group(1))
vals={v for v in vals if len(v)>=4 and not re.fullmatch(r'[\d./:-]+',v)}
h=sorted(hashlib.sha256(v.encode()).hexdigest() for v in vals)
open('.house-markers.sha256','w').write("# sha256 of strings that identify the maintainer's private installation\n# (rooms, floors, locations, custom device names, gateway address).\n# Plaintext is never committed; scripts/check-no-house-data.sh hashes candidate\n# tokens in staged/tracked files and refuses a match. Regenerate with\n# scripts/gen-house-markers.sh (reads the gitignored knx/ model).\n"+"\n".join(h)+"\n")
print("markers:",len(h))
PY
