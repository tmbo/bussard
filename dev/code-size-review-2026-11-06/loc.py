import sys, os, re, collections
# Count product lines per file: code lines excluding inline #[cfg(test)] modules, blank lines and pure comment lines.
def split(path):
    lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    n = len(lines)
    in_test = [False]*n
    i = 0
    while i < n:
        if re.match(r'\s*#\[cfg\(test\)\]', lines[i]):
            # find the opening brace of the mod
            j = i; depth = 0; started=False
            while j < n:
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]: started=True
                in_test[j] = True
                if started and depth <= 0: break
                j += 1
            i = j+1
        else:
            i += 1
    prod=test=comment=blank=0
    for k,l in enumerate(lines):
        s=l.strip()
        if in_test[k]: test+=1
        elif not s: blank+=1
        elif s.startswith('//'): comment+=1
        else: prod+=1
    return prod,test,comment,blank
tot=collections.Counter(); per=[]
root=sys.argv[1]
for dp,dn,fn in os.walk(root):
    if '/target' in dp or '/tests' in dp.replace(root,'',1) and not dp.replace(root,'',1).startswith('/crates'): pass
    for f in fn:
        if not f.endswith('.rs'): continue
        p=os.path.join(dp,f)
        rel=os.path.relpath(p,root)
        parts=rel.split(os.sep)
        if 'target' in parts: continue
        crate=parts[1] if parts[0]=='crates' else parts[0]
        kind='tests' if 'tests' in parts[2:3] or 'tests' in parts[:3] and parts[0]!='crates' else 'src'
        if parts[0]=='crates' and parts[2]=='tests': kind='tests'
        prod,test,comment,blank=split(p)
        if kind=='tests': test+=prod; prod=0
        tot[(crate,'prod')]+=prod; tot[(crate,'test')]+=test; tot[(crate,'comment')]+=comment
        per.append((prod,rel))
crates=sorted({c for c,_ in tot})
print(f"{'crate':20} {'prod':>7} {'test':>7} {'doc/cmt':>7}")
P=T=0
for c in crates:
    print(f"{c:20} {tot[(c,'prod')]:7} {tot[(c,'test')]:7} {tot[(c,'comment')]:7}"); P+=tot[(c,'prod')]; T+=tot[(c,'test')]
print(f"{'TOTAL':20} {P:7} {T:7}")
print()
print("largest product files:")
for prod,rel in sorted(per,reverse=True)[:int(sys.argv[2]) if len(sys.argv)>2 else 40]:
    print(f"{prod:6} {rel}")
