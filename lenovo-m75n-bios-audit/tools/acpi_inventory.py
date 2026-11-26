#!/usr/bin/env python3
"""Find checksum-valid static DSDT/SSDT AML tables in A75-extracted bodies.
Not a live ACPI dump, not proof of dynamic table equivalence.
"""
import argparse, collections, hashlib, json, re, struct
from pathlib import Path

def inspect(root):
    hits=collections.defaultdict(list)
    for p in sorted(root.rglob('body.bin')):
        if any('NVAR store' in x or 'Padding' in x for x in p.parts):continue
        b=p.read_bytes()
        for m in re.finditer(b'DSDT|SSDT',b):
            i=m.start()
            if i+36>len(b):continue
            size=struct.unpack_from('<I',b,i+4)[0]
            if not 36<=size<=len(b)-i:continue
            data=b[i:i+size]
            if sum(data)%256 or not all(c==0 or 32<=c<=126 for c in data[10:24]):continue
            key=(m.group().decode(),size,hashlib.sha256(data).hexdigest())
            hits[key].append({'path':str(p.relative_to(root)),'offset':i})
    return [{'signature':k[0],'size':k[1],'sha256':k[2],'occurrences':v} for k,v in sorted(hits.items())]

def main():
    p=argparse.ArgumentParser();p.add_argument('roots',nargs='+',type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args()
    results=[inspect(r) for r in a.roots];a.output.write_text(json.dumps(results,indent=2)+'\n')
    for root,rows in zip(a.roots,results):print(root.name,'unique tables',dict(collections.Counter(x['signature'] for x in rows)),'occurrences',sum(len(x['occurrences']) for x in rows))
    if len(results)>1:print('unique hash sets equal',all({x['sha256'] for x in rows}=={x['sha256'] for x in results[0]} for rows in results))
if __name__=='__main__':main()
