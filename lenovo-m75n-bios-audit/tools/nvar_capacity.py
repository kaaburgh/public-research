#!/usr/bin/env python3
"""Offline A75 NVAR compact-size estimate; aggregate output only; never writes firmware."""
from pathlib import Path
from collections import defaultdict
import sys,re

def meta(p):
    return dict(x.split(': ',1) for x in (p/'info.txt').read_text(errors='replace').splitlines() if ': ' in x)
def h(x):return int(x.split('h',1)[0],16)
def read_store(p):
    nodes={}; roots=defaultdict(list); structural=0; free=0
    for q in p.iterdir():
        if not q.is_dir() or not (q/'info.txt').is_file():continue
        d=meta(q); typ=d.get('Type');size=h(d['Full size'])
        structural+=size
        if typ=='Free space':free+=size
        if typ!='NVAR entry':continue
        off=h(d['Offset']);assert off not in nodes
        nodes[off]=(q,d)
        if d.get('Variable GUID') and d.get('Text') and re.search(r'\bValid\b',d.get('Attributes','')) and d.get('Subtype') not in ('Invalid','Invalid link'):
            roots[(d['Text'],d['Variable GUID'].upper())].append(off)
    assert structural==(p/'body.bin').stat().st_size
    records={};errors=0
    for key,starts in roots.items():
        ends=set()
        for start in starts:
            off=start;seen=set()
            while True:
                if off in seen or off not in nodes:errors+=1;break
                seen.add(off);q,d=nodes[off]
                if not re.search(r'\bValid\b',d.get('Attributes','')) or d.get('Subtype') in ('Invalid','Invalid link') or d.get('Text')!=key[0] or d.get('Variable GUID',key[1]).upper()!=key[1]:errors+=1;break
                if 'Next node at offset' in d:off=h(d['Next node at offset']);continue
                if d.get('Subtype') not in ('Full','Data') or not (q/'body.bin').is_file():errors+=1;break
                ends.add(off);break
        if len(ends)!=1:errors+=1;continue
        root=nodes[starts[0]][1];q,term=nodes[next(iter(ends))]
        payload=(q/'body.bin').stat().st_size;tail=max(h(root.get('Tail size','0h')),h(term.get('Tail size','0h')))
        records[key]=(payload,tail)
    return records,errors,free,structural,len(nodes)
def cost(records):
    # Generous one-record estimate; UTF16, inline GUID and table slot,
    # 10-byte header, observed auth tail, padding and 64 extra per record.
    return sum(n+tail+2*(len(name)+1)+16+16+10+15+64 for (name,guid),(n,tail) in records.items())
def main():
    old=Path(sys.argv[1]);new=Path(sys.argv[2]);defaults=sorted(new.rglob('* StdDefaults'))
    assert defaults
    dsets=[]
    for p in defaults:
        r,errors,_,_,_=read_store(p);assert not errors;dsets.append(r)
    assert all(r==dsets[0] for r in dsets);d=dsets[0]
    newcontainer=(defaults[0]/'body.bin').stat().st_size
    print('defaults',len(d),'container size',newcontainer)
    for i,p in enumerate(sorted(old.rglob('* NVAR store')),1):
        r,errors,free,capacity,nodecount=read_store(p);print('store',i,'nodes',nodecount,'resolved',len(r),'errors',errors,'raw free',free,'capacity',capacity)
        assert not errors
        kept={k:v for k,v in r.items() if k not in d and k[0] not in ('StdDefaults','MfgDefaults')};containers=[k for k in r if k[0]=='StdDefaults'];assert len(containers)==1
        kept[containers[0]]=(newcontainer,0);kept.update(d)
        payload=sum(n for n,tail in kept.values());estimate=cost(kept)
        print('reconstructed logical entries',len(kept),'payload',payload,'generous estimate',estimate,'headroom',capacity-estimate)
if __name__=='__main__':main()
