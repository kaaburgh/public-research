#!/usr/bin/env python3
"""Reconstructed verifier, not the original inventory generator. Python 3.10+.
Run locally against UEFIExtract A75 dump roots. Does not write firmware.
"""
import argparse, csv, hashlib, pathlib, struct, collections

def sha(b): return hashlib.sha256(b).hexdigest()
def num(b, o, n): return int.from_bytes(b[o:o+n], 'little')
def norm(data):
    b=bytearray(data)
    if b[:2]==b'MZ':
        p=num(b,60,4)
        if b[p:p+4]!=b'PE\0\0': raise ValueError('PE signature')
        s=p+24; magic=num(b,s,2); n=num(b,p+6,2); st=s+num(b,p+20,2)
        if magic==0x20b: bo=s+24; width=8; dd=s+112
        elif magic==0x10b: bo=s+28; width=4; dd=s+96
        else: raise ValueError('PE magic')
        rva,size=struct.unpack_from('<II',b,dd+5*8); delta=0
    elif b[:2]==b'VZ':
        n=b[4]; st=40; bo=16; width=8; delta=num(b,6,2)-40
        rva,size=struct.unpack_from('<II',b,24)
    else: raise ValueError('not PE/TE')
    base=num(b,bo,width)
    sections=[]
    for i in range(n):
        o=st+40*i; vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8)
        sections.append((va,rs,rp-delta))
    def at(r,l):
        for va,rs,rp in sections:
            if va<=r and r+l<=va+rs and 0<=rp+r-va<=len(b)-l: return rp+r-va
        raise ValueError(f'unmapped RVA {r:x}')
    if size:
        off=at(rva,size); end=off+size
        while off<end:
            if end-off<8: raise ValueError('short reloc header')
            page,bs=struct.unpack_from('<II',b,off)
            if bs<8 or bs%2 or off+bs>end: raise ValueError('bad reloc block')
            for i in range(off+8,off+bs,2):
                v=num(b,i,2); t=v>>12
                if not t: continue
                w={3:4,10:8}.get(t)
                if not w: raise ValueError(f'unsupported reloc {t}')
                a=at(page+(v&4095),w)
                b[a:a+w]=((num(b,a,w)-base)%(1<<(8*w))).to_bytes(w,'little')
            off+=bs
    b[bo:bo+width]=bytes(width)
    return bytes(b)

def index(root):
    result=collections.defaultdict(list)
    for p in root.rglob('body.bin'):
        # Hash each extracted payload; exclude NVAR and padding. Hash matching is
        # independent of extraction instance numbering and directory names.
        if any('NVAR store' in x or 'Padding' in x for x in p.parts): continue
        d=p.read_bytes(); result[sha(d)].append((p,d))
    return result

def main():
    p=argparse.ArgumentParser(); p.add_argument('inventory',type=pathlib.Path); p.add_argument('dump124',type=pathlib.Path);p.add_argument('dump132',type=pathlib.Path);p.add_argument('dump133',type=pathlib.Path);a=p.parse_args()
    roots=[a.dump124,a.dump132,a.dump133]; idx=[index(x) for x in roots]
    with a.inventory.open(encoding='utf-8-sig',newline='') as f: rows=list(csv.DictReader(f,delimiter='\t'))
    count=collections.Counter(); missing=[]; mismatch=[]
    for r in rows:
        if r['section'] not in ('PE32 image section','TE image section'): continue
        data=[]
        for v,i in zip(('124','132','133'),idx):
            h=r.get('sha'+v,''); matches=i.get(h,[])
            if not h or h=='-': data.append(None);continue
            if not matches: missing.append((r['module'],v,h));data.append(None);continue
            data.append(matches[0][1]);count['hash matches']+=1
        for pair,x,y in [('124_132',data[0],data[1]),('132_133',data[1],data[2])]:
            if x is None or y is None: count[pair+' absent/unverified']+=1;continue
            if x==y: count[pair+' exact']+=1;continue
            try: equal=norm(x)==norm(y)
            except (ValueError,struct.error,IndexError) as e: count[pair+' normalization error']+=1; mismatch.append((r['module'],pair,str(e)));continue
            count[pair+(' normalized equal' if equal else ' different')]+=1
            expected=r['relocation_comparison'] if pair=='124_132' else r['132_133_normalized']
            if expected and (('identical' in expected or 'equal' in expected or expected=='same_after_reloc') != equal): mismatch.append((r['module'],pair,expected,equal))
    print(dict(count)); print('missing hashes:',len(missing),missing[:10]);print('classification discrepancies:',len(mismatch),mismatch[:10]); return bool(missing or mismatch)
if __name__=='__main__': raise SystemExit(main())
