#!/usr/bin/env python3
"""Offline reconstruction of M75n SmiFlash map, not an SMI client/emulator.
Only reads extracted descriptor bodies; deliberately no flash/variable writes.
"""
import argparse, hashlib, struct
from pathlib import Path
GUID='0DCA793A-EA96-42D8-BD7B-DC7F684E38C1'
BLOCK=0x1000
ROM=0x1000000
EXPECTED='1314b86f236c3e713e73488e65c8894d2a852ed34a8d157606cd2d2e8511d994'
def digest(b): return hashlib.sha256(b).hexdigest()
def classify(data):
    if len(data)%24 or len(data)<48 or data[-24:]!=bytes(24):raise ValueError('invalid descriptor array')
    rows=list(struct.iter_unpack('<QIIII',data[:-24])); fixed={0xff021000,0xff041000,0xff2f1000,0xffdd0000,0xffe00000}
    # 1.24 SmiFlash 0x14b3..0x1570: skip outer fixed addresses, swap lower addresses.
    for i in range(len(rows)):
        if rows[i][0] in fixed:continue
        for j in range(i+1,len(rows)):
            if rows[j][0]<rows[i][0]:rows[i],rows[j]=rows[j],rows[i]
    regions=[]; n=0
    for base,offset,size,_,flags in rows:
        if base!=0xff000000+offset or not size or offset%BLOCK or size%BLOCK or offset+size>ROM:raise ValueError('unexpected region')
        if base in (0xff021000,0xff041000):typ=2
        elif base in (0xff2f1000,0xffdd0000):typ=1
        elif base==0xffe00000:typ=0
        else:typ=0x80+n;n+=1
        regions.append((offset,size,typ))
    return regions,n

def generate(data):
    regions,n=classify(data); result=[]; gap=0x7f+n; last=-2
    for offset in range(0,ROM,BLOCK):
        typ=next((t for o,s,t in regions if o<=offset<o+s),None)
        if typ is None:
            if last+BLOCK!=offset:gap+=1
            last=offset;typ=gap
        # OEM post-hook 1.24 RVA 0x27c0 / 1.32 0x2810, request 0x25.
        if 0x61000<=offset<0x81000:typ=0x7e
        result.append((offset,BLOCK,typ))
    return result

def compress(rows):
    out=[]
    for o,s,t in rows:
        if out and out[-1][0]+out[-1][1]==o and out[-1][2]==t:
            a,b,c=out[-1];out[-1]=(a,b+s,c)
        else:out.append((o,s,t))
    return out

def pack(rows):return b''.join(struct.pack('<IIB',*r) for r in rows)
def expand(data):
    out=[]; expected=0
    for o,s,t in struct.iter_unpack('<IIB',data):
        if o!=expected or not s or s%BLOCK or o+s>ROM:raise ValueError('invalid map')
        out.extend((i,BLOCK,t) for i in range(o,o+s,BLOCK));expected=o+s
    if expected!=ROM:raise ValueError('incomplete map')
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('roots',nargs='+',type=Path);a=p.parse_args(); all_maps=[]
    for root in a.roots:
        paths=sorted(root.glob('**/* '+GUID+'/*/body.bin'))
        if len(paths)!=2:raise ValueError(f'{root}: expected two tables, got {len(paths)}')
        for path in paths:
            data=path.read_bytes();rows=generate(data);compact=compress(rows);raw=pack(rows)
            if expand(pack(compact))!=rows or expand(raw)!=rows:raise ValueError('round-trip')
            print(root.name,digest(data),len(rows),len(compact),sum(s for _,s,_ in rows),digest(raw))
            for o,s,t in compact:print(f'{o:06x}-{o+s-1:06x}: {t:02x}')
            all_maps.append(raw)
    if any(digest(x)!=EXPECTED for x in all_maps):raise SystemExit('historical model digest mismatch')
if __name__=='__main__':main()
