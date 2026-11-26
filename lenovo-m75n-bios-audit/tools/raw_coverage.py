#!/usr/bin/env python3
"""Account for all raw byte positions, not semantic change attribution.
M75n 16 MiB only. Union boundaries from validated AMD directories and FV headers.
No raw data or per-region private hashes are exported.
"""
import argparse, collections, json, re, struct
from pathlib import Path
from amd_data import directories
SIZE=0x1000000

def intervals(b):
    out=[]
    for off,k,stride in [(0x82000,'$PSP',16),(0x189000,'$PL2',16),(0x145000,'$BHD',24),(0x289000,'$BL2',24)]:
        out.append((off,off+16+struct.unpack_from('<I',b,off+8)[0]*stride,'AMD directory'))
    for k,rows in directories(b).items():
        for r in rows:
            if r['status']!='mapped':continue
            t=r['type']&255; label='PSP payload' if k in ('$PSP','$PL2') else {0x60:'APCB',0x68:'APCB',0x66:'microcode',0x63:'BIOS type 63 (APOB candidate)',0x62:'BIOS compressed/raw image'}.get(t,'other AMD payload')
            out.append((r['offset'],r['offset']+r['size'],label))
    for m in re.finditer(b'_FVH',b):
        o=m.start()-40
        if o<0 or o+56>len(b) or o%8:continue
        size=struct.unpack_from('<Q',b,o+32)[0];hs=struct.unpack_from('<H',b,o+48)[0]
        if 56<=hs<=size<=len(b)-o and hs%2==0 and sum(x[0] for x in struct.iter_unpack('<H',b[o:o+hs]))%65536==0:
            label='NVAR FV candidate' if o in (0x21000,0x41000) else 'firmware volume'
            out.append((o,o+size,label))
    return out

def compare(a,b):
    if len(a)!=SIZE or len(b)!=SIZE:raise ValueError('expected 16 MiB ROMs')
    ia,ib=intervals(a),intervals(b);bounds=sorted({0,SIZE}|{x for o,e,_ in ia+ib for x in (o,e)})
    priority=['APCB','microcode','AMD directory','NVAR FV candidate','BIOS type 63 (APOB candidate)','firmware volume','PSP payload','BIOS compressed/raw image','other AMD payload']
    rows=[];totals=collections.defaultdict(lambda:[0,0])
    for o,e in zip(bounds,bounds[1:]):
        labels=lambda iv:sorted({k for s,t,k in iv if s<=o and e<=t})
        la,lb=labels(ia),labels(ib);kind=next((k for k in priority if k in la or k in lb),'unmapped')
        x,y=a[o:e],b[o:e];diff=0 if x==y else sum(p!=q for p,q in zip(x,y))
        rows.append({'start':o,'end_exclusive':e,'labels_old':la,'labels_new':lb,'category':kind,'changed_bytes':diff})
        totals[kind][0]+=e-o;totals[kind][1]+=diff
    if sum(v[0] for v in totals.values())!=SIZE:raise AssertionError('coverage gap')
    if sum(v[1] for v in totals.values())!=sum(x!=y for x,y in zip(a,b)):raise AssertionError('diff accounting mismatch')
    return {'total_bytes':SIZE,'changed_bytes':sum(v[1] for v in totals.values()),'categories':dict(totals),'intervals':rows}

def main():
    p=argparse.ArgumentParser();p.add_argument('roms',nargs=3,type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args()
    data=[r.read_bytes() for r in a.roms];r={name:compare(data[i],data[j]) for name,i,j in [('124_132',0,1),('132_133',1,2),('124_133',0,2)]};a.output.write_text(json.dumps(r,indent=2)+'\n')
    for k,v in r.items():print(k,'total',v['total_bytes'],'changed',v['changed_bytes'],'unmapped',v['categories'].get('unmapped',[0,0]),'intervals',len(v['intervals']))
if __name__=='__main__':main()
