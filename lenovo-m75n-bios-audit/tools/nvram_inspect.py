#!/usr/bin/env python3
"""Inspect A75-decoded NVAR graph and StdDefaults. Never writes firmware.
Local output intentionally limited to selected settings and structural diagnostics.
Not a raw NVAR parser: trusts A75 metadata, does not decide active store.
"""
import argparse, collections, hashlib, json, re, struct
from pathlib import Path
GLOBAL='8BE4DF61-93CA-11D2-AA0D-00E098032B8C'
TARGET={'Setup':'EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9','AmdSetup':'3A997502-647A-4C82-998E-52EF9486A247','SecureBootSetup':'7B59104A-C00D-4158-87FF-F04D6396A915','PK':GLOBAL,'BootOrder':GLOBAL}
def meta(p):return dict(x.split(': ',1) for x in (p/'info.txt').read_text(errors='replace').splitlines() if ': ' in x)
def hexnum(s):return int(s.split('h',1)[0],16)
def body(p):return (p/'body.bin').read_bytes()
def valid(d):return bool(re.search(r'\bValid\b',d.get('Attributes',''))) and d.get('Subtype')!='Invalid'
def resolve(store):
    nodes={};roots=collections.defaultdict(list);issues=[]
    for p in store.iterdir():
        if not p.is_dir() or not (p/'info.txt').exists():continue
        d=meta(p)
        if d.get('Type')!='NVAR entry':continue
        o=hexnum(d['Offset']); nodes[o]=(p,d)
        if valid(d) and d.get('Variable GUID') and d.get('Text'):
            roots[(d['Text'],d['Variable GUID'].upper())].append(o)
    resolved={}
    for key,starts in roots.items():
        if key[0] not in TARGET and not re.fullmatch(r'Boot[0-9A-Fa-f]{4}',key[0]):continue
        if key[1]!=TARGET.get(key[0],GLOBAL):continue
        ends={}
        for start in starts:
            o=start;seen=set()
            while True:
                if o in seen or o not in nodes:issues.append((key[0],'cycle/missing',o));break
                seen.add(o);p,d=nodes[o]
                if not valid(d) or d.get('Text')!=key[0] or d.get('Variable GUID',key[1]).upper()!=key[1]:issues.append((key[0],'invalid/mismatched',o));break
                if 'Next node at offset' in d:o=hexnum(d['Next node at offset']);continue
                if d.get('Subtype') not in ('Full','Data') or not (p/'body.bin').is_file():issues.append((key[0],'bad terminal',o));break
                ends[o]=body(p);break
        if len(ends)==1:resolved[key[0]]=next(iter(ends.items()))
        elif len(ends)>1:issues.append((key[0],'multiple terminals',sorted(ends)))
    return resolved,issues

def load_option(b):
    if len(b)<8:return False
    n=struct.unpack_from('<H',b,4)[0];p=6
    while p+2<=len(b) and b[p:p+2]!=b'\0\0':p+=2
    if p+2>len(b):return False
    p+=2;end=p+n
    if end>len(b):return False
    paths=0
    while p+4<=end:
        typ,sub,size=struct.unpack_from('<BBH',b,p)
        if size<4 or p+size>end:return False
        p+=size
        if typ==0x7f and sub==0xff:
            if size!=4:return False
            paths+=1
            if p==end:return True
        elif typ==0x7f and (sub!=1 or size!=4):return False
    return False

def inspect(root):
    defaults=[];live=[]
    for s in sorted(root.rglob('* StdDefaults')):
        rows={}
        for p in s.iterdir():
            if not p.is_dir() or not (p/'info.txt').exists():continue
            d=meta(p)
            if d.get('Type')=='NVAR entry' and d.get('Variable GUID') and (p/'body.bin').is_file():
                b=body(p);rows[d['Text']+'|'+d['Variable GUID']]={'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        defaults.append(rows)
    for s in sorted(root.rglob('* NVAR store')):
        r,issues=resolve(s);d={'issues':issues,'resolved':{n:{'offset':o,'size':len(b)} for n,(o,b) in r.items() if n in TARGET}}
        if 'AmdSetup' in r:
            b=r['AmdSetup'][1]
            if len(b)==0x53f:d['amd_header']=[struct.unpack_from('<I',b,i)[0] for i in (0,4)];d['amd_selected']={'TSME':b[0xc5],'UMA':b[0xd0:0xd8].hex()}
        if 'SecureBootSetup' in r:d['secure_boot_config']=r['SecureBootSetup'][1][:1].hex()
        if 'BootOrder' in r:
            b=r['BootOrder'][1]
            if len(b)%2:raise ValueError('odd BootOrder size')
            names=[f'Boot{x:04X}' for (x,) in struct.iter_unpack('<H',b)]
            d['boot_order_count']=len(names);d['boot_valid_count']=sum(n in r and load_option(r[n][1]) for n in names)
        live.append(d)
    return {'defaults':defaults,'live':live}
def main():
    p=argparse.ArgumentParser();p.add_argument('roots',nargs='+',type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args()
    results=[inspect(x) for x in a.roots];a.output.write_text(json.dumps(results,indent=2)+'\n')
    for p,r in zip(a.roots,results):print(p.name,'defaults counts',[len(x) for x in r['defaults']],'stores',len(r['live']),'boot validity',[(x.get('boot_order_count'),x.get('boot_valid_count')) for x in r['live']],'issues',[len(x['issues']) for x in r['live']])
if __name__=='__main__':main()
