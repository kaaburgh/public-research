#!/usr/bin/env python3
"""Offline instruction matching aid for PE/TE. NOT a semantic equivalence checker.
Coordinates: PE objdump VAs (subtract ImageBase for RVA); TE RVAs.
All original instructions are retained in the JSON report. No firmware is executed.
"""
import argparse, collections, difflib, json, re, struct, subprocess, tempfile
from pathlib import Path
LINE=re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*?)\s*$',re.I)
BRANCH=re.compile(r'^(callq?|j[a-z]+|loop[a-z]*)\s+(?:0x)?[0-9a-f]+(?:\s+<[^>]+>)?$',re.I)
RIP=re.compile(r'\[rip(?:[+-]0x[0-9a-f]+)?\]',re.I)
def parse(text):
    out=[]
    for line in text.splitlines():
        m=LINE.match(line)
        if m and m[3]:out.append((int(m[1],16),m[2].split(),m[3]))
    return out

def normalized(ins):
    # Used only for candidates. Preserve immediates, memory displacements other than RIP.
    s=ins.split('#',1)[0].strip().lower()
    s=re.sub(r'\s+',' ',s)
    m=BRANCH.fullmatch(s)
    if m:s=m[1]+' <direct-target>'
    return RIP.sub('[rip+<disp>]',s)

def disassemble(path,objdump):
    b=path.read_bytes()
    if b[:2]==b'MZ':
        return parse(subprocess.check_output([objdump,'-d','-M','intel','--insn-width=16',str(path)],text=True))
    if b[:2]!=b'VZ' or len(b)<40:raise ValueError('not a PE/TE image')
    machine,n,_,stripped=struct.unpack_from('<HBBH',b,2)
    arch={0x14c:'i386',0x8664:'i386:x86-64'}.get(machine)
    if not arch:raise ValueError(f'unsupported TE machine {machine:x}')
    delta=stripped-40;out=[]
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)/'section.bin'
        for i in range(n):
            off=40+40*i
            vs,va,rs,rp=struct.unpack_from('<IIII',b,off+8)
            flags=struct.unpack_from('<I',b,off+36)[0]
            if not flags&0x20000000 or not rs:continue
            raw=rp-delta;length=min(rs,vs or rs)
            if raw<0 or raw+length>len(b):raise ValueError('TE section out of bounds')
            p.write_bytes(b[raw:raw+length])
            out+=parse(subprocess.check_output([objdump,'-D','-b','binary','-m',arch,'-M','intel','--insn-width=16',f'--adjust-vma=0x{va:x}',str(p)],text=True))
    return out

def chunks(rows):
    # int3 delimited search chunks, NOT true function boundaries.
    out=[];cur=[]
    for row in rows:
        if row[2].strip().lower()=='int3':
            if cur:out.append(cur);cur=[]
        else:cur.append(row)
    if cur:out.append(cur)
    return out

def match(old,new):
    a,b=chunks(old),chunks(new)
    na,nb=[[tuple(normalized(r[2]) for r in c) for c in x] for x in (a,b)]
    lookup=collections.defaultdict(list)
    for j,f in enumerate(nb):lookup[f].append(j)
    used=set();pairs=[];unmatched=[]
    for i,f in enumerate(na):
        choices=[j for j in lookup[f] if j not in used]
        if len(choices)==1:
            j=choices[0];used.add(j);pairs.append((i,j,'unique-normalized-exact',1.0))
        else:unmatched.append(i)
    # Only approximate candidates with roughly comparable lengths. Ambiguous ties are not matched.
    for i in unmatched:
        scores=[]
        for j,g in enumerate(nb):
            if j in used or not na[i] or not g:continue
            if min(len(na[i]),len(g))/max(len(na[i]),len(g))<0.5:continue
            sm=difflib.SequenceMatcher(None,na[i],g,autojunk=False)
            if sm.quick_ratio()>=0.65:scores.append((sm.ratio(),j))
        scores.sort(reverse=True)
        if scores and scores[0][0]>=0.75 and (len(scores)==1 or scores[0][0]-scores[1][0]>=0.02):
            ratio,j=scores[0];used.add(j);pairs.append((i,j,'approximate-candidate',ratio))
    return {'old_chunks':a,'new_chunks':b,'pairs':sorted(pairs),'old_unmatched':sorted(set(range(len(a)))-{x[0] for x in pairs}),'new_unmatched':sorted(set(range(len(b)))-used)}

def main():
    p=argparse.ArgumentParser();p.add_argument('old',type=Path);p.add_argument('new',type=Path);p.add_argument('-o','--output',required=True,type=Path);p.add_argument('--objdump',default='objdump');a=p.parse_args()
    old,new=[disassemble(x,a.objdump) for x in (a.old,a.new)]
    result=match(old,new);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=1)+'\n')
    print('instructions',len(old),len(new),'chunks',len(result['old_chunks']),len(result['new_chunks']),'pairs',len(result['pairs']),'unmatched',len(result['old_unmatched']),len(result['new_unmatched']))
if __name__=='__main__':main()
