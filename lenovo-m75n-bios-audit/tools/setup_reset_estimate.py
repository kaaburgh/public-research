#!/usr/bin/env python3
"""Read-only local comparison; keep owner output private."""
from pathlib import Path
from nvar_capacity import meta,h
import re,argparse
GUID='EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9'
def setup(p):
    nodes={}
    for q in p.iterdir():
        if not q.is_dir() or not (q/'info.txt').is_file():continue
        d=meta(q)
        if d.get('Type')=='NVAR entry':nodes[h(d['Offset'])]=(q,d)
    ends={}
    for q,d in nodes.values():
        if d.get('Text')!='Setup' or d.get('Variable GUID','').upper()!=GUID or not re.search(r'\bValid\b',d.get('Attributes','')):continue
        seen=set()
        while 'Next node at offset' in d:
            off=h(d['Next node at offset']);assert off not in seen;seen.add(off);q,d=nodes[off]
            assert d.get('Text')=='Setup' and 'Valid' in d['Attributes']
        ends[h(d['Offset'])]=(q/'body.bin').read_bytes()
    assert len(ends)==1
    return next(iter(ends.values()))
def ifr(p):
    questions={};current=None;depth=0
    lines=[]
    for line in p.read_text().splitlines():
        if lines and re.match(r"\s*(OneOf|Numeric|CheckBox) Prompt:",lines[-1]) and "QuestionFlags:" not in lines[-1]:lines[-1]+=" "+line.strip()
        else:lines.append(line)
    for line in lines:
        indentation=len(line)-len(line.lstrip('\t'))
        m=re.match(r'\s*(OneOf|Numeric|CheckBox) Prompt: "(.*?)", Help: .*?QuestionFlags: 0x[0-9A-Fa-f]+, QuestionId: (0x[0-9A-Fa-f]+), VarStoreId: 0x1, VarOffset: (0x[0-9A-Fa-f]+), (.*)',line)
        if current and indentation<=depth:current=None
        if m:
            kind,name,qid,offset,rest=m.groups();size=1 if kind=='CheckBox' else int(re.search(r'Size: (\d+)',rest)[1])//8
            current=(name.strip(),int(offset,16),size);questions.setdefault(current,{'opts':{},'qids':set()})['qids'].add(qid);depth=indentation
        elif current:
            m=re.match(r'\s*OneOfOption Option: "(.*?)" Value: (\d+)',line)
            if m:questions[current]['opts'].setdefault(int(m[2]),set()).add(m[1])
    return questions
def main():
    p=argparse.ArgumentParser(description="Read-only local comparison; do not publish owner output.")
    p.add_argument("old_dump",type=Path);p.add_argument("new_dump",type=Path);p.add_argument("old_ifr",type=Path);p.add_argument("new_ifr",type=Path);a=p.parse_args()
    old=sorted(a.old_dump.rglob('* NVAR store'));assert len(old)==2;live=setup(old[1]);other=setup(old[0]);defaultold=setup(next(old[1].glob('* StdDefaults')));new=setup(next(a.new_dump.rglob('* StdDefaults')));assert len(live)==len(defaultold)==446 and len(new)==449
    qa=ifr(a.old_ifr);qb=ifr(a.new_ifr);common=qa.keys()&qb.keys();print('questions',len(qa),len(qb),'common',len(common));print('raw diff live old defaults',sum(a!=b for a,b in zip(live,defaultold)),'live new defaults common prefix',sum(a!=b for a,b in zip(live,new)))
    for key in sorted(common,key=lambda k:k[1]):
        name,off,w=key
        if not name or off+w>446 or off not in {8,0xb,0x39,0x7a,0x9e,0x181,0x193}:continue
        vals=[int.from_bytes(b[off:off+w],'little') for b in (other,live,defaultold,new)]
        if vals[1]==vals[3]:continue
        opts=qb[key]['opts'];print(hex(off),w,name,vals,'=>', ['/'.join(sorted(opts.get(v,[]))) for v in vals])
if __name__=='__main__':main()
