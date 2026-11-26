#!/usr/bin/env python3
"""Enumerate extracted FFS leaf payloads independently of historical ledger.
Inputs: UEFIExtract A75 dump directories. Outputs local TSV (may contain private hashes).
The historical profile also includes leaves under nested raw files in ancestor volume-image files.
"""
import argparse, csv, hashlib, re, collections
from pathlib import Path
from audit_verify import norm

def sha(b): return hashlib.sha256(b).hexdigest()
def meta(p):
    try: return dict(line.split(': ',1) for line in (p/'info.txt').read_text(errors='replace').splitlines() if ': ' in line)
    except FileNotFoundError: return {}
def ordered(p):
    # Label lineage first, ordinal only as tie-breaker. Avoid a root index shift (10 -> 9) swapping copies.
    labels=tuple(re.sub(r'^\d+ ','',s) for s in p.parts)
    indices=tuple(int(m[1]) if (m:=re.match(r'^(\d+) ',s)) else -1 for s in p.parts)
    return labels,indices
def label(p): return re.sub(r'^\d+ ','',p.name)
def inventory(root):
    infos={}
    for p in sorted(root.rglob('info.txt'),key=lambda p:ordered(p.relative_to(root))):
        d=meta(p.parent); infos[p.parent]=d
    # UEFIExtract info repeats the key Type (text and numeric); File GUID is authoritative.
    files=[p for p,d in infos.items() if d.get('File GUID') and d.get('Subtype') not in ('Pad','Padding')]
    file_set=set(files); occurrences=collections.Counter(); out={}
    for p in files:
        d=infos[p]; guid=d['File GUID'].upper(); occurrences[guid]+=1; inst=occurrences[guid]
        name=d.get('Text',guid); subtype=d.get('Subtype',''); sections=collections.Counter()
        # For compatibility, include nested raw/file/volume leaves, but not a nested file's section children.
        def visit(q):
            children=sorted((x for x in q.iterdir() if x.is_dir()),key=ordered)
            if q!=p and q in file_set and children: return
            if 'Startup AP data padding file' in q.name or 'NVAR store' in q.name: return
            if not children:
                b=q/'body.bin'
                if b.is_file():
                    section='raw file' if q==p else label(q)
                    sections[section]+=1
                    out[(guid,inst,section,sections[section])]=(name,subtype,b.read_bytes(),str(q.relative_to(root)))
                return
            for child in children: visit(child)
        visit(p)
    return out

def cmp(a,b):
    if a is None: return 'identical' if b is None else 'added'
    if b is None:return 'removed'
    if a==b:return 'identical'
    return 'same_size_changed' if len(a)==len(b) else 'size_changed'
def normalization(a,b):
    if a is None or b is None or a==b:return ''
    try: return 'identical_after_reloc' if norm(a)==norm(b) else 'different_after_reloc'
    except (ValueError,IndexError,OverflowError, __import__('struct').error) as e:return 'error: '+str(e)
def main():
    p=argparse.ArgumentParser();p.add_argument('roots',nargs=3,type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args()
    inventories=[inventory(r) for r in a.roots]; keys=sorted(set().union(*inventories))
    fields=['guid','instance','module','subtype','section','section_instance']+[x+v for x in ('size','sha','path') for v in ('124','132','133')]+['comparison','comparison_132_133','relocation_comparison','132_133_normalized']
    with a.output.open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,delimiter='\t');w.writerow(fields)
        for k in keys:
            vals=[i.get(k) for i in inventories];name,subtype,_,_=next(x for x in vals if x);b=[x[2] if x else None for x in vals];ex=k[2] in ('PE32 image section','TE image section','Raw section with PE32 image')
            w.writerow([k[0],k[1],name,subtype,k[2],k[3],*[len(x) if x is not None else '' for x in b],*[sha(x) if x is not None else '' for x in b],*[x[3] if x else '' for x in vals],cmp(b[0],b[1]),cmp(b[1],b[2]),normalization(b[0],b[1]) if ex else '',normalization(b[1],b[2]) if ex else ''])
    print('rows per release:',*[len(x) for x in inventories],'union:',len(keys))
if __name__=='__main__':main()
