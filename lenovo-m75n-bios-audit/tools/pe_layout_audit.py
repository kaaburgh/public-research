#!/usr/bin/env python3
"""Compare layout changes in M33 1.32/1.33 PE32+ images. No firmware execution.
Conservative: requires identical decoded instruction boundaries, monotonic data
anchors and a bijective mapping of all relocation slots and their targets.
Reports remaining code and zero-byte insertions/deletions; does NOT assert
semantic equivalence. Only two known build path prefixes and Setup date/time
literals are normalized. GNU objdump is required.
"""
import argparse, collections, difflib, json, re, struct, subprocess
from pathlib import Path


def instructions(path):
    result = {}
    text = subprocess.check_output(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', str(path)], text=True, stderr=subprocess.DEVNULL)
    for line in text.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+(.*)', line)
        if match:
            result[int(match[1], 16)] = match[2]
    return result


def parse_pe(b):
    p = struct.unpack_from('<I', b, 60)[0]
    assert b[p:p+4] == b'PE\0\0' and struct.unpack_from('<H', b, p+24)[0] == 0x20b
    assert struct.unpack_from('<Q', b, p+24+24)[0] == 0, 'requires zero image base'
    o = p+24+struct.unpack_from('<H', b, p+20)[0]
    sections = {}
    for i in range(struct.unpack_from('<H', b, p+6)[0]):
        s = b[o+40*i:o+40*(i+1)]
        name = s[:8].rstrip(b'\0').decode()
        vs, va, rs, rp = struct.unpack_from('<IIII', s, 8)
        assert name not in sections and rp+rs <= len(b)
        sections[name] = (va, vs, rp, rs)
    def offset(a):
        for va, vs, rp, rs in sections.values():
            if va <= a < va+rs:
                return rp+a-va
        raise ValueError(f'unmapped RVA {a:x}')
    rel = {}
    va, vs, rp, rs = sections['.reloc']
    j = 0
    while j+8 <= vs:
        page, size = struct.unpack_from('<II', b, rp+j)
        assert size >= 8 and size % 2 == 0 and j+size <= vs
        for i in range(j+8, j+size, 2):
            e = struct.unpack_from('<H', b, rp+i)[0]
            typ, adr = e >> 12, page+(e&0xfff)
            if typ == 0:
                continue
            assert typ in (3, 10) and adr not in rel
            width = 8 if typ == 10 else 4
            rel[adr] = (width, int.from_bytes(b[offset(adr):offset(adr)+width], 'little'))
        j += size
    assert j == vs
    return sections, rel


def compare(old, new, setup=False):
    blobs = [Path(x).read_bytes() for x in (old, new)]
    (sx, rx), (sy, ry) = map(parse_pe, blobs)
    ax, bx = map(instructions, (old, new))
    assert ax.keys() == bx.keys(), 'instruction boundary mismatch'
    base, size, raw, rs = sx['.data']
    base2, size2, raw2, rs2 = sy['.data']
    anchors = collections.defaultdict(set)
    anchors[base].add(base2)
    anchors[base+size].add(base2+size2)
    changed = 0
    residual_code = []
    rip_changed = index_changed = 0
    for adr, x in ax.items():
        y = bx[adr]
        if x != y:
            changed += 1
        u, v = [re.search(r'# 0x([0-9a-f]+)', z) for z in (x, y)]
        if u and v:
            t, w = int(u[1],16), int(v[1],16)
            if base <= t <= base+size and base2 <= w <= base2+size2:
                anchors[t].add(w)
                if x == y:
                    continue
                xx, yy = [re.sub(r'\[rip[+-]0x[0-9a-f]+\]', '[rip+DATA]', z.split('#')[0].strip()) for z in (x,y)]
                if xx == yy:
                    rip_changed += 1
                    continue
        if x == y:
            continue
        u, v = [re.search(r'\+0x([0-9a-f]+)\]', z) for z in (x,y)]
        if u and v:
            t, w = int(u[1],16), int(v[1],16)
            if base <= t < base+size and base2 <= w < base2+size2 and x[:u.start()] == y[:v.start()] and x[u.end():] == y[v.end():]:
                anchors[t].add(w)
                index_changed += 1
                continue
        residual_code.append((hex(adr),x,y))
    assert all(len(v)==1 for v in anchors.values()), 'conflicting anchors'
    pairs = sorted((u,next(iter(v))) for u,v in anchors.items())
    assert all(v<w for (_,v),(_,w) in zip(pairs,pairs[1:])), 'nonmonotonic anchors'
    def masked_data(blob, sections, rel):
        va, vs, rp, rs = sections['.data']
        assert vs <= rs
        d = bytearray(blob[rp:rp+vs])
        for a,(width,_) in rel.items():
            if va <= a <= va+vs-width:
                d[a-va:a-va+width] = b'\xfe'*width
        return d
    def canonical(d, adr, prefix):
        repl={prefix:'PATH'}
        if setup:
            for t,tag in [('16:49:50','TIME'),('15:31:59','TIME'),('11/11/2025','DATE'),('05/15/2026','DATE')]:
                repl[t.encode('utf-16le')]=tag
        tokens, loc = [], []
        i=0
        while i<len(d):
            m=next(((s,t) for s,t in repl.items() if d.startswith(s,i)),None)
            loc.append(adr+i)
            if m:
                tokens.append(m[1]); i+=len(m[0])
            else:
                tokens.append(d[i]); i+=1
        return tokens,loc
    x=masked_data(blobs[0],sx,rx)
    y=masked_data(blobs[1],sy,ry)
    mapping, edits, nonzero = {}, [], []
    for (u,v),(t,w) in zip(pairs,pairs[1:]):
        d,e=x[u-base:t-base],y[v-base2:w-base2]
        if d==e:
            mapping.update((u+i,v+i) for i in range(len(d)))
            continue
        a,al=canonical(d,u,b'e:\\nanoamd\\31a\\nanoamd\\')
        b,bl=canonical(e,v,b'd:\\builds\\sourcecode\\nanoamd\\m33kt33a_s_260515\\')
        for tag,i,j,k,l in difflib.SequenceMatcher(None,a,b,autojunk=False).get_opcodes():
            if tag=='equal':
                mapping.update(zip(al[i:j],bl[k:l]))
            else:
                edit=(hex(u),hex(v),tag,j-i,l-k)
                edits.append(edit)
                if any(t!=0 for t in a[i:j]+b[k:l]):
                    nonzero.append(edit)
    mapping.update(pairs)
    issues=[]; verified=0; seen=set()
    for loc,(width,target) in rx.items():
        q=mapping.get(loc)
        other=ry.get(q)
        if not other or other[0]!=width or q in seen:
            issues.append((hex(loc),'slot mismatch')); continue
        seen.add(q)
        want=mapping.get(target)
        if want is None and sx['.text'][0]<=target<sx['.text'][0]+sx['.text'][1]:
            want=target
        if want is None or other[1]!=want:
            issues.append((hex(loc),'target mismatch')); continue
        verified+=1
    return dict(instructions=len(ax),changed_instruction_rows=changed,rip_changes=rip_changed,index_changes=index_changed,residual_code=residual_code,anchors=len(pairs),data_edits=edits,nonzero_data_edits=nonzero,old_relocs=len(rx),new_relocs=len(ry),verified_relocs=verified,reloc_issues=issues,unmapped_new_relocs=len(ry)-len(seen))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('old'); p.add_argument('new'); p.add_argument('--setup',action='store_true')
    a=p.parse_args()
    print(json.dumps(compare(a.old,a.new,a.setup),indent=2))
