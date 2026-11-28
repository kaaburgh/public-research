"""Untrusted root hint generator; no assurance authority."""
from checker import u, need, MAX_NODES, MAX_BYTES
def propose(rom):
    """Untrusted root discovery hint. Opaque gaps remain explicit; no claim of completeness."""
    out=[]; pos=0; search=0; candidates=0; work=0
    def gap(a,b):
        if a<b:
            x=rom[a:b]; out.append({'offset':a,'size':b-a,'kind':'erased' if all(v==255 for v in x) or all(v==0 for v in x) else 'opaque'})
    while (j:=rom.find(b'_FVH',search))>=0:
        candidates+=1; need(candidates<=MAX_NODES,'discovery_limit')
        search=j+1; o=j-40
        if o<pos or o+56>len(rom): continue
        n=u(rom,o+32,8); hl=u(rom,o+48,2)
        if not (72<=hl<=n<=len(rom)-o and hl%2==0): continue
        work+=hl; need(work<=MAX_BYTES,'discovery_checksum_budget')
        if sum(u(rom,i,2) for i in range(o,o+hl,2))%65536: continue
        gap(pos,o); out.append({'offset':o,'size':n,'kind':'fv'}); pos=o+n; search=pos
    gap(pos,len(rom)); return out
