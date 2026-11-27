#!/usr/bin/env python3
"""Offline M75n DXE PCD v6 reconstruction check, input raw section bodies."""
import struct, uuid, sys
from pathlib import Path

def parse(b):
    assert uuid.UUID(bytes_le=b[:16])==uuid.UUID('3c7d193c-682c-4c14-a68f-552dea4f437e')
    ver,L,sku,uninit,loc,ex,guid,st,sz,skuoff,name,nloc,nex,nguid=struct.unpack_from('<IIQ8I3H',b,16)
    assert ver==6 and L==len(b)
    return list(struct.unpack_from(f'<{nloc}I',b,loc)),[struct.unpack_from('<IHH',b,ex+8*i) for i in range(nex)], [str(uuid.UUID(bytes_le=b[guid+i*16:guid+(i+1)*16])) for i in range(nguid)]

def reconstruct(old,new,pei):
    local,ex,guids=parse(old); nlocal,nex,nguids=parse(new); peilocal,_,_=parse(pei)
    base=len(peilocal)+1
    assert base==443 and len(local)==276 and len(ex)==77 and guids==nguids
    removed={('a13d1e82-21b8-4204-92bb-373afb01c6ac',n) for n in (49,51,52,53)}
    removedidx={t-base for e,t,g in ex if (guids[g],e) in removed}
    assert len(removedidx)==4
    offmask=0xfffff
    removedoff={local[i]&offmask for i in removedidx}
    assert removedoff=={0x87c,0x87e,0x8a5,0xa03}
    head=bytearray(old[:0x90])
    for off,delta in ((0x14,-48),(0x20,-1),(0x24,-32),(0x2c,-48),(0x30,-48),(0x34,-48)):
        struct.pack_into('<I',head,off,struct.unpack_from('<I',head,off)[0]+delta)
    for off in (0x40,0x42):struct.pack_into('<H',head,off,struct.unpack_from('<H',head,off)[0]-4)
    out=head+ b''.join(struct.pack('<IHH',e,t-sum(k<t-base for k in removedidx),g) for e,t,g in ex if t-base not in removedidx)
    for i,x in enumerate(local):
        if i in removedidx:continue
        off=x&offmask
        if 0x90<=off<len(old):off-=48+sum(k<(x&offmask) for k in removedoff if k<len(old))
        elif off>=len(old):off-=48+sum(len(old)<=k<(x&offmask) for k in removedoff)
        out+=struct.pack('<I',(x&~offmask)|off)
    out+=bytes(x for i,x in enumerate(old[0x748:],0x748) if i not in removedoff)+b'\xda'*3
    assert out==new
    return out
if __name__=='__main__':
    old,new,pei=(Path(p).read_bytes() for p in sys.argv[1:]);reconstruct(old,new,pei);print('PASS: exact reconstruction',len(new),'bytes')
