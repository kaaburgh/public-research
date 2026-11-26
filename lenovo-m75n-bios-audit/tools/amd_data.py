#!/usr/bin/env python3
"""Read-only M75n Picasso FP5 AMD directory/APCB/patch inspector. Local output may be private."""
import argparse, hashlib, json, struct
from pathlib import Path

def sha(b): return hashlib.sha256(b).hexdigest()
def u(b,o,n=4): return int.from_bytes(b[o:o+n],'little')
def require(ok,why):
    if not ok: raise ValueError(why)
def fletcher(b):
    a=z=0
    for (v,) in struct.iter_unpack('<H',b): a=(a+v)%65535; z=(z+a)%65535
    return z<<16|a

def directories(b):
    require(len(b)==0x1000000,'M75n 16 MiB only')
    result={}
    for off,sig,stride in [(0x82000,b'$PSP',16),(0x189000,b'$PL2',16),(0x145000,b'$BHD',24),(0x289000,b'$BL2',24)]:
        require(b[off:off+4]==sig,'directory signature')
        n=u(b,off+8); end=off+16+n*stride
        require(0<n<=256 and end<=len(b),'directory bounds')
        require(fletcher(b[off+8:end])==u(b,off+4),'directory checksum')
        rows=[]
        for i in range(n):
            p=off+16+i*stride; typ,size,addr=struct.unpack_from('<IIQ',b,p)
            r={'index':i,'type':typ,'size':size,'address':addr}
            if stride==24:r['destination']=u(b,p+16,8)
            if size==0xffffffff and typ==0xb:r['status']='fuse sentinel'
            elif not size:r['status']='zero length'
            elif 0xff000000<=addr and addr+size<=0x100000000:
                r.update(status='mapped',offset=addr-0xff000000,sha256=sha(b[addr-0xff000000:addr-0xff000000+size]))
            else:raise ValueError(f'unmapped entry {sig!r} {i}')
            rows.append(r)
        result[sig.decode()]=rows
    return result

def tokens(data):
    items=[];p=0
    while p+4<=len(data):
        d=u(data,p);p+=4
        if d==0x001fff00:break
        items.append(((d>>8)&0x1fff,((d>>21)&7)+1))
    else:raise ValueError('missing token terminator')
    out={}
    for t,w in items:
        require(p+w<=len(data) and t not in out,'token bounds/duplicate')
        out[t]=u(data,p,w);p+=w
    return out

def apcb(b):
    require(b[:4]==b'APCB','APCB signature')
    h=u(b,4,2);size=u(b,8)
    require(32<=h<=size<=len(b) and sum(b[:size])%256==0,'APCB size/checksum')
    norm=bytearray(b[:size]);norm[12:16]=bytes(4);norm[16]=0
    result={'size':size,'normalized_sha256':sha(norm),'groups':[]};p=h
    while p<size:
        require(p+16<=size,'group header')
        sig,g,hs,version,gs=struct.unpack_from('<4sHHII',b,p)
        require(16<=hs<=gs and p+gs<=size,'group size')
        q=p+hs;group={'signature':sig.decode('ascii'),'id':g,'offset':p,'types':[]}
        while q<p+gs:
            require(q+16<=p+gs,'type header')
            gi,t,ts=struct.unpack_from('<HHI',b,q)
            require(gi==g and 16<=ts<=p+gs-q,'type size/group')
            r={'type':t,'offset':q,'size':ts,'sha256':sha(b[q:q+ts])}
            if g==0x1707 and t in (0xd,0xf):r['tokens']=tokens(b[q+16:q+ts])
            group['types'].append(r);q+=ts
        result['groups'].append(group);p+=gs
    return result

def inspect(b):
    dirs=directories(b);blocks={};patches={}
    for rows in dirs.values():
        for r in rows:
            if r['status']!='mapped':continue
            typ=r['type']&255;o=r['offset'];data=b[o:o+r['size']]
            if typ in (0x60,0x68):blocks[o]=apcb(data)
            if typ==0x66:
                require(len(data)>=32,'short patch')
                patches[o]={'equiv_id':u(data,24,2),'revision':u(data,4),'date_bcd':f'{u(data,0):08x}','size':len(data),'sha256':sha(data)}
    return {'directories':dirs,'apcb':blocks,'microcode':patches}

def main():
    p=argparse.ArgumentParser();p.add_argument('roms',nargs='+',type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args()
    results=[inspect(x.read_bytes()) for x in a.roms];a.output.write_text(json.dumps(results,indent=2)+'\n')
    for path,r in zip(a.roms,results):print(path.name,'directory entries',sum(map(len,r['directories'].values())),'APCB',len(r['apcb']),'patches',[(hex(x['equiv_id']),hex(x['revision']),x['date_bcd']) for x in r['microcode'].values()])
if __name__=='__main__':main()
