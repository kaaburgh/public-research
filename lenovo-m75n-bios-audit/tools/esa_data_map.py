#!/usr/bin/env python3
"""Partial EsaFull data correspondence. Requires matching objdump -d -M intel --no-show-raw-insn .asm files. Not PE equivalence."""
import sys, re, struct, collections, bisect
from pathlib import Path
import numpy as np
U=collections.defaultdict
class Image:
 def __init__(self,p):
  self.b=Path(p).read_bytes(); b=self.b; pe=struct.unpack_from('<I',b,60)[0]; n=struct.unpack_from('<H',b,pe+6)[0]; off=pe+24+struct.unpack_from('<H',b,pe+20)[0]
  self.sec={}
  for i in range(n):
   o=off+40*i; name=b[o:o+8].rstrip(b'\0').decode(); vs,va,rs,rp=struct.unpack_from('<IIII',b,o+8); assert va==rp; self.sec[name]=(va,va+vs)
  start,end=self.sec['.reloc']; self.rel={};o=start
  while o<end:
   pg,n=struct.unpack_from('<II',b,o); assert n>=8 and o+n<=end
   for k in range(o+8,o+n,2):
    x=struct.unpack_from('<H',b,k)[0]; typ=x>>12; adr=pg+(x&4095)
    if typ: assert typ==10 and adr not in self.rel; self.rel[adr]=struct.unpack_from('<Q',b,adr)[0]
   o+=n
  start,end=self.sec['.text']; self.ins={}; self.refs={}; self.br={}; self.pieces=U(list)
  for line in Path(str(p)+'.asm').read_text().splitlines():
   m=re.match(r'\s*([0-9a-f]+):\s+(.*)',line)
   if not m:continue
   a=int(m[1],16); t=m[2].strip()
   if not start<=a<end:continue
   z=re.search(r'# 0x([0-9a-f]+)',t)
   if z:self.refs[a]=int(z[1],16)
   z=re.match(r'^(?:call|j\w+|loop\w*)\s+0x([0-9a-f]+)$',t)
   if z:self.br[a]=int(z[1],16)
   self.ins[a]=t
  bounds={start};bounds.update(v for v in self.rel.values() if start<=v<end);bounds.update(v for a,v in self.br.items() if self.ins[a].startswith('call') and start<=v<end)
  piece=[]
  def flush():
   if piece:
    ts=tuple(self.norm(a) for a in piece)
    self.pieces[ts].append(tuple(piece));piece.clear()
  for a,t in self.ins.items():
   if a in bounds or t.startswith('int3'):flush()
   if not t.startswith('int3'):piece.append(a)
  flush()
  self.data0,self.data1=self.sec['.data'];self.arr=np.array(list(b[self.data0:self.data1]),dtype=np.int16)
  for a in self.rel:
   if self.data0<=a<self.data1:self.arr[a-self.data0:a-self.data0+8]=np.arange(256,264,dtype=np.int16)
 def norm(self,a):
  t=self.ins[a]
  if a in self.br:return re.sub(r'0x[0-9a-f]+$','TARGET',t)
  if a in self.refs:return re.sub(r'\[rip[+-]0x[0-9a-f]+\]','[rip+TARGET]',t.split('#')[0]).strip()
  return t
A,B=map(Image,sys.argv[1:3]); print('pieces',sum(map(len,A.pieces.values())),sum(map(len,B.pieces.values())),flush=True)
code={}; n=0
for k,x in A.pieces.items():
 y=B.pieces.get(k,[])
 if len(x)==len(y)==1:
  assert len(x[0])==len(y[0]); code.update(zip(x[0],y[0]));n+=1
print('unique code pieces',n,'instructions',len(code),flush=True)
bad=set()
for a,b in code.items():
 if a in A.br and b in B.br and A.br[a] in code and code[A.br[a]]!=B.br[b]:bad.add(a)
for k,x in A.pieces.items():
 if len(x)==1 and any(a in bad for a in x[0]):
  for a in x[0]:code.pop(a,None)
print('bad branch instructions',len(bad),'remaining mapped',len(code),flush=True)
refs=U(collections.Counter); inv=U(collections.Counter)
for a,b in code.items():
 x=A.refs.get(a,-1);y=B.refs.get(b,-1)
 if A.data0<=x<A.data1 and B.data0<=y<B.data1:refs[x][y]+=1;inv[y][x]+=1
anchors={x:next(iter(ys)) for x,ys in refs.items() if len(ys)==1 and len(inv[next(iter(ys))])==1}
print('RIP anchors',len(refs),len(anchors),'conflicts',len(refs)-len(anchors),'references',sum(sum(v.values()) for v in refs.values()),flush=True)
groups=U(list)
for x,y in anchors.items():groups[y-x].append(x)
intervals=[]
for d,xs in groups.items():
 lo=max(A.data0,B.data0-d);hi=min(A.data1,B.data1-d)
 eq=A.arr[lo-A.data0:hi-A.data0]==B.arr[lo+d-B.data0:hi+d-B.data0]
 edges=np.flatnonzero(np.diff(np.r_[False,eq,False]));starts=(edges[0::2]+lo).tolist();ends=(edges[1::2]+lo).tolist()
 seen=set()
 for x in xs:
  i=bisect.bisect_right(starts,x)-1
  if i<0 or x>=ends[i] or i in seen:continue
  seen.add(i);l,r=starts[i],ends[i]
  if r-l<16 or not np.any(A.arr[l-A.data0:r-A.data0]):continue
  intervals.append((l,r,d))
print('candidate intervals',len(intervals),flush=True)
oldcnt=np.zeros(A.data1-A.data0,dtype=np.int16);newcnt=np.zeros(B.data1-B.data0,dtype=np.int16)
for l,r,d in intervals:oldcnt[l-A.data0:r-A.data0]+=1;newcnt[l+d-B.data0:r+d-B.data0]+=1
m=np.full(len(oldcnt),-1,dtype=np.int64); nmap=np.full(len(newcnt),-1,dtype=np.int64)
for l,r,d in intervals:
 ok=(oldcnt[l-A.data0:r-A.data0]==1)&(newcnt[l+d-B.data0:r+d-B.data0]==1)
 ix=np.flatnonzero(ok)+l;m[ix-A.data0]=ix+d;nmap[ix+d-B.data0]=ix
def datamap(x):return int(m[x-A.data0]) if A.data0<=x<A.data1 else -1
reloc_mapped=0; targetok=collections.Counter(); unresolved=[];contradictions=[]
for x,t in A.rel.items():
 y=datamap(x)
 if y<0 or datamap(x+7)!=y+7 or y not in B.rel:continue
 reloc_mapped+=1;w=B.rel[y];target=code.get(t,anchors.get(t,datamap(t)))
 if target in (-1,None):targetok['unknown']+=1;unresolved.append((x,y,t,w))
 elif target==w:targetok['confirmed']+=1
 else:targetok['contradiction']+=1;contradictions.append((x,y,t,w,target))
print('mapped bytes',int(np.sum(m>=0)),'/',len(m),'ambiguous old bytes',int(np.sum(oldcnt>1)),flush=True)
print('data relocs total',sum(A.data0<=x<A.data1 for x in A.rel),'mapped slots',reloc_mapped,'targets',dict(targetok),flush=True)
print('contradictions',[[hex(x) for x in r] for r in contradictions],flush=True)
def section(img,x):return next((k for k,(l,r) in img.sec.items() if l<=x<r),'outside')
print('unknown target sections',collections.Counter((section(A,t),section(B,w)) for x,y,t,w in unresolved))
neededA={t for x,y,t,w in unresolved if section(A,t)=='.text'};neededB={w for x,y,t,w in unresolved if section(B,w)=='.text'}
def fingerprints(img,needed):
 out={}
 for k,ps in img.pieces.items():
  for p in ps:
   for i,a in enumerate(p):
    if a in needed:out[a]=(k,i)
 return out
fa,fb=fingerprints(A,neededA),fingerprints(B,neededB)
counts=collections.Counter()
for x,y,t,w in unresolved:
 if section(A,t)!='.text':continue
 if t in fa and w in fb and fa[t]==fb[w]:counts['same normalized piece and index']+=1
 else:counts['not matched']+=1
print('extra code target fingerprint comparison',dict(counts))
def run_info(img):
 need=set(img.rel.values());fp=fingerprints(img,need)
 bysig=U(list); allruns=[]; rel=sorted(x for x in img.rel if img.data0<=x<img.data1); starts=[];p=[]
 for x in rel:
  if p and x!=p[-1]+8:starts.append(p);p=[]
  p.append(x)
 if p:starts.append(p)
 for r in starts:
  if len(r)<3:continue
  sig=[]
  for x in r:
   t=img.rel[x]
   if t in fp:sig.append(('C',fp[t]))
   elif img.sec['.text'][0]<=t<img.sec['.text'][1]:sig.append(('?',))
   elif img.data0<=t<img.data1:
    v=img.arr[t-img.data0:t-img.data0+16]
    sig.append(('D',tuple(v)) if len(v)==16 and np.all(v<256) and np.any(v) else ('?',))
   else:sig.append(('?',))
  if sum(s!=('?',) for s in sig)<max(3,len(sig)//2):continue
  bysig[tuple(sig)].append(r);allruns.append(r)
 return bysig,allruns
ra,ar=run_info(A); rb,br=run_info(B)
runmap={};runstats=collections.Counter();contr=[]
for k,rs in ra.items():
 ss=rb.get(k,[])
 if len(rs)==len(ss)==1:
  runstats['runs']+=1
  for x,y,s in zip(rs[0],ss[0],k):
   runmap[x]=y;runstats['slots']+=1
   if s!=('?',):runstats['informative targets']+=1
   if datamap(x)==y:runstats['agrees with byte map']+=1
   elif datamap(x)>=0:runstats['differs from byte map']+=1;contr.append((x,y,datamap(x)))
   else:runstats['new slots']+=1
print('vtable-like run counts',len(ar),len(br),'independent unique normalized run matches',dict(runstats))
independent=collections.Counter(); bytepairs={}
for x,t in A.rel.items():
 y=datamap(x)
 if y<0 or datamap(x+7)!=y+7 or y not in B.rel:continue
 bytepairs[x]=y;w=B.rel[y];target=code.get(t,anchors.get(t,datamap(t)))
 if target==w:independent['confirmed code' if t in code else 'confirmed RIP anchor' if t in anchors else 'consistent masked range']+=1
print('byte target breakdown',dict(independent))
for x,y,z in contr:
 print('run corrections',hex(x),hex(A.rel[x]),hex(y),hex(B.rel[y]),'rejected',hex(z),hex(B.rel[z]))
print('union old slots proposed',len(set(bytepairs)|set(runmap)),'unmatched',5832-len(set(bytepairs)|set(runmap)))
