"""v0.3.3 restricted PI derivation checker. No firmware execution. Python 3.10+ stdlib."""
import hashlib, json, lzma, struct, uuid

FFS2 = uuid.UUID('8c8ce578-8a3d-4f1c-9935-896185c32dd3').bytes_le
LZMA = uuid.UUID('ee4e5898-3914-4259-9d6e-dc7bd79403cf').bytes_le
PKCS7 = uuid.UUID('4aafd29d-68df-49ee-8aa9-347d375665a7').bytes_le
X509 = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le
MAX_BYTES = 64 * 1024**2
MAX_NODES = 100000
MAX_DEPTH = 16

class Invalid(ValueError):
    """Stable code; optional parser coordinates, never host paths."""
    location=None
    def diagnostic(self):
        return {'error':str(self),**(self.location or {})}

def need(ok, code):
    if not ok: raise Invalid(code)

def digest(b): return hashlib.sha256(b).hexdigest()
def canonical(x):
    def validate(v, d=0):
        need(d <= 32, 'json_depth')
        if v is None or type(v) is bool: return
        if type(v) is int: need(0 <= v < 2**53, 'json_integer'); return
        if type(v) is str: need(0 < len(v) <= 4096 and all(32 <= ord(c) <= 126 for c in v), 'json_string'); return
        if type(v) is list:
            for i in v: validate(i, d+1)
            return
        need(type(v) is dict, 'json_type')
        for k, i in v.items(): validate(k, d+1); validate(i, d+1)
    validate(x)
    return (json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode('ascii')

def read_canonical(b):
    need(len(b) <= 8*1024**2, 'json_size')
    try: x = json.loads(b)
    except (ValueError, RecursionError) as e: raise Invalid('json_parse') from e
    need(canonical(x) == b, 'json_not_canonical')
    return x

def u(b, o, n):
    need(type(o) is int and 0 <= o <= len(b)-n, 'bounds')
    return int.from_bytes(b[o:o+n], 'little')

def align(n, k): return (n+k-1)//k*k

def guid(b): return str(uuid.UUID(bytes_le=bytes(b))).upper()

def header(buf, off, polarity):
    need(off % 8 == 0 and off+24 <= len(buf), 'ffs_bounds_alignment')
    h=buf[off:off+24]; size=u(h,20,3); attr=h[19]
    need(not attr&1 and size != 0xffffff, 'ffs_large_unsupported')
    need(24 <= size <= len(buf)-off, 'ffs_size')
    need((sum(h)-h[17]-h[23])%256 == 0, 'ffs_header_checksum')
    state=h[23] ^ (255 if polarity else 0)
    need(not state&0xc0 and state&3 == 3, 'ffs_state')
    highest=1 << (state.bit_length()-1)
    need(highest in (4,8,16) and state&4, 'ffs_state')
    body=buf[off+24:off+size]
    if highest != 16:
        need((sum(body)+h[17])%256==0 if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')
    return guid(h[:16]),h[18],size,{4:'data_valid',8:'marked_for_update',16:'deleted'}[highest]

class Checker:
    """Certificate only proposes top-level partition; checker walks supported grammar itself."""
    def __init__(self, rom, targets):
        need(len(rom)<=MAX_BYTES, 'rom_limit')
        self.rom=rom; self.targets={str(uuid.UUID(g)).upper() for g in targets}; self.owners={g:[] for g in self.targets}
        self.streams=[rom]; self.lineage=[{"stream":0,"kind":"artifact","sha256":digest(rom),"size":len(rom)}]; self.tracked_fv=set(); self.tracked_ffs=set(); self.opaque=[]; self.issues=[]; self.leaves=[]; self.deleted_leaves=[]; self.pad_count=0; self.nodes=0; self.scan_candidates=0; self.scan_work=0; self.expanded=len(rom); self.position={'stage':'root','stream':0,'offset':0}
    def at(self,stage,s,o):
        self.position={'stage':stage,'stream':s,'offset':o}
    def tick(self, depth):
        self.nodes+=1; need(self.nodes<=MAX_NODES and depth<=MAX_DEPTH,'resource_limit')
    def unknown(self,s,o,n,code,owner=None):
        need(len(self.opaque)+len(self.issues)<MAX_NODES,"diagnostics_limit")
        row={'stream':s,'offset':o,'size':n,'reason':code}; self.opaque.append(row)
        if owner is not None: owner['opaque'].append(row)
    def leaf(self,s,o,n,kind,deleted=False):
        need(len(self.leaves)+len(self.deleted_leaves)<MAX_NODES,'leaf_limit')
        (self.deleted_leaves if deleted else self.leaves).append({'stream':s,'offset':o,'size':n,'kind':kind})
    def coverage(self):
        return 'incomplete' if self.issues else 'except_opaque' if self.opaque else 'leaf_conditional' if self.leaves else 'grammar_complete'
    def issue(self,s,o,code):
        need(len(self.opaque)+len(self.issues)<MAX_NODES,"diagnostics_limit")
        self.issues.append({'stream':s,'offset':o,'reason':code})
    def fv(self,s,off,n,depth):
        self.at('fv_header',s,off); self.tick(depth); b=self.streams[s]; self.tracked_fv.add((s,off))
        need(n>=72 and off+n<=len(b) and b[off+40:off+44]==b'_FVH','fv_header')
        f=b[off:off+n]; hl=u(f,48,2)
        need(u(f,32,8)==n and 72<=hl<=n and hl%2==0 and sum(u(f,i,2) for i in range(0,hl,2))%65536==0,'fv_length_checksum')
        if f[16:32]!=FFS2 or f[55]!=2:
            self.unknown(s,off,n,'unsupported_fv'); return
        total=0; end=False
        for p in range(56,hl-7,8):
            self.at('fv_blockmap',s,off+p); count,bs=u(f,p,4),u(f,p+4,4)
            if count==bs==0: end=True; break
            need(count>0 and bs>0,'fv_blockmap'); total+=count*bs
        need(end and total==n,'fv_blockmap')
        if any(f[p+8:hl]): self.unknown(s,off,n,'unsupported_fv_header_tail'); return
        pol=bool(u(f,44,4)&0x800); erase=255 if pol else 0; pos=hl
        ext=u(f,52,2); ext_end=0; ext_seen=False; fv_name=None
        if ext:
            self.at('fv_ext_pointer',s,off+52)
            need(ext%4==0 and align(hl,8)+24<=ext<=n-20,'fv_ext_bounds')
            self.at('fv_ext_size',s,off+ext+16); ext_size=u(f,ext+16,4); need(20<=ext_size<=n-ext,'fv_ext_size')
            if ext_size!=20:
                self.unknown(s,off,n,'unsupported_fv_ext_entries'); return
            ext_end=ext+ext_size; fv_name=guid(f[ext:ext+16])
        while pos<n:
            self.at('ffs_padding',s,off+pos); self.tick(depth); a=align(pos,8)
            if a>n: a=n
            need(all(x==erase for x in f[pos:a]),'ffs_padding'); pos=a
            if pos==n or (all(x==erase for x in f[pos:pos+24]) and all(x==erase for x in f[pos:])): break
            self.at('ffs_header',s,off+pos)
            try: g,t,z,state=header(f,pos,pol)
            except Invalid as e:
                self.issue(s,off+pos,str(e)); self.unknown(s,off+pos,n-pos,'unparsed_ffs_tail'); return
            self.tracked_ffs.add((s,off+pos)); owner=None
            body_start=pos+24; body_end=pos+z
            if ext and pos==align(hl,8):
                need(t==0xf0 and state=='data_valid' and body_start<=ext<ext_end<=body_end,'fv_ext_not_in_leading_pad')
                ext_seen=True
            if t==0xf0:
                self.pad_count+=1
                if ext and pos==align(hl,8):
                    bad=any(x!=erase for x in f[body_start:ext]) or any(x!=erase for x in f[ext_end:body_end])
                else: bad=any(x!=erase for x in f[body_start:body_end])
                if bad:
                    self.issue(s,off+body_start,'pad_file_data')
                    self.unknown(s,off+body_start,z-24,'pad_file_data')
            else:
                if g in self.targets:
                    owner={'stream':s,'offset':off+pos,'fv_offset':off,'fv_name':fv_name,'state':state,'raw':[],'opaque':[]}; self.owners[g].append(owner)
                if state=='deleted':
                    self.leaf(s,off+body_start,z-24,'deleted_ffs_body',deleted=True)
                elif 2<=t<=15: self.sections(s,off+body_start,z-24,owner,depth+1)
                elif t==1: self.leaf(s,off+body_start,z-24,'raw_ffs_body')
                else: self.unknown(s,off+body_start,z-24,'unsupported_ffs_type',owner)
            pos+=z
        self.at('fv_ext_completion',s,off)
        if ext: need(ext_seen,'fv_ext_missing_pad')
    def sections(self,s,off,n,owner,depth):
        self.at('sections',s,off); self.tick(depth); b=self.streams[s]; pos=0
        while pos<n:
            self.at('section_padding',s,off+pos); self.tick(depth); a=align(pos,4)
            need(a<=n and all(x==0 for x in b[off+pos:off+a]),'section_padding'); pos=a
            if pos==n: break
            o=off+pos; self.at('section_header',s,o); need(n-pos>=4,'section_header'); z=u(b,o,3); t=b[o+3]
            if z==0xffffff:
                self.unknown(s,o,n-pos,'extended_section_unsupported',owner); return
            need(4<=z<=n-pos,'section_size'); body=b[o+4:o+z]
            if t==0x19:
                self.leaf(s,o+4,len(body),'raw_section')
                if owner is not None: owner['raw'].append({'stream':s,'offset':o+4,'size':len(body),'bytes':body})
            elif t==0x17:
                before=len(self.opaque); self.fv(s,o+4,len(body),depth+1)
                if owner is not None: owner['opaque'].extend(self.opaque[before:])
            elif t==2:
                self.at('guided_header',s,o); need(len(body)>=20,'guided_header'); start=u(body,16,2)
                need(24<=start<=z,'guided_offset')
                if body[:16]==LZMA:
                    self.at('lzma_input',s,o+start); remaining=MAX_BYTES-self.expanded
                    need(remaining>0,'expansion_budget')
                    try:
                        dec=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE,memlimit=MAX_BYTES)
                        data=dec.decompress(b[o+start:o+z],max_length=remaining+1)
                    except lzma.LZMAError as e: raise Invalid('lzma_invalid_or_limit') from e
                    need(len(data)<=remaining and dec.eof and not dec.unused_data,'lzma_bounds_or_trailing')
                    self.expanded+=len(data); k=len(self.streams); self.streams.append(data)
                    self.lineage.append({"stream":k,"kind":"lzma_alone","parent_stream":s,"offset":o+start,"size":z-start,"output_size":len(data),"sha256":digest(data)})
                    self.sections(k,0,len(data),owner,depth+1)
                else: self.unknown(s,o,z,'unsupported_guided_section',owner)
            elif t==1:
                self.at('compression_header',s,o); need(len(body)>=5,'compression_header')
                if body[4]==0:
                    need(u(body,0,4)==len(body)-5,'compression_size'); self.sections(s,o+9,len(body)-5,owner,depth+1)
                else: self.unknown(s,o,z,'unsupported_compression',owner)
            elif t not in (0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x18,0x1b,0x1c): self.unknown(s,o,z,'unknown_section_type',owner)
            else: self.leaf(s,o+4,len(body),'section_%02x'%t)
            pos+=z
    def scan(self):
        # Negative evidence only relative to supported grammar; a signature scan is a tripwire, not a proof of absence.
        for s,b in enumerate(self.streams):
            start=0
            while (j:=b.find(b'_FVH',start))>=0:
                self.at('tripwire_fv',s,j); self.scan_candidates+=1; need(self.scan_candidates<=MAX_NODES,'tripwire_limit')
                start=j+1; o=j-40
                if o>=0 and (s,o) not in self.tracked_fv and o+56<=len(b):
                    length=u(b,o+32,8); hl=u(b,o+48,2)
                    if 56<=hl<=length<=len(b)-o and hl%2==0:
                        self.scan_work+=hl; need(self.scan_work<=MAX_BYTES,'tripwire_checksum_budget')
                        if sum(u(b,i,2) for i in range(o,o+hl,2))%65536==0: self.issue(s,o,'untracked_fv')
            for g in sorted(self.targets):
                pat=uuid.UUID(g).bytes_le; start=0
                while (j:=b.find(pat,start))>=0:
                    self.at('tripwire_ffs',s,j); self.scan_candidates+=1; need(self.scan_candidates<=MAX_NODES,'tripwire_limit')
                    start=j+1
                    if (s,j) in self.tracked_ffs or j+24>len(b): continue
                    h=b[j:j+24]; z=u(h,20,3)
                    if (24<=z<=len(b)-j or h[19]&1):
                        if (sum(h)-h[17]-h[23])%256==0: self.issue(s,j,'untracked_ffs_candidate')
                        elif 1<=h[18]<=15 and any((h[23]^p)&0x3f in (3,7,15,23,31,32,63) for p in (0,255)): self.issue(s,j,'unresolved_ffs_candidate')
    def run(self,regions):
        try: return self._run(regions)
        except Invalid as e:
            e.location={**self.position,'lineage':self.lineage.copy()}
            raise
        except Exception as e:
            # Implementation failure, not evidence that input bytes are invalid.
            name=type(e).__name__
            if not name.isascii() or not name.replace('_','').isalnum(): name='Exception'
            failure=Invalid('internal_'+name)
            failure.location={**self.position,'lineage':self.lineage.copy(),'error_kind':'internal_checker_error'}
            raise failure from None
    def _run(self, regions):
        self.at('root_partition',0,0)
        need(type(regions) is list and len(regions)<=MAX_NODES,'regions')
        pos=0
        for r in regions:
            self.at('root_partition',0,pos)
            need(type(r) is dict and set(r)=={'offset','size','kind'},'region_fields')
            o,n,k=r['offset'],r['size'],r['kind']; need(type(o) is int and type(n) is int and o==pos and 0<n<=len(self.rom)-o,'region_partition')
            if k=='fv': self.fv(0,o,n,0)
            elif k=='opaque': self.unknown(0,o,n,'unparsed_root')
            elif k=='erased': need(all(x==255 for x in self.rom[o:o+n]) or all(x==0 for x in self.rom[o:o+n]),'not_erased')
            else: raise Invalid('region_kind')
            pos+=n
        self.at('root_partition',0,pos)
        need(pos==len(self.rom),'region_partition'); self.scan(); return self
    def select(self,g):
        g=str(uuid.UUID(g)).upper(); owners=self.owners[g]; live=[o for o in owners if o['state']=='data_valid']; marked=[o for o in owners if o['state']=='marked_for_update']
        counts={'data_valid':len(live),'deleted':sum(o['state']=='deleted' for o in owners),'marked_for_update':len(marked),'raw_per_live':[len(o['raw']) for o in live]}
        assurance={'derivation':'verified','scope':'supported_PI_grammar','coverage':self.coverage(),'issues':self.issues,'opaque':self.opaque,'uninterpreted_leaves':self.leaves,'deleted_uninterpreted':self.deleted_leaves,'pad_count':self.pad_count,'counts':counts,'lineage':self.lineage,'owners':[{**{k:v for k,v in o.items() if k!='raw'},'raw':[{**{k:v for k,v in q.items() if k!='bytes'},'sha256':digest(q['bytes'])} for q in o['raw']]} for o in owners]}
        if self.issues or marked or not live or any(len(o['raw'])!=1 for o in live): return None,assurance,'selection_unresolved'
        if any(o['opaque'] for o in live): return None,assurance,'opaque_in_owner'
        payloads=[o['raw'][0]['bytes'] for o in live]
        if any(x!=payloads[0] for x in payloads[1:]): return None,assurance,'selection_ambiguous'
        assurance['selection']='unique' if len(live)==1 else 'equivalent_content_class'
        assurance['locators']=[{k:v for k,v in o['raw'][0].items() if k!='bytes'} for o in live]
        return payloads[0],assurance,None

