import unittest, struct, lzma, uuid, zlib
from checker import *
from pilot import compare_pair, evaluate, summary, signature_lists, TARGETS
G=next(iter(TARGETS.values()))[0]; OTHER='11111111-2222-3333-4444-555555555555'

def section(t,b): return (len(b)+4).to_bytes(3,'little')+bytes([t])+b

def pack_sections(*xs):
    b=b''
    for x in xs: b+=bytes(-len(b)%4)+x
    return b

def ffs(g,body,state=7,pol=True,t=2):
    h=bytearray(uuid.UUID(g).bytes_le+b'\0\xaa'+bytes([t,0])+(len(body)+24).to_bytes(3,'little')+bytes([state^(255 if pol else 0)]));h[16]=(-(sum(h)-h[17]-h[23]))%256;return bytes(h)+body

def fv(*fs,pol=True,n=4096):
    h=bytearray(bytes(16)+FFS2+struct.pack('<Q',n)+b'_FVH'+struct.pack('<IHHHBB',0x800 if pol else 0,72,0,0,0,2)+struct.pack('<IIII',1,n,0,0));h[50:52]=((-sum(u(h,i,2) for i in range(0,72,2)))%65536).to_bytes(2,'little');b=bytes(h);fill=bytes([255 if pol else 0]);
    for f in fs: b+=fill*(-len(b)%8)+f
    assert len(b)<=n;return b+fill*(n-len(b))

def compressed(b): return section(2,LZMA+struct.pack('<HH',24,1)+lzma.compress(b,format=lzma.FORMAT_ALONE))

def payload(year=2025,month=1,day=2,hour=3,minute=4,second=5):
    t=struct.pack('<HBBBBBBIhBB',year,month,day,hour,minute,second,0,0,0,0,0)
    h=struct.pack('<IHH',24,0x200,0xef1)+PKCS7
    entry=bytes(16)+b'certificate';ls=X509+struct.pack('<III',28+len(entry),0,len(entry))+entry
    return t+h+ls

def target(b=None,state=7,pol=True): return ffs(G,section(0x19,payload() if b is None else b),state,pol)

def select(b,cert=None): return Checker(b,[G]).run(propose(b) if cert is None else cert).select(G)

def comps(rows): return {x['id']:x['verdict'] for x in rows}

class Tests(unittest.TestCase):
    def test_simple(self):
        b=fv(target());x,a,e=select(b);self.assertEqual(x,payload());self.assertEqual(a['selection'],'unique');self.assertIsNone(e)
    def test_nested_lzma(self):
        inner=fv(ffs(G,compressed(section(0x19,payload()))));outer=fv(ffs(OTHER,compressed(section(0x17,inner))))
        x,a,e=select(outer);self.assertEqual(x,payload());self.assertEqual(len(a['lineage']),3)
    def test_deleted(self):
        x,a,e=select(fv(target(),target(state=23)));self.assertEqual(a['counts']['deleted'],1);self.assertEqual(x,payload())
    def test_marked(self):
        x,a,e=select(fv(target(),target(state=15)));self.assertIsNone(x);self.assertEqual(a['counts']['marked_for_update'],1)
    def test_polarity_zero(self): self.assertEqual(select(fv(target(pol=False),pol=False))[0],payload())
    def test_duplicates_identical(self):
        x,a,e=select(fv(target())+fv(target()));self.assertEqual(x,payload());self.assertEqual(a['selection'],'equivalent_content_class')
    def test_duplicates_distinct(self): self.assertEqual(select(fv(target())+fv(target(b'other')))[2],'selection_ambiguous')
    def test_invalid_header(self):
        bad=bytearray(target());bad[16]^=1;x,a,e=select(fv(target(),bytes(bad)));self.assertIsNone(x);self.assertEqual(a['coverage'],'incomplete')
    def test_hidden_fv(self):
        b=fv(target())+fv(target());x,a,e=select(b,[{'offset':0,'size':4096,'kind':'fv'},{'offset':4096,'size':4096,'kind':'opaque'}]);self.assertIsNone(x);self.assertIn('untracked_fv',[i['reason'] for i in a['issues']])
    def test_hidden_compressed_conditional(self):
        b=fv(target())+zlib.compress(fv(target(b'other')));x,a,e=select(b);self.assertEqual(x,payload());self.assertEqual(a['coverage'],'except_opaque')
    def test_overlap(self):
        b=fv(target());with_cert=[{'offset':0,'size':4096,'kind':'fv'},{'offset':1,'size':1,'kind':'opaque'}]
        with self.assertRaises(Invalid): select(b,with_cert)
    def test_erased_lie(self):
        with self.assertRaises(Invalid): select(fv(target()),[{'offset':0,'size':4096,'kind':'erased'}])
    def test_nested_owner(self):
        b=fv(ffs(G,section(0x17,fv(ffs(OTHER,section(0x19,b'wrong'))))),n=8192);x,a,e=select(b);self.assertIsNone(x);self.assertEqual(a['counts']['raw_per_live'],[0])
    def test_two_raw(self): self.assertIsNone(select(fv(ffs(G,pack_sections(section(0x19,b'a'),section(0x19,b'b')))))[0])
    def test_unknown_compression(self):
        b=fv(target(),ffs(OTHER,section(1,struct.pack('<IB',8,1)+b'unknown')));x,a,e=select(b);self.assertEqual(a['coverage'],'except_opaque')
    def test_untracked_in_raw(self):
        hidden=fv(target());outer=fv(target(b'prefix'+target(b'other')));x,a,e=select(outer);self.assertIsNone(x);self.assertIn('untracked_ffs_candidate',[i['reason'] for i in a['issues']])
    def test_canonical(self):
        self.assertEqual(read_canonical(canonical({'a':1})),{'a':1})
        for x in (b'{"a":1,"a":1}\n',b'{"a":1.0}\n',b'{"a":-0}\n',b'{"a":1}',b'{"a":"\\u0061"}\n'):
            with self.assertRaises(Invalid): read_canonical(x)
    def test_structural_components(self):
        a,b=payload(),payload(2026,2,3,4,5,6);x=comps(compare_pair(a,b,len(a),1,'derived_in_supported_grammar'))
        self.assertEqual(x['C5'],'PASS');self.assertEqual(x['C6'],'PASS');self.assertEqual(x['C7'],'PASS');self.assertEqual(x['C8'],'PASS');self.assertEqual(x['C4'],'OPEN')
    def test_malformed_tail(self): self.assertIsNone(signature_lists(payload()+b'junk'))
    def test_length_refutes_diff(self): self.assertEqual(comps(compare_pair(b'a',b'ab',1,1,'derived_in_supported_grammar'))['C3'],'FAIL')
    def test_diff_limit_refutes(self): self.assertEqual(comps(compare_pair(bytes(5000),b'x'*5000,5000,1,'derived_in_supported_grammar'))['C3'],'FAIL')
    def test_multiplicity_and_summary(self):
        a=fv(target());b=fv(target())+fv(target());r=evaluate({'a':a,'b':b},{'a':propose(a),'b':propose(b)},{'X':(G,len(payload()),1)});c=comps(r['results'][0]['components']);self.assertEqual(c['C1'],'FAIL');self.assertEqual(c['multiplicity'],'FAIL');self.assertEqual(c['C6'],'PASS');self.assertEqual(summary(r)['equal_structural_signature_lists'],'refuted_within_supported_grammar')
    def test_conditional_summary(self):
        a=fv(target())+b'opaque';b=fv(target())+b'opaque2';r=evaluate({'a':a,'b':b},{'a':propose(a),'b':propose(b)},{'X':(G,len(payload()),1)});self.assertEqual(summary(r)['equal_structural_signature_lists'],'consistent_conditional');self.assertEqual(summary(r)['P2-47_full'],'partial_not_established')
    def test_missing_role(self):
        a=fv(target());r=evaluate({'a':a},{'a':propose(a)},{'X':(G,len(payload()),1)});self.assertEqual(comps(r['results'][0]['components'])['C2'],'BLOCKED');self.assertEqual(r['diagnostics']['b']['error'],'rom_missing')

if __name__=='__main__': unittest.main(verbosity=2)
