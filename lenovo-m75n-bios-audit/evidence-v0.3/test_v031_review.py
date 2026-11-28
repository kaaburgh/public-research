"""PR #5 defect inversions. Independent PI fixture builder from reviewer commit 3ae7117."""
import copy, pathlib, unittest, uuid, zlib
import checker, pilot, handoff, legacy_import
from checker import Checker, Invalid, canonical, digest
from discovery import propose
from v03_fixtures import *
from test_v03_regression import receipt, handoff_ok

def pair(a,b):
    return pilot.evaluate({'a':a,'b':b},{'a':propose(a),'b':propose(b)})

def component(r,tid,cid):
    return next(c for row in r['results'] if row['id']==tid for c in row['components'] if c['id']==cid)

class ReviewDefects(unittest.TestCase):
    def test_pad_hidden_compressed_copy(self):
        blob=zlib.compress(rom(True,tag=b'Q'))
        a=rom(False,[ffs(PAD_NAME,0xf0,blob)])
        r=pair(a,rom(True))
        self.assertIn('pad_file_data',[x['reason'] for x in r['diagnostics']['a']['issues']])
        self.assertEqual(component(r,'SB-001','C1')['verdict'],'BLOCKED')
    def test_pad_named_as_target_not_owner(self):
        a=rom(False,[ffs(GUIDS['SB-001'].bytes_le,0xf0,b'\xff'*32)])
        r=pair(a,rom(True))
        self.assertEqual(component(r,'SB-001','C1')['verdict'],'PASS')
        self.assertEqual(r['results'][0]['selection']['a']['counts']['data_valid'],1)
        self.assertEqual(r['diagnostics']['a']['pad_count'],1)
    def test_raw_file_leaf_conditional(self):
        a=rom(False,[ffs(OTHER.bytes_le,1,zlib.compress(rom(False,tag=b'Q')))])
        r=pair(a,rom(True))
        self.assertIn('raw_ffs_body',[x['kind'] for x in r['diagnostics']['a']['uninterpreted_leaves']])
        self.assertEqual(pilot.summary(r)['equal_structural_signature_lists'],'consistent_conditional')
    def test_opaque_inside_owner_blocks(self):
        def image(new):
            f=ffs(GUIDS['SB-001'].bytes_le,2,stream(sec(0x19,payload('SB-001',new)),crc32_sec(sec(0x19,b'second'))))
            return fv([f]+[target_file(t,new) for t in TARGETS if t!='SB-001'],size=0x10000)
        r=pair(image(False),image(True))
        self.assertEqual(component(r,'SB-001','C1')['verdict'],'BLOCKED')
        self.assertEqual(component(r,'SB-001','C1')['reason'],'opaque_in_owner')
        self.assertEqual(component(r,'SB-001','C6')['verdict'],'BLOCKED')
    def test_fv_extension_supported(self):
        a=rom(False,ext_name=OTHER.bytes_le); b=rom(True,ext_name=OTHER.bytes_le)
        r=pair(a,b)
        self.assertEqual(component(r,'SB-001','C1')['verdict'],'PASS')
        self.assertEqual(component(r,'SB-001','C6')['verdict'],'PASS')
        self.assertEqual(r['results'][0]['selection']['a']['owners'][0]['fv_name'],str(OTHER).upper())
    def test_fv_extension_bad_size(self):
        a=bytearray(rom(False,ext_name=OTHER.bytes_le)); a[0x70:0x74]=(19).to_bytes(4,'little')
        with self.assertRaises(Invalid): Checker(bytes(a),[TARGETS['SB-001'][0]]).run(propose(bytes(a)))
    def test_fv_extension_bad_pad(self):
        a=bytearray(rom(False,ext_name=OTHER.bytes_le)); a[72+18]=1
        a[72+16]=0; a[72+16]=(-(sum(a[72:96])-a[89]-a[95]))%256
        with self.assertRaises(Invalid): Checker(bytes(a),[TARGETS['SB-001'][0]]).run(propose(bytes(a)))
    def test_missing_multiplicity(self):
        r=pair(b'opaque-a',b'opaque-b')
        self.assertEqual(component(r,'SB-001','multiplicity')['verdict'],'BLOCKED')
        self.assertEqual(pilot.summary(r)['P2-47_full'],'not_evaluated')
    def test_empty_run_not_evaluated(self):
        r=pilot.evaluate({},{}); s=pilot.summary(r)
        self.assertEqual(s['P2-47_full'],'not_evaluated')
        self.assertEqual(s['timestamp_only_semantic_conclusion'],'not_evaluated')
        self.assertEqual(s['differential_gate']['status'],'not_evaluated')
    def test_refutation_summary(self):
        r=pair(rom(False),rom(True,tag=b'D')); s=pilot.summary(r)
        self.assertEqual(s['P2-47_full'],'conditional_refutation')
        self.assertEqual(s['timestamp_only_semantic_conclusion'],'conditional_refutation')
    def test_timestamp_subset_does_not_refute_semantics(self):
        r=pair(rom(False),rom(False)); s=pilot.summary(r)
        self.assertEqual(s['P2-47_full'],'conditional_refutation')
        self.assertEqual(s['timestamp_only_semantic_conclusion'],'partial_not_established')
    def test_differential_six(self):
        r=pair(rom(False),rom(True))
        self.assertEqual(pilot.differential(r)['status'],'mismatch')
        for row in r['results']:
            for i,role in enumerate(('a','b')):
                row['selection'][role]['payload']['sha256']=pilot.REFERENCE_HASHES[row['id']][i]
        self.assertEqual(pilot.differential(r)['status'],'all_six_match')
        del r['results'][0]['selection']['a']['payload']
        self.assertEqual(pilot.differential(r)['status'],'not_evaluated')
    def test_edited_verdict_duplicate_rejected(self):
        r=receipt(pair(rom(False),rom(True,[target_file('SB-001',True)])))
        self.assertTrue(handoff_ok(r))
        for cid in ('C1','multiplicity'):
            c=component(r,'SB-001',cid); c['verdict']='PASS'; c['reason']=None
        r['summary']=pilot.summary(r)
        self.assertFalse(handoff_ok(r))
    def test_edited_verdict_suffix_rejected(self):
        r=receipt(pair(rom(False),rom(True,tag=b'D')))
        self.assertTrue(handoff_ok(r))
        for row in r['results']:
            for c in row['components']:
                if c['verdict']=='FAIL': c['verdict']='PASS'; c['reason']=None
        r['summary']=pilot.summary(r)
        self.assertFalse(handoff_ok(r))
    def test_lineage_tamper_rejected(self):
        r=receipt(pair(rom(False),rom(True)))
        r['diagnostics']['a']['lineage'][0]['sha256']='0'*64
        self.assertFalse(handoff_ok(r))
    def test_deleted_container_body_reported(self):
        dead=ffs(OTHER.bytes_le,0x0b,stream(lzma_sec(sec(0x17,rom(False)))),state=DELETED)
        a=rom(False,[dead])
        r=pair(a,rom(True))
        self.assertTrue(r['diagnostics']['a']['deleted_uninterpreted'])
        self.assertEqual(component(r,'SB-001','C1')['verdict'],'PASS')
    def test_lowercase_guid(self):
        g=TARGETS['SB-001'][0]; a=rom(False)
        p,_,_=Checker(a,[g.lower()]).run(propose(a)).select(g.lower())
        self.assertEqual(p,payload('SB-001',False))
    def test_legacy_exact_lineage(self):
        p=pilot.PROFILE_PATH.with_name('historical')/'1983499b83c4049b85ef7a0295b1748e32e77129d89d21117ffb3bb1ffedf25d.json'
        r=checker.read_canonical(p.read_bytes()); r['version']='0.3.1-legacy-import'; r['summary']=legacy_import.legacy_summary(r['results'])
        self.assertEqual(handoff.validate(r)['legacy_byte_subset'],'consistent_conditional')
        r['results'][0]['selected_paths'][0]='changed'
        with self.assertRaises(Invalid): handoff.validate(r)
    def test_tripwire_budget(self):
        a=b'_FVH'* (checker.MAX_NODES+1)
        with self.assertRaises(Invalid): Checker(a,[TARGETS['SB-001'][0]]).run([{'offset':0,'size':len(a),'kind':'opaque'}])

if __name__=='__main__': unittest.main()
