"""P1-P8 regression tests for v0.3.2. Original reviewer fixtures retained."""
import contextlib, copy, io, json, pathlib, tempfile, unittest
from unittest.mock import patch
import checker, pilot, handoff, replay_compare
from checker import Checker, Invalid, canonical, digest
from discovery import propose
from v03_fixtures import *
from test_v03_regression import receipt, handoff_ok

def pair(a,b):
    return pilot.evaluate({'a':a,'b':b},{'a':propose(a),'b':propose(b)})
def comp(r,tid,cid):
    return next(c for row in r['results'] if row['id']==tid for c in row['components'] if c['id']==cid)
def resync(r):
    for row in r['results']: comp(r,row['id'],'C1')['observed']=row['selection']
    r['summary']=pilot.summary(r)

class V032(unittest.TestCase):
    def test_aborted_evaluate_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            with patch.object(pilot,'evaluate',side_effect=Invalid('suffix_consistency')),contextlib.redirect_stdout(io.StringIO()):
                code=pilot.main(['--rom-a',str(p/'missing-a'),'--rom-b',str(p/'missing-b'),'--receipts',str(p/'rc')])
            self.assertEqual(code,2)
            path=next((p/'rc').iterdir()); r=checker.read_canonical(path.read_bytes())
            self.assertEqual(r['run_error'],{'stage':'evaluate','code':'suffix_consistency'})
            self.assertEqual(r['results'],[])
            self.assertEqual(handoff.validate(r)['execution'],'aborted')
            self.assertTrue(handoff_ok(r))
    def test_aborted_summary_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)
            with patch.object(pilot,'summary',side_effect=RuntimeError('private/path')),contextlib.redirect_stdout(io.StringIO()):
                code=pilot.main(['--rom-a',str(p/'a'),'--rom-b',str(p/'b'),'--receipts',str(p/'rc')])
            self.assertEqual(code,2)
            r=checker.read_canonical(next((p/'rc').iterdir()).read_bytes())
            self.assertEqual(r['run_error'],{'stage':'summary','code':'RuntimeError'})
            self.assertNotIn('private/path',str(r)); self.assertEqual(r['results'],[])
            self.assertEqual(handoff.validate(r)['exit_criterion'],'not_met')
    def test_localize_padding(self):
        a=fv([ffs(OTHER.bytes_le,1,b'odd'),target_file('SB-001',False)],gap_fill=0)
        r=pair(a,rom(True)); q=r['diagnostics']['a']
        self.assertEqual(q['error'],'ffs_padding')
        self.assertEqual(q['stream'],0); self.assertEqual(q['offset'],99)
        self.assertEqual(q['lineage'][0]['sha256'],digest(a))
    def test_localize_decompressed_section(self):
        f=ffs(GUIDS['SB-001'].bytes_le,2,stream(lzma_sec(b'\x03\x00\x00\x19')))
        a=fv([f]); q=pair(a,rom(True))['diagnostics']['a']
        self.assertEqual(q['error'],'section_size')
        self.assertEqual((q['stream'],q['offset']),(1,0))
        self.assertEqual(q['lineage'][1]['parent_stream'],0)
        self.assertEqual(q['lineage'][1]['output_size'],4)
    def test_full_subset_not_refuted(self):
        a=rom(False)
        def f(t): 
            p=bytearray(payload(t,False)); p[0]^=1; p[2]^=1
            return ffs(GUIDS[t].bytes_le,2,stream(sec(0x19,bytes(p))))
        r=pair(a,fv([f(t) for t in TARGETS],size=0x10000)); s=pilot.summary(r)
        self.assertEqual(s['exact_diff_set'],'conditional_refutation')
        self.assertEqual(s['historical_diff_scope'],'consistent_conditional')
        self.assertEqual(s['P2-47_full'],'partial_not_established')
    def test_new_header_hypothesis_not_historical_refutation(self):
        def f(t,new):
            p=bytearray(payload(t,new)); p[20:22]=(0x201).to_bytes(2,'little')
            return ffs(GUIDS[t].bytes_le,2,stream(sec(0x19,bytes(p))))
        r=pair(*[fv([f(t,new) for t in TARGETS],size=0x10000) for new in (False,True)])
        s=pilot.summary(r)
        self.assertEqual(s['historical_dwLength'],'consistent_conditional')
        self.assertEqual(s['P2-47_full'],'partial_not_established')
    def test_gate_exit_code(self):
        r=pair(rom(False),rom(True)); r['summary']=pilot.summary(r)
        self.assertEqual(r['summary']['differential_gate']['status'],'mismatch')
        self.assertEqual(pilot.exit_code(r),4)
        self.assertEqual(r['summary']['exit_criterion'],'not_met')
        for row in r['results']:
            for i,role in enumerate(('a','b')):
                row['selection'][role]['payload']['sha256']=pilot.REFERENCE_HASHES[row['id']][i]
        r['summary']=pilot.summary(r)
        self.assertEqual(r['summary']['exit_criterion'],'met')
        self.assertEqual(pilot.exit_code(r),0)
        del r['results'][0]['selection']['a']['payload']; r['summary']=pilot.summary(r)
        self.assertEqual(pilot.exit_code(r),2)
    def test_coordinated_diff_tamper(self):
        r=receipt(pair(rom(False),rom(True)))
        c=comp(r,'SB-001','C3'); c['observed']=[]; c['verdict']='FAIL'
        resync(r); self.assertFalse(handoff_ok(r))
    def test_raw_leaf_erasure(self):
        r=receipt(pair(rom(False),rom(True)))
        for role in ('a','b'):
            for s in [r['diagnostics'][role]]+[row['selection'][role] for row in r['results']]:
                s['uninterpreted_leaves']=[]; s['coverage']='grammar_complete'
        for row in r['results']:
            for c in row['components']:
                if c['assurance']=='conditional_coverage': c['assurance']='derived_in_supported_grammar'
        resync(r); self.assertFalse(handoff_ok(r))
    def test_certificate_tamper(self):
        r=receipt(pair(rom(False),rom(True))); self.assertTrue(handoff_ok(r))
        r['certificates']['a']['regions'][0]['size']-=8
        self.assertFalse(handoff_ok(r))
    def test_lineage_parent_bounds(self):
        r=receipt(pair(rom(False),rom(True)))
        q={'stream':1,'kind':'lzma_alone','parent_stream':1,'offset':0,'size':1,'output_size':1,'sha256':'0'*64}
        r['diagnostics']['a']['lineage'].append(q)
        for row in r['results']:
            # deepcopy makes this either a shared lineage or a separate one.
            l=row['selection']['a']['lineage']
            if len(l)==1: l.append(q)
        resync(r); self.assertFalse(handoff_ok(r))
    def test_coverage_distinction(self):
        r=pair(rom(False),rom(True))
        self.assertEqual(r['diagnostics']['a']['coverage'],'leaf_conditional')
        r=pair(rom(False)+b'opaque',rom(True))
        self.assertEqual(r['diagnostics']['a']['coverage'],'except_opaque')
    def test_replay_compare_no_promotion(self):
        a=receipt(pair(rom(False),rom(True))); b=copy.deepcopy(a)
        b.update(run_id='another',utc='2026-11-28T01:00:00+00:00',runtime='3.14')
        z=replay_compare.compare(a,b)
        self.assertTrue(z['normalized_equal']); self.assertFalse(z['same_run_id']); self.assertFalse(z['assurance_upgrade'])
        b['summary']['P2-47_full']='unverified'
        self.assertEqual(replay_compare.compare(a,b)['different_fields'],['summary'])

if __name__=='__main__': unittest.main()
