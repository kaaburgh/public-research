"""Review mutants for code new in v0.3.2 (PR #8, 0cbac26f), complementing the 106 in mutation_v032.py. Runner copied from mutation_v032.py.
Usage: python3 mutation_v032_review.py <evidence-v0.3> <v1> <935daa0> [--extra test_v032_addendum]"""

import os, pathlib, re, shutil, subprocess, sys, tempfile

SRC, V1, IR = (pathlib.Path(p).resolve() for p in sys.argv[1:4])
EXTRA = sys.argv[sys.argv.index('--extra') + 1] if '--extra' in sys.argv else None
HERE = pathlib.Path(__file__).resolve().parent
AUTHOR = ('test_pilot', 'test_v03_regression', 'test_v031_review','test_v031_addendum','test_v032')
M = [
 ('x01','pilot.py',"r['results']=[]; r['diagnostics']={}","pass",'aborted receipt drops partial results'),
 ('x02','pilot.py',"        r['certificates']={}\n","        pass\n",'aborted receipt drops certificates (keeps digests)'),
 ('x03','pilot.py',"code=str(e) if isinstance(e,Invalid) and str(e).isascii() and str(e).replace('_','').isalnum() else type(e).__name__","code=str(e)",'aborted code sanitisation'),
 ('x04','pilot.py',"'execution':'aborted'","'execution':'completed'",'aborted summary marks execution'),
 ('x05','pilot.py',"stage='summary'; r['summary']=summary(r)","r['summary']=summary(r)",'stage recorded for summary'),
 ('x06','pilot.py',"stage='receipt_encoding'; need(len(canonical(r))<=8*1024**2,'receipt_size')","stage='receipt_encoding'",'oversize receipt aborted'),
 ('x07','pilot.py',"clause('historical_diff_scope',scope and bool(d),d)","clause('historical_diff_scope',scope,d)",'historical change-occurrence clause'),
 ('x08','pilot.py',"clause('timestamp_only_bytes',isinstance(d,list) and all(i<16 for i in d),d)","clause('timestamp_only_bytes',isinstance(d,list) and all(i<40 for i in d),d)",'timestamp_only_bytes bound 16'),
 ('x09','pilot.py',"x['dwLength']==24 for x in hs","x['dwLength']>0 for x in hs",'historical dwLength = 24'),
 ('x10','pilot.py',"all(q['type']==x509 for q in z) and ","",'historical X509 type'),
 ('x11','pilot.py',"sum(q['entries'] for q in z)==expected for z in ls","True for z in ls",'historical X509 count'),
 ('x12','pilot.py',"if state(rows,['C1']) not in ('consistent_conditional','derived_within_supported_grammar'):","if False:",'C1 prerequisite for P2-47_full'),
 ('x13','pilot.py',"'historical_dwLength','C6','C7','historical_x509_count','C4']","'historical_dwLength','C7','historical_x509_count','C4']",'C6 in P2-47_full'),
 ('x14','pilot.py',"historical_ids=['C2','historical_diff_bound',","historical_ids=['C2',",'historical bound in P2-47_full'),
 ('x15','pilot.py',"'historical_x509_count','C4']","'historical_x509_count']",'OPEN C4 keeps P2-47_full unestablished'),
 ('x16','pilot.py',"'exit_criterion':'met' if complete and gate['status']=='all_six_match' else 'not_met'","'exit_criterion':'met' if gate['status']=='all_six_match' else 'not_met'",'exit criterion requires completeness'),
 ('x17','pilot.py',"if 'FAIL' in states: return 1","if 'FAIL' in states: return 2",'exit 1 on refutation'),
 ('x18','pilot.py',"return 2 if 'BLOCKED' in states or r['summary']['exit_criterion']!='met' else 0","return 0",'exit 2 on BLOCKED'),
 ('x19','pilot.py',"if 'run_error' in r: return 2","if 'run_error' in r: return 0",'exit_code on aborted receipt (main never calls it)'),
 ('x21','checker.py',"self.at('lzma_input',s,o+start); remaining","remaining",'LZMA failure located at the LZMA input'),
 ('x22','checker.py',"'lineage':self.lineage.copy()","'lineage':[]",'lineage attached to structural failure'),
 ('x23','checker.py',"o=off+pos; self.at('section_header',s,o);","o=off+pos;",'stage section_header'),
 ('x24','checker.py',"            self.at('ffs_header',s,off+pos)\n","            pass\n",'stage ffs_header'),
 ('x26','verdicts.py',"need([i for i in d if 16<=i<40]==expected,'diff_header_consistency')","pass",'header-prefix vs C3 cross-check'),
 ('x28','handoff.py',"x['offset']+x['size']<=sizes[parent]","True",'lineage source range inside parent'),
 ('x29','handoff.py',"need(sum(sizes)<=64*1024**2,'lineage_budget')","pass",'lineage expansion budget'),
 ('x30','handoff.py',"if 'size' in q: need(count(q['size']) and q['offset']+q['size']<=sizes[q['stream']],'locator_bounds')","pass",'locator inside its stream'),
 ('x31','handoff.py',"need(expected==[x for x in q['opaque'] if x['reason']=='unparsed_root'],'certificate_opaque')","pass",'opaque root rows match certificate'),
 ('x32','handoff.py',"need(x in s['opaque'],'owner_opacity'); within(x,sizes)","within(x,sizes)",'owner opacity subset of opaque'),
 ('x33','handoff.py',"need(count(owner['fv_offset']) and owner['fv_offset']<=owner['offset'],'owner_fv_offset')","pass",'owner FV offset'),
 ('x34','handoff.py',"need(r['results']==[] and r['diagnostics']=={} and r['certificates']=={},'aborted_results')","pass",'aborted receipt carries no results'),
 ('x35','handoff.py',"e['stage'] in ('input','evaluate','summary','receipt_encoding') and ","",'aborted stage vocabulary'),
 ('x36','handoff.py',"expected=error_summary(); need(expected==r['summary'],'receipt_summary_mismatch')","expected=r['summary']",'aborted summary fixed'),
 ('x37','handoff.py',"within(q,sizes); need(type(q['stage']) is str,'error_stage')","pass",'failed-role location checked'),
 ('x38','handoff.py',"need(set(r['certificates'])==set(ROMS)-set(r['input_errors']),'certificate_roles')","pass",'certificate role set'),
 ('x39','handoff.py',"need('error' in q and 'coverage' not in q,'diagnostic_without_input')","pass",'no coverage without input'),
 ('x40','replay_compare.py',"aa={k:v for k,v in a.items() if k not in ('run_id','utc','runtime')}","aa={k:v for k,v in a.items() if k not in ('run_id','utc','runtime','results')}",'replay compares results'),
 ('x41','replay_compare.py',"need(r['version']==VERSION and 'run_error' not in r,'replay_current_completed_receipt')","pass",'replay only for current completed receipts'),
 ('x42','replay_compare.py',"need(p.name==digest(raw)+'.json','receipt_filename_hash')","pass",'replay filename = digest'),
 ('x43','replay_compare.py',"r=read_canonical(raw); validate(r)","r=read_canonical(raw)",'replay validates receipts'),
 ('x44','replay_compare.py',"return 0 if result['normalized_equal'] else 1","return 0",'replay exit code on mismatch'),
 ('x45','handoff.py',"        expected=summary(r)\n    need(expected==r['summary'],'receipt_summary_mismatch')","        expected=summary(r)\n    pass",'current-receipt summary bound to results (2nd site of author h02)'),
 ('A-p01', 'pilot.py', "'equal':min(sizes)>=40 and a[40:]==b[40:]", "'equal':min(sizes)>=40 and a[41:]==b[41:]", 'C6 equality from 40'),
 ('A-p01b', 'pilot.py', "'suffix_sha256':[digest(a[40:]),digest(b[40:])]", "'suffix_sha256':[digest(a[41:]),digest(b[41:])]", 'C6 suffix digest from 40'),
 ('A-p04', 'pilot.py', 'if data==0 or data%entry: return None', 'if data%entry: return None', 'empty signature list invalid'),
 ('A-p13', 'pilot.py', "if len(a)!=len(b): d={'length_mismatch':sizes}", 'if len(a)!=len(b): d=[]', 'length mismatch observed'),
 ('A-n14', 'checker.py', 'self.targets={str(uuid.UUID(g)).upper() for g in targets}', 'self.targets={g for g in targets}', 'GUID normalisation'),
 ('A-v03', 'verdicts.py', "all(len(o['raw'])==1 and not o['opaque'] for o in live)", "all(len(o['raw'])==1 for o in live)", 'owner opacity blocks readiness'),
 ('A-v05', 'verdicts.py', "need(s.get('locators')==[{k:v for k,v in q.items() if k!='sha256'} for q in raws],'selection_locator')", 'pass', 'locators bound to owner RAW'),
 ('A-s01', 'pilot.py', "if not any(c['verdict'] in ('PASS','FAIL') for c in relevant): return 'not_evaluated'", 'pass', 'P2-47_full not_evaluated'),
 ('A-z01', 'pilot.py', 'return 2 if write_receipt(args.receipts,r) else 3', 'return 2', 'aborted run receipt persisted'),
 ('A-z02', 'checker.py', "e.location={**self.position,'lineage':self.lineage.copy()}", 'pass', 'structural failure coordinates'),
 ('A-z03', 'pilot.py', "if gate['status']=='mismatch': return 4", "if gate['status']=='mismatch': return 0", 'gate mismatch exit code'),
 ('A-z04', 'verdicts.py', "need([i for i in d if i<16]==expected,'diff_timestamp_consistency')", 'pass', 'timestamp diff cross-check'),
 ('A-z06', 'handoff.py', "need(q['root_regions']==regions and type(regions) is list,'certificate_partition')", "need(type(regions) is list,'certificate_partition')", 'certificate and observed root regions'),
 ('A-z07', 'handoff.py', "parent<i and count(x['offset'])", "parent<len(lineage) and count(x['offset'])", 'lineage parent ordering'),
 ('A-z08', 'checker.py', "'except_opaque' if self.opaque else 'leaf_conditional' if self.leaves else 'grammar_complete'", "'except_opaque' if self.opaque or self.leaves else 'grammar_complete'", 'leaf conditional category'),
 ('A-z09', 'replay_compare.py', "'assurance_upgrade':False", "'assurance_upgrade':True", 'same checker replay must not promote'),
]
EQUIVALENT = {
 'x19': 'pilot.main() returns 2 for aborted runs before exit_code() is reached',
 'A-s01': 'v0.3.2 C1 override: C1 consistent implies every pair component measured, otherwise full is overwritten; conjunction never reaches not_evaluated',
 'x13': 'C6 FAIL implies C2 FAIL (sizes differ) or a diff offset >= 40 (historical_diff_bound FAIL); C4 is always OPEN, so C6 never changes P2-47_full',
 'h01': 'recompute() always yields OPEN for C4/C9 and the legacy receipt is compared in full',
 'h03': 'legacy receipt is compared in full against the pinned import (old == r)',
 'h04': 'after recompute() equality, a PASS/FAIL pair component implies verdicts.ready, which implies handoff ready',
 'v07': 'recompute() regenerates C2.observed from payload sizes, so any edit of C2.observed already mismatches',
 'v11': 'recompute() emits C8.observed = C7.observed, so a one-sided edit mismatches; a two-sided edit makes them equal',
 'n02': 'ext >= body_start of the leading pad is also required by fv_ext_not_in_leading_pad',
 'n04': 'unreachable: without a leading pad the ExtHeaderSize read from erased bytes fails fv_ext_size first',
}

def run(cmd, cwd, env):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600, env=env)
    except subprocess.TimeoutExpired:
        return 'timeout'
    if p.returncode == 0:
        return 'SURVIVED'
    m = re.search(r'FAILED \(([^)]*)\)', p.stderr)
    tail = m.group(1) if m else 'crash'
    return 'assert' if 'failures=' in tail else 'error-only'

env0 = dict(os.environ, V1_DIR=str(V1), IR_DIR=str(IR))
base = run([sys.executable, '-m', 'unittest', '-q', *AUTHOR], str(SRC), env0)
assert base == 'SURVIVED', f'baseline author suite failed: {base}'
rows = []
for mid, f, old, new, meaning in M:
    with tempfile.TemporaryDirectory() as d:
        dst = pathlib.Path(d) / 'v'; shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns('__pycache__'))
        p = dst / f; text = p.read_text()
        if text.count(old) != 1:
            rows.append((mid, meaning, f'ANCHOR x{text.count(old)}', '-')); print(rows[-1], flush=True); continue
        mutated=text.replace(old,new)
        try: compile(mutated,str(p),'exec')
        except SyntaxError:
            rows.append((mid,meaning,'INVALID_SYNTAX','-')); print(rows[-1],flush=True); continue
        p.write_text(mutated)
        env = dict(env0, V03_DIR=str(dst))
        a = run([sys.executable, '-m', 'unittest', '-q', *AUTHOR], str(dst), env)
        x = run([sys.executable, '-m', 'unittest', '-q', EXTRA], str(HERE), dict(env, PYTHONPATH=str(HERE))) if EXTRA else '-'
        rows.append((mid, meaning, a, x))
    print(f'{mid:5} author:{rows[-1][2]:10} extra:{rows[-1][3]:10} {meaning}', flush=True)

invalid=[r for r in rows if r[2].startswith('ANCHOR') or r[2] in ('INVALID_SYNTAX','timeout')]
live = [r for r in rows if r not in invalid and r[0] not in EQUIVALENT]
print(f'equivalent (excluded): {sorted(EQUIVALENT)}')
surv = [r[0] for r in live if r[2] == 'SURVIVED']
err = [r[0] for r in live if r[2] == 'error-only']
print(f'\nmutants {len(rows)}, non-equivalent {len(live)}; author suite: survived {len(surv)} {surv}; detected only via errors {len(err)} {err}')
if EXTRA:
    both = [r[0] for r in live if r[2] == 'SURVIVED' and r[3] == 'SURVIVED']
    print(f'extra suite {EXTRA}: survived author+extra {len(both)} {both}')

print('invalid/stale/timeout:',invalid)
# No green exit for incomplete mutation execution; errors-only remain distinct from assertion failures.
sys.exit(1 if invalid or surv else 0)
