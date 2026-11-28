#!/usr/bin/env python3
"""v0.3.2 adaptation of the independent PR #7 mutation suite (97f188d3). Ports the 49 PR #5 mutant properties to the refactored
code and adds mutants for code new in v0.3.1. Each mutant runs the combined 127-test suite
(test_pilot, test_v03_regression, test_v031_review) in a temporary copy; detection is split into assertion
failures and errors-only. Optional extra suite: --extra <module> (run from this directory, V03_DIR set).
Usage: python3 mutation_v032.py <evidence-v0.3 dir> <v1 worktree> <935daa0 worktree> [--extra test_v031_addendum]"""
import os, pathlib, re, shutil, subprocess, sys, tempfile

SRC, V1, IR = (pathlib.Path(p).resolve() for p in sys.argv[1:4])
EXTRA = sys.argv[sys.argv.index('--extra') + 1] if '--extra' in sys.argv else None
HERE = pathlib.Path(__file__).resolve().parent
AUTHOR = ('test_pilot', 'test_v03_regression', 'test_v031_review','test_v031_addendum','test_v032')
M = [
 # --- ported from PR #5 (c = checker, p = pilot/verdicts, h = handoff, l = legacy)
 ('c01','checker.py',"need((sum(h)-h[17]-h[23])%256 == 0, 'ffs_header_checksum')","need(True, 'ffs_header_checksum')",'FFS header checksum'),
 ('c02','checker.py',"need((sum(body)+h[17])%256==0 if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')","need(True if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')",'FFS_ATTRIB_CHECKSUM data checksum'),
 ('c03','checker.py',"need((sum(body)+h[17])%256==0 if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')","need((sum(body)+h[17])%256==0 if attr&0x40 else True, 'ffs_data_checksum')",'fixed 0xAA checksum'),
 ('c05','checker.py',"need(not state&0xc0 and state&3 == 3, 'ffs_state')","need(not state&0xc0, 'ffs_state')",'lower State bits required'),
 ('c06','checker.py',"if self.issues or marked or not live","if self.issues or not live",'MARKED_FOR_UPDATE blocks'),
 ('c07','checker.py',"owners=self.owners[g]; live=[o for o in owners if o['state']=='data_valid']","owners=self.owners[g]; live=[o for o in owners if o['state']!='marked_for_update']",'deleted not live'),
 ('c08','checker.py',"if self.issues or marked or not live","if marked or not live",'issues block selection'),
 ('c09','checker.py',"self.issue(s,j,'untracked_ffs_candidate')","pass",'untracked FFS candidate'),
 ('c10','checker.py',"elif 1<=h[18]<=15 and","elif False and 1<=h[18]<=15 and",'plausible invalid FFS candidate'),
 ('c11','checker.py',"self.issue(s,o,'untracked_fv')","pass",'untracked FV'),
 ('c12','checker.py',"for s,b in enumerate(self.streams):","for s,b in enumerate(self.streams[:1]):",'tripwire on decompressed streams'),
 ('c13','checker.py',"self.sections(k,0,len(data),owner,depth+1)","self.sections(k,0,len(data),None,depth+1)",'owner through LZMA'),
 ('c14','checker.py',"else: self.unknown(s,o,z,'unsupported_guided_section',owner)","else: pass",'unsupported GUID-defined section reported'),
 ('c15','checker.py',"else: self.unknown(s,o,z,'unsupported_compression',owner)","else: pass",'unsupported compression reported'),
 ('c16','checker.py',"self.unknown(s,o,z,'unknown_section_type',owner)","pass",'unknown section type reported'),
 ('c17','checker.py',"o==pos and 0<n<=len(self.rom)-o","0<n<=len(self.rom)-o",'root partition contiguity'),
 ('c18','checker.py',"need(all(x==255 for x in self.rom[o:o+n]) or all(x==0 for x in self.rom[o:o+n]),'not_erased')","pass",'erased root regions verified'),
 ('c19','checker.py',"need(len(data)<=remaining and dec.eof and not dec.unused_data,'lzma_bounds_or_trailing')","need(len(data)<=remaining,'lzma_bounds_or_trailing')",'LZMA trailing data'),
 ('c20','checker.py',"if any(f[p+8:hl]): self.unknown(s,off,n,'unsupported_fv_header_tail'); return","if False: return",'FV header tail'),
 ('c21','checker.py',"need(end and total==n,'fv_blockmap')","need(True,'fv_blockmap')",'block map'),
 ('c22','checker.py',"need(all(x==erase for x in f[pos:a]),'ffs_padding')","need(True,'ffs_padding')",'inter-file padding'),
 ('c23','checker.py',"need(a<=n and all(x==0 for x in b[off+pos:off+a]),'section_padding')","need(a<=n,'section_padding')",'inter-section padding'),
 ('c24','checker.py',"need(u(f,32,8)==n and 72<=hl<=n","need(72<=hl<=n",'FvLength bound to region'),
 ('c27','checker.py',"self.unknown(s,o,n-pos,'extended_section_unsupported',owner); return","return",'extended-size section reported'),
 ('c28','checker.py',"if state=='deleted':","if False:",'deleted body not parsed as live'),
 ('c29','checker.py',"else: self.unknown(s,off+body_start,z-24,'unsupported_ffs_type',owner)","else: pass",'unsupported FFS type reported'),
 ('c30','checker.py',"if any(x!=payloads[0] for x in payloads[1:]): return None,assurance,'selection_ambiguous'","if False: pass",'differing duplicates ambiguous'),
 ('c31','checker.py',"assurance['selection']='unique' if len(live)==1 else 'equivalent_content_class'","assurance['selection']='unique'",'equivalence class labelled'),
 ('p01','pilot.py',"'equal':min(sizes)>=40 and a[40:]==b[40:]","'equal':min(sizes)>=40 and a[41:]==b[41:]",'C6 equality from 40'),
 ('p01b','pilot.py',"'suffix_sha256':[digest(a[40:]),digest(b[40:])]","'suffix_sha256':[digest(a[41:]),digest(b[41:])]",'C6 suffix digest from 40'),
 ('p02','verdicts.py',"add('C3',d==DIFF,d)","add('C3',isinstance(d,list) and set(d)<=set(DIFF),d)",'C3 exact, not subset'),
 ('p03','pilot.py',"'wRevision':u(b,20,2)","'wRevision':0x200",'C5 measures wRevision'),
 ('p04','pilot.py',"if data==0 or data%entry: return None","if data%entry: return None",'empty signature list invalid'),
 ('p05','verdicts.py',"and q['header_size']==0 for q in z)","for q in z)",'C8 SignatureHeaderSize'),
 ('p06','verdicts.py',"and sum(q['entries'] for q in z)==expected_count","",'C8 entry count'),
 ('p07','verdicts.py',"add('C4_plausibility',all(x is not None and timestamp(bytes.fromhex(x)) for x in t),t)","add('C4_plausibility',True,t)",'C4 plausibility measured'),
 ('p08','pilot.py',"if all(x['assurance']=='derived_in_supported_grammar' for x in c): return 'derived_within_supported_grammar'","return 'derived_within_supported_grammar'",'conditional not promoted'),
 ('p09','pilot.py',"if any(x is not None and x['verdict']=='FAIL' for x in c): return 'conditional_refutation'","pass",'conditional refutation reported'),
 ('p10','verdicts.py',"'FAIL' if duplicate else 'PASS' if unique else 'BLOCKED'","'PASS' if duplicate or unique else 'BLOCKED'",'duplicates fail C1'),
 ('p11','verdicts.py',"'PASS' if a==b else 'FAIL'","'PASS'",'multiplicity compares'),
 ('p12','verdicts.py',"level='derived_in_supported_grammar' if len(info)==2 and all(s['coverage']=='grammar_complete' for s in selection.values()) else 'conditional_coverage'","level='derived_in_supported_grammar'",'conditional level'),
 ('p13','pilot.py',"if len(a)!=len(b): d={'length_mismatch':sizes}","if len(a)!=len(b): d=[]",'length mismatch observed'),
 ('h01','handoff.py',"if c['id'] in ('C4','C9'): need(c['verdict']=='OPEN','semantic_overclaim')","pass",'handoff semantic overclaim'),
 ('h02','handoff.py',"need(expected==r['summary'],'receipt_summary_mismatch')","pass",'handoff summary'),
 ('h03','handoff.py',"for c in x['components']: need(c['verdict']==('PASS' if c['id'] in ('C2','C6','legacy_diff_subset','legacy_dwLength') else 'OPEN'),'legacy_upgrade')","pass",'handoff legacy upgrade'),
 ('h04','handoff.py',"need(ready,'result_without_derived_inputs')","pass",'handoff derived inputs'),
 # --- new in v0.3.1: extended header, pad, leaves, owner opacity
 ('n01','checker.py',"need(ext%4==0 and align(hl,8)+24<=ext<=n-20,'fv_ext_bounds')","need(align(hl,8)+24<=ext<=n-20,'fv_ext_bounds')",'ext header 4-byte alignment'),
 ('n02','checker.py',"need(ext%4==0 and align(hl,8)+24<=ext<=n-20,'fv_ext_bounds')","need(ext%4==0 and ext<=n-20,'fv_ext_bounds')",'ext header after pad header'),
 ('n03','checker.py',"if ext_size!=20:","if False:",'ext entries opaque'),
 ('n04','checker.py',"if ext: need(ext_seen,'fv_ext_missing_pad')","pass",'ext header must be seen'),
 ('n05','checker.py',"need(t==0xf0 and state=='data_valid' and body_start<=ext<ext_end<=body_end,'fv_ext_not_in_leading_pad')","need(t==0xf0 and body_start<=ext<ext_end<=body_end,'fv_ext_not_in_leading_pad')",'leading pad must be DATA_VALID'),
 ('n06','checker.py',"bad=any(x!=erase for x in f[body_start:ext]) or any(x!=erase for x in f[ext_end:body_end])","bad=any(x!=erase for x in f[ext_end:body_end])",'pad bytes before ext header'),
 ('n07','checker.py',"bad=any(x!=erase for x in f[body_start:ext]) or any(x!=erase for x in f[ext_end:body_end])","bad=any(x!=erase for x in f[body_start:ext])",'pad bytes after ext header'),
 ('n08','checker.py',"self.issue(s,off+body_start,'pad_file_data')","pass",'pad data is an issue (not only opaque)'),
 ('n09','checker.py',"self.leaf(s,o+4,len(body),'raw_section')","pass",'RAW section recorded as leaf'),
 ('n10','checker.py',"else: self.leaf(s,o+4,len(body),'section_%02x'%t)","else: pass",'other leaf sections recorded'),
 ('n11','checker.py',"if owner is not None: owner['opaque'].extend(self.opaque[before:])","pass",'opacity of nested FV propagates to owner'),
 ('n12','checker.py',"self.leaf(s,off+body_start,z-24,'deleted_ffs_body',deleted=True)","pass",'deleted body inventoried'),
 ('n13','checker.py',"self.scan_work+=hl; need(self.scan_work<=MAX_BYTES,'tripwire_checksum_budget')","pass",'tripwire checksum budget'),
 ('n14','checker.py',"self.targets={str(uuid.UUID(g)).upper() for g in targets}","self.targets={g for g in targets}",'GUID normalisation'),
 ('n15','checker.py',"self.unknown(s,off,n,'unsupported_fv_ext_entries'); return","return",'ext entries reported as opaque'),
 ('n16','checker.py',"if f[16:32]!=FFS2 or f[55]!=2:","if f[16:32]!=FFS2:",'FV revision 2 required'),
 # --- new in v0.3.1: shared verdict rules and receipt consistency
 ('v01','verdicts.py',"need(counts==s['counts'],'selection_counts')","pass",'counts recomputed'),
 ('v02','verdicts.py',"need(s['coverage']==coverage,'selection_coverage')","pass",'coverage recomputed'),
 ('v03','verdicts.py',"all(len(o['raw'])==1 and not o['opaque'] for o in live)","all(len(o['raw'])==1 for o in live)",'owner opacity blocks readiness'),
 ('v04','verdicts.py',"need(s.get('payload')=={'sha256':raws[0]['sha256'],'size':raws[0]['size']},'selection_payload')","pass",'payload bound to owner RAW'),
 ('v05','verdicts.py',"need(s.get('locators')==[{k:v for k,v in q.items() if k!='sha256'} for q in raws],'selection_locator')","pass",'locators bound to owner RAW'),
 ('v07','verdicts.py',"need(obs['C2']==sizes,'size_observation')","pass",'C2 observation bound to payload sizes'),
 ('v08','verdicts.py',"need(equal==(not any(i>=40 for i in d)),'diff_suffix_consistency')","pass",'C3/C6 cross-consistency'),
 ('v09','verdicts.py',"need(equal==tail['equal'],'suffix_consistency')","pass",'C6 flag vs hashes'),
 ('v10','verdicts.py',"need(total==sizes[i]-40,'list_consumption')","pass",'signature lists consume tail'),
 ('v11','verdicts.py',"need(x==y and type(x) is list and len(x)==2,'list_observation_disagreement')","need(type(x) is list and len(x)==2,'list_observation_disagreement')",'C7 and C8 share one observation'),
 ('v12','verdicts.py',"return 1900<=u(b,0,2)<=9999 and b[7]==0 and","return 1900<=u(b,0,2)<=9999 and",'EFI_TIME Pad1 checked'),
 ('v13','verdicts.py',"return 'partial',False if z['parsed_entries']>expected_count else None","return 'partial',None",'count refutation under list limit'),
 ('v14','verdicts.py',"if any(kind=='invalid' for kind,_ in info): add('C7',False,x)","if False: pass",'malformed list is FAIL'),
 ('v15','verdicts.py',"c['data_valid']>0 and not selection[r]['issues'] and not c['marked_for_update']","c['data_valid']>0 and not c['marked_for_update']",'multiplicity blocked by issues'),
 ('v16','verdicts.py',"else: need('payload' not in s and 'selection' not in s,'unresolved_payload')","else: pass",'no payload on unresolved selection'),
 # --- new in v0.3.1: semantic summary and gate
 ('s01','pilot.py',"if not any(c['verdict'] in ('PASS','FAIL') for c in relevant): return 'not_evaluated'","pass",'P2-47_full not_evaluated'),
 ('s02','pilot.py',"bad=[x for x in c if isinstance(x['observed'],dict) or any(i>=16 for i in x['observed'])]","bad=[x for x in c if isinstance(x['observed'],dict) or any(i>=40 for i in x['observed'])]",'timestamp scope bound 16'),
 ('s03','pilot.py',"bad=[x for x in c if isinstance(x['observed'],dict) or any(i>=16 for i in x['observed'])]","bad=[x for x in c if not isinstance(x['observed'],dict) and any(i>=16 for i in x['observed'])]",'length mismatch refutes timestamp-only'),
 ('s04','pilot.py',"return 'partial_not_established' if c else 'not_evaluated'","return 'partial_not_established'",'timestamp not_evaluated'),
 ('s05','pilot.py',"'status':'mismatch' if mismatches else 'not_evaluated' if missing else 'all_six_match'","'status':'not_evaluated' if missing else 'mismatch' if mismatches else 'all_six_match'",'gate mismatch precedes missing'),
 ('s06','pilot.py',"elif x['sha256']==expected[i]: matches.append(label)","elif x['sha256'] in expected: matches.append(label)",'gate compares per role'),
 ('s07','pilot.py',"scope=isinstance(d,list) and set(d)<=set(EXPECTED_DIFF)","scope=isinstance(d,list) and d==EXPECTED_DIFF",'historical diff bound not exact'),
 # --- CLI and handoff identity (not exercised by unit suites)
 ('k01','pilot.py',"need(actual==ROMS[role] and len(b)==16777216,'rom_identity')","need(True,'rom_identity')",'CLI ROM identity'),
 ('k02','pilot.py',"cert['artifact_sha256']==actual,'certificate_binding')","True,'certificate_binding')",'CLI certificate binding'),
 ('k03','pilot.py',"open(pathlib.Path(directory)/name,'xb')","open(pathlib.Path(directory)/name,'wb')",'exclusive receipt creation'),
 ('k04','pilot.py',"if r.get('input_errors') or gate['missing']: return 2","if r.get('input_errors') or gate['missing']: return 0",'incomplete CLI exit code'),
 ('k05','handoff.py',"need(path.name==digest(raw)+'.json','receipt_filename_hash')","pass",'receipt filename = digest'),
 ('k06','handoff.py',"need(s[k]==r['diagnostics'][role][k],'diagnostic_mismatch')","pass",'selection vs diagnostics'),
 ('k07','handoff.py',"need(r['tool_sha256'][name]==digest(PROFILE_PATH.with_name(name).read_bytes()),'tool_identity')","pass",'tool identity'),
 ('k08','handoff.py',"need(r['profile_sha256']==digest(PROFILE_PATH.read_bytes()),'profile_identity')","pass",'profile identity'),
 ('k09','handoff.py',"need(a is not None and a['sha256']==sha and a['size']==16777216,'artifact_identity')","pass",'artifact identity'),
 ('k10','handoff.py',"need(set(selection)==set(successful),'selection_role_set')","pass",'selection role set'),
 ('k11','legacy_import.py',"'byte_observations':state(rows,['C2','C3','C6'])","'byte_observations':'consistent_conditional'",'legacy byte_observations computed'),
 ('k12','legacy_import.py',"'legacy_byte_subset':state(rows,['C2','C6','legacy_diff_subset','legacy_dwLength'])","'legacy_byte_subset':'derived_within_supported_grammar'",'legacy subset status computed'),
 ('z01','pilot.py',"return 2 if write_receipt(args.receipts,r) else 3","return 2",'aborted run receipt persisted'),
 ('z02','checker.py',"e.location={**self.position,'lineage':self.lineage.copy()}","pass",'structural failure coordinates'),
 ('z03','pilot.py',"if gate['status']=='mismatch': return 4","if gate['status']=='mismatch': return 0",'gate mismatch exit code'),
 ('z04','verdicts.py',"need([i for i in d if i<16]==expected,'diff_timestamp_consistency')","pass",'timestamp diff cross-check'),
 ('z05','handoff.py',"need((raw['stream'],raw['offset'],raw['size']) in leaves,'raw_leaf_membership')","pass",'RAW leaf invariant (both sites)'),
 ('z06','handoff.py',"need(q['root_regions']==regions and type(regions) is list,'certificate_partition')","need(type(regions) is list,'certificate_partition')",'certificate and observed root regions'),
 ('z07','handoff.py',"parent<i and count(x['offset'])","parent<len(lineage) and count(x['offset'])",'lineage parent ordering'),
 ('z08','checker.py',"'except_opaque' if self.opaque else 'leaf_conditional' if self.leaves else 'grammar_complete'","'except_opaque' if self.opaque or self.leaves else 'grammar_complete'",'leaf conditional category'),
 ('z09','replay_compare.py',"'assurance_upgrade':False","'assurance_upgrade':True",'same checker replay must not promote'),
 ('k13','discovery.py',"if sum(u(rom,i,2) for i in range(o,o+hl,2))%65536: continue","if False: continue",'discovery checksum filter'),
]
EQUIVALENT = {
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
        if text.count(old) != (2 if mid=='z05' else 1):
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
