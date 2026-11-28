#!/usr/bin/env python3
"""Mutation testing of the v0.3 pilot (PR #4, 3c3c555c): which deliberate defects survive the author's
24-test suite (test_pilot.py) and which are detected by test_v03_adversarial.py.
Usage: python3 mutation_v03.py <evidence-v0.3 dir> <v1 worktree> <935daa0 worktree>
Each mutant is applied to a temporary copy; the original directory is never modified."""
import os, pathlib, shutil, subprocess, sys, tempfile

SRC, V1, IR = (pathlib.Path(p).resolve() for p in sys.argv[1:4])
HERE = pathlib.Path(__file__).resolve().parent
M = [  # (id, file, old, new, meaning)
 ('c01','checker.py',"need((sum(h)-h[17]-h[23])%256 == 0, 'ffs_header_checksum')","need(True, 'ffs_header_checksum')",'FFS header checksum not verified'),
 ('c02','checker.py',"need((sum(body)+h[17])%256==0 if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')","need(True if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')",'FFS_ATTRIB_CHECKSUM data checksum not verified'),
 ('c03','checker.py',"need((sum(body)+h[17])%256==0 if attr&0x40 else h[17]==0xaa, 'ffs_data_checksum')","need((sum(body)+h[17])%256==0 if attr&0x40 else True, 'ffs_data_checksum')",'fixed 0xAA file checksum not verified'),
 ('c04','checker.py',"need(not state&0xc0 and state&3 == 3, 'ffs_state')","need(state&3 == 3, 'ffs_state')",'reserved State bits not checked'),
 ('c05','checker.py',"need(not state&0xc0 and state&3 == 3, 'ffs_state')","need(not state&0xc0, 'ffs_state')",'lower State bits not required'),
 ('c06','checker.py',"if self.issues or marked or not live","if self.issues or not live",'MARKED_FOR_UPDATE no longer blocks'),
 ('c07','checker.py',"live=[o for o in owners if o['state']=='data_valid']","live=[o for o in owners if o['state']!='marked_for_update']",'deleted owners counted as live'),
 ('c08','checker.py',"if self.issues or marked or not live","if marked or not live",'tripwire issues ignored by selection'),
 ('c09','checker.py',"if (sum(h)-h[17]-h[23])%256==0: self.issue(s,j,'untracked_ffs_candidate')","if False: self.issue(s,j,'untracked_ffs_candidate')",'untracked valid FFS candidates ignored'),
 ('c10','checker.py',"elif 1<=h[18]<=15 and","elif False and 1<=h[18]<=15 and",'plausible invalid FFS candidates ignored'),
 ('c11','checker.py',"self.issue(s,o,'untracked_fv')","pass",'untracked FV ignored'),
 ('c12','checker.py',"for s,b in enumerate(self.streams):","for s,b in enumerate(self.streams[:1]):",'tripwire skips decompressed streams'),
 ('c13','checker.py',"self.sections(k,0,len(data),owner,depth+1)","self.sections(k,0,len(data),None,depth+1)",'owner lost through LZMA'),
 ('c14','checker.py',"else: self.unknown(s,o,z,'unsupported_guided_section')","else: pass",'unsupported GUID-defined section silently skipped'),
 ('c15','checker.py',"else: self.unknown(s,o,z,'unsupported_compression')","else: pass",'unsupported compression silently skipped'),
 ('c16','checker.py',"self.unknown(s,o,z,'unknown_section_type')","pass",'unknown section type silently skipped'),
 ('c17','checker.py',"o==pos and 0<n<=len(self.rom)-o","0<n<=len(self.rom)-o",'root partition contiguity not enforced'),
 ('c18','checker.py',"need(all(x==255 for x in self.rom[o:o+n]) or all(x==0 for x in self.rom[o:o+n]),'not_erased')","pass",'erased regions not verified'),
 ('c19','checker.py',"need(len(data)<=remaining and dec.eof and not dec.unused_data,'lzma_bounds_or_trailing')","need(len(data)<=remaining,'lzma_bounds_or_trailing')",'LZMA trailing data / truncation accepted'),
 ('c20','checker.py',"if any(f[p+8:hl]): self.unknown(s,off,n,'unsupported_fv_header_tail'); return","if False: return",'FV header tail not checked'),
 ('c21','checker.py',"need(end and total==n,'fv_blockmap')","need(True,'fv_blockmap')",'block map not checked'),
 ('c22','checker.py',"need(all(x==erase for x in f[pos:a]),'ffs_padding')","need(True,'ffs_padding')",'inter-file padding not checked'),
 ('c23','checker.py',"need(a<=n and all(x==0 for x in b[off+pos:off+a]),'section_padding')","need(a<=n,'section_padding')",'inter-section padding not checked'),
 ('c24','checker.py',"need(u(f,32,8)==n and 72<=hl<=n","need(72<=hl<=n",'FvLength not bound to region size'),
 ('c25','checker.py',"u(f,52,2)!=0 or ","",'ExtHeaderOffset ignored (FV with ext header parsed from HeaderLength)'),
 ('c26','checker.py',"need(off % 8 == 0 and off+24 <= len(buf), 'ffs_bounds_alignment')","need(off+24 <= len(buf), 'ffs_bounds_alignment')",'FFS 8-byte alignment not checked'),
 ('c27','checker.py',"self.unknown(s,o,n-pos,'extended_section_unsupported'); return","return",'extended-size section silently ends stream'),
 ('c28','checker.py',"if state!='deleted':","if True:",'deleted file bodies parsed as live'),
 ('c29','checker.py',"elif t not in (1,0xf0): self.unknown(s,off+pos+24,z-24,'unsupported_ffs_type')","elif False: pass",'unsupported FFS types silently skipped'),
 ('c30','checker.py',"if any(x!=payloads[0] for x in payloads[1:]): return None,assurance,'selection_ambiguous'","if False: pass",'differing duplicate payloads not ambiguous'),
 ('c31','checker.py',"assurance['selection']='unique' if len(live)==1 else 'equivalent_content_class'","assurance['selection']='unique'",'equivalence class reported as unique'),
 ('p01','pilot.py',"a[40:]==b[40:]","a[41:]==b[41:]",'C6 compares from offset 41'),
 ('p02','pilot.py',"add('C3',not exceeded and d==EXPECTED_DIFF","add('C3',not exceeded and set(d)<=set(EXPECTED_DIFF)",'C3 exact set weakened to subset (v1 semantics)'),
 ('p03','pilot.py',"'wCertificateType':0xef1,","'wCertificateType':(header_view(b) or {}).get('wCertificateType'),",'C5 ignores wCertificateType'),
 ('p04','pilot.py',"if data==0 or data%entry: return None","if data%entry: return None",'empty signature lists accepted'),
 ('p05','pilot.py',"and q['header_size']==0 for q in z)","for q in z)",'C8 ignores SignatureHeaderSize'),
 ('p06','pilot.py',"and sum(q['entries'] for q in z)==count","",'C8 ignores entry count'),
 ('p07','pilot.py',"add('C4_plausibility',timestamp(a) and timestamp(b)","add('C4_plausibility',True",'C4 plausibility always PASS'),
 ('p08','pilot.py',"if all(x['assurance']=='derived_in_supported_grammar' for x in c): return 'derived_within_supported_grammar'","return 'derived_within_supported_grammar'",'conditional coverage promoted to derived'),
 ('p09','pilot.py',"if any(x is not None and x['verdict']=='FAIL' for x in c): return 'conditional_refutation'","pass",'conditional refutation reported as unverified'),
 ('p10','pilot.py',"'FAIL' if duplicate else 'PASS' if unique else 'BLOCKED'","'PASS' if unique or duplicate else 'BLOCKED'",'duplicates pass C1'),
 ('p11','pilot.py',"'PASS' if ca==cb else 'FAIL'","'PASS'",'multiplicity always PASS'),
 ('p12','pilot.py',"level='derived_in_supported_grammar' if len(rows)==2 and all(v[1]['coverage']=='grammar_complete' for v in rows.values()) else 'conditional_coverage'","level='derived_in_supported_grammar'",'opaque coverage labelled derived'),
 ('p13','pilot.py',"if len(a)!=len(b): add('C3',False","if len(a)!=len(b): add('C3',True",'length mismatch passes C3'),
 ('h01','handoff.py',"if c['id'] in ('C4','C9'): need(c['verdict']=='OPEN','semantic_overclaim')","pass",'handoff accepts C4/C9 PASS'),
 ('h02','handoff.py',"need(expected==r['summary'],'receipt_summary_mismatch')","pass",'handoff accepts any summary'),
 ('h03','handoff.py',"for c in x['components']: need(c['verdict']==('PASS' if c['id'] in ('C2','C6','legacy_diff_subset','legacy_dwLength') else 'OPEN'),'legacy_upgrade')","pass",'handoff accepts upgraded legacy verdicts'),
 ('h04','handoff.py',"need(ready,'result_without_derived_inputs')","pass",'handoff accepts results without derived inputs'),
 ('l01','legacy_import.py',"bool(o['diff_offsets']) and set(o['diff_offsets'])<=set(e['allowed_diff_offsets'])","True",'importer ignores v1 diff observation'),
]

def run(cmd, cwd, env=None):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600, env=env).returncode
    except subprocess.TimeoutExpired:
        return 'timeout'

rows = []
for mid, f, old, new, meaning in M:
    with tempfile.TemporaryDirectory() as d:
        dst = pathlib.Path(d) / 'v03'; shutil.copytree(SRC, dst)
        p = dst / f; text = p.read_text()
        n = text.count(old)
        if n != 1:
            rows.append((mid, meaning, f'PATTERN x{n}', '-')); continue
        p.write_text(text.replace(old, new))
        author = run([sys.executable, '-m', 'unittest', '-q', 'test_pilot'], dst)
        env = dict(os.environ, V03_ALLOW_UNPINNED='1')
        ours = run([sys.executable, str(HERE / 'test_v03_adversarial.py'), str(dst), str(V1), str(IR)], d, env)
        env2 = dict(env, V03_DIR=str(dst), V1_DIR=str(V1), IR_DIR=str(IR), PYTHONPATH=str(HERE))
        reg = run([sys.executable, '-m', 'unittest', '-q', 'test_v03_regression'], str(HERE), env2)
        k = lambda c: 'killed' if c != 0 else 'SURVIVED'
        rows.append((mid, meaning, k(author), k(ours), k(reg)))
    print(f'{rows[-1][0]}  author:{rows[-1][2]:9} adversarial:{rows[-1][3]:9} regression:{rows[-1][4]:9} {meaning}', flush=True)

EQUIVALENT = {'c26': 'fv() aligns pos to 8 before every header() call', 'c04': 'a reserved bit 0x40/0x80 is always the highest set bit, so highest-bit check rejects it anyway', 'l01': 'pinned SHA-256 of the v1 receipt makes the observation check redundant'}
live = [r for r in rows if r[0] not in EQUIVALENT]
sa = sum(r[2] == 'SURVIVED' for r in live)
sr = [r[0] for r in live if r[4] == 'SURVIVED']
sall = [r[0] for r in live if r[2] == r[3] == r[4] == 'SURVIVED']
print(f'\nmutants {len(rows)} ({len(EQUIVALENT)} equivalent: {EQUIVALENT})')
print(f'non-equivalent {len(live)}: survived author suite {sa}; survived regression suite {len(sr)} {sr}; survived all three {len(sall)} {sall}')
