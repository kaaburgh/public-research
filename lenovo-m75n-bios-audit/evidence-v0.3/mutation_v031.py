"""Version-specific mutation gate for v0.3.1. Does not claim exhaustive coverage.
Run from the directory: python3 mutation_v031.py
Original 49-mutant v0.3 suite remains pinned at review commit 3ae7117.
"""
import pathlib, shutil, subprocess, tempfile, sys, os
HERE=pathlib.Path(__file__).resolve().parent
SUITES=('test_pilot','test_v03_regression','test_v031_review')
M=[
 ('pad_data','checker.py',"if bad:","if False:"),
 ('pad_names','checker.py',"if t==0xf0:","if False:"),
 ('opaque_owner','checker.py',"if any(o['opaque'] for o in live): return None,assurance,'opaque_in_owner'","if False: pass"),
 ('raw_leaf','checker.py',"elif t==1: self.leaf(s,off+body_start,z-24,'raw_ffs_body')","elif t==1: pass"),
 ('ext_size','checker.py',"need(20<=ext_size<=n-ext,'fv_ext_size')","need(ext_size<=n-ext,'fv_ext_size')"),
 ('ext_pad','checker.py',"need(t==0xf0 and state=='data_valid' and body_start<=ext<ext_end<=body_end,'fv_ext_not_in_leading_pad')","need(True,'fv_ext_not_in_leading_pad')"),
 ('header_checksum','checker.py',"need((sum(h)-h[17]-h[23])%256 == 0, 'ffs_header_checksum')","need(True,'ffs_header_checksum')"),
 ('fixed_checksum','checker.py',"if attr&0x40 else h[17]==0xaa","if attr&0x40 else True"),
 ('untracked_fv','checker.py',"self.issue(s,o,'untracked_fv')","pass"),
 ('untracked_ffs','checker.py',"self.issue(s,j,'untracked_ffs_candidate')","pass"),
 ('scan_streams','checker.py',"for s,b in enumerate(self.streams):","for s,b in enumerate(self.streams[:1]):"),
 ('lzma_trailing','checker.py',"need(len(data)<=remaining and dec.eof and not dec.unused_data,'lzma_bounds_or_trailing')","need(len(data)<=remaining,'lzma_bounds_or_trailing')"),
 ('root_partition','checker.py',"o==pos and 0<n<=len(self.rom)-o","0<n<=len(self.rom)-o"),
 ('blockmap','checker.py',"need(end and total==n,'fv_blockmap')","need(True,'fv_blockmap')"),
 ('c3_subset','verdicts.py',"add('C3',d==DIFF,d)","add('C3',isinstance(d,list) and set(d)<=set(DIFF),d)"),
 ('c8_count','verdicts.py',"and sum(q['entries'] for q in z)==expected_count",""),
 ('c8_header','verdicts.py',"and q['header_size']==0 for q in z)","for q in z)"),
 ('c5_certtype','verdicts.py',"'wCertificateType':0xef1,'CertType':PKCS7_ID","'wCertificateType':x.get('wCertificateType') if x else None,'CertType':PKCS7_ID"),
 ('c1_duplicate','verdicts.py',"'FAIL' if duplicate else 'PASS' if unique else 'BLOCKED'","'PASS' if duplicate or unique else 'BLOCKED'"),
 ('multiplicity','verdicts.py',"'PASS' if a==b else 'FAIL'","'PASS'"),
 ('vacuous_counts','verdicts.py',"c['data_valid']>0 and not selection[r]['issues']","not selection[r]['issues']"),
 ('receipt_verdicts','handoff.py',"need({c['id']:c for c in recompute(x,size,count)}=={c['id']:c for c in x['components']},'receipt_verdict_mismatch')","pass"),
 ('receipt_summary','handoff.py',"need(expected==r['summary'],'receipt_summary_mismatch')","pass"),
 ('legacy_lineage','handoff.py',"need(old==r,'legacy_import_mismatch')","pass"),
 ('semantic_status','pilot.py',"'P2-47_full':conjunction(['C1','C2','C3','C4','C4_plausibility','C5','C6','C7','C8'])","'P2-47_full':'partial_not_established'"),
 ('gate','pilot.py',"'status':'mismatch' if mismatches else 'not_evaluated' if missing else 'all_six_match'","'status':'all_six_match'"),
]
def run(p):
    env=dict(os.environ,V03_DIR=str(p))
    return subprocess.run([sys.executable,'-m','unittest','-q',*SUITES],cwd=p,env=env,capture_output=True,text=True,timeout=180)
base=run(HERE)
if base.returncode:
    print(base.stdout,base.stderr); raise SystemExit('baseline failed')
survived=[]; invalid=[]
for name,file,old,new in M:
    with tempfile.TemporaryDirectory() as d:
        dest=pathlib.Path(d)/'pilot';shutil.copytree(HERE,dest,ignore=shutil.ignore_patterns('__pycache__'))
        p=dest/file;src=p.read_text()
        if src.count(old)!=1:
            invalid.append(name);print(name,'ANCHOR_MISMATCH');continue
        try: compile(src.replace(old,new),str(p),'exec')
        except SyntaxError: invalid.append(name);print(name,'INVALID_MUTANT');continue
        p.write_text(src.replace(old,new));r=run(dest)
        if r.returncode==0: survived.append(name); print(name,'SURVIVED')
        else: print(name,'detected')
print('mutants',len(M),'survived',survived,'invalid',invalid)
sys.exit(bool(survived or invalid))
