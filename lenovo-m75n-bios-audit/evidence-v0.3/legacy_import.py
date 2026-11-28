"""Import the pinned v1 real-ROM receipt as historical conditional evidence; never upgrade it."""
import argparse, json, hashlib, sys
from checker import digest, canonical, need, Invalid
from pilot import TARGETS, ROMS, record, write_receipt, read_bounded, NON_CLAIMS, state

CLAIMS_SHA='27b7a694155a3a82b943c47125f001da12356c4cd9f2627bd28b414c5c22dc3f'
RECEIPT_SHA='e386231e513052d0cfee38922e83c95ecb3bbb1e85834a1b0f665cd7b110147b'
RECEIPT_BLOB='d6cb826afb74df052cd283a4c6a7a297d00a56f1'
VERIFIER_SHA='76fc95a1146140b4dbc5a3df351b559cb9db3a3bdf8c72f3bc9185b95d6aa465'
SOURCE_COMMIT='5cfc7c245066ced5e7854a191fcd1c06d7f41f62'
PROTOCOL_COMMIT='4095d9cf951f79bd0d4ca51f89afe82a350dbb88'
RUN_COMMIT='935daa09485a5fb6ba7b396c1024c027f735ad5c'

def blob_sha(b): return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()

def import_v1(claim_bytes, receipt_bytes):
    need(digest(claim_bytes)==CLAIMS_SHA,'legacy_claim_identity')
    need(digest(receipt_bytes)==RECEIPT_SHA and blob_sha(receipt_bytes)==RECEIPT_BLOB,'legacy_receipt_identity')
    p=json.loads(claim_bytes); r=json.loads(receipt_bytes)
    need(r['registry_sha256']==CLAIMS_SHA and r['verifier_sha256']==VERIFIER_SHA and r['source_commit']==SOURCE_COMMIT,'legacy_binding')
    need(set(r['artifacts'])=={'rom132','rom133'},'legacy_artifacts')
    for role,old in (('a','rom132'),('b','rom133')):
        need(r['artifacts'][old]['sha256']==ROMS[role] and r['artifacts'][old]['size']==16777216 and r['artifacts'][old]['extract_exit']==0,'legacy_rom_identity')
    need(len(r['results'])==len(p['claims'])==3 and {x['id'] for x in r['results']}=={x['id'] for x in p['claims']}==set(TARGETS),'legacy_claim_set')
    out=[]
    for c in p['claims']:
        x=next(q for q in r['results'] if q['id']==c['id']); e=c['expected']; o=x['observed']
        need(digest(json.dumps(c,sort_keys=True,separators=(',',':')).encode())==x['claim_sha256'],'legacy_claim_hash')
        need(x['verdict']=='PASS' and len(x['checks'])==8 and all(v is True for v in x['checks'].values()),'legacy_result')
        need(o['sizes']==[e['size_each']]*2 and o['body_sha256']==e['body_sha256'] and o['dwLength']==[24,24] and o['suffix_offsets']==[40,40] and o['suffix_sha256']==[e['suffix_sha256_each']]*2 and o['suffix_equal'] is True and bool(o['diff_offsets']) and set(o['diff_offsets'])<=set(e['allowed_diff_offsets']),'legacy_observations')
        level='adapter_asserted'; comps=[record('C2','PASS',level,o['sizes']),record('C6','PASS',level,o['suffix_sha256']),record('legacy_diff_subset','PASS',level,o['diff_offsets']),record('legacy_dwLength','PASS',level,o['dwLength'])]
        for i in ('C1','C3','C4','C4_plausibility','C5','C7','C8','C9','multiplicity'): comps.append(record(i,'OPEN',level,None,'not_established_by_v1_contract'))
        out.append({'id':c['id'],'guid':c['selector']['guid'],'components':comps,'selection':'adapter_asserted','selected_paths':x['selected_paths']})
    return {'version':'0.3.1-legacy-import','source_commit':SOURCE_COMMIT,'legacy_protocol_commit':PROTOCOL_COMMIT,'legacy_run_commit':RUN_COMMIT,'legacy_receipt_sha256':digest(receipt_bytes),'legacy_receipt_git_blob':RECEIPT_BLOB,'legacy_claims_sha256':CLAIMS_SHA,'legacy_verifier_sha256':VERIFIER_SHA,'results':out,'summary':legacy_summary(out)}

def legacy_summary(rows):
    return {'byte_observations':state(rows,['C2','C3','C6']),'legacy_byte_subset':state(rows,['C2','C6','legacy_diff_subset','legacy_dwLength']),'equal_structural_signature_lists':state(rows,['C1','C5','C6','C7']),'x509_tag_and_entry_counts':state(rows,['C1','C7','C8']),'P2-47_full':'partial_not_established' if any(c['verdict']=='PASS' for row in rows for c in row['components']) else 'not_evaluated','non_claims':NON_CLAIMS}

def main():
    p=argparse.ArgumentParser();p.add_argument('claims');p.add_argument('receipt');p.add_argument('output_dir');a=p.parse_args()
    try: r=import_v1(read_bounded(a.claims,8*1024**2),read_bounded(a.receipt,8*1024**2)); return 0 if write_receipt(a.output_dir,r) else 3
    except (OSError,Invalid,KeyError,TypeError,ValueError) as e: print('IMPORT_REJECTED',str(e),file=sys.stderr); return 2
if __name__=='__main__': sys.exit(main())
