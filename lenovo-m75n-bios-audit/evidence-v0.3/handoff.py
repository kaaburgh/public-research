"""Render computed pilot status from a canonical receipt. Not execution attestation."""
import argparse, pathlib, sys
from checker import read_canonical, digest, need, Invalid
from pilot import summary, error_summary, TARGETS, PROFILE_PATH, read_bounded, NON_CLAIMS, ROMS, VERSION
from verdicts import recompute, count, hash_id
from legacy_import import CLAIMS_SHA, RECEIPT_SHA, RECEIPT_BLOB, PROTOCOL_COMMIT, RUN_COMMIT, legacy_summary

CURRENT_IDS={'C1','C2','C3','C4_plausibility','C4','C5','C6','C7','C8','C9','multiplicity'}
LEGACY_IDS=CURRENT_IDS|{'legacy_diff_subset','legacy_dwLength'}

def check_identity(r):
    need(r['profile_sha256']==digest(PROFILE_PATH.read_bytes()),'profile_identity')
    for name in ('pilot.py','checker.py','verdicts.py','discovery.py'): need(r['tool_sha256'][name]==digest(PROFILE_PATH.with_name(name).read_bytes()),'tool_identity')
    need(set(r['artifacts'])<=set(ROMS) and set(r['input_errors'])<=set(ROMS),'artifact_roles')
    for role,a in r['artifacts'].items():
        need(a['expected_sha256']==ROMS[role] and hash_id(a['sha256']) and count(a['size']),'artifact_record')

def check_lineage(lineage,sha,size):
    need(type(lineage) is list and bool(lineage),'lineage_empty')
    need(lineage[0]=={'stream':0,'kind':'artifact','sha256':sha,'size':size},'root_lineage_identity')
    sizes=[size]
    for i,x in enumerate(lineage[1:],1):
        need(set(x)=={'stream','kind','parent_stream','offset','size','output_size','sha256'} and x['stream']==i and x['kind']=='lzma_alone' and hash_id(x['sha256']),'lineage_node')
        parent=x['parent_stream']
        need(count(parent) and parent<i and count(x['offset']) and count(x['size']) and x['size']>0 and x['offset']+x['size']<=sizes[parent] and count(x['output_size']),'lineage_range')
        sizes.append(x['output_size'])
    need(sum(sizes)<=64*1024**2,'lineage_budget')
    return sizes

def within(q,sizes):
    need(count(q['stream']) and q['stream']<len(sizes) and count(q['offset']) and q['offset']<=sizes[q['stream']],'locator_stream')
    if 'size' in q: need(count(q['size']) and q['offset']+q['size']<=sizes[q['stream']],'locator_bounds')

def check_diagnostics(q,sha,size,certificate):
    sizes=check_lineage(q['lineage'],sha,size)
    for key in ('issues','opaque','uninterpreted_leaves','deleted_uninterpreted'):
        for x in q[key]: within(x,sizes)
    regions=certificate['regions']
    need(q['root_regions']==regions and type(regions) is list,'certificate_partition')
    pos=0
    for x in regions:
        need(set(x)=={'offset','size','kind'} and x['offset']==pos and count(x['offset']) and count(x['size']) and x['size']>0 and x['kind'] in ('fv','erased','opaque'),'certificate_partition')
        pos+=x['size']
    need(pos==size,'certificate_partition')
    expected=[{'stream':0,'offset':x['offset'],'size':x['size'],'reason':'unparsed_root'} for x in regions if x['kind']=='opaque']
    need(expected==[x for x in q['opaque'] if x['reason']=='unparsed_root'],'certificate_opaque')
    return sizes

def check_selection(s,sizes):
    leaves={(x['stream'],x['offset'],x['size']) for x in s['uninterpreted_leaves'] if x['kind']=='raw_section'}
    for owner in s['owners']:
        within(owner,sizes)
        need(count(owner['fv_offset']) and owner['fv_offset']<=owner['offset'],'owner_fv_offset')
        for x in owner['opaque']:
            need(x in s['opaque'],'owner_opacity'); within(x,sizes)
        for raw in owner['raw']:
            within(raw,sizes)
            need((raw['stream'],raw['offset'],raw['size']) in leaves,'raw_leaf_membership')
            need(hash_id(raw['sha256']),'raw_digest')
    for raw in s.get('locators',[]):
        within(raw,sizes)
        need((raw['stream'],raw['offset'],raw['size']) in leaves,'raw_leaf_membership')

def validate_error(r):
    check_identity(r)
    need(r['results']==[] and r['diagnostics']=={} and r['certificates']=={},'aborted_results')
    e=r['run_error']
    need(set(e)=={'stage','code'} and e['stage'] in ('input','evaluate','summary','receipt_encoding') and type(e['code']) is str and e['code'].isascii() and e['code'].replace('_','').isalnum(),'run_error')
    need(set(r['certificate_sha256'])<=set(ROMS) and all(hash_id(x) for x in r['certificate_sha256'].values()),'aborted_certificate_hash')
    expected=error_summary(); need(expected==r['summary'],'receipt_summary_mismatch')
    return expected

def validate(r):
    legacy=r['version']=='0.3.1-legacy-import'
    need(legacy or r['version']==VERSION,'receipt_version')
    if 'run_error' in r:
        need(not legacy,'legacy_run_error'); return validate_error(r)
    need(len(r['results'])==3 and {x['id'] for x in r['results']}==set(TARGETS),'receipt_target_set')
    for x in r['results']:
        need(x['guid']==TARGETS[x['id']][0],'receipt_guid')
        ids=LEGACY_IDS if legacy else CURRENT_IDS
        need(len(x['components'])==len(ids) and {c['id'] for c in x['components']}==ids,'receipt_component_set')
        for c in x['components']:
            need(c['verdict'] in ('PASS','FAIL','BLOCKED','OPEN'),'receipt_verdict')
            need(c['assurance'] in (('adapter_asserted',) if legacy else ('derived_in_supported_grammar','conditional_coverage','unresolved','interpretation')),'receipt_assurance')
            if c['id'] in ('C4','C9'): need(c['verdict']=='OPEN','semantic_overclaim')
    if legacy:
        need(r['legacy_claims_sha256']==CLAIMS_SHA and r['legacy_receipt_sha256']==RECEIPT_SHA and r['legacy_receipt_git_blob']==RECEIPT_BLOB and r['legacy_protocol_commit']==PROTOCOL_COMMIT and r['legacy_run_commit']==RUN_COMMIT,'legacy_reference')
        for x in r['results']:
            for c in x['components']: need(c['verdict']==('PASS' if c['id'] in ('C2','C6','legacy_diff_subset','legacy_dwLength') else 'OPEN'),'legacy_upgrade')
        old_path=PROFILE_PATH.with_name('historical')/'1983499b83c4049b85ef7a0295b1748e32e77129d89d21117ffb3bb1ffedf25d.json'
        raw=old_path.read_bytes(); need(digest(raw)==old_path.stem,'legacy_pinned_import')
        old=read_canonical(raw); old['version']='0.3.1-legacy-import'; old['summary']=legacy_summary(old['results'])
        need(old==r,'legacy_import_mismatch'); expected=old['summary']
    else:
        check_identity(r)
        successful={}; need(set(r['diagnostics'])==set(ROMS),'diagnostic_roles')
        need(set(r['certificates'])==set(ROMS)-set(r['input_errors']),'certificate_roles')
        for role, sha in ROMS.items():
            a=r['artifacts'].get(role); error=r['input_errors'].get(role); q=r['diagnostics'][role]
            if error is None:
                need(a is not None and a['sha256']==sha and a['size']==16777216,'artifact_identity')
                cert=r['certificates'][role]
                need(type(cert) is dict and set(cert)=={'artifact_sha256','regions'} and cert['artifact_sha256']==sha,'certificate_binding')
                if 'coverage' in q:
                    successful[role]=check_diagnostics(q,sha,16777216,cert)
                else:
                    need('error' in q,'diagnostic_error')
                    if 'lineage' in q:
                        sizes=check_lineage(q['lineage'],sha,16777216)
                        within(q,sizes); need(type(q['stage']) is str,'error_stage')
            else:
                need('error' in q and 'coverage' not in q,'diagnostic_without_input')
        for x in r['results']:
            selection=x['selection']
            _,size,count=TARGETS[x['id']]
            need({c['id']:c for c in recompute(x,size,count)}=={c['id']:c for c in x['components']},'receipt_verdict_mismatch')
            need(set(selection)==set(successful),'selection_role_set')
            for role,s in selection.items():
                need(role not in r['input_errors'] and role in r['diagnostics'],'selection_without_input')
                check_selection(s,successful[role])
                for k in ('coverage','issues','opaque','uninterpreted_leaves','deleted_uninterpreted','pad_count','lineage'):
                    need(s[k]==r['diagnostics'][role][k],'diagnostic_mismatch')
            ready=set(selection)=={'a','b'} and all('payload' in v and v['derivation']=='verified' and v['selection'] in ('unique','equivalent_content_class') and not v['issues'] for v in selection.values())
            for c in x['components']:
                if c['id'] in ('C2','C3','C4_plausibility','C5','C6','C7','C8') and c['verdict'] in ('PASS','FAIL'):
                    need(ready,'result_without_derived_inputs')
                    need(c['assurance']==('derived_in_supported_grammar' if all(v['coverage']=='grammar_complete' for v in selection.values()) else 'conditional_coverage'),'assurance_mismatch')
        expected=summary(r)
    need(expected==r['summary'],'receipt_summary_mismatch')
    return expected

def main():
    p=argparse.ArgumentParser();p.add_argument('receipt');a=p.parse_args()
    try:
        path=pathlib.Path(a.receipt); raw=read_bounded(path,8*1024**2);need(path.name==digest(raw)+'.json','receipt_filename_hash');r=read_canonical(raw);s=validate(r)
        print('# P2-47 — generated handoff (not execution attestation)')
        print('Receipt SHA-256:',digest(raw))
        print('Pilot exit criterion (recorded, not independently replayed):',s.get('exit_criterion','not_applicable_legacy'))
        if 'run_error' in r:
            print('Aborted execution:',r['run_error']); print('No component results.'); return 0
        import json
        for k,v in s.items(): print(k+': '+(', '.join(v) if isinstance(v,list) else json.dumps(v,sort_keys=True) if isinstance(v,dict) else v))
        from collections import Counter
        for role,q in r.get('diagnostics',{}).items():
            if 'coverage' in q:
                print('\n'+role+' coverage: '+q['coverage']+'; opaque='+str(len(q['opaque']))+'; uninterpreted_leaves='+str(len(q['uninterpreted_leaves']))+'; deleted_uninterpreted='+str(len(q['deleted_uninterpreted'])))
                print('  leaf kinds: '+json.dumps(dict(Counter(x['kind'] for x in q['uninterpreted_leaves'])),sort_keys=True))
                print('  opaque ranges: '+json.dumps(q['opaque'],sort_keys=True))
                print('  Complete leaf/deleted ranges: in receipt; not proof of global absence.')
            elif 'error' in q:
                print('\n'+role+' structural/input blocker: '+json.dumps(q,sort_keys=True))
        for x in r['results']:
            print('\n'+x['id']+' '+x['guid'])
            for c in x['components']: print('  '+c['id']+': '+c['verdict']+' ['+c['assurance']+']'+(' — '+c['reason'] if c['reason'] else ''))
        if 'input_errors' in r: print('\nInput errors:',r['input_errors'])
        return 0
    except (OSError,Invalid,KeyError,TypeError,ValueError,IndexError,AttributeError,OverflowError) as e: print('HANDOFF_REJECTED',str(e),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
