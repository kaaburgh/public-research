"""M75n P2-47 fixed pilot profile. Separate measurements from acceptance. No firmware writes."""
import argparse, datetime, json, pathlib, sys, uuid, os
from checker import Checker, Invalid, canonical, read_canonical, digest, need, u, PKCS7, X509, MAX_BYTES
from discovery import propose
from verdicts import selection_components, pair_components, record, timestamp

VERSION='0.3.2-draft'
ROMS={'a':'7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145','b':'fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498'}
TARGETS={
 'SB-001':('CC0F8A3F-3DEA-4376-9679-5426BA0A907E',842,1),
 'SB-002':('9FE7DE69-0AEA-470A-B50A-139813649189',3908,3),
 'SB-003':('FBF95065-427F-47B3-8077-D13C60710998',9485,7)}
EXPECTED_DIFF=[0,2,3,4,5,6]
REFERENCE_HASHES={"SB-001":["8d1ef5a32a826b698e4aa1c433948e28c18f440d3f4959ef372645d52f1d1760","004035b62688a0fc9579cccafcea872db381e2722743e281dfac1f31355e3592"],"SB-002":["cde335afcc53dd3ac9d959e9ce99bad7b06f658e057cb57f4ea15721de2da404","e570d3fc5313bfeae868d86692306b9185d1dafd3f893478b0321770b8f610a5"],"SB-003":["0848e78f2e6e9f859cd3ba1206b9df171c78035a09749e7c7417dfa31afa4bf2","d81634e7642017ce28ee43c9d783dd103b3a90057a224a902ff12ad638ae3094"]}
PROFILE_PATH=pathlib.Path(__file__).with_name('profile.json')
NON_CLAIMS=['installed_databases','runtime_policy','1.24_to_1.32','other_factory_stores','certificate_der_validity','signature_authenticity','boot_role','flash_safety','global_absence']

def profile():
    p=read_canonical(PROFILE_PATH.read_bytes())
    need(p['artifact_roles']=={k:{'sha256':v,'size':16777216} for k,v in ROMS.items()} and p['targets']==[{'id':k,'guid':v[0],'size_each':v[1],'x509_entry_count_each':v[2]} for k,v in TARGETS.items()] and p['exact_diff_offsets']==EXPECTED_DIFF and p['non_claims']==NON_CLAIMS and p['reference_payload_sha256']==REFERENCE_HASHES and p['version']==VERSION,'profile_mismatch')
    return p

def header_view(b):
    if len(b)<40: return None
    return {'dwLength':u(b,16,4),'wRevision':u(b,20,2),'wCertificateType':u(b,22,2),'CertType':str(uuid.UUID(bytes_le=b[24:40])).upper()}

def header_matches(b):
    return header_view(b)=={'dwLength':24,'wRevision':0x200,'wCertificateType':0xef1,'CertType':str(uuid.UUID(bytes_le=PKCS7)).upper()}

def signature_lists(b):
    # Full consumption of bounded layout; not DER, PKCS7 signature or certificate validation.
    if len(b)<=40: return None
    p=40; out=[]
    while p<len(b):
        if len(b)-p<28: return None
        if len(out)>=4096: return {'limit':4096,'parsed_entries':sum(q['entries'] for q in out)}
        size,head,entry=u(b,p+16,4),u(b,p+20,4),u(b,p+24,4)
        if not (28<=size<=len(b)-p and head<=size-28 and entry>16): return None
        data=size-28-head
        if data==0 or data%entry: return None
        count=data//entry
        out.append({'type':str(uuid.UUID(bytes_le=b[p:p+16])).upper(),'header_size':head,'entry_size':entry,'entries':count})
        p+=size
    return out

def compare_pair(a,b,size,count,level):
    sizes=[len(a),len(b)]
    if len(a)!=len(b): d={'length_mismatch':sizes}
    else:
        d=[]
        for i,(x,y) in enumerate(zip(a,b)):
            if x!=y:
                d.append(i)
                if len(d)>4096: d={'exceeds':4096}; break
    lists=[signature_lists(a),signature_lists(b)]
    observations={'C2':sizes,'C3':d,'C4_plausibility':[x[:16].hex() if len(x)>=16 else None for x in (a,b)],
        'C5':[header_view(a),header_view(b)],
        'C6':{'suffix_sha256':[digest(a[40:]),digest(b[40:])],'lengths':[max(0,len(a)-40),max(0,len(b)-40)],'equal':min(sizes)>=40 and a[40:]==b[40:]},
        'C7':lists,'C8':lists}
    return pair_components(observations,sizes,size,count,level)

def evaluate(roms,certs,targets=TARGETS):
    selected={}; diagnostics={}
    for role in ('a','b'):
        if role not in roms: diagnostics[role]={'error':'rom_missing'}; continue
        if role not in certs: diagnostics[role]={'error':'certificate_missing'}; continue
        try:
            c=Checker(roms[role],[x[0] for x in targets.values()]).run(certs[role])
            selected[role]={id:c.select(x[0]) for id,x in targets.items()}
            diagnostics[role]={'coverage':c.coverage(),'issues':c.issues,'opaque':c.opaque,'uninterpreted_leaves':c.leaves,'deleted_uninterpreted':c.deleted_leaves,'pad_count':c.pad_count,'lineage':c.lineage,'root_regions':certs[role]}
        except Invalid as e: diagnostics[role]=e.diagnostic()
    results=[]
    for id,(g,size,count) in targets.items():
        rows={r:selected[r][id] for r in selected}; assurance={r:v[1] for r,v in rows.items()}
        for role,v in rows.items():
            if v[0] is not None: assurance[role]['payload']={'sha256':digest(v[0]),'size':len(v[0])}
        c1,mult,ready,level=selection_components(assurance)
        components=[c1,mult]
        if ready: components+=compare_pair(rows['a'][0],rows['b'][0],size,count,level)
        else:
            for cid in ('C2','C3','C4_plausibility','C5','C6','C7','C8'): components.append(record(cid,'BLOCKED','unresolved',None,'payload_unavailable'))
            for cid in ('C4','C9'): components.append(record(cid,'OPEN','interpretation'))
        results.append({'id':id,'guid':g,'selection':assurance,'components':components})
    return {'diagnostics':diagnostics,'results':results}

def state(rows,ids):
    # Only exact required components can support a proposition. No majority vote or percentage.
    if not rows: return 'unverified'
    c=[next((z for z in r['components'] if z['id']==i),None) for r in rows for i in ids]
    if any(x is not None and x['verdict']=='FAIL' and x['assurance']=='derived_in_supported_grammar' for x in c): return 'refuted_within_supported_grammar'
    if any(x is not None and x['verdict']=='FAIL' for x in c): return 'conditional_refutation'
    if not all(x is not None and x['verdict']=='PASS' for x in c): return 'unverified'
    if all(x['assurance']=='derived_in_supported_grammar' for x in c): return 'derived_within_supported_grammar'
    return 'consistent_conditional'

def historical_components(rows):
    """Derived historical clauses, never upgrades the exact C3 contract."""
    out=[]
    for row in rows:
        by={c['id']:c for c in row['components']}
        c=by['C3']; d=c['observed']; level=c['assurance']
        measured=c['verdict'] in ('PASS','FAIL')
        scope=isinstance(d,list) and set(d)<=set(EXPECTED_DIFF)
        def clause(id,ok,obs,measured=measured,level=level):
            return record(id,'PASS' if ok else 'FAIL',level,obs) if measured else record(id,'BLOCKED','unresolved')
        h=by['C5']; lists=by['C7']
        hs=h['observed']
        ls=lists['observed']
        # The historical report states dwLength and X509 count, not every newer layout hypothesis.
        dw=clause('historical_dwLength',isinstance(hs,list) and all(x is not None and x['dwLength']==24 for x in hs),hs,h['verdict'] in ('PASS','FAIL'),h['assurance'])
        expected=TARGETS.get(row['id'],(None,None,None))[2]
        complete=isinstance(ls,list) and all(isinstance(z,list) for z in ls)
        x509=str(uuid.UUID(bytes_le=X509)).upper()
        cnt=clause('historical_x509_count',complete and all(all(q['type']==x509 for q in z) and sum(q['entries'] for q in z)==expected for z in ls),ls,expected is not None and lists['verdict'] in ('PASS','FAIL'),lists['assurance'])
        out.append({'id':row['id'],'components':row['components']+[clause('historical_diff_bound',scope,d),clause('historical_diff_scope',scope and bool(d),d),clause('timestamp_only_bytes',isinstance(d,list) and all(i<16 for i in d),d),dw,cnt]})
    return out

def summary(r):
    rows=r['results']
    hist=historical_components(rows)
    props={name:state(rows,ids) for name,ids in profile()['propositions'].items()}
    def conjunction(source,ids):
        result=state(source,ids)
        if result in ('conditional_refutation','refuted_within_supported_grammar'): return result
        relevant=[c for row in source for c in row['components'] if c['id'] in ids]
        if not any(c['verdict'] in ('PASS','FAIL') for c in relevant): return 'not_evaluated'
        return 'partial_not_established' if result=='unverified' else result
    # C1 is a selection prerequisite, not a refutation of the historical byte finding.
    historical_ids=['C2','historical_diff_bound','historical_dwLength','C6','C7','historical_x509_count','C4']
    full=conjunction(hist,historical_ids)
    if state(rows,['C1']) not in ('consistent_conditional','derived_within_supported_grammar'):
        full='partial_not_established' if any(c['verdict'] in ('PASS','FAIL') for row in rows for c in row['components'] if c['id'] not in ('C1','multiplicity')) else 'not_evaluated'
    gate=differential(r)
    complete={row['id'] for row in rows}==set(TARGETS) and len(rows)==len(TARGETS) and not r.get('input_errors') and not any(c['verdict']=='BLOCKED' for row in rows for c in row['components'])
    return {**props,'exact_diff_set':state(rows,['C3']),'historical_diff_scope':state(hist,['historical_diff_scope']),
        'historical_diff_bound':state(hist,['historical_diff_bound']),'historical_dwLength':state(hist,['historical_dwLength']),
        'historical_x509_count':state(hist,['historical_x509_count']),'timestamp_only_bytes':state(hist,['timestamp_only_bytes']),
        'timestamp_plausibility':state(rows,['C4_plausibility']),'timestamp_only_semantic_conclusion':timestamp_scope(rows),
        'variable_roles':'unverified','P2-47_full':full,'differential_gate':gate,
        'exit_criterion':'met' if complete and gate['status']=='all_six_match' else 'not_met','non_claims':NON_CLAIMS}

def timestamp_scope(rows):
    # A different exact offset set does not disprove timestamp-only if all changed bytes remain in EFI_TIME.
    c=[x for row in rows for x in row['components'] if x['id']=='C3' and x['verdict'] in ('PASS','FAIL')]
    bad=[x for x in c if isinstance(x['observed'],dict) or any(i>=16 for i in x['observed'])]
    if bad: return 'refuted_within_supported_grammar' if any(x['assurance']=='derived_in_supported_grammar' for x in bad) else 'conditional_refutation'
    return 'partial_not_established' if c else 'not_evaluated'

def differential(r):
    matches=[]; mismatches=[]; missing=[]
    for tid,expected in REFERENCE_HASHES.items():
        row=next((x for x in r['results'] if x['id']==tid),None)
        for i,role in enumerate(('a','b')):
            x=row['selection'].get(role,{}).get('payload') if row and isinstance(row['selection'],dict) else None
            label=tid+'/'+role
            if x is None: missing.append(label)
            elif x['sha256']==expected[i]: matches.append(label)
            else: mismatches.append(label)
    return {'status':'mismatch' if mismatches else 'not_evaluated' if missing else 'all_six_match','matches':matches,'mismatches':mismatches,'missing':missing}

def read_bounded(path,limit):
    with open(path,'rb') as f: b=f.read(limit+1)
    need(len(b)<=limit,'file_limit'); return b

def write_receipt(directory,r):
    raw=canonical(r); name=digest(raw)+'.json'
    try:
        pathlib.Path(directory).mkdir(parents=True,exist_ok=True)
        with open(pathlib.Path(directory)/name,'xb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
    except OSError:
        print('RECEIPT_WRITE_FAILED',file=sys.stderr); sys.stdout.buffer.write(raw); return False
    print(name); return True

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument('--rom-a',required=True); p.add_argument('--rom-b',required=True); p.add_argument('--certificate-a'); p.add_argument('--certificate-b'); p.add_argument('--receipts',required=True); args=p.parse_args(argv)
    profile()
    r={'profile_sha256':digest(PROFILE_PATH.read_bytes()),'version':VERSION,'run_id':str(uuid.uuid4()),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runtime':sys.version.split()[0],'tool_sha256':{name:digest(pathlib.Path(__file__).with_name(name).read_bytes()) for name in ('pilot.py','checker.py','verdicts.py','discovery.py')},'artifacts':{},'certificates':{},'diagnostics':{},'results':[]}
    roms={}; certs={}; errors={}
    stage='input'
    try:
        for role in ('a','b'):
            try:
                b=read_bounded(getattr(args,'rom_'+role),MAX_BYTES); actual=digest(b); r['artifacts'][role]={'sha256':actual,'size':len(b),'expected_sha256':ROMS[role]}
                need(actual==ROMS[role] and len(b)==16777216,'rom_identity'); roms[role]=b
                path=getattr(args,'certificate_'+role)
                cert=read_canonical(read_bounded(path,8*1024**2)) if path else {'artifact_sha256':actual,'regions':propose(b)}
                need(type(cert) is dict and set(cert)=={'artifact_sha256','regions'} and cert['artifact_sha256']==actual,'certificate_binding')
                r['certificates'][role]=cert; certs[role]=cert['regions']
            except (OSError,Invalid) as e: errors[role]=str(e) if isinstance(e,Invalid) else 'input_io'; roms.pop(role,None)
        r['input_errors']=errors
        stage='evaluate'
        r.update(evaluate(roms,certs))
        stage='summary'; r['summary']=summary(r)
        stage='receipt_encoding'; need(len(canonical(r))<=8*1024**2,'receipt_size')
    except Exception as e:
        # Preserve an attempt, never a fabricated set of measured results. No arbitrary exception strings or private paths.
        code=str(e) if isinstance(e,Invalid) and str(e).isascii() and str(e).replace('_','').isalnum() else type(e).__name__
        r['input_errors']=errors
        r['run_error']={'stage':stage,'code':code}
        r['results']=[]; r['diagnostics']={}
        r['certificate_sha256']={role:digest(canonical(c)) for role,c in r['certificates'].items()}
        r['certificates']={}
        r['summary']=error_summary()
        return 2 if write_receipt(args.receipts,r) else 3
    if not write_receipt(args.receipts,r): return 3
    return exit_code(r)

def error_summary():
    return {'P2-47_full':'not_evaluated','exit_criterion':'not_met','execution':'aborted','non_claims':NON_CLAIMS}

def exit_code(r):
    # 0 = measured checks passed AND differential gate met. 1 = a checked predicate refuted.
    # 2 = incomplete/aborted, 3 = write failure (main), 4 = complete inputs disagree with reference hashes.
    if 'run_error' in r: return 2
    states=[x['verdict'] for y in r['results'] for x in y['components'] if x['id'] not in ('C4','C9')]
    gate=r['summary']['differential_gate']
    if r.get('input_errors') or gate['missing']: return 2
    if gate['status']=='mismatch': return 4
    if 'FAIL' in states: return 1
    return 2 if 'BLOCKED' in states or r['summary']['exit_criterion']!='met' else 0

if __name__=='__main__': sys.exit(main())
