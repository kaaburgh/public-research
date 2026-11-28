"""M75n P2-47 fixed pilot profile. Separate measurements from acceptance. No firmware writes."""
import argparse, datetime, json, pathlib, sys, uuid, os
from checker import Checker, Invalid, canonical, read_canonical, digest, need, propose, u, PKCS7, X509, MAX_BYTES

VERSION='0.3-draft'
ROMS={'a':'7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145','b':'fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498'}
TARGETS={
 'SB-001':('CC0F8A3F-3DEA-4376-9679-5426BA0A907E',842,1),
 'SB-002':('9FE7DE69-0AEA-470A-B50A-139813649189',3908,3),
 'SB-003':('FBF95065-427F-47B3-8077-D13C60710998',9485,7)}
EXPECTED_DIFF=[0,2,3,4,5,6]
PROFILE_PATH=pathlib.Path(__file__).with_name('profile.json')
NON_CLAIMS=['installed_databases','runtime_policy','1.24_to_1.32','other_factory_stores','certificate_der_validity','signature_authenticity','boot_role','flash_safety','global_absence']

def profile():
    p=read_canonical(PROFILE_PATH.read_bytes())
    need(p['artifact_roles']=={k:{'sha256':v,'size':16777216} for k,v in ROMS.items()} and p['targets']==[{'id':k,'guid':v[0],'size_each':v[1],'x509_entry_count_each':v[2]} for k,v in TARGETS.items()] and p['exact_diff_offsets']==EXPECTED_DIFF and p['non_claims']==NON_CLAIMS,'profile_mismatch')
    return p

def record(id,verdict,assurance,observed=None,reason=None):
    return {'id':id,'verdict':verdict,'assurance':assurance,'observed':observed,'reason':reason}

def timestamp(b):
    # Plausibility only, not proof that producer interprets bytes as EFI_TIME.
    if len(b)<16: return False
    tz=int.from_bytes(b[12:14],'little',signed=True)
    try: datetime.datetime(u(b,0,2),b[2],b[3],b[4],b[5],b[6])
    except ValueError: return False
    return 1900<=u(b,0,2)<=9999 and b[7]==0 and u(b,8,4)<=999999999 and (-1440<=tz<=1440 or tz==2047) and b[14]&~3==0 and b[15]==0

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
        if len(out)>=4096: raise Invalid('signature_list_limit')
        size,head,entry=u(b,p+16,4),u(b,p+20,4),u(b,p+24,4)
        if not (28<=size<=len(b)-p and head<=size-28 and entry>16): return None
        data=size-28-head
        if data==0 or data%entry: return None
        count=data//entry
        out.append({'type':str(uuid.UUID(bytes_le=b[p:p+16])).upper(),'header_size':head,'entry_size':entry,'entries':count})
        p+=size
    return out

def compare_pair(a,b,size,count,level):
    result=[]
    def add(id,ok,observed): result.append(record(id,'PASS' if ok else 'FAIL',level,observed))
    add('C2',len(a)==len(b)==size,[len(a),len(b)])
    # Total on verified payloads: differing lengths refute exact offset equality.
    if len(a)!=len(b): add('C3',False,{'length_mismatch':[len(a),len(b)]})
    else:
        d=[]; exceeded=False
        for i,(x,y) in enumerate(zip(a,b)):
            if x!=y:
                d.append(i)
                if len(d)>4096: exceeded=True; break
        add('C3',not exceeded and d==EXPECTED_DIFF,{'exceeds':4096} if exceeded else d)
    add('C4_plausibility',timestamp(a) and timestamp(b),[timestamp(a),timestamp(b)])
    result.append(record('C4','OPEN','interpretation',None,'timestamp_semantics_not_established'))
    add('C5',header_matches(a) and header_matches(b),[header_view(a),header_view(b)])
    add('C6',len(a)>=40 and len(b)>=40 and a[40:]==b[40:],{'suffix_sha256':[digest(a[40:]),digest(b[40:])],'lengths':[max(0,len(a)-40),max(0,len(b)-40)]})
    try: x,y=signature_lists(a),signature_lists(b)
    except Invalid:
        for cid in ('C7','C8'): result.append(record(cid,'BLOCKED','unresolved',None,'signature_list_limit'))
        result.append(record('C9','OPEN','interpretation',None,'variable_role_not_established'))
        return result
    add('C7',x is not None and y is not None,[x,y])
    def matches(z): return z is not None and all(q['type']==str(uuid.UUID(bytes_le=X509)).upper() and q['header_size']==0 for q in z) and sum(q['entries'] for q in z)==count
    add('C8',matches(x) and matches(y),[x,y])
    result.append(record('C9','OPEN','interpretation',None,'variable_role_not_established'))
    return result

def evaluate(roms,certs,targets=TARGETS):
    selected={}; diagnostics={}
    for role in ('a','b'):
        if role not in roms: diagnostics[role]={'error':'rom_missing'}; continue
        try:
            c=Checker(roms[role],[x[0] for x in targets.values()]).run(certs[role])
            selected[role]={id:c.select(x[0]) for id,x in targets.items()}
            diagnostics[role]={'coverage':'incomplete' if c.issues else 'except_opaque' if c.opaque else 'grammar_complete','issues':c.issues,'opaque':c.opaque,'lineage':c.lineage}
        except (Invalid,KeyError) as e: diagnostics[role]={'error':str(e) if isinstance(e,Invalid) else 'certificate_missing'}
    results=[]
    for id,(g,size,count) in targets.items():
        rows={r:selected[r][id] for r in selected}; assurance={r:v[1] for r,v in rows.items()}
        for role,v in rows.items():
            if v[0] is not None: assurance[role]['payload']={'sha256':digest(v[0]),'size':len(v[0])}
        duplicate=any(v[1]['counts']['data_valid']>1 or any(n>1 for n in v[1]['counts']['raw_per_live']) for v in rows.values())
        level='derived_in_supported_grammar' if len(rows)==2 and all(v[1]['coverage']=='grammar_complete' for v in rows.values()) else 'conditional_coverage'
        ready=len(rows)==2 and all(v[0] is not None for v in rows.values())
        unique=ready and all(v[1]['selection']=='unique' for v in rows.values())
        components=[record('C1','FAIL' if duplicate else 'PASS' if unique else 'BLOCKED',level if duplicate or unique else 'unresolved',assurance, None if duplicate or unique else 'selection_unresolved')]
        # Multiplicity is independent of equivalence of payloads; no automatic cross-version pairing.
        if len(rows)==2:
            ca,cb=(rows[r][1]['counts'] for r in ('a','b'))
            components.append(record('multiplicity','PASS' if ca==cb else 'FAIL',level,{'a':ca,'b':cb},None if ca==cb else 'multiplicity_changed'))
        else: components.append(record('multiplicity','BLOCKED','unresolved',None,'input_unavailable'))
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

def summary(r):
    rows=r['results']; return {
        **{name:state(rows,ids) for name,ids in profile()['propositions'].items()},
        'timestamp_only_semantic_conclusion':'unverified',
        'variable_roles':'unverified',
        'P2-47_full':'partial_not_established',
        'non_claims':NON_CLAIMS}

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
    r={'profile_sha256':digest(PROFILE_PATH.read_bytes()),'version':VERSION,'run_id':str(uuid.uuid4()),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'runtime':sys.version.split()[0],'tool_sha256':{name:digest(pathlib.Path(__file__).with_name(name).read_bytes()) for name in ('pilot.py','checker.py')},'artifacts':{},'certificates':{},'diagnostics':{},'results':[]}
    roms={}; certs={}; errors={}
    for role in ('a','b'):
        try:
            b=read_bounded(getattr(args,'rom_'+role),MAX_BYTES); actual=digest(b); r['artifacts'][role]={'sha256':actual,'size':len(b),'expected_sha256':ROMS[role]}
            need(actual==ROMS[role] and len(b)==16777216,'rom_identity'); roms[role]=b
            path=getattr(args,'certificate_'+role)
            cert=read_canonical(read_bounded(path,8*1024**2)) if path else {'artifact_sha256':actual,'regions':propose(b)}
            need(type(cert) is dict and set(cert)=={'artifact_sha256','regions'} and cert['artifact_sha256']==actual,'certificate_binding')
            r['certificates'][role]=cert; certs[role]=cert['regions']
        except (OSError,Invalid) as e: errors[role]=str(e) if isinstance(e,Invalid) else 'input_io'; roms.pop(role,None)
    r.update(evaluate(roms,certs)); r['input_errors']=errors; r['summary']=summary(r)
    if not write_receipt(args.receipts,r): return 3
    # Exit is execution signal, not acceptance. OPEN interpretations are intentionally not success.
    states=[x['verdict'] for y in r['results'] for x in y['components'] if x['id'] not in ('C4','C9')]
    return 1 if 'FAIL' in states else 2 if 'BLOCKED' in states or errors else 0

if __name__=='__main__': sys.exit(main())
