"""Shared decision rules: logical consistency, not execution attestation."""
import uuid, datetime
from checker import need, u, PKCS7, X509
DIFF=[0,2,3,4,5,6]
PKCS7_ID=str(uuid.UUID(bytes_le=PKCS7)).upper()
X509_ID=str(uuid.UUID(bytes_le=X509)).upper()
PAIR_IDS=('C2','C3','C4_plausibility','C5','C6','C7','C8')

def record(id,verdict,assurance,observed=None,reason=None):
    return {'id':id,'verdict':verdict,'assurance':assurance,'observed':observed,'reason':reason}

def count(x):
    return type(x) is int and x>=0

def hash_id(x):
    return isinstance(x,str) and len(x)==64 and all(c in '0123456789abcdef' for c in x)

def timestamp(b):
    # Plausibility only, not proof that producer interprets bytes as EFI_TIME.
    if len(b)<16: return False
    tz=int.from_bytes(b[12:14],'little',signed=True)
    try: datetime.datetime(u(b,0,2),b[2],b[3],b[4],b[5],b[6])
    except ValueError: return False
    return 1900<=u(b,0,2)<=9999 and b[7]==0 and u(b,8,4)<=999999999 and (-1440<=tz<=1440 or tz==2047) and b[14]&~3==0 and b[15]==0


def inspect_selection(s):
    need(s['derivation']=='verified' and s['scope']=='supported_PI_grammar','selection_scope')
    owners=s['owners']; live=[o for o in owners if o['state']=='data_valid']; marked=[o for o in owners if o['state']=='marked_for_update']
    need(all(o['state'] in ('data_valid','marked_for_update','deleted') for o in owners),'owner_state')
    counts={'data_valid':len(live),'deleted':sum(o['state']=='deleted' for o in owners),'marked_for_update':len(marked),'raw_per_live':[len(o['raw']) for o in live]}
    need(counts==s['counts'],'selection_counts')
    coverage='incomplete' if s['issues'] else 'except_opaque' if s['opaque'] or s['uninterpreted_leaves'] else 'grammar_complete'
    need(s['coverage']==coverage,'selection_coverage')
    ready=not s['issues'] and not marked and bool(live) and all(len(o['raw'])==1 and not o['opaque'] for o in live)
    raws=[o['raw'][0] for o in live] if ready else []
    if ready:
        need(all(hash_id(x['sha256']) and count(x['size']) for x in raws),'raw_identity')
        ready=all((x['sha256'],x['size'])==(raws[0]['sha256'],raws[0]['size']) for x in raws)
    if ready:
        need(s.get('selection')==('unique' if len(live)==1 else 'equivalent_content_class'),'selection_kind')
        need(s.get('payload')=={'sha256':raws[0]['sha256'],'size':raws[0]['size']},'selection_payload')
        need(s.get('locators')==[{k:v for k,v in q.items() if k!='sha256'} for q in raws],'selection_locator')
    else: need('payload' not in s and 'selection' not in s,'unresolved_payload')
    return counts, ready

def selection_components(selection):
    need(set(selection)<= {'a','b'},'selection_roles')
    info={r:inspect_selection(s) for r,s in selection.items()}
    level='derived_in_supported_grammar' if len(info)==2 and all(s['coverage']=='grammar_complete' for s in selection.values()) else 'conditional_coverage'
    duplicate=any(c['data_valid']>1 or any(n>1 for n in c['raw_per_live']) for c,_ in info.values())
    ready=len(info)==2 and all(x[1] for x in info.values())
    unique=ready and all(s['selection']=='unique' for s in selection.values())
    opaque_owner=any(o['opaque'] for s in selection.values() for o in s['owners'] if o['state']=='data_valid')
    c1=record('C1','FAIL' if duplicate else 'PASS' if unique else 'BLOCKED',level if duplicate or unique else 'unresolved',selection,None if duplicate or unique else 'opaque_in_owner' if opaque_owner else 'selection_unresolved')
    counts_ok=len(info)==2 and all(c['data_valid']>0 and not selection[r]['issues'] and not c['marked_for_update'] and not any(o['opaque'] for o in selection[r]['owners'] if o['state']=='data_valid') for r,(c,_) in info.items())
    if counts_ok:
        a,b=(info[r][0] for r in ('a','b')); mult=record('multiplicity','PASS' if a==b else 'FAIL',level,{'a':a,'b':b},None if a==b else 'multiplicity_changed')
    else: mult=record('multiplicity','BLOCKED','unresolved',None,'counts_unresolved')
    return c1,mult,ready,level

def pair_components(obs,sizes,expected_size,expected_count,level):
    need(set(obs)==set(PAIR_IDS),'pair_observation_set')
    need(obs['C2']==sizes,'size_observation')
    result=[]
    def add(id,ok,o): result.append(record(id,'PASS' if ok else 'FAIL',level,o))
    add('C2',sizes==[expected_size]*2,sizes)
    d=obs['C3']
    if sizes[0]!=sizes[1]: need(d=={'length_mismatch':sizes},'diff_length')
    elif type(d) is dict: need(d=={'exceeds':4096} and sizes[0]>4096,'diff_limit')
    else: need(type(d) is list and len(d)<=4096 and all(count(x) and x<sizes[0] for x in d) and d==sorted(set(d)),'diff_offsets')
    add('C3',d==DIFF,d)
    t=obs['C4_plausibility']; need(type(t) is list and len(t)==2,'timestamp_observation')
    for i,x in enumerate(t):
        if sizes[i]<16: need(x is None,'timestamp_bounds')
        else: need(type(x) is str and len(x)==32 and all(c in '0123456789abcdef' for c in x),'timestamp_bytes')
    add('C4_plausibility',all(x is not None and timestamp(bytes.fromhex(x)) for x in t),t)
    result.append(record('C4','OPEN','interpretation',None,'timestamp_semantics_not_established'))
    h=obs['C5']; need(type(h) is list and len(h)==2,'header_observation')
    for i,x in enumerate(h):
        if sizes[i]<40: need(x is None,'header_bounds')
        else: need(type(x) is dict and set(x)=={'dwLength','wRevision','wCertificateType','CertType'} and all(count(x[k]) for k in ('dwLength','wRevision','wCertificateType')) and x['dwLength']<2**32 and x['wRevision']<2**16 and x['wCertificateType']<2**16 and str(uuid.UUID(x['CertType'])).upper()==x['CertType'],'header_fields')
    add('C5',all(x=={'dwLength':24,'wRevision':0x200,'wCertificateType':0xef1,'CertType':PKCS7_ID} for x in h),h)
    tail=obs['C6']; need(type(tail) is dict and set(tail)=={'suffix_sha256','lengths','equal'} and tail['lengths']==[max(0,n-40) for n in sizes] and len(tail['suffix_sha256'])==2 and all(hash_id(x) for x in tail['suffix_sha256']) and type(tail['equal']) is bool,'suffix_observation')
    equal=min(sizes)>=40 and tail['lengths'][0]==tail['lengths'][1] and tail['suffix_sha256'][0]==tail['suffix_sha256'][1]
    need(equal==tail['equal'],'suffix_consistency')
    if min(sizes)>=40 and sizes[0]==sizes[1] and isinstance(d,list):
        need(equal==(not any(i>=40 for i in d)),'diff_suffix_consistency')
    add('C6',equal,tail)
    x,y=obs['C7'],obs['C8']; need(x==y and type(x) is list and len(x)==2,'list_observation_disagreement')
    def classify(z,i):
        if z is None: return 'invalid',False
        if type(z) is dict:
            need(set(z)=={'limit','parsed_entries'} and z['limit']==4096 and count(z['parsed_entries']) and z['parsed_entries']>=4096 and sizes[i]>=40+4096*45 and z['parsed_entries']*17<=sizes[i]-40,'list_limit_observation')
            return 'partial',False if z['parsed_entries']>expected_count else None
        need(type(z) is list and 0<len(z)<=4096,'list_count')
        total=0
        for q in z:
            need(type(q) is dict and set(q)=={'type','header_size','entry_size','entries'} and str(uuid.UUID(q['type'])).upper()==q['type'] and all(count(q[k]) for k in ('header_size','entry_size','entries')) and q['entry_size']>16 and q['entries']>0,'list_fields')
            total+=28+q['header_size']+q['entry_size']*q['entries']
        need(total==sizes[i]-40,'list_consumption')
        return 'complete',all(q['type']==X509_ID and q['header_size']==0 for q in z) and sum(q['entries'] for q in z)==expected_count
    info=[classify(z,i) for i,z in enumerate(x)]
    if any(kind=='invalid' for kind,_ in info): add('C7',False,x)
    elif all(kind=='complete' for kind,_ in info): add('C7',True,x)
    else: result.append(record('C7','BLOCKED','unresolved',x,'signature_list_limit'))
    if any(ok is False for _,ok in info): add('C8',False,x)
    elif all(ok is True for _,ok in info): add('C8',True,x)
    else: result.append(record('C8','BLOCKED','unresolved',x,'signature_list_limit'))
    result.append(record('C9','OPEN','interpretation',None,'variable_role_not_established'))
    return result

def recompute(row,size,count_expected):
    c1,mult,ready,level=selection_components(row['selection'])
    components=[c1,mult]
    if ready:
        by={c['id']:c for c in row['components']}
        sizes=[row['selection'][r]['payload']['size'] for r in ('a','b')]
        components+=pair_components({id:by[id]['observed'] for id in PAIR_IDS},sizes,size,count_expected,level)
    else:
        components += [record(id,'BLOCKED','unresolved',None,'payload_unavailable') for id in PAIR_IDS]
        components += [record(id,'OPEN','interpretation') for id in ('C4','C9')]
    return components
