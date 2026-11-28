"""Compare two accepted current-version receipts, not attest independence.
Run separately on original ROMs. Different hints may legitimately change the
trace; a non-match is not an automatic refutation of a research assertion.
"""
import argparse, pathlib, sys
from checker import canonical, read_canonical, digest, need, Invalid
from handoff import validate
from pilot import VERSION, read_bounded

def load(path):
    p=pathlib.Path(path); raw=read_bounded(p,8*1024**2)
    need(p.name==digest(raw)+'.json','receipt_filename_hash')
    r=read_canonical(raw); validate(r)
    need(r['version']==VERSION and 'run_error' not in r,'replay_current_completed_receipt')
    return r,digest(raw)

def compare(a,b):
    # Metadata exclusion is an explicit contract. No normalization of observed data.
    aa={k:v for k,v in a.items() if k not in ('run_id','utc','runtime')}
    bb={k:v for k,v in b.items() if k not in ('run_id','utc','runtime')}
    diff=sorted(k for k in set(aa)|set(bb) if k not in aa or k not in bb or aa[k]!=bb[k])
    return {'same_run_id':a['run_id']==b['run_id'],'normalized_equal':not diff,'different_fields':diff,
            'normalized_sha256':[digest(canonical(aa)),digest(canonical(bb))],
            'independence':'not_attested','assurance_upgrade':False,
            'coverage':[a['summary']['exit_criterion'],b['summary']['exit_criterion']]}

def main():
    p=argparse.ArgumentParser();p.add_argument('first');p.add_argument('second');args=p.parse_args()
    try:
        a,ha=load(args.first); b,hb=load(args.second)
        result={**compare(a,b),'receipt_sha256':[ha,hb]}
        sys.stdout.buffer.write(canonical(result))
        return 0 if result['normalized_equal'] else 1
    except (OSError,ValueError,KeyError,TypeError,IndexError,AttributeError) as e:
        print('REPLAY_COMPARE_REJECTED',type(e).__name__,file=sys.stderr); return 2
if __name__=='__main__': sys.exit(main())
