#!/usr/bin/env python3
"""Check key coverage and per-release payload multisets, accounting for redacted hashes.
No semantic claims. An ordinal mismatch is reported separately from missing content.
"""
import argparse, collections, csv
from pathlib import Path
KEY=('guid','instance','section','section_instance')
def read(p):
    with p.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f,delimiter='\t'))
    d={tuple(r[k] for k in KEY):r for r in rows}
    if len(d)!=len(rows):raise ValueError(f'duplicate keys: {p}')
    return d

def main():
    p=argparse.ArgumentParser();p.add_argument('reference',type=Path);p.add_argument('generated',type=Path);a=p.parse_args();old,new=read(a.reference),read(a.generated)
    missing=old.keys()-new.keys();extra=new.keys()-old.keys();bad=bool(missing or extra)
    print('keys',len(old),len(new),'missing',len(missing),'extra',len(extra))
    for v in ('124','132','133'):
        # A public reference may redact some hash cells. Match only known hashes,
        # preserve multiplicity, and check counts/sizes independently.
        def hashes(rs):return collections.Counter((r['guid'],r['section'],r['sha'+v]) for r in rs.values() if r.get('sha'+v))
        def sizes(rs):return collections.Counter((r['guid'],r['section'],str(r.get('size'+v,''))) for r in rs.values())
        wanted,got=hashes(old),hashes(new);lack=wanted-got;size_diff=sizes(old)!=sizes(new)
        bad|=bool(lack or size_diff)
        ordinal=[k for k in old.keys()&new.keys() if old[k].get('sha'+v) and old[k]['sha'+v]!=new[k].get('sha'+v)]
        print(v,'known hash records',sum(wanted.values()),'missing multiset items',sum(lack.values()),'size multiset differs',size_diff,'ordinal mismatches',len(ordinal))
        for k in ordinal:print('  ', '|'.join(k),old[k]['module'])
    return bad
if __name__=='__main__':raise SystemExit(main())
