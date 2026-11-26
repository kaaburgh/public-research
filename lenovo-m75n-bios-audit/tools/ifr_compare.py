#!/usr/bin/env python3
"""Extract exact en-US IFR using ifrextract-rs 1.6.1; retain full conditions and IDs."""
import argparse, difflib, hashlib, json, subprocess
from pathlib import Path
MODULES=('Setup','CbsSetupDxeRV','AmdPbsSetupDxe')
def extract(root,tool,out):
    out.mkdir(parents=True,exist_ok=False);result={}
    for name in MODULES:
        matches=[p for p in root.rglob('* '+name) if (p/'info.txt').is_file() and 'File GUID:' in (p/'info.txt').read_text(errors='replace')]
        if len(matches)!=1:raise ValueError(f'{name}: {len(matches)} FFS matches')
        bodies=list(matches[0].glob('* PE32 image section/body.bin'))
        if len(bodies)!=1:raise ValueError(f'{name}: {len(bodies)} PE32 bodies')
        efi=out/(name+'.efi');efi.write_bytes(bodies[0].read_bytes())
        subprocess.run([str(tool.resolve()),str(efi.resolve())],check=True,capture_output=True)
        files=sorted(out.glob(name+'.efi.*.en-US.uefi.ifr.txt'))
        if len(files)!=(2 if name=='Setup' else 1):raise ValueError(f'{name}: unexpected formset count')
        for f in files:
            header,sep,text=f.read_text().partition('\n')
            if not sep or not header.startswith('Program version: 1.6.1, Extraction mode: UEFI, SHA256:'):raise ValueError('unexpected extractor format/version')
            result[f.name]=text
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('roots',nargs=3,type=Path);p.add_argument('--tool',required=True,type=Path);p.add_argument('-o','--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    result=[extract(root,a.tool,a.output/v) for root,v in zip(a.roots,('124','132','133'))]
    keys=sorted(set().union(*(r.keys() for r in result)));report={}
    for k in keys:
        texts=[r[k] for r in result];report[k]=[hashlib.sha256(t.encode()).hexdigest() for t in texts]
        for i,j in ((0,1),(1,2)):
            diff=''.join(difflib.unified_diff(texts[i].splitlines(keepends=True),texts[j].splitlines(keepends=True),fromfile=('124','132','133')[i],tofile=('124','132','133')[j]))
            (a.output/(k+f'.{i}-{j}.diff')).write_text(diff)
    (a.output/'hashes.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
