#!/usr/bin/env python3
"""Regression checks for reconstructed M75n platform inspectors; no private output files."""
import argparse, collections, struct
from pathlib import Path
import amd_data as amd
import nvram_inspect as nv
import acpi_inventory as acpi

def check(ok,msg):
    if not ok:raise AssertionError(msg)
def expect_value_error(fn):
    try:fn()
    except ValueError:return
    raise AssertionError('malformed input accepted')
def unit_checks():
    # Two packed EFI_DEVICE_PATH instances with separate End Entire nodes.
    node=bytes((1,1,4,0));end=bytes((0x7f,0xff,4,0));dp=(node+end)*2
    load=struct.pack('<IH',1,len(dp))+b'\0\0'+dp
    check(nv.load_option(load),'packed paths rejected')
    check(not nv.load_option(load[:-1]),'truncated path accepted')
    check(not nv.load_option(load[:8]+bytes((1,1,0,0))+load[12:]),'zero node length accepted')
    check(not nv.load_option(load[:-3]+bytes((0xff,3,0))),'bad end node accepted')
    desc=struct.pack('<III',0x00001601,0x00601b01,0x001fff00)
    check(amd.tokens(desc+b'\x00\x00\x01\x00\x00')=={0x16:0,0x1b:256},'token width/value')
    expect_value_error(lambda:amd.tokens(desc[:-4]))
    expect_value_error(lambda:amd.tokens(desc+b'\x00'))
    expect_value_error(lambda:amd.directories(bytes(32)))

def main():
    p=argparse.ArgumentParser();p.add_argument('workdir',type=Path,nargs='?');a=p.parse_args();unit_checks();print('synthetic boundary tests: PASS')
    if a.workdir is None:return
    base=a.workdir;vs=('124','132','133');roms=[(base/(v+'.rom')).read_bytes() for v in vs];ds=[amd.inspect(b) for b in roms]
    for d in ds:
        check(sum(map(len,d['directories'].values()))==125,'directory count');check(len(d['apcb'])==48,'APCB count');check(len(d['microcode'])==3,'microcode count')
    broken=bytearray(roms[0]);broken[0x82004]^=1;expect_value_error(lambda:amd.directories(broken))
    block=bytearray(roms[0][0x146000:0x148000]);block[32]^=1;expect_value_error(lambda:amd.apcb(block))
    def metadata(d):return {k:[{a:b for a,b in r.items() if a!='sha256'} for r in rows] for k,rows in d['directories'].items()}
    check(all(metadata(d)==metadata(ds[0]) for d in ds),'directory metadata changed')
    check(all(d['directories'][k]==ds[0]['directories'][k] for d in ds for k in ('$PSP','$PL2')),'PSP payloads changed')
    def blocks(d):return {o:r['normalized_sha256'] for o,r in d['apcb'].items()}
    check(blocks(ds[1])==blocks(ds[2]),'stock APCB changed')
    check(sum(blocks(ds[0])[o]!=h for o,h in blocks(ds[2]).items())==1,'live APCB difference count')
    check([[r['revision'] for r in d['microcode'].values()] for d in ds]==[[0x08108109,0x08108002,0x08200103],[0x0810810e,0x08108002,0x08200105],[0x0810810e,0x08108002,0x08200105]],'patch revisions')
    print('AMD directories/APCB/microcode: PASS')
    roots=[base/(v+'.rom.dump') for v in vs];ns=[nv.inspect(r) for r in roots]
    for n in ns:
        check(bool(n['defaults']) and all(len(x)==13 and x==n['defaults'][0] for x in n['defaults']),'StdDefaults copies')
        for s in n['live']:
            check(not s['issues'],'selected NVAR chain ambiguity')
            if 'boot_order_count' in s:check(s['boot_order_count']==s['boot_valid_count'],'invalid boot path')
    changed=[k.split('|')[0] for k,v in ns[0]['defaults'][0].items() if v!=ns[2]['defaults'][0].get(k)]
    check(changed==['Setup'],'unexpected defaults changes');check(ns[1]['defaults'][0]==ns[2]['defaults'][0],'stock defaults changed')
    print('NVAR selected chains/StdDefaults: PASS (active store not identified)')
    ac=[acpi.inspect(r) for r in roots]
    def multiset(rows):return {r['sha256']:len(r['occurrences']) for r in rows}
    check(all(collections.Counter(r['signature'] for r in x)=={'DSDT':1,'SSDT':32} and multiset(x)==multiset(ac[0]) for x in ac),'ACPI tables/multiplicity')
    print('static DSDT/SSDT: PASS')
if __name__=='__main__':main()
