#!/usr/bin/env python3
"""Conservative well-formed EFI_LOAD_OPTION model for P2-116.
Inputs: UEFITool A75 extracted AFU tree; never writes NVRAM or prints payload/IDs.
Not an emulator or validator for all malformed data. Use only on trusted captures.
"""
import argparse
import collections
from pathlib import Path
import re
import struct

def check(b):
    if not b or len(b)<8: return "missing/short"
    length=struct.unpack_from("<H",b,4)[0]
    limit=len(b)-length
    off=6
    if length<4 or limit<8: return "header/description"
    while off+2<=limit and b[off:off+2]!=b"\0\0":
        off+=2
    if off+2>limit: return "header/description"
    off+=2
    end=off+length
    last=None
    while off+4<=end:
        typ,sub,size=struct.unpack_from("<BBH",b,off)
        last=(typ,sub,size)
        if typ not in (1,2,3,4,5,127) or size<4 or off+size>end:
            return "node"
        off+=size
    return "pass" if off==end and last==(127,255,4) else "termination"

def scan(store):
    opts={}
    for f in store.iterdir():
        if not re.fullmatch(r"\d+ Boot(?:[0-9A-Fa-f]{4}|Order)",f.name):
            continue
        s=(f/"info.txt").read_text()
        if re.search(r"Subtype: (Full|Data)\n",s):
            name=f.name.split(" ")[1]
            if name in opts: raise ValueError("ambiguous terminal record")
            opts[name]=(f/"body.bin").read_bytes()
    order=opts["BootOrder"]
    if len(order)%2: raise ValueError("odd BootOrder size")
    return collections.Counter(check(opts.get(f"Boot{n:04X}")) for (n,) in struct.iter_unpack("<H",order))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("store",nargs="+",type=Path)
    for i,store in enumerate(p.parse_args().store,1):
        print(f"store {i}: {dict(scan(store))}")
