#!/usr/bin/env python3
"""Arithmetic-only model of NVMe cleanup bounds. Does not access hardware."""
def geometry(base, n, width, page=4096):
    assert base % page == 0 and 1 <= n <= 63 and width in (16, 64)
    requested = page+n*width
    alloc = (requested+page-1)//page*page
    ptr = (base & ~(page-1))+page
    zero_end = ptr+alloc
    return alloc, ptr-base, zero_end-(base+alloc)

if __name__ == "__main__":
    cases=0
    for base in (0x100000,0x200000):
        for n in range(1,64):
            for width in (16,64):
                assert geometry(base,n,width)==(8192,4096,4096)
                cases+=1
    print(f"{cases} cleanup geometry cases: one page beyond allocation")
