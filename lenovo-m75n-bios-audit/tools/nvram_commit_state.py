#!/usr/bin/env python3
"""Model only the traced DXE state selector; no firmware execution or writes."""
def select(raw_a, raw_b):
    a,b=(~raw_a)&255,(~raw_b)&255
    a,b=a or 0x20,b or 0x20
    va=bool(a&4) and not bool(a&0xe0)
    vb=bool(b&4) and not bool(b&0xe0)
    if va and vb:
        if b&0x10: first=True
        elif a&0x10: first=False
        elif a&8: first=bool(b&8)
        else: first=va
    else: first=va
    return 0 if first else 1 if vb else None

# Old bank assumed physically intact; state-only transitions and complete ordered writes.
stages=[('initial',0xf0,0xe0,'old'),('erase alternate',0xf0,0xff,'old'),('prepare alternate',0xf0,0xfc,'old'),('records copied',0xf0,0xfc,'old'),('retire old',0xe0,0xfc,'old'),('new commit partial state bit3 only',0xe0,0xf4,'old'),('new commit partial state bit2 only',0xe0,0xf8,'new'),('new committed',0xe0,0xf0,'new')]
for old_index in [0,1]:
    for stage,old,new,expect in stages:
        a,b=(old,new) if old_index==0 else (new,old)
        selected=select(a,b)
        actual='old' if selected==old_index else 'new' if selected is not None else 'none'
        assert actual==expect,(stage,old_index,a,b,actual,expect)
        print(f'old bank {old_index+1}; {stage}: {actual}')
print('16/16 state-only stage/order cases pass; no power-loss or flash test')
