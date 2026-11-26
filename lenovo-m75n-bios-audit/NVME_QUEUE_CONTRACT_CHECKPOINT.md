# NVMe queue contract checkpoint (2026-11-26)

All three ROMs verified. UEFIExtract A75. PE image SHA256:

| Module | 1.24 | 1.32 and 1.33 |
|---|---|---|
| Nvme | 2209f6e495f0a14f87512b4e0e0821af004323986a34338f400db8393650efca | 641bc0804afee4844538f0c0918a9254eafe75d32e1c6758aeeba6ecfd320f63 |
| NvmeSmm | 959b65f7a53e3340d31113c2357f764e941866f28f9a900871f51788c9a56fca | e451504894969e9d14d5868fe1488510998736704c4ac5a6d6daed2475caa7a4 |

## P2-111 — NVMe admin queue size contract / S24

New initial DXE AQA advertises 64 admin entries while software wrap uses 63; same SMM initial encoding/check. Recovery paths retain count-minus-one encoding, advertise 63 entries. Conditional firmware boot/management regression candidate, not measured.

Evidence: Nvme old 1D02–1D9C uses min(CAP.MQES+1,256), stores count, writes AQA (count−1 twice); 132 1C23–1C92 stores 63 and writes 0x003F003F. Admin SQ tail increments at 666D, compares against +A0 at 6675, wraps at 667E, rings doorbell 6742. Recovery 6A5F–6A82 subtracts 0x10001; SMM initial A02/C20 direct encoding vs old 974/BE7 minus-one; SMM recovery 269E–26C1 subtracts, wrap 22A9–22BA. 132/133 PE hashes exact. Synthetic ring model yields mismatch at command 63 (tail62→0, hardware delta2). AQA zero-based per Microsoft NVME_ADMIN_QUEUE_ATTRIBUTES.

Limits: Need live command count/trace and controller behavior, actual recovery execution, testing across SSDs; normal Linux driver independently initializes queues. No proof of corrupted storage, boot failure or throughput loss. Both PE residuals remain open.

## P2-112 — NVMe early queue allocation / S24

Early I/O queue preallocation maps four 4KiB queues, but subsequent ordinary Create I/O queue function still tests old allocation-pointer fields and allocates new I/O buffers. Potential redundant allocation/mapping lifetime issue.

Evidence: 132 initialization zeroes 0x1B0 controller object (17B4–17DF); prealloc 1B13–1B54 assigns +58/+80/+B8/+E0/+158, DMA maps at 1B9A/1C08/1D35/1D9B; +A8/+D0 not assigned on this path. Ordinary caller A2B–A4B invokes 5A14; checks +D0 at 5A61 and +A8 at 5BE5, allocates and replaces +E0/+B8 and corresponding DMA map fields (5B29/5CAD), absent intervening explicit unmap in traced success path. Existing list retains original buffers. 132=133.

Limits: Need full ownership/lifetime mapping incl. stop/unmap and SMM handoff. Do not claim permanent leak, exact OS-reserved memory delta or performance loss. Other PE changes still open.

## Queue contract detail

Reference: [Microsoft NVME_ADMIN_QUEUE_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/nvme/ns-nvme-nvme_admin_queue_attributes), ASQS/ACQS are zero-based 12-bit fields. Old DXE 1B7D cap 256, 1D02–1D38 sets software counts, 1D8F subtracts 0x10001 before writing register 0x24. New 1C23 sets both fields to 0x3f and 1C87–1C92 writes directly. In both, submission path uses +A0 as modulo count, not inclusive max index: old 63FD–640E, new 666D–667E. Admin route identified by command +40=1; e.g. Identify at 1F7D/1FDA→1FF6. Doorbell offset computed from queue ID and CAP.DSTRD at 6706–6742. Initial software queue state zeroed in allocation helper 5684; no other direct stores to +A0/+A2 in Nvme .text except initial assignments. New recovery uses original arithmetic at 6A75 (old 6805), so 63 software entries correspond to 63 actual entries after that path. SMM likewise changes initial programming and comparison to direct encoding but preserves old recovery and tail wrap. 

Synthetic model assumes sequential, successful admin submissions, zero initial tail, no intervening controller reset, correct hardware modulo depth. It models doorbell delta only, not command content or controller reaction. Run `python3 tools/nvme_queue_contract_model.py`. At submission 63, old software tail62 and new tail0 with hardware depth64 indicate two positions, one more than intended. This is a concrete static inconsistency under stated assumptions; actual boot can finish before reaching it, controller behavior varies, recovery may mask it. A Linux driver can configure its own queues after firmware handoff; boot and firmware-management paths still matter. No claim that this causes storage corruption or observed failure.

## Allocation ownership detail

New EndOfDxe prealloc helper 4524 allocates record +30/+38/+40/+48/+50 each 4KiB, +60 2MiB, +58 24-byte state. Init maps preallocated buffers, stores +B8/+E0 while leaving +A8/+D0 zero after full struct zeroing. Ordinary Start directly calls init 8F6; after Identify at 960/9E3, calls 5A14 at A4B using min(63,CAP.MQES+1). 5A14 still allocates using legacy raw-allocation fields +D0/+A8, maps replacements and overwrites I/O queue addresses/map pointers. Success path has no explicit preceding unmap. This is a lifecycle candidate, not proof of permanent allocation leak; inspect release/stop and all ownership fields before calculating reserved memory. Existing allocator status-loss issue (P2-90) separate. No firmware modification or device execution.
