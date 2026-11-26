# NVMe lifecycle and reachability follow-up (2026-11-26)

All three ROM SHA256 verified against manifest. Nvme PE SHA256 124 2209f6e495f0a14f87512b4e0e0821af004323986a34338f400db8393650efca; 132=133 641bc0804afee4844538f0c0918a9254eafe75d32e1c6758aeeba6ecfd320f63. Follow P2-90/111/112. No firmware execution or writes.

## P2-117 — NVMe DXE stop / S24

Stop replaces four FreeBuffer calls with zeroing. On lazy I/O allocations, it uses aligned interior pointer with whole-allocation page count: 4096-byte write past allocation for normal 4KiB page case. Conditional firmware memory corruption candidate.

Evidence: 124 cleanup 13E6–14F3 Unmap + FreeBuffer raw pointers +50/+78/+A8/+D0. 132 cleanup 141E–1502 Unmap current +68/+90/+C8/+F0 then zero +58/+80/+B8/+E0 with page counts +70/+98/+B0/+D8 shifted 12. 280 is REP STOS zero. 5A6E–5B30 and 5BF2–5CB4 allocate P+16N/P+64N, store ceil(bytes/4096), align (base&~(P−1))+P, replace pointers. P=4096 (CAP check 1994/19DD/1A8C), N=min(63,MQES+1) at A2B–A4B. With successful page allocation, 252 geometry cases all exceed by one page. Stop worker 10D8 called at BDE (Start failure) and 10BD (Stop last controller); no normal ExitBootServices call shown. 132=133.

Limits: Conditional on successful lazy allocation and cleanup reaching corresponding branch. Actual allocation adjacency, runtime consequences and boot occurrence unmeasured. Do not test by deliberately triggering faulty stop on owner machine.

## P2-118 — NVMe early preallocation ownership / S24

P2-112 refined: early I/O mappings overwritten by ordinary allocation; Stop only unmaps latest mapping and does not free raw queue pages. Early allocation record stays linked; two lazy 2-page buffers retained per successful Start→Stop. No measured OS memory delta.

Evidence: 132 1B0C stores record pointer +1A8, 1B36/1B45 early I/O pointers, 1D35/1D9B early mappings, 5B29/5CAD overwrite pointers and Map output handles +F0/+C8. Only stores to raw +A8/+D0 in lazy creator. Stop 1447/145D unmaps current handles; 1559 frees controller context; no FreeBuffer of four queues or unlink of prealloc record in traced Stop. 47BC preallocation failure cleanup frees five 1-page and one 512-page buffers; sole direct call 4685. 2MiB buffer separately freed/cleared when no qualifying namespace at C3D–C6B or 2662–2688. 132=133.

Limits: Repeated successful Start/Stop may retain additional 16KiB per controller cycle; actual firmware allocation lifetime/OS map and SMM ownership not fully established. Not a quantified total RAM loss. P2-112 superseded for traced path.

## P2-119 — NVMe EndOfDxe dependency and admin reachability / S24

New list begins as two zero pointers, initialized only after successful PCI handle enumeration in EndOfDxe callback. Start before successful initialization has a null-list dereference candidate; initialized empty/missing list instead returns out-of-resources. Ordinary one-namespace boot core admin sequence only 5–6 submissions, not sufficient on its own to reach P2-111 wrap.

Evidence: 132 .data [7290,72A0) all zero, six DIR64 elsewhere; only head writes 457D/4584 and insertion 4722–473A. 456E failure skips initialization. Start 1A8F compares head to self, 1ACF loads head and 1AE6 reads node+10 without null guard. New event registration 593–5BF. Core success path: Set Features 1E68→6B80→6C00; Identify controller 960→1EB0, optional namespace list 9E3, Create I/O CQ/SQ A4B→5A14→5BCD/5D45, each new namespace 2152→1EB0. Completion 68FB–690C copies SQHD to state +8/+4; software full predicate 6613–6643 does not reset for simple serialized head=tail before wrap. Recovery 6A75 corrects AQA count. Same PE 132/133.

Limits: Actual BDS/EndOfDxe ordering and admin command count not observed; security/passthrough/extra namespaces may add commands. No claim of normal boot failure, exact timeout or runtime SMM effect. PE remains partial.

## Cleanup model

UEFI PCI I/O AllocateBuffer/FreeBuffer allocate/free pages, Map/Unmap manage DMA mappings: https://uefi.org/specs/UEFI/2.11/14_Protocols_PCI_Bus_Support.html ; page alignment and page size per boot services: https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html . The code computes P=2^(CAP.MPSMIN+12), rejects >4096 (1994/19DD), stores P at +3C (1A8C). For N=1..63, both 16N and 64N are positive and <4096. Allocation request P+N*width rounds to 2 pages. PCI I/O AllocateBuffer returns a page-aligned base; code rounds down then adds P (5B08–5B17/5C8C–5C9B). This always skips a page, even for already aligned base. Stored +B0/+D8 is page count 2 computed before Map. Cleanup does not use raw pointers or subtract the alignment offset, zeroes 2 pages at base+4096. The range arithmetic is independent of actual addresses, conditional on allocation succeeding and cleanup using replaced pointers. Synthetic model tested 252 cases, no writes or hardware execution. If the first lazy allocation fails before storing the replacement, the original preallocated buffer may still be cleared using its own size instead. Do not deliberately exercise the defective Stop path on hardware.

## Admin count qualifier

The base successful path without recovery or optional commands has four fixed submissions (Set Features, controller Identify, Create I/O CQ, Create I/O SQ), plus optional active namespace list Identify and one Identify for each newly seen namespace. The model counts 5–6 for a single namespace, not a bound on all commands. Additional firmware security, pass-through, management, enumeration/retry paths may increase it. Serialized successful head=tail does not trigger the queue-full reset branch before first mismatch: at nonzero head it compares tail−1 to head (6619–6625). At zero head it compares tail to count−1 (6627–6634). Before first command both zero, no trigger. At submission 63 head=tail=62, no trigger. Actual controller may consume commands differently and recovery may correct AQA while introducing other conditions. No claim about Linux queue management or real failure.

B07 remains partial. Next prioritize BDS policy path / NVRAM / USB and residual NVMe mappings. 87 pending unchanged.
