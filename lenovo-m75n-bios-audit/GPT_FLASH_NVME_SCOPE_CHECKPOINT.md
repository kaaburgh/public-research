# GPT measurement, flash volume lifecycle and NVMe scope — 2026-11-27

All three original ROMs SHA256 verified against manifest. UEFIExtract A75, GNU objdump -d -M intel --no-show-raw-insn. No firmware execution, disk modification, or flash writes.

## P2-129 / E124 — TcgDxe S24 closure

PE hashes 124 dda9c29787a8424260e254caa610a277c5daf67ca25554675173ec77daf2b80d; 132=133 4c301513cbe09d8dd36ccd4a5dfcf72b0e6d73aec0e7c3484b7e52cc2c26201f. 24704→24800 bytes. P2-42 already identified GPT validation changes; this checkpoint completes attribution, not a new independent defect. All changed normalized instructions are within old 10C0–1518/new 10C0–156C. New signature and exact entry-size validation; LBA multiplication guard; count check does not by itself establish safe size arithmetic at all later calculations. No malformed disk experiments or exploit claim. UEFI 2.10 §5 (https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html) permits larger power-of-two multiples of 128. Ordinary 128-byte entries unaffected by this size predicate. Old code already used 128-byte stride. Function measures GPT using EFI_TCG_PROTOCOL, not normal OS I/O; actual TPM dispatch and error effects not tested.

Normalize only direct branch targets and RIP references; SequenceMatcher with autojunk=False, excluding INT3. 5606/5624 decoded rows, 5584 paired, 5331 outside changed function. Outside 659 direct and 294 RIP references; 1 branch at 5328→5388 has target in exact shifted raw suffix [52D0,532A)→[5330,538A), hence resolves +60. All other mapped targets agree, 342 differing raw instruction spans contain references. 21 DIR64 slots shift +60; all targets map. Masked .data exact; unnamed/xdata raw exact; remaining header edits are .text size, image size, relocated directories/section offsets. 22 bytes .text zero padding both; DEPEX/UI/version exact. 132/133 exact. Static section attribution closed, runtime risk open.

## P2-130 / E125 — FlashDriver and FlashDriverSmm S24 closure

PE hashes:
- DXE 124 e10f6c5e6a5e97f38033ff036c46cb88fec78f5db0b34d42bed805a1f4a10343; 132=133 ba06e89712955e2e8bc28a9f8bd5c6c51a3ad8b47983b4b569078bfe1d3f9de6.
- SMM 124 d5790926bd67dc90fbf793e541a7f7c0268c3312071f7f564edb3272ff1392df; 132=133 d7c371ef8bc5fe436a4e0c6bfd4f2fa20d610bd6affff40d681e168d58c5f072.

DXE 1B14 produces pending 16-byte FV records, incrementing count at 5720, writes temporary signature via 1794. 1BB8 finds record for target base, masks signature in supplied buffer and marks pending flag if full header qualifies. 1C40 restores signature when end reaches recorded extent, removes record. These functions precede the changed region and are byte-identical. 50B0 is nested write-operation depth (increment/decrement, transition to/from zero calls backend activation/deactivation). SMM analogous globals 4118 and 4770.

Read wrapper old 1CFC, new 1CFC: old tests depth after underlying read 1580; new drops that gate, still tests nonempty pending table, matching FV base and sufficient buffer length. Both synthesize _FVH in returned buffer. End wrapper old 1F58, new 1F4C: old flushes pending list only when depth was nonzero and becomes zero. New also flushes when depth already zero and count nonzero. Flagged entries receive signature restore, then pending count cleared. Existing status treatment and nested write depth logic otherwise unchanged. Underlying calls return statuses not exhaustively audited; no claim of successful physical writes. SMM old/new ranges FFC–1094→FFC–1088 and 1254–1300→1248–12FC implement identical normalized changes.

DXE 3978→3980 instructions, 3890 outside changed functions, 704 direct, 682 RIP references, one INT3 branch 218F→218B explicitly mapped. SMM 3875→3877, 3787 outside, 700 direct, 609 RIP references. All other outside reference targets agree. 626/582 changed instruction byte spans outside contain references, no nonreference raw diffs. Map changed functions as above; intermediate code shifts -C, final code shifts -4 with padding accounting. All 43/44 DIR64 slot locations unchanged and targets map. Data exact after masking relocations; PE headers, unnamed, xdata, reloc raw sections exact. .text raw padding 208/16 bytes respectively both zero, identical terminal code. DEPEX/UI/version exact. Both PE rows closed for static attribution. P1-31 refined.

Simple conditional model (not flash simulator): for depth 0..3 and pending 0,1,10, after=max(depth-1,0); old=(depth!=0 and after==0); new=(after==0 and (depth!=0 or pending!=0)). 12/12 combinations checked; only depth=0,pending>0 differs. This is a selection predicate, not proof of power-loss safety.

## P2-131 / E126 — NVMe regression scope

Independently rechecked prior queue Stop finding. Completion-queue lazy allocation path 124 57FE–58C0 / 132 5A6E–5B30 has same sequence: original requested size includes alignment page, stored before calling AllocateBuffer; Map uses aligned interior host address and original NumberOfBytes pointer. SQ uses analogous width (132 5BF2–5CB4). Thus mapping range concern predates update; actual backend may map differently or adjust size. Normal init clears queue element bytes; new Stop at 14AF–14F1 clears allocated page count from interior pointer, distinct new behavior. Stop direct callers BDE and 10BD; recovery AQA subtracts one at 6A75 as before. No proof of ordinary Stop during boot or actual memory corruption. No hardware tests. Both NVMe PEs remain partial.

Current queue 83 S24 +1 S33 =84. Next: remaining high-priority Setup/NVRAM and USB/NVMe PE changes; SmiFlashDxe and ReFlash update flow; EsaFull residual. No raw owner data published.
