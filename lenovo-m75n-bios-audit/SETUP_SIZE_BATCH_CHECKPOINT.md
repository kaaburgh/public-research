# Runtime variable routing and small Setup-size candidates — 2026-11-26

Verified three owner-supplied ROMs, A75 extraction and GNU objdump. No firmware writes, raw SMI calls, or hardware tests. Pair-specific closure means complete byte attribution, not observed runtime equivalence.

## P2-77 / E72 — B03: separate legacy SmiVariable vs normal UEFI variable route

**Finding:** SmiVariable is a separate software-SMI interface, not the installed normal UEFI runtime-variable entrypoints; new local copy changes return handling in a legacy enumeration branch.

**Evidence:** 33 NvramDxe installs RuntimeServices GetVariable/GetNextVariableName/SetVariable at0x1FE3/1FD1/1FF5 (functions0x1728/17A4/1804). Conditional SMM branches call0x2224/2370/2498→0x2178→SMM Communication protocol (located0x2113, GUID c68ed8e2-9dc6-4cbd-9d94-db65acc5c332); NvramSmm registers communication handler at0x103F and installs SMM Variable protocol at0x10E0. SmiVariable instead registers SW Dispatch2 handler at0xB94 onward, uses CPU save-state, obtains separate runtime table. In GetNextVariableName branch old0x9A9 writes updated size to original request, new0xA27 writes size into local copy, common return0xB3A–B93 does not copy that field back.

**Limits:** No claim of actual OS call traces, no raw SMI use; possible legacy caller return-size regression, not established for Linux efivarfs or routine runtime latency. Full SmiVariable diff remains partial.

## P2-78 / E73 — B02/B05: eight P1 Setup-size candidate PE/TE sections

**Finding:** All changed bytes mapped to Setup 446→449 and compensating stack displacement or relocation in eight high-priority modules.

**Evidence:** AmdSocFp5RvDxe/Pei, OemPei, SetupCheckSumPei, SetupConfigDxe, SetupDataChecksumErr, SetupItemLinkageDxe/Smm. Full same-size raw/normalized byte comparison, every nonrelocation byte assigned to old/new instruction, sibling payload equality, 32=33. Per-module raw/norm counts, relocation slots, size instruction and changed address span in data/setup-size-followup.tsv. TE ImageBase cleared and relocation targets normalized against image base; verified identical relocation slot/type list 24/32.

**Limits:** Closes eight S24 static rows only; variable migration/runtime still open. No new control-flow operation identified.

## P2-79 / E74 — B05 and other Setup-size candidates: 35 P2 PE/TE sections

**Finding:** All nonrelocation differences explained by Setup size, stack/local displacement or correlated metadata; no new condition/call target found.

**Evidence:** 35 additional modules, per-module coordinates and counts in data/setup-size-followup.tsv. All sibling payloads equal. 32/33 raw identical except ComTypeControlPei and MiscFunctionPortingPpi, normalized equal. Exceptions explicitly checked: AmiAgesaDxe 0x3BC adjusts +0x16→+0x13 keeping total0x1D4; RsdpPlus file0x208 .data.VirtualSize 0x3F0→0x3F4, RVA0xA26 Setup size. All other changed nonrelocation bytes map to decoded old/new instructions.

**Limits:** Closes 35 S24 static rows; no inference about actual firmware runtime or policy reset. Remaining UsbInt13 offset changes not part of closure.

## Reproduce
Use `data/setup-size-followup.tsv` to select each exact GUID and section. From A75 extraction compare body.bin of all three and hash all sibling sections. For PE, use raw byte comparison, `objdump -d -M intel --insn-width=16` and PE section mapping from RVA to file offset; for TE read StrippedSize minus 40, ImageBase, relocation directory (offset = RVA minus stripped delta), validate and normalize each HIGHLOW/DIR64 relocation by subtracting ImageBase modulo 32/64 bits; zero ImageBase; require identical target/type lists. For TE x86 text disassemble using `objdump -D -b binary -m i386 -M intel --insn-width=16` restricted to raw .text range; addresses in matrix are PE RVAs or TE file offsets. Every normalized difference must map to an enclosing old/new instruction, except explicitly listed PE section-header metadata in RsdpPlus. Verify compensating frame/local displacement and unchanged predicates, calls and Setup field offsets, not simply literal pattern count. Do not count unchanged sections as newly closed. The two 32/33 nonidentical TE bodies normalize equal and already belong to S33 relocation-only rows.

P2-77–79 / E72–74: separate legacy SmiVariable and normal runtime-variable route confirmed; legacy return-size candidate. 43 S24 small PE/TE sections (8 P1 + 35 P2) fully attributed to Setup-size adaptation, stack/layout and TE relocation. 122 S24 + 5 S33 =127 pending; 39/44 S33 attributed. Hardware untested; B03 partial.
