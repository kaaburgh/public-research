# APCB MMIO boundary and native browser save follow-up — 2026-11-26

Verified owner-provided 1.24 AFU and 1.32/1.33 vendor ROMs, UEFIExtract A75 and objdump. No physical tests, no firmware writes. Public data exclude private NVAR dumps.

## P2-71 / E66 — B04/B09: APCB Data Fabric MMIO boundary

**Finding:** Unknown byte 0x125 is logical PCI memory-ceiling token, not UMA or DRAM timing. Existing dynamic resource calculation explains plausible live/factory difference.

**Evidence:** Live APCB 0x290000 DFG group0x1703/type0x6 relative 0xDC length0x58: descriptor #6 at 0x100 =0x00030601 (token0x306, width1), payload0x125 E0 vs C0; other 11 DFG values equal. AmdApcbRvDxe 33 mapping table 0x46A0 entry0x46B8 (logical8,0x306); vtable+38/+40 Get/SetCfgParameter. PciRootBridge PE SHA256 428c13f8651c760fc31cfbf9e5f4c0ab4ffa128f31c2d875e2db9b6149df6640 all three identical. Function0x4538 gets MemCeil. (fallback C0000000), reads logical8 size1 at0x4652, shl24 at0x465E; GCD/PCI resource scan, alignment and comparison0x47ED–4807; writes MemCeil. at0x4831, shr24 then sets token at0x4869, APCB writeback0x4874 and conditional reset0x48AF. E0/C0 encode 3.5/3 GiB respectively.

**Limits:** No proof why live value differs, updater retention, actual e820 map or 512 MiB loss. Old unchanged code can adjust it after enumeration. Not a new PCI allocator algorithm. Field semantics closed; runtime remains B12.

## P2-72 / E67 — B04: native Save & Exit / CBS routing

**Finding:** Both BIOS UI engines support dynamic buffer VarStore lookup and persistence through HII RouteConfig; the native callback is not a direct NVRAM write. Save loop ignores individual write status.

**Evidence:** CbsSetupDxeRV 33 installs HII ConfigAccess at0xF07, vtable ExtractConfig0x738/RouteConfig0xA10/Callback0xAEC, adds packages0xF9A. IFR at0x134EB opcode24 length31: AmdSetup GUID3A997502-647A-4C82-998E-52EF9486A247 ID0x5000 size0x53F. AMITSESetupData $SPF compiled 145 records lacks AmdSetup; runtime parser0x259E5→0x21AAC handles opcode24 with flags0 (vs26 flag0x1000), append0x25390 and merge/cache expansion0x28668. BrowserCallback AMITSE0x202A8/EsaFull0x28284 scans runtime record names/GUIDs, falls back outside current formset, EFI_NOT_FOUND if absent; updates via cache helper0x118C0/0xBA5F4. AMITSE save0x12DC4 loops runtime table;0x13360→0x11728→0x1C710→HiiConfigRouting.RouteConfig0x1CA18 for ordinary non-EFI varstore, vs direct SetVariable on flagged/special stores. EsaFull parser0x32DA8, save loop0xC01BE→0xC063C→0xBA45C→0x248A4→RouteConfig0x24BAC. Both loops ignore status and advance. CBS RouteConfig persists AmdSetup then calls APCB helper, itself returns SetVariable status; prior P2-43/69 width and retry caveats unchanged.

**Limits:** Conditional static route resolved. Actual CBS package enumeration in chosen browser mode, cache presence, callback dispatch, order of persistence and runtime UMA not demonstrated. No direct variable writes; 128 MiB is candidate, not guarantee.

## P2-73 / E68 — S24: LEMComputraceApiDxe/Smm

**Finding:** All 26 changed bytes in each PE attributed to Setup size and compensating stack displacement; no changed condition or call target.

**Evidence:** DXE 4512 B, SMM 6240 B; all 26 raw differences per PE in two functions DXE0x574/0x644, SMM0x818/0x8E8, SMM instruction offsets +0x2A4. Frames 0x200→0x210 and 0x210→0x220, rbp base moves -0x10 while rbp positive local displacement +0x10, effective addresses for those locals unchanged; Setup size0x1BE→0x1C1 at DXE0x5D4/0x6B2, SMM0x878/0x956. RSP-relative Setup field read/write offsets unchanged. All changed bytes decoded by objdump; PE remainder and DXE/MM DEPEX, UI, Version sections identical across three. 32=33 PE hashes exact. No new code path.

**Limits:** Static section attribution only; platform policy/actual runtime not measured. Close two S24 PE rows.

## Reproduction
Use inventory GUID and section instance to extract exact PE bodies. For APCB decode descriptors using token=(d>>8)&0x1fff and width=((d>>21)&7)+1, locate sentinel 0x001fff00, map value offsets cumulatively. Check mapping table and both PciRootBridge call sites using objdump -d -M intel; compare entire PciRootBridge bodies and decode the CbsSetupDxeRV IFR opcode at 0x134EB. Verify both browser implementation paths and the generic save-loop caller. No assertion of actual runtime VarStore list or active UI engine. For Computrace use cmp -l (1-based byte offsets) and objdump -d -M intel --no-show-raw-insn; DXE/SMM diff offset relation +0x2A4. Compare actual DEPEX bytes separately, not file locations. Static attribution does not imply runtime validation.

P2-71–73 / E66–68: APCB byte0x125 attributed to DFG token0x306 PCI MMIO boundary (logical8), PciRootBridge unchanged; native browser dynamic AmdSetup VarStore and conditional RouteConfig path identified in both UI engines, save loop ignores write status; two Computrace API PE rows closed by complete 26-byte attribution each. 166 S24 + 5 S33 =171 pending; 39/44 S33 attributed. Actual browser registration/persistence and hardware remain open.
