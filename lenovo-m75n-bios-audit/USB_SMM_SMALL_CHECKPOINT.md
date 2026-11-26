# OEM software dispatch, USB layout and remaining small sections — 2026-11-26

Offline comparison of three verified ROMs. No raw SMI use, variable writes, failure injection, or hardware tests. Pair-specific closure means full binary attribution, not proof of runtime equivalence.

## P2-80 / E75 — B03: OEM SW dispatch and WMISwSmi dependency

**Finding:** Two legacy OEM table entries removed; one WMI operation re-registered via standard SW Dispatch2 and separate Lenovo_PRELOADElement path removed.

**Evidence:** OemSwSmiDispatchProtocol PE 5504 B, 233 raw diffs: header2, text122, data109. All 116 changed instructions preserve operations and shift data RIP targets -0x10. Old .data [0x1040,0x1140) matches, old [0x1150,0x1458) equals new [0x1140,0x1448); removed two 8-byte records, zeros pad tail, section size metadata -0x10, rest equal. Registration loop 0xAE2–B1A: table30→28 records before sentinel. WMISwSmi DEPEX first GUID changes from OEM protocol to standard SMM SW Dispatch2; remaining bytes equal. Old WMISwSmi registers two OEM entries at0x33B8/33CD; new directly registers one via standard protocol at0x33FA–3431. Old 0x2ED8–2FB5 branch accesses Lenovo_PRELOADElement; its string and discriminator absent 32/33. WMIAcpiMemAddr retained. All three sections 32=33.

**Limits:** Close OEM PE and WMI DEPEX only. WMI executable still partial; exact external callers and effect of removed legacy preload feature unknown. No raw SMI invocation or hardware observations. Not evidence of generic OS runtime regression.

## P2-81 / E76 — B07: UsbInt13 shared USB structure layout

**Finding:** All four changed bytes are coherent layout adaptation to USB global-data fields; no independent change to legacy INT13 logic.

**Evidence:** UsbInt13 4928 B 4 raw diffs, 0x4E9 reads field+0x6A9→0x6A7, 0xE0C/E4A/E88 compare three counters+0x6B6/7/8→+0x6B4/5/6. Pointer obtained from same USB protocol GUID 2ad8e2d2-2e91-4cd1-95f5-e78fe5ebe316. Uhcd old0x15F1/15F8 initializes counters, new0x1561/1568 shifted; old0xF76/new0xF41 obtains first shifted field address. UsbRtDxe old0x6E69/6E87/6EA5 vs new0x6DB7/6DD5/6DF3 reads counters, old0x6F3E/6F52/6F66 vs new0x6E8C/6EA0/6EB4 increments; SMM equivalent old0x73E1/73FF/741D vs new0x7323/7341/735F. SMM first-field read old0x1E2D3/new0x1AF77. Siblings equal, 32=33.

**Limits:** Close UsbInt13 PE only; other USB modules still have behavioral changes. INT13 is legacy boot interface, not Linux USB stack. No hardware validation.

## P2-82 / E77 — Remaining Setup-size candidates (seven PE)

**Finding:** Seven more same-size PE bodies fully explained by length and compensating stack changes.

**Evidence:** AbtExtendedMessageProtocol, DeleteUefiCaFromDb, DevFwUpd, KeyboardLayouts, LemKeyboardLayoutProtocol, SwSmi534D3220, UpdateSerial_NUM. All changed raw bytes map to decoded old/new instructions; 32=33; siblings equal. Per-module counts/coordinates in data/usb-smm-small-followup.tsv.

**Limits:** Static attribution only; no actual variable changes or tests.

## P2-83 / E78 — S24: version/time metadata and CSM layout (nine PE/TE)

**Finding:** Nine other S24 rows fully attributed to build date/version and in CrbPei/CsmDxe also Setup size/layout; no new branch discovered.

**Evidence:** AmiDeviceGuardApi, AmiRedFishApi, SecureBootDXE, HardwareSignatureEntry, CopyRight, CrbDxe, CrbPei, CsmDxe, SmbiosType0. Exact raw/TE normalized changed-byte checks and sibling equality; data strings verified. 2021-12-16→2025-11-11; build time 14:24:36→16:49:50. CrbDxe/Pei trivial version-return functions 24→32→33. CsmDxe RIP data targets moved +8, all mapped to zero-initialized storage, stack/size compensated; ASCII timestamp. See data/usb-smm-small-followup.tsv.

**Limits:** Time fallback may matter to authenticated variable operations, not simply cosmetic; no claim of runtime equivalence. Only S24 closures, S33 separately tracked.

## Reproduce
Extract by GUID and section in data/usb-smm-small-followup.tsv. Compare same-size PE raw bodies and all sibling payloads; use objdump and map changed bytes to instructions. Normalize TE ImageBase and HIGHLOW/DIR64 slots as described in SETUP_SIZE_BATCH_CHECKPOINT.md. For OEM SW dispatcher compare section headers, unchanged instruction addresses/opcodes except RIP displacement, table prefix and shifted suffix; compare all unwind/other sections. Decode WMI DEPEX GUID operands and compare all remaining bytes. For UsbInt13 confirm identical protocol GUID and producer/counter accesses across Uhcd and UsbRtDxe/Smm, not merely matching numeric offsets. Verify version/time data literals separately; timestamp-dependent behavior remains possible. Do not invoke raw SMI handlers or modify any variables.

P2-80–83 / E75–78: OEM dispatcher two entries removed, WMI standard registration retained for one, obsolete preload variable branch removed; WMI DEPEX closed, PE remains partial. UsbInt13 coherent shared structure layout. Seven Setup-size and nine build-time/version/layout sections closed. 103 S24 + 5 S33 =108 pending, 39/44 S33 attributed. Hardware untested.
