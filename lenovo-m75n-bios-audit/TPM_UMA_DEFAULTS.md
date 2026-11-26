# TPM, UMA synchronization and defaults checkpoint

2026-11-26. Offline analysis of source-verified M33KT24A live and M33KT32A/33A factory ROMs. All newly reviewed changed payloads in this note are identical in 1.32 and 1.33. Addresses are RVAs (PE base zero, TE stripped delta applied). Extract using A75, verify hashes in data/inventory.tsv; compare section bytes, relocation-normalized whole TE payloads and objdump instructions. See METHODOLOGY.md and prior SMM_TPM_AHCI.md. Private ROM/NVRAM stays external. No hardware execution.

## P2-39 / Tpm20PlatformDxe / TPM2 measured boot

**Finding:** Подтверждён нарушенный контракт размера; PCR7 использует другой путь

**Evidence:** 124 helper 0x9D0 sets *size=0 at 0x9DF, GetVariable NULL data at 0x9FF, allocate 0xA29, read 0xA56. 133 helper 0xA30 reads caller size at 0xA5D, allocate 0xA70, read 0xA9D, no probe. Caller 0x1CA0 frame 0x78: size slots rsp+0x38 / +0x48 lack dominating stores, only pointer slots +0x20/+0x40 initialized. Calls 0x1CE8/0x1DBF via wrapper 0x1C10. Format helper 0x6888 receives bounded destination rsp+0x50, not sizes. 0xDB48 table points to 0x1CA0; 0x201C callback at 0x20E5; 0x6034→0x7938→0x798C registers standard ReadyToBoot GUID at 0xD8A0. TCG2 LocateProtocol 0x694. PCR1/event 0x80000002; error EFI_NOT_FOUND, BootOrder return success. PCR7 separate 0x12E4 QueryVariableInfo 0x132C, allocate max size 0x1369, reset size each direct GetVariable 0x13D1/1488/153F/1603/16C7 etc; no shared helper defect. 32=33.

**Residual risk:** Strong static contract regression, PCR1 variable events may be omitted; exact stack values and runtime dispatch unknown. Not evidence of PCR7 defect on TPM2, boot variable deletion or TPM clear. Repeated cold-boot event logs and PCR replay needed.

## P2-40 / AmiTcgPlatformDxe / legacy TPM measured boot

**Finding:** Аналогичный дефект PCR1 и явно нулевой размер на PCR7 path

**Evidence:** 36032→36000 B, 32=33. Old helper 0x1318 clears size and probes at 0x134C; new 0x1318 reads *size 0x1340, alloc 0x1353, GetVariable 0x1380, resets on error 0x1399. PCR1 caller 0x15D0 via wrapper 0x13B8 uses uninitialized rbp+0x20/+0x38 sizes at calls 0x1600/164E; PCR1 event 0x80000002. PCR7 function 0x1444 zeros shared size rbp+0x67 at 0x145F, calls helper 0x1517 in loop (bound 5 at 0x15A7): SecureBoot, PK, KEK, db, dbx. Nonempty variables cannot fit in zero-length buffer; failure leaves size zero. PCR7 event 0x80000001. DEPEX requires EFI_TCG_PROTOCOL f541796d-a62e-4954-a775-9584f61b9cdd; TcgDxe installs at 0x2BFE/2C56 after earlier protocol/init and TPM capability response gates. Not established on AMD fTPM.

**Residual risk:** Legacy path conditional. Distinguish from TPM2 PCR7 routine in P2-39. Static bug, not hardware-observed; other module diffs residual.

## P2-41 / TPM policy / fTPM initialization (7 sections)

**Finding:** Все нормализованные отличия связаны с размером Setup и стеком

**Evidence:** TcgPlatformSetupPeiPolicy TE 22 normalized bytes (0x348 frame 1CC→1D0; 0x353 size; buffer at 0x392 and fields 0x3E6–4B9 -4); AmdPspFtpmPei TE 6 normalized bytes (0x102E frame 1DC→1E0, 0x1039 size, 0x10A2 buffer and field offsets 0x10D4/10DD/10EB); AmiPspFtpmPei TE 4 normalized (0x2D7 frame 1D8→1DC, 0x2E1 size, 0x31D buffer, 0x340 field); TcgPlatformSetupPolicy PE 28 raw, stack and two Setup-size operands; TPMHwPresent PE 37 raw, two stack frames and three size operands; Tcg2Dxe PE 12 raw (0x312C,313C,3371,337C,338E,66F2,6715,6963,69FF,6DD4 and associated epilogue; stack +0x10), TcgSmm PE 3 raw (0x1206,120D,134E). PE changes confined to .text, TE relocation-normalized full payload checked, DEPEX same, 32=33.

**Residual risk:** No new TPM initialization or policy algorithm identified in these seven sections. Does not establish runtime fTPM behavior or rule out changes in other modules/PSP firmware.

## P2-42 / TcgDxe / AmiTcgNvflagSample

**Finding:** Дополнительные проверки GPT и изменение размера TcgInterfaceVar

**Evidence:** TcgDxe 24704→24800 B. New 0x1232 checks EFI PART signature, 0x1245–125E LBA arithmetic guard, 0x1264–126C requires entry size 0x80; 0x1272–1289 count check followed by 32-bit size calculation. Standard entries unaffected by size condition, larger valid entry sizes may be rejected on measurement path; old loop already assumed stride 0x80. AmiTcgNvflagSample 2720 B: 879 raw diffs; new 0x48C initializes size=1 for TcgInterfaceVar; 0x57A uses size=1 for SetVariable rather than returned size, 0x588 resets local. .data changes at 0x880/888/890 not fully attributed. 32=33.

**Residual risk:** GPT measurement path not native OS storage I/O; no demonstrated regression. Other TcgDxe/Nvflag diff groups remain open. Legacy TCG dispatch and exact error behavior not proved.

## P2-43 / OememDxe / UMA synchronization

**Finding:** Выявлены guard, реальный protocol notify и риск неатомарной записи

**Evidence:** OememDxe 133 callback 0x410, guard 0x45A–46A exits for extended CMOS marker ED. SetupLoadDefault 0xD15–D27 checks same marker; reads SetupDataChecksumError at 0xD58, deletes on successful read at 0xD84, conditional clears marker at 0xDB3. OememDxe event registered 0xB12–B4F for GUID CD3D0A05-9E24-437C-A891-1EE053DB7638; NvramDxe installs at 0x214F (D080 GUID, D250 interface); not standard ReadyToBoot event. 0x4FA compares DWORD Setup[1A3] vs AmdSetup[D4]; equal→0x61D close, mode-only difference ignored. Unequal: persist AmdSetup at 0x53E, then APCB GetCfgParameter 0x577, mode from AmdSetup[D1] at 0x5B6, size at 0x5F0, writeback 0x600, reset 0x61A. Failures exit 0x62A without rollback. Subsequent same-size condition can skip repair. Other CBS path: RouteConfig 0xA10 registered in CbsSetupDxeRV config-access interface; ConfigToBlock 0xA82, SetVariable 0xAB6, APCB helper 0xAC5→0x3254 (vtable +58 at 0x332C, +10 writeback at 0x3336). APCB return not propagated; RouteConfig returns SetVariable status. 32=33 for OememDxe.

**Residual risk:** Conditional transaction/order defect, not observed runtime. Normal RouteConfig can compensate if browser routes AmdSetup; exact native save dispatch and event delivery/order still open. Marker appears associated with checksum/defaults recovery; writer unknown. No direct CMOS/variable writes proposed. 128 MiB is candidate for first controlled test, not guarantee.

## P2-44 / SetupLoadDefault / сохранение password algorithm

**Finding:** Удалена зависимость сохранения алгоритма хеша от признака наличия пароля

**Evidence:** 10016→9792 B, 32=33. 124 reads LnvAnyPasswordPresentVar at 0xE23 into global flag 0x23F0; 0x666–674 restores saved Setup[0x52] only if flag nonzero. 133 removes read and condition; captures original Setup[0x52] into temporary byte at 0x424–427, restores unconditionally at 0x666–668. IFR field Set Password Encryption Algorithm: SHA-256=0, SM3=1. Same marker recovery and CSM/filter preservation elsewhere in both versions.

**Residual risk:** Likely broader preservation of existing hash algorithm during defaults reset, not evidence of password reset/lockout or new encryption algorithm. Remaining module changes and exact reset invocation/order not fully explained.

## Reproduction and runtime boundaries

For the seven small TPM modules, compare raw PE .text with identical remaining sections, or normalize TE HIGHLOW relocations and ImageBase first. Verify all remaining byte changes in decoded instructions; size 0x1BE→0x1C1 and stack/local displacements compensate, not a general proof of platform equivalence. No evidence of TPM clear. For measured boot, read-only baseline before an official update: TPM major version, manufacturer, event log and PCR values; repeat cold boots and compare EV_EFI_VARIABLE_BOOT presence and replay (raw PCR values need not match across versions). On TPM-bound encrypted storage ensure recovery access. For UMA, capture before/after native Setup and CBS values, actual memory reservation and boot behavior; compare normal BIOS menu Save & Exit and a repeated cold boot. Do not write EFI variables/CMOS directly. APCB failure injection is not part of this audit. Firmware event ordering and actual browser dispatch remain unknown.

P2-69: native Setup callback is HII CHANGING, original Value pointer/32-bit IFR confirmed; two FormBrowser2 update return statuses ignored. Save & Exit CBS routing not yet proven. See MAILBOX_UI_UMA_CHECKPOINT.md.
