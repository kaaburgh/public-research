# FastBoot trigger/edge cases and NvramPei size check — 2026-11-26

Verified three owner-provided ROMs, A75 extraction and objdump. Static analysis only; no hardware operations or personal NVAR export.

## P2-74 / E69 — B02: FastBootOption trigger and BootFlow producer

**Finding:** ExitBootServices callback and BootFlow=7 producer identified; unchanged preexisting gate, not universal boot-time execution.

**Evidence:** FastBootOption 24/33 entry RVA0x2DE–2E7 creates event0x201 (EVT_SIGNAL_EXIT_BOOT_SERVICES, UEFI 2.11 §7), TPL16, callbacks0x6F8/0x7AC. LocateProtocol GUID0302CB4F-AF05-4A16-99A9-31ADCF870890, interface byte0 nonzero; GetVariable BootFlow GUID EF152FB4-7B2F-427D-BDB4-7E0A05826E64 at0x787/83B, compare7, then call0x2F4. DataSize stack [rbp-0x30] not initialized in either callback; return failure skips work. FastBootRuntime33 0x1423–1438 installs same protocol with interface0x21C0; reads Setup field0x61 at0x1688, sets flag1 only on matching value at0x1697, else0. Bds33 function0xD410 finds AMI POST manager protocol8A91B1E1-56C7-4ADC-ABEB-1C2CA1729EFF, installs another protocol, sets BootFlow=7 via0xD3B8 (attributes2,size4), calls method0, writes0 on return; Bds24 corresponding0xD390/0xD338. Bds33 caller0xBAE4 checks policy byte+0x47. AMITSE33 installs POST manager at0x1DB8 with first method0x1F00; reads BootFlow at0x209F–20B8. ESA contains same GUID. UEFI event constant source https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html ; GUID mapping https://github.com/theopolis/uefi-firmware-parser/blob/master/uefi_firmware/guids/efiguids_ami.py .

**Limits:** Exact BDS policy label/selected path on owner machine and successful callback read unresolved; no assertion of regular boot triggering or runtime regression. Old uninitialized length is not new in 1.32. B02 partial.

## P2-75 / E70 — B02: FastBootOption edge cases

**Finding:** New maximum-based numbering can leave allocated BootOrder tail partly uninitialized; old and new ignore Boot####/BootOrder write results.

**Evidence:** 33 allocates original size+6 at0x50A–530 and copies old bytes at0x56A; max scan0x590–5B2, increment0x5CC, append ID0x5EA, allocate option0x661, on failure branch0x66E skips write, otherwise SetVariable result ignored; 0x71B increments ID,0x724 compares FFFF, exits0x727 before all3 slots when max FFFC/FFFD. Writes full oldsize+6 at0x785 (status ignored). For max FFFC, IDs FFFD/FFFE appended; third 2-byte slot not initialized by this function; for FFFD one appended, four bytes uninitialized. max FFFE/FFFF wrap case can attempt low IDs. 24 first-free scan0x52F–568; grows stored size by2 per iteration0x56B–576, old fixed stack; loop0x69E–6A5, writes computed size0x6DA, also ignores status. Both can append ID before successful record allocation/write.

**Limits:** Conditional on trigger, readable BootOrder, no already-detected synthetic BBS options and extreme existing IDs or write failures; no observed corruption, normal small IDs not affected by tail case. New overflow boundary distinct from preexisting write failure risk. Keep FastBootOption partial pending full residual map.

## P2-76 / E71 — B05: NvramPei Setup size check

**Finding:** Entire normalized TE difference attributed to expected Setup size check, not changed variable-validation algorithm.

**Evidence:** NvramPei 6376B each; raw51 changed bytes, ImageBase0x09E6EB44→0x09E6EB64, stripped delta0x198, 43 HIGHLOW relocations in both (directory RVA0x1A00 size0x68). Normalize targets by subtracting ImageBase modulo2^32; zero ImageBase; sole differing file byte0x1A7 BE→C1. i386 disassembly file0x175–1B1: calls PEI variable GetVariable with dataNULL/size0, GUID EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9 and UTF16 Setup; after EFI_BUFFER_TOO_SMALL compares returned size at0x1A4:0x1BE→0x1C1, sete at0x1AB. 32=33 exact. PEI DEPEX/UI/version same all three, TE SHA256 24=0863f780cdb0de0dcc3963f5e92a3765e3dcb2c8f544f8ed859d98b86adbd6dd; 32/33=2daec63730b797fdeb1c2fc60e70f8409f86d2fd6148c2fde7df65ee4f8e92a0.

**Limits:** Static attribution closes this TE row; size expectation supports earlier migration/reset finding, actual preservation of old Setup depends on migration path, not established by this check alone.

## Reproduction
Extract by GUID/section-instance in inventory. For PE use objdump -d -M intel --no-show-raw-insn; map RVAs to raw section offsets before reading literals. Follow BootFlow producer and its protocol methods separately from ExitBootServices callback. Use a bounded arithmetic model (uint16_t increment) to verify tail-count cases, not live NVRAM manipulation. For NvramPei parse TE header and relocation blocks; offset=rva-(StrippedSize-40), validate each HIGHLOW target and subtract image base modulo2^32, compare complete normalized bodies. Decode changed bytes with objdump -D -b binary -m i386 -M intel --start-address=0x175 --stop-address=0x1b2. Compare DEPEX/UI/Version hashes separately.

P2-74–76 / E69–71: FastBootOption ExitBootServices + BootFlow7 gate and BDS producer mapped, unchanged uninitialized DataSize guard; new max-ID wrap/early-exit leaves tail potentially uninitialized, both versions ignore option writes. NvramPei sole normalized byte attributed to Setup size check, one S24 row closed. 165 S24 + 5 S33 =170 pending; 39/44 S33 attributed. B02 remains partial; runtime not tested.
