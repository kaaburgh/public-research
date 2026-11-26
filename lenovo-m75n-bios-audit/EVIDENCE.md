# Reconstructed detailed evidence
This file consolidates prior static analysis notes; addresses are from earlier disassemblies, not newly re-verified except inventory hashes. See data/p1-public.tsv and data/p2-public.tsv for other static evidence. Full device-specific records intentionally remain private.

## NVMe (1.24→1.32, all seven modules identical 1.32→1.33)
Nvme GUID 634E8DB5-C432-43BE-A653-9CA2922CC458, PE32 30560→31136; .text 0x6a0e→0x6c0e. NvmeSmm E5E2C9D9-5BF5-497E-8860-94F81A09ADE0, 11488→12480, .text 0x2415→0x274d. TpmNvmeSupport ADD70A4D-1067-4FA3-A669-94C82877F106 1984 unchanged size, 9 byte changes Setup/stack. NvmeDynamicSetup, NvmeInt13, ThirdPartyNvme, LEMEfiNvmExpressPassThruProtocolHook exact. 
DXE 1.32 entry registers EndOfDxe GUID 02ce967a-dd7e-4ffc-9ee7-810cf0470880 via CreateEventEx at RVA 0x5bf, callback 0x4524 enumerates PCI class 01:08:02, associates DMA allocations by PCI location, record 0x68. Helper 0x4780 rounds size, calls PCI IO AllocateBuffer; return status handling needs checking. Cleanup 0x47bc. Admin AQA at MMIO 0x24 old min(CAP.MQES,0x100), new fixed 0x3f (64 entries encoded zero-based); IO queue cap at 0xa2b old 0x100→0x3f. ASQ/ACQ writes 0x28/0x30. Edge case CAP.MQES<63 and failure handling open. This is firmware preboot, not Linux queue size. 
SMM DEPEX + EFI_SMM_ACCESS2_PROTOCOL c2702b74-800c-4131-8746-8fb5b89ce4ac; GetCapabilities twice, size then descriptor array (stride 0x20); new SMRAM checking, internal copy of external data; notification and legacy SMI handling restructured. New SMM notify GUID 85a8ab57-0644-4110-850f-981322047070, two others not attributed. Security-hardening inference, not confirmed CVE. Old normalized heuristic chunks 62→64 DXE (43 exact), 29→33 SMM (22 exact); not function counts, no proof of equivalence.
 
## USB (1.24→1.32; 1.32=1.33)
UsbRtDxe GUID 171F43DC-C4D9-47A6-9641-65DDCDD5AA30 126368→113888, .text 114983→103351; UsbRtSmm 04EAAAA1-29A1-11D7-8838-00500473D4EB 181344→167456, .text 128055→114983. DEPEX/version unchanged. UsbPei nested PE32 30560 exact. UsbInt13 4928 bytes, four shifted shared state offsets 0x6a9→0x6a7, 0x6b6..b8→0x6b4..b6. SmartUsbProtection 3744/11 bytes, UsbHubTuningDxe 2720/5, USBTimingEx 1952/8: Setup size/stack. FchSandstoneDxe 38912/5, FchSandstonePei 20200/4 normalized, same cause. FchSandstoneSmmInit, FchSmmDispatcher, FchSSSataD3ColdSmm exact.
CCID removed: old USB interface class 0x0b branch DXE 0x4394 vs 0x430c; removed region approx 0x16a8c–0x197a4. Old CCID ops 0x62 IccPowerOn at 0x193bd, 0x63 IccPowerOff at 0x178f5, 0x65 GetSlotStatus at 0x179b9, 0x6f XfrBlock at 0x177fa, 0x6c GetParameters at 0x17a79, 0x61 SetParameters at 0x17b6c. SMM analogous removal. USB mass storage paths refactored, new DXE wrapper 0x9438/SMM 0x9a04; old wrapper near 0x1bad8, some chunks moved not new. DXE dispatcher 0x6a8 / SMM 0x820 adds command restriction; SMM request 0x1e150→0x1adf4 uses shorter validated request and allowlist. Exact bug and runtime effect unproven. Uhcd detailed P2-15/20: CCID removed, common fallback SMI removed when callback absent, 14 callsites; runtime applicability unproven. No proof of xHCI driver equivalence.
 
## Other core evidence
P2-08, 16, 23–25 provide detailed AmdSetup migration, native Setup selective defaults, UMA callbacks. P1-33–35 establish unchanged static flash map and compatible two formats, correcting earlier speculation. Do not pursue incident. Public rows exclude personal live variable values. 33 static checksum-valid ACPI tables match (one DSDT +32 SSDT variants); dynamic tables not proven. CPU patch changes and factory APCB comparison described in HANDOFF. More proof: private sheet, exact ROMs; absent intermediate scripts must be reconstructed, not invented.

## E50–51: vendor corroboration and PCR1 experiment
P2-55: Lenovo HT518672 M75n M33KT33A SRWINX64=Y, WMI=N, HT518129 M33KT32A certificate transition. Independent support for earlier ISO changelog; exact SRWIN-to-mailbox call chain open. P2-56: new PCR1 replay/boot variable summary tool, exact blob 25cd7f013e6ce18c27894f202d27ac2c8daf9bb6, eight synthetic checks, no actual M75n data. See VENDOR_PCR1_CHECKPOINT.md for sources, protocol and limitations.

## E52–54: conditional UMA model and hardware controls
P2-57 derives 225 modeled size cases from P2-24/25/43; no new disassembly. P2-58 uses kernel sysfs docs and locally tested UMA capture/compare tool (blob 1ed289ae7cf721bebc5503ee4a08c11927730665). P2-59 adds bounded CPU RNG smoke test (blob 73449aa7adefb2a488f142663081d054e5e9ad6b), based on external Picasso report, not M75n evidence. See UMA_RUNTIME_CHECKPOINT.md.

## E55–57: SMI, APOB NV and boot inventory
P2-60 AMD OSRR #56255 p153 PMCx02B; target measurement pending. P2-61 coreboot PSP guide and AMD EDK2 reference corroborate type63 APOB NV, not target payload validation. P2-62 UEFI Boot Manager/Device Path specs plus read-only boot_inventory.py blob 6a64763c5893691a2e040e212df272b10f1125c8, nine synthetic checks. See SMM_APOB_BOOT_CHECKPOINT.md.

## E58–60: restored ROMs
P2-63 HII ID0x809 = existing Performance Mode, exact forms and normal strings; S33 Setup closed. P2-64 vendor APOB NV erased, live record accounts for 41436 bytes. P2-65 thermal PE/TE exact difference attribution independently repeated. See ROM_RESTORED_CHECKPOINT.md.

## E61–65: targeted binary follow-up
- E61: P2-66 B10: SecureBootDXE and mailbox producer — Confirmed request-specific handling and incomplete error aggregation; no new ordinary-boot key reset identified.
- E62: P2-67 B10: NvramDxe/NvramSmm policy scope — Both new predicates add mailbox-read success to existing Secure Boot policy decision, not a generic NVRAM write path.
- E63: P2-68 B10: EsaFull expanded GUI paths — Expanded functions are called from UI object selection and position-update handlers; likely focus/visibility/layout behavior, not a demonstrated OS-runtime change.
- E64: P2-69 B04: native UMA browser callback — Confirms CHANGING action and full IFR value pointer; browser-data update errors are ignored, distinct from persistent CBS RouteConfig.
- E65: P2-70 B09: remaining unmapped raw bytes — Located two changed bytes within EFS-containing page; directory pointers identical.
See MAILBOX_UI_UMA_CHECKPOINT.md.

## E66–68: MMIO and browser-save follow-up
- E66: P2-71 B04/B09: APCB Data Fabric MMIO boundary — Unknown byte 0x125 is logical PCI memory-ceiling token, not UMA or DRAM timing. Existing dynamic resource calculation explains plausible live/factory difference.
- E67: P2-72 B04: native Save & Exit / CBS routing — Both BIOS UI engines support dynamic buffer VarStore lookup and persistence through HII RouteConfig; the native callback is not a direct NVRAM write. Save loop ignores individual write status.
- E68: P2-73 S24: LEMComputraceApiDxe/Smm — All 26 changed bytes in each PE attributed to Setup size and compensating stack displacement; no changed condition or call target.
See MMIO_BROWSER_SAVE_CHECKPOINT.md.

## E69–71: FastBoot and NvramPei follow-up
- E69: P2-74 B02: FastBootOption trigger and BootFlow producer — ExitBootServices callback and BootFlow=7 producer identified; unchanged preexisting gate, not universal boot-time execution.
- E70: P2-75 B02: FastBootOption edge cases — New maximum-based numbering can leave allocated BootOrder tail partly uninitialized; old and new ignore Boot####/BootOrder write results.
- E71: P2-76 B05: NvramPei Setup size check — Entire normalized TE difference attributed to expected Setup size check, not changed variable-validation algorithm.
See FASTBOOT_TRIGGER_CHECKPOINT.md.

## E72–74: variable route and Setup-size batch
- E72: P2-77 B03: separate legacy SmiVariable vs normal UEFI variable route — SmiVariable is a separate software-SMI interface, not the installed normal UEFI runtime-variable entrypoints; new local copy changes return handling in a legacy enumeration branch.
- E73: P2-78 B02/B05: eight P1 Setup-size candidate PE/TE sections — All changed bytes mapped to Setup 446→449 and compensating stack displacement or relocation in eight high-priority modules.
- E74: P2-79 B05 and other Setup-size candidates: 35 P2 PE/TE sections — All nonrelocation differences explained by Setup size, stack/local displacement or correlated metadata; no new condition/call target found.
See SETUP_SIZE_BATCH_CHECKPOINT.md and data/setup-size-followup.tsv.

## E75–78: OEM dispatch, USB layout, remaining small sections
- E75: P2-80 B03: OEM SW dispatch and WMISwSmi dependency — Two legacy OEM table entries removed; one WMI operation re-registered via standard SW Dispatch2 and separate Lenovo_PRELOADElement path removed.
- E76: P2-81 B07: UsbInt13 shared USB structure layout — All four changed bytes are coherent layout adaptation to USB global-data fields; no independent change to legacy INT13 logic.
- E77: P2-82 Remaining Setup-size candidates (seven PE) — Seven more same-size PE bodies fully explained by length and compensating stack changes.
- E78: P2-83 S24: version/time metadata and CSM layout (nine PE/TE) — Nine other S24 rows fully attributed to build date/version and in CrbPei/CsmDxe also Setup size/layout; no new branch discovered.
See USB_SMM_SMALL_CHECKPOINT.md and data/usb-smm-small-followup.tsv.

## E79: complete S33 NvramDxe/NvramSmm layout
Two S33 PE sections closed: old code/data preserved under mapping, new mailbox predicate and corresponding list entry plus build-time constants. See NVRAM_PAIR_LAYOUT_CHECKPOINT.md.

## E80: complete S33 mailbox producer layout
All S33 differences attributed to added mailbox handler and registration, supporting variables and code/data layout. See SWSMI_MAILBOX_LAYOUT_CHECKPOINT.md.

## E81: SecureBootDXE reordered functions
Normalized per-function pairs 2A0→2A0 (45/45),328→5AC (74/84 old;100 new),4A0→328 (60/60),5B4→774 (59/62 old;65 new),668→830 onward (465/471); total 703/722 exact normalized matches (not semantic proof). Init boot mode comparisons 0x12/0x20 order swapped; new callback uses same GUID 7739f24c-93d7-11d4-9a3a-0090273fc14d, helper now takes GUID in RDX and preserves it via RDI. New init 71E–75F creates event and registers protocol notify; callback starts 43C. Remaining matched-body indexed references/date constants, full raw data and relocation validation pending.

## E82: SecureBootDXE / S33
All 18 DIR64 slots and targets, 101 direct transfers and 55 RIP references verified; four indexed references mapped; retained .data byte-identical under mapping after relocation masking. 722→839 nonpadding instructions. Header/zero sections and padding accounted for. See ESA_SECUREBOOT_FINAL_MAP_CHECKPOINT.md. Runtime behavior, request authentication and failure handling remain untested; S33 static closure only.

## E83: EsaFull / class-specific method mapping
CustomOrderedListLayoutEx and CustomOrderedListLayout strings→constructors→vtables→actual call targets traced; BestFit vs CustomBestFit field offsets likewise retained. Corrected code splitting: 4491/4494 normalized piece matches; 347077/347378 old rows. 62477/62488 mapped direct transfers verified, 11 unresolved, zero incongruent in accepted map. Candidate map is not semantic proof; ambiguous duplicate pieces, data/reloc mapping unresolved. EsaFull remains partial.

## E84: EsaFull / actual residual code
0x884 allocates 8 KiB before instead of after five LocateProtocol calls; only direct caller 0x710 ignores returned status. 0x1EA68 OEMRevision 0x1200→0x1210. D1928 descriptor table 147BD0: delete second 32-byte record (no string ID); remaining 17 exact including Enter Password and action pointers. Sizes 0x630→0x5D8, 0x240→0x220, 0x120→0x110, count12→11. Deleted element exact UI purpose and runtime behavior unknown; no evidence of password verification algorithm change. Data matching incomplete; no closure.

## E85: Nvme DXE / S24
New EndOfDxe callback 4524–477E enumerates PCI NVMe, preallocates five 4 KiB buffers and 2 MiB per record (2 MiB also allocated conditionally in old driver). AllocateBuffer wrapper 4780–47B5 returns zero unconditionally. Missing preallocated record causes failure at 1A98; first queue NULL checked 1B5F. CAP.MPSMIN check 19DD; CC 460000 at1A70; AQA 003F003F at1C75–1C92. Old min(MQES+1,256). 32=33. See NVME_SMM_IPL_CHECKPOINT.md. Failure/late discovery and memory retention untested; no measured SSD throughput impact. Remaining mapping partial.

## E86: NvmeSmm / S24
54→72 byte DEPEX: append PUSH c2702b74-800c-4131-8746-8fb5b89ce4ac and AND; original operands unchanged. GetCapabilities 59D–5EF. Comm callback CFC validates lengths and local copies; handler 11F8 validates 0x62 structure, tests LegacyBoot flag at125E, set by callback1328 registered14CA–14D8. 32=33. DEPEX closed, executable remains partial; no complete safety or runtime proof.

## E87: PiSmmIpl / S24
Old1B7C–1EF8→new1B7C–1F54 checked range arithmetic/split path; old2C18–2EE8→new2C74–2F50 section RVA+size overflow guard. Outside ranges 2184 mapped instructions, 93 raw changes only branch/RIP encoding; 281 branch and 78 changed RIP references verified. All 33 DIR64 slots and other sections byte identical; header alignment and .text growth accounted. 32=33. No claim of global overflow safety or hardware equivalence; actual SMM initialization untested.
