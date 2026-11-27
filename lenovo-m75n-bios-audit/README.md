# Lenovo ThinkCentre M75n: BIOS 1.24 → 1.33 audit

Snapshot 2026-11-26. Goal: assess real post-upgrade regressions on Picasso FP5 / Ryzen PRO 3300U, not diagnose a third-party update failure. 1.32 is an intermediate comparison point, not a required flash step. Static analysis only; no hardware update, no performance measurements.

Start with [HANDOFF.md](HANDOFF.md), [METHODOLOGY.md](METHODOLOGY.md), [EVIDENCE.md](EVIDENCE.md), [BACKLOG.md](BACKLOG.md), [SOURCES.md](SOURCES.md). Data files are sanitized snapshots of the working ledger, not independent proof. The private working sheet is authoritative for device-specific data; its URL and raw data are intentionally not public. No firmware images or proprietary executables are committed.

- [data/inventory.tsv](data/inventory.tsv): 2256 original inventory records, 22 columns; private 1.24 non-executable hashes and free-text conclusions omitted.
- [data/changes.tsv](data/changes.tsv): 283 changed records (corrected from 284; see REPRODUCTION.md), same schema.
- [data/pending.tsv](data/pending.tsv): 89 pair-specific rows: 88 open/partial/candidate in 1.24→1.32 and 1 remaining partial section in 1.32→1.33 (43 of 44 attributed). Heuristic priority, not a finding.
- [data/p1-public.tsv](data/p1-public.tsv), [data/p2-public.tsv](data/p2-public.tsv): selected historical evidence records; omitted rows remain in private ledger.
- [tools/audit_verify.py](tools/audit_verify.py): executable hash and relocation verifier.
- [tools/inventory.py](tools/inventory.py), [tools/compare_inventory.py](tools/compare_inventory.py): independently regenerated inventory and multiset verification.
- [tools/flashmap_model.py](tools/flashmap_model.py): offline model with golden hash regression.
- [tools/instruction_diff.py](tools/instruction_diff.py): PE/TE candidate matching aid.
- [REPRODUCTION.md](REPRODUCTION.md): actual commands, test results, corrections, remaining limitations.

The owner provides ROMs/AFU dump separately to each new session or agent; absence of those files in Git is expected, not a reproducibility blocker. Never publish personal dumps or generated private inventory.

Do not run flash tools, write EFI variables, or publish personal dumps. Compare binaries offline. Add new evidence with stable IDs, version pair, hash, coordinates, method, uncertainty, and explicit next test. Keep historical corrections rather than deleting them.

## Platform-specific reproduction

[PLATFORM_REPRODUCTION.md](PLATFORM_REPRODUCTION.md) describes six additional tools: AMD directory/APCB/microcode inspection, NVAR graph/defaults inspection, static ACPI comparison, IFR extraction/diff, platform regression tests, and raw-ROM accounting. All were tested on the three owner-supplied images. Keep their generated reports local.

Latest risk analysis: [SMM_TPM_AHCI.md](SMM_TPM_AHCI.md), B03/B06 partial and a strong measured-boot regression candidate. Earlier [CPU_FASTBOOT.md](CPU_FASTBOOT.md): B01 static closure, B02 partial.

Further analysis: [TPM_UMA_DEFAULTS.md](TPM_UMA_DEFAULTS.md), seven TPM policy sections attributed; measured boot defect confirmed statically, UMA synchronization/error paths and password-algorithm preservation clarified.

B10 checkpoint: [RELEASE_132_133.md](RELEASE_132_133.md) and [data/s33-attribution.tsv](data/s33-attribution.tsv). 26 additional sections attributed, 11 partial, 7 previously relocation-only; pair-specific statuses retained independently.

Further B10: P2-51/52 validate 27,253 actual relocation slots and targets; four more PE sections attributed; 7 S33 sections remain partial. Tool `tools/pe_layout_audit.py`.

Latest B10 checkpoint P2-53/54: 38/44 changed sections attributed; six partial. Active queue 174 rows (168 S24 + 6 S33). The 4096-byte RSA signature metadata block is attributed; EsaFull has real expanded GUI code, not merely layout.

Checkpoint P2-55/56: [VENDOR_PCR1_CHECKPOINT.md](VENDOR_PCR1_CHECKPOINT.md) independently corroborates SRWINx64-only factory-key reset support in 1.33 and provides a synthetic-tested read-only PCR1 audit tool. No binary section reclassified; 174 pending rows.

P2-57–59: [UMA_RUNTIME_CHECKPOINT.md](UMA_RUNTIME_CHECKPOINT.md) documents conditional UMA size-gate model, Linux RAM/VRAM observation and an additional bounded RNG regression control. No new ROM analysis; pending counts unchanged.

P2-60–62: [SMM_APOB_BOOT_CHECKPOINT.md](SMM_APOB_BOOT_CHECKPOINT.md) confirms the Picasso SMI PMU event and APOB NV entry type from external documentation, and adds a synthetic-tested read-only boot inventory. No pending reclassification.

P2-63–65: [ROM_RESTORED_CHECKPOINT.md](ROM_RESTORED_CHECKPOINT.md) verifies source access and Setup internal alias, closes S33 Setup, attributes APOB live-state region and rechecks thermal modules. Current queue 173; 39/44 S33 attributed.

P2-66–70 / E61–65: all three ROMs verified; mailbox producer/consumer and NVRAM policy scope narrowed, conditional restore/deletion failure risk; EsaFull UI selection/position logic narrowed; native UMA callback CHANGING and ignored browser-update status confirmed; EFS page pointers exact, two tail bytes still unresolved. No new section closure: 39/44 S33, 173 pending. Hardware and complete mapping remain open. See [MAILBOX_UI_UMA_CHECKPOINT.md](MAILBOX_UI_UMA_CHECKPOINT.md).

P2-71–73 / E66–68: APCB byte0x125 attributed to DFG token0x306 PCI MMIO boundary (logical8), PciRootBridge unchanged; native browser dynamic AmdSetup VarStore and conditional RouteConfig path identified in both UI engines, save loop ignores write status; two Computrace API PE rows closed by complete 26-byte attribution each. 166 S24 + 5 S33 =171 pending; 39/44 S33 attributed. Actual browser registration/persistence and hardware remain open. See [MMIO_BROWSER_SAVE_CHECKPOINT.md](MMIO_BROWSER_SAVE_CHECKPOINT.md).

P2-74–76 / E69–71: FastBootOption ExitBootServices + BootFlow7 gate and BDS producer mapped, unchanged uninitialized DataSize guard; new max-ID wrap/early-exit leaves tail potentially uninitialized, both versions ignore option writes. NvramPei sole normalized byte attributed to Setup size check, one S24 row closed. 165 S24 + 5 S33 =170 pending; 39/44 S33 attributed. B02 remains partial; runtime not tested. See [FASTBOOT_TRIGGER_CHECKPOINT.md](FASTBOOT_TRIGGER_CHECKPOINT.md).

P2-77–79 / E72–74: separate legacy SmiVariable and normal runtime-variable route confirmed; legacy return-size candidate. 43 S24 small PE/TE sections (8 P1 + 35 P2) fully attributed to Setup-size adaptation, stack/layout and TE relocation. 122 S24 + 5 S33 =127 pending; 39/44 S33 attributed. Hardware untested; B03 partial. See [SETUP_SIZE_BATCH_CHECKPOINT.md](SETUP_SIZE_BATCH_CHECKPOINT.md).

P2-80–83 / E75–78: OEM dispatcher two entries removed, WMI standard registration retained for one, obsolete preload variable branch removed; WMI DEPEX closed, PE remains partial. UsbInt13 coherent shared structure layout. Seven Setup-size and nine build-time/version/layout sections closed. 103 S24 + 5 S33 =108 pending, 39/44 S33 attributed. Hardware untested. See [USB_SMM_SMALL_CHECKPOINT.md](USB_SMM_SMALL_CHECKPOINT.md).

P2-84/E79: full 1.32→1.33 layout/relocation attribution of NvramDxe and NvramSmm; 2 S33 closures. 103 S24 + 3 S33 =106 pending; 41/44 S33 attributed. Actual hardware and mailbox authorization behavior remain open. See [NVRAM_PAIR_LAYOUT_CHECKPOINT.md](NVRAM_PAIR_LAYOUT_CHECKPOINT.md).

P2-85/E80: full S33 SwSmi534D0040 attribution; 103 S24 + 2 S33 =105 pending, 42/44 S33 attributed. Remaining S33 SecureBootDXE and EsaFull. See [SWSMI_MAILBOX_LAYOUT_CHECKPOINT.md](SWSMI_MAILBOX_LAYOUT_CHECKPOINT.md).

P2-86/E81: SecureBootDXE old function reordering separated from new event callback; 703/722 normalized old instructions match in five segmented comparisons, remaining code/data/relocation verification open. 105 pending, 42/44 S33 attributed unchanged. See [SECUREBOOT_REORDER_CHECKPOINT.md](SECUREBOOT_REORDER_CHECKPOINT.md).

P2-87–89 / E82–84: SecureBootDXE fully statically attributed; corrected EsaFull wrong-class matches, verified 4491/4494 normalized pieces and isolated three actual code residuals; full data mapping still partial. 103 S24 + 1 S33 =104 pending, 43/44 S33 attributed. See [ESA_SECUREBOOT_FINAL_MAP_CHECKPOINT.md](ESA_SECUREBOOT_FINAL_MAP_CHECKPOINT.md).

P2-90–92 / E85–87: NVMe EndOfDxe preallocation/fixed queues and lost allocation status; NvmeSmm DEPEX closed, legacy gate/local copies identified; PiSmmIpl static attribution closed. 101 S24 + 1 S33 =102 pending, 43/44 S33 attributed; NVMe PE bodies remain partial. See [NVME_SMM_IPL_CHECKPOINT.md](NVME_SMM_IPL_CHECKPOINT.md).

P2-93/E88: PiSmmCore static attribution closed, full outside mapping and 57 relocations verified; communication/loader checks and two end-address boundary mismatch candidates identified. 100 S24 + 1 S33 =101 pending, 43/44 S33 attributed. See [PISMMCORE_CHECKPOINT.md](PISMMCORE_CHECKPOINT.md).

P2-94–95/E89–90: SmiVariable static attribution closed (legacy output-copy issue and unused temporary data copy); new OememDxe serial-ring wake enforcement and default change identified. 99 S24 + 1 S33 =100 pending; 43/44 S33 attributed. OememDxe remains partial. See [SMIVARIABLE_SERIAL_WAKE_CHECKPOINT.md](SMIVARIABLE_SERIAL_WAKE_CHECKPOINT.md).

P2-96–97/E91–92: OememDxe and FastBootOption static PE maps closed. Mandatory Setup write gates UMA notify, FastBoot failure handling and pool/ID risks refined. 97 S24 + 1 S33 =98 pending; 43/44 S33 attributed. Runtime still untested. See [OEM_FASTBOOT_FINAL_CHECKPOINT.md](OEM_FASTBOOT_FINAL_CHECKPOINT.md).

P2-98–99/E93–94: both S3 script writer PE maps and S3Resume2Pei TE map closed. Record-length guards and resume statistics source/rollover changes identified; 94 S24 + 1 S33 =95 pending, 43/44 S33 attributed. Hardware S3 open. See [S3_SCRIPT_RESUME_CHECKPOINT.md](S3_SCRIPT_RESUME_CHECKPOINT.md).

P2-100/E95: BootScriptExecutorDxe PE closed, PE/TE relocation-directory range guard identified. 93 S24 + 1 S33 =94 pending; 43/44 S33 attributed. All four examined S3 components statically attributed, hardware S3 remains open. See [S3_EXECUTOR_CHECKPOINT.md](S3_EXECUTOR_CHECKPOINT.md).

P2-101/E96: AhciInt13Smm PE closed, local-copy/init/free routing and status caveats recorded. 92 S24 + 1 S33 =93 pending; 43/44 S33 attributed. See [AHCI_SMM_FINAL_CHECKPOINT.md](AHCI_SMM_FINAL_CHECKPOINT.md).

P2-102/E97: SetupLoadDefault closed. Password algorithm preservation broadened; two password-policy preservation entries removed (minimum length and strong password, both default Disabled). 91 S24 + 1 S33 =92 pending; 43/44 S33 attributed. See [SETUP_DEFAULTS_POLICY_CHECKPOINT.md](SETUP_DEFAULTS_POLICY_CHECKPOINT.md).

P2-103/E98: USB dispatcher state gate and retained 16 entries confirmed; previous SMM init/callback attribution corrected. Queue unchanged: 91 S24 + 1 S33 =92 pending. USB PE mapping incomplete. See [USB_DISPATCH_FOLLOWUP_CHECKPOINT.md](USB_DISPATCH_FOLLOWUP_CHECKPOINT.md).

P2-106–110/E101–105: all three ROMs hash-verified again; selector helpers byte-identical, DXE size-mismatch migration filter traced to vendor StdDefaults (13 keys); intended non-default key preservation, caller ignores migration result. Three small TPM/OEM PE bodies attributed (AmiTcgNvflagSample, LEMAllDriversConnectedEventHook, SwSmi534D0140). Queue: 88 S24 + 1 S33 = 89 pending; 43/44 S33 attributed. Actual flash/reset and runtime untested. See [NVRAM_MIGRATION_SMALL_OEM_CHECKPOINT.md](NVRAM_MIGRATION_SMALL_OEM_CHECKPOINT.md).

P2-111–112/E106–107: NVMe DXE/SMM initial admin queue size contract mismatch (64 hardware vs 63 software), recovery subtracts one; deterministic ring model shows first mismatch at 63rd serialized submission. Early I/O queue preallocation followed by old lazy allocation path, ownership/lifetime risk open. No hardware reproduction; both PE rows remain partial. Queue 89 unchanged. See [NVME_QUEUE_CONTRACT_CHECKPOINT.md](NVME_QUEUE_CONTRACT_CHECKPOINT.md).

P2-113/E108: EsaFull S33 conservative data map proposes 5120/5832 .data relocation slots (4266 target-consistent, 848 unknown, six inference conflicts); independent unique vtable-like runs propose 3192 slots, reject two false byte-map pairs, union 5235 old slot proposals. Remaining attribution incomplete; 89 pending, 43/44 S33 attributed. See [ESAFULL_DATA_MAPPING_CHECKPOINT.md](ESAFULL_DATA_MAPPING_CHECKPOINT.md).

P2-114/E109: Tpm20PlatformDxe S24 static PE attribution closed, including vendor-specific RDRAND helper (INTC TPM only), PCR7 buffer cleanup, capacity corrections and existing PCR1 helper regression. Runtime remains open. 87 S24 + 1 S33 =88 pending, 43/44 S33 attributed. See [TPM20_PLATFORM_FINAL_CHECKPOINT.md](TPM20_PLATFORM_FINAL_CHECKPOINT.md).

P2-115/E110: AmiTcgPlatformDxe legacy PE static attribution closed, preserves P2-40 conditional PCR1/PCR7 risks. 86 S24 + 1 S33 =87 pending, 43/44 S33 attributed. See [AMI_TCG_PLATFORM_FINAL_CHECKPOINT.md](AMI_TCG_PLATFORM_FINAL_CHECKPOINT.md).

P2-116/E111: BDS expands existing malformed Boot#### deletion policy to a second path; both AFU NVAR stores' BootOrder instances pass bounded well-formed model (9+10). BDS remains partial; 87 pending unchanged. See [BDS_LOAD_OPTION_CHECKPOINT.md](BDS_LOAD_OPTION_CHECKPOINT.md).

P2-117–119/E112–114: NVMe lifecycle follow-up finds conditional Stop zeroing beyond allocated I/O buffer, overwritten initial mapping/retained lazy pages, new EndOfDxe initialization dependency and limited basic admin count. No hardware execution; 86 S24 + 1 S33 =87 pending unchanged. See [NVME_LIFECYCLE_CHECKPOINT.md](NVME_LIFECYCLE_CHECKPOINT.md).

P2-120/E115: native Setup[61] minimal-device Fast Boot vs separate [3C] POST-state option; BDS BootMode/BootNext gate and 21-entry table traced, normalized chunks match across all releases. Actual BootFlow7/EBS path and other BDS differences remain. 87 pending unchanged. See [BDS_FASTBOOT_ACTIVATION_CHECKPOINT.md](BDS_FASTBOOT_ACTIVATION_CHECKPOINT.md).

P2-121/E116: Uhcd shared callback installation and request-size contract traced, unchanged DXE DEPEX and callback producer; three explicit SMI calls match new filter. Missing-callback scenario remains conditional. 87 pending unchanged. See [USB_CALLBACK_CONTRACT_CHECKPOINT.md](USB_CALLBACK_CONTRACT_CHECKPOINT.md).

P2-122–123/E117–118: new scoped EFI global Timeout/PlatformLang validation, fixed 7-byte SecureBootSetup read no longer retries with increased capacity, and SMM variable communication copies/allocations; successful enumeration size/status path preserved, new allocation-failure paths. 87 pending unchanged. See [NVRAM_VARIABLE_CONTRACT_CHECKPOINT.md](NVRAM_VARIABLE_CONTRACT_CHECKPOINT.md).

P2-124/E119: NVRAM dual-bank physical backend mapping; 18 normalized pieces/1130 instructions match all versions, state-only selector model 16/16 stages. Old bank retained in assumed ordered writes; error after pointer switch and ignored migration result remain conditional. 87 pending unchanged. See [NVRAM_COMMIT_STATE_CHECKPOINT.md](NVRAM_COMMIT_STATE_CHECKPOINT.md).

P2-125/E120: NvmeSmm uses returned queue bases, unlike DXE Stop interior-pointer defect; separate conditional duplicate release/stale registration after resource failure. 26/38 normalized pieces matched, all 12 dispatch relocations mapped. 87 pending unchanged. See [NVME_SMM_LIFECYCLE_CHECKPOINT.md](NVME_SMM_LIFECYCLE_CHECKPOINT.md).

P2-126/E121: all named NVAR chains resolved on both banks; generous compact-size model with new defaults fits with ~53% headroom. Owner aggregates private; tool nvar_capacity.py. No exact write emulation or hardware test. 87 pending unchanged. See [NVAR_CAPACITY_CHECKPOINT.md](NVAR_CAPACITY_CHECKPOINT.md).

P2-127/E122: owner Setup terminal vs new defaults matched by 287 common named IFR question keys; private thermal/device/boot/security drift list, TPM read-only and OS Optimized Defaults override caveats. 87 pending unchanged. See [SETUP_RESET_DRIFT_CHECKPOINT.md](SETUP_RESET_DRIFT_CHECKPOINT.md).

P2-128/E123: BDS table has root bridge and PCI 06/01 nonrecursive connection before EndOfDxe; no direct early NVMe Start demonstrated. 87 pending unchanged.

P2-129–131/E124–126: close TcgDxe, FlashDriver and FlashDriverSmm static PEs; GPT measurement limits refine P2-42; pending FV header recovery refined; NVMe Map alignment slack predates update, new Stop defect distinct. 83 S24 +1 S33 =84 pending. See [GPT_FLASH_NVME_SCOPE_CHECKPOINT.md](GPT_FLASH_NVME_SCOPE_CHECKPOINT.md).

P2-132–134/E127–129: SmiFlashDxe and ReFlashSmm static closures; context ownership transfer and SMM header snapshot confirmed, ReFlash DXE grows communication buffer by 64 KiB and independently resets EDU variable read sizes; remaining DXE attribution open. 82 pending. See [REFLASH_FLOW_CHECKPOINT.md](REFLASH_FLOW_CHECKPOINT.md).

P2-135–137/E130–132: ReFlash PE and FID/FIDT/SGN metadata statically closed. Recovery prefix unchanged; DxeCore four-digit alias 132/133 but raw PCD DBs equal for this pair. External policy and DxeCore remaining mapping open. 78 pending. See [REFLASH_FID_PCD_CHECKPOINT.md](REFLASH_FID_PCD_CHECKPOINT.md).

P2-138/E133: exact 2192B DXE PCD v6 reconstruction from 124 to both 132/133. Four removed Ex tokens also removed from traced Uhcd config paths. PcdDxe raw section closed, Uhcd PE partial. 77 pending. See [PCD_RECONSTRUCTION_CHECKPOINT.md](PCD_RECONSTRUCTION_CHECKPOINT.md).

P2-139–142/E134–137: DxeCore PE statically closed; current ROM bounds checked, FPDT producer/consumers aligned. SmiFlash conditional Enhanced Power Saving Mode preservation, EDU size resets and fixed network backup length traced to Ip4Dxe producer. 76 pending. See [DXECORE_SMIFLASH_CONFIG_CHECKPOINT.md](DXECORE_SMIFLASH_CONFIG_CHECKPOINT.md).

P2-143–144/E138–139: ACPI, DxeIpl, PeiCore statically closed. New early LZMA/relocation guards satisfy inspected vendor image bounds. 73 pending. See [ACPI_PEI_LOADER_CHECKPOINT.md](ACPI_PEI_LOADER_CHECKPOINT.md).

P2-145/E140: SmiFlash PE statically closed; request/header/trailer, SMM lookup, stack and backup changes attributed; error and hardware behavior separate. 72 pending. See [SMIFLASH_FINAL_CHECKPOINT.md](SMIFLASH_FINAL_CHECKPOINT.md).

P2-146/E141: five NVMe Start failure paths retain CQ or CQ+SQ fields before common teardown; existing DriverOrder ForceReconnect path traced after EndOfDxe. 72 pending unchanged. See [NVME_START_RECONNECT_CHECKPOINT.md](NVME_START_RECONNECT_CHECKPOINT.md).
