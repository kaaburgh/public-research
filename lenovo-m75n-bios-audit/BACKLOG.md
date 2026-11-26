# Active backlog
See data/pending.tsv for machine-generated queue. It has 87 pair-specific records: 86 candidate/partial/open rows for 1.24→1.32 and 1 remaining partial section for 1.32→1.33 (43 of 44 attributed). Review of existing evidence is not a claim that every row is unresolved. Review each pair separately; priority is provisional and not measured likelihood. Private P1/P2 blocker fields provide details; historical third-party AFU incident is out of scope.

| ID | Priority | Work | Completion condition |
|---|---|---|---|
| B01 | CLOSED (static) | CPU policy Stibp/CpuPei/CpuDxe | all changed code groups attributed, no new CPU policy operations; runtime B12 remains |
| B02 | High / partial | FastBootOption/FastBootRuntime, OEM init | FastBootRuntime explained; P2-74–75/97 FastBootOption static PE mapped; exact BDS path label and other OEM init remain |
| B03 | High / partial | SmiVariable/PiSmmCore/PiSmmIpl, SMM latency | P2-32–34/77: separate legacy SW-SMI vs normal runtime-variable path established; legacy return-size candidate; residual mapping and B12 latency |
| B04 | High / partial | UMA guard/order/error path, APCB byte 0x125 | P2-43: recovery guard, protocol notify, transaction order, alternate CBS route identified. P2-71 byte0x125 attributed; P2-72 conditional native RouteConfig established. P2-96 OememDxe mapped; actual browser registration/delivery, persistence and runtime UMA remain. |
| B05 | High / partial | Setup/NVRAM remaining callbacks, actual boot/Secure Boot | P2-44: password algorithm preservation broadened; validate migration/reset, remaining callbacks and actual state. |
| B06 | High / partial | TPM/AHCI/OEM | P2-39–42: TPM2 PCR1 contract confirmed, legacy PCR7 conditional, seven policy/fTPM sections explained; event log/PCR replay, legacy dispatch, residual TcgDxe/Nvflag and legacy SMM/OEM. |
| B07 | Medium | Remaining USB/NVMe, S3 | resolve residual changed functions, SMI fallback and queue limits; run appropriate tests |
| B08 | CLOSED | Normalizer discrepancy | Both TE modules differ only at ImageBase byte +0x10. Full normalized images equal; ledger corrected. See REPRODUCTION.md. |
| B09 | High / partial | Completeness | raw_coverage.py accounts for all 16 MiB per pair, two changed bytes unmapped in 1.24 comparisons; explain these and candidate APOB type 63, embedded raw PE, remaining unknown contained changes. See PLATFORM_REPRODUCTION.md. |
| B10 | High / partial | Independent 1.32→1.33 | 43/44 attributed including 7 reloc-only; P2-87 closes SecureBootDXE; only EsaFull data/relocations partial. |
| B11 | High / partial | Reproducibility | all core and platform inspectors restored and tested, including selected NVAR link graph, APCB/PSP/microcode, IFR, ACPI and raw accounting. Remaining complete raw NVAR/active-store semantics, more synthetic fixtures and independent function-level semantic verification. |
| B12 | High | Hardware baseline | before/after same OS/settings: microcode, meminfo, boot entries, Secure Boot, TPM event log/PCRs if present, temperatures, idle W, CPU/memory workloads, PCIe link/AER, USB, NVMe, AC loss; then UMA as separate change |
| B13 | Blocked | Windows packages | static unpack Inno Setup via innoextract, compare scripts/AFU; not required to assess post-boot changes |
 
Completion criteria: all inventory differences explained/blocked with justification; raw-region coverage accounted; all critical static conclusions independently reproduced; distinguish unknown runtime effects and measurements. No requirement to solve historical third-party failure or obtain 1.31.

Earlier checkpoint queue: 173 pair-specific records (168 S24 + 5 S33).

P2-55/56: B10 mailbox purpose corroborated by Lenovo documentation (SRWINx64 supported; WMI not supported on M75n); exact caller/authorization remains open. B06/B12 read-only PCR1 baseline tool prepared and synthetic-tested; physical data still needed. No change in pending counts. See VENDOR_PCR1_CHECKPOINT.md.

P2-57–59: B04 conditional model and read-only UMA observation prepared; B12 RNG smoke test added. All remain open for actual hardware and binary evidence. B10/B02/B03 cannot progress offline without ROMs. No pending-count change.

P2-60–62: B03 PMU counter 0x2B confirmed in AMD OSRR; B09 type63 is documented APOB NV, payload/active state remains open; B02/B05 boot inventory and B12 experimental controls added. No binary closure. See SMM_APOB_BOOT_CHECKPOINT.md.

P2-63–65: verified ROMs supplied; B10 Setup resolved; B09 APOB NV actual region accounted, cache selection and other residuals open; thermal module prior closure reverified. Next B10 mailbox and EsaFull. See ROM_RESTORED_CHECKPOINT.md.

P2-66–70 / E61–65: all three ROMs verified; mailbox producer/consumer and NVRAM policy scope narrowed, conditional restore/deletion failure risk; EsaFull UI selection/position logic narrowed; native UMA callback CHANGING and ignored browser-update status confirmed; EFS page pointers exact, two tail bytes still unresolved. No new section closure: 39/44 S33, 173 pending. Hardware and complete mapping remain open.

P2-71–73 / E66–68: APCB byte0x125 attributed to DFG token0x306 PCI MMIO boundary (logical8), PciRootBridge unchanged; native browser dynamic AmdSetup VarStore and conditional RouteConfig path identified in both UI engines, save loop ignores write status; two Computrace API PE rows closed by complete 26-byte attribution each. 166 S24 + 5 S33 =171 pending; 39/44 S33 attributed. Actual browser registration/persistence and hardware remain open.

P2-74–76 / E69–71: FastBootOption ExitBootServices + BootFlow7 gate and BDS producer mapped, unchanged uninitialized DataSize guard; new max-ID wrap/early-exit leaves tail potentially uninitialized, both versions ignore option writes. NvramPei sole normalized byte attributed to Setup size check, one S24 row closed. 165 S24 + 5 S33 =170 pending; 39/44 S33 attributed. B02 remains partial; runtime not tested.

P2-77–79 / E72–74: separate legacy SmiVariable and normal runtime-variable route confirmed; legacy return-size candidate. 43 S24 small PE/TE sections (8 P1 + 35 P2) fully attributed to Setup-size adaptation, stack/layout and TE relocation. 122 S24 + 5 S33 =127 pending; 39/44 S33 attributed. Hardware untested; B03 partial.

P2-80–83 / E75–78: OEM dispatcher two entries removed, WMI standard registration retained for one, obsolete preload variable branch removed; WMI DEPEX closed, PE remains partial. UsbInt13 coherent shared structure layout. Seven Setup-size and nine build-time/version/layout sections closed. 103 S24 + 5 S33 =108 pending, 39/44 S33 attributed. Hardware untested.

P2-84/E79: full 1.32→1.33 layout/relocation attribution of NvramDxe and NvramSmm; 2 S33 closures. 103 S24 + 3 S33 =106 pending; 41/44 S33 attributed. Actual hardware and mailbox authorization behavior remain open.

P2-85/E80: full S33 SwSmi534D0040 attribution; 103 S24 + 2 S33 =105 pending, 42/44 S33 attributed. Remaining S33 SecureBootDXE and EsaFull.

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

P2-104/E99: B11 independent raw NVAR graph on verified 1.24 AFU: 1814 outer + 39 nested defaults records cross-checked, all valid named chains uniquely resolve; detached data chains accounted by invalidated roots. Both stores contain different terminal payloads; FFS state interpretation alone cannot select AMI active store. 91 S24 + 1 S33 =92 pending, unchanged. New ROMs not accessible in this session; next actual active-store selection and USB/NVMe/EsaFull mapping when supplied. See [RAW_NVAR_BASELINE_CHECKPOINT.md](RAW_NVAR_BASELINE_CHECKPOINT.md).

P2-105/E100: B05/B11 1.24 active-store predicate reconstructed in PEI and DXE. With default addresses and captured E0/F0 FFS states, PEI selects second store (0x41000). Both are readable but Setup/BootOrder differ; no runtime/HOB or migration proof. 91 S24 + 1 S33 =92 pending. See [RAW_NVAR_BASELINE_CHECKPOINT.md](RAW_NVAR_BASELINE_CHECKPOINT.md#active-store-selection-follow-up-p2-105e100).

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
