# Handoff
Read README, SOURCES, METHODOLOGY, EVIDENCE, BACKLOG, then the private sheet if authorized. The sheet is the live registry; this commit is a dated static snapshot. Preserve scope: assess post-upgrade risks from M33KT24A to M33KT33A. Do not restart the third-party update-error investigation or search for 1.31.

Current conclusions:
- Native Setup 446→449 bytes. PEI and DXE detect size mismatch; DXE rebuilds store with new StdDefaults, selectively preserves other variables. SecureBootSetup belongs to defaults; it may return to Enabled and affect actual SecureBoot state. BootOrder and AmdSetup absent from defaults; preservation still conditional on updater and later callbacks.
- AmdSetup size 0x53F; IDs 0x420C3F32→0xEF162DFE→0xBA27F8CE; migration copies [0x20,0x164) on mismatch if variable survives. DDR4/AMD UMA settings in range.
- Factory APCB payloads and key AGESA/SMU/memory drivers unchanged after normalization. Live override must be analyzed privately, not conflated with OEM policy. Microcode 08108109→0810810E for Picasso B1; effect unknown. Other patch 08200103→08200105, 08108002 unchanged.
- PCIe/IOMMU baseline unchanged; NVMe and USB changes mostly preboot, not proof of runtime equivalence. S3 script validation tightened. No demonstrated runtime regression. Native UMA menu and a 32-bit callback width mismatch plus second sync path are important practical findings.
- Recommended verification on local hardware, not remote-only flashing. First capture settings and baseline; use official procedure; compare identical configurations before changing UMA. No claim of guaranteed safe downgrade or update.

Resume order: CPU policies (Stibp/CpuPei/CpuDxe), FastBoot, SMM variable/core/IPL, TPM/AHCI, remaining OEM callbacks, raw coverage, then hardware verification. Continue open rows in data/pending.tsv and private Backlog; do not close a row merely because a pattern or high instruction similarity exists. P1 and P2 historical IDs cross-reference evidence. Distinguish 1.24→1.32 from 1.32→1.33. Explicitly note old claims superseded by later findings.

Reproduction: owner provides ROMs/AFU dump externally; this is expected and not a blocker. Reconstructed inventory.py reproduces all 2256 keys and all per-release payload hash multisets, with corrected PcdPeim lineage matching. audit_verify.py reproduces 1522 executable hashes and zero classification discrepancies on corrected reference. B08 closed: the two TE changes are ImageBase-only. Corrected union 283; 257 exact +68 normalized +182 different +1 removed. Flash map model matches golden digest for all six descriptor copies. See REPRODUCTION.md for commands and evidence. Remaining: raw-ROM coverage (B09), specialized parsers and independent semantic verification (B11). No hardware update performed.

Platform checkpoint: `PLATFORM_REPRODUCTION.md` replaces the earlier missing-specialized-tools blocker for the historical M75n checks. AMD/APCB/patch, selected NVAR chains/defaults, static DSDT/SSDT, full en-US IFR and raw byte accounting reproduced. B09 remains partial: physical differences are counted, two changed bytes remain outside recognized structures, and contained semantic differences are open. B11 remains partial for complete independent semantic verification, active NVAR store selection, and broader parser/fixture coverage. Resume B01 CPU policies rather than repeating successful checks. ROM/AFU remain external by design.

Risk checkpoint P2-27–31 / E23–26: B01 static closed for Stibp, CpuPei, CpuDxe. FastBootRuntime explained; FastBootOption changed dynamic BootOrder allocation and ID selection; B02 partial. Next B03 SMM, then residual B02 OEM and B06. 177 open/partial/candidate 124→132, 37 132→133 evidence reviews. See CPU_FASTBOOT.md. Runtime and microcode A/B remain open.

Risk checkpoint P2-32–38 / E27–33: B03 partial (SMM range checks, request copies; legacy interface not proved to be Linux efivarfs path), B06 partial (Ahci and legacy SMM DEPEX explained, code residual). Strong new static regression candidate in Tpm20PlatformDxe: variable-size probe removed, caller stack lengths uninitialized, ReadyToBoot measured-boot path may skip BootOrder/Boot#### PCR1 events. Not runtime demonstrated, no evidence of TPM clear or actual boot-variable deletion. Prioritize validation before TPM-bound boot update, then residual OEM/UMA. 175 open/partial/candidate 124→132 and 37 132→133 evidence reviews. See SMM_TPM_AHCI.md.

Risk checkpoint P2-39–44 / E34–39: seven TPM policy/fTPM sections closed (size/stack); Tpm20PlatformDxe PCR1 contract defect confirmed, separate TPM2 PCR7 path has initialized buffers; AmiTcgPlatformDxe legacy PCR1/PCR7 helper defect conditional on legacy protocol. OememDxe notification belongs to NvramDxe, recovery marker guard identified, persistent AmdSetup precedes APCB writes and same-size gate can skip retry; CBS RouteConfig alternate writes APCB if routed. SetupLoadDefault now always preserves prior password hash algorithm within this path. No runtime regression demonstrated. B04/B05/B06 partial. 168 S24 open/partial/candidate, 37 S33 evidence reviews. Next B10 independent second-pair review, residual UMA browser/event, OEM/SMM. See TPM_UMA_DEFAULTS.md.

B10 checkpoint P2-45–50 / E40–45: 44 sections changed 1.32→1.33; 7 relocation-only, 26 additionally statically attributed, 11 partial. 168 S24 open/partial/candidate and 11 S33 partial = 179 pair-specific records. Factory Secure Boot certificate lists exactly identical (three authenticated containers; timestamp changes only), AMITSE .text sole change ACPI OEMRevision 0x1200→0x1210, HII string updates; Setup adds internal LemPower000L ID, forms unchanged. New request-triggered Secure Boot mailbox producer in SwSmi534D0040. Large crypto/BDS/Setup code sizes and instruction boundaries unchanged, but address/data mapping not closed. Next B10 residual consumers/producer and large modules, B04 native browser/UMA, B02/B03 OEM/SMM. See RELEASE_132_133.md and data/s33-attribution.tsv; S24 statuses independent. Runtime remains untested.

Further B10 P2-51–52/E46–47: exact PE code/reference audit validates 27,253/27,253 relocation sites and targets with monotonic data anchors and no nonzero canonical data edits after explicit path/date normalization. AbtCryptoDriver/TlsDxe/CryptRuntimeDxe/Bds attributed; Setup code differences address/time/version only, HII LemPower000L meaning remains. SecureBootDXE protocol-notify consumer and two NVRAM policy predicates narrowed. 168 S24 +7 S33 remaining =175 records. Seven residuals: Setup, EsaFull, SwSmi534D0040, SecureBootDXE, NvramDxe, NvramSmm, 4096-byte block. Runtime remains untested.

Latest B10 P2-53–54/E48–49: 4096-byte body all 511 changes within two RSA-2048 signature fields; identical modulus and strict SHA256 DigestInfo checks 4/4, zeroing fields makes bodies identical. Signed ranges/trust chain not verified. EsaFull normalized chunk multiset matches 97.6% old rows; two actual transfers point to enlarged functions rather than identical clones, GUI semantics unresolved. 38/44 S33 changed sections attributed, six partial (Setup, EsaFull, SwSmi534D0040, SecureBootDXE, NvramDxe, NvramSmm). 168 S24 + 6 S33 = 174 active records. No runtime proof. Next resolve residuals, then native UMA routing, OEM/SMM.

P2-55/56 / E50–51: Lenovo HT518672 identifies M33KT33A as minimum SRWINx64 factory-key restoration release, WMI=N for M75n; HT518129 lists 1.32 certificate transition. Corroborates P1-24/P2-49/52, not actual SRWIN call graph or authorization proof. B06/B12: tools/pcr1_audit.py performs TPM2 PCR1 replay and boot-variable name summary, eight synthetic fixture checks passed. See VENDOR_PCR1_CHECKPOINT.md. No new firmware bytes available (Library materialization failed); no rows reclassified. B10 six partial, B04 native routing, B02/B03 remain next when ROMs supplied; B12 read-only baseline ready.

P2-57–59 / E52–54: B04 size-gate model (225 conditional pairs) clarifies low-byte-safe 128 MiB can skip secondary APCB write if browser values agree; native RouteConfig still open. tools/uma_audit.py (nine fixture assertions + model checks) compares RAM/VRAM/GTT and firmware map. B12 adds tools/rng_smoke.c, compiled/run on container CPU, motivated by unverified Dell Picasso report, not a Lenovo regression finding. See UMA_RUNTIME_CHECKPOINT.md. Source bytes remain inaccessible; B10 and B02/B03 blocked this session; no reclassifications. Need owner-supplied verified ROMs. Hardware baseline can be captured independently.

P2-60–62 / E55–57: AMD OSRR 56255 p153 confirms PMCx02B for Picasso; perf per-CPU rate and separate hwlat sampling protocol prepared, actual target not tested. B09 generic type63 independently identified as APOB NV; actual content and 0x20043/44 open. B02/B05/B12 boot_inventory.py captures BootOrder and all OS-visible Boot#### without raw payload, nine synthetic checks passed; allocator trigger/collision handling and live states open. See SMM_APOB_BOOT_CHECKPOINT.md. Binary sources unavailable; 174 pending unchanged. B10→B04→B02/B03 next on source access.

P2-63–65 / E58–60: all three source hashes verified, A75 extraction succeeded. S33 Setup now closed: LemPower000L string ID0x809 = existing Performance Mode QID0x14D/Setup[8]; forms/defaults unchanged. B09 type63 live APOB vs erased vendor region, 41436 differences exactly accounted, other residuals remain. ThermalMode/Pei prior P2-01/02 independently reverified. 39/44 S33 attributed, 168 S24 + 5 S33 = 173 pending. See ROM_RESTORED_CHECKPOINT.md. Next B10 mailbox and EsaFull, then B04/B02/B03. Source access restored in this session only.

P2-66–70 / E61–65: all three ROMs verified; mailbox producer/consumer and NVRAM policy scope narrowed, conditional restore/deletion failure risk; EsaFull UI selection/position logic narrowed; native UMA callback CHANGING and ignored browser-update status confirmed; EFS page pointers exact, two tail bytes still unresolved. No new section closure: 39/44 S33, 173 pending. Hardware and complete mapping remain open. Next B04 Save & Exit routing and APCB 0x125, B10 residual data/GUI/authorization mapping, then B02/B03. Source access available this session.

P2-71–73 / E66–68: APCB byte0x125 attributed to DFG token0x306 PCI MMIO boundary (logical8), PciRootBridge unchanged; native browser dynamic AmdSetup VarStore and conditional RouteConfig path identified in both UI engines, save loop ignores write status; two Computrace API PE rows closed by complete 26-byte attribution each. 166 S24 + 5 S33 =171 pending; 39/44 S33 attributed. Actual browser registration/persistence and hardware remain open. Next B02/B03 residuals, B10 mailbox/GUI mapping; actual B04 delivery and hardware B12. Source access verified this session.

P2-74–76 / E69–71: FastBootOption ExitBootServices + BootFlow7 gate and BDS producer mapped, unchanged uninitialized DataSize guard; new max-ID wrap/early-exit leaves tail potentially uninitialized, both versions ignore option writes. NvramPei sole normalized byte attributed to Setup size check, one S24 row closed. 165 S24 + 5 S33 =170 pending; 39/44 S33 attributed. B02 remains partial; runtime not tested. Next B03 remaining SMM and B02 OEM/boot error paths, then B10 residual mapping; B04 hardware validation.

P2-77–79 / E72–74: separate legacy SmiVariable and normal runtime-variable route confirmed; legacy return-size candidate. 43 S24 small PE/TE sections (8 P1 + 35 P2) fully attributed to Setup-size adaptation, stack/layout and TE relocation. 122 S24 + 5 S33 =127 pending; 39/44 S33 attributed. Hardware untested; B03 partial. Next remaining P1 risk-specific modules, B03/B10 complete residual mapping, B12 hardware; B04 actual persistence.

P2-80–83 / E75–78: OEM dispatcher two entries removed, WMI standard registration retained for one, obsolete preload variable branch removed; WMI DEPEX closed, PE remains partial. UsbInt13 coherent shared structure layout. Seven Setup-size and nine build-time/version/layout sections closed. 103 S24 + 5 S33 =108 pending, 39/44 S33 attributed. Hardware untested. Next B10 mailbox residuals, USB/SMM core code and other risk-specific P1 rows.

P2-84/E79: full 1.32→1.33 layout/relocation attribution of NvramDxe and NvramSmm; 2 S33 closures. 103 S24 + 3 S33 =106 pending; 41/44 S33 attributed. Actual hardware and mailbox authorization behavior remain open. Next: remaining three S33 modules, then risk-specific S24 core, SMM, NVMe and USB.

P2-85/E80: full S33 SwSmi534D0040 attribution; 103 S24 + 2 S33 =105 pending, 42/44 S33 attributed. Remaining S33 SecureBootDXE and EsaFull. Next complete remaining two S33 maps, then risk-specific S24.

P2-86/E81: SecureBootDXE old function reordering separated from new event callback; 703/722 normalized old instructions match in five segmented comparisons, remaining code/data/relocation verification open. 105 pending, 42/44 S33 attributed unchanged. Resume with complete SecureBootDXE target/data/relocation mapping, then EsaFull.

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

P2-147/E142: NVMe per-namespace PRP and metadata buffer allocations replaced by shared controller buffers; scope and cleanup traced, concurrency/OS memory unproved. 72 pending. See [NVME_NAMESPACE_OWNERSHIP_CHECKPOINT.md](NVME_NAMESPACE_OWNERSHIP_CHECKPOINT.md).

P2-148/E143: common new NVMeSmm/AhciInt13Smm SMRAM descriptor init ignores statuses; conditional failure may leave null table with nonzero count. No observed failure. 72 pending. See [SMM_DESCRIPTOR_INIT_CHECKPOINT.md](SMM_DESCRIPTOR_INIT_CHECKPOINT.md).
