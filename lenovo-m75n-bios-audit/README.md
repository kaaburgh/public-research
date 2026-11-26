# Lenovo ThinkCentre M75n: BIOS 1.24 → 1.33 audit

Snapshot 2026-11-26. Goal: assess real post-upgrade regressions on Picasso FP5 / Ryzen PRO 3300U, not diagnose a third-party update failure. 1.32 is an intermediate comparison point, not a required flash step. Static analysis only; no hardware update, no performance measurements.

Start with [HANDOFF.md](HANDOFF.md), [METHODOLOGY.md](METHODOLOGY.md), [EVIDENCE.md](EVIDENCE.md), [BACKLOG.md](BACKLOG.md), [SOURCES.md](SOURCES.md). Data files are sanitized snapshots of the working ledger, not independent proof. The private working sheet is authoritative for device-specific data; its URL and raw data are intentionally not public. No firmware images or proprietary executables are committed.

- [data/inventory.tsv](data/inventory.tsv): 2256 original inventory records, 22 columns; private 1.24 non-executable hashes and free-text conclusions omitted.
- [data/changes.tsv](data/changes.tsv): 283 changed records (corrected from 284; see REPRODUCTION.md), same schema.
- [data/pending.tsv](data/pending.tsv): 102 pair-specific rows: 101 open/partial/candidate in 1.24→1.32 and 1 remaining partial section in 1.32→1.33 (43 of 44 attributed). Heuristic priority, not a finding.
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
