# Active backlog
See data/pending.tsv for machine-generated queue. It has 127 pair-specific records: 122 candidate/partial/open rows for 1.24→1.32 and 5 remaining partial sections for 1.32→1.33 (39 of 44 attributed). Review of existing evidence is not a claim that every row is unresolved. Review each pair separately; priority is provisional and not measured likelihood. Private P1/P2 blocker fields provide details; historical third-party AFU incident is out of scope.

| ID | Priority | Work | Completion condition |
|---|---|---|---|
| B01 | CLOSED (static) | CPU policy Stibp/CpuPei/CpuDxe | all changed code groups attributed, no new CPU policy operations; runtime B12 remains |
| B02 | High / partial | FastBootOption/FastBootRuntime, OEM init | FastBootRuntime explained; P2-74–75 trigger/edge cases narrowed, exact BDS path label and full residual/OEM init remain |
| B03 | High / partial | SmiVariable/PiSmmCore/PiSmmIpl, SMM latency | P2-32–34/77: separate legacy SW-SMI vs normal runtime-variable path established; legacy return-size candidate; residual mapping and B12 latency |
| B04 | High / partial | UMA guard/order/error path, APCB byte 0x125 | P2-43: recovery guard, protocol notify, transaction order, alternate CBS route identified. P2-71 byte0x125 attributed; P2-72 conditional native RouteConfig established. Actual browser registration/delivery, persistence and runtime UMA remain. |
| B05 | High / partial | Setup/NVRAM remaining callbacks, actual boot/Secure Boot | P2-44: password algorithm preservation broadened; validate migration/reset, remaining callbacks and actual state. |
| B06 | High / partial | TPM/AHCI/OEM | P2-39–42: TPM2 PCR1 contract confirmed, legacy PCR7 conditional, seven policy/fTPM sections explained; event log/PCR replay, legacy dispatch, residual TcgDxe/Nvflag and legacy SMM/OEM. |
| B07 | Medium | Remaining USB/NVMe, S3 | resolve residual changed functions, SMI fallback and queue limits; run appropriate tests |
| B08 | CLOSED | Normalizer discrepancy | Both TE modules differ only at ImageBase byte +0x10. Full normalized images equal; ledger corrected. See REPRODUCTION.md. |
| B09 | High / partial | Completeness | raw_coverage.py accounts for all 16 MiB per pair, two changed bytes unmapped in 1.24 comparisons; explain these and candidate APOB type 63, embedded raw PE, remaining unknown contained changes. See PLATFORM_REPRODUCTION.md. |
| B10 | High / partial | Independent 1.32→1.33 | P2-45–54: 31/37 non-reloc sections attributed, plus 7 reloc-only; 5 partial (EsaFull expanded GUI, four mailbox modules); P2-63 closes Setup HII ID. |
| B11 | High / partial | Reproducibility | all core and platform inspectors restored and tested, including selected NVAR link graph, APCB/PSP/microcode, IFR, ACPI and raw accounting. Remaining complete raw NVAR/active-store semantics, more synthetic fixtures and independent function-level semantic verification. |
| B12 | High | Hardware baseline | before/after same OS/settings: microcode, meminfo, boot entries, Secure Boot, TPM event log/PCRs if present, temperatures, idle W, CPU/memory workloads, PCIe link/AER, USB, NVMe, AC loss; then UMA as separate change |
| B13 | Blocked | Windows packages | static unpack Inno Setup via innoextract, compare scripts/AFU; not required to assess post-boot changes |
 
Completion criteria: all inventory differences explained/blocked with justification; raw-region coverage accounted; all critical static conclusions independently reproduced; distinguish unknown runtime effects and measurements. No requirement to solve historical third-party failure or obtain 1.31.

Latest active queue: 173 pair-specific records (168 S24 + 5 S33).

P2-55/56: B10 mailbox purpose corroborated by Lenovo documentation (SRWINx64 supported; WMI not supported on M75n); exact caller/authorization remains open. B06/B12 read-only PCR1 baseline tool prepared and synthetic-tested; physical data still needed. No change in pending counts. See VENDOR_PCR1_CHECKPOINT.md.

P2-57–59: B04 conditional model and read-only UMA observation prepared; B12 RNG smoke test added. All remain open for actual hardware and binary evidence. B10/B02/B03 cannot progress offline without ROMs. No pending-count change.

P2-60–62: B03 PMU counter 0x2B confirmed in AMD OSRR; B09 type63 is documented APOB NV, payload/active state remains open; B02/B05 boot inventory and B12 experimental controls added. No binary closure. See SMM_APOB_BOOT_CHECKPOINT.md.

P2-63–65: verified ROMs supplied; B10 Setup resolved; B09 APOB NV actual region accounted, cache selection and other residuals open; thermal module prior closure reverified. Next B10 mailbox and EsaFull. See ROM_RESTORED_CHECKPOINT.md.

P2-66–70 / E61–65: all three ROMs verified; mailbox producer/consumer and NVRAM policy scope narrowed, conditional restore/deletion failure risk; EsaFull UI selection/position logic narrowed; native UMA callback CHANGING and ignored browser-update status confirmed; EFS page pointers exact, two tail bytes still unresolved. No new section closure: 39/44 S33, 173 pending. Hardware and complete mapping remain open.

P2-71–73 / E66–68: APCB byte0x125 attributed to DFG token0x306 PCI MMIO boundary (logical8), PciRootBridge unchanged; native browser dynamic AmdSetup VarStore and conditional RouteConfig path identified in both UI engines, save loop ignores write status; two Computrace API PE rows closed by complete 26-byte attribution each. 166 S24 + 5 S33 =171 pending; 39/44 S33 attributed. Actual browser registration/persistence and hardware remain open.

P2-74–76 / E69–71: FastBootOption ExitBootServices + BootFlow7 gate and BDS producer mapped, unchanged uninitialized DataSize guard; new max-ID wrap/early-exit leaves tail potentially uninitialized, both versions ignore option writes. NvramPei sole normalized byte attributed to Setup size check, one S24 row closed. 165 S24 + 5 S33 =170 pending; 39/44 S33 attributed. B02 remains partial; runtime not tested.

P2-77–79 / E72–74: separate legacy SmiVariable and normal runtime-variable route confirmed; legacy return-size candidate. 43 S24 small PE/TE sections (8 P1 + 35 P2) fully attributed to Setup-size adaptation, stack/layout and TE relocation. 122 S24 + 5 S33 =127 pending; 39/44 S33 attributed. Hardware untested; B03 partial.
