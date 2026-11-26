# Active backlog
See data/pending.tsv for machine-generated queue. It has 179 pair-specific records: 168 candidate/partial/open rows for 1.24→1.32 and all 37 non-relocation-equivalent differences for 1.32→1.33 (including non-executable sections). Review of existing evidence is not a claim that every row is unresolved. Review each pair separately; priority is provisional and not measured likelihood. Private P1/P2 blocker fields provide details; historical third-party AFU incident is out of scope.

| ID | Priority | Work | Completion condition |
|---|---|---|---|
| B01 | CLOSED (static) | CPU policy Stibp/CpuPei/CpuDxe | all changed code groups attributed, no new CPU policy operations; runtime B12 remains |
| B02 | High / partial | FastBootOption/FastBootRuntime, OEM init | FastBootRuntime explained; FastBootOption BootOrder allocation/numbering attributed; remaining trigger/error paths and OEM init |
| B03 | High / partial | SmiVariable/PiSmmCore/PiSmmIpl, SMM latency | P2-32–34: validation and local copies attributed; residual mapping and actual runtime/legacy path distinction, B12 latency |
| B04 | High / partial | UMA guard/order/error path, APCB byte 0x125 | P2-43: recovery guard, protocol notify, transaction order, alternate CBS route identified. Native browser routing, callback delivery, runtime UMA and byte 0x125 remain. |
| B05 | High / partial | Setup/NVRAM remaining callbacks, actual boot/Secure Boot | P2-44: password algorithm preservation broadened; validate migration/reset, remaining callbacks and actual state. |
| B06 | High / partial | TPM/AHCI/OEM | P2-39–42: TPM2 PCR1 contract confirmed, legacy PCR7 conditional, seven policy/fTPM sections explained; event log/PCR replay, legacy dispatch, residual TcgDxe/Nvflag and legacy SMM/OEM. |
| B07 | Medium | Remaining USB/NVMe, S3 | resolve residual changed functions, SMI fallback and queue limits; run appropriate tests |
| B08 | CLOSED | Normalizer discrepancy | Both TE modules differ only at ImageBase byte +0x10. Full normalized images equal; ledger corrected. See REPRODUCTION.md. |
| B09 | High / partial | Completeness | raw_coverage.py accounts for all 16 MiB per pair, two changed bytes unmapped in 1.24 comparisons; explain these and candidate APOB type 63, embedded raw PE, remaining unknown contained changes. See PLATFORM_REPRODUCTION.md. |
| B10 | High / partial | Independent 1.32→1.33 | P2-45–50: all 37 non-reloc sections reviewed, 26 attributed; 11 partial (mailbox, Setup/Bds/crypto/EsaFull, one 4096-byte opaque block); 7 relocation-only previously attributed. |
| B11 | High / partial | Reproducibility | all core and platform inspectors restored and tested, including selected NVAR link graph, APCB/PSP/microcode, IFR, ACPI and raw accounting. Remaining complete raw NVAR/active-store semantics, more synthetic fixtures and independent function-level semantic verification. |
| B12 | High | Hardware baseline | before/after same OS/settings: microcode, meminfo, boot entries, Secure Boot, TPM event log/PCRs if present, temperatures, idle W, CPU/memory workloads, PCIe link/AER, USB, NVMe, AC loss; then UMA as separate change |
| B13 | Blocked | Windows packages | static unpack Inno Setup via innoextract, compare scripts/AFU; not required to assess post-boot changes |
 
Completion criteria: all inventory differences explained/blocked with justification; raw-region coverage accounted; all critical static conclusions independently reproduced; distinguish unknown runtime effects and measurements. No requirement to solve historical third-party failure or obtain 1.31.
