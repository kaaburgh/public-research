# Active backlog
See data/pending.tsv for machine-generated queue. It includes every historical status containing candidate/partial/open plus normalized 1.32→1.33 differences, not a promise that all are unresolved. Review each pair separately; priority is provisional and not measured likelihood. Private P1/P2 blocker fields provide details; historical third-party AFU incident is out of scope.

| ID | Priority | Work | Completion condition |
|---|---|---|---|
| B01 | High | CPU policy Stibp/CpuPei/CpuDxe | attribute changes in MSR/CPUID/mitigation paths or state concrete blocker; distinguish microcode |
| B02 | High | FastBootOption/FastBootRuntime, OEM init | attribute changed paths and config defaults; assess cold boot/device enumeration |
| B03 | High | SmiVariable/PiSmmCore/PiSmmIpl, SMM latency | compare dispatch/data validation/DEPEX; distinguish runtime path from preboot |
| B04 | High | UMA guard/order/error path, APCB byte 0x125 | prove callback input width, synchronization trigger and fallback; verify on hardware |
| B05 | High | Setup/NVRAM remaining callbacks, actual boot/Secure Boot | verify boot state after official update, no destructive writes |
| B06 | Medium | TPM/AHCI/other OEM handlers | attribute register/access changes, interface and reset effects |
| B07 | Medium | Remaining USB/NVMe, S3 | resolve residual changed functions, SMI fallback and queue limits; run appropriate tests |
| B08 | High | Normalizer discrepancy | AmdSpiRomProtectPei and PlatformCustomizePei: old different, new normalized equal; inspect header and relocation entries; do not auto-close |
| B09 | High | Completeness | full raw region diff incl PSP/BHD/APCB/APOB/microcode/embedded raw PE, duplicate GUID and unmatched sections; explain all or explicit blockers |
| B10 | Medium | 1.32→1.33 distinct changes | review each of 24 normalized differences, including crypto, TLS, SecureBootDXE, NVRAM, Setup, BDS |
| B11 | High | Reproducibility | reconstruct missing inventory generator and flashmap model; preserve exact outputs, scripts, tests; verify prior results independently |
| B12 | High | Hardware baseline | before/after same OS/settings: microcode, meminfo, boot entries, Secure Boot, temperatures, idle W, CPU/memory workloads, PCIe link/AER, USB, NVMe, AC loss; then UMA as separate change |
| B13 | Blocked | Windows packages | static unpack Inno Setup via innoextract, compare scripts/AFU; not required to assess post-boot changes |
 
Completion criteria: all inventory differences explained/blocked with justification; raw-region coverage accounted; all critical static conclusions independently reproduced; distinguish unknown runtime effects and measurements. No requirement to solve historical third-party failure or obtain 1.31.
