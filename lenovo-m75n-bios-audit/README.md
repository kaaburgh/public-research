# Lenovo ThinkCentre M75n: BIOS 1.24 → 1.33 audit

Snapshot 2026-11-26. Goal: assess real post-upgrade regressions on Picasso FP5 / Ryzen PRO 3300U, not diagnose a third-party update failure. 1.32 is an intermediate comparison point, not a required flash step. Static analysis only; no hardware update, no performance measurements.

Start with [HANDOFF.md](HANDOFF.md), [METHODOLOGY.md](METHODOLOGY.md), [EVIDENCE.md](EVIDENCE.md), [BACKLOG.md](BACKLOG.md), [SOURCES.md](SOURCES.md). Data files are sanitized snapshots of the working ledger, not independent proof. The private working sheet is authoritative for device-specific data; its URL and raw data are intentionally not public. No firmware images or proprietary executables are committed.

- [data/inventory.tsv](data/inventory.tsv): 2256 original inventory records, 22 columns; private 1.24 non-executable hashes and free-text conclusions omitted.
- [data/changes.tsv](data/changes.tsv): 283 changed records (corrected from 284; see REPRODUCTION.md), same schema.
- [data/pending.tsv](data/pending.tsv): 175 pair-specific rows: 168 open/partial/candidate in 1.24→1.32 and 37 evidence reviews in 1.32→1.33 (44 differences minus 7 relocation-equivalent). Heuristic priority, not a finding.
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
