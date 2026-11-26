# Lenovo ThinkCentre M75n: BIOS 1.24 → 1.33 audit

Snapshot 2026-11-26. Goal: assess real post-upgrade regressions on Picasso FP5 / Ryzen PRO 3300U, not diagnose a third-party update failure. 1.32 is an intermediate comparison point, not a required flash step. Static analysis only; no hardware update, no performance measurements.

Start with [HANDOFF.md](HANDOFF.md), [METHODOLOGY.md](METHODOLOGY.md), [EVIDENCE.md](EVIDENCE.md), [BACKLOG.md](BACKLOG.md), [SOURCES.md](SOURCES.md). Data files are sanitized snapshots of the working ledger, not independent proof. The private working sheet is authoritative for device-specific data; its URL and raw data are intentionally not public. No firmware images or proprietary executables are committed.

- [data/inventory.tsv](data/inventory.tsv): 2256 original inventory records, 22 columns; private 1.24 non-executable hashes and free-text conclusions omitted.
- [data/changes.tsv](data/changes.tsv): 284 changed records, same schema.
- [data/pending.tsv](data/pending.tsv): 220 pair-specific rows: 183 historical open/partial/candidate in 1.24→1.32 and 37 evidence reviews in 1.32→1.33 (44 differences minus 7 relocation-equivalent). Heuristic priority, not a finding.
- [data/p1-public.tsv](data/p1-public.tsv), [data/p2-public.tsv](data/p2-public.tsv): selected historical evidence records; omitted rows remain in private ledger.
- [tools/audit_verify.py](tools/audit_verify.py): reconstructed verifier; see verification caveats.

Do not run flash tools, write EFI variables, or publish personal dumps. Compare binaries offline. Add new evidence with stable IDs, version pair, hash, coordinates, method, uncertainty, and explicit next test. Keep historical corrections rather than deleting them.
