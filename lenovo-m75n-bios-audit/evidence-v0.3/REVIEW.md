# Review v0.3.1 (PR #5 follow-up)

Base: v0.3 commit 3c3c555c6c84f11b8f26b8580adf74851b831f8e; review commit 3ae7117aa64401e0805cbc6be398f67cfe444c1e. PR #5 remains historical. Review changes against R1–R9 and additional R10–R14, not just a new feature list.

1. Run all three suites and version-specific mutation script; check baseline, stale mutation anchors, syntactic validity, actual test failures and surviving mutants. Retest original adversarial vectors (expect fixed defects to fail closed, not the old bad outcomes). Regression tests/fixtures were imported from PR #5 with explicit adaptation to new API/coverage.
2. Attack pad data/name, FV extension bounds/checksums, both erase polarities, opacity within owner, deletion and visible duplicate tripwire. Check whether conservative leaf coverage is appropriate and whether new diagnostics are complete.
3. Attack handoff: independently edit a verdict, reason, observed value, count, selection, root identity, legacy path, summary, differential status; recanonicalize and rename by digest. Distinguish inconsistencies from fabricated but internally consistent receipts; replay is needed for the latter.
4. Check C3 exact set, C4 field plausibility vs semantics, C5, C6 exact tail, C7 list layout, C8 counts, resource limit behavior, empty runs and multiplicity. Ensure weaker v1 subset cannot silently upgrade to exact C3.
5. Run real ROMs if accessible and compare all six hashes with A75 and phase A. Preserve all failures; do not modify expectations or ignore diagnostics. If blocked, identify the first unsupported/malformed structure with exact offset and proposed reviewed grammar addition. No binaries/private paths in Git.
6. Evaluate whether v0.3.1 is sufficient to proceed to real-ROM replay, not whether the complete general protocol is done. Publish report in separate branch/PR; leave source and main untouched.

Historical sources and tests: PR #5 (3ae7117a), PR #4 (3c3c555c), PR #1 (4095d9cf), independent run 935daa09. Original historical import file is preserved; use legacy_import.py with exact original v1 inputs to generate a v0.3.1 receipt. Historical HANDOFF.md still describes v0.3.
