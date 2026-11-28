# Review v0.3.2

Follow-up to PR #7 (97f188d30a1f9e73f594a23a13911706478f83af), based on PR #6 (985eb325131c87c8ffab8d38d9e7de63abca27fe). Focus on P1–P8, not another redesign. P9/P10 deferred until actual ROM blockers. Review the v0.3.2 normative section in PROTOCOL.md and TEST_RESULTS.md.

1. Verify full suite and adaptation of the 41 addendum tests. Run mutation_v032.py, distinguish surviving, equivalent, invalid and errors-only mutations; review changed anchors and equivalences. Historical test scripts are preserved by commit.
2. Inject internal errors during input/evaluate/summary/encoding; verify aborted receipt, exit codes, handoff and no promoted result. Check parser errors at nested LZMA stream offsets and diagnostics on blocked roles.
3. Check exact vs historical scope, identical payload, subset, changed forbidden bytes, differing length, new header/plausibility hypotheses, counts. Check gate mismatch and missing combinations, not merely all-pass cases.
4. Attack coordinated edits to C3/prefixes, leaves, root hints and lineage. Fully fabricated internally coherent receipt is outside consistency verification. Compare two independently run receipts; no assurance promotion.
5. If real ROMs available: verify SHA-256, run pilot, retain receipt even if BLOCKED; identify first actual blocker by stream/offset/lineage, compare six hashes with A75 and phase A; preserve expectations. No binaries or private paths in public Git.
6. Report readiness for real run and remaining substantive blockers only. Save separate PR against main; do not modify prior branches or main.
