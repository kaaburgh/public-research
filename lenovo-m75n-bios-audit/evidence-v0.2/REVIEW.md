# Reviewer brief — v0.2

Review as a protocol and trust-boundary design, not as a claim that firmware is safe. Compare to v1 (commit 4095d9cf951f79bd0d4ca51f89afe82a350dbb88) and independent run (commit 935daa09485a5fb6ba7b396c1024c027f735ad5c, REPORT.md and PROVENANCE.md). This is a standalone PR based on main; no dependency on merging PR #1.

Please find counterexamples where a misleading PASS can occur. In particular:
1. Are object identity, extraction lineage, selector scope and evidence acceptance sufficiently separated? Is complete coverage falsifiable, and how should A75 and independent adapters prove it? Should observation manifests bind pack digest directly, not only via receipt?
2. Does the selector count every relevant RAW node, including malformed or nested ones, without double counting? How should an unsupported parser feature affect coverage? Propose concrete test vectors.
3. Audit canonical JSON profile, exact set checks, resource limits, typed comparisons, bounds/undefined cases, mixed verdicts, and exit semantics. Are the primitive operations adequate and safely composable? Is the implementation overly restrictive or underspecified?
4. Audit evidence lifecycle: immutable identity, historical source vs protocol revision, stale and conflicting receipts, append-only enforcement, blind run freeze, trust and review. How should receipt validation and trust policy be designed?
5. Evaluate the migration: 3 new claim IDs, exact diff offsets strengthened from independent observation; no semantic authentication claim. What could be lost in migration?
6. How to scale to 2256 inventory entries, duplicate FFS GUIDs, normalization of PE/TE and semantic reasoning without building a general-purpose unsafe DSL? What abstractions should be generic and what BIOS-specific?
7. Review reference core and CLI for false positives, failure to record blocked runs, privacy leakage and denial of service. Try adversarial synthetic tests. No need to acquire ROMs or execute firmware. Distinguish protocol defects from implementation bugs.

Deliver findings severity-ranked with reproduction or counterexample, suggested contract changes, and an adoption decision (accept / accept with changes / redesign). Do not rewrite claims to fit outcomes. Preserve separate review branch/PR.

Known gaps: no real adapter or actual ROM replay in v0.2; no independent receipt validator, cryptographic attestation, CI enforcement, dependency graph, or Sheets migration. Core synthetic tests executed in authoring JS environment using test-only digest, not the Node CLI. The author intentionally chose a narrow, strict JSON profile and versioned primitive vocabulary; review these decisions rather than assuming them immutable.
