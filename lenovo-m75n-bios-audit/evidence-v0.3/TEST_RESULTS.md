# v0.3.1 validation results

Tested implementation commit: `7fcedc38ebdeb98adc3c7ad1fc6902a789a71d77`.
Python 3.13.5. All 13 locally tested source, fixture, profile and historical receipt files were verified against the Git tree's blob IDs before reporting results.

## Unit and regression tests

```sh
V1_DIR=/path/to/v1-checkout IR_DIR=/path/to/independent-reproduction-checkout \
  python -m unittest -q test_pilot test_v03_regression test_v031_review
```

The paths denote repository roots at commits 4095d9cf951f79bd0d4ca51f89afe82a350dbb88 and 935daa09485a5fb6ba7b396c1024c027f735ad5c, respectively. Original claims and A75 receipt were retrieved from these pinned Git objects. First run: 73 tests, one skipped because those two inputs were absent. Final run with them: **73/73, zero skips** (8.863 seconds).

- test_pilot: 24
- test_v03_regression: 28
- test_v031_review: 21

## Mutation tests

Version-specific mutation_v031.py: **26/26 detected, 0 survived, 0 invalid mutation anchors or syntax errors**. The exact committed mutation definitions and unittest command were executed in isolated temporary copies using a four-worker local runner (parallel scheduling only), with original historical artifacts available. Every mutant triggered at least one assertion failure; none were counted solely due to an import failure. The old 49-mutant v0.3 suite is historical and was not rerun unmodified against the refactored code. This is not an exhaustive mutation score for the complete implementation.

Detected: pad_data, pad_names, opaque_owner, raw_leaf, ext_size, ext_pad, header_checksum, fixed_checksum, untracked_fv, untracked_ffs, scan_streams, lzma_trailing, root_partition, blockmap, c3_subset, c8_count, c8_header, c5_certtype, c1_duplicate, multiplicity, vacuous_counts, receipt_verdicts, receipt_summary, legacy_lineage, semantic_status, gate.

## CLI checks

- Missing ROMs: runner exit 2; canonical receipt 9c5c74bb1969a22de4c0a05f907bdf8eeefa52a6ad193971e3e6ef74b504cb7a.json; handoff exit 0. P2-47_full and differential gate not_evaluated, multiplicity BLOCKED.
- Historical import: executed using original claims and A75 receipt; generated canonical receipt f2793d270efa9f2cbd484358fe33cf0b8d0fe58510a223b3ced87b197327c88c.json. Handoff accepted it; legacy_byte_subset consistent_conditional, byte_observations unverified, P2-47_full partial_not_established.

## Outstanding and decisions

No authentic ROM 1.32/1.33 bytes were available; no real derivation, no real six-hash comparison, no claim of completed pilot. The six expected hashes agree between the pinned A75 and phase A published observations, and gate logic is tested synthetically. Extended FV support is restricted to the validated 20-byte extension in the leading pad; extension entries and unsupported grammars remain opaque. MARKED_FOR_UPDATE remains blocked; no PI-effective-copy annotation implemented. Uninterpreted live leaves conservatively downgrade coverage (including ordinary RAW leaves); deleted bodies are reported separately. Timestamp exact-offset and semantic conclusions are separate. Resource-limit uncertainty (C7) does not preclude count refutation (C8). Receipt consistency verification is not execution attestation. Real-ROM feasibility and independent adversarial review remain gates before acceptance.
