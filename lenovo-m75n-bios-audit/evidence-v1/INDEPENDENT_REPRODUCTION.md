# Independent agent task — pilot SB-001..003

Goal: determine whether the historical observations survive an independent machine-readable handoff. Do not read historical prose or claims.json before phase A if a blind test is desired; the owner can supply only this file and input ROMs at first.

Input identities:
- M33KT32A, 16777216 bytes, SHA-256 7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145
- M33KT33A, 16777216 bytes, SHA-256 fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498

Phase A: independently extract the original ROMs with A75 (or a separately documented extractor); find exactly one Raw section leaf under each of these FFS GUIDs in each ROM:
- SB-001: CC0F8A3F-3DEA-4376-9679-5426BA0A907E
- SB-002: 9FE7DE69-0AEA-470A-B50A-139813649189
- SB-003: FBF95065-427F-47B3-8077-D13C60710998
Record extraction version/hash, ROM hashes, exact paths and counts, body sizes/hashes, little-endian u32 at 16, byte offset 16+that u32, SHA-256 and equality of remaining suffixes, full set of differing byte offsets (if sizes differ report explicitly). Save machine-readable JSON and its SHA-256 before reading phase B. Report ambiguity/failure without substituting a different payload. No firmware execution/writes. No raw blobs in Git.

Phase B: obtain claims.json and verify.py from the pinned pilot commit, run self-test and the official verifier on the same input ROMs. Save the separate receipt. Compare independent phase-A observations with receipt observed fields, not prose. Report agreement/disagreement per claim ID and classify input, selection, implementation or original-claim errors. Do not change expectations or verifier to fit the result. A successful official replay is not an independent implementation. If unable to run, report BLOCKED, not agreement.

Deliver the phase-A JSON, hash, command/tool provenance, official receipt and short discrepancies report. Keep all input binaries local. This does not decide whether a BIOS update is safe.
