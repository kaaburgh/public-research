# Independent reproduction: pilot SB-001..003 (Lenovo M75n BIOS)

Protocol: `evidence-v1/INDEPENDENT_REPRODUCTION.md` (commit `4095d9cf…`). See `PROVENANCE.md` for hashes.

## Result

| Step | Outcome |
|---|---|
| Phase A (own stdlib extractor, frozen before claims/verifier were read) | Done. `phaseA/phaseA_observations.json` |
| Verifier self-test | PASS (synthetic only, as the verifier states). `phaseB/selftest_output.txt` |
| Official verifier with UEFIExtract NE alpha 75 | **SB-001 PASS, SB-002 PASS, SB-003 PASS.** Receipt: `phaseB/official_receipt_A75.json` |
| Receipt observed fields vs phase-A observations | All match for all three claims (sizes, body SHA-256, `u32` at offset 16, suffix SHA-256, differing offsets). `phaseB/compare_receipt_vs_phaseA.py` prints ALL_MATCH |
| Expectations / verifier edited? | No |

A first official attempt, before A75 was available, was BLOCKED. It is superseded by the run above.

Phase A was run before `claims.json` and `verify.py` were opened. A75 was obtained only after phase A output was frozen, so phase A was not informed by A75 output.

## Phase A notes

- Target GUIDs each occur as one type-0x02 FFS file. The file is nested inside an LZMA section of the top-level volume. Its body is again an LZMA section wrapping one RAW section. Structural walk found exactly one match per GUID per ROM.
- No Tiano (type 1) compression was encountered. Section parse errors: 0 after fixing 4-byte section alignment. Two bugs in my first walker were fixed by inspecting structure, not expected values.
- The byte-level cross-check finds the 16-byte GUID 4–5 times across the ROM and decompressed streams. Only one occurrence is an FFS header. I did not verify the others (presumably dependency expressions). This does not affect the structural count, which the official locator also reports as 1.
- The two differing payloads differ at offsets 0, 2, 3, 4, 5 and 6 only, identically for all three claims. The bytes look like a date/time field. This is an observation, not an interpretation.

## Assessment against the five questions

**1. Formal spec sufficiency: insufficient for independent reproduction.**
- The spec names the extractor but not its dump layout. `verify.py` depends on `info.txt` containing `File GUID:` and on `<n> <section>/body.bin` directories. Without A75 an implementer must reverse-engineer this layout.
- "Raw section leaf under the FFS GUID" hides two LZMA encapsulation layers. The official receipt shows the selected leaf path as `… Volume image section / <FFS> / LZMA / Raw section`. The spec does not mention this.
- The meaning of the 16-byte prefix and of `dwLength` is not stated.
- The predicate name `auth_container_pair_v1` suggests an authentication property. The verifier checks only bytes and hashes.
- The `sources` anchors (`RELEASE_132_133.md` P2-47, `data/inventory.tsv`) are checked only as non-empty strings. They are not resolved.
- `claims.json` records `source_commit` `5cfc7c24…`, which differs from the protocol's pinned commit `4095d9cf…`. I did not resolve which commit the claims were written against.

**2. Ambiguities and hidden assumptions.**
- `expected_occurrences: 1` counts RAW leaves under the FFS owner. Byte-level GUID occurrences are 4–5. The spec does not define "occurrence".
- `validate()` hard-codes `dwLength == 24`, `suffix_offset == 40` and `allowed_diff_offsets == [0,2,3,4,5,6]`.
- `allowed_diff_offsets` is checked as a subset, not an exact set. Exact equality holds here, but body hashes pin the content anyway.
- `locate()` silently skips a RAW section that has subdirectories instead of counting it or failing.

**3. Risk of a false PASS.**
- PASS means these specific bytes match these pinned hashes. It does not establish the semantic claim named by the predicate. Any summary that says PASS confirms the claim overstates it.
- PASS also depends on the extractor producing the directory layout `locate()` expects. A different extractor that drops or merges nested directories could change the count without an error, especially via the silent-skip path above.
- The claims were not edited to fit observations.

**4. Reproducibility without previous chats.** Phase A is reproducible from the protocol and `phaseA/tool/`. The official step is reproducible from the pinned verifier, the A75 asset (SHA-256 checked above), and the input ROM hashes. Both need the input images, which the owner supplies.

**5. Scalability to other results.** Each new claim needs a hand-written contract in `claims.json` and, for different header layouts, code changes in `verify.py`. The hard-coded constants in `validate()` block this. Images using Tiano compression need a decompressor that my phase-A walker lacks. A scalable protocol would need a documented extractor dump format, a general predicate definition, and extractor test vectors independent of the verifier.

## Open items

- Resolve the `source_commit` mismatch (`5cfc7c24…` in claims vs `4095d9cf…` fetched).
- Decide whether the `auth_container_pair_v1` predicate should claim more than byte identity.
- `bios_afu.bin.bak2` (1.24) was not part of this protocol and was not processed.
