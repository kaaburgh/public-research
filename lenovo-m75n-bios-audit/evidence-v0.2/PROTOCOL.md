# Evidence protocol v0.2 — review draft

Status: proposal with executable reference core. Not adopted; does not replace v1 or the audit ledger. Scope of this release: deterministic byte-level claims, conditional extraction observations, append-only execution receipts. Firmware-specific semantic interpretation, production adapters and CI are follow-up work.

## 1. Goals and threat model

Prevent meaning drift across agent handoffs. A claim is a typed, immutable proposition, not a prose summary or a status field. A claim can be checked using a small allowlisted evaluator, rather than executing arbitrary agent-supplied code. Keep distinctions between (1) bytes identified by hash, (2) structural extraction/selection, (3) deterministic predicate result, (4) semantic interpretation/risk. A hash is content identity, not evidence that a tool ran or selected the right object. A receipt is reproducible evidence of reported execution, not an authenticated attestation.

Threats: mistaken scope, wrong ROM, incomplete/ambiguous selection, parser defects, stale evidence, mismatched versions, false or fabricated receipts, lost negative results, silent schema changes, incomplete comparisons, semantic overclaiming. Trust includes input acquisition, extractor/adapter, evaluator, runtime and repository governance. No claim of protection from an intentionally malicious agent controlling all of these. No firmware execution or writes. Treat arbitrary extraction code/binaries as untrusted; isolate execution outside this evaluator.

## 2. Identities and storage

- Artifact identity = SHA-256 of raw bytes and byte count. A local object store uses filenames exactly equal to lowercase 64-digit SHA-256; never follow input-specified paths. Verify each loaded object's digest and size, including original ROM. Large or private bytes stay out of public Git; the store is supplied locally. This pilot is limited to 64 MiB per object.
- Claim identity = (exact claim pack SHA-256, claim ID). IDs are unique in a pack, never silently reused with changed meaning. A replacement references its predecessor's exact commit/path/id; the old pack stays addressable. A source reference points to a historical commit/path/anchor, not the commit where the claim was authored. A protocol revision is independently pinned by Git commit and exact engine/runner hashes. No self-referential commit field is needed.
- Canonical wire encoding (not RFC 8785): ASCII printable nonempty strings, nonnegative safe integers (<= 2^53-1), booleans, null, arrays, objects; keys sorted lexicographically by ASCII code, compact JSON using JSON.stringify string escaping, one trailing LF. No other whitespace, duplicate keys, negative zero, decimals, or exponents. Validate exact round trip; hash original bytes. Pretty examples are explanatory, not wire format. This restricted profile is deliberately reviewable; expansion needs a version change. Inputs <=8 MiB. The reference JS validator is normative for this draft; schema and implementation must be reconciled before adoption.
- No writes to historical files. Each execution appends a distinct receipt named SHA256(canonical bytes). The runner uses exclusive creation and random run ID; failed/blocked attempts retained. Git history/branch protection and review must enforce non-deletion and non-rewrite; filename alone cannot enforce this. Never replace BLOCKED with PASS. Store original and sanitized receipts separately if needed, with lineage; avoid local paths in canonical data.

## 3. Claim pack (wire fields; see pilot.claims.json)

Top-level version, artifacts[], selectors[], claims[]. Artifact: id, sha256, size. Selector: id, kind, guid, section_type. Claim: id, selector, inputs {a,b} (ordered artifact IDs), sources[] {commit,path,anchor}, predecessor (null or {commit,path,id}), checks[] {id,op,args,expected}. No free-form executable expressions, implied defaults, mutable verdicts or confidence fields. All checks are conjunctive. IDs and references must resolve uniquely. Historical source anchors are provenance declarations; the evaluator does not fetch or verify anchors. Review them separately.

## 4. Canonical extraction observation (one adapter invocation per manifest)

Top-level version, pack_sha256 (digest of the exact canonical pack bytes), adapter {id,sha256,toolchain}, entries[]. Adapter hash identifies executable or adapter bundle manifest (review must define the latter precisely); toolchain identifies its version/configuration. Each entry: artifact (pack ID), selector (pack ID), coverage (complete/incomplete/unknown), owner_count, raw_node_count, leaf_count (integer or null when unknown), issues[] (unique machine-readable codes), payload (null or {sha256,size}), locator (null or printable trace). Exactly one entry per requested (artifact,selector); no duplicates, missing, or extras. The adapter MUST bind the exact pack digest at execution; mismatched pack_sha256 rejects the run. Counts must be consistent (leaf_count cannot exceed raw_node_count when both are known). Source and predecessor paths are repository-relative. The digest binding prevents accidental reuse of observations under changed selector definitions, but cannot prevent an untrusted producer from relabeling observations.

### unique_ffs_leaf_v1

Count structurally parsed FFS FILE headers with the GUID in all firmware volumes reachable in the input through supported encapsulations. Do not count byte-pattern GUID occurrences. A section belongs to its nearest enclosing FFS owner; do not traverse a nested FFS file's descendants as if they belonged to the outer owner. For the matched owner count every structurally recognized section of type 0x19 (RAW), including malformed/unexpected non-leaves; count valid leaf payloads separately. Expected unique selection: owner_count=1, raw_node_count=1, leaf_count=1, zero issues, complete coverage. The payload is the exact section body excluding common section header, after decompression/encapsulation processing, without padding trimming or normalization. A RAW node with children, missing body, unsupported compression, unparsed relevant volume, uncertain owner, malformed bounds or ambiguous lineage MUST report an issue and incomplete/unknown coverage; never silently skip. Complete means adapter asserts exhaustive traversal for THIS selector, not coverage of every ROM byte. No match or multiple matches is BLOCKED in this protocol (not proof of absence). Define a separate negative-existence predicate with a stronger coverage contract before asserting absence.

Adapter conformance requirement: document parser and versions, search domain and exclusions, validate bounds and report unresolved nodes; use adversarial test vectors (missing body, duplicate GUID, second malformed RAW, nested owner, unsupported compression, truncation, misalignment). Do not label a simple dump-directory scan as independently verified completeness; UEFIExtract A75 layout assumptions and extraction diagnostics must be explicit in a production adapter. Independent extractor must implement the same selection contract or report BLOCKED. No production adapter is implemented in v0.2. The core accepts externally supplied observation manifests and verifies their referenced bytes, not the truth of the structural assertion. A PASS must be described as conditional on adapter coverage/selection, even if an original ROM object with the correct hash was supplied.

## 5. Predicate kernel

| op | args | observed type / meaning |
|---|---|---|
| size_v1 | {input} | byte length |
| sha256_v1 | {input} | SHA-256 of full payload |
| read_u32_le_v1 | {input,offset} | four-byte unsigned little-endian integer |
| range_sha256_v1 | {input,offset,length} | SHA-256 of selected range |
| range_equal_v1 | {left,right} | byte equality of two ranges, left=a right=b |
| diff_offsets_v1 | {left:"a",right:"b"} | exact ascending list of differing zero-based offsets; equal-length payloads required |

input is a or b. Range length is an integer or "rest". Half-open [offset,offset+length); rest ends at payload length. Zero-length ranges allowed, out-of-bounds forbidden. diff_offsets limit 4096; above limit BLOCKED, no truncation. No implicit conversions or normalization. Check passes only if observed value is exactly equal to typed expected value. No higher-order expressions, unknown operations rejected. For unequal-length diff use a size comparison first and a separate future predicate if required. Bounds failures and undefined operations are BLOCKED rather than false. Predicate version identifies exact semantics. Extend only by explicit spec and tests; do not let claims define operations.

## 6. Evaluation and verdicts

Validate both canonical documents; malformed/missing/extra fields, unknown versions or ops, duplicate IDs or missing observation entries reject the run. Verify original ROM objects and selected payload objects in the local store. Reject incomplete/ambiguous selections before evaluating operations. Every expected check gets PASS, FAIL, or BLOCKED; valid measured mismatches are FAIL. Claim aggregate: any FAIL -> FAIL, else any BLOCKED -> BLOCKED, else PASS. Mixed FAIL/BLOCKED retains all individual outcomes. Run exit 1 if any FAIL, 2 otherwise if any BLOCKED or run invalid or receipt write failed, 0 only if all PASS. Invalid inputs produce a run-level error, not a claim PASS. Resource limits are conservative pilot limits; memory cache and runtime are not hardened against hostile large bundles.

Receipt fields: version, run_id, utc, runtime, platform, pack_sha256, observations_sha256, engine_sha256, runner_sha256, results[] (id,verdict,checks[]), run_error. Each check includes observed or reason. The observation digest binds pack identity, adapter identity, selector counts and payload references; pack digest binds exact input identities, predicates and expected values. Retain both referenced manifests beside receipts. A receipt consumer MUST validate exact claim/check coverage (including duplicates), recompute aggregation and verify manifest/tool hashes; do not trust a printed ALL_MATCH or a producer's exit code alone. A receipt validator/acceptance ledger is specified as follow-up, not implemented by the runner.

## 7. Acceptance, independence and knowledge graph

An imported claim is a proposition, not a fact. Evidence status is derived outside the claim from validated receipts: unverified, reproduced (same implementation), independently reproduced (distinct extraction implementations plus matching typed values), contested (valid conflicting evidence), or stale (changed dependency/tool contract; never delete history). These labels are review decisions, not generated by the byte kernel. A blind run must publish/freeze phase-A observations in an immutable externally timestamped commit before reading expectations; preserve pre-sanitization hash and explicit transformations. Both passes must compare exact claim/check/observation sets, not only common rows; disagreement and incomplete coverage are retained. Same extractor with a different model is not independent extraction. A malicious or inaccurate extractor can still fabricate evidence; independent implementations and review reduce, not eliminate, this risk.

For later semantic claims, keep a typed DAG distinct from the byte kernel: fact references include pack digest + claim ID + receipt digest; relations must distinguish logical implication, supports, contradicts and prerequisite. A hypothesis remains a hypothesis even if supporting observations are PASS; evidence invalidation propagates "needs review", never proves negation. Store counterevidence and assumptions. No automatic inference of risk level from binary equality. No graph execution in this release.

## 8. Pilot, test and rollout

Three existing SB claims migrated to new IDs; exact difference set strengthened using independent phase-A observations. The old predicate and receipts are immutable history. The new claims concern byte lengths, hashes, header u32, fixed suffix and exact offsets only; do not imply Secure Boot semantics, valid certificates or risk-free update. v0.2 has not been replayed on real ROM. No changes to main audit, Sheets, or v1.

Run `node selftest.mjs` for synthetic core tests (test digest deliberately noncryptographic; real runner uses Node crypto). Then, after a reviewed adapter produces a canonical manifest and local hash-named objects:
```sh
node verify.mjs pilot.claims.json observations.json /local/objects /local/receipts
```
Node.js 20+ standard modules; no external dependencies. The CLI is reference code, not production. Preserve all attempts, inspect before publication. Do not commit objects. See REVIEW.md before extending. Priority after review: adapter conformance, strict independent receipt consumer, bulk inventory (2256 keys), PE/TE normalization; only then semantic graph and generated Sheets view.
