# Evidence protocol v0.3 — restricted pilot, review draft

## Goal and exit criterion

Prevent accumulation of factual AND semantic errors across independent agents. The smallest successful pilot is: for the two pinned M75n factory ROMs, compute a P2-47 component status from derivation/check receipts, preserve v1 evidence without upgrading its assurance, generate a handoff from computed state, and reproduce the result with independently generated certificates. A conditional or refuted outcome is a valid research outcome; a blocked run is not a completed replay. A fresh independent adversarial review is required before adoption. Do not migrate the inventory until this criterion is met.

v1 and v0.2 remain historical experiments (PR #1 / #2); independent review #3 and commit 935daa0 are not modified. This is a new contract, not an in-place upgrade. Current code is a restricted, executable prototype, not the general platform. It supports only the P2-47 pilot and synthetic fixtures. No real ROM replay yet. No firmware writes or execution.

## Architecture and trust

1. Artifact identity: digest and size of immutable raw bytes. Acquisition metadata (vendor package, URL, package-to-ROM extraction) is separate evidence; pinned digests do not prove vendor authenticity. The pilot uses different pinned ROM digests for roles a/b; no arbitrary aliasing. Private blobs stay local.
2. Derivation: untrusted search proposes a partition of the original image into FV, opaque and erased regions. The checker verifies exact contiguous partition, checks erased bytes, parses supported FV/FFS/section structures, decompresses supported encapsulations itself, computes GUIDs/states/offsets from bytes and derives payloads. No adapter-supplied payload or count is accepted. A certificate cannot claim byte values. This is intentionally narrower than arbitrary certificate trees: root hints only, trusted grammar traversal below. Each derived LZMA stream records parent, source interval, output size and digest. Locators refer to that stream, not host paths. Future typed certificates can add explicit per-node hints if they improve cost or supported formats; do not enlarge the trusted kernel casually.
3. Selection: computed from verified structures. Supported-grammar coverage is not global coverage of all possible encodings. Report opaque areas and unresolved candidates; never infer global absence. Explicitly distinguish a definite structural finding from a candidate found by heuristic scan. The tripwire searches visible streams for valid-looking untracked FV/FFS headers, including in RAW or other leaf bytes. It can refute completeness; cannot prove it. Opaque areas could contain hidden compressed copies. A visible candidate with valid header is blocking, not merely conditional. A plausible invalid candidate is also blocking. Other byte matches are not counted as owners. No runtime dispatch inference.
4. Predicate/claim: typed expectations and observed values over checker-derived bytes. A true byte comparison cannot establish a broader proposition. v0.3 pilot uses a fixed, versioned profile in pilot.py + profile.json, no agent-supplied code or generic expression evaluation. Preserve v0.2's canonical encoding and narrow operation vocabulary conceptually; Python implementation replaces JS. General reusable content-addressed claim and request identities are specified below, not yet implemented as a generic evaluator.
5. Proposition: exact component set, explicit dependencies and non-claims; status computed from required component verdicts AND assurance. Evidence that supplied an expectation is not an independent confirmation of that expectation. Retain both byte-level and structural/semantic claims. C4 and C9 remain OPEN, not PASS based on plausible values. A result is scoped to the original roles and selector policy. No implication about installed variable state, signatures' authenticity or safety of updating.
6. Receipt: canonical JSON, hashes of code/profile, input identities, root certificates, diagnostics, derivation lineage, selected locators, component verdicts and typed observations, assurance and computed summary. Receipts report runs, not attestation; a compromised runtime can fabricate them. Distinguish predicate PASS from accepted proposition status. Separate files per execution with exclusive creation; on write failure emit receipt to stdout and nonzero exit. Preserve failed/blocked attempts. Repository history/review or external append-only storage must enforce retention; local filenames alone cannot. The separate handoff consumer recomputes summary and performs limited structure/identity checks; it is not an independent verifier or acceptance ledger. Real replay still required. Do not promote old receipts by relabeling.
7. Handoff: generated from summary and component receipts, never an unqualified PASS. In future DAG, references are content digests; only explicit reviewed implications can derive propositions. Supports/contradicts/assumes/prerequisite edges do not imply logical equivalence. Invalidation marks downstream needs-review, not negation. Review policies versioned. No auto-generated global risk score.

## Wire identity (target generic architecture)

Canonical restricted JSON: ASCII printable nonempty strings, nonnegative safe integers, booleans, null, arrays, sorted-key objects, compact encoding plus LF. Reject noncanonical bytes including duplicates, exponent/decimal forms, whitespace, negative zero. Maximum document 8 MiB, depth 32. Hash exact canonical bytes. No paths from certificates. Source references repository-relative commit/path/anchor, not identity of executing revision. Separate request digest H(canonical({artifact:{sha256,size},selector,grammar_version})), claim-core digest H(canonical({kind,request_digests,predicate,expected,scope})), provenance/annotations digest and pack manifest. The same request can be reused across packs; cannot change request semantics by relabeling. Snapshot checks (pinned hash) and relation checks (properties of a specified pair) are distinct. Pilot binds fixed profile by hash; generic request store, independent receipt ledger, graph and policy engine are future work. Never infer a broader claim from source anchor alone.

## Duplicate and state policy

State is derived after accounting for FV erase polarity. PI defines state bits and integrity checks; this implementation uses a conservative supported subset. Highest set state bit = DATA_VALID / MARKED_FOR_UPDATE / DELETED with required lower bits and header checksum; DATA_VALID and MARKED_FOR_UPDATE also require body checksum or fixed checksum per attributes. A deleted file is counted separately; its body not interpreted as a live file. A physically present file need not execute. We deliberately do not emulate PI recovery precedence across marked and valid copies yet. Until reviewed, any marked target blocks selection. Do not assume firmware-specific priority from PI alone. Invalid parsed candidate or unsupported region is not silently skipped.

| Situation | Selection and acceptance |
|---|---|
| One structurally valid DATA_VALID owner, one RAW section | unique within supported grammar; opaque limitations explicit |
| Multiple valid owners with different payloads | BLOCKED unless a future explicit path or all-copies query is used |
| Multiple valid owners, each one byte-identical RAW payload | content equivalence class; uniqueness proposition FAIL, not interchangeable structural copies |
| Valid + verified deleted | select valid, report deleted separately |
| Valid + MARKED_FOR_UPDATE | BLOCKED pending reviewed PI/recovery policy |
| Invalid header/state/checksum/bounds in searched structure | BLOCKED; typed diagnostic and opaque tail if appropriate |
| GUID in ordinary data, no plausible header | not an owner; scan heuristic is not proof of absence |
| Valid-looking header outside checked tree | BLOCKED, including visible candidate in opaque region |
| Unreadable/unsupported region without visible blocking candidate | conditional coverage; cannot promote to global completeness |
| Different multiplicity | report independently of content comparison; observed counts conditional if coverage incomplete |

Future exact path selector must include GUID container chain, local coordinate and disambiguating evidence (e.g. neighboring identity); ordinal alone is not cross-version identity. If two indistinguishable structural copies remain, require explicit quantifier/all-copies or report ambiguity. Separate inventory of deleted/invalid/recovery copies; no collapsing them to live copy count. Separate evidence needed to resolve invalid candidate; never remove diagnostic in prose. This pilot has no arbitrary path selector and no claim about executing copy.

## Supported grammar and limits

Root partition uses contiguous `{offset,size,kind}` records. `kind` = fv / erased / opaque. Verified FV header checksum, length and block map, FFS2 with standard 24-byte file headers, both erase polarities, state/header/data checksum rules, file alignment, common section lengths, nearest FFS owner, RAW body, FV image, uncompressed compression wrapper and LZMA GUID-defined section. No FFS3, extended FV/file/section headers, Tiano, AMD directories, vendor-specific container grammar, NVAR or PE internal layout. Unsupported opaque areas reported, malformed supported structures reject or block. RAW is a leaf in the PI grammar (not defined by extractor UI tree). No global uniqueness: opaque bytes can encode arbitrary unsupported structures, including inside ordinary PI leaf payloads. Bounds, depth (16), total original+expanded bytes (64 MiB), node and diagnostic cap (100000); not hardened for malicious images or denial of service. Unsupported regions may prevent progress on real ROM; resolve by reviewed format-specific additions, not by suppressing diagnostics. Reference spec sources: PI 1.8 Volume 3 code definitions and storage design discussion; UEFI 2.10 runtime services (authenticated variables) and Secure Boot and Driver Signing (signature list layouts). URLs in SOURCES.md.

## P2-47 proposition components

For each of three target GUIDs across a=1.32 and b=1.33:

| Component | Exact scope | Expected origin |
|---|---|---|
| C1 | exactly one DATA_VALID structural owner and exactly one RAW in each; marked/invalid/unknown not silently ignored | authored policy, historical v1 selection is weaker |
| C2 | sizes 842/3908/9485 per GUID | P2-47 + inventory |
| C3 | exact difference set [0,2,3,4,5,6], equal lengths | P2-47 + phase A observation, not independently confirmed by that observation |
| C4_plausibility | valid calendar/time-field ranges and layout | UEFI EFI_TIME, author hypothesis |
| C4 | actual semantics of first 16 bytes as timestamp | OPEN, requires format/consumer evidence |
| C5 | 24-byte WIN_CERTIFICATE_UEFI_GUID-like header at 16; revision 0x0200, type 0x0EF1, PKCS7 GUID | UEFI format hypothesis; actual vendor bytes not yet checked |
| C6 | equal bytes after offset 40 | P2-47 |
| C7 | tail consumed exactly as nonempty EFI_SIGNATURE_LIST layout with bounded sizes and entries | P2-47 + UEFI structural layout |
| C8 | all lists X509 type GUID, zero signature header size, aggregate counts 1/3/7 | P2-47 + UEFI signature list definition |
| C9 | identify variable role PK/KEK/db | OPEN, not asserted in P2-47 |
| multiplicity | same observed state/RAW counts across versions | authored comparison; not claim of same runtime role |

C5 records observed header fields, not just a boolean. C5 is a structural test, not signature verification: dwLength=24 means no certificate data in this header, so do NOT interpret as a valid authenticated update. C7/C8 do not parse DER certificate bodies or validate trust. C4 plausibility cannot prove intended interpretation. A different real value is a finding, not cause to rewrite expected values. Equal structural lists in this pilot = C1 AND C5 AND C6 AND C7 across all GUIDs; this intentionally stronger scoped proposition includes unique selection. A failed uniqueness component refutes that scoped conjunction, not equality of the selected suffixes. The X509 count statement requires C1/C7/C8. C3 exact set and C6 are separate byte observations. P2-47 full semantic result remains not established until C4 supported by evidence; C9 outside the historical statement. No fraction/majority vote. Non-claims recorded in profile/summary.

Verdict per component PASS/FAIL/BLOCKED/OPEN. A concrete measured mismatch is FAIL (including length mismatch, diff count exceeds limit, malformed signature list); missing or unverified inputs/selection are BLOCKED. Pair result may be conditional if coverage has opaque regions. `derived_in_supported_grammar` is scope-limited, never global. `consistent_conditional` means equality holds on checker-derived selected payloads under stated coverage, not proven all-copy equality. `refuted_within_supported_grammar` for failed scoped conjunct; conditional refutation when coverage incomplete. No independently-derived status yet: requires separate reviewed implementations/modes of failure and frozen results, not merely two agents calling same checker. Commit/reveal: expectation digest with salt before phase A; agent receives only input/card, no previous reports; server-timestamped commitment to phase A before reveal. Historical phase A was not externally frozen and had parser limitations; valuable byte agreement, not independent uniqueness proof.

## v1 evidence

Pinned importer reads exact v1 claims and real-ROM A75 receipt from commit 935daa0. Checks identity (SHA-256 registry, SHA-256 and Git blob identity receipt, exact claim keys, verifier hash, observations, ROM hashes); preserves v1 scope and original receipt. Records C2, C6, `legacy_diff_subset` and `legacy_dwLength` as adapter-asserted conditional evidence. C1, exact C3, C5, C7, C8 and semantic components stay OPEN in legacy import. No conversion of subset into equality or uniqueness. The phase A published observations are referenced as supporting historical byte agreement, not accepted as an independent derivation under v0.3. Original v1 receipt remains separate; no new execution implied by import.

## Run

Python 3.10+ stdlib. `python3 -m unittest -v test_pilot` from this directory. Use original pinned ROMs and local receipt directory. Optional root certificates are canonical JSON `{artifact_sha256,regions}`. If omitted, untrusted root scanner proposes a partition. Checker derives data independently; a scanner miss produces opaque/issue, not unconditional PASS.

```
python3 pilot.py --rom-a /local/132.rom --rom-b /local/133.rom --receipts /local/receipts
python3 legacy_import.py /local/v1/claims.json /local/official_receipt_A75.json /local/receipts
python3 handoff.py /local/receipts/RECEIPT_SHA.json
```

Exit 0 = completed determinate component evaluation with no FAIL/BLOCKED, not adoption or proof of complete P2-47; 1 measured FAIL, 2 blocked/error, 3 persistence failure (receipt fallback stdout). Invalid invocation may not write receipt; wrapper needed for external attempts. OPEN semantic components deliberately retained. See REVIEW.md for blockers. Do not commit firmware images or private diagnostics. Public ROM receipts may still contain proprietary metadata; review publication.
