# Evidence protocol v1 — pilot, 2026-11-27

Scope: Lenovo M75n M33KT32A → M33KT33A. Source snapshot 5cfc7c245066ced5e7854a191fcd1c06d7f41f62. Additive pilot; the existing audit and Sheets remain unchanged. This directory is authoritative only for the pilot contract, not the entire audit.

## Contract
- Artifact: exact size and SHA-256 of original ROM. Names are not identities. Inputs stay local. Missing input or wrong hash = BLOCKED, not PASS or disproof.
- Claim: stable ID, versioned predicate, selector, input IDs, expected typed values, exact historical source. A changed expectation/selector/predicate requires a new ID; preserve old record and link supersession in a later revision. Never edit claims to make a failing run pass. Every migrated claim starts imported_unverified, regardless of historical prose.
- Verifier: read-only, deterministic computation of observable properties. It must not select payloads by expected hashes: selection by exact FFS GUID and section, unique match; hashes checked afterwards. Ambiguous extraction = BLOCKED. No silent parser fallback. The trusted computing base includes extractor, script, Python and interpretation of the selector. Record their versions/hashes. No firmware execution or writes.
- Receipt: separately written JSON. Bind exact registry bytes and verifier bytes by SHA-256, source ROM hashes, extractor binary hash, Python/platform, UTC, observed values, per-check booleans and verdict. PASS means all checks passed for the given scope; FAIL means a valid identified pair contradicted at least one expectation; BLOCKED means missing/mismatched inputs or extraction/selection error. Receipt is not a signed attestation and cannot prove that an untrusted agent actually ran code. Recompute when possible. Do not use an old receipt for changed inputs, registry or code.
- Interpretation: prose only, linked to claim IDs. No promotion to fact by paraphrasing. A successful suffix check says nothing about installed db/PK/KEK, actual firmware policy, runtime behavior, safety of flashing or completeness of analysis. P2-47 also described X509 types/counts; these are NOT checked in this pilot.
- Revision policy: additive changes; retain original evidence. New predicate gets explicit semantics, negative tests and independent review. Later versions may add dependency graph and invalidation, CI and generated Sheets view; none is claimed implemented here.

## Predicate auth_container_pair_v1
Select exactly one leaf Raw section within exactly one FFS file with the given GUID in each freshly extracted A75 tree. Refuse duplicates. Compare full body size and SHA-256; read unsigned little-endian dwLength at offset 16; compute offset 16+dwLength and require 40; SHA-256 of each suffix; explicit byte equality of suffixes; diff offsets must be nonempty and a subset of [0,2,3,4,5,6]. Subset (not exact set) deliberately preserves the narrow reading of "differ only" in P2-47. No parsing of signature list semantics and no claim that EFI_TIME values are valid.
 
## Execute
Python 3.10+ standard library only. Obtain original public ROMs and UEFIExtract NE A75 from owner (see SOURCES.md and METHODOLOGY.md). Check extractor provenance/version yourself; runner records binary hash, not a preapproved hash. Use a dedicated local directory outside public Git; source ROMs are never modified. The script copies them into a fresh temporary directory for extraction.
```sh
python3 verify.py --self-test
python3 verify.py --rom132 /path/to/ImageM33-132.ROM --rom133 /path/to/ImageM33-133.ROM --extractor /path/to/UEFIExtract_A75 --out /path/to/local/receipt.json
```
Exit 0 all PASS, 1 any FAIL (unless BLOCKED), 2 any BLOCKED or invalid invocation. A failure before any claim produces BLOCKED for all claims; inspect receipt and stderr. Output path must not exist. Never publish ROMs, extracted binaries or private dump hashes. Inspect receipts before committing. This pilot only uses vendor ROMs; 1.24 live AFU is out of scope.

See INDEPENDENT_REPRODUCTION.md for a different-agent test. No original firmware was available in the migration session; no actual PASS receipt is supplied.
