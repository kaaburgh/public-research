# 1.32 → 1.33 independent audit

2026-11-26. Factory source ROMs verified against SOURCES.md. 44 changed sections, 7 relocation-only, 37 independently reviewed here. 26 more attributed; 11 partial. Pair-specific records in data/s33-attribution.tsv. No physical tests. Attribution means explaining changed binary content, not proving absence of runtime regression.

## P2-45 / 1.32→1.33: малые PE/TE (13 секций)

**Finding:** Все изменения атрибутированы: идентификатор CBS, версии и даты; Ofbd меняет порог версии

**Evidence:** CbsBasePeiRV 4 bytes file0xF08–F0B, CbsBaseDxeRV 0x122B–122E, CbsSetupDxeRV 0x3770–3773: EF162DFE→BA27F8CE. CrbPei normalized only byte file0x2B5 (RVA0x434), CrbDxe only byte0x8D5 version return 32→33. CopyRight 0x137E ASCII version. SmbiosType0 6 bytes (minor release 0x491, version 0x74E, date 0x758/59/5C/61). CsmDxe 8 bytes ASCII build date/time, .text exact. CryptoPPI 6 bytes EFI_TIME in .data file0xB320,322–326. AmiDeviceGuardApi 6 timestamp bytes file0xC56,C58,C59,C61–63; AmiRedFishApi same at RVA0x91F/929; HardwareSignatureEntry 6 bytes 0xAE4/AE6/AE7/B0A/B0B/B19 update global timestamp. Ofbd only 0x1F67 threshold 3332→3333, compare unchanged. Date/time 2025-11-11 16:49:50→2026-05-15 15:31:59.

**Limits:** Static attribution closes these rows, not hardware testing. Timestamp can feed hardware signature and authorization freshness; version gate may change selected path. No new CPU or power algorithm in these diffs.

## P2-46 / 1.32→1.33: raw metadata / free space

**Finding:** Девять секций идентифицированы, один 4096-byte блок остаётся

**Evidence:** 147923CE… nested raw 72BCFBE0 and direct raw file both 164B only offset4 M3332A→M3333A. FID 3FD1D3A2… 120B 7 bytes build/date at 0x2B/2C/2E–32; FIDT 709E6472…156B 7 bytes at0x4E/50/52–56. 86E3F707… 15B text version at6/B. A59A0056…118B date 4 at57/58/5B/60. DAF4BF89…5247B 5 bytes date+M3332A→M3333A. Free space 9E21…88→3304 B and C049…3096→2744 B all FF. 414D94AD…/5A88641B…4096 B header 4A3CA68B-7723-48FB-803D-578CC1FEC44D, 511 diff bytes in 0x148..247 / 0x358..457; likely signature-related but format not proven.

**Limits:** Version and layout only for 9 attributed rows. 4096-byte container unresolved; no assertion of signing scheme or verification policy.

## P2-47 / Заводские Secure Boot сертификаты 1.32→1.33

**Finding:** Списки сертификатов побайтно идентичны

**Evidence:** Raw sections CC0F8A3F…842B, 9FE7DE69…3908B, FBF95065…9485B differ only EFI_TIME bytes 0,2–6. WIN_CERTIFICATE_UEFI_GUID dwLength=24 at16, signature list bytes start40; exact equality of entire suffix. SHA256 suffixes 79ff44aecb43cf487a74a7834454fe33b964cb8d67dc13caaf28930aa067a26a / 791aa21abcd4632136d6fb6330063af2e0d2d14b24aff96301567c1a82501221 / f0fb458845c395520bca386e03fe377f04cc09492276c1019e34d126683008ed. Lists X509 signature type; 1/3/7 entries. Timestamp only changes.

**Limits:** No certificate/owner/list data changes in these three sections. Authenticated-update timestamps and actual installed databases may differ. Does not reverse 1.24→1.32 certificate/DBX changes.

## P2-48 / AMITSE/EsaFull/Setup — HII + ACPI

**Finding:** AMITSE code change is OEMRevision; resources mostly strings; Setup adds internal identifier

**Evidence:** AMITSE .text 488288 raw bytes, sole diff file0x455F0. RVA0x455EF mov eax,0x1200→0x1210, compares/stores ACPI header+0x18 OEMRevision, excludes WPBT, recomputes checksum; existing traversal of RSDT/XSDT/FACP. .data two bytes year/version; xdata, unnamed, reloc exact. HII list at .rsrc+0x60, 5 string packages+END: en-US 2 changed string IDs (55,450), fr-FR 3 (55,450,451), ru-RU 1 (450), zh-cht 2 (55,450), x-UEFI-AMI unchanged. 450 support phone→URL, other translation/OK text. EsaFull same resources and OEMRevision constant, large code layout residual. Setup .rsrc 7 packages: forms type2 and four normal-language packages exact; x-UEFI-AMI +30 bytes adds ID2057 LemPower000L; no other decoded string change. All packages lengths validated.

**Limits:** Runtime ACPI headers/checksums can differ despite static AML equality; no change in AML discovered. Absolute notice wording update does not prove feature activation. AMITSE static attributed; EsaFull/Setup remain partial; internal identifier use unknown.

## P2-49 / SwSmi534D0040 / Secure Boot mailbox

**Finding:** 1.33 добавляет producer запроса, дополняющий ранее обнаруженный consumer

**Evidence:** PE 32256→33088 B, .text 25824→26432. Normalized instruction sequence 6523→6676; dispatch table length grows by one, one inserted handler RVA0x25F4–0x2844, other changes mostly address relocation. Reads standard Secure Boot state variables, forms LenovoMailBoxSecureBootModeVar (same name/GUID/signature as P1-18), saves via SetVariable; consumer SecureBootDXE handles later. Existing authorization path used conditionally; full authorization/caller context unresolved. No direct PK/KEK/db/dbx writes in producer.

**Limits:** Request-triggered not periodic. No evidence of auto activation or security bypass solely from producer. Do not test raw SMI. NvramDxe/NvramSmm/SecureBootDXE exact changes still partial.

## P2-50 / 1.32→1.33: большие PE/crypto/BDS

**Finding:** Сильные признаки изменений layout/build paths, но полное равенство не доказано

**Evidence:** AbtCryptoDriver, TlsDxe, CryptRuntimeDxe, Bds, Setup: same .text raw sizes and decoded instruction addresses. Changed disassembly rows respectively 1216/2802/1274/2623/2625; after masking RIP and direct branch targets 9/9/6/10/26 remain. .data raw growth 256/352/0/224/224 B (CryptRuntime virtual +288); unchanged .xdata/unnamed section bytes. ASCII strings>=12 changed build path prefixes e:\nanoamd\31a\nanoamd\…→d:\builds\sourcecode\nanoamd\m33kt33a_s_260515\…; OpenSSL and StdLib path suffixes same. Setup version/timestamp immediate changes and HII in P2-48. EsaFull larger code relocation/reordering residual.

**Limits:** Heuristic not proof: must map every changed reference and changed data before closure. No identified new crypto algorithm or measured regression; no CVE attribution. Runtime UEFI TLS independent of Linux network stack.


## Reproduction

Extract exact FFS sections by GUID, instance and section key in inventory.tsv; check lengths and SHA256. Compare full bodies, normalize TE HIGHLOW relocation/ImageBase before comparing. Map PE sections using VirtualAddress and PointerToRawData. For HII .rsrc in AMITSE/EsaFull/Setup, package list starts at offset 0x60, header GUID+length 20 bytes, each package uses a 24-bit length and 8-bit type. Type 4 string package StringInfoOffset at +8, language name at +46. Decode UCS2 block 0x14, duplicate 0x20, SKIP2 0x21, SKIP1 0x22, END 0; compare string IDs, not shifted raw bytes. Type 2 forms compared byte-for-byte. For certificate containers compare authenticated-variable header EFI_TIME (16 bytes), WIN_CERTIFICATE_UEFI_GUID length at +16, then exact list payload at +40. Preserve all data locally. For large PE, compare disassembly and mask branch/RIP operands only for triage; prove resolved targets and data equivalence before closing. No raw firmware, SMI invocation, variable writes, or personal NVRAM exported.

## Follow-up (supersedes provisional P2-50)

### P2-51 / 1.32→1.33: exact PE layout/reference audit

**Finding:** AbtCryptoDriver, TlsDxe, CryptRuntimeDxe, Bds closed for binary attribution; Setup code/layout explained; one HII ID unresolved

**Evidence:** GNU objdump same instruction addresses incl padding: Abt 179160 rows/1216 changes (1207 RIP+9 index); TLS 262435/2802 (2793+9); CryptRuntime 177808/1274 (1268+6); Bds 200677/2623 (2613+10); Setup 205387/2625 (2599+23+3 version/time). Monotonic .data anchors 845/1140/843/1280/1583, zero conflicts. Compare anchor intervals after masking relocation slots, canonicalizing only exact old/new source-path prefixes and Setup UTF16 date/time literals; zero-only edits 11/18/10/10/10, no other edits. Then validate every relocation slot width and bijective actual pointer mapping: 5219/6052/5168/5366/5448 =27253, no missing/unknown/mismatched targets. .xdata and unnamed sections identical; section tail padding all zero. Bds resource only DataRVA at .rsrc+0x48 relocated by 0xE0. Setup code residual 0x79F version, 0x16C54/5E build date/time; HII internal ID LemPower000L remains. Test script pe_layout_audit.py.

**Limits:** Static layout attribution, not semantic proof of arbitrary padding or runtime. Debug directory and build paths change; no new decoded instructions except Setup version/time. No crypto policy change identified. Setup kept partial for identifier meaning/native route.

### P2-52 / SecureBootDXE/NvramDxe/NvramSmm — mailbox consumer and policy

**Finding:** Новая логика срабатывает при наличии запроса; обычный путь сохранён

**Evidence:** SecureBootDXE existing init relocated 0x328→0x5AC, same factory state processing plus protocol-notify registration 0x71E..75F, GUID 3aa83745-9454-4f7a-a7c0-90dbd02fab8e installed by Bds routine 0x1B2C→0x1A24; callback 0x43C checks boot mode HOB and mailbox read/signature, exits on failure/absence, performs requested state/restore actions, clears mailbox and conditionally resets. NvramDxe/Smm normalized rows 12255→12272 and 12103→12120, six diff groups each: three indexed .data offsets, two build-time immediate changes, added 17-instruction mailbox-presence predicate (DXE RVA0xC3D0, SMM0xB2C8) inserted into existing function-pointer policy list after SecureBootSetup string (DXE raw0xD490/SMM0xCFB0). Existing policy wrapper iterates list and uses SecureBootSetup byte1 condition; DXE caller around 0xAF1C in authenticated-variable handling. Without mailbox, extra predicate returns false and existing predicates run.

**Limits:** No evidence of extra periodic SMI or autonomous reset from new callback without mailbox. Auth policy and request caller authorization need full static mapping; runtime ordering/failure cases not tested. Earlier migration reset P2-16–18 remains independent.

Reproduce: `python3 tools/pe_layout_audit.py old.efi new.efi` (add `--setup` for native Setup). Tested against the five matching 1.32/1.33 payloads with GNU objdump. The program reports residual code and data edits, and validates pointer slots and targets, not arbitrary semantic equivalence. Four further sections attributed, so 37/44 total, seven partial.

## Final B10 follow-up

### P2-53 / 4096-byte signed metadata

**Finding:** Changes fully confined to RSA signature fields

**Evidence:** 414D94AD-998D-47D2-BFCD-4E882241DE32 / 5A88641B-BBB9-4AA6-80F7-498AE407C31F. 4096 bytes. All 511 differences within RSA-2048 signature fields [0x148,0x248),[0x358,0x458). Moduli [0x48,0x148),[0x258,0x358) identical in both bodies, SHA256 8b1fc6ec6379d824de3c85d8c28b619b8531b573704a0fbe9a4065f0ba0450d7. pow(s,65537,n) gives strict PKCS#1 v1.5 SHA-256 DigestInfo in all four cases. Digests 132: 71aef374d15d844b66cc5109fb9096384db834a009ddad6b4f2d196164f48bdc / adb8cc92776e881ca22f0e29df61a9b50b28a4111f07c5551479c79a7229c398; 133: 70c1e88165f23fbc4c6c91f10acbdcf431042e3c466496c0c91d19e9017984f8 / a518d9bea1120007d16b2074b512330ca4fd3ed6b2315ed97f5a70cfd2fd7754. Zero signature fields: identical body SHA256 6f2912c7ff84b3cc0416f03d770e4ad8a19a66458ff84dbcd123617912ab1497.

**Limits:** Signature field attribution only. Signed source ranges and trust chain not recovered or verified; no claim of complete authentication.

### P2-54 / EsaFull UI engine

**Finding:** Layout dominates; real expanded GUI code remains

**Evidence:** EsaFull 2101824→2104512 B; .text raw length 1334016 unchanged, 663171 bytes differ. 3481 int3 chunks each; 347522→347527 nonpadding decoded rows. Candidate normalization masks RIP/direct branch targets and indexed .data addresses (132 0x145e00..0x1dae00;133 ..0x1db780). 3422/3481 normalized chunks multiset match, 339182/347522 old rows (97.6%); unique 3172 chunks,334690 rows. Unique-chunk transfers:59692 consistent targets,821 unmapped,2 incongruent (old caller 0x106fec call 0x1046f8→new 0x108a20 call 0x105a94; old 0x107003 jmp 0x104b44→new 0x108a37 jmp 0x1060b0; unchanged clones at 0x12d264/0x12d528 are not actual targets). Real targets expand from 320→449 and310→482 normalized rows. New loops/scans over 11-byte records, virtual calls +0x2c0/+0x128/+0x148/+0x2e0, object count+0x48/table+0x68. ESA UI engine strings and SkiaPkg/ESACustom Controls source paths. P2-48 HII strings and OEMRevision remain attributed.

**Limits:** 59 chunks/8340 old rows unmatched; clone/reference/data semantics and exact UI behavior unresolved. No evidence of Linux runtime impact; keep partial.

Signature structure reproducibility (apply to each extracted 4096-byte body):

```python
from hashlib import sha256
prefix = bytes.fromhex('3031300d060960864801650304020105000420')
for m, s in [(0x48, 0x148), (0x258, 0x358)]:
    n = int.from_bytes(body[m:m+256], 'big')
    sig = int.from_bytes(body[s:s+256], 'big')
    assert sig < n
    em = pow(sig, 65537, n).to_bytes(256, 'big')
    assert em == b'\x00\x01' + b'\xff' * (256-3-len(prefix)-32) + b'\x00' + prefix + em[-32:]
    print(sha256(body[m:m+256]).hexdigest(), em[-32:].hex())
normalized = bytearray(body)
for s in (0x148, 0x358): normalized[s:s+256] = bytes(256)
print(sha256(normalized).hexdigest())
```

EsaFull: split GNU objdump .text rows at INT3 padding; remove padding; normalize candidate RIP/branch targets and indexed data addresses only for candidate matching. Compare multisets, then use uniquely paired chunks to map actual call/jump addresses. Do not treat identical clones as actual targets. Inspect the expanded target ranges given above. Remaining branch targets/data and UI semantics not proven. Final B10: 38/44 attributed, six partial.

P2-63 follow-up: Setup HII ID2057 is existing Performance Mode, no new visible form or option; combined with P2-51 this closes S33 Setup. 39/44 attributed, 5 partial. See ROM_RESTORED_CHECKPOINT.md.
