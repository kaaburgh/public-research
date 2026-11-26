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
