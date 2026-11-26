# Tpm20PlatformDxe final static attribution — 2026-11-26

P2-114/E109, S24 closure (runtime open). Input PE SHA256:
- 124: ecc92bb9c7735d6a044cae9b5fefde51e4d205e8bf6673bcc1a060889c5991d0
- 132=133: 74ee07f128b8b06946642cd802c8bc3b643e1cc0589372adb64d73b332c574b5

## Important applicability clarification

New RDRAND instructions at 3F0/402/413 implement 16/32/64-bit helpers, respectively (16-bit helper uses 32-bit RDRAND then stores AX). No other direct caller of the new helpers besides C817→402. No relocation targets to these helpers. The 32-bit helper checks CF, returns false on failure, stores output and returns true on success. C804 attempts it up to ten times, falls back to old GetTime + GetNextMonotonicCount + SMBIOS UUID + CRC32 / arithmetic path. Old C77C had only that latter path. New C8C8 factors out the old SMBIOS UUID traversal; its EFI_STATUS is ignored by caller. Constructor 46C calls CPUID leaf 1 at 5FD, output ECX to stack, result not consumed here.

Crucially, this routine is only called by 29A0 at 2A7D, in the existing Intel TPM vendor-specific branch. 29E7 references EFI_TCG2_PROTOCOL GUID 607f766c-7455-42be-930b-e4d76db2720f, then 2A30 calls GetCapability with size 0x24; 2A49 compares ManufacturerID (struct offset 0x18) to 0x494e5443 (INTC). The other branch 2AA0 constructs TPM_CC_GetRandom 0x17B; old 124 branch has the same vendor test and TPM command. 29A0 is called at 1B86; return status is ignored as before and 1B97 calls function 2BB4 constructing TPM_CC_HierarchyChangeAuth 0x129 for TPM_RH_PLATFORM 0x4000000C. This is a platform authorization random-data path, not general-purpose OS entropy or a clear operation.

Reference definitions: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/Tcg2Protocol.h and https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_getekcertificate.c (INTC 0x494e5443, AMD 0x414d4400). ManufacturerID test is TPM-specific, not CPU vendor. If M75n returns AMD, it does not execute the added RDRAND path. Actual machine TPM manufacturer not captured. Read-only check if TPM is enabled: tpm2_getcap properties-fixed; record TPM2_PT_MANUFACTURER. Do not change hierarchy authorization as a test.

## Complete changed-code groups

Old→new start RVAs; normalized instruction segmentation as in EsaFull tool, followed by monotonic SequenceMatcher and manual branch/operand review.

| Old | New | Attribution |
|---|---|---|
| — | 3F0,402,413 | new RDRAND helpers above |
| 42C | 46C | constructor stack + CPUID leaf 1; LocateProtocol sequence preserved |
| 72C | 784 | DeployedMode/AuditMode PCR measurement: reset size to 1 before second read, saved RBX |
| 9D0 | A30 | remove size probe, use caller size directly, add null checks. P2-39 PCR1 contract defect stands |
| 129C | 12E4 | PCR7 variable measurement stack slots 38/40 exchanged; allocate status check reorder; add full-buffer zero before FreePool on normal tail (180C), three earlier measurement error branches skip it |
| 1990 | 19FC | MemoryOverwriteRequestControl path initializes 1-byte capacity before setting; original write length 1 retained |
| 1D9C | 1E10 | Setup 446→449 and stack frame growth |
| 32F4 | 3368 | LastBootFailed read/write size reset to 4; prior write used returned length |
| 3374 | 33F0 | Setup length 446→449 |
| 3C2C | 3CA8 | Setup length and stack slots; explicit fixed 449 before SetVariable; shifted branch to reinit |
| 6864 | 68EC | indexed image-relative data references E0F8/E0D0/E210→E1D8/E1B0/E2F0, +E0 data move only |
| C77C | C804/C8C8 | RDRAND retries and old fallback split, described above |

The earlier PCR1 caller uninitialized length finding remains. The PCR7 function uses QueryVariableInfo maximum size (1320–1358), separately allocated buffer, explicit length per read; it is not the same helper. Added normal-tail clearing uses that allocation length; earlier per-read zeroing was already present. Three error branches formerly went to shared final cleanup 17A6, now jump to 1812 (skip new clearing), while final dbt success/absence branches target 17EE. No blanket claim of PCR7 correctness or runtime memory safety.

## Mapping checks

PE text 0xD4A0→0xD580, entry point 3F0→430, .data/other sections shift +E0. 135/138 pieces; 10897 paired instructions outside changed pieces, 837 direct refs and 417 RIP refs verified. One branch to a linear-disassembly internal byte at old D5BD→new D69D is in an exact shifted suffix; no semantic claim on that dead/ambiguous decoding. 525 nonidentical instruction byte spans all contain direct/RIP references; non-reference spans byte-identical. For changed pieces 3164 normalized pairs after rejecting false a0F→a51 alignment (old size-probe branch removed); 442/442 RIP refs, 686/689 direct refs consistent after manual changed epilogue/reinit mapping, remaining three intentional PCR7 branches above. Remaining changed instructions fall into listed groups. This is static attribution, not machine-checked equivalence.

All 44 DIR64 slots shift +E0; five code targets and 39 data targets map. Masked .data (4384 bytes) exactly equal. Unnamed and .xdata sections entirely zero; size change explained by layout. Resource section 4944 bytes, sole raw differing byte at offset 72 from RVA F100→F1E0. Reloc slots all accounted; all section padding zero. Header changes only .text size, entry, image size, data directory RVAs, section sizes/addresses. 132/133 exact payloads.

S24 row closed for *static attribution*, not for risk. Actual PCR1 event logs, TPM manufacturer, boot state and PCR replay remain B06/B12. No TPM clear, device changes, or hardware execution performed.
