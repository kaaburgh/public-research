# NVRAM migration and small OEM/TPM module attribution

26 November 2026. Verified 1.24 AFU and official 1.32/1.33 ROMs against manifest; extracted UEFIExtract A75. PE32+ RVA-to-raw translation, GNU objdump Intel syntax. Static analysis, no firmware execution or writes.

## P2-106 — NVAR selector / all versions

Selector helpers byte-identical 1.24/1.32/1.33; same preserved pair/state gives same selection.

Evidence: PEI TE raw [1122,11FA) SHA256 04cc4fe15d5e8879291d69e70ffe214f8202f83c3ea7b06593601f1d5665e9b8; DXE RVA [7E90,7F7C) old, [8110,81FC) new SHA256 a32684956be8292ba1b83a704084dd31857080fc17a36f822328bf1d1ba7e06e. PE RVA/file offset mapping verified.

Limits: HOB overrides, flash preservation and live selection unverified.

## P2-107 — Setup/NVRAM migration / 1.32–1.33

Size mismatch path reconstructs scratch store; copies non-default name/GUID keys, excludes old versions of 13 StdDefaults keys. BootOrder/Boot####, PK/KEK/db/dbx and AmdSetup intended to survive this path; Setup/SecureBootSetup may reset.

Evidence: DXE 15E0 probe only checks size on EFI_BUFFER_TOO_SMALL (446→449); 1E70 calls 5388 with flags 1,1; return ignored. External defaults GUID 9221315B-30BB-46B5-813E-1B1BF4712BD3; 4254 copies defaults containers, 7E18 extracts nested StdDefaults, 4958 excludes defaults containers and keys found via 7844, 4CE8 copies remaining keys, 52D0 commits. Four vendor StdDefaults bodies hash identical (4008df040f61fb80d5e8cd8a7fcab9c056fba130c110f7e1aa371dd8ce5e0401).

Limits: Conditional route only; nested defaults parse failure, copy/commit errors, other firmware policies, authenticated variable persistence and post-flash behavior untested. NvramDxe/Smm PE residuals remain.

## P2-108 — AmiTcgNvflagSample / S24

TcgInterfaceVar SetVariable uses fixed one-byte size rather than length returned by prior GetVariable; stack/register adaptation; static PE attribution.

Evidence: Function 478–610→478–614; outside 251 decoded instructions, 28 direct transfers, 27 RIP refs, no target/raw-span exceptions; four DIR64 slots mapped, .data only three relocation bytes change, headers size changes. Inside 92→96 instructions; four branch references to relocated epilogue 606→60A resolved. 32=33.

Limits: Actual TPM/measurement behavior untested; no evidence of TPM clear. Static attribution only.

## P2-109 — LEMAllDriversConnectedEventHook / S24

Setup 446→449; Sub1LastRun error path writes fixed 4-byte value and restores capacity; AbtSetup second read resets capacity to 4 bytes. Stack changes; static PE attribution.

Evidence: Function 674–1658→674–1664; outside 452 decoded instructions, 69 direct transfers, 33 RIP refs, no exceptions; one DIR64 slot target mapped, .data one byte changes, header only .text size. Inside 824→827 instructions, normalized matching and manual stack/branch target checks.

Limits: No proof of all error-path safety or Computrace activation/network behavior; actual OEM runtime untested.

## P2-110 — SwSmi534D0140 / S24

Setup size/stack adaptation; AMITSESetup write length fixed at 771 bytes instead of prior GetVariable output size; error path rearranged. Static PE attribution.

Evidence: Function E28–1328→E28–133C; outside 1289 decoded instructions, 195 direct transfers, 142 RIP refs, no exceptions; seven DIR64 slots mapped, .data three pointer bytes change, header only .text size. Inside 289→297 instructions, normalized matching and manual stack/register/branch checks. 32=33.

Limits: Password-related firmware path; no proof of behavior for shorter successful reads or complete access policy; no exploit or hardware testing.

## Migration details

The Setup GUID EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9 and UTF16 name Setup are verified at the data references in all three size probes (124 DF90/D248, 132 DFE0/D248, 133 DFF0/D258). The size probe returns true on statuses other than EFI_BUFFER_TOO_SMALL; it is not a general validity check. At 132 1D48 R14D=1, 1E45 checks initialization, 1E5A size probe, 1E70 calls migration, 1E75 continues regardless of result. 5388 creates scratch using 697C, copies prefix (descriptor length +3C), discovers FV2 and reads vendor raw section 19h, copies StdDefaults and MfgDefaults containers via 4254, tolerating EFI_NOT_FOUND. 7E18 resolves nested defaults via 7844 then 73B4/7DA8. 4958 first rejects defaults containers via 48C4; if bit0 of flags set, returns true when nested store missing or key lookup via 7844 returns zero; optional bit1 allowlist inactive with flags=1. 4CE8 enumerates old keys, 4254 skips existing destination (already started); 52D0 writes scratch back. Conditional failure paths remain. 132/133 inspected migration regions match after RIP and relocated helper targets (C480→C4D0, C42E→C47E); prior P2-84 mapped S33 NvramDxe. No conclusion about authenticated write acceptance or exact on-device migration result.

Four extracted StdDefaults bodies are equal: two per vendor image (NVAR store, external defaults). Entries: Setup, PlatformLang, Timeout, AMITSESetup, SLD_Flag, RtcWakeData, NetworkStackVar, DashSetupVariable, MctpSetupVariable, UsbSupport, WifiSetup, SecureBootSetup, PCI_COMMON. No MfgDefaults found in extraction. Standard EFI boot entries and enrolled keys, and AmdSetup, absent from this list. This is a selective preservation policy, not assurance against all other reset routes. User data and machine identifiers not published.

## Small module method

Compare instructions excluding INT3 padding outside indicated changed function; map ordered instruction addresses, check decoded operands normalized only for direct branch and RIP targets, verify target correspondence and raw instruction lengths/difference categories. Relocation directories identical; map each DIR64 target. Header changes restricted to section virtual sizes and padding; other section raw bytes exact except pointer values. Inside changed functions use normalized alignment and inspect changed instructions, including branch targets into shifted stack/register operations. No formal whole-function semantic equivalence proof; closure is static attribution. Remaining runtime and access-policy verification separate. 1.32 and 1.33 PE bodies exact for these three modules.

Remaining queue 89. Next: USB/NVMe and Setup/NvramDxe/NvramSmm remaining PE changes, EsaFull S33 data mapping. Hardware validation independent.
