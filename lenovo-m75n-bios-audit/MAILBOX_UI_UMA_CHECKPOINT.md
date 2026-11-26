# Targeted mailbox, GUI and UMA follow-up — 2026-11-26

All three original images verified against previous manifests. Offline analysis of A75 extracted modules and GNU objdump; no flash, variable writes, raw SMI, hardware or failure injection. Attribution status remains conservative. The previous P2-63 Setup closure is for S33 only.

## P2-66 / E61 — B10: SecureBootDXE and mailbox producer

**Finding:** Confirmed request-specific handling and incomplete error aggregation; no new ordinary-boot key reset identified.

**Evidence:** All 410 extracted PE32 occurrences per release scanned: mailbox UTF16 name absent in 32, present only in four modules in 33. DEPEX identical in 32/33 for all four. SecureBootDXE callback 0x43C closes event, excludes special boot modes, exits on read failure or signature mismatch; valid request enters existing Secure Boot state/key routines. Restore helper 0xA38 loops over key/database entries, overwrites return status on subsequent iterations (0xABA–0xB1E), does not aggregate failures; callback 0x574 deletes request without checking deletion result, uses operation status for conditional reset at 0x577–593. Producer reads three standard mode variables; pre-existing authorization helper 0x5418 invoked conditionally; ordinary operations gated by existing platform/password-state checks. No raw invocation tested.

**Limits:** Possible partial restore with later successful status or request left pending after deletion failure; no failure observed on device. Last-status helper predates 1.33; new path reuses it. Actual external SRWIN call and all authorization boundaries remain unverified. No vulnerability/bypass claim. Keep both S33 sections partial.

## P2-67 / E62 — B10: NvramDxe/NvramSmm policy scope

**Finding:** Both new predicates add mailbox-read success to existing Secure Boot policy decision, not a generic NVRAM write path.

**Evidence:** DXE predicate 0xC3D0–0xC417 and SMM 0xB2C8–0xB30F check read status only; consumer separately validates request content. DXE wrapper 0x9FF8, SMM 0x9268 iterate predicates, apply existing SecureBootSetup-dependent guard and mode condition. Three direct callers each: DXE 0xA2D6/0xA475/0xAF25, SMM 0x9546/0x96E5/0xA195; mode-variable setting, key/state maintenance and authenticated-variable handling. Ordinary absent request leaves prior predicate sequence behavior unchanged apart from extra lookup; no new DEPEX. Prior P2-52 code diff groups remain applicable.

**Limits:** Full data-pointer attribution, caller authorization and hardware effects not complete. Read success alone is not a proof of exploitability; no test manipulating mailbox or EFI variables. Both S33 sections remain partial.

## P2-68 / E63 — B10: EsaFull expanded GUI paths

**Finding:** Expanded functions are called from UI object selection and position-update handlers; likely focus/visibility/layout behavior, not a demonstrated OS-runtime change.

**Evidence:** 33 caller 0x1089C8–0x108A2F follows object links through virtual methods, selects eligible object, calls 0x105A94 only on changed object, sets local flag; 0x108A30 tail-calls 0x1060B0. First expanded target saves object and two coordinate-like properties, traverses 11-byte records by 16-bit object key; second checks object eligibility/property change and adjusts bounded positions using virtual getter/setter pairs and margins. Both are UI-specific in context; P2-54 exact transfer matches retained. DEPEX identical 32/33.

**Limits:** Class names and exact vtable method semantics not yet independently identified; 59 residual chunks/data references not closed. Focus/scroll interpretation is inference, no observed GUI behavior. Keep S33 partial.

## P2-69 / E64 — B04: native UMA browser callback

**Finding:** Confirms CHANGING action and full IFR value pointer; browser-data update errors are ignored, distinct from persistent CBS RouteConfig.

**Evidence:** Setup entry 0xEBC saves original HII callback Action at context+8, Type at +0x12, Value pointer at +0x18; 0x377B requires Action=0 (EFI_BROWSER_ACTION_CHANGING); QID 0x2893 IFR 32-bit, read at 0x37E3 still BYTE. 0x14FB0 helper locates FormBrowser2 and HiiConfigRouting by standard GUIDs; retrieves browser data (0x1506D/150D0), converts block (0x1511D), updates browser via BrowserCallback RetrieveData=FALSE at 0x1516B; returns status. Caller 0x381E/383D ignores both statuses and returns EFI_SUCCESS at 0x3842. CbsSetupDxeRV RouteConfig 0xA10 performs persistent SetVariable then APCB helper; reverified. UEFI HII protocol reference https://uefi.org/specs/UEFI/2.9_A/35_HII_Configuration_Processing_and_Browser_Protocol.html ; protocol GUIDs corroborated by EDK2/iPXE headers.

**Limits:** Shows width mismatch on standard callback contract and two ignored update errors; actual browser dispatch/availability and whether native Save & Exit routes CBS remain unresolved. 128 MiB avoids truncation, not guarantee of persistence or reclamation. No hardware writes.

## P2-70 / E65 — B09: remaining unmapped raw bytes

**Finding:** Located two changed bytes within EFS-containing page; directory pointers identical.

**Evidence:** SPI page 0x20000–0x20FFF begins 0x55AA55AA, EFS address 0xFF020000 is documented by coreboot https://doc.coreboot.org/soc/amd/psp_integration.html . At +0x14 pointer 0xFF082000 resolves $PSP; +0x1C 0xFF145000 resolves $BHD in all three. First 0x20 bytes exact; bytes 0x20043/44 are the only non-FF bytes in remainder of page in live 1.24, vendor 32/33 all FF there; only two raw differences in this page. UEFIExtract calls initial region Padding, not proof of unused bytes.

**Limits:** Page-level attribution only; exact meaning/ownership of the two bytes, whether live state or factory delta, and retention unknown. Do not treat as padding or SPI mode change without proof. No clean 1.24 factory ROM. B09 partial.

## Reproduction
Extract the exact PE32 payloads using inventory GUID/section keys and verify SHA256. Compare their DEPEX separately. For the mailbox string scan, enumerate extracted PE32 body.bin occurrences (410 each) and search the UTF-16LE name; do not mistake occurrence count for unique images or a proof of no dynamic consumers. Decode x86-64 instructions with objdump -d -M intel --no-show-raw-insn; for the UMA callback use native IFR form 0x2890. Validate EFS signature and map its two known directory pointers against the actual ROM signatures; compare the 4KiB page locally. The values of private live bytes are not published. The UEFI HTML specification was indexed but direct fetch gave 403; protocol GUID/signatures corroborated via headers (https://dox.ipxe.org/FormBrowser2_8h_source.html and https://bsdio.com/edk2/docs/master/_hii_config_access_8h.html). No claim about firmware authorization bypass or exact semantics of the two EFS tail bytes.

## Status
39/44 S33 attributed; five remain partial. 168 S24 + 5 S33 = 173 pending. No new reclassification. All findings are static and hardware testing remains outstanding.
