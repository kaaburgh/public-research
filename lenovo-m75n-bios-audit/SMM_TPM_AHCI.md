# SMM, TPM and AHCI risk checkpoint

2026-11-26. Offline comparison of extracted PE32 bodies from 1.24/1.32/1.33. All six named modules' 1.32 and 1.33 bodies are byte-identical. No hardware update performed. Addresses below are RVAs for image base zero (objdump -d -M intel --no-show-raw-insn); verify by extraction and SHA-256. Candidate alignment: SequenceMatcher over instruction text with RIP displacements and direct branch targets masked and padding NOP/INT3 filtered; ratios are heuristic, not proof of semantic equivalence. Verify changed operands against raw sections and call paths. Private dumps remain external.

## Payload hashes

| Module | 1.24 SHA256 | 1.32 / 1.33 SHA256 |
|---|---|---|
| PiSmmCore | 288852eb33507f32a047056e5d26e0029140c670483c317005fb53cd91404993 | 08e12909d96c7aca57fffeb09c31a2daec11dac754d7cd5c6ee108c7c487f606 |
| PiSmmIpl | c8444bb13315057aaaab56f01592d371ee7b664710dce960c231aeebd229f0b0 | 11f00f114dc8a5800300d2349a8b850c12ab5dfeead6c91ee510315c84302f45 |
| SmiVariable | d3513eb0fd2a259a786d02d04dbfb5aacbf2f30052ee4ebe27b6afc118efb5f9 | bf7aefb050e035f37498906f44cc163b5b1f59de6c2cb6f965979f0173943bde |
| Ahci | 1581ed22aca08c1c2219e9e406a327dce254ccf33e8185825d6fa3fa8c4fdd4c | 2f92586b442c5692b4f0e8b14f618e9c17ff38484e010a3fc352c8a376e90891 |
| AhciInt13Smm | 43f160ac06c2de632ea9f2c33b2d66392a28514ef64024cfdb0ec8efb8c1ef70 | b671927243d7ef9ea3a231d4e9cb02a213262d35b98df120046cd613913c71e1 |
| Tpm20PlatformDxe | ecc92bb9c7735d6a044cae9b5fefde51e4d205e8bf6673bcc1a060889c5991d0 | 74ee07f128b8b06946642cd802c8bc3b643e1cc0589372adb64d73b332c574b5 |

## P2-32 / PiSmmCore

**Finding:** Усилена проверка диапазонов и размеров SMM communication

**Evidence:** 34176→34272 B; .text 0x71B0→0x7210; 7579→7612 heuristic instruction rows, 42 diff groups; similarity .99098 is not equivalence. New 0xE66–0xEB3 checked end calculations, 0xEB5–0xEC6 checks communication header >=0x18 before subtract; 0xED2 calls range validator 0x5220, dispatch 0xEF3→0x306C, error path 0xF2A. Old 0xE6A–0xEA5 had unchecked arithmetic. Helpers old 0x5148/51A8→new 0x5194/51F8 use inclusive last-byte end (previous guard already used -1). PE parser 0x6738–0x6747 adds 32-bit RVA+size check. .data 66 bytes changed, relocation 81; unnamed/xdata identical. 32=33.

**Limitations and risk:** Potential added work per communication request and rejected previously accepted malformed requests; no new periodic SMI trigger identified. Remaining data/RIP references not fully attributed; actual SMI frequency/latency unmeasured.

## P2-33 / PiSmmIpl

**Finding:** Проверки переполнения при подготовке SMM

**Evidence:** 14336 B each; .text 0x2662→0x26CA; 2517→2539 heuristic rows, similarity .9486. New 0x1D0A–0x1D4B checked 64-bit ends for ranges, overlap/error branch calls 0x1934; call at 0x1FB2 after SMM access protocol lookup; SMRAM descriptors stride 0x20. PE loader 0x2D48–0x2D57 checks 32-bit RVA+length vs old 0x2CEE. .data, unnamed, xdata, reloc identical at respective offsets; DEPEX unchanged; 32=33.

**Limitations and risk:** Primarily boot-time SMM initialization; no evidence of new periodic runtime activity. Residual code mapping/error behavior not fully attributed.

## P2-34 / SmiVariable

**Finding:** Локальные копии входных структур в SMM

**Evidence:** 5504→5824 B; .text 0xF0A→0x103A; 1021→1105 heuristic rows. Handler 0x6C4→0x6A4; stack 0x50→0xA0. New copies at 0x819 (12B), 0x8CF (32B), 0x9CA (24B), 0xA64 (32B) via 0x11E0. SMM pool alloc 0x10CC via SMST+0x50, free helper 0x10FC selects SMM/BS by range. Some original input rereads remain 0x96D–0x98A,0x9CF,0xAC8. .data and DEPEX unchanged; legacy SW SMI registration remains; 32=33.

**Limitations and risk:** Security hardening inference; not full isolation proof. Legacy SMI interface not proven to be Linux efivarfs path. Added latency only when affected handler executes; no periodic trigger identified. Residual branches/actual OS usage open.

## P2-35 / Ahci

**Finding:** Все 10 изменённых байтов объяснены

**Evidence:** 34240 B each; all ten raw changed bytes in .text. 0x3F9C/3FA4 frame -0x200→-0x210, stack 0x300→0x310; 0x3FE9 Setup size 0x1BE→0x1C1; compensating offsets 0x3FDD,4024/402B,4081,4263/426B. All other sections/DEPEX equal; 32=33.

**Limitations and risk:** No new AHCI data-path logic found. Native Linux storage performance not established by firmware static comparison; configuration/reset effects separate.

## P2-36 / AhciInt13Smm

**Finding:** SMM access dependency и копирование запроса

**Evidence:** 8000→8576 B; .text 0x1830→0x1A00; heuristic 1679→1810 rows, .9407 similarity. DEPEX 72→90 B adds AND EFI_SMM_ACCESS2_PROTOCOL c2702b74-800c-4131-8746-8fb5b89ce4ac. New protocol lookup 0x4D9, GetCapabilities 0x4FB/51F, SMRAM descriptor count 0x527–52B. Handler 0x1520; 0x1535–1566 alloc/copy 0x481 B; count bound at 0x156F–1575; new free/range helper 0x1AC0. 32=33.

**Limitations and risk:** Legacy INT13/SMM path, not evidence of native Linux libata throughput change. DEPEX fully attributed; executable partially attributed. Check all init/failure paths and whether handler executes in target boot mode.

## P2-37 / Tpm20PlatformDxe

**Finding:** Изменения RNG, размеров переменных и очистки буферов

**Evidence:** 66688→66912 B; .text 0xD4A0→0xD580; 14263→14327 heuristic rows, similarity .98734. New RDRAND wrappers 0x3F0/402/413; 0xC804 retries 32-bit RDRAND up to ten before old fallback; direct call 0x2A7D behind TPM manufacturer INTC gate at 0x2A49. New size init 0x815/33AC, Setup size at 0x5328/5341, dbt cleared 0x17EE–180C before free. DEPEX identical; .data 80 diff bytes, .rsrc 1. 32=33.

**Limitations and risk:** Intel-gated RNG unlikely relevant to AMD fTPM; actual manufacturer not measured. No direct TPM-clear change established. Residual data/control flow remains; measured boot issue separate P2-38.

## P2-38 / Tpm20PlatformDxe / measured boot

**Finding:** Кандидат на регрессию: размер буфера BootOrder/Boot#### не инициализирован

**Evidence:** Old helper 0x9D0 initializes *size=0 and queries GetVariable size via NULL buffer; new 0xA30 reads *size at 0xA5D and allocates at 0xA70, then calls GetVariable at 0xA9D, no size probe. Only direct caller wrapper 0x1C10→0x1C37 does not initialize size. Caller 0x1CA0 passes local +0x38 at 0x1CD7 and +0x48 at 0x1DAE, no prior dominating write; +0x20/+0x40 are output pointers, not sizes. Failed allocation/read maps to EFI_NOT_FOUND (0x1C4F); BootOrder not-found path returns success (0x1CF2–1D1C), Boot#### loop continues. Measurement wrapper 0x1C89→0xAD4 PCR1, EV_EFI_VARIABLE_BOOT 0x80000002; callback 0x201C via table 0xDB48 at 0x20E5; ReadyToBoot registration 0x6034→0x7938→0x798C. 32=33.

**Limitations and risk:** Strong static regression candidate, not observed hardware failure. Depending on stack values, TPM dispatch, read/allocation, BootOrder/Boot#### measurements may be missing or vary; PCR1-bound sealing/attestation affected. Does not itself delete boot variables or clear TPM. Verify actual event log and PCR baseline; repeat cold boots. Prioritize before update if TPM-bound unlock used.

## Measured boot verification

Read-only capture before/after an official update with the same configuration, where TPM and securityfs are available: save `/sys/kernel/security/tpm0/binary_bios_measurements`, decode with `tpm2_eventlog`, record PCR1 and other relevant banks with `tpm2_pcrread`, repeat cold boots. Compare presence/order/content of EV_EFI_VARIABLE_BOOT records and PCR replay, not raw PCR equality across firmware versions. Establish recovery access for TPM-bound disk unlock before any update. Secure Boot disabled does not necessarily disable TPM measured boot. No flash, variable write or TPM clear is part of this audit.

Status: B03/B06 partial, 2 section rows closed, 5 partially attributed; P2-38 separate candidate in the same TPM section. No CVE attribution and no measured performance regression.

P2-77: NvramDxe installs normal EFI runtime variable callbacks, conditionally routes via SMM Communication to NvramSmm. SmiVariable separately registers software SMI and uses CPU save-state. New legacy enumeration size is stored locally rather than original response as in 1.24; compatibility candidate only. See SETUP_SIZE_BATCH_CHECKPOINT.md. No observed routine Linux overhead.

P2-80: OemSwSmiDispatchProtocol fully attributed, two legacy records removed with WMI standard SW Dispatch2 registration for retained operation and removed Lenovo_PRELOADElement branch. WMI DEPEX closed, PE residual open. No hardware invocation or proof of routine OS impact.
