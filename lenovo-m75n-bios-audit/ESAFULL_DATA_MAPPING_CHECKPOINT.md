# EsaFull 1.32 → 1.33: relocation-slot and data-map checkpoint

P2-113/E108. Follow-up to ESA_SECUREBOOT_FINAL_MAP_CHECKPOINT.md. Offline analysis, no hardware execution.

## Inputs and reproduction

Extract EsaFull PE bodies from verified vendor M33KT32A / M33KT33A ROMs using UEFIExtract NE A75 (see prior checkpoint).

- 1.32 PE SHA256: 587fe62378b72f8e2a338290f7eaddc6ada05499114e47627ed1dcfc5809f24c
- 1.33 PE SHA256: c4c608dc4c0897a882196309914ed3b1bcd2d439b8dc2d5e535fa2e1276f454e
- Both .text RVA 0x300, size 0x145af8. .data RVA 0x145e00, size 0x95000 → 0x95980. 5832 DIR64 slots in .data plus 9 in .CRT each.

Run:
```sh
objdump -d -M intel --no-show-raw-insn EsaFull-132.bin > EsaFull-132.bin.asm
objdump -d -M intel --no-show-raw-insn EsaFull-133.bin > EsaFull-133.bin.asm
python3 tools/esa_data_map.py EsaFull-132.bin EsaFull-133.bin
```
Python 3 + NumPy. Tool is deliberately a *partial correspondence* heuristic, not an equivalence proof. It independently rebuilds a less aggressive code map than P2-89, without its manual embedded-table corrections, and must not replace the earlier corrected semantic map.

## Measurements

1. Split decoded .text at INT3, direct call destinations, DIR64 code targets. Normalize only direct branch targets and RIP displacement. Accept fingerprints occurring exactly once per image; reject pieces with contradictions against known direct branch targets. 4493/4492 pieces total, 4079 unique paired pieces / 333682 mapped instructions, zero detected contradictions against known direct branch targets. This does not prove all branch targets or indexed data references.
2. Collect RIP references from those pairs. 15202 references, 2647 distinct old data addresses, 2643 mutually unambiguous anchors. Mask each relocated 8-byte pointer with position tokens 256..263, distinct from literal bytes. For each anchor delta expand its maximal equal range in masked .data; require >=16 bytes and some nonzero/token. Reject overlap on either side at byte level. 213 candidate intervals; 575898/610304 old bytes provisionally mapped, 4436 old bytes in overlapping candidates. Zero padding and repeated data can still give wrong alignment.
3. Pair slots only when first and last bytes map consecutively and new slot exists. 5120/5832 old .data slots paired. 4099 targets agree with unique-code map, 34 with direct RIP anchors, 133 with inferred masked intervals (4266 total consistent, not all independent); 848 unknown (464 code,384 data); 6 conflict with inferred target.
4. Independently group maximal adjacent 8-byte DIR64 slots, length >=3. Fingerprint each target by normalized code piece and instruction index or exact 16-byte nonzero literal data prefix (no pointer token); allow unknown only when enough informative targets remain. Accept run fingerprints unique on both sides. 113 paired runs / 3192 proposed slots, 3169 informative. 3075 agree with byte map, 115 previously unmapped, 2 conflict. Union 5235 old slots with proposals, 597 not proposed; do not add metrics as if independently verified or all mapped one-to-one.

## Specific corrections and residuals

- Old slot 0x1764f0 target 0x5be98: independent run points to 0x1764c0 → 0x5b3a8 (not greedy masked interval 0x1764a8 → 0x5aaa0).
- Old 0x1764f8 → 0x5befc: run points to 0x1764c8 → 0x5b40c (not 0x1764b0 → 0x5aa88). Both new correct proposed targets share exact normalized piece fingerprints with old targets. This is further evidence against over-interpreting repeated-vtable alignment.
- Of six target conflicts in byte map: old 0x1da820/870/8c0 and 0x188380 point into zero-filled data with shifted alignment; old 0x17c2d0 and actual new 0x17c818 both UTF-16 "dbx" (the guessed mapping 0x17c810 instead points to "dbt"); old 0x185c38 / new 0x186150 have matching leading literal bytes but inferred 0x186158 is shifted. These are conflicts in candidate inference, not six proven firmware behavior changes.
- 429/464 otherwise unresolved code target pairs share exact normalized piece plus instruction index; duplicates cannot establish identity alone. Of 35 remaining pairs, many involve indexed image-relative data displacements; 0x4ac34 is a linear-disassembly boundary artifact (direct disassembly confirms same setter + ret at both versions). The two wrong vtable slots above also contribute to these 35. No full closure.
- .CRT nine slot targets equal at same code addresses, but this method does not independently establish code identity at those addresses; previous checkpoint remains authoritative.

Next: resolve indexed image-relative references and ambiguous data targets with call/relocation graph, not arbitrary zero padding. No new evidence of a runtime regression from EsaFull. Queue remains 88 S24 + 1 S33 = 89; S33 43/44 attributed.
