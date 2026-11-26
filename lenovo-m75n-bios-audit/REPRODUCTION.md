# Reproduction checkpoint — 2026-11-26

Inputs are external by design: owner supplies 1.24 live AFU, stock 1.32/1.33 ROMs and exact toolchain if needed. Source manifest identifies them. ROM absence in Git is not a blocker. Private source SHA verified locally for all three before testing. No executable from firmware was run; no firmware or private generated files committed.

## Commands
Extract with A75 as described in METHODOLOGY.md. Use absolute script paths if the working directory is not the repository folder.
```sh
python3 tools/inventory.py 124.rom.dump 132.rom.dump 133.rom.dump -o regenerated.tsv
python3 tools/compare_inventory.py data/inventory.tsv regenerated.tsv
python3 tools/audit_verify.py data/inventory.tsv 124.rom.dump 132.rom.dump 133.rom.dump
python3 tools/flashmap_model.py 124.rom.dump 132.rom.dump 133.rom.dump
python3 tools/instruction_diff.py smiflash124.efi smiflash132.efi -o smiflash-diff.json
```
For last command extract the PE32 body.bin of SmiFlash from each dump to the given paths. Compare reports locally; generated data may contain private hashes or instruction bytes and must not be blindly committed.

## Actual local checks (corrected private reference)
- Independent enumeration: release rows 2256,2253,2253; union 2256; zero missing/extra keys; per-release SHA and size multisets exact; corrected ordinal mismatches 0.
- Executable verifier: 1522 hash matches, 0 missing, 0 classification discrepancies, exit 0. 124→132 257 exact / 68 normalized equal / 182 different / 1 removed. 132→133 476 exact / 7 normalized equal / 24 different / 1 absent both.
- Flashmap: six descriptor bodies, each SHA256 9a89d41dbb2d3d9f43a0d2028c3f545f0a84a02b5856758b7ad3b6f6a222dba1. Each 4096 records, 9 compact ranges, sum 16777216; both forms round-trip; expanded record array SHA256 1314b86f236c3e713e73488e65c8894d2a852ed34a8d157606cd2d2e8511d994; exit 0. This models successful response payloads, not SMI execution or every AFU check.
- Instruction matching: SmiFlash PE32 8182/8230 instruction rows, 105/106 int3 chunks, 95 candidate pairs, 10/11 unmatched; AmdSpiRomProtectPei TE (machine 0x14c) 108/108 exact disassembled instruction rows. This is search/matching, not proof of all functions or actual runtime behavior.

## Corrections
B08: AmdSpiRomProtectPei TE raw diff is one byte at +0x10 (0x2c→0x6c), ImageBase 0x09E5222C→0x09E5226C; PlatformCustomizePei same +0x10 (0x24→0x64), 0x09E51B24→0x09E51B64. Both full images equal after zeroing ImageBase and normalizing supported relocations. Old stats counted them as normalized different. No other changed byte, 1.32=1.33. E14 in private ledger.
PcdPeim 9B3ADA4F-AE56-4C24-8DEA-F03B7558AE50 duplicate: old 1.24 instance numbering matched opposite volume. Correct pairing: 4F1C52D3…/5C60F367… = exact 066599efbb763c5f645ba55933519e44dab63d2526993bba758fa3e8d742cf58; 61C0F511…/147923CE… = 06301eba460f62f72ddc6683dc559877b6b764b4042aea9e6497e24ad2cba15e → 981b6a47d4eabce71fb434f7f11d171b4153d5e52a6df60e136c6d86eba7885f (81 raw bytes; normalized digest equal to first copy). E15. Inventory corrected using 1.32 stable instance keys; formerly changed first copy now exact; remove it from changes. Original 284 changed union→283. Historical snapshot at de8af33 retained in Git. No content loss; all hash multisets unchanged.
 
## Tested script Git blob IDs
- audit_verify.py 5127d88f36b2535f2e97bd595a337bc53c065598
- inventory.py 58ea62d48a92ed00b4bfb4c6b1acc3f4768469e7
- compare_inventory.py 2cb08a3d0b367f9faec55d70025dad513fd9b0d8
- flashmap_model.py 89b770d614e5847a492c32cb3b99c9b37d01b23d
- instruction_diff.py 4dfdcc64ebb7770eca04b599c0a892d7c3d46473

The script contents were independently verified on upload by exact blob SHA. Original temporary scripts are unavailable; these are reconstructed implementations. Remaining gaps: raw-ROM coverage, specialized parsers, generalization beyond the three ROMs, independent semantic verification and hardware measurement. Python 3.10+ and GNU objdump. No dependency on chat history for running these five tools.
