# Platform reconstruction checkpoint — 2026-11-26

External inputs: owner-supplied ROMs (including private AFU), named 124.rom, 132.rom, 133.rom, exact SHA-256 verified privately, A75 extraction as in METHODOLOGY.md. Absence from Git is intentional. Python 3.10+, ifrextract-rs 1.6.1. Outputs are LOCAL and may contain private data. Do not publish them.

```sh
python3 tools/amd_data.py 124.rom 132.rom 133.rom -o amd.json
python3 tools/nvram_inspect.py 124.rom.dump 132.rom.dump 133.rom.dump -o nvram.json
python3 tools/acpi_inventory.py 124.rom.dump 132.rom.dump 133.rom.dump -o acpi.json
python3 tools/ifr_compare.py 124.rom.dump 132.rom.dump 133.rom.dump --tool /path/to/ifrextract-rs -o ifr_run
python3 tools/verify_platform.py .
python3 tools/raw_coverage.py 124.rom 132.rom 133.rom -o raw.json
```

Use absolute script paths if running from a separate work directory. IFR output directory must not exist. Run `verify_platform.py` with no arguments for synthetic boundary checks without ROMs.

## Reproduced results

- AMD: 4 checksum-valid directories per release ($PSP, $PL2, $BHD, $BL2), 20/29/36/40 entries, 125 total. Fletcher-32 on count/reserved/entries. All directory metadata equal across releases. All mapped PSP payload hashes equal, including directory entries that point to subdirectories. 48 APCB blocks per release (144 valid checksums total); compare declared SizeOfApcb after clearing UniqueApcbID and checksum. 47/48 equal from 1.24 to 1.33 and 48/48 from 1.32 to 1.33. One live override differs; factory vs machine-specific distinction retained. CBSG 0x1707 types 0xd/0xf parsed using descriptor token bits 8..20, width bits 21..23 plus 1, sentinel 0x001fff00, packed little-endian values. Unknown byte 0x125 remains.
- Microcode: 3 patches per release, each 3200 B, directory type 0x66 (low byte), revision/equivalence/date extracted from patch header; 8181: 08108109 (2019-04-17) -> 0810810e (2024-11-12), 8180 unchanged 08108002, 8201: 08200103 -> 08200105 (2024-11-11). No microcode signature/authentication verification or performance inference.
- NVAR: selected name/GUID roots resolved through A75 offset links to Full/Data terminals without ambiguity in the supplied AFU. Both BootOrder sets passed structural checks. Two entries in each contain multiple packed device paths; a parser requiring a single End Entire would reject valid FilePathList. This is not a proof that the BDS implementation accepts all structurally valid paths. StdDefaults counts 3/2/2, each copy contains 13 name/GUID entries and all copies within a release are identical. Only Setup differs 1.24→1.33. This corrects the earlier undercount of StdDefaults copies in 1.24. Active NVAR store selection, other variables and raw link decoding not proven.
- ACPI: 1 DSDT + 32 SSDT unique checksum-valid static tables in each release, 132 extraction occurrences, hash sets and multiplicities match. Occurrences include repeated extracted/container copies and do not imply 132 distinct firmware tables. No dynamic/live table assertion.
- IFR: ifrextract-rs 1.6.1, en-US, removed only extractor header. AMD CBS/PBS identical in all versions; both native Setup formsets identical between 1.32 and 1.33. The native 1.24→1.32 diffs are preserved locally with full IDs, conditions/options and defaults.

| IFR formset | SHA-256 1.24 | SHA-256 1.32/1.33 |
|---|---|---|
| CBS | b37ed819eb80482c2c43dd3580002c62803f3d7b420c1e4016e6d22c78b0b4a3 | same |
| PBS | 8520d635cfee756c4be242a23ade91ecd2ccbb6162c1e0abfe98e8c3f6b3a131 | same |
| Setup 0.0 | 862530b02ca63eb94dfb06308d60d77da9808025ad1aff30ca839653e0db4723 | 915de70c7431ca58018f32a8cc91ba2a11ba0e9576a543fc2aa4738a72aa1ddb |
| Setup 0.1 | c425532297272c22175bd788dea761e7349a8ab2c8312c7c60a85fc95e8b7ec3 | d95cc2b108256d2992cd3647451c57cc1ad46144815808e60b72247dcaeedc54 |

## Raw-ROM coverage

197 atomic address ranges per pair; union boundaries from validated AMD directory entries and checksum-valid FV headers. Sum of lengths equals 16,777,216; sum of changed bytes equals direct raw comparison, with overlap labels retained and deterministic priority. All three comparisons passed.

| Pair | Changed bytes | Unmapped bytes | Changed unmapped bytes |
|---|---:|---:|---:|
| 1.24→1.32 | 5590489 | 292300 | 2 |
| 1.32→1.33 | 4575347 | 423372 | 0 |
| 1.24→1.33 | 5590595 | 292300 | 2 |

For 1.24→1.33: FV (excluding separately tagged NVAR FV) 5353790, NVAR FV candidate 194425, BIOS type 63 (APOB candidate) 41436, microcode 756, APCB 186, unmapped 2. These are physical byte-position comparisons, not semantic changes. Layout/compression/rebase and live state can inflate counts. Type 63 interpretation and unmapped bytes remain open. Do not claim full semantic attribution. B09 partial.

## Actual regression run

`verify_platform.py .` exit 0:
- synthetic boundary tests PASS (packed EFI paths, truncated paths, invalid length, invalid token data, wrong ROM size)
- AMD directories/APCB/microcode PASS, deliberate checksum corruption rejected
- NVAR selected chains/StdDefaults PASS (active store not identified)
- static DSDT/SSDT PASS

IFR and raw accounting ran separately with exit 0; IFR hashes manually compared to historical values. Tests do not cover arbitrary platforms or all malformed inputs. The NVAR parser operates on extracted metadata and is not a raw parser.

## Tested Git blob IDs
amd_data.py 0e8b616a91e7ecaea246721d9958e61baeea4f57
nvram_inspect.py 3f36b010ae21da6b48aeb2fbc879e1d19e7dcc16
acpi_inventory.py dfd2e702a9f95d24ce4dc9d129483fbf439f68ff
ifr_compare.py 47e10000295bb11e3d8b573f0d9831f8de1b24eb
verify_platform.py d7073ada76f10300a223347c01240fa554fb0cc7
raw_coverage.py d3d54850bd9118f34f7bcc888b990077d07debda

All original ROM contents and machine-specific generated reports stay private. No flashing, EFI variable writes, or hardware tests performed.

P2-64 follow-up: type63 APOB NV at 0x2BA000 size0x10000 is all FF in both vendor ROMs; live 1.24 APOB record accounts for all 41436 differing bytes in that region. Cache validity/selection and remaining B09 residuals open. See ROM_RESTORED_CHECKPOINT.md.

P2-70: two changed unmapped bytes localized to EFS page at 0x20000; known directory pointers exact, field semantics unresolved. See MAILBOX_UI_UMA_CHECKPOINT.md.

P2-71: the last unknown live-vendor APCB payload field (0x125) is Data Fabric token0x306, read/written as logical8 by unchanged PciRootBridge. See MMIO_BROWSER_SAVE_CHECKPOINT.md. No claim of physical RAM loss.
