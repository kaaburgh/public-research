# Independent raw NVAR baseline — 2026-11-26

P2-104/E99, B05/B11. Verified owner-supplied 1.24 AFU against private manifest. UEFIExtract NE A75 extraction completed; independently decoded raw file bodies at ROM offsets 0x21090 and 0x41090, size 0x1FF70 each, verified identical to slices of source. No raw data, names, GUID values from live variables, payload hashes or device-specific identifiers published.

| Measurement | First store | Second store |
|---|---:|---:|
| All records | 979 | 835 |
| Valid entries | 870 | 741 |
| Valid named roots | 164 | 165 |
| Valid data-only entries | 706 | 576 |
| Valid links | 702 | 571 |
| Indexed GUID slots | 63 | 63 |
| FF gap before GUID table | 167 | 29332 |
| Bad links from valid entries | 0 | 0 |
| Valid named root chains with multiple terminal offsets | 0 | 0 |
| Detached valid data entries | 4 | 23 |
| Invalidated records directly pointing into detached chains | 4 | 5 |
| Detached entries reachable via those chains | 4 | 23 |

162 common resolved name/GUID keys; 143 terminal payloads equal, 19 differ; 2/3 keys unique to first/second. Detached records do not imply corruption: all are reachable via historical invalidated records. A75 offsets and exact header/payload bytes independently matched for all 1814 records after accounting for five extended headers per store (43 bytes each, not emitted as tail.bin). All three nested StdDefaults bodies separately decode to 13 named entries, 9 indexed GUIDs, 16 bytes FF gap, no links or ambiguity; all 39 match A75. No extended checksum flagged in these samples; no authentication verification.

## Reproduce

Use A75 and the owner-supplied 1.24 dump, never publish generated reports. Format cross-reference: bundled UEFITool A75 common/ksy/ami_nvar.ksy and common/nvramparser.cpp (19a4dab71f1f994cc2a26b6808e0249e0098c366).
1. Walk each raw NVAR body from offset zero while signature NVAR. Read little-endian size at +4 (2 bytes), next at +6 (3 bytes), attributes +9; advance exactly size. Require 10 < size <= remaining bytes.
2. Valid bit 0x80; data-only bit 0x08; local GUID bit 0x04, otherwise 1-byte index resolved at body_end - 16*(index+1); ASCII name bit 0x02, otherwise UTF-16LE NUL-terminated. For valid extended-header bit 0x10, read u16 tail length at record end-2 and exclude that tail from payload. Compare only full GUID/name keys. GUID table extent is 16*(max valid indexed GUID +1). Validate nonoverlap, uniform FF gap.
3. For each valid named root, follow next relative to record start until 0xFFFFFF; require target to exist and be valid data-only, no cycle; group terminal offsets by full key. Count detached data-only records and walk links from invalidated entries to account for them. Compare resolved payloads only by full key across stores.
4. Cross-check A75 direct child offsets (subtract outer FFS header size 24, nested record header size for StdDefaults), header bytes and payload bytes. A75 omits the extended tails from its extraction output here; do not call these mismatches.
5. FFS raw state bytes E0/F0; both FV attributes 0x4FEFF contain erase polarity bit 0x800. Complement state and take highest programmed bit, yielding 0x10 (EFI_FILE_DELETED), 0x08 (EFI_FILE_MARKED_FOR_UPDATE). Reference UEFITool common/ffs.h. This is generic FFS interpretation, not a proof of AMI's NVAR copy-selection or AFU capture semantics. Both FFS headers have valid checksums.

## Consequence

Both copies structurally readable but distinct; cannot treat them as interchangeable backups or decide which is active based on count, free space, FFS state, or physical order alone. Existing Setup-size migration findings remain conditional. To close B11 selection, trace NvramPei and NvramDxe discovery/ordering logic (including file-state tests) and compare with read-only EFI variable observations; later post-update readback separately. Never restore a raw variable store blindly.

Source access: local 1.24 verified; four library ROM entries and both ISO entries lacked authorized raw materialization; direct Lenovo download unavailable in runtime (DNS failure). No 1.32/1.33 re-analysis, no new inventory attribution, no firmware writes or hardware tests. Pending queue remains 92.
## Active-store selection follow-up (P2-105/E100)

Reconstructed the actual AMI decision instead of applying generic FFS highest-bit rules alone. Binary SHA256 (extracted firmware executables, not machine-specific data): NvramPei TE 0863f780cdb0de0dcc3963f5e92a3765e3dcb2c8f544f8ed859d98b86adbd6dd; NvramDxe PE 5a4f6526be7fedbeb2ad54995998e54f543a96797ac17356b84dbedfd994f957.

- PEI TE raw offset 2E6 retrieves two base addresses via GUID HOB lookup 13DA, fallback first FF021000, second FF041000, first size 0x20000. At 4C2–4D1 first base output is stack+28, second stack+18 (account for pushes). At 4DB–4F0 first passed ECX, second EDX.
- Helper 1122 checks _FVH, header length 0x48, ext-header offset and length; aligns ext offset+size to 8. Both live FVs have ext offset 0x60 and ext size 0x14, so relative file header 0x78. 116C adds 0x17 to header offset and base, reads FFS state byte, complements it, substitutes 0x20 on zero/error.
- 118B uses the following exact branch-equivalent logic (a,b normalized state; out_b indicates second structurally usable):
```python
def select(a,b):
    va = bool(a & 4 and not a & 0xe0)
    vb = bool(b & 4 and not b & 0xe0)
    if va and vb:
        if b & 0x10: return True,vb
        if a & 0x10: return False,vb
        if a & 8: return bool(b & 8),vb
    return va,vb
```
- Captured raw E0/F0 -> normalized 1F/0F; both usable by this predicate; first deleted bit set, second deleted bit clear. Return false, second usable true. Caller 4F6–50C swaps ESI to second, saves first at stack+24; 515 obtains header offset, 522 adds 0x18, 532 initializes selected descriptor. 6C2–6F6 publishes selected/other addresses and size/header offsets into GUID HOB. Thus the conditional static PEI selection for the actual dump is 0x41000, NVAR body 0x41090.
- DXE 7E90,7EEC,7F24 implement same FV offset, complemented state, and selection logic. 2DD0–2EB1 reads two headers via protocol, calls predicate and swaps descriptor pointers +48/+58 if first not chosen and second usable; reads selected source at 2EB1–2ECB. No direct hardware confirmation that this exact caller is exercised on the running target.
- Transcribed logic exercised in Python for seven raw state pairs E0/F0, F0/E0, F8/FF, FF/F8, F0/F8, F8/F0, FF/FF; observed (first chosen, second usable) respectively (False,True),(True,True),(True,False),(False,True),(False,True),(True,True),(False,False). This is model testing, not emulation.
- Selected-key comparison across both copies (sizes/equality only): Setup 446/446 unequal; AmdSetup 1343/1343 equal; BootOrder 18/20 unequal (9/10 entries); SecureBootSetup 7/7 equal; PK/KEK/db/dbx payloads equal. This confirms baseline selection matters for Setup and BootOrder, not evidence that either is lost by update.

Remaining: HOB address overrides, PEI callback and defaults paths, actual boot variable state, newer migration code and hardware readback. The 1.24 default-path selection is now statically explained; B05/B11 as a whole remain partial. No new S24/S33 attribution, no hardware or writes. This supersedes the earlier uncertainty about the ordinary 1.24 selection predicate in P2-104, not the uncertainty about actual runtime.
