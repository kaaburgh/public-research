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
