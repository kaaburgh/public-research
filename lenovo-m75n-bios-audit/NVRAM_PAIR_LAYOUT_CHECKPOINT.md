# NVRAM pair layout — 2026-11-26

P2-84/E79. Compare extracted 1.32 and 1.33 PE32+ bodies only, verified input ROMs. No firmware invocation or hardware test.

| Module | SHA256 1.32 | SHA256 1.33 |
|---|---|---|
| NvramDxe | 3d1c9932757acca64c618655590400ca9262dccf14295c768ead174af4dcb477 | cdcd515950c8065ac4981a1524cb558a2ecf4889f6f1fd8e25dbfca35f2393b8 |
| NvramSmm | dc39c4f9fddbe76eeb34b8879b2bfb8d24c9278eaa0bc49c8ad2edfaa8f03bea | 7f4e1d2d8084e6e434f51ffe2817063f261a711949899ae8cf171d27d8a60fd0 |

All addresses below hexadecimal RVAs.

| Metric | DXE | SMM |
|---|---:|---:|
| Old/new non-INT3 instructions | 12255/12272 | 12103/12120 |
| Old mapped instructions with raw changes | 771 | 711 |
| Direct branches mapped | 2392 | 2435 |
| RIP references mapped | 833 | 701 |
| Indexed references mapped | 3 | 3 |
| Monotonic data anchors | 259 | 236 |
| Old/new DIR64 | 131/132 | 140/141 |
| Old slots/targets verified | 131 | 140 |
| Unmatched old instruction groups | 3 (explained) | 3 (explained) |

Old instruction map: DXE k < C3D0 unchanged, otherwise k+50; SMM k < B2D0 unchanged, otherwise k+40. Exclude INT3 padding. Compare objdump -d -M intel --no-show-raw-insn, and raw instruction spans using next decoded address. Same decoded instructions have identical raw encodings; all mapped instruction lengths equal. Map direct targets, RIP data targets and the three indexed .data references. New 17 nonpadding instructions at C3D0/B2C8 constitute mailbox-read predicate. Remaining three old instruction changes in DXE A01A/C20F/C219 and SMM 928A/B107/B111: first references new predicate list head instead of old first predicate; latter two are EFI_TIME constants (2025-11-11 16:49:50 → 2026-05-15 15:31:59). Prior predicate logic retained (P2-52/67).

Data: parse PE sections and DIR64 slots; gather monotonic anchors from RIP/indexed targets and section boundaries. Mask 8-byte relocation values and align bytes between adjacent anchors with SequenceMatcher(autojunk=False). Five edits each: inserted GUID cb394d2c-44a4-43ef-9dbe-c44104e5afbd (DXE D100, SMM B5F0), inserted predicate pointer, inserted UTF16 LenovoMailBoxSecureBootModeVar and padding, plus two zero-only padding adjustments. Old list EA80 / CF60 first two pointer slots map to EA98/EAA0 / CFB8/CFC0. New list heads EA90 / CFB0 contain added pointer C3D0 / B2C8. The first anchor maps the list boundary, not the old first pointer; explicitly map the old slots by identity. All old relocations map bijectively and point to mapped code/data targets. Exactly one extra slot per module. No other nonzero masked-data edits.

Header: DXE raw size 62464 unchanged; four header bytes differ (178 debug RVA EE10→EE60, 1D0 .text VS B530→B580, 1F8 .data VS 27B8→27F8, 220 unnamed VS 78C→798). SMM 60384→60544, SizeOfCode +40, initialized data +60, SizeOfImage +A0; .text VS B22A→B26A and raw +40, .data VS/raw 27E0→2840; following section RVAs/raw starts move accordingly. Unnamed VS 72C→738, .reloc VS 134→138. Both unnamed and .xdata section raw bytes all zero and identical; no exception directory present (do not interpret these as populated unwind tables). Debug directories all zero, relocated header RVA only. All raw padding after virtual sizes zero. All section-header changes account for section sizes/placement, all relocation changes follow the verified slot map.

Conclusion: both S33 PE rows fully attributed. The new predicate is presence/read-status only, not consumer verification or an assertion about authorization. Static attribution does not establish runtime safety, and S24 versions remain independently partial. No SMI calls, NVRAM writes, or updates executed.

P2-84/E79: full 1.32→1.33 layout/relocation attribution of NvramDxe and NvramSmm; 2 S33 closures. 103 S24 + 3 S33 =106 pending; 41/44 S33 attributed. Actual hardware and mailbox authorization behavior remain open.
