# ROM access restored — Setup alias and APOB NV closure (2026-11-26)

All three inputs now readable. SHA256 matches the previous private/public manifests. Extracted all sections using owner-supplied UEFIExtract NE A75, offline. No flash or device writes. This checkpoint supersedes the previous session's source-access blocker; future sessions still require the owner to supply the images or authorize materialization.

## P2-63 / E58 — B10 Setup alias resolved

Setup 1.32/1.33 PE hashes: 38c9280cd35ca36ed10345a387915e2f7b75626686ca72b4da92dd00804bfbc8 / 2e502dc0717beeebcf17d9a3a3097e867ccef72fbf6061a013ac44258c1b9426. Read PE section table, .rsrc raw offset 0x110e80/0x110f60, HII list at +0x60. Parse list length at +16 and each 24-bit package length/type. Forms 40062 bytes hash a77bc97803bde38cc49c762f10a8194e9532cb83ce4c843c8d12c53e378d4310 identical, four ordinary language packages identical, END identical. x-UEFI-AMI package 11157→11187 bytes. Parse StringInfoOffset at +8, UCS2 0x14, skip 0x21/0x22, END; only decoded string ID2057 (0x809) changes from absent to LemPower000L. UTF16 literal at 1.33 raw file 0x1715A7, no other extracted PE32 contains this exact string. Form package offset0x6675: ONE_OF prompt ID0x809, help0x80A, QID0x14D, varstore1, offset8. Other raw byte pattern at 0x6A30 crosses prompt/help field boundary, not a reference. ifrextract-rs 1.6.1 confirms Form0x28A1 Intelligent Cooling, Performance Mode, values 1 Performance (standard/manufacturing default), 0 Balance, 2 Full speed. Same form in both releases. P2-51 earlier resolved code, data and relocations; close only S33 Setup PE32. The new internal alias could affect management enumeration; no claim of exact consumer or runtime behavior. No new fan policy or visible menu option. S24 Setup remains open.

## P2-64 / E59 — B09 APOB region verified

Read raw $BL2 (offset0x289000), entry27 with stride24, type0x63, address mapped to file offset0x2BA000, size0x10000 in all three. 1.32 and 1.33 region all FF (SHA256 71189f7fb6aed638640078fba3a35fda6c39c8962e74dcc75935aac948da9063). Live 1.24 begins APOB and has a size-like header word 0xA3A4 at +8, last non-FF at 0xA3A3, 23644 trailing FF. Count non-FF: 41436, exactly the prior type63 raw diff count. This confirms a live-vs-factory state delta, not 1.32→1.33 executable change. Header field semantics and validity not fully proven; no private payload/hash exported. Actual updater preservation, retraining/cache selection remain open. B09 remains partial for two unmapped changed bytes (0x20043/44), embedded raw PE and contained differences. No flash.

## P2-65 / E60 — thermal-code independent recheck

Extract ThermalMode PE and ThermalModePei TE from each image. Both 32=33 exact; DEPEX all three exact. PE 6304 bytes, 22 raw diffs exclusively .text, disassembly confirms Setup size and stack changes (two frames). TE 3232 bytes, stripped delta0x180. Apply HIGHLOW relocation normalization at six file offsets 0x17E/513/53F/544/BD4/BD8 and clear ImageBase. Exactly 12 remaining bytes at 0x4EA/52A/531/55D/568/576/593/5AF/606/651/6C1/70C. Disassemble x86 at file offsets (objdump -D -b binary -m i386 -M intel); frame and buffer 0x1D4→0x1D8, size446→449. Effective field offsets 0x93 and 0x08 identical. Independently confirms existing P2-01/02, not a new closure. No fan algorithm difference identified in these modules. Actual settings, noise/idle/temperature remain B12.

## Status

39/44 S33 attributed, 5 partial (EsaFull and four mailbox-related modules). 168 S24 + 5 S33 = 173 pending. Next B10 exact mailbox behavior and EsaFull changed GUI paths; then B04/B02/B03. No actual hardware update or performance measurements.
