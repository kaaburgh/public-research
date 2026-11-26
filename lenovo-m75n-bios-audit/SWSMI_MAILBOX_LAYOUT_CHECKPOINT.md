# S33 SwSmi534D0040 layout — 2026-11-26

P2-85/E80. Extracted 1.32 SHA256 0e18c4d19bfad1a5407d89c482c5dd7fb081bd36cc385a2e8806f7b870492491; 1.33 ed5b764e05245fcfc64f63d5ca41dd88ab45079964d36b9a0317f679e6b8a074. No firmware invocation.

Disassemble with objdump -d -M intel --no-show-raw-insn. Exclude INT3. Align normalized instructions using SequenceMatcher(autojunk=False), masking RIP displacement and direct branch targets; map equal blocks and same-length replace blocks, then verify targets and actual bytes. All 6523 old instructions map; 153 added instructions span 25F4–2844 (new mailbox handler, previously semantically analyzed P2-66). Old address deltas: 2126 unchanged, 4225 +254, 172 +250 (hex displacements). 495 mapped raw changes, zero changes with same decoded instruction and zero length mismatches. 1027 direct branches,454 RIP references and2 indexed references verified; three residual old instructions: two table bounds 6E0/7ED 0x35→0x36, LEA at 4319→456D remains target image base zero. No unexplained old instruction.

Data alignment by 80 monotonic anchors from RIP/indexed references and end; mask DIR64 values. Old first data anchor 6780 maps to new 69F0; new 69E0–69EF prefix is EFI global-variable GUID 8be4df61-93ca-11d2-aa0d-00e098032b8c. Five other edits: GUID cb394d2c-44a4-43ef-9dbe-c44104e5afbd inserted; one new dispatch record (4-byte descriptor and 8-byte handler pointer); four zero bytes deleted and eight inserted; UTF16 SetupMode, AuditMode, DeployedMode, LenovoMailBoxSecureBootModeVar and zeros inserted. All 92 old relocation slots and targets map bijectively; only extra relocation at 6CF0 points to added handler. No other nonzero edits.

PE size 32256→33088. .text VS 64DA→672A, raw64E0→6740; .data VS EF4→FB4, raw F00→FC0; unnamed VS 36C→378, raw380 unchanged, .xdata VS318→32C raw320→340, .reloc VS CC and raw E0 unchanged. All subsequent section positions and optional header sizes move accordingly. Unnamed and .xdata contents entirely zero; exception directory absent; debug directory bytes zero, RVA moves 7420→7740. All section raw padding zero. Relocation changes follow verified slots. 

Static closure only; does not imply safe runtime authorization or successful key operations. No raw SMI calls, no writes, no hardware test. 

P2-85/E80: full S33 SwSmi534D0040 attribution; 103 S24 + 2 S33 =105 pending, 42/44 S33 attributed. Remaining S33 SecureBootDXE and EsaFull.
