# NVRAM variable API / SMM communication checkpoint (P2-122–123)

Scope: extracted PE from the three verified firmware images, no hardware execution. SHA-256:

| Module | 1.24 | 1.32 | 1.33 |
|---|---|---|---|
| NvramDxe | 5a4f6526be7fedbeb2ad54995998e54f543a96797ac17356b84dbedfd994f957 | 3d1c9932757acca64c618655590400ca9262dccf14295c768ead174af4dcb477 | cdcd515950c8065ac4981a1524cb558a2ecf4889f6f1fd8e25dbfca35f2393b8 |
| NvramSmm | cc9b2b452796464b304e1f752d7833b3a9474bff45ef86b7f1518b73a3571c6d | dc39c4f9fddbe76eeb34b8879b2bfb8d24c9278eaa0bc49c8ad2edfaa8f03bea | 7f4e1d2d8084e6e434f51ffe2817063f261a711949899ae8cf171d27d8a60fd0 |

## Policy and read semantics
1.24→1.32 new validator DXE RVA 4638, SMM 30B4 (156 instructions each); called from the pre-existing write policy 5974/43F0 after the EFI global GUID check. Decoded UTF16 names Timeout, PlatformLang, PlatformLangCodes. Timeout requires exactly two bytes. PlatformLang requires at least three bytes, final NUL and no earlier NUL. If a lookup of PlatformLangCodes returns BUFFER_TOO_SMALL, allocates and reads the list and validates match/length/separator. Earlier return or error branches exist; this is not a claim of rigorous validation of every code nor a ban on all writes. Delete path is separate. Other policy gates are present.

SecureBootSetup fixed-length read in DXE 9E4C (1.24) / A0CC (1.32), SMM 8D2C / 933C: initially passes 7 bytes, same variable GUID/name, static destination initialized with seven bytes. 1.24 on BUFFER_TOO_SMALL retries with same destination and returned capacity. 1.32 removes retry. Scoped correction of old unsafe capacity contract, not change of SecureBootSetup format. GetVariable wrapper 5608→5848 / 4084→42C4 guards null record pointer before reading attributes; new attribute helper uses same header flag bits with narrower access.

## SMM communication
1.24 5FC0 → 1.32 661C. Same initial external range validator and alignment adjustment, same seven dispatch IDs; new per-operation handlers. GetVariable 6254: copies fixed 0x30-byte header; verifies even name size, capacity and terminating NUL; copies name into local allocation and invokes lower-level read. 631B updates returned size; data buffer remains external. GetNextVariableName 634C: copies 0x20 header, local name buffer, then calls 510C (old 4E70, same normalized underlying enumeration). If success, copies returned name via 7778 and GUID, and always copies returned size at 642B including BUFFER_TOO_SMALL. Copy helper returns status but caller does not propagate it. SetVariable 644C: header copy, local name and separate data allocations, invokes CD8 with copied inputs, frees on normal completion. Name-based operation 6570: copied name and GUID. New allocation helper 8354→8324 uses SMM pool; release at 8394. Several early exits after local allocation skip release; possible resource retention on error, not evidence of routine workload leak. Some output fields remain external; not complete security assessment.

Reproduction: objdump -d -M intel --no-show-raw-insn on extracted modules; resolve RIP references via PE section RVA→file offset (NvramDxe has distinct raw/VMA); split functions at direct call targets, relocation targets and INT3; compare normalized instruction sequences, retaining operands except relocated RIP and direct branch targets. 1.24→1.32 piece count DXE 197→198, SMM 196→204. 1.32→1.33 comparison shows unchanged normalized new functions above; known mailbox-specific changes P2-84 remain separate. Not all modified pieces/relocations attributed. 

No live firmware writes or malformed requests. No conclusion of ordinary efivarfs incompatibility. Remaining: scratch-store commit and other error paths, all residual mappings. Queue 87 unchanged.
