# CPU and FastBoot risk checkpoint

Static comparison M33KT24A to M33KT33A, 2026-11-26. All five modules identical between 1.32 and 1.33. Source ROMs provided externally; no hardware execution. Addresses below are RVA (PE image base 0), except explicit TE file offsets. Reproduce by extracting named FFS PE32/TE bodies with A75, verify hashes against inventory, use `objdump -d -M intel --no-show-raw-insn` for PE and `instruction_diff.py`/TE section map for x86 TE. Compare actual section bytes and source/target operands, not just similarity.

## P2-27 — Stibp / CPU mitigations

Изменение только размера Setup

PE32 2208B, 2 raw changed bytes; единственное изменение инструкции RVA 0x392: GetVariable size 0x1BE→0x1C1. CPUID filters, MSR 0xC001102E read/OR 0x14008000/write at 0x320–0x33D and 0x4B8–0x4D3 unchanged. Setup 0x160 availability and 0x161 STIBP Status; StdDefaults both 0 in all checked releases, status Disabled. DEPEX unchanged; 1.32=1.33.

**Risk and limitations:** Нет нового алгоритма STIBP; успешность чтения Setup зависит от миграции, Linux policies/microcode independent. Не выводить фактическое состояние mitigations из IFR.

## P2-28 — CpuPei — CPU policy

Все 12 нормализованных изменённых байтов объяснены

TE 8128B, x86, stripped delta 0x1A0; 57 raw diffs→12 after HIGHLOW/ImageBase normalization. RVA 0x1929 stack 0x1C8→0x1CC, 0x1953 buffer base -0x1C8→-0x1CC, 0x1959 size 0x1BE→0x1C1; 0x197D–0x19AA field loads offset -4, 0x19AD base -4. Effective Setup offsets 0x157–0x15E unchanged. Defaults 01 00 00 00 01 01 01 01 in both 124/133: PSS enabled, startup P-state/PPC=0, SVM/NX/C6/CPB enabled; 0x159 unnamed. DEPEX and 1.32/1.33 payload identical.

**Risk and limitations:** Не найдено изменения CPU policy в этом модуле. Runtime зависит от actual configuration and microcode. 32-bit disassembly of embedded mixed mode code not used as proof; full normalized diff attributed.

## P2-29 — CpuDxe — CPU policy

Изменения объяснены по машинному коду и секциям

PE32 34400→34432; .text virtual 0x633A unchanged, 7140 objdump rows each (incl .rodata/padding), 64 different: 54 RIP references (42 +8, 12 +16), 7 Setup/stack, 3 register allocation. RVA 0x149E size; Setup static buffer 0x7CA0 expands past previous end 0x7E5E→0x7E61. Global targets 0x7E60–0x7E98→+8 and 0x7EA0–0x7EB8→+16, one-to-one references. 0x182B/1835/183B equivalent byte store [pointer+0x18] from global 0x72C1. 0x53B8–0x5480 stack 0x1F0→0x200; effective field offsets 0x157–0x15E same. .data raw prefix exact +32 zero pad, virtual +16; .rodata, unnamed section, .xdata, .reloc bytes exact at respective section offsets. Exception directory absent; no new unwind behavior established. DEPEX and 32/33 exact.

**Risk and limitations:** No newly changed MSR/CPUID/control-register operations in compared code. B01 static closed for three named modules; runtime and microcode A/B remain open. PE section headers shift, no claim of full platform equivalence.

## P2-30 — FastBootRuntime

Размер Setup и буферы; новых условий не обнаружено

5632B, exactly 30 raw changed bytes all .text. RVA 0x13DC/13E4 stack 0x620→0x640; 0x13FB Setup length. 0x14BF RomHoleReplaceOA2Var size expression old 0x1BE+0x1A = new 0x1C1+0x17 = 0x1D8. Buffer 0x180→0x190, relative field +0xFA unchanged; Setup fastboot field +0x61 unchanged at 0x161F/163F and 0x1688. Remaining stack offsets +0x10/+0x20 and epilogue; .data and other sections exact; 1.32=1.33. StdDefaults 0x3C/0x61 both 1.

**Risk and limitations:** Нет признаков новой fast boot runtime policy. Config migration and actual boot/LastBoot variables not tested.

## P2-31 — FastBootOption

Переработано создание Boot#### и BootOrder

6272→6432 B, .text 0xDF0→0xEA0; function 0x2F4, same trigger callback reads BootFlow=7 (old 0x795/new 0x849), protocol guard. EFI_GLOBAL_VARIABLE at old 0x1080/new 0x1120, BootOrder old 0x15D8/new 0x1678. Old 0x4EF copies BootOrder into stack [rsp+0x50], scans free number from 1 at 0x52F–0x568; new 0x50A allocates BootOrder size+6 via AllocatePool, copy 0x56A, 0x590–0x5CC selects max existing ID (initial min1)+1, appends 3 entries and writes at 0x785. Same BBS-type 5/0x81–83 synthetic labels UEFI:CD/DVD Drive, Removable Device, Network Device. New code frees original buffer and temporary allocation. Some allocation/read error paths 0x38A/0x3BB→0x4F4 return success, SetVariable statuses not checked in loop. Existing description scan lacks explicit length bound; no full semantic closure. 1.32=1.33. 

**Risk and limitations:** Likely improvement for long BootOrder (old fixed stack copy replaced); new max+1 strategy risks wrap for extreme IDs and collision with unlisted Boot#### (not proved exclusive to new version). Ordinary boot trigger not demonstrated; no direct deletion of existing normal boot entries observed in inspected path. B02 remains partial: OEM init and error handling/trigger semantics.

For FastBootOption, old fixed stack copy and new AllocatePool(size+6) are a specific changed path, not proof of full robustness. Synthetic Boot options are BBS-shaped even though descriptions say UEFI; do not infer actual boot behavior from labels. New max+1 wraps at UINT16 limit, but applicability requires appropriate BootFlow and existing state. No evidence of ordinary boot regression. All source-specific private NVAR values omitted.
