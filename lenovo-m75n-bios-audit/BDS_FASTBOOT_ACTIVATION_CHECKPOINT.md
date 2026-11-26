# BDS Fast Boot activation checkpoint (P2-120/E115)

Verified PE bodies from all three ROMs. Bds SHA256 124 ab589ebcd41cb46fabf0455f5eddcd8015cf9293d1c4c09817c8a92d96a76b24, 132 ecdef42f0d2cfc0e71f23f0b4b842aaf05e9064dd084ae422539fea3ea9191c6, 133 779b97df1b80bcb694cdfbf5a85cf2a36a4efebecb73c1cc06580496a1fc89ea. Static analysis only. 

## Distinguish the two UI questions
English IFR shows native Setup 0x61 Fast Boot (minimal devices needed for active boot option; no effect for BBS options), Q190→192, standard default1, manufacturing default0. Separate Setup 0x3C Fast Boot (last successful startup state to shorten POST), Q1AE→1B0, standard/manufacturing default1. The firmware protocol flag is driven by the first. FastBootRuntime 132=133 SHA256 3440a90500d6a5f7e4dd2e10e89687ea13b81718e0f530ac73426a28cfd9a271. At 13D0 initializes 0x49-byte protocol object at RVA21C0 and installs GUID 0302CB4F-AF05-4A16-99A9-31ADCF870890. 1617–1658 can reset Setup[61] based on OEM service output, 1680 reads Setup again, 1688–16A0 sets flag0 for value1 (or clears on failure/zero). 16EB records successful LastBoot read in +0F; 11C8 reads previous state and copies DWORD+4 to +10, sets +1C on successful option-init route; later 1742–17A2 can delete LastBoot and clear +0F. +47 zeroed during initialization (1367); external consumers not exhaustively checked. No assumption that it stays zero.

## BDS path
124→132/133: 38CC→38D0 locates protocol, requires nonzero flag0 and successful Setup read (446→449); invokes predicate table (single entry D278→D2F8). Predicate branches:
- If flag0 zero, false.
- Read PHIT BootMode via HOB list GUID 7739F24C-93D7-11D4-9A3A-0090273FC14D; absent HOB defaults to mode0.
- Mode 0x12 (flash update): calls cleanup D15C (old D0DC), deleting LastBootFailed if readable and LastBoot conditionally. Continues.
- Mode1 (minimal configuration): true.
- If protocol +1C=0, mode5 (S4 resume) and +0F nonzero: returns DWORD+10>0.
- Else read BootNext (size2, EFI global GUID); successful read returns false; failure returns current flag0. No assumption that all read failures mean absent.
Reference boot-mode constants: https://uefi.org/specs/PI/1.8/V1_Services_PEI.html .
Dispatcher AF28→AFB0 locates GUID 42544F90-B0C2-42F2-884D-2769AE6599C5, sets flag+48=1, invokes 21 pointers, stops on error, then cleanup table and clears +48 if execution returns. First function rejects successfully read nonzero BootFlow; entry 19 (zero-based) BA64→BAE4 calls D390→D410 only if +47 zero. D410 locates POST manager, installs helper protocol, requires successful BootFlow=7 write before calling method0, resets BootFlow=0 if it returns; returns EFI_ABORTED. FastBootOption EBS callback may execute while BootFlow=7; actual OS handoff path and other dispatch guards not established. 

## Comparison
Table 124 at C7C90, new C7D30. 21 entries and null terminator; exact new entries in both 132/133, all old pointers +80 except first +88, one repeated entry. The normalized initial instruction chunk (up to first INT3) of all 20 unique entries matches across all versions. Together with D278, D338, D390, AF28 matched 973 unique instruction addresses; 138 direct/RIP refs to mapped addresses agree, 167 refs outside map not fully resolved (no disagreement among mapped refs). Normalize RIP displacement and absolute direct branch/call operands only; this is not a full equivalence proof. Prior P2-74/97 conditions refined; actual dispatch and risk still conditional. No hardware changes. BDS PE pending, queue 87 unchanged.
