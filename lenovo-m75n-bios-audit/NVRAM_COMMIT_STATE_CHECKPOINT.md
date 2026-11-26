# NVRAM migration commit / dual-bank checkpoint (P2-124/E119)

Extracted and verified NvramDxe PE hashes as in NVRAM_VARIABLE_CONTRACT_CHECKPOINT.md. Follow-up to P2-105–107. No flash writes.

## Backend identification

132 6F75–7001 copies nine function pointers from table E6D0 to F3A0 and installs flash interface at +60. Descriptor +40 uses that table when flash flag is set (7045–7058). RAM-only table D3A0 is separate. Active descriptor selected by initialization; P2-107's migration 5388 uses active store, prepares scratch, copies permitted names, then 52D0 commits via +20/+28. Table slots map 124 E610 →132 E6D0→133 E6E0; ordered target list 132: 29EC, 2A24, 2A3C, 2AF8, 4F9C, 518C, 2B7C, 2CEC, 2DD0. 124 differs only prepare/finalize addresses 4D5C/4F4C; same normalized bodies.

## State transitions and conditional failure

52D0 invokes backend +20; if error returns immediately. On success initializes descriptor and copies scratch variables (4CE8). Invokes +28 with abort flag derived from copy status. On finalize failure attempts abort callback. Prepare 4F9C checks header with 4F2C; on valid header and dual bank, swaps +48/+58, modifies buffered FFS state to FC at 50A8–50DE, erases/programs target prefix (511D/5138); erases data range and reconstructs records through copy. Finalize 518C success path first retires old bank (51DA mask1C applied by 4ED4 and programmed 524A), then clears new header's 0C bits (5268, 5296). Under assumed intact initial active F0 and alternate E0, this gives new FC before copy, old E0 after retire, new F0 after commit. The state selector 81A4 treats DATA_VALID bit set and no E0 bits in complemented state as a selectable store; DELETED alone does not exclude a sole valid bank, but resolves priority when both valid. Therefore old E0 can still be selected with new FC or F4; new F8 or F0 preferred once valid. This is *state-only*, assumes old data intact, valid FV headers, successful writes in order, not protection against arbitrary power failure/corruption.

Run tools/nvram_commit_state.py: 16/16 stage/order cases pass (two bank positions and eight stage states including two partial commit-bit orderings). Prepare error after pointer swap can return before rollback; finalize abort at 51B5–51CC swaps pointers and updates offset but no demonstrated full cache reload there. 1E70 migration result ignored at 1E75. These are conditional error concerns, not observed failures, and underlying machinery is pre-existing. Do not deliberately interrupt power on owner device.

## Scoped mapping evidence

Split code pieces and normalize direct targets/RIP references as before, match ordered pieces and check known target correspondences. 18 pieces / 1130 instructions match both adjacent comparisons. 254 direct/RIP refs per pair; 230 with target in code map agree, 24 outside map unresolved. 132 start RVAs: 4ED4,4F2C,4F9C,518C,52D0,5388,4CE8,697C,28C8,2DD0,8110,816C,81A4,27DC,29EC,2A24,2A3C,2AF8. This is scoped logic attribution, not whole-PE closure or a physical write test. Queue unchanged at 87.
