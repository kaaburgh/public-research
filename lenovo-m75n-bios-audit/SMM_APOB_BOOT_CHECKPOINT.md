# SMM observability, APOB type mapping and boot-state verification — 2026-11-26

## Scope

Previous P2-57–59/E52–54 verified in Git at b6d5adfdcb3ceca5f6f2324b77367051644e2f01. Current container contains previous UMA/RNG tools and BD790i archives, not the three M75n ROMs. Official ISO URL DNS resolution failed again. B10 and binary residuals B04/B02/B03 cannot be re-disassembled. No new hardware or binary measurements. Work below is independent documentary corroboration and preparation of read-only tests; no pending section reclassified.

## P2-60 / E55 — direct AMD SMI counting

AMD [OSRR #56255 rev 3.03, July 2018, p.153](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/56255_OSRR.pdf), verified on rendered page, defines PMCx02B (LsSmiRx) for family 17h models 00h–2Fh, including Picasso model 18h. Unit mask bits are reserved. This is a programmable PMU event, not Intel's MSR 0x34. Do not write MSRs or issue SMIs. Use the kernel perf interface on the physical machine, after confirming CPU identity and CPU PMU event format.

```sh
umask 077
lscpu
grep -m1 '^microcode' /proc/cpuinfo
sudo perf stat -a -A -I 1000 -e cpu/event=0x2b,umask=0/ -- sleep 60
```

Capture stderr to a private file for each run. Repeat at least three times in comparable idle conditions, then under an unchanged representative workload (separate runs). Keep per-CPU counts and time-enabled/running information; reject unsupported, not-counted or substantially multiplexed samples. An SMI may reach several logical CPUs; do not treat their sum as unique platform interrupts. A zero is meaningful only if the event was successfully scheduled and applicable; confirm on target. Does not measure time in SMM or identify handler. [Linux hardware latency detector](https://docs.kernel.org/trace/hwlat_detector.html) can complement it by sampling interruption gaps with interrupts disabled. Use only in a maintenance window; it consumes CPU and perturbs latency. Equal SMI counts plus larger gaps is a reason to investigate duration, not proof of SMM causality. No target test executed: container family 25 model 17 and perf executable absent.

For P2-32–34, keep separate (1) idle periodic SMI rate, (2) representative workload, (3) bounded ordinary read-only EFI variable observations if desired. [efivarfs](https://docs.kernel.org/filesystems/efivarfs.html) exposes UEFI variables; firmware can implement runtime services through a different SMM path from legacy SW SMI. Do not infer specific handler from timing alone. No raw SMI invocation or firmware write. B03 static residuals stay open.

## P2-61 / E56 — type 0x63 APOB NV

[coreboot PSP integration guide](https://doc.coreboot.org/soc/amd/psp_integration.html), BIOS Directory Table Entry Types, identifies 0x61 as APOB location, 0x62 as BIOS reset image and 0x63 as APOB nonvolatile copy; ABL can replay the latter for S3 and some S5 boots. An [AMD-authored Vangogh EDK2 reference patch](https://patchew.org/EDK2/20240126060050.1725-1-duke.zhai%40amd.com/20240126060050.1725-5-duke.zhai%40amd.com/) independently defines APOB_NV_COPY = 0x63 (indexed excerpt; direct fetch failed; different platform). This resolves the generic entry-type ambiguity, not actual payload semantics on M75n. Prior PLATFORM_REPRODUCTION.md reports equal directory metadata and 41,436 differing bytes tagged type63 in live 1.24 vs factory 1.33, out of 5,590,595 total changed byte positions. It is consistent with live-state difference; must still inspect actual headers, length, valid/erased state, copies and runtime selection, including 1.32/1.33 comparison. Do not simply subtract these bytes and call the remainder code. Two unmapped bytes 0x20043/44 remain open; embedded raw PE and contained FV changes likewise. B09 remains partial.

## P2-62 / E57 — B02/B05 boot inventory

P2-31 describes FastBootOption's change from scanning free IDs starting at 1 to max existing BootOrder ID +1 and three synthetic options. The [UEFI Boot Manager specification](https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html) defines BootOrder as ordering of references, not a guaranteed exhaustive enumeration of Boot#### variables. [Device Path Protocol](https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html) defines BBS node type 5/subtype 1 for legacy boot; an option's label alone does not establish actual native UEFI boot. A hypothetical BootOrder=(0001,0003) with existing but unlisted Boot0004 would make 0004 a candidate for collision under the reconstructed allocation rule. This does NOT establish overwrite, existence of such state on M75n or that the old algorithm is collision-free; exact full allocator, BootFlow=7 dispatch and SetVariable error handling need binary follow-up. No attempt to construct such a state on hardware.

New `tools/boot_inventory.py`, SHA256 3edc0d3ccb334068cbc137ba79651f1699b49da0a3486204a12ea1d627962f91, blob 6a64763c5893691a2e040e212df272b10f1125c8. Tested locally with `python3 tools/boot_inventory.py self-test` (9 synthetic checks) and `python3 -m py_compile`. Reads only selected global efivarfs boot variables. Parses variable attributes, load-option structure and bounded device-path node framing (not full semantic validation); accepts multiple End Entire paths. Reports unlisted options, missing references, duplicate IDs, max order ID, BBS node presence, payload hashes and read/parse errors, not raw descriptions/device paths/payload. Keep output private (IDs and hashes can still be identifying).

```sh
umask 077
sudo python3 tools/boot_inventory.py capture > boot-124.json
# after official update and before changing settings, if Linux boots:
sudo python3 tools/boot_inventory.py capture > boot-133.json
python3 tools/boot_inventory.py compare boot-124.json boot-133.json
```

Record normal boot settings and efibootmgr output privately, capture only in stable state; runtime snapshot is non-atomic, sees only OS-visible variables and does not select active physical NVAR store. Unknown/read failures are not classified as removals. A changed hash may be normal BDS maintenance; compare order, names and actual boot behavior, not hashes alone. No target log available, no update performed. B02/B05 remain partial.

## Status

38/44 S33 attributed, 6 partial. 168 S24 + 6 S33 = 174 pending. All three findings complement existing conclusions. Next binary work remains B10 then B04/B02/B03, dependent on verified ROMs; B12 now has SMI rate and boot inventory protocols as well as prior PCR1/UMA/RNG controls. No hardware changes or extra flash steps recommended.
