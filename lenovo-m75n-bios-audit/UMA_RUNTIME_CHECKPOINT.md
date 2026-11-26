# UMA state model and hardware regression controls — 2026-11-26

## Scope and input availability
B10 remains the highest binary priority: Setup HII identifier, EsaFull and four mailbox modules. The ROMs are not present in the current container. Library materialization of the 1.33 ROM and two prior validation artifacts returned “This Project file does not have an authorized raw-byte materialization path.” Official Lenovo USB-package retrieval was attempted; curl failed DNS resolution, web open could not access ZIP/EXE bytes, and container download rejected the unviewable URL. The available BD790i acquisition archive contains unrelated firmware. No new binary diff or closure is claimed. B02/B03 also require actual executable sections. Official 1.32/1.33 USB packages are listed by Lenovo DS544268 as a compact alternative to the ISO; use owner-supplied verified images. Do not publish private ROMs or device captures.

## P2-57 / E52 — B04 conditional synchronization model

Re-express P2-24/25/43 as an explicitly limited state machine: native Setup[0x1A3] N, AmdSetup[D4] A, APCB UMA size P. Assume the browser saves the full native N and the callback stores A=N&0xff. At OememDxe notification, if recovery guard applies, delivery is absent, or N=A, return with no correction. Otherwise persist A=N first, then attempt APCB update and reset. Under the stated assumptions, if the APCB write fails after NVRAM persistence, the next invocation sees N=A and can skip repair even while P differs. Conversely low-byte-safe values 64/80/96/128 need no width correction, but if browser routing did not write APCB, the secondary path can skip an otherwise necessary write. The other eleven values enter the mismatch branch (384 becomes 128, Auto becomes 255, all other explicit >=256 become 0). The model checks all 15x15 requested-size/old-APCB-size cases with success, post-NVRAM failure and guard/delivery paths; it is not independent disassembly or proof that these abstract states occur on hardware. Mode-only mismatches remain outside the size gate. Do not deliberately induce failures. Native browser dispatch, ordinary CBS RouteConfig and runtime hardware behavior stay open.

## P2-58 / E53 — Linux test, independent of firmware source bytes

Kernel [amdgpu memory sysfs documentation](https://docs.kernel.org/gpu/amdgpu/driver-misc.html) distinguishes driver-visible VRAM, CPU-visible VRAM and GTT, all reported in bytes. [amdgpu_vram_mgr.c](https://kernel.googlesource.com/pub/scm/linux/kernel/git/next/linux-next/%2B/3271faf42d135bcf569c3ff6af55c21858eec212/drivers/gpu/drm/amd/amdgpu/amdgpu_vram_mgr.c) reports real_vram_size for total VRAM; [module parameters](https://docs.kernel.org/gpu/amdgpu/module-parameters.html) can restrict VRAM/GTT for testing, so driver counters alone do not prove physical RAM was freed. Upstream [display discussion](https://lists.openwall.net/linux-kernel/2025/07/22/932) distinguishes Raven2/Picasso from earlier APU display pinning restrictions; [PCI driver mapping](https://gbmc.googlesource.com/linux/%2B/c1ed18c11bdb80eced208a61d40b1988f36a014f/drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c) classifies 1002:15d8 as Raven-family APU. This is architectural context, not a guarantee for 128 MiB on the target kernel.

New `tools/uma_audit.py`: SHA256 aaba0d5ce548b99d3bf335c85721843bcc9e41cf05888db0ccbeb7465a0a58fc, Git blob 1ed289ae7cf721bebc5503ee4a08c11927730665. `python3 tools/uma_audit.py self-test` passed nine capture/comparison assertions and 225 conditional model cases; py_compile and container capture passed (container had no AMD GPU, not an M75n measurement). Only read-only files, no raw NVRAM, no device serials. Keep actual captures private.

```sh
umask 077
sudo python3 tools/uma_audit.py capture > 124-baseline.json
# After official upgrade, before changing UMA, with same kernel/settings:
sudo python3 tools/uma_audit.py capture > 133-baseline.json
python3 tools/uma_audit.py compare 124-baseline.json 133-baseline.json
# Only after stable boot, local console/display and recovery access:
# Change UMA in native menu to 128 MiB, normal Save & Exit; no direct EFI writes.
sudo python3 tools/uma_audit.py capture > 133-128.json
python3 tools/uma_audit.py compare 133-baseline.json 133-128.json
```

Capture again after cold boot (keep separate files). For a starting VRAM allocation of 2048 MiB, a change to 128 MiB would imply a gain of approximately 1920 MiB system RAM if all else is equal. Confirm with e820/sysfs firmware map when available and actual GPU workloads/display; GTT limits can change with available system RAM. Retain actual configured UMA mode/size from menu separately; driver/sysfs counter does not prove APCB selection or persistence. Script comparison uses MemTotal and VRAM with a heuristic 64 MiB tolerance, reports firmware System RAM delta separately and returns null for unavailable map/counters, and filters only relevant command-line flags (not all possible confounders). Use root to read module parameters, review unknowns. Do not set vramlimit to simulate physical reclamation. Same-kernel A/B and local console are prerequisites, not guarantees. No flash or settings change executed.

## P2-59 / E54 — B12 RNG smoke test

An indexed [Dell community report](https://www.dell.com/community/en/conversations/vostro/vostro-3515-ryzen-7-3700u-bios-138139-break-rdrandrdseed-131-and-1361-work-regression-traced-to-amd-psp-firmware/6b072832d46bb6e1a8cb867d) dated 2026-11-25 alleges RDRAND/RDSEED regression on Ryzen 7 3700U Picasso with microcode 0810810E after Vostro 3515 BIOS 1.38/1.39; direct page fetch failed, so this is only a lead, not verified diagnosis. Existing M75n PLATFORM_REPRODUCTION.md records equal mapped PSP payload hashes, reducing support for the same mechanism, not proving equivalence of runtime behavior. Linux [kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html) document RDRAND workarounds for buggy BIOS. No specific Lenovo CVE or regression inferred.

New `tools/rng_smoke.c`: SHA256 90ffeebcaa76ef4c357b48893b44bfa489d77af6460044113189a90318daf01c, Git blob 73449aa7adefb2a488f142663081d054e5e9ad6b. On x86-64 Linux with GCC-compatible compiler:
```sh
cc -std=c11 -O2 -Wall -Wextra -Werror tools/rng_smoke.c -o /tmp/m75n-rng-smoke
/tmp/m75n-rng-smoke
grep -m1 '^microcode' /proc/cpuinfo
grep -m1 '^flags' /proc/cpuinfo
sudo dmesg | grep -Ei 'rdrand|rdseed|microcode'
```

Run before/after identical settings. CPUID-gated, target-specific intrinsics, six instruction/width combinations, 4096 bounded attempts per combination; count successful calls, carry clear, zero, all ones and adjacent equal successes. No random output or state changes. Compilation and run passed on container CPU: 4096 successful calls per combination, all counters zero. That is not M75n data. A carry-clear is a legitimate transient failure (especially RDSEED); occasional zero, all-ones, or equal 16-bit values are not diagnostic. Persistent failures or constant values warrant investigation; test is not entropy validation. If a CPUID-advertised instruction traps, record the process failure; do not bypass CPUID or kernel controls. Include this with earlier PCR1 validation and existing B12 controls.

## Status
No new binary section attributed, 38/44 S33 still attributed; 168 S24 + 6 S33 = 174 pending. B04 conditional model and measurement protocol added, B12 now has two further read-only controls. B10, then native browser routing and OEM/SMM remain blocked on source bytes. No physical device modified. No actual timing or performance change established.
