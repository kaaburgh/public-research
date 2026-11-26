# Vendor corroboration and measured-boot verification (2026-11-26)

## P2-55 / E50: documented remote factory-key reset

Lenovo [HT518672](https://support.lenovo.com/sa/en/solutions/ht518672) lists ThinkCentre M75n with **M33KT33A** as the minimum release for remote factory-key restoration via SRWINx64; WMI is explicitly not supported. The [English solution](https://support.lenovo.com/ng/en/solutions/ht518672) describes separate SRWIN and WMI interfaces and warns that restoring factory keys removes custom Secure Boot certificates. [HT518129](https://support.lenovo.com/gb/en/solutions/HT518129) lists M33KT32A for the 2011→2023 certificate transition. The [download page](https://support.lenovo.com/de/de/downloads/ds544268) identifies 1.32 as December 15, 2025 and 1.33 as June 16, 2026. The relevant indexed excerpts were retrieved November 26, 2026; some direct page fetches failed, so claims are limited to the visible excerpts.

Independent corroboration of the prior ISO changelog (P1-24). Together with P2-47 (identical factory certificate-list payloads), P2-49 (new request producer), P2-52 (guarded consumer and NVRAM predicates), the evidence strongly supports the interpretation of the 1.33 mailbox as the explicit administrative key-reset feature. It does not establish the exact call chain from SRWINx64 or prove enforcement of authorization, failure handling, or absence of other callers. Do not run SRWIN or send raw requests for validation. WMI is not the appropriate target for this model. The next offline step is to acquire official SRWINx64 and follow the documented interface to its firmware request path, checking SVP/no-SVP and reset behavior without executing it.

The upgrade and a later explicit Restore Factory Keys are distinct operations. Do not restore keys merely to test the update. Existing custom keys may be lost by the explicit restore, and ordinary 1.24→1.33 Setup migration remains a separate risk even when no mailbox exists. No evidence here changes the actual firmware section closure status.

## P2-56 / E51: PCR1 validation prepared

The [TCG PC Client PFP](https://www.trustedcomputinggroup.org/resources/documents/pc-client-specific-platform-firmware-profile-specification) specifies measurement of boot configuration in PCR1; both legacy EV_EFI_VARIABLE_BOOT and EV_EFI_VARIABLE_BOOT2 may occur. See also [Project Mu replay documentation](https://microsoft.github.io/mu/dyn/mu_plus/TpmTestingPkg/TpmReplayPei/Tool/TpmReplaySchema/) and [tpm2_eventlog](https://tpm2-tools.readthedocs.io/en/stable/man/tpm2_eventlog.1/).

New tool: `tools/pcr1_audit.py`. SHA256 86090bbf895859f5ec84ec119cb4ea4a270e1f2f9fa31b53aec164eb4e18c3d7, blob 25cd7f013e6ce18c27894f202d27ac2c8daf9bb6. Tested locally with `python3 tools/pcr1_audit.py --self-test` (8 fixture checks) and `python3 -m py_compile tools/pcr1_audit.py`. No real M75n log available.

Read-only, on the M75n, before any update, in a private directory (do not publish raw event logs):

```sh
umask 077
mkdir -p pcr1-baseline
sudo cat /sys/kernel/security/tpm0/binary_bios_measurements > pcr1-baseline/eventlog.bin
sudo tpm2_pcrread sha256:1 > pcr1-baseline/pcr1.txt
tpm2_eventlog pcr1-baseline/eventlog.bin > pcr1-baseline/eventlog.yaml
python3 tools/pcr1_audit.py pcr1-baseline/eventlog.bin > pcr1-baseline/summary.json
sudo efibootmgr > pcr1-baseline/boot-options.txt
```

If the TPM or securityfs log is unavailable, record that fact, do not change TPM state to force collection. If SHA256 bank is not active, select an available bank. Manually compare the replay with the same-boot PCR1 value or pass its hex value as `--expected`. Cross-check tpm2_eventlog output. Capture at least three independent cold boots at the same configuration before update and after (plus warm boots separately if useful). Compare the presence, multiplicity, order and names of BootOrder/Boot#### events to actual boot options; do not interpret unrelated digest changes as a defect. A new missing or variable set of events with replay matching hardware would support P2-38/39; a mismatch suggests incomplete log, parser limitations, or later extensions and is not a diagnosis. If events consistently appear, the defect is not observed for that configuration, not disproved. TPM-bound unlock requires independent recovery access before flashing.

Scope: only TPM2 Spec ID Event03/Event2 logs, PCR1 replay using recorded digests, no validation of digest-to-payload correspondence or full attestation. Synthetic checks cover positive replay, unrelated PCR and EV_NO_ACTION handling, both boot-event types, empty event list, unclassified record, truncated and invalid header, absent bank. Fail closed on malformed framing; no real event log validation yet.

## State

No new firmware bytes examined in this cycle: ROMs/AFU exist as Library references but materialization returned no authorized raw-byte path; direct network retrieval also unavailable. Their absence from Git is intentional. B10 remains 38/44 attributed, six partial; 168 S24 + 6 S33 = 174 pending pair-specific records. B06/B12 remain open, but the concrete measured-boot experiment is ready. B10 and B04 remain the next binary priorities once images are provided. No hardware change made.
