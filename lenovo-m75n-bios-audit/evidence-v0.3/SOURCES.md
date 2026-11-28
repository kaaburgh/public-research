# Pinned source and review references

- Historical audit `5cfc7c245066ced5e7854a191fcd1c06d7f41f62`, `lenovo-m75n-bios-audit/RELEASE_132_133.md` P2-47 and `data/inventory.tsv`, `SOURCES.md`.
- v1 protocol `4095d9cf951f79bd0d4ca51f89afe82a350dbb88`, `lenovo-m75n-bios-audit/evidence-v1/claims.json`.
- Independent reproduction `935daa09485a5fb6ba7b396c1024c027f735ad5c`, `lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/` (phase A observations and phase B official receipt).
- v0.2 `23419c178f4eaaf75c1e2dcdbcb9c269c00f72b1`; independent review PR #3 `b5d717753d587f38de078635a87cc4356a45fcef`, `lenovo-m75n-bios-audit/evidence-v0.2-review/REPORT.md` and `tests/derivation_poc.py`.
- PI 1.8, Volume 3, [Firmware Storage Code Definitions](https://uefi.org/specs/PI/1.8/V3_Code_Definitions.html) and [Firmware Storage Design Discussion](https://uefi.org/specs/PI/1.8/V3_Design_Discussion.html).
- UEFI 2.10, [Runtime Services](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html) and [Secure Boot and Driver Signing](https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html).

The public specification search results corroborate the structural concepts, but the full HTML pages could not be retrieved in the authoring session (HTTP 403). Exact PI recovery precedence and detailed extended layouts are deliberately not implemented. Review the authoritative sections before accepting the parser. The expected header values are hypotheses for these vendor containers, not measured results.
