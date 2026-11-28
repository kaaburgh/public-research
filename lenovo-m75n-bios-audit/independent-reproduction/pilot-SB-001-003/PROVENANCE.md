# Tool and input provenance

| Item | Value |
|---|---|
| Protocol | `lenovo-m75n-bios-audit/evidence-v1/INDEPENDENT_REPRODUCTION.md` at commit `4095d9cf951f79bd0d4ca51f89afe82a350dbb88` |
| Verifier and claims | `verify.py` SHA-256 `76fc95a1146140b4dbc5a3df351b559cb9db3a3bdf8c72f3bc9185b95d6aa465`; `claims.json` SHA-256 `27b7a694155a3a82b943c47125f001da12356c4cd9f2627bd28b414c5c22dc3f` (both fetched at the protocol commit above) |
| claims.json `source_commit` field | `5cfc7c245066ced5e7854a191fcd1c06d7f41f62` (differs from the fetch commit; not resolved here) |
| Extractor | UEFIExtract NE alpha 75, release `A75` of LongSoft/UEFITool, asset `UEFIExtract_NE_A75_x64_linux.zip` |
| Asset SHA-256 (checked against GitHub's asset digest) | `5ee05d0da0c235626de67959d6cd97767e0d7ac67d42c8839e5972e8c23fd5a5` |
| Extracted binary SHA-256 | `f1b8d112838adcf741c43dbd87f3dc61f06996239e9801ae62cf46ea1cd2485a` |
| Input ROM M33KT32A (`rom132`) | 16 777 216 bytes, SHA-256 `7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145` |
| Input ROM M33KT33A (`rom133`) | 16 777 216 bytes, SHA-256 `fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498` |
| Phase A extractor | stdlib Python walker in `phaseA/tool/` (not A75), run before A75 was obtained |
| Phase A JSON | Original (pre-sanitization) SHA-256 `130227d9ab9f3fe16a4efafb45133d45382849fa482fd686174e236d2923e5b8`. Published copy differs only in `roms[].path`, which was reduced to the file name; published SHA-256 `6559d2cbe6dc9c374c8dfe67f63370285cec071cf64a3d6eb81327425ddbd9e9` |

Input binaries are not in this repository.
