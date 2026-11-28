# Migrated claims (human view, non-normative)

The canonical registry is `pilot.claims.json`; inspect with `python3 -m json.tool pilot.claims.json`. IDs SB-001-v02..SB-003-v02 refer to the same three RAW sections as v1 but include exact differing offsets from the independent run. Each has ten checks, with no implied semantic conclusion. The historical v1 receipt cannot be treated as a v0.2 receipt. A production adapter and a fresh replay are required. Source anchors and predecessor IDs are reviewable against pinned commits.

| Claim | FFS GUID | Body bytes | Exact differing offsets |
|---|---|---:|---|
| SB-001-v02 | CC0F8A3F-3DEA-4376-9679-5426BA0A907E | 842 | 0, 2, 3, 4, 5, 6 |
| SB-002-v02 | 9FE7DE69-0AEA-470A-B50A-139813649189 | 3908 | 0, 2, 3, 4, 5, 6 |
| SB-003-v02 | FBF95065-427F-47B3-8077-D13C60710998 | 9485 | 0, 2, 3, 4, 5, 6 |

For each role a/b: size, full SHA-256, u32 at 16, suffix SHA-256 from 40. Then suffix equality and exact offset set. No certificate parsing or authenticated update verification.
