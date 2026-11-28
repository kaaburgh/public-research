# v0.3.2 implementation test results

Tested source commit: `57930db2ce1569dd0d4c003b1873b5cec8ebe4d9`. Python 3.13.5 in the author session's Linux container. Git blob SHA-1 values of all 15 transferred code, fixture, profile and pinned historical receipt files were checked against that commit's tree. No real ROM or original v1 inputs were available in the local runtime.

| Command (in evidence-v0.3) | Run | Passed | Skipped | Failed/errors |
|---|---:|---:|---:|---:|
| python3 -m unittest -q test_pilot test_v03_regression | 52 | 51 | 1 | 0 |
| python3 -m unittest -q test_v031_review | 21 | 21 | 0 | 0 |
| python3 -m unittest -q test_v031_addendum | 41 | 40 | 1 | 0 |
| python3 -m unittest -q test_v032 | 13 | 13 | 0 | 0 |
| Total | 127 | 125 | 2 | 0 |

Both skips require the original v1 claims and original independent A75 receipt via V1_DIR and IR_DIR; they were not transferred into this runtime. The already pinned historical import was available and its validation regression passed. A separate missing-ROM CLI invocation returned 2, produced receipt `e69a118a8f63ec6c37deb053a03bf44e29ce02e55a543cecfe1dd31826ab6e0e.json`, and handoff rendered the blocked outcome (exit criterion not met). This is not a real-ROM run.

The 106 mutation definitions in mutation_v032.py (97 adapted from the reviewer, nine added) were not executed in this session; the previous version's mutation results are not results for v0.3.2. Recheck anchor multiplicities, inherited equivalence classifications, survivors and errors-only detections. In particular the new certificate and lineage tests may reject tampering through overlapping invariants, so independent mutation analysis remains valuable. No claimed mutation score.

P9/P10 intentionally deferred. No first real-ROM run, no new six-SHA256 match, no independent replay or promotion of assurance. Readiness remains conditional on review and the real-ROM run.
