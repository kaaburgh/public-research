# NVAR compact migration capacity estimate (P2-126/E121)

Use the verified owner AFU 1.24 and manufacturer 1.33 A75 extraction trees; do not publish raw NVRAM, names, or payloads. Run:

python3 tools/nvar_capacity.py /path/old.rom.dump /path/new.rom.dump

The tool sums direct A75 child Full size and requires exact agreement with each NVAR body size; resolves all named valid roots through their link chains using name+GUID, checks cycles/missing/invalid nodes and requires a unique terminal per key. Data-only orphan links are not independent named variables. Uses terminal body size and observed authentication-tail length. Both new StdDefaults copies agree in key set and payload/tail sizes (prior checkpoints verify their body hashes). Model keeps all non-default entries, replaces the defaults container and includes all 13 defaults as separate entries even if not materialized at that stage. Per logical record budgets payload, observed tail, UTF16 name, 16-byte inline GUID and 16-byte GUID-table slot, 10-byte header, 15 padding and 64 extra bytes. This is deliberately generous for the one-record-per-key compaction assumption, not a formal upper bound on unknown firmware allocator behavior.

Tested on both owner banks; all chains resolved, total estimated compact usage below half of capacity with roughly 53% headroom. Owner-specific detailed aggregate output stored in private evidence. The old near-full bank contains history, not necessarily live-data capacity pressure. Actual firmware may impose individual variable limits, special auth handling, transient allocations or different record construction. No proof of successful migration or write error recovery; offline estimate only. No change to section attribution counts.
