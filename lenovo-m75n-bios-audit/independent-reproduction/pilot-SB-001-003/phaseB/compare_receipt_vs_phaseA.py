#!/usr/bin/env python3
"""Compare official verify.py receipt 'observed' fields with phase-A observations.
Usage: compare_receipt_vs_phaseA.py <receipt.json> <phaseA_observations.json>"""
import json, sys
rc = json.load(open(sys.argv[1]))
pa = json.load(open(sys.argv[2]))
roms = {r["file_name"]: r for r in pa["roms"]}
ok = True
for x in rc["results"]:
    o = x["observed"]
    lv = [roms[n]["targets"][x["id"]]["candidates"][0]["raw_leaves"][0] for n in ("ImageM33v32.ROM", "ImageM33v33.ROM")]
    c = pa["cross_rom_comparison"][x["id"]]
    pairs = {
        "sizes": (o["sizes"], [l["body_size"] for l in lv]),
        "body_sha256": (o["body_sha256"], [l["body_sha256"] for l in lv]),
        "dwLength": (o["dwLength"], [l["u32_le_at_16"] for l in lv]),
        "suffix_sha256": (o["suffix_sha256"], [l["suffix_sha256"] for l in lv]),
        "diff_offsets": (o["diff_offsets"], c["differing_offsets"]),
    }
    for k, (a, b) in pairs.items():
        ok &= a == b
        print(x["id"], k, "MATCH" if a == b else "DIFF")
print("ALL_MATCH" if ok else "DISCREPANCY")
