import json, sys
v02 = json.load(open(sys.argv[1])); v1 = json.load(open(sys.argv[2])); pa = json.load(open(sys.argv[3]))
roms = {r["sha256"]: r for r in pa["roms"]}
art = {a["id"]: a for a in v02["artifacts"]}
v1c = {c["id"]: c for c in v1["claims"]}
sel = {s["id"]: s for s in v02["selectors"]}
problems = 0
for a in v02["artifacts"]:
    ok = v1["artifacts"][a["id"]] == {"size": a["size"], "sha256": a["sha256"]}
    print("artifact", a["id"], "matches v1:", ok); problems += not ok
for c in v02["claims"]:
    p = c["predecessor"]["id"]; e = v1c[p]["expected"]; s = sel[c["selector"]]
    ok_guid = s["guid"] == v1c[p]["selector"]["guid"]
    ch = {k["id"]: k for k in c["checks"]}
    leaves = [roms[art[c["inputs"][r]]["sha256"]]["targets"][p]["candidates"][0]["raw_leaves"][0] for r in ("a", "b")]
    cmpx = pa["cross_rom_comparison"][p]
    rows = {
      "guid": ok_guid,
      "size": ch["size_a"]["expected"] == ch["size_b"]["expected"] == e["size_each"] == leaves[0]["body_size"] == leaves[1]["body_size"],
      "hash": [ch["hash_a"]["expected"], ch["hash_b"]["expected"]] == e["body_sha256"] == [l["body_sha256"] for l in leaves],
      "u32@16": ch["header_a"]["expected"] == ch["header_b"]["expected"] == e["dwLength_each"] == leaves[0]["u32_le_at_16"],
      "suffix_off": ch["suffix_a"]["args"]["offset"] == e["suffix_offset"] == leaves[0]["offset_16_plus_u32"],
      "suffix_hash": ch["suffix_a"]["expected"] == ch["suffix_b"]["expected"] == e["suffix_sha256_each"] == leaves[0]["suffix_sha256"] == leaves[1]["suffix_sha256"],
      "diff": ch["exact_diff"]["expected"] == cmpx["differing_offsets"] and set(ch["exact_diff"]["expected"]) <= set(e["allowed_diff_offsets"]),
      "diff_equals_v1_allowed_set": ch["exact_diff"]["expected"] == e["allowed_diff_offsets"],
    }
    problems += not all(rows.values())
    print(c["id"], "<-", p, rows)
print("PROBLEMS", problems)
