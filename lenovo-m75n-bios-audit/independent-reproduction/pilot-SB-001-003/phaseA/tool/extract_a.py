#!/usr/bin/env python3
"""Phase A extractor (stdlib only). Produces machine-readable JSON of observations for the
three FFS GUIDs in the given ROMs. Does not read claims.json, verify.py or any prior reports.

Usage: extract_a.py <out.json> <rom1> <rom2> ...
"""
import sys, os, json, hashlib, struct, uuid, lzma, platform, collections

TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TOOL_DIR)
from ffs_explore import find_fvs, walk_ffs, parse_sections, GUIDS

LZMA_GUID = "ee4e5898-3914-4259-9d6e-dc7bd79403cf"
TOOL_VERSION = "extract_a.py/1 (stdlib, own FFS/section walker; LZMA via python lzma FORMAT_ALONE)"
# FFS file types whose body is a section stream (raw 0x01, pad 0xF0, erased 0xFF are not)
SECTION_FILE_TYPES = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}
TARGET_UP = {v.upper(): k for k, v in GUIDS.items()}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def walk_bytes(data, base_path, out):
    """Enumerate every FFS file reachable in `data` (FV scan + LZMA + FV sections).
    Records target hits, all unresolved/failed items, and counters."""
    for (b, l, h) in find_fvs(data):
        if b + l > len(data):
            out["notes"].append({"kind": "fv_out_of_bounds", "path": base_path, "fv_off": b})
            continue
        for f in walk_ffs(data, b, l, h):
            if "guid" not in f:
                out["notes"].append({"kind": "ffs_parse_error", "path": base_path, "fv_off": b, "detail": f})
                continue
            out["counters"]["ffs_files_seen"] += 1
            p = base_path + [f"FV@0x{b:x}", f"FFS@0x{f['off']:x}:{f['guid']}"]
            if f["guid"].upper() in TARGET_UP:
                out["_hits"].append({"tag": TARGET_UP[f["guid"].upper()], "path": p,
                                     "file": f, "container": data})
            if f["type"] in SECTION_FILE_TYPES:
                walk_sections(data, f["body_off"], f["body_end"], p, out)
            else:
                out["counters"]["non_section_ffs_skipped"] += 1


def walk_sections(buf, start, end, path, out):
    nodes = []
    parse_sections(buf, start, end, 0, nodes)
    for n in nodes:
        if "error" in n:
            out["notes"].append({"kind": "section_parse_error", "path": path,
                                 "off": n["off"], "size": n["size"], "type": n["type"]})
            out["counters"]["section_parse_errors"] += 1
            continue
        t = n["type"]
        if t == 0x19:
            continue
        if t == 0x01:
            ct = n.get("comp_type")
            if ct == 0:
                walk_bytes_container(buf, n["off"] + n["hdr"] + 5, n["off"] + n["size"], path + [f"COMP0@0x{n['off']:x}"], out)
            else:
                out["notes"].append({"kind": "unresolved_compression", "path": path, "comp_type": ct, "off": n["off"]})
                out["counters"][f"unresolved_compression_type_{ct}"] += 1
        elif t == 0x02:
            if n["guid"] == LZMA_GUID:
                payload = bytes(buf[n["off"] + n["data_off"]: n["off"] + n["size"]])
                try:
                    dec = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
                except Exception as e:
                    out["notes"].append({"kind": "lzma_failed", "path": path, "off": n["off"], "err": str(e)})
                    out["counters"]["lzma_failed"] += 1
                    continue
                out["counters"]["lzma_ok"] += 1
                out.setdefault("_streams", []).append(dec)
                walk_sections(dec, 0, len(dec), path + [f"LZMA@0x{n['off']:x}"], out)
            else:
                out["notes"].append({"kind": "unknown_guid_section", "path": path, "guid": n["guid"], "off": n["off"]})
                out["counters"]["unknown_guid_section"] += 1
        elif t == 0x17:
            walk_bytes(bytes(buf[n["off"] + n["hdr"]: n["off"] + n["size"]]), path + [f"FVSEC@0x{n['off']:x}"], out)


def walk_bytes_container(buf, start, end, path, out):
    walk_sections(buf, start, end, path, out)


def raw_leaves(buf, start, end, path, out_list, depth=0):
    """Collect RAW (0x19) leaves of a file's section stream, descending through the same
    encapsulations. Returns list of dicts with path and body bytes location."""
    nodes = []
    parse_sections(buf, start, end, 0, nodes)
    for n in nodes:
        if "error" in n:
            out_list.append({"error": "section_parse_error", "path": path, "off": n["off"]})
            continue
        t = n["type"]
        if t == 0x19:
            body = bytes(buf[n["off"] + n["hdr"]: n["off"] + n["size"]])
            out_list.append({"path": path + [f"RAW@0x{n['off']:x}"], "sec_off": n["off"],
                             "sec_size": n["size"], "body": body})
        elif t == 0x01 and n.get("comp_type") == 0:
            raw_leaves(buf, n["off"] + n["hdr"] + 5, n["off"] + n["size"], path + [f"COMP0@0x{n['off']:x}"], out_list, depth+1)
        elif t == 0x02 and n.get("guid") == LZMA_GUID:
            payload = bytes(buf[n["off"] + n["data_off"]: n["off"] + n["size"]])
            dec = lzma.decompress(payload, format=lzma.FORMAT_ALONE)
            raw_leaves(dec, 0, len(dec), path + [f"LZMA@0x{n['off']:x}"], out_list, depth+1)
        elif t == 0x17:
            sub = bytes(buf[n["off"] + n["hdr"]: n["off"] + n["size"]])
            for (b, l, h) in find_fvs(sub):
                for f in walk_ffs(sub, b, l, h):
                    if "guid" in f:
                        raw_leaves(sub, f["body_off"], f["body_end"], path + [f"FVSEC@0x{n['off']:x}", f"FV@0x{b:x}", f"FFS@0x{f['off']:x}"], out_list, depth+1)


def analyse(rom_paths):
    per_rom = {}
    for rp in rom_paths:
        data = open(rp, "rb").read()
        out = {"notes": [], "counters": collections.Counter(), "_hits": []}
        walk_bytes(data, ["ROM"], out)
        # cross-check: raw occurrences of each GUID's EFI byte form in ROM and in decompressed streams
        rec = {
            "path": rp, "file_name": os.path.basename(rp), "size_bytes": len(data), "sha256": sha256(data),
            "fv_count_top_level": len(find_fvs(data)),
            "counters": dict(out["counters"]), "notes_count": len(out["notes"]),
            "notes_by_kind": dict(collections.Counter(n["kind"] for n in out["notes"])),
            "targets": {},
        }
        # byte-level cross-check: occurrences of each GUID (EFI byte order) in the raw ROM and in
        # every decompressed LZMA stream reached by the walk. Structural match count is separate.
        streams = [data] + out.get("_streams", [])
        rec["byte_level_crosscheck"] = {"streams_scanned": len(streams)}
        for tag, g in GUIDS.items():
            b = uuid.UUID(g).bytes_le
            rec["byte_level_crosscheck"][tag] = {
                "occurrences_total": sum(x.count(b) for x in streams),
                "occurrences_in_raw_rom": data.count(b)}

        for tag, g in GUIDS.items():
            hits = [h for h in out["_hits"] if h["tag"] == tag]
            entry = {"guid": g, "ffs_match_count": len(hits), "candidates": []}
            for h in hits:
                f = h["file"]
                cont = h["container"]
                body = bytes(cont[f["body_off"]: f["body_end"]])
                leaves = []
                raw_leaves(cont, f["body_off"], f["body_end"], h["path"], leaves)
                raw = [x for x in leaves if "body" in x]
                errs = [x for x in leaves if "error" in x]
                cand = {
                    "path": " > ".join(h["path"]),
                    "ffs_type": f["type"], "ffs_attrs": f["attrs"], "ffs_size": f["size"],
                    "ffs_body_size": len(body), "ffs_body_sha256": sha256(body),
                    "section_parse_errors_in_file": len(errs),
                    "raw_leaf_count": len(raw),
                    "raw_leaves": [],
                }
                for x in raw:
                    b = x["body"]
                    rec_leaf = {"path": " > ".join(x["path"]), "body_size": len(b), "body_sha256": sha256(b)}
                    if len(b) >= 20:
                        u = struct.unpack_from("<I", b, 16)[0]
                        rec_leaf["u32_le_at_16"] = u
                        rec_leaf["offset_16_plus_u32"] = 16 + u
                        rec_leaf["suffix_from_16_plus_u32_len"] = max(0, len(b) - (16 + u))
                        rec_leaf["suffix_sha256"] = sha256(b[16+u:]) if 16 + u <= len(b) else None
                    cand["raw_leaves"].append(rec_leaf)
                # only a candidate with exactly one RAW leaf yields a comparable payload
                cand["_body"] = raw[0]["body"] if len(raw) == 1 else None
                entry["candidates"].append(cand)
            rec["targets"][tag] = entry
        per_rom[rp] = (rec, out)
    return per_rom


if __name__ == "__main__":
    out_json = sys.argv[1]
    roms = sys.argv[2:]
    results = analyse(roms)
    # store body bytes in a separate scratch dir (never in JSON / git), for cross-ROM comparison
    docs = []
    bodies = {}
    for rp, (rec, _) in results.items():
        for tag, ent in rec["targets"].items():
            for c in ent["candidates"]:
                b = c.pop("_body", None)
                if b is not None:
                    bodies[(os.path.basename(rp), tag)] = b
        docs.append(rec)
    # cross-ROM comparison of single-leaf bodies
    comparisons = {}
    for tag in GUIDS:
        a = bodies.get((os.path.basename(roms[0]), tag))
        b = bodies.get((os.path.basename(roms[1]), tag))
        if a is None or b is None:
            comparisons[tag] = {"status": "missing_in_one_or_both"}
            continue
        comp = {"size_a": len(a), "size_b": len(b), "sha256_a": sha256(a), "sha256_b": sha256(b)}
        if len(a) == len(b):
            diffs = [i for i in range(len(a)) if a[i] != b[i]]
            comp["differing_offsets_count"] = len(diffs)
            comp["differing_offsets"] = diffs
        else:
            comp["size_mismatch_reported"] = True
        comparisons[tag] = comp
    doc = {
        "protocol": "INDEPENDENT_REPRODUCTION phase A (pilot SB-001..003)",
        "tool": {"name": TOOL_VERSION, "python": platform.python_version(), "platform": platform.platform()},
        "scope_note": "FFS GUID matches are counted via recursive walk; cross-check via raw GUID byte occurrence counts.",
        "roms": docs,
        "cross_rom_comparison": comparisons,
    }
    with open(out_json, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(out_json)
