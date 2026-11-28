#!/usr/bin/env python3
"""Proof-carrying extraction PoC for the review of evidence protocol v0.2 (Python 3.10+, stdlib only).

Idea: the adapter is an untrusted *search* procedure; it emits a structure certificate (a parse tree
with offsets only). A small trusted checker re-derives everything from the artifact bytes:
  * every node is re-parsed from bytes (GUIDs, sizes, types are never taken from the adapter);
  * children must partition their parent (gaps only as alignment or erased bytes, verified);
  * supported encapsulations (LZMA GUID-defined, FV image) must be expanded, others are declared opaque;
  * every occurrence of the selector GUID / "_FVH" in leaf or opaque bytes is tested for a
    structurally valid FFS/FV header; an untracked valid header makes coverage incomplete;
  * selection (owner/RAW counts, nearest-owner rule) and the payload are computed by the checker.
Result: payload lineage is verified, completeness is falsifiable and relative to an explicit list of
opaque regions. Synthetic images only; this is not a production FFS parser.
Usage: python3 -I derivation_poc.py
"""
import hashlib, lzma, struct, uuid, zlib

LZMA_GUID = uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF").bytes_le
FFS2 = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3").bytes_le
TARGET = uuid.UUID("CC0F8A3F-3DEA-4376-9679-5426BA0A907E")
OTHER = uuid.UUID("11111111-2222-3333-4444-555555555555")
SECTION_FILE_TYPES = set(range(0x02, 0x10))
sha = lambda b: hashlib.sha256(b).hexdigest()


class Invalid(Exception):
    """Certificate rejected: it does not describe these bytes."""


def need(ok, msg):
    if not ok:
        raise Invalid(msg)

# ---------------------------------------------------------------- synthetic image builder (test fixture)

def section(stype, body):
    size = 4 + len(body)
    return struct.pack("<I", size)[:3] + bytes([stype]) + body

def lzma_section(inner):
    data = lzma.compress(inner, format=lzma.FORMAT_ALONE)
    return section(0x02, LZMA_GUID + struct.pack("<HH", 24, 1) + data)

def align(b, n, fill):
    return b + bytes([fill]) * (-len(b) % n)

def sections(*secs):
    out = b""
    for s in secs:
        out = align(out, 4, 0) + s
    return out

def ffs(guid, ftype, body, deleted=False):
    size = 24 + len(body)
    hdr = bytearray(guid.bytes_le + b"\x00\x00" + bytes([ftype, 0]) + struct.pack("<I", size)[:3] + b"\x00")
    hdr[16] = (-sum(hdr)) & 0xFF          # header checksum (State and File checksum counted as 0)
    hdr[17] = 0xAA                        # FFS_FIXED_CHECKSUM
    hdr[23] = 0xE8 if deleted else 0xF8   # erase polarity 1: ~(construction|header_valid|data_valid[|deleted])
    return bytes(hdr) + body

def fv(files, length):
    hl = 72
    hdr = bytearray(b"\x00" * 16 + FFS2 + struct.pack("<Q", length) + b"_FVH" + struct.pack("<IHHHBB", 0x800, hl, 0, 0, 0, 2)
                    + struct.pack("<IIII", length // 4096 or 1, 4096, 0, 0))
    hdr[50:52] = struct.pack("<H", (-sum(struct.unpack("<36H", bytes(hdr)))) & 0xFFFF)
    body = bytes(hdr)
    for f in files:
        body = align(body, 8, 0xFF) + f
    need(len(body) <= length, "fixture FV too small")
    return body + b"\xff" * (length - len(body))

DEPEX = bytes([0x02]) + TARGET.bytes_le + bytes([0x08])  # PUSH <target GUID>; END  (benign GUID occurrence)

def payload(tag):
    return bytes(16) + struct.pack("<I", 24) + b"\x00" * 20 + tag.encode() * 8

def target_file(tag, deleted=False):
    return ffs(TARGET, 0x02, sections(lzma_section(sections(section(0x19, payload(tag))))), deleted)

def driver_with_depex():
    return ffs(OTHER, 0x07, sections(section(0x13, DEPEX), section(0x10, b"MZ" + b"\x90" * 62)))

def image(variant):
    inner_fv = fv([target_file("v133") if variant != "no_main" else driver_with_depex(), driver_with_depex()], 0x1000)
    main_fv = fv([driver_with_depex(), ffs(OTHER, 0x0B, sections(lzma_section(sections(section(0x17, inner_fv)))))], 0x4000)
    rom = bytearray(b"\xff" * 0x10000)
    rom[0x1000:0x1000 + len(main_fv)] = main_fv
    if variant in ("hidden_fv_gap", "hidden_fv_opaque"):
        backup = fv([target_file("OLD-COPY")], 0x1000)
        rom[0x9000:0x9000 + len(backup)] = backup
    if variant == "deleted_dup":
        dup_fv = fv([target_file("stale", deleted=True)], 0x1000)
        rom[0x9000:0x9000 + len(dup_fv)] = dup_fv
    if variant == "compressed_copy_opaque":
        blob = zlib.compress(fv([target_file("COMPRESSED-COPY")], 0x1000))
        rom[0x9000:0x9000 + len(blob)] = blob
    return bytes(rom)

# ---------------------------------------------------------------- trusted checker

class Ctx:
    def __init__(self, guid):
        self.guid = guid.bytes_le
        self.owners, self.issues, self.opaque, self.benign = [], [], [], 0

def check_gap(buf, start, end, fill_ok, where):
    gap = buf[start:end]
    need(all(x in fill_ok for x in gap), f"unexplained bytes {where} [{start:#x},{end:#x})")

def parse_fv(buf, off):
    need(off + 72 <= len(buf) and buf[off + 40:off + 44] == b"_FVH", f"no FV header at {off:#x}")
    length = struct.unpack_from("<Q", buf, off + 32)[0]
    hl = struct.unpack_from("<H", buf, off + 48)[0]
    need(56 <= hl < length and off + length <= len(buf) and hl % 2 == 0, "FV bounds")
    need(sum(struct.unpack_from(f"<{hl // 2}H", buf, off)) & 0xFFFF == 0, "FV header checksum")
    need(buf[off + 16:off + 32] == FFS2, "unsupported FV filesystem")
    return length, hl

def parse_ffs(fvb, off, aligned=True):
    need((off % 8 == 0 or not aligned) and off + 24 <= len(fvb), "FFS alignment/bounds")
    h = fvb[off:off + 24]
    size = h[20] | h[21] << 8 | h[22] << 16
    need(size >= 24 and off + size <= len(fvb), "FFS size")
    z = bytearray(h); z[17] = 0; z[23] = 0
    need(sum(z) & 0xFF == 0, "FFS header checksum")
    state = (~h[23]) & 0xFF
    need(state & 0x07 == 0x07 and not state & 0x20, "FFS state not valid")
    return {"guid": bytes(h[:16]), "type": h[18], "size": size, "deleted": bool(state & 0x10)}

def valid_ffs_at(buf, off):
    try: parse_ffs(buf, off, aligned=False); return True
    except (Invalid, IndexError, struct.error): return False

def valid_fv_at(buf, off):
    try: parse_fv(buf, off); return True
    except (Invalid, IndexError, struct.error): return False

def scan_leaf(ctx, buf, start, end, where):
    """Leaf/opaque bytes: every GUID or _FVH occurrence must not start a valid, untracked structure."""
    i = buf.find(ctx.guid, start, end)
    while i >= 0:
        if valid_ffs_at(buf, i):
            ctx.issues.append(f"untracked_ffs_header:{where}+{i:#x}")
        else:
            ctx.benign += 1
        i = buf.find(ctx.guid, i + 1, end)
    j = buf.find(b"_FVH", start, end)
    while j >= 0:
        if j >= 40 and valid_fv_at(buf, j - 40):
            ctx.issues.append(f"untracked_fv:{where}+{j - 40:#x}")
        j = buf.find(b"_FVH", j + 1, end)

def check_fv(ctx, buf, node, path, owner):
    off = node["offset"]
    length, hl = parse_fv(buf, off)
    fvb = buf[off:off + length]
    pos = hl
    for f in node["files"]:
        check_gap(fvb, pos, f["offset"], {0xFF}, f"in FV {path}")
        info = parse_ffs(fvb, f["offset"])
        here = f"{path}/FFS@{f['offset']:#x}"
        if info["guid"] == ctx.guid:
            ctx.owners.append({"path": here, "deleted": info["deleted"], "raw": []})
            if info["deleted"]:
                ctx.issues.append(f"deleted_owner_present:{here}")
        new_owner = ctx.owners[-1] if info["guid"] == ctx.guid else None
        body = fvb[f["offset"] + 24:f["offset"] + info["size"]]
        if info["type"] in SECTION_FILE_TYPES:
            check_sections(ctx, body, f.get("sections", []), here, new_owner)
        else:
            scan_leaf(ctx, body, 0, len(body), here)
        pos = f["offset"] + info["size"]
    check_gap(fvb, pos, length, {0xFF}, f"tail of FV {path}")

def check_sections(ctx, buf, secs, path, owner):
    pos = 0
    for s in secs:
        check_gap(buf, pos, s["offset"], {0x00}, f"between sections {path}")
        need(s["offset"] % 4 == 0 and s["offset"] - pos < 4, f"section alignment {path}")
        o = s["offset"]; need(o + 4 <= len(buf), "section bounds")
        size = buf[o] | buf[o + 1] << 8 | buf[o + 2] << 16; stype = buf[o + 3]
        need(size >= 4 and o + size <= len(buf) and size != 0xFFFFFF, f"section size {path}")
        here = f"{path}/S{stype:#04x}@{o:#x}"
        body = buf[o + 4:o + size]
        if stype == 0x19:
            if owner is not None:
                owner["raw"].append({"path": here, "body": bytes(body)})
            scan_leaf(ctx, body, 0, len(body), here)
        elif stype == 0x02:
            g = bytes(body[:16]); doff = struct.unpack_from("<H", body, 16)[0]
            if g == LZMA_GUID and not s.get("opaque"):
                inner = lzma.decompress(bytes(buf[o + doff:o + size]), format=lzma.FORMAT_ALONE)
                check_sections(ctx, inner, s.get("sections", []), here + "/LZMA", owner)
            else:
                reason = s.get("opaque") or "unsupported_guid_section"
                ctx.opaque.append(f"{here}:{reason}")
                ctx.issues.append(f"unexpanded_encapsulation:{here}:{reason}")
        elif stype == 0x17:
            need("fv" in s, f"FV image section not expanded {here}")
            check_fv(ctx, body, s["fv"], here + "/FV", owner)
        else:
            scan_leaf(ctx, body, 0, len(body), here)
        pos = o + size
    check_gap(buf, pos, len(buf), {0x00}, f"tail of sections {path}")

def check(rom, cert, guid=TARGET):
    """Returns a v0.2-style observation entry computed by the checker, or raises Invalid."""
    ctx = Ctx(guid)
    pos = 0
    for r in cert["regions"]:
        check_gap(rom, pos, r["offset"], {0xFF}, "at top level")
        if r["kind"] == "fv":
            length, _ = parse_fv(rom, r["offset"])
            check_fv(ctx, rom, r, f"FV@{r['offset']:#x}", None)
            pos = r["offset"] + length
        elif r["kind"] == "opaque":
            ctx.opaque.append(f"top@{r['offset']:#x}+{r['length']:#x}:{r['reason']}")
            scan_leaf(ctx, rom, r["offset"], r["offset"] + r["length"], "top")
            pos = r["offset"] + r["length"]
        else:
            raise Invalid("unknown region kind")
    check_gap(rom, pos, len(rom), {0xFF}, "at end of image")
    live = [o for o in ctx.owners if not o["deleted"]]
    raws = [x for o in ctx.owners for x in o["raw"]]
    unique = len(ctx.owners) == 1 and len(raws) == 1 and not ctx.issues
    # Completeness is relative to the opaque list: an unsupported encoding inside an opaque region is invisible.
    coverage = "incomplete" if ctx.issues else "complete_except_opaque" if ctx.opaque else "complete"
    return {"owner_count": len(ctx.owners), "live_owner_count": len(live), "raw_node_count": len(raws),
            "coverage": coverage, "issues": ctx.issues, "opaque": ctx.opaque,
            "benign_guid_occurrences": ctx.benign,
            "payload_sha256": sha(raws[0]["body"]) if unique else None, "locator": raws[0]["path"] if unique else None}

# ---------------------------------------------------------------- adapters (untrusted)

def honest_cert(variant):
    """What a correct adapter would emit for the fixture layout (offsets only)."""
    target = {"offset": 0, "sections": [{"offset": 0, "sections": [{"offset": 0}]}]}
    driver = lambda off: {"offset": off, "sections": [{"offset": 0}, {"offset": 4 + len(DEPEX) + (-(4 + len(DEPEX)) % 4)}]}
    d0 = len(driver_with_depex()); d0a = d0 + (-d0 % 8)
    inner_files = [target if variant != "no_main" else driver(0)]
    first = len(target_file("v133")) if variant != "no_main" else d0
    inner_files.append(driver(72 + first + (-(72 + first) % 8)))
    inner_files[0]["offset"] = 72
    fv_img = {"offset": 72 + d0a, "sections": [{"offset": 0, "sections": [{"offset": 0, "fv": {"offset": 0, "files": inner_files}}]}]}
    regions = [{"kind": "fv", "offset": 0x1000, "files": [driver(72), fv_img]}]
    if variant in ("hidden_fv_opaque", "compressed_copy_opaque"):
        regions.append({"kind": "opaque", "offset": 0x9000, "length": 0x1000, "reason": "vendor_data"})
    if variant == "deleted_dup":
        regions.append({"kind": "fv", "offset": 0x9000, "files": [{"offset": 72, "sections": [{"offset": 0, "sections": [{"offset": 0}]}]}]})
    return {"regions": regions}

def run(name, rom, cert, expect):
    try:
        r = check(rom, cert)
        outcome = ("PASS-eligible" if r["coverage"] == "complete" else "CONDITIONAL") if r["payload_sha256"] else "BLOCKED"
        detail = f"owners={r['owner_count']} raw={r['raw_node_count']} coverage={r['coverage']} issues={r['issues']} opaque={r['opaque']} benign_guid={r['benign_guid_occurrences']}"
    except Invalid as e:
        outcome, detail = "REJECTED", str(e)
    ok = outcome == expect
    print(f"{'ok  ' if ok else 'FAIL'} {name}: {outcome}  ({detail})")
    return ok

if __name__ == "__main__":
    results = []
    good = image("base")
    r = check(good, honest_cert("base"))
    expected_payload = sha(payload("v133"))
    results.append(run("P1 honest certificate; unique owner; DEPEX GUID operand is benign", good, honest_cert("base"), "PASS-eligible"))
    results.append(r["payload_sha256"] == expected_payload)
    print(f"     payload derived by checker == fixture payload: {results[-1]}")
    # P2: v0.2 counterexample N03/N04 is unrepresentable: the adapter cannot name a payload at all.
    erased = b"\xff" * 0x10000
    results.append(run("P2 erased flash + certificate claiming an FV (N03 analogue)", erased, honest_cert("base"), "REJECTED"))
    results.append(run("P3 backup FV with a second copy omitted from the certificate", image("hidden_fv_gap"), honest_cert("base"), "REJECTED"))
    results.append(run("P4 backup FV declared opaque 'vendor_data'", image("hidden_fv_opaque"), honest_cert("hidden_fv_opaque"), "BLOCKED"))
    c5 = honest_cert("base"); c5["regions"][0]["files"][1]["sections"][0]["opaque"] = "claimed_unsupported"
    results.append(run("P5 adapter leaves the LZMA section holding the target unexpanded", good, c5, "BLOCKED"))
    results.append(run("P6 deleted duplicate owner present (policy must be explicit)", image("deleted_dup"), honest_cert("deleted_dup"), "BLOCKED"))
    c7 = honest_cert("base"); c7["regions"][0]["files"][0]["offset"] = 80
    results.append(run("P7 adapter points a node at the wrong offset", good, c7, "REJECTED"))
    results.append(run("P8 zlib-compressed copy inside an opaque region: invisible; result is explicitly conditional",
                       image("compressed_copy_opaque"), honest_cert("compressed_copy_opaque"), "CONDITIONAL"))
    results.append(run("P9 no target in image (absence is not proven, only 'no owner in verified tree')", image("no_main"), honest_cert("no_main"), "BLOCKED"))
    print(f"\n{sum(results)}/{len(results)} expectations hold")
    raise SystemExit(0 if all(results) else 1)
