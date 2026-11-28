#!/usr/bin/env python3
# Independent stdlib-only FFS explorer (phase A tooling). Does not decompress; reports structure.
import sys, struct, uuid

GUIDS = {
    "SB-001": "CC0F8A3F-3DEA-4376-9679-5426BA0A907E",
    "SB-002": "9FE7DE69-0AEA-470A-B50A-139813649189",
    "SB-003": "FBF95065-427F-47B3-8077-D13C60710998",
}

def guid_bytes(s):
    return uuid.UUID(s).bytes_le

def align8(x):
    return (x + 7) & ~7

def find_fvs(data):
    fvs = []
    i = 0
    while True:
        i = data.find(b"_FVH", i)
        if i < 0:
            break
        base = i - 40
        if base >= 0 and base + 64 <= len(data):
            fv_len = struct.unpack_from("<Q", data, base + 32)[0]
            hdr_len = struct.unpack_from("<H", data, base + 48)[0]
            if 0 < fv_len <= len(data) - base and hdr_len >= 56 and hdr_len < fv_len:
                fvs.append((base, fv_len, hdr_len))
        i += 4
    return fvs

def parse_sections(buf, start, end, depth, out):
    off = start
    while off + 4 <= end:
        size = buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16)
        stype = buf[off+3]
        hdr = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from("<I", buf, off+4)[0]
            hdr = 8
        if size < hdr or off + size > end:
            out.append({"depth": depth, "off": off, "error": "bad size", "size": size, "type": stype})
            break
        node = {"depth": depth, "off": off, "size": size, "type": stype, "hdr": hdr}
        if stype == 0x19:  # RAW
            node["body_off"] = off + hdr
            node["body_len"] = size - hdr
        elif stype == 0x01:  # COMPRESSION
            node["uncomp_len"] = struct.unpack_from("<I", buf, off+hdr)[0]
            node["comp_type"] = buf[off+hdr+4]
        elif stype == 0x02:  # GUID_DEFINED
            node["guid"] = str(uuid.UUID(bytes_le=bytes(buf[off+hdr:off+hdr+16])))
            node["data_off"] = struct.unpack_from("<H", buf, off+hdr+16)[0]
            node["attr"] = struct.unpack_from("<H", buf, off+hdr+18)[0]
        out.append(node)
        off = (off + size + 3) & ~3  # EFI sections are 4-byte aligned (FFS files are 8-byte aligned)
    return out

def walk_ffs(data, fv_base, fv_len, hdr_len):
    files = []
    off = fv_base + hdr_len
    fv_end = fv_base + fv_len
    while off + 24 <= fv_end:
        raw = data[off:off+24]
        if raw == b"\xff" * 24:
            # free space: skip to next 8-byte aligned region if whole remainder is erased
            break
        name = uuid.UUID(bytes_le=bytes(raw[0:16]))
        ftype = raw[18]
        attrs = raw[19]
        fsize = raw[20] | (raw[21] << 8) | (raw[22] << 16)
        hsize = 24
        if attrs & 0x01:  # FFS_ATTRIB_LARGE_FILE
            fsize = struct.unpack_from("<Q", data, off+24)[0]
            hsize = 32
        if fsize < hsize or off + fsize > fv_end:
            files.append({"off": off, "error": "bad file size", "size": fsize})
            break
        files.append({"off": off, "guid": str(name), "type": ftype, "attrs": attrs,
                      "size": fsize, "hdr": hsize, "body_off": off + hsize,
                      "body_end": off + fsize})
        off = align8(off + fsize)
    return files

if __name__ == "__main__":
    path = sys.argv[1]
    data = open(path, "rb").read()
    fvs = find_fvs(data)
    print(f"# {path}: size={len(data)} FV count={len(fvs)}")
    for (b, l, h) in fvs:
        print(f"FV @0x{b:08x} len=0x{l:x} hdr=0x{h:x}")
    targets = {guid_bytes(v): k for k, v in GUIDS.items()}
    for (b, l, h) in fvs:
        for f in walk_ffs(data, b, l, h):
            if "guid" not in f:
                continue
            g = f["guid"].upper()
            tag = [k for k, v in GUIDS.items() if v == g]
            if tag:
                print(f"\nFFS {tag[0]} {g} at 0x{f['off']:x} type=0x{f['type']:02x} size=0x{f['size']:x} hdr={f['hdr']}")
                nodes = []
                parse_sections(data, f["body_off"], f["body_end"], 0, nodes)
                for n in nodes:
                    print("   " * (n["depth"]+1) + str({k: (hex(v) if isinstance(v, int) and k in ("off","body_off") else v) for k, v in n.items()}))
