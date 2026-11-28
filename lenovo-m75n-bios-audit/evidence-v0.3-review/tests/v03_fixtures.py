"""Independent PI image builder for the v0.3 review (not derived from test_pilot.py).
Constants are restated from PI 1.8 Vol. 3 / UEFI 2.10, not imported from the code under review."""
import lzma, struct, uuid, zlib

FFS2 = uuid.UUID('8C8CE578-8A3D-4F1C-9935-896185C32DD3').bytes_le
LZMA = uuid.UUID('EE4E5898-3914-4259-9D6E-DC7BD79403CF').bytes_le
CRC32_GUID = uuid.UUID('FC1BCDB0-7D31-49AA-936A-A4600D9DD083').bytes_le
PKCS7 = uuid.UUID('4AAFD29D-68DF-49EE-8AA9-347D375665A7').bytes_le
X509 = uuid.UUID('A5C059A1-94E4-4AA7-87B5-AB155C2BF072').bytes_le
PAD_NAME = b'\xff' * 16
OTHER = uuid.UUID('11111111-2222-3333-4444-555555555555')
TARGETS = {'SB-001': ('CC0F8A3F-3DEA-4376-9679-5426BA0A907E', 842, 1),
           'SB-002': ('9FE7DE69-0AEA-470A-B50A-139813649189', 3908, 3),
           'SB-003': ('FBF95065-427F-47B3-8077-D13C60710998', 9485, 7)}
GUIDS = {k: uuid.UUID(v[0]) for k, v in TARGETS.items()}
DATA_VALID, MARKED, DELETED, HEADER_INVALID, UNDER_CONSTRUCTION = 0x07, 0x0F, 0x17, 0x23, 0x03
LAYOUT = {'SB-001': [774], 'SB-002': [1261, 1261, 1262], 'SB-003': [1321] * 6 + [1323]}

def sec(t, body, size=None):
    return (size if size is not None else 4 + len(body)).to_bytes(3, 'little') + bytes([t]) + body

def stream(*secs, pad=0):
    out = b''
    for s in secs:
        out += bytes([pad]) * (-len(out) % 4) + s
    return out

def lzma_sec(inner, trailing=b''):
    return sec(0x02, LZMA + struct.pack('<HH', 24, 1) + lzma.compress(inner, format=lzma.FORMAT_ALONE) + trailing)

def crc32_sec(inner):
    return sec(0x02, CRC32_GUID + struct.pack('<HHI', 28, 0x02, zlib.crc32(inner)) + inner)

def ffs(name, ftype, body, state=DATA_VALID, checksum_attr=False, polarity=1, file_checksum=None):
    attr = 0x40 if checksum_attr else 0
    h = bytearray(name + b'\0\0' + bytes([ftype, attr]) + (24 + len(body)).to_bytes(3, 'little') + b'\0')
    h[16] = (-sum(h)) & 0xFF
    h[17] = file_checksum if file_checksum is not None else ((-sum(body)) & 0xFF if checksum_attr else 0xAA)
    h[23] = state ^ (0xFF if polarity else 0)
    return bytes(h) + body

def fv(files, size=0x8000, ext_name=None, polarity=1, header_tail=b'', blocks=None, gap_fill=None):
    erase = 0xFF if polarity else 0
    hl = 72 + len(header_tail)
    ext_off = hl + 24 if ext_name else 0
    nb = blocks if blocks is not None else size // 0x1000
    hdr = bytearray(bytes(16) + FFS2 + struct.pack('<Q', size) + b'_FVH' +
                    struct.pack('<IHHHBB', 0x800 if polarity else 0, hl, 0, ext_off, 0, 2) + struct.pack('<IIII', nb, 0x1000, 0, 0) + header_tail)
    hdr[50:52] = ((-sum(struct.unpack(f'<{hl // 2}H', bytes(hdr)))) & 0xFFFF).to_bytes(2, 'little')
    body = bytes(hdr)
    if ext_name:  # EDK2 GenFv convention: EFI_FIRMWARE_VOLUME_EXT_HEADER inside a leading pad file
        body += ffs(PAD_NAME, 0xF0, ext_name + struct.pack('<I', 20), polarity=polarity)
    fill = bytes([erase if gap_fill is None else gap_fill])
    for f in files:
        body += fill * (-len(body) % 8) + f
    assert len(body) <= size
    return body + bytes([erase]) * (size - len(body))

def efi_time(year, month, day, hour, minute, second):
    return struct.pack('<HBBBBBBIhBB', year, month, day, hour, minute, second, 0, 0, 0, 0, 0)

def auth_hdr(dwlength=24, revision=0x200, certtype=0xEF1, guid=PKCS7):
    return struct.pack('<IHH', dwlength, revision, certtype) + guid

def sig_lists(entry_sizes, tag, header_size=0, sigtype=X509):
    out = b''
    for e in entry_sizes:
        entry = bytes(16) + (tag * e)[:e - 16]
        out += sigtype + struct.pack('<III', 28 + header_size + e, header_size, e) + bytes(header_size) + entry
    return out

def payload(tid, newer, tag=b'C'):
    t = efi_time(2026, 2, 3, 4, 5, 6) if newer else efi_time(2025, 1, 2, 3, 4, 5)
    p = t + auth_hdr() + sig_lists(LAYOUT[tid], tag)
    assert len(p) == TARGETS[tid][1], (tid, len(p))
    return p

def target_file(tid, newer, tag=b'C', state=DATA_VALID, wrap=None, checksum_attr=False, file_checksum=None):
    s = sec(0x19, payload(tid, newer, tag))
    if wrap == 'lzma':
        s = lzma_sec(s)
    return ffs(GUIDS[tid].bytes_le, 0x02, stream(s), state=state, checksum_attr=checksum_attr, file_checksum=file_checksum)

def rom(newer, extra=(), ext_name=None, tag=b'C', size=0x10000):
    return fv([target_file(t, newer, tag) for t in TARGETS] + list(extra), size=size, ext_name=ext_name)
