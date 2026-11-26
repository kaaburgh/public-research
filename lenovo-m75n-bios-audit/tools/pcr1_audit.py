#!/usr/bin/env python3
"""Read-only TPM2 PC Client event-log PCR1 replay and boot-variable summary."""
import argparse
import hashlib
import json
import re
import struct
import uuid
from pathlib import Path

ALGS = {4: 'sha1', 11: 'sha256', 12: 'sha384', 13: 'sha512', 18: 'sm3'}
GLOBAL = uuid.UUID('8be4df61-93ca-11d2-aa0d-00e098032b8c').bytes_le
BOOT_TYPES = {0x80000002, 0x8000000c}
NO_ACTION = 3


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise ValueError(f'truncated field at byte {self.pos}')
        out = self.data[self.pos:self.pos+n]
        self.pos += n
        return out

    def unpack(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize('<' + fmt)))

    def remaining(self):
        return len(self.data) - self.pos


def audit(data, bank='sha256'):
    r = Reader(data)
    pcr, typ = r.unpack('II')
    r.take(20)
    size, = r.unpack('I')
    h = Reader(r.take(size))
    if pcr != 0 or typ != NO_ACTION or h.take(16) != b'Spec ID Event03\0':
        raise ValueError('not a TPM2 Spec ID Event03 log')
    h.take(8)  # platformClass + four version/UINTN bytes
    count, = h.unpack('I')
    if not 0 < count <= 64:
        raise ValueError('invalid algorithm count')
    sizes = {}
    for _ in range(count):
        alg, n = h.unpack('HH')
        if alg in sizes or not 0 < n <= 128:
            raise ValueError('invalid/duplicate digest size')
        sizes[alg] = n
    n, = h.unpack('B')
    h.take(n)
    if h.remaining():
        raise ValueError('unparsed Spec ID bytes')
    alg = next((a for a, name in ALGS.items() if name == bank), None)
    hash_size = hashlib.new(bank).digest_size
    if sizes.get(alg) != hash_size:
        raise ValueError('requested bank absent or digest size mismatch')
    value = bytes(hash_size)
    events, extended, missing_bank = 0, 0, 0
    variables, malformed = [], []
    while r.remaining():
        offset = r.pos
        pcr, typ, count = r.unpack('III')
        if not 0 < count <= len(sizes):
            raise ValueError(f'invalid digest count at {offset}')
        digests = {}
        for _ in range(count):
            a, = r.unpack('H')
            if a not in sizes or a in digests:
                raise ValueError(f'unknown/duplicate algorithm at {offset}')
            digests[a] = r.take(sizes[a])
        n, = r.unpack('I')
        event = r.take(n)
        if pcr != 1:
            continue
        events += 1
        if typ != NO_ACTION:
            if alg in digests:
                value = hashlib.new(bank, value + digests[alg]).digest()
                extended += 1
            else:
                missing_bank += 1
        if typ not in BOOT_TYPES:
            continue
        try:
            e = Reader(event)
            guid = e.take(16)
            chars, length = e.unpack('QQ')
            name = e.take(chars * 2).decode('utf-16-le')
            payload = e.take(length)
            if e.remaining() or guid != GLOBAL:
                raise ValueError('noncanonical boot-variable record')
            if name == 'BootOrder':
                if len(payload) % 2:
                    raise ValueError('odd BootOrder length')
                variables.append({'name': name, 'type': hex(typ), 'entries': len(payload)//2})
            elif re.fullmatch(r'Boot[0-9a-fA-F]{4}', name):
                variables.append({'name': name, 'type': hex(typ)})
            else:
                malformed.append(offset)
        except (ValueError, UnicodeError):
            malformed.append(offset)
    return {'bank': bank, 'pcr1_replay': value.hex(), 'pcr1_events': events,
            'pcr1_extended': extended, 'pcr1_missing_bank': missing_bank,
            'boot_variables': variables, 'unclassified_boot_event_offsets': malformed}


def self_test():
    d = hashlib.sha256(b'fixture').digest()
    spec = b'Spec ID Event03\0' + bytes(8) + struct.pack('<IHHB', 1, 11, 32, 0)
    header = struct.pack('<II20sI', 0, 3, bytes(20), len(spec)) + spec
    def record(pcr, typ, event):
        return struct.pack('<IIIH', pcr, typ, 1, 11) + d + struct.pack('<I', len(event)) + event
    def var(name, payload):
        return GLOBAL + struct.pack('<QQ', len(name), len(payload)) + name.encode('utf-16-le') + payload
    log = header + record(1, 3, b'no action') + record(7, 1, b'ignored')
    log += record(1, 0x80000002, var('BootOrder', b'\x01\x00'))
    log += record(1, 0x8000000c, var('Boot0001', b'fixture'))
    a = audit(log)
    assert a['pcr1_replay'] == hashlib.sha256(hashlib.sha256(bytes(32)+d).digest()+d).hexdigest()
    assert a['pcr1_events'] == 3 and a['pcr1_extended'] == 2
    assert [v['name'] for v in a['boot_variables']] == ['BootOrder', 'Boot0001']
    assert audit(header)['boot_variables'] == []
    assert audit(log + record(1, 0x80000002, b'bad'))['unclassified_boot_event_offsets']
    for bad, bank in [(log[:-1], 'sha256'), (b'bad', 'sha256'), (log, 'sha1')]:
        try:
            audit(bad, bank)
        except ValueError:
            pass
        else:
            raise AssertionError('malformed/unsupported input accepted')
    print('8 fixture checks passed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', nargs='?', type=Path)
    p.add_argument('--bank', choices=ALGS.values(), default='sha256')
    p.add_argument('--expected', help='PCR1 hex value captured from the same boot')
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if args.log is None:
        p.error('provide a TPM2 binary event log')
    try:
        result = audit(args.log.read_bytes(), args.bank)
        if args.expected is not None:
            expected = bytes.fromhex(args.expected.removeprefix('0x'))
            if len(expected) != hashlib.new(args.bank).digest_size:
                raise ValueError('expected PCR has wrong length')
            result['matches_live_pcr'] = result['pcr1_missing_bank'] == 0 and expected.hex() == result['pcr1_replay']
        print(json.dumps(result, indent=2))
    except (ValueError, OSError) as exc:
        p.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    main()
