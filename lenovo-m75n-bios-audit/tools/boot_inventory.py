#!/usr/bin/env python3
"""Read-only UEFI boot inventory; no descriptions, device paths or raw payloads exported."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'


def option(payload):
    if len(payload) < 8:
        raise ValueError('short load option')
    attrs, size = struct.unpack_from('<IH', payload)
    p = 6
    while p + 2 <= len(payload) and payload[p:p+2] != b'\0\0':
        p += 2
    if p + 2 > len(payload):
        raise ValueError('unterminated description')
    p += 2
    end = p + size
    if end > len(payload):
        raise ValueError('device path out of bounds')
    bbs = False
    last_end = False
    while p < end:
        if end - p < 4:
            raise ValueError('short device path node')
        t, s, n = struct.unpack_from('<BBH', payload, p)
        if n < 4 or p+n > end:
            raise ValueError('invalid device path length')
        if t == 0x7f and (s not in (1, 0xff) or n != 4):
            raise ValueError('invalid end node')
        bbs |= t == 5 and s == 1
        last_end = (t, s) == (0x7f, 0xff)
        p += n
    if size and not last_end:
        raise ValueError('missing End Entire')
    return {'load_attrs': attrs, 'active': bool(attrs & 1), 'bbs': bbs,
            'path_size': size, 'sha256': hashlib.sha256(payload).hexdigest()}


def inspect(root):
    if not root.is_dir():
        raise ValueError('efivarfs unavailable')
    entries, errors, scalars = {}, {}, {}
    for path in sorted(root.iterdir()):
        if not path.name.lower().endswith('-'+GUID):
            continue
        name = path.name[:-37]
        if name not in ('BootOrder', 'BootNext', 'BootCurrent') and not re.fullmatch(r'Boot[0-9a-fA-F]{4}', name):
            continue
        key = name if name in ('BootOrder', 'BootNext', 'BootCurrent') else 'Boot'+name[4:].upper()
        if key in entries or key in errors or key in scalars:
            raise ValueError(f'duplicate variable {key}')
        try:
            data = path.read_bytes()
            if len(data) < 4:
                raise ValueError('missing efivarfs attributes')
            vattrs, = struct.unpack_from('<I', data)
            payload = data[4:]
            if name == 'BootOrder':
                if len(payload) % 2:
                    raise ValueError('odd BootOrder length')
                scalars[key] = [f'Boot{x:04X}' for x, in struct.iter_unpack('<H', payload)]
            elif name in ('BootNext', 'BootCurrent'):
                if len(payload) != 2:
                    raise ValueError('invalid boot selector size')
                scalars[key] = f'Boot{int.from_bytes(payload, "little"):04X}'
            else:
                entries[key] = dict(option(payload), variable_attrs=vattrs)
        except (OSError, ValueError) as e:
            errors[key] = type(e).__name__ + ': ' + (e.strerror if isinstance(e, OSError) and e.strerror else 'read/parse failure')
    order = scalars.get('BootOrder')
    present = set(entries) | {k for k in errors if re.fullmatch(r'Boot[0-9A-F]{4}', k)}
    result = {'order': order, 'next': scalars.get('BootNext'), 'current': scalars.get('BootCurrent'),
              'entries': entries, 'errors': errors}
    if order is not None:
        result['unlisted'] = sorted(present - set(order))
        result['missing_references'] = sorted(set(order) - present)
        result['duplicate_order_ids'] = len(order) - len(set(order))
        result['max_order_id'] = max((int(k[4:], 16) for k in order), default=None)
    return result


def compare(a, b):
    old, new = a['entries'], b['entries']
    unknown = set(a['errors']) | set(b['errors'])
    oldkeys, newkeys = set(old), set(new)
    return {'removed_readable': sorted(oldkeys - newkeys - unknown),
            'added_readable': sorted(newkeys - oldkeys - unknown),
            'payload_changed': sorted(k for k in oldkeys & newkeys if old[k]['sha256'] != new[k]['sha256']),
            'variable_attrs_changed': sorted(k for k in oldkeys & newkeys if old[k]['variable_attrs'] != new[k]['variable_attrs']),
            'order_before': a['order'], 'order_after': b['order'],
            'unresolved': sorted(unknown), 'complete': a['order'] is not None and b['order'] is not None and not unknown}


def self_test():
    import tempfile
    end = bytes.fromhex('7fff0400')
    bbs = bytes.fromhex('050109000500000000') + end
    def load(path):
        return struct.pack('<IH', 1, len(path)) + b'X\0\0\0' + path
    assert option(load(end))['active']
    assert option(load(bbs))['bbs']
    assert not option(load(end+end))['bbs']
    for bad in [b'', load(end[:-1]), load(b'\x01\x01\x00\x00')]:
        try:
            option(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('invalid option accepted')
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        def write(n, p):
            (r / (n+'-'+GUID)).write_bytes(struct.pack('<I', 7)+p)
        write('BootOrder', struct.pack('<HH', 1, 3))
        write('Boot0001', load(end))
        write('Boot0004', load(bbs))
        a = inspect(r)
        assert a['unlisted'] == ['Boot0004'] and a['missing_references'] == ['Boot0003']
        write('Boot0001', load(bbs))
        write('Boot0004', b'bad')
        b = inspect(r)
        c = compare(a, b)
        assert c['payload_changed'] == ['Boot0001'] and not c['removed_readable']
        assert not c['complete'] and c['unresolved'] == ['Boot0004']
    print('9 synthetic checks passed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    s = p.add_subparsers(dest='cmd', required=True)
    c = s.add_parser('capture'); c.add_argument('--root', type=Path, default=Path('/sys/firmware/efi/efivars'))
    c = s.add_parser('compare'); c.add_argument('old', type=Path); c.add_argument('new', type=Path)
    s.add_parser('self-test')
    args = p.parse_args()
    if args.cmd == 'self-test':
        self_test(); return
    try:
        out = inspect(args.root) if args.cmd == 'capture' else compare(json.loads(args.old.read_text()), json.loads(args.new.read_text()))
        print(json.dumps(out, indent=2))
    except (OSError, ValueError) as e:
        p.exit(2, f'error: {e}\n')


if __name__ == '__main__':
    main()
