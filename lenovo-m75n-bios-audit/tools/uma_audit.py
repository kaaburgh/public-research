#!/usr/bin/env python3
"""Read-only Linux UMA observations and an explicitly conditional firmware model."""
import argparse
import json
import re
import tempfile
from pathlib import Path

MIB = 1024 ** 2
FIELDS = ('vram_total', 'vis_vram_total', 'gtt_total')
SIZES = (64, 80, 96, 128, 256, 384, 512, 768, 1024, 2048, 3072, 4096, 8192, 16384, 0xffffffff)
PARAMS = ('vramlimit', 'vis_vramlimit', 'gttsize', 'gartsize', 'sg_display')


def read(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def number(path):
    s = read(path)
    return int(s) if s is not None and re.fullmatch(r'[0-9]+', s) else None


def firmware_map(sys):
    entries = []
    for p in sorted((sys / 'firmware/memmap').glob('*')):
        try:
            start, end = (int(read(p / x), 0) for x in ('start', 'end'))
            typ = read(p / 'type')
            if not typ or end < start:
                return None
            entries.append((typ, end-start+1))
        except (TypeError, ValueError):
            return None
    if not entries:
        return None
    return {'system_ram_bytes': sum(n for t,n in entries if t == 'System RAM'),
            'reserved_region_bytes': sorted(n for t,n in entries if t == 'Reserved')}


def capture(root=Path('/')):
    proc, sys = root / 'proc', root / 'sys'
    mem = read(proc / 'meminfo') or ''
    m = re.search(r'^MemTotal:\s+(\d+)\s+kB\s*$', mem, re.M)
    gpus = {}
    for p in sorted((sys / 'bus/pci/devices').glob('*')):
        if read(p / 'vendor') != '0x1002' or not (read(p / 'class') or '').startswith('0x03'):
            continue
        driver = p / 'driver'
        try:
            name = driver.resolve(strict=True).name
        except OSError:
            name = None
        gpus[p.name] = {'device': read(p / 'device'), 'driver': name,
                        **{k: number(p / ('mem_info_' + k)) for k in FIELDS}}
    return {'schema': 1, 'bios_version': read(sys / 'class/dmi/id/bios_version'),
            'kernel': read(proc / 'sys/kernel/osrelease'),
            'memtotal_bytes': int(m.group(1)) * 1024 if m else None,
            'gpus': gpus, 'firmware_map': firmware_map(sys), 'params': {k: read(sys / 'module/amdgpu/parameters' / k) for k in PARAMS},
            'memory_cmdline': sorted(x for x in (read(proc / 'cmdline') or '').split()
                                     if x.startswith(('mem=', 'memmap=', 'crashkernel=', 'amdgpu.', 'iommu=', 'amd_iommu=')))}


def compare(old, new, tolerance_mib=64):
    if old.get('schema') != 1 or new.get('schema') != 1:
        raise ValueError('unsupported capture schema')
    notes = []
    for k in ('kernel', 'params', 'memory_cmdline'):
        if old[k] != new[k]:
            notes.append(k + ' changed; attribution confounded')
    if not old['kernel'] or not new['kernel']:
        notes.append('kernel version unavailable')
    if set(old['gpus']) != set(new['gpus']):
        notes.append('GPU enumeration changed')
    pairs = []
    for bdf in sorted(set(old['gpus']) & set(new['gpus'])):
        a, b = old['gpus'][bdf], new['gpus'][bdf]
        if a['device'] == b['device'] == '0x15d8' and a['driver'] == b['driver'] == 'amdgpu':
            pairs.append((bdf, a, b))
    if len(pairs) != 1:
        return {'status': 'inconclusive', 'notes': notes + ['need exactly one matching Picasso/Raven-family amdgpu device (1002:15d8)']}
    bdf, a, b = pairs[0]
    def delta(x, y):
        return None if x is None or y is None else (y-x)/MIB
    ram = delta(old['memtotal_bytes'], new['memtotal_bytes'])
    vram = delta(a['vram_total'], b['vram_total'])
    if ram is None or vram is None:
        status = 'inconclusive_missing_counters'
    elif notes:
        status = 'inconclusive_changed_environment'
    elif vram < 0 and ram > 0 and abs(ram + vram) <= tolerance_mib:
        status = 'consistent_with_reclaimed_uma'
    elif vram < 0:
        status = 'vram_reduced_but_ram_gain_not_corresponding'
    elif vram == 0 and abs(ram) <= tolerance_mib:
        status = 'no_observed_uma_change'
    else:
        status = 'other_memory_change'
    return {'status': status, 'notes': notes, 'gpu': bdf,
            'bios_before': old['bios_version'], 'bios_after': new['bios_version'],
            'ram_delta_mib': ram, 'vram_delta_mib': vram,
            'visible_vram_delta_mib': delta(a['vis_vram_total'], b['vis_vram_total']),
            'gtt_delta_mib': delta(a['gtt_total'], b['gtt_total']),
            'firmware_ram_delta_mib': delta((old.get('firmware_map') or {}).get('system_ram_bytes'), (new.get('firmware_map') or {}).get('system_ram_bytes')),
            'tolerance_mib': tolerance_mib,
            'limit': 'Consistency check only; no proof of APCB, hardware stability or unchanged GPU workloads.'}


def model(native, amd_size, apcb_size, *, recovery=False, delivery=True, fail_after_nvram=False):
    # P2-24/25/43: model only the observed size gate and ordering.
    # The alternative CBS RouteConfig path and actual boot memory selection are outside this model.
    if recovery or not delivery or native == amd_size:
        return amd_size, apcb_size, False
    return native, apcb_size if fail_after_nvram else native, not fail_after_nvram


def self_test():
    with tempfile.TemporaryDirectory() as td:
        r = Path(td)
        def put(p, v):
            f = r / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(str(v))
        put('proc/meminfo', 'MemTotal: 6000000 kB\nMemAvailable: 1000000 kB\n')
        put('proc/sys/kernel/osrelease', '6.12.0')
        put('proc/cmdline', 'root=PRIVATE mem=8G')
        p = 'sys/bus/pci/devices/0000:05:00.0/'
        put(p + 'vendor', '0x1002'); put(p + 'device', '0x15d8'); put(p + 'class', '0x030000')
        put(p + 'mem_info_vram_total', 2048*MIB)
        driver = r/'sys/bus/pci/drivers/amdgpu'; driver.mkdir(parents=True)
        (r/(p+'driver')).symlink_to(driver)
        put('sys/firmware/memmap/0/start', '0x100000000'); put('sys/firmware/memmap/0/end', '0x17fffffff')
        put('sys/firmware/memmap/0/type', 'Reserved')
        a = capture(r)
        assert a['firmware_map']['reserved_region_bytes'] == [2048*MIB]
        put(p + 'mem_info_vram_total', 128*MIB)
        put('proc/meminfo', 'MemTotal: 7966080 kB\n')
        b = capture(r)
        assert compare(a,b)['status'] == 'consistent_with_reclaimed_uma'
        assert compare(a,b)['ram_delta_mib'] == 1920
        assert a['memory_cmdline'] == ['mem=8G']
        assert compare(a,a)['status'] == 'no_observed_uma_change'
        put('proc/meminfo', 'MemTotal: 6000000 kB\n')
        c = capture(r)
        assert compare(a,c)['status'] == 'vram_reduced_but_ram_gain_not_corresponding'
        put('proc/sys/kernel/osrelease', '6.13.0')
        assert compare(a,capture(r))['status'] == 'inconclusive_changed_environment'
        (r/(p+'mem_info_vram_total')).unlink()
        assert compare(a,capture(r))['status'] == 'inconclusive_missing_counters'
        (r/(p+'driver')).unlink()
        assert compare(a,capture(r))['status'] == 'inconclusive'
    exact = [s for s in SIZES if (s & 255) == s]
    assert exact == [64,80,96,128]
    for s in SIZES:
        for old in SIZES:
            x = s & 255
            normal = model(s,x,old)
            if s != x:
                assert normal == (s,s,True)
                failed = model(s,x,old,fail_after_nvram=True)
                assert model(s,failed[0],failed[1]) == (s,old,False)
            else:
                assert normal == (s,old,False)
            assert model(s,x,old,recovery=True) == (x,old,False)
            assert model(s,x,old,delivery=False) == (x,old,False)
    print('9 capture/comparison assertions; 15x15 conditional state cases passed')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('capture'); sub.add_parser('self-test')
    c = sub.add_parser('compare'); c.add_argument('before', type=Path); c.add_argument('after', type=Path)
    c.add_argument('--tolerance-mib', type=float, default=64)
    sub.add_parser('model')
    a = p.parse_args()
    if a.cmd == 'self-test':
        self_test(); return
    if a.cmd == 'capture':
        result = capture()
    elif a.cmd == 'compare':
        if not 0 <= a.tolerance_mib <= 1024:
            p.error('tolerance must be in [0,1024] MiB')
        result = compare(json.loads(a.before.read_text()), json.loads(a.after.read_text()), a.tolerance_mib)
    else:
        result = [{'native': s, 'callback_low_byte': s & 255, 'size_gate_taken': s != (s & 255)} for s in SIZES]
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
