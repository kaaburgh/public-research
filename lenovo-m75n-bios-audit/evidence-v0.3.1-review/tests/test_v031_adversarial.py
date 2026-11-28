#!/usr/bin/env python3
"""Adversarial tests for evidence protocol v0.3.1 (PR #6, commit 985eb325).

Usage: python3 test_v031_adversarial.py <evidence-v0.3 dir of PR #6> <v1 worktree> <935daa0 worktree>
Part A re-runs the PR #5 counterexamples (expect them fixed). Part B adds new attacks.
Each case records CURRENT behaviour: kind 'fixed' (old defect now closed), 'ok' (property holds),
'defect' (behaviour this review considers wrong), 'boundary' (documented limit of consistency checking),
'note'. Exit 0 when every recorded expectation holds. Synthetic images only; no firmware.
"""
import copy, hashlib, json, os, pathlib, struct, subprocess, sys, tempfile, uuid, zlib

V = pathlib.Path(sys.argv[1]).resolve()
PINNED = {
    'checker.py': '3cf09556789786db2cd27be36fde67f1b34d6330c368caa9cef70f34b80a8a95',
    'verdicts.py': '11551d31c5ad31b956533dbb5e7a632da84790c67fc7ab2b1530744ca26296f7',
    'pilot.py': '07bb553769ba1f3cb1ed5b2670f8d75d6368c388f6a6f0c26cebbf9e29095b31',
    'handoff.py': '0ed31e908c42fdf2fc91d361337ebbefef6806191445e99ea145982f8ef47e82',
    'legacy_import.py': '48ed15cda298b5c7f0f108ba76346dfda7363f96f07b6fd938abb1f0209621f6',
    'discovery.py': '7ee9a4aa9ef253d46b00042cc617d8bc479f5d97a823071eb24ca557f3b0176f',
    'profile.json': '0363a40fc9d2019dd169fb27013bfcff2a84ab519a2060475e2c76f8679b7306',
}
for name, h in PINNED.items():
    got = hashlib.sha256((V / name).read_bytes()).hexdigest()
    if got != h and not os.environ.get('V031_ALLOW_UNPINNED'):
        sys.exit(f'pinned hash mismatch for {name}: {got}')
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(V)); sys.path.insert(1, str(HERE))
import checker, pilot, handoff, legacy_import, verdicts  # noqa: E402
from checker import Checker, Invalid, canonical, digest  # noqa: E402
from discovery import propose  # noqa: E402
from v03_fixtures import *  # noqa: E402,F401,F403
V1 = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None
IR = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 else None

ROWS = []
def record(cid, kind, title, expected, observed, holds):
    ROWS.append({'id': cid, 'kind': kind, 'title': title, 'expected': expected, 'observed': observed, 'holds': bool(holds)})
    print(f"{'ok  ' if holds else 'FAIL'} {cid} [{kind}] {title}\n      expected: {expected}\n      observed: {observed}")

def pair(a, b):
    return pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})
def comp(r, tid, cid):
    return next(c for row in r['results'] if row['id'] == tid for c in row['components'] if c['id'] == cid)
def summ(r):
    return pilot.summary(r)
def receipt(r):
    """Assemble a receipt as pilot.main() would. Synthetic ROMs cannot have the pinned identity, so (exactly like the
    PR's own test helper) the root identity fields are overwritten with the pinned constants: this is itself the
    demonstration that root identity in a receipt is a consistency check, not evidence."""
    rc = {'profile_sha256': digest(pilot.PROFILE_PATH.read_bytes()), 'version': pilot.VERSION, 'run_id': str(uuid.uuid4()),
          'utc': '2026-11-28T00:00:00+00:00', 'runtime': sys.version.split()[0],
          'tool_sha256': {n: digest((V / n).read_bytes()) for n in ('pilot.py', 'checker.py', 'verdicts.py', 'discovery.py')},
          'artifacts': {k: {'sha256': v, 'size': 16777216, 'expected_sha256': v} for k, v in pilot.ROMS.items()},
          'certificates': {}, 'diagnostics': {}, 'results': []}
    rc.update(copy.deepcopy(r)); rc['input_errors'] = {}
    for role, sha in pilot.ROMS.items():
        root = {'stream': 0, 'kind': 'artifact', 'sha256': sha, 'size': 16777216}
        if 'lineage' in rc['diagnostics'].get(role, {}):
            rc['diagnostics'][role]['lineage'][0] = dict(root)
        for row in rc['results']:
            if role in row['selection']:
                row['selection'][role]['lineage'][0] = dict(root)
                row['components'][0]['observed'] = row['selection']
    rc['summary'] = pilot.summary(rc)
    return rc
def handoff_run(rc):
    with tempfile.TemporaryDirectory() as d:
        raw = canonical(rc); p = pathlib.Path(d) / (digest(raw) + '.json'); p.write_bytes(raw)
        out = subprocess.run([sys.executable, str(V / 'handoff.py'), str(p)], capture_output=True, text=True, cwd=str(V))
        return out.returncode, out.stdout, out.stderr.strip()
def sync_c1(rc):
    for row in rc['results']:
        row['components'][0]['observed'] = row['selection']
def resummarize(rc):
    sync_c1(rc); rc['summary'] = pilot.summary(rc)

FV_MAIN = uuid.UUID('5C60F367-A505-419A-859E-2A4FF6CA6FE5').bytes_le
WRAPPER = uuid.UUID('4F1C52D3-D824-4D2A-A2F0-EC40C23C5916').bytes_le
FVIMG = uuid.UUID('9E21FD93-9C72-4C15-8C4B-E77F1DB2D792').bytes_le

# ======================================================================= Part A: PR #5 counterexamples
A, B = rom(False), rom(True)
base = pair(A, B)
code, out, err = handoff_run(receipt(base))
record('A00', 'ok', 'Baseline synthetic pair renders', 'handoff exit 0; equal_structural consistent_conditional (leaves make coverage conditional)',
       f"exit {code} {err}; status {summ(base)['equal_structural_signature_lists']}", code == 0 and summ(base)['equal_structural_signature_lists'] == 'consistent_conditional')

hidden = zlib.compress(fv([target_file(t, True, b'X') for t in TARGETS], size=0x10000))
r = pair(rom(False, [ffs(PAD_NAME, 0xF0, hidden)], size=0x20000), rom(True, [ffs(PAD_NAME, 0xF0, hidden)], size=0x20000))
record('A-D1', 'fixed', 'Compressed differing copy inside a pad file', 'pad_file_data issue; C1 BLOCKED',
       f"issues {[i['reason'] for i in r['diagnostics']['a']['issues']]}; C1 {comp(r,'SB-001','C1')['verdict']}",
       'pad_file_data' in [i['reason'] for i in r['diagnostics']['a']['issues']] and comp(r, 'SB-001', 'C1')['verdict'] == 'BLOCKED')
raw = ffs(OTHER.bytes_le, 0x01, hidden)
r = pair(rom(False, [raw], size=0x20000), rom(True, [raw], size=0x20000))
record('A-D1b', 'fixed', 'Same blob in a RAW FFS file body', 'listed as raw_ffs_body leaf; status conditional, not derived',
       f"leaf kinds {sorted({x['kind'] for x in r['diagnostics']['a']['uninterpreted_leaves']})}; status {summ(r)['equal_structural_signature_lists']}",
       'raw_ffs_body' in {x['kind'] for x in r['diagnostics']['a']['uninterpreted_leaves']} and summ(r)['equal_structural_signature_lists'] == 'consistent_conditional')
def owner_crc(tid, new):
    return ffs(GUIDS[tid].bytes_le, 0x02, stream(sec(0x19, payload(tid, new)), crc32_sec(stream(sec(0x19, payload(tid, new, b'Z'))))))
r = pair(fv([owner_crc(t, False) for t in TARGETS], size=0x10000), fv([owner_crc(t, True) for t in TARGETS], size=0x10000))
record('A-D2', 'fixed', 'CRC32 GUID-defined section with a plaintext second RAW inside the owner', 'C1 BLOCKED opaque_in_owner',
       f"C1 {comp(r,'SB-001','C1')['verdict']} {comp(r,'SB-001','C1')['reason']}", comp(r, 'SB-001', 'C1')['reason'] == 'opaque_in_owner')
r = pair(rom(False, ext_name=FV_MAIN), rom(True, ext_name=FV_MAIN))
record('A-D3a', 'fixed', 'FV with 20-byte extended header in the leading pad file', 'parsed; C1 PASS; fv_name recorded',
       f"C1 {comp(r,'SB-001','C1')['verdict']}; fv_name {r['results'][0]['selection']['a']['owners'][0]['fv_name']}",
       comp(r, 'SB-001', 'C1')['verdict'] == 'PASS')
r = pair(b'\xff' * 0x10000 + b'opaque', b'\xff' * 0x10000 + b'opaque')
record('A-D3b', 'fixed', 'Nothing found in either ROM', 'multiplicity BLOCKED; P2-47_full not_evaluated',
       f"multiplicity {comp(r,'SB-001','multiplicity')['verdict']}; P2-47_full {summ(r)['P2-47_full']}",
       comp(r, 'SB-001', 'multiplicity')['verdict'] == 'BLOCKED' and summ(r)['P2-47_full'] == 'not_evaluated')
req = pair(rom(False), fv([target_file(t, True) for t in TARGETS] * 2, size=0x10000))
rc = receipt(req)
for row in rc['results']:
    for c in row['components']:
        if c['id'] in ('C1', 'multiplicity') and c['verdict'] == 'FAIL': c['verdict'] = 'PASS'; c['reason'] = None
resummarize(rc); code, _, err = handoff_run(rc)
record('A-D4', 'fixed', 'Edit C1/multiplicity FAIL->PASS in an equivalence-class run', 'handoff rejects', f'exit {code} {err}', code == 2)
rdiff = pair(A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000))
rc = receipt(rdiff)
for row in rc['results']:
    for c in row['components']:
        if c['verdict'] == 'FAIL': c['verdict'] = 'PASS'; c['reason'] = None
resummarize(rc); code, _, err = handoff_run(rc)
record('A-D5', 'fixed', 'Flip all FAIL verdicts to PASS, observations untouched', 'handoff rejects', f'exit {code} {err}', code == 2)
s = summ(rdiff)
record('A-D6', 'fixed', 'Lists changed: semantic summary fields', 'P2-47_full and timestamp_only report refutation',
       f"P2-47_full {s['P2-47_full']}; timestamp_only {s['timestamp_only_semantic_conclusion']}",
       s['P2-47_full'] == 'conditional_refutation' and s['timestamp_only_semantic_conclusion'] == 'conditional_refutation')
many = efi_time(2025, 1, 2, 3, 4, 5) + auth_hdr() + sig_lists([17] * 4097, b'X')
v = {c['id']: c['verdict'] for c in pilot.compare_pair(many, many, len(many), 1, 'conditional_coverage')}
record('A-D7', 'fixed', '4097 signature lists, expected 1 entry', 'C7 BLOCKED (format uncertain), C8 FAIL (count refuted)', f"C7 {v['C7']}, C8 {v['C8']}", v['C7'] == 'BLOCKED' and v['C8'] == 'FAIL')
inner = fv([target_file(t, False, b'OLD') for t in TARGETS], size=0x10000)
dead = ffs(OTHER.bytes_le, 0x0B, stream(lzma_sec(sec(0x17, inner))), state=DELETED)
r = pair(rom(False, [dead], size=0x20000), rom(True, [dead], size=0x20000))
record('A-D8', 'fixed', 'Deleted container (LZMA) holding older copies', 'deleted body inventoried; selection of live copy unaffected',
       f"deleted_uninterpreted {[x['kind'] for x in r['diagnostics']['a']['deleted_uninterpreted']]}; C1 {comp(r,'SB-001','C1')['verdict']}",
       r['diagnostics']['a']['deleted_uninterpreted'] and comp(r, 'SB-001', 'C1')['verdict'] == 'PASS')
padn = ffs(GUIDS['SB-001'].bytes_le, 0xF0, b'\xff' * 32)
r = pair(rom(False, [padn]), rom(True, [padn]))
record('A-S4', 'fixed', 'Erased pad file named like the target', 'not an owner; C1 PASS', f"C1 {comp(r,'SB-001','C1')['verdict']}, pad_count {r['diagnostics']['a']['pad_count']}",
       comp(r, 'SB-001', 'C1')['verdict'] == 'PASS')
c = Checker(A, [TARGETS['SB-001'][0].lower()]).run(propose(A))
record('A-D1c', 'fixed', 'Lowercase target GUID', 'normalised; payload selected', f"selected {c.select(TARGETS['SB-001'][0].lower())[0] is not None}",
       c.select(TARGETS['SB-001'][0].lower())[0] is not None)
blob = bytearray(b'\x00' * 0x100000)
for off in range(0, len(blob) - 72, 512):
    blob[off + 32:off + 40] = struct.pack('<Q', len(blob) - off); blob[off + 40:off + 44] = b'_FVH'; blob[off + 48:off + 50] = struct.pack('<H', 0xFFFE)
res = {}
for label, regions in (('discovery', None), ('checker', [{'offset': 0, 'size': len(A), 'kind': 'fv'}, {'offset': len(A), 'size': len(blob), 'kind': 'opaque'}])):
    try:
        Checker(A + bytes(blob), [TARGETS['SB-001'][0]]).run(regions if regions else propose(A + bytes(blob))); res[label] = 'completed'
    except Invalid as e:
        res[label] = f'Invalid({e})'
record('A-R1', 'fixed', 'Tripwire work on 2048 large-HeaderLength _FVH candidates (1 MiB): via discovery and via explicit root regions',
       'both stopped by their checksum budgets (fail closed)', json.dumps(res), all('budget' in v for v in res.values()))

# ======================================================================= Part B1: extended FV header and pad files
def ext_fv(files, ext_bytes, size=0x10000, polarity=1, pad_extra=b''):
    """FV whose leading pad file body = ext_bytes + pad_extra; ExtHeaderOffset = 72 + 24."""
    erase = 0xFF if polarity else 0
    hdr = bytearray(bytes(16) + FFS2 + struct.pack('<Q', size) + b'_FVH' + struct.pack('<IHHHBB', 0x800 if polarity else 0, 72, 0, 96, 0, 2) + struct.pack('<IIII', size // 0x1000, 0x1000, 0, 0))
    hdr[50:52] = ((-sum(struct.unpack('<36H', bytes(hdr)))) & 0xFFFF).to_bytes(2, 'little')
    body = bytes(hdr) + ffs(PAD_NAME, 0xF0, ext_bytes + pad_extra, polarity=polarity)
    for f in files:
        body += bytes([erase]) * (-len(body) % 8) + f
    return body + bytes([erase]) * (size - len(body))
def tfile(tid, new, polarity=1, tag=b'C'):
    return ffs(GUIDS[tid].bytes_le, 0x02, stream(lzma_sec(sec(0x19, payload(tid, new, tag)))), polarity=polarity)
def realistic(new, polarity=1, inner_ext=None):
    inner_ext = inner_ext if inner_ext is not None else FV_MAIN + struct.pack('<I', 20)
    inner = ext_fv([tfile(t, new, polarity) for t in TARGETS], inner_ext, size=0x10000, polarity=polarity)
    image_file = ffs(FVIMG, 0x0B, stream(lzma_sec(sec(0x17, inner))), polarity=polarity)
    return ext_fv([image_file], WRAPPER + struct.pack('<I', 20), size=0x20000, polarity=polarity)
r = pair(realistic(False), realistic(True))
sel = r['results'][0]['selection']['a']
record('B1-1', 'ok', 'Phase-A path analogue: FV(ext) > FV-image file > LZMA > FV section > FV(ext) > target > LZMA > RAW',
       'C1 PASS, owner fv_name = 5C60F367 (inner FV), LZMA streams for the FV image and each target in lineage',
       f"C1 {comp(r,'SB-001','C1')['verdict']}; fv_name {sel['owners'][0]['fv_name']}; lineage kinds {[x['kind'] for x in sel['lineage']]}",
       comp(r, 'SB-001', 'C1')['verdict'] == 'PASS' and sel['owners'][0]['fv_name'] == '5C60F367-A505-419A-859E-2A4FF6CA6FE5')
r0 = pair(realistic(False, polarity=0), realistic(True, polarity=0))
record('B1-2', 'ok', 'Same path with erase polarity 0', 'C1 PASS', f"C1 {comp(r0,'SB-001','C1')['verdict']}; coverage {r0['diagnostics']['a'].get('coverage', r0['diagnostics']['a'])}",
       comp(r0, 'SB-001', 'C1')['verdict'] == 'PASS')
used = FV_MAIN + struct.pack('<I', 28) + struct.pack('<HHI', 8, 3, 0x8000)
rent = pair(realistic(False, inner_ext=used), realistic(True, inner_ext=used))
record('B1-3', 'note', 'Inner FV extended header with one EFI_FV_EXT_TYPE_USED_SIZE entry (ExtHeaderSize 0x1C, common in EDK2 builds)',
       'whole inner FV opaque (unsupported_fv_ext_entries); all targets BLOCKED — a real-ROM risk if FV_MAIN carries entries',
       f"opaque reasons {sorted({o['reason'] for o in rent['diagnostics']['a']['opaque']})}; C1 {comp(rent,'SB-001','C1')['verdict']}",
       comp(rent, 'SB-001', 'C1')['verdict'] == 'BLOCKED' and 'unsupported_fv_ext_entries' in {o['reason'] for o in rent['diagnostics']['a']['opaque']})
img = ext_fv([tfile('SB-001', False)], FV_MAIN + struct.pack('<I', 20), pad_extra=b'\x00hidden\x00')
c = Checker(img, [TARGETS['SB-001'][0]]).run(propose(img))
record('B1-4', 'ok', 'Data after the extended header inside the leading pad file', 'pad_file_data issue', f"issues {[i['reason'] for i in c.issues]}", 'pad_file_data' in [i['reason'] for i in c.issues])
img = bytearray(ext_fv([tfile('SB-001', False)], FV_MAIN + struct.pack('<I', 20)))
img[52:54] = struct.pack('<H', 98); img[50:52] = b'\0\0'; img[50:52] = ((-sum(struct.unpack('<36H', bytes(img[:72])))) & 0xFFFF).to_bytes(2, 'little')
try:
    Checker(bytes(img), [TARGETS['SB-001'][0]]).run(propose(bytes(img))); res = 'accepted'
except Invalid as e:
    res = f'Invalid({e})'
record('B1-5', 'ok', 'ExtHeaderOffset not 4-byte aligned', 'rejected', res, res.startswith('Invalid'))
nested_pad = fv([ffs(OTHER.bytes_le, 0x0B, stream(sec(0x17, fv([ffs(PAD_NAME, 0xF0, b'data')], size=0x1000))))] + [target_file(t, False) for t in TARGETS], size=0x10000)
c = Checker(nested_pad, [TARGETS['SB-001'][0]]).run(propose(nested_pad))
record('B1-6', 'ok', 'Pad file with data in a nested FV (outside the owner)', 'pad_file_data issue blocks globally', f"issues {[i['reason'] for i in c.issues]}", 'pad_file_data' in [i['reason'] for i in c.issues])

# ======================================================================= Part B2: opacity inside / outside the owner, deletion
own_fv = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(sec(0x19, payload('SB-001', False)), sec(0x17, fv([], size=0x1000)[:16] + b'\x00' * 16 + fv([], size=0x1000)[32:])))
weird = bytearray(fv([], size=0x1000)); weird[16:32] = uuid.UUID('5473C07A-3DCB-4DCA-BD6F-1E9689E7349A').bytes_le
weird[50:52] = b'\0\0'; weird[50:52] = ((-sum(struct.unpack('<36H', bytes(weird[:72])))) & 0xFFFF).to_bytes(2, 'little')
owner = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(sec(0x19, payload('SB-001', False)), sec(0x17, bytes(weird))))
x, a, e = Checker(fv([owner]), [TARGETS['SB-001'][0]]).run(propose(fv([owner]))).select(TARGETS['SB-001'][0])
record('B2-1', 'ok', 'Owner contains an FV image section with an unsupported (FFS3) volume', 'opaque_in_owner', f'{e}', e == 'opaque_in_owner')
other = ffs(OTHER.bytes_le, 0x07, stream(sec(0x01, struct.pack('<IB', 8, 1) + b'tiano...')))
r = pair(rom(False, [other]), rom(True, [other]))
record('B2-2', 'ok', 'Unsupported compression in an unrelated file (outside the owner)', 'coverage limited, C1 PASS conditional (as specified)',
       f"C1 {comp(r,'SB-001','C1')['verdict']} [{comp(r,'SB-001','C1')['assurance']}]", comp(r, 'SB-001', 'C1')['verdict'] == 'PASS')
plain_dead = ffs(OTHER.bytes_le, 0x0B, stream(sec(0x17, fv([target_file('SB-001', False, b'OLD')], size=0x2000))), state=DELETED)
r = pair(rom(False, [plain_dead], size=0x20000), rom(True, [plain_dead], size=0x20000))
record('B2-3', 'note', 'Deleted container holding an UNCOMPRESSED older FV',
       'policy says "select valid, report deleted separately"; tripwire sees the plaintext FV inside the deleted body and blocks all targets (inconsistent with the LZMA case A-D8)',
       f"issues {sorted({i['reason'] for i in r['diagnostics']['a']['issues']})}; C1 {comp(r,'SB-001','C1')['verdict']}",
       comp(r, 'SB-001', 'C1')['verdict'] == 'BLOCKED' and 'untracked_fv' in {i['reason'] for i in r['diagnostics']['a']['issues']})

# ======================================================================= Part B3: receipt-edit ladder
def try_edit(label, mutate, rc0):
    rc = json.loads(canonical(rc0)); mutate(rc); code, _, err = handoff_run(rc); return code, err
rc0 = json.loads(canonical(receipt(base)))  # JSON round-trip: no shared in-memory lists, as in a real file
singles = {
    'verdict C6 PASS->FAIL': lambda rc: comp(rc, 'SB-001', 'C6').update(verdict='FAIL'),
    'reason text': lambda rc: comp(rc, 'SB-001', 'C2').update(reason='x'),
    'observed C2 sizes': lambda rc: comp(rc, 'SB-001', 'C2').update(observed=[841, 842]),
    'counts data_valid': lambda rc: rc['results'][0]['selection']['a']['counts'].update(data_valid=2),
    'owner state': lambda rc: rc['results'][0]['selection']['a']['owners'][0].update(state='deleted'),
    'payload sha': lambda rc: rc['results'][0]['selection']['a']['payload'].update(sha256='0' * 64),
    'locator offset': lambda rc: rc['results'][0]['selection']['a']['locators'][0].update(offset=1),
    'coverage token': lambda rc: rc['diagnostics']['a'].update(coverage='grammar_complete'),
    'diagnostic leaf removed (one place)': lambda rc: rc['diagnostics']['a']['uninterpreted_leaves'].pop(),
    'root lineage sha': lambda rc: rc['diagnostics']['a']['lineage'][0].update(sha256='1' * 64),
    'summary token': lambda rc: rc['summary'].update(byte_observations='derived_within_supported_grammar'),
    'gate status in summary': lambda rc: rc['summary']['differential_gate'].update(status='all_six_match'),
    'tool hash': lambda rc: rc['tool_sha256'].update({'checker.py': '2' * 64}),
}
res = {k: try_edit(k, f, rc0)[0] for k, f in singles.items()}
record('B3-1', 'ok', 'Single-field edits (13 kinds), re-canonicalised and renamed by digest', 'all rejected (exit 2)', json.dumps(res), all(v == 2 for v in res.values()))
cert_code = try_edit('cert', lambda rc: rc['certificates'].update(a={'artifact_sha256': '3' * 64, 'regions': []}), rc0)[0]
record('B3-2', 'defect', 'Edit the recorded root certificate (partition hints) only', 'not validated at all (artifact binding, consistency with unparsed_root rows)',
       f'exit {cert_code}', cert_code == 0)
# two-field coordinated edit: C3 observation + verdict
rsub = pair(A, fv([ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, efi_time(2026, 2, 3, 3, 4, 5) + payload(t, False)[16:]))) for t in TARGETS], size=0x10000))
rc1 = json.loads(canonical(receipt(rsub)))
before = (comp(rc1, 'SB-001', 'C3')['verdict'], comp(rc1, 'SB-001', 'C3')['observed'])
def coord_c3(rc):
    for row in rc['results']:
        c = next(x for x in row['components'] if x['id'] == 'C3'); c['observed'] = [0, 2, 3, 4, 5, 6]; c['verdict'] = 'PASS'
    resummarize(rc)
code, err = try_edit('c3', coord_c3, rc1)
record('B3-3', 'boundary', 'Coordinated edit of C3 observation AND verdict (true diff [0,2,3]) ', 'accepted although C4_plausibility in the same receipt records bytes 0..15 of a and b, which determine the diff in [0,16)',
       f'before {before}; exit {code}', code == 0)
def c3_cross_check(rc):
    """Proposed cheap consistency rule: bytes 0..39 are recoverable from C4_plausibility (hex of 0..15) and C5 (16..39)."""
    bad = []
    for row in rc['results']:
        cs = {c['id']: c for c in row['components']}
        if cs['C3']['verdict'] not in ('PASS', 'FAIL') or not isinstance(cs['C3']['observed'], list): continue
        heads = []
        for t, h in zip(cs['C4_plausibility']['observed'], cs['C5']['observed']):
            heads.append(bytes.fromhex(t) + struct.pack('<IHH', h['dwLength'], h['wRevision'], h['wCertificateType']) + uuid.UUID(h['CertType']).bytes_le)
        d40 = [i for i in range(40) if heads[0][i] != heads[1][i]]
        if [i for i in cs['C3']['observed'] if i < 40] != d40: bad.append(row['id'])
    return bad
forged = json.loads(canonical(rc1)); coord_c3(forged)
record('B3-4', 'ok', 'Proposed cross-check (observed bytes 0..39 from C4/C5 vs C3) on genuine vs coordinated-edit receipts',
       'genuine: no violation; edited: violation in all three targets', f"genuine {c3_cross_check(rc1)}; edited {c3_cross_check(forged)}",
       c3_cross_check(rc1) == [] and len(c3_cross_check(forged)) == 3)
def forge_gate(rc):
    for row in rc['results']:
        for i, role in enumerate(('a', 'b')):
            ref = pilot.REFERENCE_HASHES[row['id']][i]; s = row['selection'][role]
            s['payload']['sha256'] = ref
            for o in s['owners']:
                if o['state'] == 'data_valid': o['raw'][0]['sha256'] = ref
    resummarize(rc)
g = json.loads(canonical(rc0)); forge_gate(g); code, _, err = handoff_run(g)
record('B3-5', 'boundary', 'Coordinated edit of payload + owner RAW hashes to the six reference values', 'accepted with differential_gate all_six_match: the gate in a received receipt is not evidence; only a replay is',
       f"before {rc0['summary']['differential_gate']['status']}; after exit {code}, {g['summary']['differential_gate']['status']}", code == 0 and g['summary']['differential_gate']['status'] == 'all_six_match')
def strip_negative(rc):
    for role in ('a', 'b'):
        for s in [rc['diagnostics'][role]] + [row['selection'][role] for row in rc['results']]:
            s['uninterpreted_leaves'] = []; s['opaque'] = []; s['coverage'] = 'grammar_complete'
    for row in rc['results']:
        for c in row['components']:
            if c['assurance'] == 'conditional_coverage': c['assurance'] = 'derived_in_supported_grammar'
    resummarize(rc)
st = json.loads(canonical(rc0)); strip_negative(st); code, _, err = handoff_run(st)
record('B3-6', 'defect', 'Delete negative evidence (all leaf/opaque rows) consistently, relabel assurance',
       'accepted and promoted to derived_within_supported_grammar; cheap invariant missed: every selected RAW locator must appear in uninterpreted_leaves',
       f"exit {code}; status {st['summary']['equal_structural_signature_lists']}", code == 0 and st['summary']['equal_structural_signature_lists'] == 'derived_within_supported_grammar')
def locator_invariant(rc):
    return all(any((l['stream'], l['offset'], l['size']) == (q['stream'], q['offset'], q['size']) for l in row['selection'][role]['uninterpreted_leaves'])
               for row in rc['results'] for role in row['selection'] for q in row['selection'][role].get('locators', []))
record('B3-7', 'ok', 'Proposed invariant (selected RAW locator present among leaves)', 'holds on genuine receipt, fails on stripped one',
       f"genuine {locator_invariant(rc0)}; stripped {locator_invariant(st)}", locator_invariant(rc0) and not locator_invariant(st))

# ======================================================================= Part B4: semantic statuses, gate, exit code
same = pair(A, A)
s1 = summ(same)
record('B4-1', 'defect', 'Identical payloads (lists identical, nothing changed)',
       'P2-47_full reports a refutation solely because exact C3 ([0,2,3,4,5,6]) is part of the conjunction; lists and timestamp-only are not refuted',
       f"P2-47_full {s1['P2-47_full']}; equal_structural {s1['equal_structural_signature_lists']}; timestamp_only {s1['timestamp_only_semantic_conclusion']}",
       s1['P2-47_full'] == 'conditional_refutation' and s1['equal_structural_signature_lists'] == 'consistent_conditional' and s1['timestamp_only_semantic_conclusion'] == 'partial_not_established')
s2 = summ(rsub)
record('B4-2', 'defect', 'Only year/month/day differ ([0,2,3]); lists identical', 'same mixing: P2-47_full refuted, timestamp_only partial',
       f"C3 {comp(rsub,'SB-001','C3')['observed']}; P2-47_full {s2['P2-47_full']}; timestamp_only {s2['timestamp_only_semantic_conclusion']}",
       s2['P2-47_full'] == 'conditional_refutation' and s2['timestamp_only_semantic_conclusion'] == 'partial_not_established')
def pad1(t, new):
    p = bytearray(payload(t, new)); p[7] = 1; return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, bytes(p))))
rp = pair(fv([pad1(t, False) for t in TARGETS], size=0x10000), fv([pad1(t, True) for t in TARGETS], size=0x10000))
s3 = summ(rp)
record('B4-3', 'defect', 'EFI_TIME.Pad1 = 1 in both versions (author plausibility hypothesis fails), everything else as expected',
       'C4_plausibility FAIL turns P2-47_full into a refutation; a failed hypothesis check is reported like a refuted finding',
       f"C4_plausibility {comp(rp,'SB-001','C4_plausibility')['verdict']}; C3 {comp(rp,'SB-001','C3')['verdict']}; P2-47_full {s3['P2-47_full']}",
       comp(rp, 'SB-001', 'C4_plausibility')['verdict'] == 'FAIL' and s3['P2-47_full'] == 'conditional_refutation')
rn = pair(A, fv([ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, efi_time(2026, 2, 3, 4, 5, 6)[:8] + b'\x01' + payload(t, True)[9:]))) for t in TARGETS], size=0x10000))
record('B4-4', 'ok', 'Nanosecond byte also changed (diff [0,2..6,8], all inside EFI_TIME)', 'timestamp_only not refuted; C3 FAIL',
       f"C3 {comp(rn,'SB-001','C3')['observed']}; timestamp_only {summ(rn)['timestamp_only_semantic_conclusion']}",
       summ(rn)['timestamp_only_semantic_conclusion'] == 'partial_not_established' and comp(rn, 'SB-001', 'C3')['verdict'] == 'FAIL')
states = [x['verdict'] for y in base['results'] for x in y['components'] if x['id'] not in ('C4', 'C9')]
exit_code = 1 if 'FAIL' in states else 2 if 'BLOCKED' in states else 0
record('B4-5', 'defect', 'Exit code when every component passes but the differential gate mismatches (pilot.main logic, line 157-158)',
       'exit 0: the gate (the pilot exit criterion) does not influence the exit code',
       f"gate {summ(base)['differential_gate']['status']}; exit {exit_code}", summ(base)['differential_gate']['status'] == 'mismatch' and exit_code == 0)
swap = copy.deepcopy(base)
for row in swap['results']:
    for i, role in enumerate(('a', 'b')):
        row['selection'][role]['payload']['sha256'] = pilot.REFERENCE_HASHES[row['id']][1 - i]
record('B4-6', 'ok', 'Gate with a/b reference hashes swapped', 'mismatch (role-specific comparison)', pilot.differential(swap)['status'], pilot.differential(swap)['status'] == 'mismatch')

# ======================================================================= Part B5: FFS states
x, a, e = Checker(fv([target_file('SB-001', False, state=MARKED)]), [TARGETS['SB-001'][0]]).run(propose(fv([target_file('SB-001', False, state=MARKED)]))).select(TARGETS['SB-001'][0])
record('B5-1', 'note', 'MARKED_FOR_UPDATE without a DATA_VALID duplicate', 'still blocked (PI 2.2.6 would treat it as valid); documented, no PI-effective annotation', f"{e} {a['counts']}", x is None)
for st_, lab in ((HEADER_INVALID, 'HEADER_INVALID'), (UNDER_CONSTRUCTION, 'under construction')):
    img = fv([target_file('SB-001', False), target_file('SB-001', False, state=st_)])
    x, a, e = Checker(img, [TARGETS['SB-001'][0]]).run(propose(img)).select(TARGETS['SB-001'][0])
    record(f'B5-{lab}', 'ok', f'Live target + duplicate in state {lab}', 'blocks', f"{e}, issues {[i['reason'] for i in a['issues']]}", x is None)

# ======================================================================= Part B6: internal inconsistency during a run
real_profile = pilot.profile(); saved = dict(pilot.ROMS); old_profile, old_cmp = pilot.profile, pilot.compare_pair
A16 = A + b'\xff' * (16777216 - len(A)); B16 = B + b'\xff' * (16777216 - len(B))
with tempfile.TemporaryDirectory() as d:
    p = pathlib.Path(d); (p / 'a').write_bytes(A16); (p / 'b').write_bytes(B16)
    try:
        pilot.profile = lambda: real_profile; pilot.ROMS.update(a=digest(A16), b=digest(B16))
        def boom(*args, **kw): raise Invalid('suffix_consistency')
        pilot.compare_pair = boom
        try:
            import io, contextlib
            with contextlib.redirect_stdout(io.StringIO()):
                pilot.main(['--rom-a', str(p / 'a'), '--rom-b', str(p / 'b'), '--receipts', str(p / 'rc')]); outcome = 'returned'
        except Invalid as e:
            outcome = f'uncaught Invalid({e})'
    finally:
        pilot.profile, pilot.compare_pair = old_profile, old_cmp; pilot.ROMS.clear(); pilot.ROMS.update(saved)
    written = sorted(x.name for x in (p / 'rc').iterdir()) if (p / 'rc').exists() else []
record('B6-1', 'defect', 'An internal consistency check (verdicts.pair_components need()) fires during pilot.main()',
       'evaluate() is outside the try: the run dies with a traceback and NO receipt (contradicts "preserve failed/blocked attempts"); 6 of the review mutants were detected only this way',
       f'{outcome}; receipts written: {written}', outcome.startswith('uncaught') and written == [])

# ======================================================================= Part B7: localisation of blocking structures and determinism
bad_pad = fv([ffs(OTHER.bytes_le, 0x01, b'odd')] + [target_file(t, False) for t in TARGETS], size=0x10000, gap_fill=0x00)
r = pair(bad_pad, rom(True))
record('B7-1', 'defect', 'Real-ROM style blocker: non-erased inter-file padding (raises Invalid inside fv())',
       'role-level diagnostics carry only the code, no stream/offset: the first real blocker cannot be localised from the receipt',
       f"diagnostics a = {r['diagnostics']['a']}", r['diagnostics']['a'] == {'error': 'ffs_padding'})
lz = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(sec(0x19, payload('SB-001', False)), trailing=b'junk')))
r = pair(fv([lz] + [target_file(t, False) for t in TARGETS if t != 'SB-001'], size=0x10000), rom(True))
record('B7-2', 'defect', 'LZMA section with trailing bytes in one target', 'whole role error {"error": code}; no offset, and the two healthy targets in that ROM are blocked too',
       f"diagnostics a = {r['diagnostics']['a']}; SB-002 C1 {comp(r,'SB-002','C1')['verdict']}", 'error' in r['diagnostics']['a'] and comp(r, 'SB-002', 'C1')['verdict'] == 'BLOCKED')
r1, r2 = pair(realistic(False), realistic(True)), pair(realistic(False), realistic(True))
record('B7-3', 'ok', 'Determinism: two evaluations of the same inputs', 'canonical results identical (receipts differ only in run_id/utc/runtime): replay comparison is a simple equality test',
       f"identical: {canonical(r1) == canonical(r2)}", canonical(r1) == canonical(r2))

# ======================================================================= Part C: legacy import on the original artifacts
if V1 and IR:
    with tempfile.TemporaryDirectory() as d:
        cl = V1 / 'lenovo-m75n-bios-audit/evidence-v1/claims.json'
        rr = IR / 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseB/official_receipt_A75.json'
        out = subprocess.run([sys.executable, str(V / 'legacy_import.py'), str(cl), str(rr), d], capture_output=True, text=True, cwd=str(V))
        name = out.stdout.strip(); rec = json.loads((pathlib.Path(d) / name).read_text())
        h = subprocess.run([sys.executable, str(V / 'handoff.py'), str(pathlib.Path(d) / name)], capture_output=True, text=True, cwd=str(V))
        record('C-1', 'ok', 'Legacy import CLI on original v1 claims + A75 receipt, then handoff', 'exit 0 / 0; byte_observations unverified; legacy_byte_subset consistent_conditional; C3 OPEN',
               f"import {out.returncode} -> {name[:12]}..; handoff {h.returncode}; {rec['summary']['byte_observations']} / {rec['summary']['legacy_byte_subset']}; C3 {comp(rec,'SB-001','C3')['verdict']}",
               out.returncode == 0 and h.returncode == 0 and rec['summary']['byte_observations'] == 'unverified' and rec['summary']['legacy_byte_subset'] == 'consistent_conditional' and comp(rec, 'SB-001', 'C3')['verdict'] == 'OPEN')
        record('C-2', 'ok', 'Generated legacy receipt digest equals the one reported in TEST_RESULTS.md', 'f2793d27...', name, name.startswith('f2793d270efa9f2cbd484358fe33cf0b8d0fe58510a223b3ced87b197327c88c'))
        up = copy.deepcopy(rec); comp(up, 'SB-001', 'C3').update(verdict='PASS', observed=[0, 2, 3, 4, 5, 6], reason=None)
        up['summary'] = legacy_import.legacy_summary(up['results'])
        code, _, err = handoff_run(up)
        record('C-3', 'ok', 'Upgrade legacy C3 to exact PASS using the recorded v1 observation', 'rejected', f'exit {code} {err}', code == 2)

json.dump(ROWS, open(os.environ.get('V031_RESULTS', os.devnull), 'w'), indent=1)
bad = [r for r in ROWS if not r['holds']]
print(f"\n{len(ROWS) - len(bad)}/{len(ROWS)} expectations hold")
sys.exit(1 if bad else 0)
