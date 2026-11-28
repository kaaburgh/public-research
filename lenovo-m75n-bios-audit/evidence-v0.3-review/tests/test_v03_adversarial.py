#!/usr/bin/env python3
"""Adversarial tests for evidence protocol v0.3 (PR #4, commit 3c3c555c).

Usage: python3 test_v03_adversarial.py <path-to-evidence-v0.3> [<path-to-v1-worktree> <path-to-935daa0-worktree>]
Fixtures are built by an independent builder (not test_pilot.py): FV extended header inside a pad file,
FFS_ATTRIB_CHECKSUM, CRC32 GUID-defined sections, deleted containers, pad files with data.
Each case records the CURRENT v0.3 behaviour. 'defect' cases document behaviour this review considers
wrong; 'ok' cases confirm a fix. Exit 0 when every recorded expectation holds. No firmware, no ROMs.
"""
import copy, hashlib, json, lzma, os, struct, subprocess, sys, tempfile, time, uuid, zlib, pathlib

V03 = pathlib.Path(sys.argv[1]).resolve()
PINNED = {
    'checker.py': 'f1424feb318177dce82bb651869551e81a0b98821984f366a271c942e72ff6c1',
    'pilot.py': '48e2c001d3f055583e6b7f26db87d56e1b6586ae79b173f5d6116d1dc5c7cde0',
    'handoff.py': '239ea1a8db7355d87cbfb5c474eb2b38b8ba757a8e4dccc4f336e1515d95f911',
    'legacy_import.py': 'c3bcb1146f98ac71d43032021444c9cd646d98d59b0dac5e397effb050488c85',
    'profile.json': '5862d36f7733dfc0ee49be37ebaf89480880055b23b6a9222ab16452f90d894d',
}
for name, h in PINNED.items():
    got = hashlib.sha256((V03 / name).read_bytes()).hexdigest()
    if got != h and not os.environ.get('V03_ALLOW_UNPINNED'):
        sys.exit(f'pinned hash mismatch for {name}: {got}')
sys.path.insert(0, str(V03))
import checker, pilot, handoff, legacy_import  # noqa: E402
from checker import Checker, Invalid, canonical, digest, propose, PKCS7, X509, FFS2, LZMA  # noqa: E402

ROWS = []
def record(cid, kind, title, expected, observed, holds):
    ROWS.append({'id': cid, 'kind': kind, 'title': title, 'expected': expected, 'observed': observed, 'holds': bool(holds)})
    print(f"{'ok  ' if holds else 'FAIL'} {cid} [{kind}] {title}\n      expected: {expected}\n      observed: {observed}")

# ------------------------------------------------------------------ independent fixture builder (v03_fixtures.py)
sys.path.insert(1, str(pathlib.Path(__file__).resolve().parent))
from v03_fixtures import *  # noqa: E402,F401,F403
AUTH_HDR = auth_hdr()
assert {k: v for k, v in TARGETS.items()} == {k: v for k, v in pilot.TARGETS.items()}, 'fixture targets differ from pilot profile'

def evaluate_pair(a, b, ca=None, cb=None):
    return pilot.evaluate({'a': a, 'b': b}, {'a': ca or propose(a), 'b': cb or propose(b)})

def comp(r, tid, cid):
    row = next(x for x in r['results'] if x['id'] == tid)
    return next(c for c in row['components'] if c['id'] == cid)

def coverage(r):
    return {k: v.get('coverage', v.get('error')) for k, v in r['diagnostics'].items()}

def receipt_from(r, artifacts_pinned=True):
    """Assemble a receipt the way pilot.main() does (main() itself requires the real pinned ROMs)."""
    rc = {'profile_sha256': digest(pilot.PROFILE_PATH.read_bytes()), 'version': pilot.VERSION, 'run_id': str(uuid.uuid4()),
          'utc': '2026-11-28T00:00:00+00:00', 'runtime': sys.version.split()[0],
          'tool_sha256': {n: digest((V03 / n).read_bytes()) for n in ('pilot.py', 'checker.py')},
          'artifacts': {k: {'sha256': v, 'size': 16777216, 'expected_sha256': v} for k, v in pilot.ROMS.items()},
          'certificates': {}, 'diagnostics': {}, 'results': []}
    rc.update(copy.deepcopy(r)); rc['input_errors'] = {}; rc['summary'] = pilot.summary(rc)
    return rc

def handoff_accepts(rc):
    with tempfile.TemporaryDirectory() as d:
        raw = canonical(rc); p = pathlib.Path(d) / (digest(raw) + '.json'); p.write_bytes(raw)
        out = subprocess.run([sys.executable, str(V03 / 'handoff.py'), str(p)], capture_output=True, text=True, cwd=str(V03))
        return out.returncode, out.stdout, out.stderr.strip()

# ------------------------------------------------------------------ baseline
A, B = rom(False), rom(True)
base = evaluate_pair(A, B)
s = pilot.summary(base)
record('B01', 'ok', 'Independent builder: three targets, exact P2-47 sizes and layout, 1.32-like vs 1.33-like time fields',
       'all measured components PASS; equal_structural_signature_lists = derived_within_supported_grammar',
       f"coverage {coverage(base)}; C1..C8 {[comp(base,'SB-003',c)['verdict'] for c in ('C1','C2','C3','C5','C6','C7','C8')]}; summary {s['equal_structural_signature_lists']}",
       s['equal_structural_signature_lists'] == 'derived_within_supported_grammar')
code, out, err = handoff_accepts(receipt_from(base))
record('B02', 'ok', 'handoff renders the baseline receipt', 'exit 0', f'exit {code} {err}', code == 0)

# ------------------------------------------------------------------ K1 regression checks (payload provenance)
try:
    Checker(b'\xff' * 0x10000, [v[0] for v in pilot.TARGETS.values()]).run([{'offset': 0, 'size': 0x10000, 'kind': 'fv'}]); res = 'accepted'
except Invalid as e:
    res = f'Invalid({e})'
record('K1a', 'ok', 'Erased flash with a certificate claiming an FV (v0.2 N03 analogue)', 'rejected', res, res.startswith('Invalid'))
try:
    Checker(A, [str(GUIDS['SB-001'])]).run([{'offset': 0, 'size': len(A), 'kind': 'fv', 'payload': 'x'}]); res = 'accepted'
except Invalid as e:
    res = f'Invalid({e})'
record('K1b', 'ok', 'Certificate region with an extra "payload" field (v0.2 N04 analogue)', 'rejected: certificate cannot carry payloads', res, res.startswith('Invalid'))

# ------------------------------------------------------------------ D1: pad file hides a compressed differing copy -> stronger status than a root gap
hidden = zlib.compress(fv([target_file(t, True, b'X') for t in pilot.TARGETS], size=0x10000))
pad = ffs(PAD_NAME, 0xF0, hidden)
A1, B1 = rom(False, [pad], size=0x20000), rom(True, [pad], size=0x20000)
r_pad = evaluate_pair(A1, B1)
A2, B2 = rom(False) + hidden + b'\xff' * (-len(hidden) % 16), rom(True) + hidden + b'\xff' * (-len(hidden) % 16)
r_gap = evaluate_pair(A2, B2)
sp, sg = pilot.summary(r_pad)['equal_structural_signature_lists'], pilot.summary(r_gap)['equal_structural_signature_lists']
record('D1', 'defect', 'Same zlib-compressed differing copy: inside a pad file vs in an unparsed root gap',
       'pad file data violates PI ("must not have any data written into the data space"); v0.3 reports it as grammar_complete and gives the STRONGEST status, while the root-gap case is conditional',
       f'pad: coverage {coverage(r_pad)}, status {sp}; gap: coverage {coverage(r_gap)}, status {sg}',
       sp == 'derived_within_supported_grammar' and sg == 'consistent_conditional')
lower = str(GUIDS['SB-001'])
cl = Checker(A, [lower]).run(propose(A))
record('D1c', 'note', 'Checker target given as lowercase GUID string',
       'no normalisation: owners never match, selection silently unresolved (safe direction, but a profile typo yields BLOCKED with no diagnostic)',
       f"owners {len(cl.owners[lower])}, issues {cl.issues}", len(cl.owners[lower]) == 0 and not cl.issues)
raw_file = ffs(OTHER.bytes_le, 0x01, hidden)
r_raw = evaluate_pair(rom(False, [raw_file], size=0x20000), rom(True, [raw_file], size=0x20000))
record('D1b', 'defect', 'Same blob in an FFS RAW file (type 0x01) body',
       'uninterpreted leaf bytes are not listed anywhere; status derived_within_supported_grammar',
       f"coverage {coverage(r_raw)}, status {pilot.summary(r_raw)['equal_structural_signature_lists']}",
       pilot.summary(r_raw)['equal_structural_signature_lists'] == 'derived_within_supported_grammar')

# ------------------------------------------------------------------ D2: opaque area INSIDE the selected owner; plaintext second RAW
def owner_with_crc32(tid, newer):
    first = sec(0x19, payload(tid, newer))
    second = crc32_sec(stream(sec(0x19, payload(tid, newer, b'Z'))))
    return ffs(GUIDS[tid].bytes_le, 0x02, stream(first, second))
A3 = fv([owner_with_crc32(t, False) for t in pilot.TARGETS], size=0x10000)
B3 = fv([owner_with_crc32(t, True) for t in pilot.TARGETS], size=0x10000)
r3 = evaluate_pair(A3, B3)
c1 = comp(r3, 'SB-001', 'C1')
record('D2', 'defect', 'Owner has RAW #1 plus a CRC32 GUID-defined section (PROCESSING_REQUIRED=0) holding a plaintext RAW #2',
       'C1 "exactly one RAW in each owner" should be BLOCKED (opaque inside selector scope); v0.3 gives C1 PASS [conditional_coverage]',
       f"C1 {c1['verdict']} [{c1['assurance']}], opaque reasons {[o['reason'] for o in r3['diagnostics']['a']['opaque']][:2]}, status {pilot.summary(r3)['equal_structural_signature_lists']}",
       c1['verdict'] == 'PASS' and pilot.summary(r3)['equal_structural_signature_lists'] == 'consistent_conditional')

# ------------------------------------------------------------------ D3: FV extended header (EDK2 / AMI convention) and vacuous multiplicity
name = uuid.UUID('5C60F367-A505-419A-859E-2A4FF6CA6FE5').bytes_le
A4, B4 = rom(False, ext_name=name), rom(True, ext_name=name)
r4 = evaluate_pair(A4, B4)
record('D3a', 'defect', 'Standard FV with ExtHeaderOffset -> ext header in leading pad file (as in FVs named 4F1C52D3.../5C60F367... in the v1 A75 paths)',
       'whole FV opaque (unsupported_fv); targets not found; predicts BLOCKED on the real ROMs',
       f"opaque {[o['reason'] for o in r4['diagnostics']['a']['opaque']]}, C1 {comp(r4,'SB-001','C1')['verdict']}",
       [o['reason'] for o in r4['diagnostics']['a']['opaque']] == ['unsupported_fv'] and comp(r4, 'SB-001', 'C1')['verdict'] == 'BLOCKED')
m = comp(r4, 'SB-001', 'multiplicity')
record('D3b', 'defect', 'Multiplicity when nothing was found in either ROM',
       'vacuous 0 == 0 reported as PASS while C1 is BLOCKED',
       f"multiplicity {m['verdict']} [{m['assurance']}], counts {m['observed']['a']}",
       m['verdict'] == 'PASS' and m['observed']['a']['data_valid'] == 0)
code, out, err = handoff_accepts(receipt_from(r4))
record('D3c', 'defect', 'Generated handoff for that run', 'shows "multiplicity: PASS" next to C1 BLOCKED',
       f"exit {code}; line: {[l.strip() for l in out.splitlines() if l.strip().startswith('multiplicity')][0]}",
       code == 0 and 'multiplicity: PASS' in out)

# ------------------------------------------------------------------ D4/D5: handoff accepts edited verdicts
Aeq, Beq = rom(False), fv([target_file(t, True) for t in pilot.TARGETS] * 2, size=0x10000)
req = evaluate_pair(Aeq, Beq)
before = pilot.summary(req)['equal_structural_signature_lists']
forged = receipt_from(req)
for x in forged['results']:
    for c in x['components']:
        if c['id'] in ('C1', 'multiplicity') and c['verdict'] == 'FAIL':
            c['verdict'] = 'PASS'; c['reason'] = None
forged['summary'] = pilot.summary(forged)
code, out, err = handoff_accepts(forged)
record('D4', 'defect', 'Equivalence class (two identical live copies in b): edit C1 and multiplicity FAIL->PASS, recompute summary, rename by hash',
       'handoff should reject (counts in the same receipt show data_valid=2); it accepts and prints the promoted status',
       f"before {before}; after: exit {code}, {forged['summary']['equal_structural_signature_lists']}; counts b {forged['results'][0]['selection']['b']['counts']}",
       code == 0 and forged['summary']['equal_structural_signature_lists'] in ('derived_within_supported_grammar', 'consistent_conditional'))
Bdiff = fv([target_file(t, True, b'D') for t in pilot.TARGETS], size=0x10000)
rdiff = evaluate_pair(A, Bdiff)
forged2 = receipt_from(rdiff)
for x in forged2['results']:
    for c in x['components']:
        if c['verdict'] == 'FAIL':
            c['verdict'] = 'PASS'
forged2['summary'] = pilot.summary(forged2)
code, out, err = handoff_accepts(forged2)
c6 = comp(forged2, 'SB-001', 'C6')
record('D5', 'defect', 'Certificate lists differ (C6/C3 FAIL); flip verdicts to PASS, keep observed suffix hashes',
       'handoff does not recompute verdicts from observed values; accepts',
       f"exit {code}; C6 observed suffix hashes equal: {c6['observed']['suffix_sha256'][0] == c6['observed']['suffix_sha256'][1]}; summary {forged2['summary']['equal_structural_signature_lists']}",
       code == 0 and c6['observed']['suffix_sha256'][0] != c6['observed']['suffix_sha256'][1])

# ------------------------------------------------------------------ D6: constant semantic summary fields
sref = pilot.summary(rdiff)
record('D6', 'defect', 'Run that refutes C3/C6 (lists and diff set changed)',
       'P2-47_full and timestamp_only stay constant ("partial_not_established"/"unverified") instead of refuted',
       f"equal_structural {sref['equal_structural_signature_lists']}; byte_observations {sref['byte_observations']}; P2-47_full {sref['P2-47_full']}; timestamp_only {sref['timestamp_only_semantic_conclusion']}",
       sref['P2-47_full'] == 'partial_not_established' and sref['timestamp_only_semantic_conclusion'] == 'unverified' and sref['equal_structural_signature_lists'] == 'refuted_within_supported_grammar')

# ------------------------------------------------------------------ D7: limit converts measured refutation into BLOCKED again
many = efi_time(2025, 1, 2, 3, 4, 5) + AUTH_HDR + (X509 + struct.pack('<III', 28 + 17, 0, 17) + bytes(17)) * 4097
cp = {c['id']: c['verdict'] for c in pilot.compare_pair(many, many, len(many), 1, 'derived_in_supported_grammar')}
record('D7', 'defect', 'Verified payload with 4097 signature lists; expected 1 entry',
       'C8 is definitely false; v0.3 reports C7/C8 BLOCKED (v0.2 finding B4 reappears)', f"C7 {cp['C7']}, C8 {cp['C8']}",
       cp['C7'] == 'BLOCKED' and cp['C8'] == 'BLOCKED')

# ------------------------------------------------------------------ D8: deleted container hides a copy; not inventoried
inner = fv([target_file(t, False, b'OLD') for t in pilot.TARGETS], size=0x10000)
dead = ffs(OTHER.bytes_le, 0x0B, stream(lzma_sec(sec(0x17, inner))), state=DELETED)
A8, B8 = rom(False, [dead], size=0x20000), rom(True, [dead], size=0x20000)
r8 = evaluate_pair(A8, B8)
cnt = comp(r8, 'SB-001', 'multiplicity')['observed']['a']
record('D8', 'defect', 'Deleted FV-image file holding older target copies (LZMA)',
       'selection correct (deleted is not live), but the deleted body is neither interpreted nor listed: deleted-copy inventory says 0, coverage grammar_complete',
       f"counts {cnt}; coverage {coverage(r8)}; opaque {r8['diagnostics']['a']['opaque']}",
       cnt['deleted'] == 0 and coverage(r8)['a'] == 'grammar_complete')

# ------------------------------------------------------------------ FFS state and integrity (vs PI 1.8 Vol. 3)
def sel(image, tid='SB-001'):
    g = pilot.TARGETS[tid][0]
    return Checker(image, [g]).run(propose(image)).select(g)
good_ck = fv([target_file('SB-001', False, checksum_attr=True)])
bad = bytearray(target_file('SB-001', False, checksum_attr=True)); bad[30] ^= 1
bad_ck = fv([bytes(bad)])
x1, a1, e1 = sel(good_ck); x2, a2, e2 = sel(bad_ck)
record('S1', 'ok', 'FFS_ATTRIB_CHECKSUM: correct and corrupted file data checksum (branch not exercised by test_pilot.py)',
       'correct -> selected; corrupted -> issue, not selected', f"good {a1['selection'] if x1 else e1}; bad {e2}, issues {[i['reason'] for i in a2['issues']]}",
       x1 is not None and x2 is None and 'ffs_data_checksum' in [i['reason'] for i in a2['issues']])
for label, st in (('HEADER_INVALID', HEADER_INVALID), ('under construction (HEADER_VALID only)', UNDER_CONSTRUCTION)):
    img = fv([target_file('SB-001', False), target_file('SB-001', False, state=st)])
    x, a, e = sel(img)
    record(f"S2-{st:#x}", 'ok', f'Live target + duplicate in state {label}', 'blocks uniqueness (PI: such a file is skipped; v0.3 is stricter)',
           f"{e}, issues {[i['reason'] for i in a['issues']]}", x is None)
img = fv([target_file('SB-001', False, state=MARKED)])
x, a, e = sel(img)
record('S3', 'note', 'MARKED_FOR_UPDATE file with NO duplicate',
       'PI 1.8 Vol.3 2.2.6 EarlyFfsUpdateCheck: the marked file is the valid one; v0.3 blocks (conservative deviation)', f"{e}, counts {a['counts']}", x is None)
pad_named = ffs(GUIDS['SB-001'].bytes_le, 0xF0, b'\xff' * 32)
rp = evaluate_pair(rom(False, [pad_named]), rom(True, [pad_named]))
c1p = comp(rp, 'SB-001', 'C1')
record('S4', 'defect', 'Pad file (type 0xF0, erased body) whose Name equals the target GUID, otherwise valid images',
       'PI: pad-file names are not identities ("No checks for duplicate files should be performed on pad files"); v0.3 counts it as a second DATA_VALID owner -> C1 FAIL, proposition refuted (false refutation)',
       f"C1 {c1p['verdict']} [{c1p['assurance']}], counts {c1p['observed']['a']['counts']}, status {pilot.summary(rp)['equal_structural_signature_lists']}",
       c1p['verdict'] == 'FAIL' and pilot.summary(rp)['equal_structural_signature_lists'] == 'refuted_within_supported_grammar')
ffs3_hdr = bytearray(GUIDS['SB-001'].bytes_le + b'\0\xaa' + bytes([2, 1]) + b'\0\0\0' + b'\xf8' + struct.pack('<Q', 4096))
ffs3_hdr[16] = (-(sum(ffs3_hdr) - ffs3_hdr[17] - ffs3_hdr[23])) & 0xFF
img = fv([target_file('SB-001', False)]) + bytes(ffs3_hdr) + b'\xff' * (0x1000 - 32)
c = Checker(img, [pilot.TARGETS['SB-001'][0]]).run(propose(img))
record('S5', 'ok', 'Plaintext FFS3 large-file header with target GUID in an unparsed root gap', 'tripwire flags it, selection blocked',
       f"issues {[i['reason'] for i in c.issues]}", any(i['reason'].endswith('ffs_candidate') for i in c.issues) and c.select(pilot.TARGETS['SB-001'][0])[0] is None)

# ------------------------------------------------------------------ resource: tripwire cost is unbounded by the node limit
blob = bytearray(b'\x00' * 0x20000)
for off in range(0, len(blob) - 72, 2048):
    blob[off + 32:off + 40] = struct.pack('<Q', len(blob) - off); blob[off + 40:off + 44] = b'_FVH'; blob[off + 48:off + 50] = struct.pack('<H', 0xFFFE)
img = fv([target_file('SB-001', False)]) + bytes(blob)
t0 = time.perf_counter(); Checker(img, [pilot.TARGETS['SB-001'][0]]).run(propose(img)); dt = time.perf_counter() - t0
per = dt / (len(blob) // 2048); est = per * (16 * 2**20 // 4)
record('R1', 'note', 'Tripwire on _FVH candidates with HeaderLength 0xFFFE (64 candidates in 128 KiB)',
       'scan() is outside MAX_NODES; cost grows with candidates x HeaderLength', f"{dt:.2f}s, {per*1000:.1f} ms/candidate; a 16 MiB image with a candidate every 4 bytes ~ {est/3600:.0f} h",
       dt > 0)

# ------------------------------------------------------------------ legacy import against original artifacts
if len(sys.argv) >= 4:
    v1, ir = pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    claims = (v1 / 'lenovo-m75n-bios-audit/evidence-v1/claims.json').read_bytes()
    receipt = (ir / 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseB/official_receipt_A75.json').read_bytes()
    out = legacy_import.import_v1(claims, receipt)
    raw = canonical(out); hist = V03 / 'historical' / (digest(raw) + '.json')
    record('L1', 'ok', 'Re-run legacy import on the original git objects (4095d9c claims.json, 935daa0 receipt)',
           'byte-identical to the committed historical receipt', f"{digest(raw)} exists: {hist.exists()}, identical: {hist.exists() and hist.read_bytes() == raw}",
           hist.exists() and hist.read_bytes() == raw)
    computed = {name: pilot.state(out['results'], ids) for name, ids in pilot.profile()['propositions'].items()}
    record('L2', 'defect', 'Legacy summary is authored, not computed',
           'generic state() over the same legacy components gives a weaker byte_observations status than the stored token',
           f"stored {out['summary']['byte_observations']}; computed {computed['byte_observations']}",
           out['summary']['byte_observations'] == 'consistent_conditional_subset_only' and computed['byte_observations'] == 'unverified')
    o = json.loads(receipt)['results'][0]['observed']['diff_offsets']
    record('L3', 'note', 'v1 receipt already records the exact observed diff list',
           'C3 could be evaluated (adapter_asserted) on the recorded observation like C2/C6 are; importer keeps it OPEN — inconsistent use of recorded observations',
           f'observed {o}; C3 in import: {comp(out, "SB-001", "C3")["verdict"]}', o == [0, 2, 3, 4, 5, 6] and comp(out, 'SB-001', 'C3')['verdict'] == 'OPEN')
    tampered = json.loads(canonical(out))
    tampered['results'][0]['selected_paths'] = ['anything/else']
    with tempfile.TemporaryDirectory() as d:
        rawt = canonical(tampered); p = pathlib.Path(d) / (digest(rawt) + '.json'); p.write_bytes(rawt)
        res = subprocess.run([sys.executable, str(V03 / 'handoff.py'), str(p)], capture_output=True, text=True, cwd=str(V03))
    record('L4', 'defect', 'Legacy-import receipt with altered selected_paths (lineage) re-hashed',
           'handoff checks legacy hashes and verdict pattern but not the imported observations/paths against the pinned v1 receipt; accepted',
           f'exit {res.returncode}', res.returncode == 0)

json.dump(ROWS, open(os.environ.get('V03_RESULTS', os.devnull), 'w'), indent=1)
bad_rows = [r for r in ROWS if not r['holds']]
print(f"\n{len(ROWS) - len(bad_rows)}/{len(ROWS)} expectations hold")
sys.exit(1 if bad_rows else 0)
