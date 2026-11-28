#!/usr/bin/env python3
"""Adversarial tests for evidence protocol v0.3.2 (PR #8, commit 0cbac26f).
Usage: python3 test_v032_adversarial.py <evidence-v0.3 dir of PR #8> [<v1 worktree> <935daa0 worktree>]
Records CURRENT behaviour. Kinds: ok (property holds), defect, boundary (limit of consistency checking), note.
Exit 0 when every recorded expectation holds. Synthetic images only; no firmware."""
import contextlib, copy, hashlib, io, json, os, pathlib, struct, subprocess, sys, tempfile, uuid
from unittest.mock import patch

V = pathlib.Path(sys.argv[1]).resolve()
PINNED = {
    'checker.py': 'f709880c9d1104cdd5dd13117a36281f05d89ec1f665581997f4f0fffabd3f9c',
    'verdicts.py': '2d40eb998fdbe5399d6bb400c83c0fd8012f21dfbe18b2fb70f9f5ae31048acd',
    'pilot.py': '007c3e9b57f7a938d96d3deeb644e9d6103cf7342f09c780e5685fcd407e83fe',
    'handoff.py': '6c9faf5c060de71e8cdd1d97d93ee540e9cd6683d99b29c793a57035f75d705e',
    'replay_compare.py': 'a39a997a347540df7f0838889ba8d615be50c0d3f26d2b41237a111a5ca3390d',
    'legacy_import.py': '48ed15cda298b5c7f0f108ba76346dfda7363f96f07b6fd938abb1f0209621f6',
    'discovery.py': '7ee9a4aa9ef253d46b00042cc617d8bc479f5d97a823071eb24ca557f3b0176f',
    'profile.json': '249101b149091731ceb0da71c7905d366ac90a0803b04fd4d69251ec3bcfd67b',
}
for name, h in PINNED.items():
    if hashlib.sha256((V / name).read_bytes()).hexdigest() != h and not os.environ.get('V032_ALLOW_UNPINNED'):
        sys.exit(f'pinned hash mismatch for {name}')
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(V)); sys.path.insert(1, str(HERE))
import checker, pilot, handoff, verdicts, replay_compare  # noqa: E402
from checker import Checker, Invalid, canonical, digest  # noqa: E402
from discovery import propose  # noqa: E402
from v03_fixtures import *  # noqa: E402,F401,F403

ROWS = []
def record(cid, kind, title, expected, observed, holds):
    ROWS.append({'id': cid, 'kind': kind, 'title': title, 'expected': expected, 'observed': observed, 'holds': bool(holds)})
    print(f"{'ok  ' if holds else 'FAIL'} {cid} [{kind}] {title}\n      expected: {expected}\n      observed: {observed}")

def pair(a, b): return pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})
def comp(r, tid, cid): return next(c for row in r['results'] if row['id'] == tid for c in row['components'] if c['id'] == cid)
def summ(r):
    s = dict(r); s.setdefault('input_errors', {}); return pilot.summary(s)
def receipt(r):
    """As pilot.main() would assemble it; synthetic roots are overwritten with the pinned identities and the
    root partition is completed to 16 MiB (same adaptation as the PR's own fixture)."""
    rc = {'profile_sha256': digest(pilot.PROFILE_PATH.read_bytes()), 'version': pilot.VERSION, 'run_id': str(uuid.uuid4()),
          'utc': '2026-11-28T00:00:00+00:00', 'runtime': sys.version.split()[0],
          'tool_sha256': {n: digest((V / n).read_bytes()) for n in ('pilot.py', 'checker.py', 'verdicts.py', 'discovery.py')},
          'artifacts': {k: {'sha256': v, 'size': 16777216, 'expected_sha256': v} for k, v in pilot.ROMS.items()},
          'certificates': {}, 'diagnostics': {}, 'results': []}
    rc.update(copy.deepcopy(r)); rc['input_errors'] = {}
    for role, sha in pilot.ROMS.items():
        root = {'stream': 0, 'kind': 'artifact', 'sha256': sha, 'size': 16777216}
        q = rc['diagnostics'].get(role, {})
        if 'lineage' in q: q['lineage'][0] = dict(root)
        regions = copy.deepcopy(q.get('root_regions', []))
        length = sum(x['size'] for x in regions)
        if length < 16777216: regions.append({'offset': length, 'size': 16777216 - length, 'kind': 'erased'})
        if 'root_regions' in q: q['root_regions'] = regions
        rc['certificates'][role] = {'artifact_sha256': sha, 'regions': regions}
        for row in rc['results']:
            if role in row['selection']: row['selection'][role]['lineage'][0] = dict(root)
    resync(rc)
    return json.loads(canonical(rc))
def resync(rc):
    for row in rc['results']: row['components'][0]['observed'] = row['selection']
    rc['summary'] = pilot.summary(rc)
def handoff_run(rc):
    with tempfile.TemporaryDirectory() as d:
        raw = canonical(rc); p = pathlib.Path(d) / (digest(raw) + '.json'); p.write_bytes(raw)
        o = subprocess.run([sys.executable, str(V / 'handoff.py'), str(p)], capture_output=True, text=True, cwd=str(V))
        return o.returncode, o.stdout, o.stderr.strip()
def force_gate(r):
    for row in r['results']:
        for i, role in enumerate(('a', 'b')):
            if 'payload' in row['selection'].get(role, {}): row['selection'][role]['payload']['sha256'] = pilot.REFERENCE_HASHES[row['id']][i]
    r.setdefault('input_errors', {}); r['summary'] = pilot.summary(r); return r
def image(build, new):
    return fv([build(t, new) for t in TARGETS], size=0x10000)
def pf(t, new, edit=None, extra=b''):
    p = bytearray(payload(t, new))
    if edit: edit(p, new)
    return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, bytes(p) + (extra if new else b''))))
A, B = rom(False), rom(True)
A16 = A + b'\xff' * (16777216 - len(A)); B16 = B + b'\xff' * (16777216 - len(B))

@contextlib.contextmanager
def synthetic_identity():
    """Let pilot.main() accept the synthetic 16 MiB images (the PR's own tests use the same technique)."""
    real = pilot.profile(); saved = dict(pilot.ROMS); old = pilot.profile
    try:
        pilot.profile = lambda: real; pilot.ROMS.update(a=digest(A16), b=digest(B16)); yield
    finally:
        pilot.profile = old; pilot.ROMS.clear(); pilot.ROMS.update(saved)
def run_main(extra_patch=None, receipts=None):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d); (p / 'a').write_bytes(A16); (p / 'b').write_bytes(B16)
        out = io.TextIOWrapper(io.BytesIO()); code = None; exc = None
        with synthetic_identity(), contextlib.redirect_stdout(out):
            ctx = extra_patch() if extra_patch else contextlib.nullcontext()
            with ctx:
                try: code = pilot.main(['--rom-a', str(p / 'a'), '--rom-b', str(p / 'b'), '--receipts', str(receipts or p / 'rc')])
                except BaseException as e: exc = f'{type(e).__name__}({e})'
        files = sorted((p / 'rc').iterdir()) if (p / 'rc').exists() else []
        rec = json.loads(files[0].read_text()) if files else None
        return code, exc, rec

# ======================================================================= P1 aborted receipts
code, exc, rec = run_main(lambda: patch.object(pilot, 'propose', side_effect=ValueError('boom /home/x')))
record('P1-1', 'ok', 'Unexpected exception during input (discovery)', 'aborted receipt stage input, sanitized code, exit 2',
       f"exit {code}, exc {exc}, run_error {rec and rec.get('run_error')}, path leaked {'/home/x' in json.dumps(rec)}",
       code == 2 and rec['run_error'] == {'stage': 'input', 'code': 'ValueError'} and '/home/x' not in json.dumps(rec))
big = {'P2-47_full': 'x', 'pad': ['y' * 4000] * 3000}
code, exc, rec = run_main(lambda: patch.object(pilot, 'summary', return_value=big))
record('P1-2', 'ok', 'Oversize normal receipt', 'aborted at receipt_encoding, exit 2', f"exit {code}, run_error {rec and rec.get('run_error')}",
       code == 2 and rec['run_error'] == {'stage': 'receipt_encoding', 'code': 'receipt_size'})
code, exc, rec = run_main(lambda: patch.object(pilot, 'summary', side_effect=Invalid('ümlaut')))
record('P1-3', 'ok', 'Invalid with a non-ASCII code', 'code replaced by the class name', f"run_error {rec and rec.get('run_error')}", rec['run_error']['code'] == 'Invalid')
def broken_sections():
    return patch.object(checker.Checker, 'sections', side_effect=IndexError('bug'))
code, exc, rec = run_main(broken_sections)
record('P1-4', 'note', 'Non-Invalid exception inside the checker (implementation bug) during evaluate',
       'whole run aborted: diagnostics and parser location of BOTH roles are dropped (only Invalid gets a location)',
       f"exit {code}, run_error {rec and rec.get('run_error')}, diagnostics {rec and rec.get('diagnostics')}",
       code == 2 and rec['run_error'] == {'stage': 'evaluate', 'code': 'IndexError'} and rec['diagnostics'] == {})
with tempfile.TemporaryDirectory() as d:
    blocker = pathlib.Path(d) / 'file'; blocker.write_text('x')
    code, exc, rec = run_main(lambda: patch.object(pilot, 'summary', side_effect=RuntimeError('x')), receipts=blocker / 'sub')
record('P1-5', 'ok', 'Aborted run whose receipt directory is unwritable', 'exit 3 (receipt on stdout)', f'exit {code} exc {exc}', code == 3)
with patch.object(pilot, 'profile', side_effect=Invalid('profile_mismatch')):
    try:
        with tempfile.TemporaryDirectory() as d:
            pilot.main(['--rom-a', 'x', '--rom-b', 'y', '--receipts', d]); res = 'returned'
    except Invalid as e:
        res = f'uncaught Invalid({e})'
record('P1-6', 'note', 'Profile mismatch before metadata initialisation', 'traceback, no receipt (documented limit)', res, res.startswith('uncaught'))
code, exc, rec = run_main(lambda: patch.object(pilot, 'summary', side_effect=RuntimeError('x')))
for role in rec['artifacts']:  # synthetic identities -> pinned ones, as the receipt() helper does for normal receipts
    rec['artifacts'][role].update(sha256=pilot.ROMS[role], expected_sha256=pilot.ROMS[role])
rc_code, out, err = handoff_run(rec)
record('P1-7', 'ok', 'Handoff on an aborted receipt', 'accepted, prints aborted + exit criterion not_met, no component results', f"exit {rc_code}; {[l for l in out.splitlines() if 'Aborted' in l or 'exit criterion' in l]}",
       rc_code == 0 and 'Aborted execution' in out and 'not_met' in out)
# suppression: a refuting normal receipt re-written as "aborted"
rref = receipt(pair(A, image(lambda t, n: pf(t, n, None), True) if False else fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000)))
sup = {k: v for k, v in rref.items() if k not in ('results', 'diagnostics', 'certificates', 'summary')}
sup.update(results=[], diagnostics={}, certificates={}, run_error={'stage': 'evaluate', 'code': 'ValueError'},
           certificate_sha256={k: digest(canonical(v)) for k, v in rref['certificates'].items()}, summary=pilot.error_summary())
code, out, err = handoff_run(sup)
record('P1-8', 'boundary', 'A refuting receipt (lists changed) rewritten as an aborted run', 'accepted: a negative result can be hidden as an abort; only replay distinguishes',
       f"original P2-47_full {rref['summary']['P2-47_full']}; rewritten handoff exit {code}", code == 0 and rref['summary']['P2-47_full'] == 'conditional_refutation')

# ======================================================================= P2 localisation
inner = lzma_sec(sec(0x19, payload('SB-001', False)) + b'\x03\x00\x00\x19')
f2 = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(stream(inner))))
q = pair(fv([f2] + [target_file(t, False) for t in TARGETS if t != 'SB-001'], size=0x10000), B)['diagnostics']['a']
record('P2-1', 'ok', 'Malformed section in an LZMA stream nested in another LZMA stream', 'location stream 2 with lineage 2 -> 1 -> 0',
       f"error {q.get('error')} stage {q.get('stage')} stream {q.get('stream')} offset {q.get('offset')}; parents {[x.get('parent_stream') for x in q.get('lineage', [])]}",
       q.get('stream') == 2 and [x.get('parent_stream') for x in q['lineage']] == [None, 0, 1])
bad_bm = bytearray(fv([target_file('SB-001', False)], size=0x2000)); bad_bm[56:60] = struct.pack('<I', 1)
bad_bm[50:52] = b'\0\0'; bad_bm[50:52] = ((-sum(struct.unpack('<36H', bytes(bad_bm[:72])))) & 0xFFFF).to_bytes(2, 'little')
holder = ffs(OTHER.bytes_le, 0x0B, stream(lzma_sec(sec(0x17, bytes(bad_bm)))))
q = pair(fv([holder] + [target_file(t, False) for t in TARGETS], size=0x10000), B)['diagnostics']['a']
record('P2-2', 'ok', 'Bad block map in an FV inside an LZMA FV-image section', 'stage fv_blockmap in stream 1 at the block-map entry',
       f"{ {k: q.get(k) for k in ('error', 'stage', 'stream', 'offset')} }", q.get('error') == 'fv_blockmap' and q.get('stream') == 1 and q.get('stage') == 'fv_blockmap')
blob = bytearray(1 << 20)
for off in range(0, len(blob) - 72, 512):
    blob[off + 32:off + 40] = struct.pack('<Q', len(blob) - off); blob[off + 40:off + 44] = b'_FVH'; blob[off + 48:off + 50] = struct.pack('<H', 0xFFFE)
img = A + bytes(blob)
r = pilot.evaluate({'a': img, 'b': B}, {'a': [{'offset': 0, 'size': len(A), 'kind': 'fv'}, {'offset': len(A), 'size': len(blob), 'kind': 'opaque'}], 'b': propose(B)})
q = r['diagnostics']['a']
record('P2-3', 'ok', 'Tripwire checksum budget exhausted', 'located at the candidate (stage tripwire_fv)', f"{ {k: q.get(k) for k in ('error', 'stage', 'stream', 'offset')} }",
       q.get('error') == 'tripwire_checksum_budget' and q.get('stage') == 'tripwire_fv')
rc = receipt(pair(fv([f2] + [target_file(t, False) for t in TARGETS if t != 'SB-001'], size=0x10000), B))
code, out, err = handoff_run(rc)
record('P2-4', 'ok', 'Handoff of a run with a located structural blocker', 'renders the blocker with stage/stream/offset; exit criterion not met',
       f"exit {code}; {[l.strip()[:110] for l in out.splitlines() if 'blocker' in l]}; exit_criterion {rc['summary']['exit_criterion']}",
       code == 0 and 'structural/input blocker' in out and rc['summary']['exit_criterion'] == 'not_met')

# ======================================================================= P3 matrix
def setb(i, v):
    def e(p, new):
        if new: p[i] = v
    return e
def both(i, raw):
    def e(p, new): p[i:i + len(raw)] = raw
    return e
def pad1(p, new): p[7] = 1
def hsize4(t, new):
    t_ = efi_time(2026, 2, 3, 4, 5, 6) if new else efi_time(2025, 1, 2, 3, 4, 5)
    lists = sig_lists([e - 4 for e in LAYOUT[t]], b'C', header_size=4)
    return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, t_ + auth_hdr() + lists)))
cases = [
    ('identical', rom(False), rom(False)),
    ('subset [0,2,3]', A, image(lambda t, n: pf(t, n, lambda p, new: p.__setitem__(slice(4, 7), bytes(payload(t, False)[4:7])) if new else None), True)),
    ('exact (baseline)', A, B),
    ('+ year high byte (1)', A, image(lambda t, n: pf(t, n, setb(1, 0x08)), True)),
    ('+ nanosecond byte (8)', A, image(lambda t, n: pf(t, n, setb(8, 1)), True)),
    ('+ wRevision byte (20)', A, image(lambda t, n: pf(t, n, setb(20, 0x01)), True)),
    ('wRevision 0x100 both', image(lambda t, n: pf(t, n, both(20, b'\x00\x01')), False), image(lambda t, n: pf(t, n, both(20, b'\x00\x01')), True)),
    ('dwLength 25 both', image(lambda t, n: pf(t, n, both(16, b'\x19')), False), image(lambda t, n: pf(t, n, both(16, b'\x19')), True)),
    ('SignatureHeaderSize 4', image(hsize4, False), image(hsize4, True)),
    ('lists differ', A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000)),
    ('length +1', A, image(lambda t, n: pf(t, n, None, b'+'), True)),
    ('EFI_TIME Pad1=1 both', image(lambda t, n: pf(t, n, pad1), False), image(lambda t, n: pf(t, n, pad1), True)),
    ('equivalence class in b + lists differ', A, fv([target_file(t, True, b'D') for t in TARGETS] * 2, size=0x10000)),
]
keys = ['exact_diff_set', 'historical_diff_bound', 'historical_diff_scope', 'timestamp_only_bytes', 'timestamp_only_semantic_conclusion',
        'historical_dwLength', 'historical_x509_count', 'equal_structural_signature_lists', 'x509_tag_and_entry_counts', 'P2-47_full']
short = {'consistent_conditional': 'cons', 'conditional_refutation': 'REF', 'refuted_within_supported_grammar': 'REF!', 'partial_not_established': 'part',
         'unverified': 'unv', 'not_evaluated': 'n/e', 'derived_within_supported_grammar': 'der'}
MATRIX = {}
for name, a, b in cases:
    r = force_gate(pair(a, b)); s = r['summary']
    MATRIX[name] = {k: short.get(s[k], s[k]) for k in keys}; MATRIX[name]['exit'] = pilot.exit_code(r)
print('\nP3 matrix (gate forced to match so that exit codes reflect the propositions):')
print(f"{'case':40} " + ' '.join(f'{k[:14]:>14}' for k in keys) + '  exit')
for name, row in MATRIX.items():
    print(f'{name:40} ' + ' '.join(f'{row[k]:>14}' for k in keys) + f"  {row['exit']}")
print()
M = MATRIX
record('P3-1', 'ok', 'Identical payloads / subset: exact set refuted, historical bound holds', 'exact REF, bound cons, P2-47_full part (not refuted)',
       f"identical {M['identical']['exact_diff_set']}/{M['identical']['historical_diff_bound']}/{M['identical']['P2-47_full']}; subset {M['subset [0,2,3]']['P2-47_full']}",
       M['identical']['P2-47_full'] == 'part' and M['subset [0,2,3]']['P2-47_full'] == 'part' and M['identical']['exact_diff_set'] == 'REF')
record('P3-2', 'ok', 'No change at all: change-occurrence clause reported separately', 'historical_diff_scope REF while P2-47_full part', f"scope {M['identical']['historical_diff_scope']}",
       M['identical']['historical_diff_scope'] == 'REF' and M['identical']['P2-47_full'] == 'part')
record('P3-3', 'ok', 'Bytes 1 or 8 changed (inside EFI_TIME, outside the historical 0,2-6 bound)', 'bound REF -> P2-47_full REF; timestamp_only_bytes cons',
       f"byte1 {M['+ year high byte (1)']['P2-47_full']}/{M['+ year high byte (1)']['timestamp_only_bytes']}; byte8 {M['+ nanosecond byte (8)']['P2-47_full']}/{M['+ nanosecond byte (8)']['timestamp_only_bytes']}",
       M['+ year high byte (1)']['P2-47_full'] == 'REF' and M['+ year high byte (1)']['timestamp_only_bytes'] == 'cons' and M['+ nanosecond byte (8)']['timestamp_only_bytes'] == 'cons')
record('P3-4', 'ok', 'Stronger hypotheses fail (C5 wRevision both, C8 header size, EFI_TIME Pad1): weaker historical claim not refuted', 'P2-47_full part in all three',
       f"{M['wRevision 0x100 both']['P2-47_full']}/{M['SignatureHeaderSize 4']['P2-47_full']}/{M['EFI_TIME Pad1=1 both']['P2-47_full']}; equal_structural {M['wRevision 0x100 both']['equal_structural_signature_lists']}; x509_counts(strong) {M['SignatureHeaderSize 4']['x509_tag_and_entry_counts']} vs historical {M['SignatureHeaderSize 4']['historical_x509_count']}",
       all(M[k]['P2-47_full'] == 'part' for k in ('wRevision 0x100 both', 'SignatureHeaderSize 4', 'EFI_TIME Pad1=1 both')))
record('P3-5', 'ok', 'Historical facts themselves changed (dwLength 25, lists differ, header byte 20, length)', 'P2-47_full REF in all four',
       f"{[M[k]['P2-47_full'] for k in ('dwLength 25 both', 'lists differ', '+ wRevision byte (20)', 'length +1')]}",
       all(M[k]['P2-47_full'] == 'REF' for k in ('dwLength 25 both', 'lists differ', '+ wRevision byte (20)', 'length +1')))
eq = M['equivalence class in b + lists differ']
record('P3-6', 'defect', 'Two identical live copies in b (C1 FAIL) whose lists differ from a (C6 FAIL on a well-defined content class)',
       'the C1-prerequisite override replaces a measured historical refutation by "partial_not_established"',
       f"equal_structural {eq['equal_structural_signature_lists']}; byte_obs-level C6 FAIL hidden: P2-47_full {eq['P2-47_full']}; exit {eq['exit']}",
       eq['P2-47_full'] == 'part' and eq['exit'] == 1)

rmask = pair(A, fv([target_file(t, True, b'D') for t in TARGETS if t != 'SB-001'], size=0x10000)); smask = summ(rmask)
per = {row['id']: [c['verdict'] for c in pilot.historical_components([row])[0]['components'] if c['id'] == 'historical_diff_bound'][0] for row in rmask['results']}
record('P3-7', 'defect', 'SB-001 absent from b; SB-002 and SB-003 lists changed (historical bound FAIL there)',
       'the C1 override is global over all three targets: a refutation measured on SB-002/003 is reported as partial_not_established',
       f"per-target historical_diff_bound {per}; C1 {[comp(rmask, t, 'C1')['verdict'] for t in TARGETS]}; P2-47_full {smask['P2-47_full']}; exit {pilot.exit_code(force_gate(rmask))}",
       per['SB-002'] == 'FAIL' and smask['P2-47_full'] == 'partial_not_established')

# ======================================================================= P4 exit codes
def ec(r): r.setdefault('input_errors', {}); r['summary'] = pilot.summary(r); return pilot.exit_code(r)
codes = {
    'all pass, gate match': pilot.exit_code(force_gate(pair(A, B))),
    'all pass, gate mismatch': ec(pair(A, B)),
    'refuted, gate match': pilot.exit_code(force_gate(pair(A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000)))),
    'refuted, gate mismatch': ec(pair(A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000))),
    'one role blocked': ec(pilot.evaluate({'a': A, 'b': B}, {'a': propose(A), 'b': [{'offset': 0, 'size': len(B), 'kind': 'opaque'}]})),
}
r_partial = force_gate(pair(A, B)); del r_partial['results'][0]['selection']['a']['payload']; r_partial['summary'] = pilot.summary(r_partial)
codes['one payload missing, others match'] = pilot.exit_code(r_partial)
r_mix = pair(A, B); del r_mix['results'][0]['selection']['a']['payload']; codes['one missing, others mismatch'] = ec(r_mix)
r_c7 = force_gate(pair(A, B)); comp(r_c7, 'SB-001', 'C7')['verdict'] = 'BLOCKED'; r_c7['summary'] = pilot.summary(r_c7); codes['gate match, a component BLOCKED'] = pilot.exit_code(r_c7)
expected_codes = {'all pass, gate match': 0, 'all pass, gate mismatch': 4, 'refuted, gate match': 1, 'refuted, gate mismatch': 4, 'one role blocked': 2,
                  'one payload missing, others match': 2, 'one missing, others mismatch': 2, 'gate match, a component BLOCKED': 2}
record('P4-1', 'ok', 'Exit-code table', json.dumps(expected_codes), json.dumps(codes), codes == expected_codes)
weak_only = {k: (MATRIX[k]['exit'], MATRIX[k]['P2-47_full']) for k in ('identical', 'subset [0,2,3]', 'wRevision 0x100 both', 'SignatureHeaderSize 4', 'EFI_TIME Pad1=1 both')}
record('P4-3', 'defect', 'Only strengthened hypotheses refuted (exact C3, full C5, C8 header size, plausibility); historical P2-47 intact',
       'exit 1 ("checked refutation") although P2-47_full is partial_not_established: the exit code does not separate strengthened from historical refutation',
       json.dumps(weak_only), all(v == (1, 'part') for v in weak_only.values()))
record('P4-2', 'note', 'Refutation together with a gate mismatch', 'exit 4 dominates 1: the refutation is visible only in the summary', f"{codes['refuted, gate mismatch']}", codes['refuted, gate mismatch'] == 4)

# ======================================================================= P5/P6 coordinated edits
base = receipt(pair(A, B))
ALZ, BLZ = fv([target_file(t, False, wrap='lzma') for t in TARGETS], size=0x10000), fv([target_file(t, True, wrap='lzma') for t in TARGETS], size=0x10000)
base_lz = receipt(pair(ALZ, BLZ))
def edit(fn, src=None, why=False):
    rc = json.loads(canonical(src or base)); fn(rc); c, _, e = handoff_run(rc); return f'{c} {e}'.strip() if why else c
singles = {
    'C3 observed only': lambda rc: comp(rc, 'SB-001', 'C3').update(observed=[0, 2, 3]),
    'C3 observed + verdict': lambda rc: (comp(rc, 'SB-001', 'C3').update(observed=[0, 2, 3], verdict='FAIL'), resync(rc)),
    'remove every leaf, relabel to grammar_complete/derived': None,
    'certificate region size': lambda rc: rc['certificates']['a']['regions'][0].update(size=rc['certificates']['a']['regions'][0]['size'] - 8),
    'lineage parent forward': lambda rc: (rc['diagnostics']['a']['lineage'][1].update(parent_stream=1)),
}
def strip(rc):
    for role in ('a', 'b'):
        for s in [rc['diagnostics'][role]] + [row['selection'][role] for row in rc['results']]: s['uninterpreted_leaves'] = []; s['coverage'] = 'grammar_complete'
    for row in rc['results']:
        for c in row['components']:
            if c['assurance'] == 'conditional_coverage': c['assurance'] = 'derived_in_supported_grammar'
    resync(rc)
singles['remove every leaf, relabel to grammar_complete/derived'] = strip
res = {k: edit(f, base_lz if k.startswith('lineage') else None, why=True) for k, f in singles.items()}
record('P6-1', 'ok', 'Edits that v0.3.1 accepted or that P6 targets', 'all rejected (exit 2) with a named code', json.dumps(res), all(v.startswith('2 HANDOFF_REJECTED') for v in res.values()))
rsub = pair(A, image(lambda t, n: pf(t, n, lambda p, new: p.__setitem__(slice(4, 7), bytes(payload(t, False)[4:7])) if new else None), True))
bs = receipt(rsub)
def three_field(rc):
    for row in rc['results']:
        c3 = next(c for c in row['components'] if c['id'] == 'C3'); c4 = next(c for c in row['components'] if c['id'] == 'C4_plausibility')
        c3['observed'] = [0, 2, 3, 4, 5, 6]; c3['verdict'] = 'PASS'
        c4['observed'][1] = efi_time(2026, 2, 3, 4, 5, 6).hex()
    resync(rc)
code = edit(three_field, bs)
record('P6-2', 'boundary', 'Coordinated three-field edit: C3 observed + verdict + recorded EFI_TIME prefix of b', 'accepted (consistent fabrication)',
       f"before exact_diff_set {bs['summary']['exact_diff_set']}; handoff exit {code}", code == 0 and bs['summary']['exact_diff_set'] == 'conditional_refutation')
def forge_gate(rc):
    for row in rc['results']:
        for i, role in enumerate(('a', 'b')):
            ref = pilot.REFERENCE_HASHES[row['id']][i]; s = row['selection'][role]; s['payload']['sha256'] = ref
            for o in s['owners']:
                if o['state'] == 'data_valid': o['raw'][0]['sha256'] = ref
    resync(rc)
g = json.loads(canonical(base)); forge_gate(g); code = handoff_run(g)[0]
record('P6-3', 'boundary', 'Payload + owner RAW digests set to the six reference values', 'accepted, exit_criterion met (a received gate is not evidence)',
       f"handoff exit {code}; gate {g['summary']['differential_gate']['status']}; exit_criterion {g['summary']['exit_criterion']}; exit_code {pilot.exit_code(g)}",
       code == 0 and g['summary']['exit_criterion'] == 'met')
other = ffs(OTHER.bytes_le, 0x07, stream(sec(0x01, struct.pack('<IB', 8, 1) + b'tiano...')))
bo = receipt(pair(rom(False, [other]), rom(True, [other])))
def erase_opaque(rc):
    for role in ('a', 'b'):
        for s in [rc['diagnostics'][role]] + [row['selection'][role] for row in rc['results']]:
            s['opaque'] = [x for x in s['opaque'] if x['reason'] != 'unsupported_compression']; s['coverage'] = 'leaf_conditional'
    resync(rc)
code = edit(erase_opaque, bo)
record('P6-4', 'boundary', 'Delete non-root opaque rows (unsupported compression): except_opaque -> leaf_conditional',
       'accepted: the P8 distinction can be erased by a consistent edit', f"before {bo['diagnostics']['a']['coverage']}; handoff exit {code}",
       bo['diagnostics']['a']['coverage'] == 'except_opaque' and code == 0)
bro = json.loads(canonical(receipt(pilot.evaluate({'a': A + b'\x5a' * 64, 'b': B + b'\x5a' * 64}, {'a': propose(A + b'\x5a' * 64), 'b': propose(B + b'\x5a' * 64)}))))
def relabel_root(rc):
    for role in ('a', 'b'):
        for reg in rc['certificates'][role]['regions']:
            if reg['kind'] == 'opaque': reg['kind'] = 'erased'
        rc['diagnostics'][role]['root_regions'] = rc['certificates'][role]['regions']
        for s in [rc['diagnostics'][role]] + [row['selection'][role] for row in rc['results']]:
            s['opaque'] = [x for x in s['opaque'] if x['reason'] != 'unparsed_root']; s['coverage'] = 'leaf_conditional'
    resync(rc)
code = edit(relabel_root, bro)
record('P6-5', 'boundary', 'Relabel an opaque root region as erased and drop its unparsed_root row', 'accepted: erased content is not verifiable without the ROM',
       f"before {bro['diagnostics']['a']['coverage']}; handoff exit {code}", bro['diagnostics']['a']['coverage'] == 'except_opaque' and code == 0)

# ======================================================================= P7 replay_compare
def write(rc, d):
    raw = canonical(rc); p = pathlib.Path(d) / (digest(raw) + '.json'); p.write_bytes(raw); return p
def rcmp(x, y):
    with tempfile.TemporaryDirectory() as d:
        o = subprocess.run([sys.executable, str(V / 'replay_compare.py'), str(write(x, d)), str(write(y, d))], capture_output=True, text=True, cwd=str(V))
        return o.returncode, (json.loads(o.stdout) if o.stdout.strip() else None), o.stderr.strip()
r1 = receipt(pair(A, B)); r2 = json.loads(canonical(r1)); r2.update(run_id=str(uuid.uuid4()), utc='2026-11-28T01:00:00+00:00')
code, out, err = rcmp(r1, r2)
record('P7-1', 'ok', 'Two receipts of the same inputs', 'normalized_equal, independence not_attested, no assurance upgrade', f"exit {code}; {out and {k: out[k] for k in ('normalized_equal', 'independence', 'assurance_upgrade')}}",
       code == 0 and out['normalized_equal'] and out['independence'] == 'not_attested' and out['assurance_upgrade'] is False)
code, out, err = rcmp(r1, r1)
record('P7-2', 'defect', 'The same receipt file compared with itself', 'exit 0 as a "replay"; only same_run_id=true hints at it; should be refused',
       f"exit {code}; same_run_id {out and out['same_run_id']}; receipt_sha256 equal {out and out['receipt_sha256'][0] == out['receipt_sha256'][1]}", code == 0 and out['same_run_id'])
split = []
for reg in propose(A + b'\x5a' * 64):
    if reg['kind'] == 'opaque' and reg['size'] >= 2:
        split += [{'offset': reg['offset'], 'size': reg['size'] // 2, 'kind': 'opaque'}, {'offset': reg['offset'] + reg['size'] // 2, 'size': reg['size'] - reg['size'] // 2, 'kind': 'opaque'}]
    else: split.append(reg)
x1 = receipt(pilot.evaluate({'a': A + b'\x5a' * 64, 'b': B}, {'a': propose(A + b'\x5a' * 64), 'b': propose(B)}))
x2 = receipt(pilot.evaluate({'a': A + b'\x5a' * 64, 'b': B}, {'a': split, 'b': propose(B)}))
same_verdicts = [[(c['id'], c['verdict'], c['observed'] if c['id'] != 'C1' else None) for c in row['components']] for row in x1['results']] == \
                [[(c['id'], c['verdict'], c['observed'] if c['id'] != 'C1' else None) for c in row['components']] for row in x2['results']]
code, out, err = rcmp(x1, x2)
record('P7-3', 'note', 'Same inputs, different (equally valid) root hints', 'verdicts and pair observations identical, but replay_compare reports a non-match (certificates/diagnostics/results) without a result-level view',
       f"verdicts+observations identical {same_verdicts}; exit {code}; different_fields {out and out['different_fields']}", same_verdicts and code == 1)
record('P7-4', 'defect', 'Output field naming', "'coverage' holds exit_criterion values, not coverage", f"{out and out['coverage']}", out and out['coverage'] == ['not_met', 'not_met'])

# ======================================================================= P8 coverage
cv = {}
cv['leaves only'] = pair(A, B)['diagnostics']['a']['coverage']
cv['unsupported compression elsewhere'] = pair(rom(False, [other]), B)['diagnostics']['a']['coverage']
cv['unparsed root gap'] = pair(A + b'\x5a' * 64, B)['diagnostics']['a']['coverage']
cv['pad data'] = pair(rom(False, [ffs(PAD_NAME, 0xF0, b'data')]), B)['diagnostics']['a']['coverage']
expected_cv = {'leaves only': 'leaf_conditional', 'unsupported compression elsewhere': 'except_opaque', 'unparsed root gap': 'except_opaque', 'pad data': 'incomplete'}
record('P8-1', 'ok', 'Coverage categories', json.dumps(expected_cv), json.dumps(cv), cv == expected_cv)
s_leaf = summ(pair(A, B))['equal_structural_signature_lists']; s_opq = summ(pair(rom(False, [other]), rom(True, [other])))['equal_structural_signature_lists']
record('P8-2', 'note', 'Proposition statuses for leaf_conditional vs except_opaque', 'identical tokens; the distinction lives only in per-role diagnostics (and is erasable, P6-4)',
       f"{s_leaf} / {s_opq}", s_leaf == s_opq == 'consistent_conditional')

json.dump(ROWS, open(os.environ.get('V032_RESULTS', os.devnull), 'w'), indent=1)
bad = [r for r in ROWS if not r['holds']]
print(f"\n{len(ROWS) - len(bad)}/{len(ROWS)} expectations hold")
sys.exit(1 if bad else 0)
