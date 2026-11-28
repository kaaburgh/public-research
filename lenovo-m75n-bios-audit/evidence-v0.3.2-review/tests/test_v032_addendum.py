"""Addendum regression tests for v0.3.2 (review of PR #8, 0cbac26f). Each test passes on the reviewed code and pins a
property of code new in v0.3.2 that the 127-test suite leaves unprotected (killed mutants per test, see
mutation_v032_review.py). Tests deliberately do NOT pin behaviour this review reports as a defect.
Usage: V03_DIR=<evidence-v0.3 of PR #8> python3 -m unittest -v test_v032_addendum
"""
import contextlib, copy, io, json, os, pathlib, struct, subprocess, sys, tempfile, unittest, uuid
from unittest.mock import patch

V = pathlib.Path(os.environ['V03_DIR']).resolve()
sys.path.insert(0, str(V)); sys.path.insert(1, str(pathlib.Path(__file__).resolve().parent))
import checker, pilot, handoff, verdicts, replay_compare  # noqa: E402
from checker import Checker, Invalid, canonical, digest  # noqa: E402
from discovery import propose  # noqa: E402
from v03_fixtures import *  # noqa: E402,F401,F403

def pair(a, b): return pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})
def comp(r, tid, cid): return next(c for row in r['results'] if row['id'] == tid for c in row['components'] if c['id'] == cid)
def summ(r): r.setdefault('input_errors', {}); return pilot.summary(r)
def image(edit=None, new=False, extra=b''):
    def f(t):
        p = bytearray(payload(t, new))
        if edit: edit(p, t, new)
        return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, bytes(p) + extra)))
    return fv([f(t) for t in TARGETS], size=0x10000)
A, B = rom(False), rom(True)
A16 = A + b'\xff' * (16777216 - len(A)); B16 = B + b'\xff' * (16777216 - len(B))

def receipt(r):
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
    resync(rc); return json.loads(canonical(rc))
def resync(rc):
    for row in rc['results']: row['components'][0]['observed'] = row['selection']
    rc['summary'] = pilot.summary(rc)
def write(rc, d, name=None):
    raw = canonical(rc); p = pathlib.Path(d) / (name or digest(raw) + '.json'); p.write_bytes(raw); return p
def handoff(rc):
    with tempfile.TemporaryDirectory() as d:
        o = subprocess.run([sys.executable, str(V / 'handoff.py'), str(write(rc, d))], capture_output=True, text=True, cwd=str(V))
        return o.returncode, o.stderr.strip()
def accepted(rc): return handoff(rc)[0] == 0
def reason(rc):
    code, err = handoff(rc); return err if code == 2 else f'exit {code}'
def replay(x, y, name_x=None):
    with tempfile.TemporaryDirectory() as d:
        return subprocess.run([sys.executable, str(V / 'replay_compare.py'), str(write(x, d, name_x)), str(write(y, d))], capture_output=True, cwd=str(V)).returncode
@contextlib.contextmanager
def synthetic_identity():
    real = pilot.profile(); saved = dict(pilot.ROMS); old = pilot.profile
    try:
        pilot.profile = lambda: real; pilot.ROMS.update(a=digest(A16), b=digest(B16)); yield
    finally:
        pilot.profile = old; pilot.ROMS.clear(); pilot.ROMS.update(saved)
def run_main(ctx):
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d); (p / 'a').write_bytes(A16); (p / 'b').write_bytes(B16)
        with synthetic_identity(), contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO())), ctx:
            code = pilot.main(['--rom-a', str(p / 'a'), '--rom-b', str(p / 'b'), '--receipts', str(p / 'rc')])
        files = sorted((p / 'rc').iterdir()) if (p / 'rc').is_dir() else []
        return code, (json.loads(files[0].read_text()) if len(files) == 1 else {'files': len(files)})
def aborted():
    code, rec = run_main(patch.object(pilot, 'summary', side_effect=RuntimeError('x')))
    for role in rec['artifacts']: rec['artifacts'][role].update(sha256=pilot.ROMS[role], expected_sha256=pilot.ROMS[role])
    return rec
BASE = None
def base():
    global BASE
    if BASE is None:
        BASE = receipt(pair(fv([target_file(t, False, wrap='lzma') for t in TARGETS], size=0x10000), fv([target_file(t, True, wrap='lzma') for t in TARGETS], size=0x10000)))
    return json.loads(canonical(BASE))

class Aborted(unittest.TestCase):
    def test_oversize_receipt_aborts(self):  # x06
        real = pilot.summary
        code, rec = run_main(patch.object(pilot, 'summary', side_effect=lambda r: {**real(r), 'pad': ['y' * 4000] * 3000}))
        self.assertEqual((code, rec.get('run_error')), (2, {'stage': 'receipt_encoding', 'code': 'receipt_size'}))
    def test_aborted_receipt_written(self):  # z01
        code, rec = run_main(patch.object(pilot, 'summary', side_effect=RuntimeError('x')))
        self.assertEqual(code, 2); self.assertIn('run_error', rec)
    def test_aborted_with_results_rejected(self):  # x34
        rec = aborted(); self.assertTrue(accepted(rec)); rec['results'] = base()['results']; self.assertFalse(accepted(rec))
    def test_aborted_stage_vocabulary(self):  # x35
        rec = aborted(); rec['run_error']['stage'] = 'replay'; self.assertFalse(accepted(rec))
    def test_aborted_summary_fixed(self):  # x36
        rec = aborted(); rec['summary'] = dict(rec['summary'], exit_criterion='met'); self.assertFalse(accepted(rec))

class HistoricalClauses(unittest.TestCase):
    def test_change_occurrence_clause(self):  # x07
        self.assertEqual(summ(pair(A, A))['historical_diff_scope'], 'conditional_refutation')
    def test_timestamp_only_bytes_bound(self):  # x08
        def e(p, t, new):
            if new: p[20] = 0x01
        self.assertEqual(summ(pair(A, image(e, True)))['timestamp_only_bytes'], 'conditional_refutation')
    def test_historical_dwlength(self):  # x09
        def e(p, t, new): p[16] = 25
        self.assertEqual(summ(pair(image(e), image(e, True)))['historical_dwLength'], 'conditional_refutation')
    def test_historical_x509_type(self):  # x10
        other = uuid.UUID('C1C41626-504C-4092-ACA9-41F936934328').bytes_le  # EFI_CERT_SHA256_GUID
        def img(new):
            t_ = efi_time(2026, 2, 3, 4, 5, 6) if new else efi_time(2025, 1, 2, 3, 4, 5)
            return fv([ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, t_ + auth_hdr() + sig_lists(LAYOUT[t], b'C', sigtype=other)))) for t in TARGETS], size=0x10000)
        self.assertEqual(summ(pair(img(False), img(True)))['historical_x509_count'], 'conditional_refutation')
    def test_historical_x509_count(self):  # x11
        def img(new):
            t_ = efi_time(2026, 2, 3, 4, 5, 6) if new else efi_time(2025, 1, 2, 3, 4, 5)
            def lay(t): return [387, 387] if t == 'SB-001' else LAYOUT[t]
            return fv([ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, t_ + auth_hdr() + sig_lists(lay(t), b'C')))) for t in TARGETS], size=0x10000)
        self.assertEqual(summ(pair(img(False), img(True)))['historical_x509_count'], 'conditional_refutation')
    def test_bound_refutes_full(self):  # x14
        def e(p, t, new):
            if new: p[1] = 0x08
        self.assertEqual(summ(pair(A, image(e, True)))['P2-47_full'], 'conditional_refutation')
    def test_full_never_established(self):  # x15
        r = pair(A, B)
        for row in r['results']:
            for i, role in enumerate(('a', 'b')): row['selection'][role]['payload']['sha256'] = pilot.REFERENCE_HASHES[row['id']][i]
        self.assertEqual(summ(r)['P2-47_full'], 'partial_not_established')

class ExitCodes(unittest.TestCase):
    def gate(self, r):
        for row in r['results']:
            for i, role in enumerate(('a', 'b')):
                if 'payload' in row['selection'].get(role, {}): row['selection'][role]['payload']['sha256'] = pilot.REFERENCE_HASHES[row['id']][i]
        r['summary'] = summ(r); return r
    def test_blocked_component_not_met(self):  # x16, x18
        r = self.gate(pair(A, B)); comp(r, 'SB-001', 'C7')['verdict'] = 'BLOCKED'; r['summary'] = summ(r)
        self.assertEqual(r['summary']['exit_criterion'], 'not_met'); self.assertEqual(pilot.exit_code(r), 2)
    def test_refutation_exit_1(self):  # x17
        r = self.gate(pair(A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000))); self.assertEqual(pilot.exit_code(r), 1)

class Localisation(unittest.TestCase):
    def test_lzma_failure_stage(self):  # x21
        f = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(sec(0x02, LZMA + struct.pack('<HH', 24, 1) + b'not an lzma stream')))
        q = pair(fv([f]), B)['diagnostics']['a']
        self.assertEqual((q.get('error'), q.get('stage')), ('lzma_invalid_or_limit', 'lzma_input'))
    def test_section_size_stage(self):  # x23
        q = pair(fv([ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(b'\x03\x00\x00\x19')))]), B)['diagnostics']['a']
        self.assertEqual(q.get('stage'), 'section_header')
    def test_leading_pad_stage(self):  # x24
        img = bytearray(fv([target_file('SB-001', False)], ext_name=OTHER.bytes_le)); img[72 + 18] = 0x01
        img[72 + 16] = 0; img[72 + 16] = (-(sum(img[72:96]) - img[89] - img[95])) % 256
        q = pair(bytes(img), B)['diagnostics']['a']
        self.assertEqual((q.get('error'), q.get('stage'), q.get('offset')), ('fv_ext_not_in_leading_pad', 'ffs_header', 72))
    def test_nested_location_and_lineage(self):  # z02, x22
        inner = lzma_sec(sec(0x19, payload('SB-001', False)) + b'\x03\x00\x00\x19')
        f2 = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(stream(inner))))
        q = pair(fv([f2] + [target_file(t, False) for t in TARGETS if t != 'SB-001'], size=0x10000), B)['diagnostics']['a']
        self.assertEqual((q.get('stream'), [x.get('parent_stream') for x in q.get('lineage', [])]), (2, [None, 0, 1]))
    def test_coverage_categories(self):  # z08
        other = ffs(OTHER.bytes_le, 0x07, stream(sec(0x01, struct.pack('<IB', 8, 1) + b'tiano...')))
        got = [pair(A, B)['diagnostics']['a'].get('coverage'), pair(rom(False, [other]), B)['diagnostics']['a'].get('coverage')]
        self.assertEqual(got, ['leaf_conditional', 'except_opaque'])

class HandoffConsistency(unittest.TestCase):
    def test_summary_bound_to_results(self):  # x45 (second receipt_summary_mismatch site; author h02 anchor is ambiguous)
        rc = base(); rc['summary'] = dict(rc['summary'], historical_diff_bound='refuted_within_supported_grammar')
        self.assertEqual(reason(rc), 'HANDOFF_REJECTED receipt_summary_mismatch')
    def test_header_prefix_cross_check(self):  # x26
        def e(p, t, new):
            if new: p[20] = 0x01
        rc = receipt(pair(A, image(e, True)))
        for row in rc['results']:
            c3 = next(c for c in row['components'] if c['id'] == 'C3'); c3['observed'] = [i for i in c3['observed'] if i != 20]; c3['verdict'] = 'PASS'
        resync(rc); self.assertFalse(accepted(rc))
    def edit_lineage(self, **kw):
        rc = base()
        for s in [rc['diagnostics']['a']] + [row['selection']['a'] for row in rc['results']]: s['lineage'][1].update(**kw)
        resync(rc); return rc
    def test_lineage_parent_order_named(self):  # z07
        self.assertEqual(reason(self.edit_lineage(parent_stream=1)), 'HANDOFF_REJECTED lineage_range')
    def test_locator_to_other_raw_leaf(self):  # v05
        rc = base(); s = rc['results'][0]['selection']['a']
        other = next(l for l in s['uninterpreted_leaves'] if l['kind'] == 'raw_section' and (l['stream'], l['offset']) != (s['locators'][0]['stream'], s['locators'][0]['offset']))
        s['locators'] = [{k: other[k] for k in s['locators'][0]}]; resync(rc)
        self.assertEqual(reason(rc), 'HANDOFF_REJECTED selection_locator')
    def test_root_regions_bound_to_certificate(self):  # z06
        rc = base(); q = rc['diagnostics']['a']; first = q['root_regions'][0]
        q['root_regions'] = [dict(first, size=8), dict(first, offset=first['offset'] + 8, size=first['size'] - 8)] + q['root_regions'][1:]
        for row in rc['results']: pass
        resync(rc); self.assertEqual(reason(rc), 'HANDOFF_REJECTED certificate_partition')
    def test_lineage_source_range(self):  # x28
        self.assertTrue(accepted(base())); self.assertFalse(accepted(self.edit_lineage(offset=16777216)))
    def test_lineage_budget(self):  # x29
        self.assertFalse(accepted(self.edit_lineage(output_size=2 ** 40)))
    def test_locator_bounds(self):  # x30
        rc = base()
        for s in [rc['diagnostics']['a']] + [row['selection']['a'] for row in rc['results']]:
            for l in s['uninterpreted_leaves'] + s.get('locators', []) + [x for o in s.get('owners', []) for x in o['raw']]: l['size'] = 2 ** 30
        resync(rc); self.assertEqual(reason(rc), 'HANDOFF_REJECTED locator_bounds')
    def test_certificate_opaque_rows(self):  # x31
        rc = receipt(pair(A + b'\x5a' * 64, B))
        for s in [rc['diagnostics']['a']] + [row['selection']['a'] for row in rc['results']]:
            s['opaque'] = [x for x in s['opaque'] if x['reason'] != 'unparsed_root']; s['coverage'] = 'leaf_conditional'
        resync(rc); self.assertFalse(accepted(rc))
    def test_owner_fv_offset(self):  # x33
        rc = base()
        for row in rc['results']: row['selection']['a']['owners'][0]['fv_offset'] = row['selection']['a']['owners'][0]['offset'] + 8
        resync(rc); self.assertFalse(accepted(rc))
    def test_owner_opacity(self):  # x32
        other = ffs(OTHER.bytes_le, 0x07, stream(sec(0x01, struct.pack('<IB', 8, 1) + b'tiano...')))
        rc = receipt(pair(rom(False, [other]), rom(True, [other])))
        row = rc['results'][0]; o = row['selection']['a']['owners'][0]
        o['opaque'].append(dict(rc['diagnostics']['a']['opaque'][0])); self.assertTrue(accepted(json.loads(canonical(receipt(pair(rom(False, [other]), rom(True, [other])))))))
        o['opaque'][-1] = dict(o['opaque'][-1], offset=o['opaque'][-1]['offset'] + 1, size=1)
        for k in ('payload', 'selection', 'locators'): row['selection']['a'].pop(k)
        _, size, n = pilot.TARGETS[row['id']]; row['components'] = verdicts.recompute(row, size, n)  # coordinated: C1 now BLOCKED
        resync(rc); self.assertEqual(reason(rc), 'HANDOFF_REJECTED owner_opacity')
    def test_failed_role_location(self):  # x37
        f = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(b'\x03\x00\x00\x19')))
        rc = receipt(pair(fv([f] + [target_file(t, False) for t in TARGETS if t != 'SB-001'], size=0x10000), B))
        self.assertTrue(accepted(rc)); rc['diagnostics']['a']['stream'] = 7; resync(rc); self.assertFalse(accepted(rc))
    def test_certificate_roles(self):  # x38
        rc = base(); rc['input_errors'] = {'b': 'input_io'}; rc['diagnostics']['b'] = {'error': 'input_io'}
        for row in rc['results']: del row['selection']['b']; _, size, count = pilot.TARGETS[row['id']]; row['components'] = verdicts.recompute(row, size, count)
        resync(rc); self.assertFalse(accepted(rc))
        del rc['certificates']['b']; resync(rc); self.assertTrue(accepted(rc))
    def test_no_coverage_without_input(self):  # x39
        rc = base(); rc['input_errors'] = {'b': 'input_io'}; del rc['certificates']['b']
        for row in rc['results']: del row['selection']['b']; _, size, count = pilot.TARGETS[row['id']]; row['components'] = verdicts.recompute(row, size, count)
        resync(rc); self.assertFalse(accepted(rc))

class InternalConsistency(unittest.TestCase):
    """Valid inputs must evaluate without the producer's own consistency checks firing. Turns detections that the author
    suite gets only as test errors (an Invalid escaping evaluate()) into explicit assertion failures."""
    def no_raise(self, fn, label):
        try: return fn()
        except Exception as e: self.fail(f'{label}: internal exception {type(e).__name__}({e})')
    def test_byte40_and_length(self):  # A-p01, A-p01b, A-p13
        def e40(p, t, new):
            if new: p[40] ^= 1
        self.no_raise(lambda: pair(A, image(e40, True)), 'byte 40 differs')
        self.no_raise(lambda: pair(A, image(None, True, b'+')), 'length mismatch')
    def test_empty_signature_list(self):  # A-p04
        empty = X509 + struct.pack('<III', 28, 0, 48)  # well-formed header, SignatureSize 48, no entries
        def img(new):
            t_ = efi_time(2026, 2, 3, 4, 5, 6) if new else efi_time(2025, 1, 2, 3, 4, 5)
            return fv([ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, t_ + auth_hdr() + empty + sig_lists(LAYOUT[t], b'C')))) for t in TARGETS], size=0x10000)
        r = self.no_raise(lambda: pair(img(False), img(True)), 'empty signature list')
        self.assertEqual(comp(r, 'SB-001', 'C7')['verdict'], 'FAIL')
    def test_lowercase_guid(self):  # A-n14
        g = pilot.TARGETS['SB-001'][0]
        got = self.no_raise(lambda: Checker(A, [g.lower()]).run(propose(A)).select(g.lower())[0], 'lowercase target GUID')
        self.assertEqual(got, payload('SB-001', False))
    def test_opaque_in_owner(self):  # A-v03
        def img(new):
            f = ffs(GUIDS['SB-001'].bytes_le, 2, stream(sec(0x19, payload('SB-001', new)), crc32_sec(sec(0x19, b'second'))))
            return fv([f] + [target_file(t, new) for t in TARGETS if t != 'SB-001'], size=0x10000)
        r = self.no_raise(lambda: pair(img(False), img(True)), 'opaque inside owner')
        self.assertEqual(comp(r, 'SB-001', 'C1')['reason'], 'opaque_in_owner')

class Replay(unittest.TestCase):
    def test_replay_rejects_aborted(self):  # x41
        rec = aborted(); self.assertEqual(replay(rec, rec), 2)
    def test_replay_filename(self):  # x42
        self.assertEqual(replay(base(), base(), name_x='0' * 64 + '.json'), 2)
    def test_replay_validates(self):  # x43
        bad = base(); comp(bad, 'SB-001', 'C6')['verdict'] = 'FAIL'; self.assertEqual(replay(bad, base()), 2)
    def test_replay_mismatch_exit(self):  # x44
        other = receipt(pair(A, fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000))); self.assertEqual(replay(base(), other), 1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
