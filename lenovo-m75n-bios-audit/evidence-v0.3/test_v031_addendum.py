"""Addendum regression tests for v0.3.1 (review of PR #6, 985eb325). Every test passes on the reviewed code and pins a
property that the author's 73-test suite leaves unprotected (killed mutants listed per test).
Usage: V03_DIR=<evidence-v0.3 of PR #6> V1_DIR=<v1 worktree> IR_DIR=<935daa0 worktree> python3 -m unittest -v test_v031_addendum
"""
import copy, hashlib, json, os, pathlib, struct, subprocess, sys, tempfile, unittest, uuid

V = pathlib.Path(os.environ.get('V03_DIR',pathlib.Path(__file__).resolve().parent)).resolve()
sys.path.insert(0, str(V)); sys.path.insert(1, str(pathlib.Path(__file__).resolve().parent))
import checker, pilot, handoff, legacy_import, verdicts, discovery  # noqa: E402
from checker import Checker, Invalid, canonical, digest  # noqa: E402
from discovery import propose  # noqa: E402
from v03_fixtures import *  # noqa: E402,F401,F403

G1 = TARGETS['SB-001'][0]
FV_MAIN = uuid.UUID('5C60F367-A505-419A-859E-2A4FF6CA6FE5').bytes_le

def sel(img, g=G1, regions=None):
    return Checker(img, [g]).run(regions if regions is not None else propose(img)).select(g)
def reasons(a): return [x['reason'] for x in a['issues']] + [x['reason'] for x in a['opaque']]
def pair(a, b): return pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})
def comp(r, tid, cid): return next(c for row in r['results'] if row['id'] == tid for c in row['components'] if c['id'] == cid)
def ext_fv(files, ext_bytes, size=0x10000, ext_off=96, pad_extra=b'', pad_state=DATA_VALID, revision=2):
    hdr = bytearray(bytes(16) + FFS2 + struct.pack('<Q', size) + b'_FVH' + struct.pack('<IHHHBB', 0x800, 72, 0, ext_off, 0, revision) + struct.pack('<IIII', size // 0x1000, 0x1000, 0, 0))
    hdr[50:52] = ((-sum(struct.unpack('<36H', bytes(hdr)))) & 0xFFFF).to_bytes(2, 'little')
    body = bytes(hdr)
    if ext_bytes is not None:
        body += ffs(PAD_NAME, 0xF0, b'\xff' * (ext_off - 96) + ext_bytes + pad_extra, state=pad_state)
    for f in files:
        body += b'\xff' * (-len(body) % 8) + f
    return body + b'\xff' * (size - len(body))
EXT20 = FV_MAIN + struct.pack('<I', 20)

def receipt(r):
    rc = {'profile_sha256': digest(pilot.PROFILE_PATH.read_bytes()), 'version': pilot.VERSION, 'run_id': str(uuid.uuid4()),
          'utc': '2026-11-28T00:00:00+00:00', 'runtime': sys.version.split()[0],
          'tool_sha256': {n: digest((V / n).read_bytes()) for n in ('pilot.py', 'checker.py', 'verdicts.py', 'discovery.py')},
          'artifacts': {k: {'sha256': v, 'size': 16777216, 'expected_sha256': v} for k, v in pilot.ROMS.items()},
          'certificates': {}, 'diagnostics': {}, 'results': []}
    rc.update(copy.deepcopy(r)); rc['input_errors'] = {}
    for role, sha in pilot.ROMS.items():
        root = {'stream': 0, 'kind': 'artifact', 'sha256': sha, 'size': 16777216}
        if 'lineage' in rc['diagnostics'].get(role, {}): rc['diagnostics'][role]['lineage'][0] = dict(root)
        for row in rc['results']:
            if role in row['selection']: row['selection'][role]['lineage'][0] = dict(root)
    # Synthetic test only: complete the recorded partition to the fake pinned artifact size.
    for role,sha in pilot.ROMS.items():
        q=rc['diagnostics'].get(role,{})
        regions=copy.deepcopy(q.get('root_regions',[]))
        length=sum(x['size'] for x in regions)
        if length<16777216: regions.append({'offset':length,'size':16777216-length,'kind':'erased'})
        if 'root_regions' in q: q['root_regions']=regions
        rc['certificates'][role]={'artifact_sha256':sha,'regions':regions}
    resync(rc)
    return json.loads(canonical(rc))
def resync(rc):
    for row in rc['results']: row['components'][0]['observed'] = row['selection']
    rc['summary'] = pilot.summary(rc)
def accepted(rc, name=None):
    with tempfile.TemporaryDirectory() as d:
        raw = canonical(rc); p = pathlib.Path(d) / (name or digest(raw) + '.json'); p.write_bytes(raw)
        return subprocess.run([sys.executable, str(V / 'handoff.py'), str(p)], capture_output=True, cwd=str(V)).returncode == 0
BASE = None
def base():
    global BASE
    if BASE is None: BASE = receipt(pair(rom(False), rom(True)))
    return json.loads(canonical(BASE))

class FFSAndGrammar(unittest.TestCase):
    def test_attr_checksum(self):  # c02
        bad = bytearray(target_file('SB-001', False, checksum_attr=True)); bad[30] ^= 1
        x, a, e = sel(fv([bytes(bad)])); self.assertIsNone(x); self.assertIn('ffs_data_checksum', reasons(a))
    def test_plausible_invalid_candidate(self):  # c10
        h = bytearray(GUIDS['SB-001'].bytes_le + b'\0\xaa' + bytes([2, 1]) + b'\0\0\0' + b'\xf8' + struct.pack('<Q', 4096))
        h[16] = (-(sum(h) - h[17] - h[23]) + 1) & 0xFF  # deliberately wrong 24-byte checksum -> 'unresolved' branch
        img = fv([target_file('SB-001', False)]) + bytes(h) + b'\xff' * (0x1000 - len(h))
        x, a, e = sel(img); self.assertIsNone(x); self.assertIn('unresolved_ffs_candidate', reasons(a))
    def test_unsupported_compression_reported(self):  # c15
        x, a, e = sel(fv([target_file('SB-001', False), ffs(OTHER.bytes_le, 0x07, stream(sec(0x01, struct.pack('<IB', 8, 1) + b'tiano...')))]))
        self.assertIn('unsupported_compression', reasons(a))
    def test_leaf_sections_listed(self):  # n10
        f = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(sec(0x19, payload('SB-001', False)), sec(0x15, b'U\0I\0'), sec(0x13, b'\x06\x08')))
        x, a, e = sel(fv([f])); kinds = {l['kind'] for l in a['uninterpreted_leaves']}
        self.assertTrue({'raw_section', 'section_15', 'section_13'} <= kinds)
    def test_fv_revision_required(self):  # n16
        x, a, e = sel(ext_fv([target_file('SB-001', False)], None, ext_off=0, revision=1)); self.assertIn('unsupported_fv', reasons(a)); self.assertIsNone(x)

class Budgets(unittest.TestCase):
    def test_tripwire_checksum_budget(self):  # n13
        blob = bytearray(1 << 20)
        for off in range(0, len(blob) - 72, 512):
            blob[off + 32:off + 40] = struct.pack('<Q', len(blob) - off); blob[off + 40:off + 44] = b'_FVH'; blob[off + 48:off + 50] = struct.pack('<H', 0xFFFE)
        a = rom(False)
        with self.assertRaises(Invalid) as e:
            Checker(a + bytes(blob), [G1]).run([{'offset': 0, 'size': len(a), 'kind': 'fv'}, {'offset': len(a), 'size': len(blob), 'kind': 'opaque'}])
        self.assertEqual(str(e.exception), 'tripwire_checksum_budget')

class ExtendedHeader(unittest.TestCase):
    def test_ext_alignment(self):  # n01
        with self.assertRaises(Invalid): sel(ext_fv([target_file('SB-001', False)], EXT20, ext_off=98))
    def test_ext_must_follow_pad_header(self):  # (n02 is equivalent: the leading-pad containment check also rejects)
        img = bytearray(ext_fv([target_file('SB-001', False)], EXT20)); img[52:54] = struct.pack('<H', 88)
        img[50:52] = b'\0\0'; img[50:52] = ((-sum(struct.unpack('<36H', bytes(img[:72])))) & 0xFFFF).to_bytes(2, 'little')
        with self.assertRaises(Invalid): sel(bytes(img))
    def test_ext_entries_opaque(self):  # n03, n15
        x, a, e = sel(ext_fv([target_file('SB-001', False)], FV_MAIN + struct.pack('<I', 28) + struct.pack('<HHI', 8, 3, 0x8000)))
        self.assertIsNone(x); self.assertIn('unsupported_fv_ext_entries', reasons(a))
    def test_leading_pad_must_be_data_valid(self):  # n05
        with self.assertRaises(Invalid): sel(ext_fv([target_file('SB-001', False)], EXT20, pad_state=MARKED))
    def test_pad_bytes_before_ext(self):  # n06
        img = bytearray(ext_fv([target_file('SB-001', False)], EXT20, ext_off=100)); img[96] = 0x00
        pad = img[72:96]; pad[17] = 0xAA
        x, a, e = sel(bytes(img)); self.assertIn('pad_file_data', reasons(a))
    def test_pad_bytes_after_ext(self):  # n07
        x, a, e = sel(ext_fv([target_file('SB-001', False)], EXT20, pad_extra=b'\x00data\x00\x00\x00'))
        self.assertIn('pad_file_data', reasons(a))

class OwnerScope(unittest.TestCase):
    def test_nested_unsupported_fv_in_owner(self):  # n11
        weird = bytearray(fv([], size=0x1000)); weird[16:32] = uuid.UUID('5473C07A-3DCB-4DCA-BD6F-1E9689E7349A').bytes_le
        weird[50:52] = b'\0\0'; weird[50:52] = ((-sum(struct.unpack('<36H', bytes(weird[:72])))) & 0xFFFF).to_bytes(2, 'little')
        owner = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(sec(0x19, payload('SB-001', False)), sec(0x17, bytes(weird))))
        self.assertEqual(sel(fv([owner]))[2], 'opaque_in_owner')
    def test_multiplicity_blocked_by_issues(self):  # v15
        stray = bytearray(target_file('SB-001', False, b'Z')); stray[16] ^= 1
        img = rom(False) + bytes(stray) + b'\xff' * (-len(stray) % 16)
        r = pair(img, rom(True) + bytes(stray) + b'\xff' * (-len(stray) % 16))
        self.assertEqual(comp(r, 'SB-001', 'multiplicity')['verdict'], 'BLOCKED')

class Semantics(unittest.TestCase):
    def test_efi_time_pad1(self):  # v12
        a = bytearray(efi_time(2025, 1, 2, 3, 4, 5) + auth_hdr() + sig_lists([774], b'C')); a[7] = 1
        self.assertEqual({c['id']: c['verdict'] for c in pilot.compare_pair(bytes(a), bytes(a), len(a), 1, 'conditional_coverage')}['C4_plausibility'], 'FAIL')
    def test_c5_revision(self):  # p03
        a = efi_time(2025, 1, 2, 3, 4, 5) + auth_hdr(revision=0x100) + sig_lists([774], b'C')
        self.assertEqual({c['id']: c['verdict'] for c in pilot.compare_pair(a, a, len(a), 1, 'conditional_coverage')}['C5'], 'FAIL')
    def test_timestamp_scope_header_change(self):  # s02
        def f(t, new, rev): return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, (efi_time(2026, 2, 3, 4, 5, 6) if new else efi_time(2025, 1, 2, 3, 4, 5)) + auth_hdr(revision=rev) + payload(t, new)[40:])))
        r = pair(fv([f(t, False, 0x200) for t in TARGETS], size=0x10000), fv([f(t, True, 0x201) for t in TARGETS], size=0x10000))
        self.assertEqual(pilot.summary(r)['timestamp_only_semantic_conclusion'], 'conditional_refutation')
    def test_timestamp_scope_length(self):  # s03
        def f(t, new): return ffs(GUIDS[t].bytes_le, 0x02, stream(sec(0x19, payload(t, new) + (b'+' if new else b''))))
        r = pair(fv([f(t, False) for t in TARGETS], size=0x10000), fv([f(t, True) for t in TARGETS], size=0x10000))
        self.assertEqual(pilot.summary(r)['timestamp_only_semantic_conclusion'], 'conditional_refutation')
    def test_gate_mismatch_precedes_missing(self):  # s05
        r = pair(rom(False), rom(True)); del r['results'][0]['selection']['a']['payload']
        self.assertEqual(pilot.differential(r)['status'], 'mismatch')
    def test_gate_per_role(self):  # s06
        r = pair(rom(False), rom(True))
        for row in r['results']:
            for i, role in enumerate(('a', 'b')): row['selection'][role]['payload']['sha256'] = pilot.REFERENCE_HASHES[row['id']][1 - i]
        self.assertEqual(pilot.differential(r)['status'], 'mismatch')

class HandoffConsistency(unittest.TestCase):
    def test_baseline(self): self.assertTrue(accepted(base()))
    def test_counts_edit(self):  # v01
        rc = base(); rc['results'][0]['selection']['a']['counts']['deleted'] = 1; rc['diagnostics']  # noqa
        resync(rc); self.assertFalse(accepted(rc))
    def test_coverage_relabel_with_leaves(self):  # v02
        rc = base()
        for role in ('a', 'b'):
            for s in [rc['diagnostics'][role]] + [row['selection'][role] for row in rc['results']]: s['coverage'] = 'grammar_complete'
        for row in rc['results']:
            for c in row['components']:
                if c['assurance'] == 'conditional_coverage': c['assurance'] = 'derived_in_supported_grammar'
        resync(rc); self.assertFalse(accepted(rc))
    def test_payload_edit(self):  # v04
        rc = base(); rc['results'][0]['selection']['a']['payload']['sha256'] = '0' * 64; resync(rc); self.assertFalse(accepted(rc))
    def test_locator_edit(self):  # v05
        rc = base(); rc['results'][0]['selection']['a']['locators'][0]['offset'] += 8; resync(rc); self.assertFalse(accepted(rc))
    def test_c6_suffix_vs_c3(self):  # v08
        r = pair(rom(False), fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000)); rc = receipt(r)
        for row in rc['results']:
            c6 = next(c for c in row['components'] if c['id'] == 'C6'); h = c6['observed']['suffix_sha256'][0]
            c6['observed']['suffix_sha256'] = [h, h]; c6['observed']['equal'] = True; c6['verdict'] = 'PASS'
        resync(rc); self.assertFalse(accepted(rc))
    def test_c6_flag(self):  # v09
        rc = base(); comp(rc, 'SB-001', 'C6')['observed']['equal'] = False; resync(rc); self.assertFalse(accepted(rc))
    def test_list_consumption(self):  # v10
        rc = base()
        for cid in ('C7', 'C8'): comp(rc, 'SB-001', cid)['observed'][0][0]['entry_size'] += 1
        resync(rc); self.assertFalse(accepted(rc))
    def test_payload_on_unresolved_selection(self):  # v16
        r = pair(b'\xff' * 0x10000 + b'opaque', b'\xff' * 0x10000 + b'opaque'); rc = receipt(r)
        rc['results'][0]['selection']['a'].update(payload={'sha256': pilot.REFERENCE_HASHES['SB-001'][0], 'size': 842}, selection='unique')
        resync(rc); self.assertFalse(accepted(rc))
    def test_filename_must_be_digest(self):  # k05
        self.assertFalse(accepted(base(), name='0' * 64 + '.json'))
    def test_selection_vs_diagnostics(self):  # k06
        rc = base(); rc['diagnostics']['a']['pad_count'] = 7; resync(rc); self.assertFalse(accepted(rc))
    def test_tool_identity(self):  # k07
        rc = base(); rc['tool_sha256']['verdicts.py'] = '1' * 64; resync(rc); self.assertFalse(accepted(rc))
    def test_profile_identity(self):  # k08
        rc = base(); rc['profile_sha256'] = '1' * 64; resync(rc); self.assertFalse(accepted(rc))
    def test_artifact_identity(self):  # k09
        rc = base(); rc['artifacts']['a']['sha256'] = '1' * 64; resync(rc); self.assertFalse(accepted(rc))
    def test_selection_role_without_input(self):
        rc = base(); rc['input_errors'] = {'b': 'input_io'}; resync(rc); self.assertFalse(accepted(rc))
    def test_selection_role_hidden(self):  # k10: drop role b from every selection and recompute verdicts consistently
        rc = base()
        for row in rc['results']:
            del row['selection']['b']; _, size, count = pilot.TARGETS[row['id']]
            row['components'] = verdicts.recompute(row, size, count)
        resync(rc); self.assertFalse(accepted(rc))

class CLIAndLegacy(unittest.TestCase):
    def test_wrong_rom_identity(self):  # k01
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d)
            (p / 'a.rom').write_bytes(b'\xff' * 16777216); (p / 'b.rom').write_bytes(b'\xfe' * 16777216)
            out = subprocess.run([sys.executable, str(V / 'pilot.py'), '--rom-a', str(p / 'a.rom'), '--rom-b', str(p / 'b.rom'), '--receipts', str(p / 'rc')], capture_output=True, text=True, cwd=str(V))
            rc = json.loads(next((p / 'rc').iterdir()).read_text())
            self.assertEqual(out.returncode, 2); self.assertEqual(rc['input_errors'], {'a': 'rom_identity', 'b': 'rom_identity'})
    def test_receipt_exclusive_create(self):  # k03
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(pilot.write_receipt(d, {'x': 1})); self.assertFalse(pilot.write_receipt(d, {'x': 1}))
    def test_cli_exit_and_binding(self):  # k02, k04 (in-process with synthetic ROM identities)
        real = pilot.profile(); saved = dict(pilot.ROMS); old_profile = pilot.profile
        a = rom(False) + b'\xff' * (16777216 - len(rom(False))); b = rom(True) + b'\xff' * (16777216 - len(rom(True)))
        try:
            pilot.profile = lambda: real
            pilot.ROMS.update(a=digest(a), b=digest(b))
            with tempfile.TemporaryDirectory() as d:
                p = pathlib.Path(d); (p / 'a').write_bytes(a); (p / 'b').write_bytes(b)
                (p / 'ca').write_bytes(canonical({'artifact_sha256': '0' * 64, 'regions': propose(a)}))
                import io, contextlib
                with contextlib.redirect_stdout(io.StringIO()):
                    code = pilot.main(['--rom-a', str(p / 'a'), '--rom-b', str(p / 'b'), '--certificate-a', str(p / 'ca'), '--receipts', str(p / 'rc')])
                rc = json.loads(next((p / 'rc').iterdir()).read_text())
                self.assertEqual(rc['input_errors'], {'a': 'certificate_binding'}); self.assertEqual(code, 2)
        finally:
            pilot.profile = old_profile; pilot.ROMS.clear(); pilot.ROMS.update(saved)
    @unittest.skipUnless(os.environ.get('V1_DIR') and os.environ.get('IR_DIR'), 'original v1 artifacts')
    def test_legacy_byte_observations_unverified(self):  # k11
        cl = (pathlib.Path(os.environ['V1_DIR']) / 'lenovo-m75n-bios-audit/evidence-v1/claims.json').read_bytes()
        rr = (pathlib.Path(os.environ['IR_DIR']) / 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseB/official_receipt_A75.json').read_bytes()
        self.assertEqual(legacy_import.import_v1(cl, rr)['summary']['byte_observations'], 'unverified')
    def test_discovery_skips_bad_checksum(self):  # k13
        img = bytearray(fv([target_file('SB-001', False)])); img[50] ^= 1
        self.assertEqual([r['kind'] for r in propose(bytes(img))], ['opaque'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
