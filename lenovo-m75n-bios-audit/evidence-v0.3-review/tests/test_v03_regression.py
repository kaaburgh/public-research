"""Regression tests proposed for v0.3: each pins behaviour the code ALREADY has (and the spec requires)
but that the author's test_pilot.py does not exercise; each kills at least one surviving mutant from
mutation_v03.py. All pass on PR #4 commit 3c3c555c.
Usage: V03_DIR=<evidence-v0.3> V1_DIR=<v1 worktree> IR_DIR=<935daa0 worktree> python3 -m unittest -v test_v03_regression
"""
import copy, json, os, pathlib, struct, subprocess, sys, tempfile, unittest, uuid

V03 = pathlib.Path(os.environ['V03_DIR']).resolve()
sys.path.insert(0, str(V03)); sys.path.insert(1, str(pathlib.Path(__file__).resolve().parent))
import checker, pilot, handoff, legacy_import  # noqa: E402
from checker import Checker, Invalid, canonical, digest, propose  # noqa: E402
from v03_fixtures import *  # noqa: E402,F401,F403

G1 = TARGETS['SB-001'][0]

def select(image, cert=None, g=G1):
    return Checker(image, [g]).run(cert if cert is not None else propose(image)).select(g)

def reasons(a):
    return [x['reason'] for x in a['issues']] + [x['reason'] for x in a['opaque']]

def verdicts(a, b, count=1):
    return {c['id']: c['verdict'] for c in pilot.compare_pair(a, b, len(a), count, 'derived_in_supported_grammar')}

def one(newer=False, tag=b'C', layout=None, hdr=None, time=None):
    t = time or (efi_time(2026, 2, 3, 4, 5, 6) if newer else efi_time(2025, 1, 2, 3, 4, 5))
    return t + (hdr or auth_hdr()) + (layout or sig_lists([774], tag))

def receipt(r):
    rc = {'profile_sha256': digest(pilot.PROFILE_PATH.read_bytes()), 'version': pilot.VERSION, 'run_id': str(uuid.uuid4()),
          'utc': '2026-11-28T00:00:00+00:00', 'runtime': sys.version.split()[0],
          'tool_sha256': {n: digest((V03 / n).read_bytes()) for n in ('pilot.py', 'checker.py')},
          'artifacts': {k: {'sha256': v, 'size': 16777216, 'expected_sha256': v} for k, v in pilot.ROMS.items()},
          'certificates': {}, 'diagnostics': {}, 'results': []}
    rc.update(copy.deepcopy(r)); rc['input_errors'] = {}; rc['summary'] = pilot.summary(rc)
    return rc

def handoff_ok(rc):
    with tempfile.TemporaryDirectory() as d:
        raw = canonical(rc); p = pathlib.Path(d) / (digest(raw) + '.json'); p.write_bytes(raw)
        return subprocess.run([sys.executable, str(V03 / 'handoff.py'), str(p)], capture_output=True, cwd=str(V03)).returncode == 0

def baseline():
    a, b = rom(False), rom(True)
    return pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})

class FFSIntegrity(unittest.TestCase):
    def test_fixed_checksum_must_be_0xAA(self):  # c03
        x, a, e = select(fv([target_file('SB-001', False, file_checksum=0x00)]))
        self.assertIsNone(x); self.assertIn('ffs_data_checksum', reasons(a))
    def test_reserved_state_bits(self):  # c04: PI "All other State bits are reserved and must be set to EFI_FVB_ERASE_POLARITY"
        x, a, e = select(fv([target_file('SB-001', False, state=0x47)]))
        self.assertIsNone(x); self.assertIn('ffs_state', reasons(a))
    def test_data_valid_without_header_bits(self):  # c05 (conservative subset)
        x, a, e = select(fv([target_file('SB-001', False, state=0x04)]))
        self.assertIsNone(x); self.assertIn('ffs_state', reasons(a))
    def test_deleted_container_is_not_traversed(self):  # c28
        inner = fv([target_file('SB-001', False, b'OLD')], size=0x8000)
        dead = ffs(OTHER.bytes_le, 0x0B, stream(lzma_sec(sec(0x17, inner))), state=DELETED)
        x, a, e = select(fv([target_file('SB-001', False), dead], size=0x10000))
        self.assertEqual(a['counts']['data_valid'], 1); self.assertEqual(a['selection'], 'unique')

class FVAndSectionGrammar(unittest.TestCase):
    def test_header_tail_after_blockmap(self):  # c20
        x, a, e = select(fv([target_file('SB-001', False)], header_tail=b'\x01' + bytes(7)))
        self.assertIsNone(x); self.assertIn('unsupported_fv_header_tail', reasons(a))
    def test_blockmap_must_cover_fv(self):  # c21
        with self.assertRaises(Invalid): select(fv([target_file('SB-001', False)], blocks=1))
    def test_inter_file_padding_must_be_erased(self):  # c22
        f = target_file('SB-001', False)
        with self.assertRaises(Invalid): select(fv([ffs(OTHER.bytes_le, 0x01, b'odd'), f], gap_fill=0x00))
    def test_inter_section_padding_must_be_zero(self):  # c23
        body = stream(sec(0x15, b'ab'), sec(0x19, payload('SB-001', False)), pad=0x5A)
        with self.assertRaises(Invalid): select(fv([ffs(GUIDS['SB-001'].bytes_le, 0x02, body)]))
    def test_root_fv_size_must_equal_fvlength(self):  # c24: block map agrees with the region, FvLength field does not
        image = bytearray(fv([target_file('SB-001', False)], size=0x8000))
        image[32:40] = struct.pack('<Q', 0x7000); image[50:52] = b'\0\0'
        image[50:52] = ((-sum(struct.unpack('<36H', bytes(image[:72])))) & 0xFFFF).to_bytes(2, 'little')
        with self.assertRaises(Invalid): select(bytes(image), [{'offset': 0, 'size': len(image), 'kind': 'fv'}])
    def test_partition_must_be_contiguous_not_just_total(self):  # c17 (test_pilot.test_overlap passes for the wrong reason)
        f = fv([target_file('SB-001', False)]); image = f + b'\xff' * 32; L = len(f)
        cert = [{'offset': 0, 'size': L, 'kind': 'fv'}, {'offset': L + 16, 'size': 16, 'kind': 'erased'}, {'offset': L, 'size': 16, 'kind': 'erased'}]
        with self.assertRaises(Invalid): select(image, cert)
    def test_lzma_trailing_bytes_rejected(self):  # c19
        f = ffs(GUIDS['SB-001'].bytes_le, 0x02, stream(lzma_sec(sec(0x19, payload('SB-001', False)), trailing=b'junk')))
        with self.assertRaises(Invalid): select(fv([f]))
    def test_unknown_section_type_reported(self):  # c16
        body = stream(sec(0x19, payload('SB-001', False)), sec(0x30, b'vendor'))
        x, a, e = select(fv([ffs(GUIDS['SB-001'].bytes_le, 0x02, body)]))
        self.assertIn('unknown_section_type', reasons(a)); self.assertEqual(a['coverage'], 'except_opaque')
    def test_extended_size_section_reported(self):  # c27
        body = stream(sec(0x19, payload('SB-001', False)), sec(0x19, bytes(8), size=0xFFFFFF))
        x, a, e = select(fv([ffs(GUIDS['SB-001'].bytes_le, 0x02, body)]))
        self.assertIn('extended_section_unsupported', reasons(a))
    def test_oem_file_type_reported(self):  # c29
        x, a, e = select(fv([target_file('SB-001', False), ffs(OTHER.bytes_le, 0xC0, b'oem data')]))
        self.assertIn('unsupported_ffs_type', reasons(a))
    def test_tripwire_scans_decompressed_streams(self):  # c12
        hidden = ffs(OTHER.bytes_le, 0x02, stream(lzma_sec(sec(0x19, b'pfx!' + target_file('SB-001', False, b'Z')))))
        x, a, e = select(fv([target_file('SB-001', False), hidden], size=0x10000))
        self.assertIsNone(x); self.assertTrue(any(i['stream'] > 0 and i['reason'] == 'untracked_ffs_candidate' for i in a['issues']))

class Components(unittest.TestCase):
    def test_c6_starts_at_40(self):  # p01
        a = one(); b = bytearray(one(True)); b[40] ^= 1
        self.assertEqual(verdicts(a, bytes(b))['C6'], 'FAIL')
    def test_c3_is_exact_not_subset(self):  # p02
        a = one(); b = bytearray(a); b[0] ^= 1; b[2] ^= 1
        self.assertEqual(verdicts(a, bytes(b))['C3'], 'FAIL')
    def test_c5_checks_certificate_type(self):  # p03
        a = one(hdr=auth_hdr(certtype=0x0002)); self.assertEqual(verdicts(a, a)['C5'], 'FAIL')
    def test_c7_rejects_empty_list(self):  # p04
        empty = X509 + struct.pack('<III', 28, 0, 32)
        a = one(layout=sig_lists([774 - 28], b'C') + empty)
        self.assertEqual(verdicts(a, a)['C7'], 'FAIL')
    def test_c8_signature_header_size(self):  # p05
        a = one(layout=sig_lists([770], b'C', header_size=4)); v = verdicts(a, a)
        self.assertEqual((v['C7'], v['C8']), ('PASS', 'FAIL'))
    def test_c8_entry_count(self):  # p06
        a = one(layout=sig_lists([387, 387], b'C')); v = verdicts(a, a, count=1)
        self.assertEqual((v['C7'], v['C8']), ('PASS', 'FAIL'))
    def test_c4_plausibility_rejects_invalid_month(self):  # p07
        a = one(time=efi_time(2025, 13, 2, 3, 4, 5)); self.assertEqual(verdicts(a, a)['C4_plausibility'], 'FAIL')
    def test_conditional_refutation(self):  # p09
        a = rom(False) + b'opaque!!'; b = fv([target_file(t, True, b'D') for t in TARGETS], size=0x10000) + b'opaque!!'
        r = pilot.evaluate({'a': a, 'b': b}, {'a': propose(a), 'b': propose(b)})
        self.assertEqual(pilot.summary(r)['equal_structural_signature_lists'], 'conditional_refutation')

class Handoff(unittest.TestCase):
    def test_baseline_accepted(self): self.assertTrue(handoff_ok(receipt(baseline())))
    def test_semantic_overclaim_rejected(self):  # h01
        rc = receipt(baseline()); next(c for c in rc['results'][0]['components'] if c['id'] == 'C4')['verdict'] = 'PASS'
        self.assertFalse(handoff_ok(rc))
    def test_summary_mismatch_rejected(self):  # h02
        rc = receipt(baseline()); rc['summary']['byte_observations'] = 'unverified'; self.assertFalse(handoff_ok(rc))
    def test_result_without_payload_rejected(self):  # h04
        rc = receipt(baseline()); del rc['results'][0]['selection']['a']['payload']; self.assertFalse(handoff_ok(rc))
    @unittest.skipUnless(os.environ.get('V1_DIR') and os.environ.get('IR_DIR'), 'needs original v1 artifacts')
    def test_legacy_upgrade_rejected(self):  # h03
        claims = (pathlib.Path(os.environ['V1_DIR']) / 'lenovo-m75n-bios-audit/evidence-v1/claims.json').read_bytes()
        rec = (pathlib.Path(os.environ['IR_DIR']) / 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseB/official_receipt_A75.json').read_bytes()
        out = legacy_import.import_v1(claims, rec)
        self.assertTrue(handoff_ok(out))
        up = copy.deepcopy(out); next(c for c in up['results'][0]['components'] if c['id'] == 'C3')['verdict'] = 'PASS'
        self.assertFalse(handoff_ok(up))

if __name__ == '__main__':
    unittest.main(verbosity=2)
