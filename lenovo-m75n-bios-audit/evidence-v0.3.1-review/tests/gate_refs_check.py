"""Independent check of the v0.3.1 differential-gate reference hashes against three published sources."""
import csv, json, subprocess, sys
repo, v031 = sys.argv[1], sys.argv[2]
def show(rev, path): return subprocess.run(['git', '-C', repo, 'show', f'{rev}:{path}'], capture_output=True, check=True).stdout
prof = json.loads(open(f'{v031}/profile.json').read())['reference_payload_sha256']
a75 = json.loads(show('935daa09485a5fb6ba7b396c1024c027f735ad5c', 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseB/official_receipt_A75.json'))
pa = json.loads(show('935daa09485a5fb6ba7b396c1024c027f735ad5c', 'lenovo-m75n-bios-audit/independent-reproduction/pilot-SB-001-003/phaseA/phaseA_observations.json'))
inv = list(csv.DictReader(show('5cfc7c245066ced5e7854a191fcd1c06d7f41f62', 'lenovo-m75n-bios-audit/data/inventory.tsv').decode().splitlines(), delimiter='\t'))
roms = {r['sha256']: r for r in pa['roms']}
order = ['7d73d99b0b7b7fbe8999d2495b0df7e5adf4936bb3fb003838640fff7e17e145', 'fe2c8dc35ee74059cddf1fc49fe313a065bc9a1279bb3e090ea28a2d9aa0c498']
guids = {'SB-001': 'CC0F8A3F-3DEA-4376-9679-5426BA0A907E', 'SB-002': '9FE7DE69-0AEA-470A-B50A-139813649189', 'SB-003': 'FBF95065-427F-47B3-8077-D13C60710998'}
ok = True
for tid, ref in prof.items():
    a = next(x for x in a75['results'] if x['id'] == tid)['observed']['body_sha256']
    p = [roms[h]['targets'][tid]['candidates'][0]['raw_leaves'][0]['body_sha256'] for h in order]
    pc = [len(roms[h]['targets'][tid]['candidates']) for h in order]; pl = [roms[h]['targets'][tid]['candidates'][0]['raw_leaf_count'] for h in order]
    row = [r for r in inv if r['guid'] == guids[tid] and r['section'] == 'Raw section']
    i = [row[0]['sha132'], row[0]['sha133']] if len(row) == 1 else None
    same = ref == a == p == i
    ok &= same
    print(tid, 'profile==A75==phaseA==inventory:', same, '| phaseA owners', pc, 'raw leaves', pl, '| inventory rows', len(row))
print('ALL_SIX_AGREE' if ok else 'DISAGREEMENT')
