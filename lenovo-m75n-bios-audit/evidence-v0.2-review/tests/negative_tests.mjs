// Adversarial and negative tests for evidence protocol v0.2 (review of PR #2, commit 23419c1).
// Usage: node negative_tests.mjs <path-to-evidence-v0.2-dir>
// Runs the real CLI (verify.mjs, Node crypto SHA-256) on synthetic inputs in a temp dir.
// No firmware, no ROMs, no network. Exit 0 when every expectation below holds
// (expectations describe CURRENT v0.2 behaviour, including the defects being demonstrated).
import {createHash} from 'node:crypto';
import {mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

const dir = resolve(process.argv[2] || '.');
const PINNED = {
  'core.mjs': '22005af9ef3d358efc9c30478fe41ed410a9ab4cb3c6318de714c520ebed34f6',
  'verify.mjs': '058b5cd6bed887907aca876930043611f3232bbf19cc325cb689d3520def2c19',
  'selftest.mjs': '8ece641a6467edafcd9e12bc504be2038d327c5b417a3faace13ea48d70e20c9',
};
const sha = b => createHash('sha256').update(b).digest('hex');
for (const [f, h] of Object.entries(PINNED)) {
  const got = sha(readFileSync(join(dir, f)));
  if (got !== h) { console.error(`pinned hash mismatch for ${f}: ${got}`); process.exit(3); }
}
const core = await import(pathToFileURL(join(dir, 'core.mjs')).href);
const {canon, parseCanonical, validatePack, evaluate} = core;

const root = mkdtempSync(join(tmpdir(), 'v02-neg-'));
let failures = 0, n = 0;
const rows = [];
function record(id, kind, title, expectation, observed, holds) {
  n++; if (!holds) failures++;
  rows.push({id, kind, title, expectation, observed, holds});
  console.log(`${holds ? 'ok  ' : 'FAIL'} ${id} [${kind}] ${title}\n      expected: ${expectation}\n      observed: ${observed}`);
}

// ---------- helpers ----------
let caseNo = 0;
function workspace() {
  const w = join(root, String(++caseNo));
  mkdirSync(join(w, 'store'), {recursive: true});
  return w;
}
function put(w, bytes) { const h = sha(bytes); writeFileSync(join(w, 'store', h), bytes); return {sha256: h, size: bytes.length}; }
function writeCanon(path, x) { const s = canon(x) + '\n'; writeFileSync(path, s); return sha(Buffer.from(s)); }
function cli(w, pack, obsFn, receiptsDir = join(w, 'receipts')) {
  const packHash = writeCanon(join(w, 'pack.json'), pack);
  const obs = obsFn(packHash);
  writeCanon(join(w, 'obs.json'), obs);
  const r = spawnSync(process.execPath, [join(dir, 'verify.mjs'), join(w, 'pack.json'), join(w, 'obs.json'), join(w, 'store'), receiptsDir], {encoding: 'utf8'});
  let receipt = null;
  try { const files = readdirSync(receiptsDir); if (files.length === 1) receipt = JSON.parse(readFileSync(join(receiptsDir, files[0]), 'utf8')); } catch {}
  return {code: r.status, stdout: r.stdout.trim(), stderr: r.stderr.trim(), receipt, packHash};
}
const GUID = 'CC0F8A3F-3DEA-4376-9679-5426BA0A907E';
function entry(artifact, payload, over = {}) {
  return {artifact, selector: 's', coverage: 'complete', owner_count: 1, raw_node_count: 1, leaf_count: 1, issues: [], payload, locator: 'test', ...over};
}
function packOf(artifacts, checks, extra = {}) {
  return {version: '0.2', artifacts, selectors: [{id: 's', kind: 'unique_ffs_leaf_v1', guid: GUID, section_type: 25}],
    claims: [{id: 'c', selector: 's', inputs: {a: artifacts[0].id, b: artifacts[1].id}, sources: [{commit: 'a'.repeat(40), path: 'x', anchor: 'x'}], predecessor: null, checks, ...extra}]};
}
function obsOf(packHash, entries, adapter = {id: 'a75', sha256: 'f'.repeat(64), toolchain: 'UEFIExtract A75'}) {
  return {version: '0.2', pack_sha256: packHash, adapter, entries};
}
const unchangedChecks = (p) => [
  {id: 'size_a', op: 'size_v1', args: {input: 'a'}, expected: p.length},
  {id: 'hash_a', op: 'sha256_v1', args: {input: 'a'}, expected: sha(p)},
  {id: 'hash_b', op: 'sha256_v1', args: {input: 'b'}, expected: sha(p)},
  {id: 'equal', op: 'range_equal_v1', args: {left: {input: 'a', offset: 0, length: 'rest'}, right: {input: 'b', offset: 0, length: 'rest'}}, expected: true},
  {id: 'nodiff', op: 'diff_offsets_v1', args: {left: 'a', right: 'b'}, expected: []},
];
const sansRun = r => { const x = JSON.parse(JSON.stringify(r)); delete x.run_id; delete x.utc; return canon(x); };

// ---------- N01 baseline (first end-to-end execution of the CLI) ----------
{
  const w = workspace();
  const romA = Buffer.from('ROM-A-synthetic'), romB = Buffer.from('ROM-B-synthetic');
  const pa = Buffer.from([0, 1, 0, 0, 0, 9, 7]), pb = Buffer.from([2, 1, 0, 0, 0, 9, 7]);
  const A = {id: 'r1', ...put(w, romA)}, B = {id: 'r2', ...put(w, romB)};
  const ra = put(w, pa), rb = put(w, pb);
  const pack = packOf([A, B], [
    {id: 'size', op: 'size_v1', args: {input: 'a'}, expected: 7},
    {id: 'diff', op: 'diff_offsets_v1', args: {left: 'a', right: 'b'}, expected: [0]},
    {id: 'tail', op: 'range_equal_v1', args: {left: {input: 'a', offset: 1, length: 'rest'}, right: {input: 'b', offset: 1, length: 'rest'}}, expected: true},
  ]);
  const r = cli(w, pack, h => obsOf(h, [entry('r1', ra), entry('r2', rb)]));
  const keys = r.receipt ? Object.keys(r.receipt).sort().join(',') : 'none';
  record('N01', 'baseline', 'CLI end-to-end PASS with real SHA-256', 'exit 0, one receipt, verdict PASS',
    `exit ${r.code}, verdict ${r.receipt?.results?.[0]?.verdict}, receipt keys: ${keys}`,
    r.code === 0 && r.receipt?.results?.[0]?.verdict === 'PASS');
  record('N01b', 'design', 'Receipt omits adapter identity, coverage, counts, locator and payload refs',
    'receipt is not self-contained; lineage only via observations_sha256',
    `adapter/locator/coverage present in receipt: ${['adapter', 'locator', 'coverage', 'entries'].some(k => JSON.stringify(r.receipt).includes(`"${k}"`))}`,
    !['adapter', 'locator', 'coverage', 'entries'].some(k => JSON.stringify(r.receipt).includes(`"${k}"`)));
}

// ---------- N02 artifact aliasing: two IDs, one digest -> vacuous "unchanged" PASS ----------
{
  const w = workspace();
  const rom = Buffer.from('the same ROM bytes, recorded twice by copy-paste');
  const ref = put(w, rom);
  const A = {id: 'rom132', ...ref}, B = {id: 'rom133', ...ref};
  const p = Buffer.from('payload'); const pr = put(w, p);
  const pack = packOf([A, B], unchangedChecks(p));
  let accepted = true; try { validatePack(JSON.parse(JSON.stringify(pack))); } catch { accepted = false; }
  const r = cli(w, pack, h => obsOf(h, [entry('rom132', pr), entry('rom133', pr)]));
  record('N02', 'false-PASS', 'Two artifact IDs with identical digest: "1.32 vs 1.33 unchanged" passes by comparing a ROM with itself',
    'pack validation should reject duplicate artifact digests or a==b by content; currently accepted',
    `validatePack accepted: ${accepted}; CLI exit ${r.code}, verdict ${r.receipt?.results?.[0]?.verdict}`,
    accepted && r.code === 0);
}

// ---------- N03 payload not derived from the ROM; ROM verified but never used ----------
{
  const w = workspace();
  const romA = Buffer.alloc(4096, 0xff), romB = Buffer.alloc(4096, 0xfe); // erased flash: no FV, no FFS, no GUID
  const A = {id: 'rom132', ...put(w, romA)}, B = {id: 'rom133', ...put(w, romB)};
  const p = Buffer.from('bytes invented by the adapter'); const pr = put(w, p);
  const pack = packOf([A, B], unchangedChecks(p));
  const r = cli(w, pack, h => obsOf(h, [entry('rom132', pr), entry('rom133', pr)]));
  const guidLE = Buffer.from('3F8A0FCCEA3D7643967954' + '26BA0A907E', 'hex');
  record('N03', 'false-PASS', 'Selected payload has no relation to the ROM (ROM is erased flash without the GUID); ROM hash verified, then ignored',
    'kernel has no derivation check: PASS',
    `GUID bytes in ROM a/b: ${romA.includes(guidLE)}/${romB.includes(guidLE)}; exit ${r.code}, verdict ${r.receipt?.results?.[0]?.verdict}`,
    r.code === 0 && r.receipt?.results?.[0]?.verdict === 'PASS');
}

// ---------- N04 adapter bug: b entry reuses a's payload ----------
{
  const w = workspace();
  const A = {id: 'rom132', ...put(w, Buffer.from('rom a'))}, B = {id: 'rom133', ...put(w, Buffer.from('rom b'))};
  const pa = Buffer.from('payload of 1.32'); const ra = put(w, pa);
  put(w, Buffer.from('payload of 1.33 (changed)'));
  const pack = packOf([A, B], unchangedChecks(pa));
  const r = cli(w, pack, h => obsOf(h, [entry('rom132', ra), entry('rom133', ra)]));
  record('N04', 'false-PASS', 'Adapter loop bug copies 1.32 payload ref into the 1.33 entry; real 1.33 payload changed',
    'no cross-check of payload vs artifact: PASS',
    `exit ${r.code}, verdict ${r.receipt?.results?.[0]?.verdict}`,
    r.code === 0 && r.receipt?.results?.[0]?.verdict === 'PASS');
}

// ---------- N05 forged adapter identity + relabeled pack binding ----------
{
  const w = workspace();
  const A = {id: 'r1', ...put(w, Buffer.from('ra'))}, B = {id: 'r2', ...put(w, Buffer.from('rb'))};
  const p = Buffer.from('pp'); const pr = put(w, p);
  const pack1 = packOf([A, B], unchangedChecks(p));
  const pack2 = packOf([A, B], unchangedChecks(p), {sources: [{commit: 'b'.repeat(40), path: 'y', anchor: 'changed provenance'}]});
  // observation produced for pack1 ...
  const h1 = sha(Buffer.from(canon(pack1) + '\n'));
  const obs1 = obsOf(h1, [entry('r1', pr), entry('r2', pr)], {id: 'x', sha256: '0'.repeat(64), toolchain: 'x'});
  // ... relabeled to pack2 by rewriting one field
  const r = cli(w, pack2, h2 => ({...obs1, pack_sha256: h2}));
  record('N05', 'trust-boundary', 'Adapter hash "000..0", toolchain "x"; observation for pack P1 rebound to P2 by editing pack_sha256',
    'accepted (documented limitation); binding only detects accidental reuse',
    `exit ${r.code}, verdict ${r.receipt?.results?.[0]?.verdict}`,
    r.code === 0);
}

// ---------- N06 definite falsification reported as BLOCKED ----------
function onlyCheckCase(label, pa, pb, check) {
  const w = workspace();
  const A = {id: 'r1', ...put(w, Buffer.from('ra' + label))}, B = {id: 'r2', ...put(w, Buffer.from('rb' + label))};
  const ra = put(w, pa), rb = put(w, pb);
  return cli(w, packOf([A, B], [check]), h => obsOf(h, [entry('r1', ra), entry('r2', rb)]));
}
{
  const r1 = onlyCheckCase('len', Buffer.from([1, 2, 3]), Buffer.from([1, 2, 3, 4]),
    {id: 'd', op: 'diff_offsets_v1', args: {left: 'a', right: 'b'}, expected: []});
  record('N06a', 'semantics', 'Claim "a and b differ at no offset"; b is one byte longer (proposition is false on verified bytes)',
    'should be FAIL; v0.2 gives BLOCKED (exit 2)', `exit ${r1.code}, verdict ${r1.receipt?.results?.[0]?.verdict}, reason ${r1.receipt?.results?.[0]?.checks?.[0]?.reason}`,
    r1.receipt?.results?.[0]?.verdict === 'BLOCKED');
  const big = Buffer.alloc(5000, 0), big2 = Buffer.alloc(5000, 1);
  const r2 = onlyCheckCase('lim', big, big2, {id: 'd', op: 'diff_offsets_v1', args: {left: 'a', right: 'b'}, expected: [0, 2, 3, 4, 5, 6]});
  record('N06b', 'semantics', 'Claim "differ exactly at 0,2..6"; payloads differ at all 5000 offsets',
    'should be FAIL (observed set larger than any expected set); v0.2 gives BLOCKED at the 4097th offset',
    `exit ${r2.code}, verdict ${r2.receipt?.results?.[0]?.verdict}`, r2.receipt?.results?.[0]?.verdict === 'BLOCKED');
  const r3 = onlyCheckCase('u32', Buffer.from([0, 0]), Buffer.from([0, 0]),
    {id: 'u', op: 'read_u32_le_v1', args: {input: 'a', offset: 16}, expected: 24});
  record('N06c', 'semantics', 'Claim "u32 at 16 equals 24"; verified payload is 2 bytes long',
    'arguably FAIL (no such field); v0.2 gives BLOCKED', `exit ${r3.code}, verdict ${r3.receipt?.results?.[0]?.verdict}`,
    r3.receipt?.results?.[0]?.verdict === 'BLOCKED');
}

// ---------- N07 negative-result collapse in receipts ----------
{
  const mk = (variant) => {
    const w = workspace();
    const romA = Buffer.from('ROM A'), romB = Buffer.from('ROM B');
    const A = {id: 'r1', sha256: sha(romA), size: romA.length}, B = {id: 'r2', sha256: sha(romB), size: romB.length};
    if (variant !== 'rom_missing') { put(w, romA); }
    put(w, romB);
    const p = Buffer.from('p'); const pr = put(w, p);
    const ea = variant === 'duplicate_guid' ? entry('r1', null, {owner_count: 2, raw_node_count: 2, leaf_count: 2, issues: ['duplicate_owner'], locator: null}) : entry('r1', pr);
    if (variant === 'payload_corrupt') writeFileSync(join(w, 'store', pr.sha256), Buffer.from('q'));
    const r = cli(w, packOf([A, B], unchangedChecks(p)), h => obsOf(h, [ea, entry('r2', pr)]));
    return r;
  };
  const a = mk('duplicate_guid'), b = mk('rom_missing'), c = mk('payload_corrupt');
  const sameResults = canon(a.receipt.results) === canon(b.receipt.results) && canon(b.receipt.results) === canon(c.receipt.results);
  record('N07', 'lost-negative', 'Duplicate FFS GUID (research finding) vs ROM missing from store vs corrupted payload object',
    'three different causes should be distinguishable in the receipt; v0.2 results[] are byte-identical',
    `results identical: ${sameResults}; reason: ${a.receipt.results[0].checks[0].reason}; exit codes ${a.code}/${b.code}/${c.code}`,
    sameResults);
  record('N07b', 'lost-negative', 'Same three runs: does anything outside results[] distinguish them?',
    'only observations_sha256 differs for the duplicate-GUID case; ROM-missing and corrupt-payload receipts differ only in run_id/utc',
    `b vs c identical except run_id/utc: ${sansRun(b.receipt) === sansRun(c.receipt)}`,
    sansRun(b.receipt) === sansRun(c.receipt));
}

// ---------- N08 run-level errors collapse ----------
{
  const w1 = workspace();
  const A = {id: 'r1', ...put(w1, Buffer.from('a'))}, B = {id: 'r2', ...put(w1, Buffer.from('b'))};
  const bad = packOf([A, B], [{id: 'x', op: 'eval', args: {}, expected: true}]);
  const r1 = cli(w1, bad, h => obsOf(h, []));
  const w2 = workspace();
  const A2 = {id: 'r1', ...put(w2, Buffer.from('a'))}, B2 = {id: 'r2', ...put(w2, Buffer.from('b'))};
  const r2 = cli(w2, packOf([A2, B2], unchangedChecks(Buffer.from('p'))), h => obsOf('c'.repeat(64), []));
  record('N08', 'lost-negative', 'Unknown operation in pack vs observation bound to another pack',
    'both produce the same run_error; cause only on stderr (not retained)',
    `run_error: "${r1.receipt?.run_error}" / "${r2.receipt?.run_error}"; stderr: "${r1.stderr}" / "${r2.stderr}"`,
    r1.receipt?.run_error === r2.receipt?.run_error && r1.code === 2 && r2.code === 2);
}

// ---------- N09 exit-code precedence changed vs v1 ----------
{
  const w = workspace();
  const A = {id: 'r1', ...put(w, Buffer.from('a'))}, B = {id: 'r2', ...put(w, Buffer.from('b'))};
  const p = Buffer.from('pp'); const pr = put(w, p);
  const pack = packOf([A, B], [{id: 'size', op: 'size_v1', args: {input: 'a'}, expected: 3}]);
  pack.selectors.push({id: 's2', kind: 'unique_ffs_leaf_v1', guid: '9FE7DE69-0AEA-470A-B50A-139813649189', section_type: 25});
  pack.claims.push({...pack.claims[0], id: 'c2', selector: 's2'});
  const r = cli(w, pack, h => obsOf(h, [entry('r1', pr), entry('r2', pr), entry('r1', null, {selector: 's2', coverage: 'unknown', locator: null}), entry('r2', pr, {selector: 's2'})]));
  record('N09', 'compat', 'One claim FAIL, another BLOCKED', 'v0.2 exits 1; v1 verify.py exits 2 for the same mix (precedence inverted)',
    `exit ${r.code}, verdicts ${r.receipt?.results?.map(x => x.verdict).join('/')}`, r.code === 1);
}

// ---------- N10 receipt write failure loses a FAIL ----------
{
  const w = workspace();
  const A = {id: 'r1', ...put(w, Buffer.from('a'))}, B = {id: 'r2', ...put(w, Buffer.from('b'))};
  const p = Buffer.from('pp'); const pr = put(w, p);
  writeFileSync(join(w, 'receipts-is-a-file'), 'x');
  const r = cli(w, packOf([A, B], [{id: 'size', op: 'size_v1', args: {input: 'a'}, expected: 3}]), h => obsOf(h, [entry('r1', pr), entry('r2', pr)]), join(w, 'receipts-is-a-file'));
  record('N10', 'lost-negative', 'Receipt directory unwritable while the claim FAILs',
    'exit 2 and no durable record of the FAIL (stdout carries nothing)', `exit ${r.code}, stdout "${r.stdout}", stderr "${r.stderr}"`,
    r.code === 2 && r.stdout === '');
}

// ---------- N11 privacy / path hygiene ----------
{
  const w = workspace();
  const A = {id: 'r1', ...put(w, Buffer.from('a'))}, B = {id: 'r2', ...put(w, Buffer.from('b'))};
  const p = Buffer.from('pp'); const pr = put(w, p);
  const pack = packOf([A, B], unchangedChecks(p), {sources: [{commit: 'a'.repeat(40), path: '../../../../etc/passwd', anchor: 'x'}]});
  const r = cli(w, pack, h => obsOf(h, [entry('r1', pr, {locator: '/home/ivan/private/BD790i/dumps/serial-XYZ123/body.bin'}), entry('r2', pr)]));
  record('N11', 'privacy', 'Absolute local path with serial number in locator; non-repository-relative source path',
    'spec says avoid local paths / repository-relative; validator accepts both', `exit ${r.code}`, r.code === 0);
}

// ---------- N12 deep nesting ----------
{
  const depth = 3_000_000;
  const s = '['.repeat(depth) + ']'.repeat(depth) + '\n';
  let outcome;
  try { parseCanonical(s); outcome = 'accepted'; } catch (e) { outcome = `${e.constructor.name}: ${String(e.message).slice(0, 60)}`; }
  record('N12', 'dos', `Document of ${s.length} bytes with nesting depth ${depth} (under the 8 MiB limit)`,
    'rejected by an exception (no crash); nesting depth is not part of the profile', outcome, outcome !== 'accepted');
}

// ---------- N13 self-test digest is non-injective ----------
{
  const digest = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('').padEnd(64, '0');
  const x = Uint8Array.of(0x4d), y = Uint8Array.of(0x4d, 0x00);
  record('N13', 'test-quality', 'selftest digest: [4d] and [4d 00] collide', 'collision (tests cannot detect trailing-zero truncation/extension)',
    `${digest(x) === digest(y)}`, digest(x) === digest(y));
}

// ---------- N14 scale limit ----------
{
  const p = {version: '0.2', artifacts: [{id: 'r1', sha256: 'a'.repeat(64), size: 1}, {id: 'r2', sha256: 'b'.repeat(64), size: 1}],
    selectors: [{id: 's', kind: 'unique_ffs_leaf_v1', guid: GUID, section_type: 25}],
    claims: Array.from({length: 2256}, (_, i) => ({id: 'k' + i, selector: 's', inputs: {a: 'r1', b: 'r2'}, sources: [{commit: 'a'.repeat(40), path: 'x', anchor: 'x'}], predecessor: null, checks: [{id: 'z', op: 'size_v1', args: {input: 'a'}, expected: 1}]}))};
  let msg = 'accepted'; try { validatePack(p); } catch (e) { msg = e.message; }
  record('N14', 'scale', '2256 inventory keys in one pack', 'rejected (limit 1024 claims/selectors): sharding and cross-pack identity required', msg, msg !== 'accepted');
}

// ---------- N15 hardening confirmed (positive findings) ----------
{
  const good = '{"a":1}\n';
  const variants = {
    'duplicate key': '{"a":1,"a":1}\n', 'unicode escape': '{"\\u0061":1}\n', 'decimal': '{"a":1.0}\n', 'exponent': '{"a":1e0}\n',
    'negative zero': '{"a":-0}\n', '2^53+1': '{"a":9007199254740993}\n', 'BOM': '\ufeff{"a":1}\n', 'non-ASCII': '{"a":"\u00e9"}\n',
    'unsorted': '{"b":1,"a":2}\n', 'whitespace': '{"a": 1}\n', 'no LF': '{"a":1}', 'CRLF': '{"a":1}\r\n', 'escaped slash': '{"a":"\\/"}\n',
    'control char': '{"a":"\\n"}\n', 'negative': '{"a":-1}\n',
  };
  const accepted = Object.entries(variants).filter(([, s]) => { try { parseCanonical(s); return true; } catch { return false; } }).map(([k]) => k);
  let goodOk = true; try { parseCanonical(good); } catch { goodOk = false; }
  record('N15', 'hardening-ok', `Canonical profile rejects ${Object.keys(variants).length} non-canonical encodings`, 'all rejected, canonical accepted',
    `accepted: [${accepted.join(', ')}], canonical ok: ${goodOk}`, accepted.length === 0 && goodOk);
}

writeFileSync(join(root, 'results.json'), JSON.stringify(rows, null, 2));
console.log(`\n${n - failures}/${n} expectations hold. Temp dir: ${root}`);
rmSync(root, {recursive: true, force: true});
process.exit(failures ? 1 : 0);
