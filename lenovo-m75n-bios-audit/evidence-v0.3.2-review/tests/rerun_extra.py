"""Re-run only the addendum (final version) against every mutant of mutation_v032_review.py; author columns are taken
from mutation_v032_review_run.txt (author suite unchanged)."""
import ast, os, pathlib, re, shutil, subprocess, sys, tempfile
src = pathlib.Path(sys.argv[1]).resolve(); here = pathlib.Path(__file__).resolve().parent
M = ast.literal_eval('[' + (here / 'mutation_v032_review.py').read_text().split("M = [", 1)[1].split("\n]\n", 1)[0] + ']')
author = {l.split()[0]: l.split()[1].split(':')[1] for l in (here.parent / 'results' / 'mutation_v032_review_run.txt').read_text().splitlines() if ' author:' in l}
eq = re.findall(r"^ '([^']+)': ", (here / 'mutation_v032_review.py').read_text().split('EQUIVALENT = {', 1)[1].split('}', 1)[0], re.M)
rows = []
for mid, f, old, new, meaning in M:
    with tempfile.TemporaryDirectory() as d:
        dst = pathlib.Path(d) / 'v'; shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__'))
        t = (dst / f).read_text(); assert t.count(old) == 1, mid; (dst / f).write_text(t.replace(old, new))
        o = subprocess.run([sys.executable, '-m', 'unittest', '-q', 'test_v032_addendum'], cwd=str(here), capture_output=True, text=True, env=dict(os.environ, V03_DIR=str(dst)), timeout=600)
        m = re.search(r'FAILED \(([^)]*)\)', o.stderr); tail = m.group(1) if m else ('OK' if o.returncode == 0 else 'crash')
        x = 'assert' if 'failures=' in tail else 'SURVIVED' if tail == 'OK' else 'error-only'
    rows.append((mid, author[mid], x)); print(f'{mid:7} author:{author[mid]:10} extra:{x:10} {meaning}', flush=True)
live = [r for r in rows if r[0] not in eq]
comb = lambda a, x: 'assert' if 'assert' in (a, x) else 'error-only' if 'error-only' in (a, x) else 'SURVIVED'
print(f'\nequivalent (excluded): {sorted(eq)}')
print(f'non-equivalent {len(live)}; combined author+addendum: survived {[r[0] for r in live if comb(r[1], r[2]) == "SURVIVED"]}; '
      f'errors-only {[r[0] for r in live if comb(r[1], r[2]) == "error-only"]}; assertion-killed {sum(comb(r[1], r[2]) == "assert" for r in live)}')
