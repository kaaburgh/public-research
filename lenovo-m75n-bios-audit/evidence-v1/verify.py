#!/usr/bin/env python3
"""Read-only evidence v1 pilot; Python 3.10+, stdlib."""
import argparse
import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
HEX = re.compile(r"[0-9a-f]{64}")
GUID = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(obj, keys):
    require(isinstance(obj, dict) and set(obj) == set(keys.split()), "unexpected/missing fields")


def valid_hash(s):
    return isinstance(s, str) and HEX.fullmatch(s) is not None


def no_duplicate_keys(items):
    obj = {}
    for k, v in items:
        require(k not in obj, "duplicate JSON key: " + k)
        obj[k] = v
    return obj


def validate(reg):
    exact_keys(reg, "schema_version source_commit artifacts claims")
    require(type(reg["schema_version"]) is int and reg["schema_version"] == 1, "schema")
    require(isinstance(reg["source_commit"], str) and re.fullmatch("[0-9a-f]{40}", reg["source_commit"]), "source commit")
    exact_keys(reg["artifacts"], "rom132 rom133")
    for a in reg["artifacts"].values():
        exact_keys(a, "size sha256")
        require(type(a["size"]) is int and a["size"] == 16777216 and valid_hash(a["sha256"]), "artifact")
    require(isinstance(reg["claims"], list) and reg["claims"], "claims")
    ids = set()
    selectors = set()
    for c in reg["claims"]:
        exact_keys(c, "id predicate state selector inputs expected sources")
        require(isinstance(c["id"], str) and re.fullmatch(r"SB-[0-9]{3}", c["id"]) and c["id"] not in ids, "claim id")
        ids.add(c["id"])
        require(c["predicate"] == "auth_container_pair_v1" and c["state"] == "imported_unverified", "predicate/state")
        require(c["inputs"] == ["rom132", "rom133"], "input order")
        s = c["selector"]
        exact_keys(s, "guid section expected_occurrences")
        require(isinstance(s["guid"], str) and GUID.fullmatch(s["guid"]) and s["guid"] not in selectors, "selector GUID")
        selectors.add(s["guid"])
        require(s["section"] == "Raw section" and type(s["expected_occurrences"]) is int and s["expected_occurrences"] == 1, "selector")
        e = c["expected"]
        exact_keys(e, "size_each body_sha256 dwLength_each suffix_offset suffix_sha256_each allowed_diff_offsets require_nonempty_diff")
        require(type(e["size_each"]) is int and 40 < e["size_each"] <= 16777216, "size")
        require(isinstance(e["body_sha256"], list) and len(e["body_sha256"]) == 2 and all(map(valid_hash, e["body_sha256"])), "body hash")
        require(valid_hash(e["suffix_sha256_each"]), "suffix hash")
        require(type(e["dwLength_each"]) is int and e["dwLength_each"] == 24 and type(e["suffix_offset"]) is int and e["suffix_offset"] == 40, "header contract")
        require(isinstance(e["allowed_diff_offsets"], list) and all(type(x) is int for x in e["allowed_diff_offsets"]) and e["allowed_diff_offsets"] == [0,2,3,4,5,6] and e["require_nonempty_diff"] is True, "diff contract")
        require(isinstance(c["sources"], list) and len(c["sources"]) == 2, "sources")
        for source in c["sources"]:
            exact_keys(source, "path anchor")
            require(all(isinstance(x, str) and x for x in source.values()), "source")
    return reg


def meta(path):
    fields = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            if k == "File GUID" and k in fields:
                raise ValueError("duplicate File GUID metadata")
            fields[k] = v
    return fields


def locate(root, selector):
    owners = []
    for p in root.rglob("info.txt"):
        g = meta(p).get("File GUID", "").upper()
        if g == selector["guid"]:
            owners.append(p.parent)
    require(len(owners) == 1, "expected exactly one FFS owner; got " + str(len(owners)))
    owner = owners[0]
    matches = []
    for p in owner.rglob("body.bin"):
        if re.sub(r"^\d+ ", "", p.parent.name) != selector["section"]:
            continue
        # Refuse a body belonging to a nested FFS file.
        if any("File GUID" in meta(q / "info.txt")
               for q in p.parents if q != owner and owner in q.parents and (q / "info.txt").is_file()):
            continue
        if any(q.is_dir() for q in p.parent.iterdir()):
            continue
        require(not p.is_symlink() and p.resolve().is_relative_to(root.resolve()), "unsafe extracted path")
        matches.append(p)
    require(len(matches) == selector["expected_occurrences"], "ambiguous/missing Raw section: " + str(len(matches)))
    return matches[0]


def observe(a, b):
    sizes = [len(a), len(b)]
    lengths = [int.from_bytes(x[16:20], "little") if len(x) >= 20 else None for x in (a,b)]
    starts = [16 + x if x is not None else None for x in lengths]
    suffixes = [x[o:] if o is not None and 40 <= o < len(x) else None for x,o in zip((a,b), starts)]
    return {
        "sizes": sizes,
        "body_sha256": [digest(a),digest(b)],
        "dwLength": lengths,
        "suffix_offsets": starts,
        "suffix_sha256": [digest(x) if x is not None else None for x in suffixes],
        "suffix_equal": suffixes[0] is not None and suffixes[1] is not None and suffixes[0] == suffixes[1],
        "diff_offsets": [i for i,(x,y) in enumerate(zip(a,b)) if x != y] if len(a) == len(b) else None,
    }


def evaluate(obs, e):
    d = obs["diff_offsets"]
    checks = {
        "size_each": obs["sizes"] == [e["size_each"]] * 2,
        "body_sha256": obs["body_sha256"] == e["body_sha256"],
        "dwLength_each": obs["dwLength"] == [e["dwLength_each"]] * 2,
        "suffix_offset": obs["suffix_offsets"] == [e["suffix_offset"]] * 2,
        "suffix_sha256_each": obs["suffix_sha256"] == [e["suffix_sha256_each"]] * 2,
        "suffix_equal": obs["suffix_equal"],
        "diff_scope": d is not None and set(d) <= set(e["allowed_diff_offsets"]),
        "nonempty_diff": bool(d) if e["require_nonempty_diff"] else True,
    }
    return checks, "PASS" if all(checks.values()) else "FAIL"


def self_test(reg):
    import copy
    a = bytearray(100)
    a[16:20] = (24).to_bytes(4, "little")
    b = bytearray(a)
    b[2] = 1
    e = dict(reg["claims"][0]["expected"])
    e.update(size_each=len(a), body_sha256=[digest(a), digest(b)], suffix_sha256_each=digest(a[40:]))
    require(evaluate(observe(a,b),e)[1] == "PASS", "positive test")
    for idx in (1, 16, 40, 99):
        c = bytearray(b)
        c[idx] ^= 1
        require(evaluate(observe(a,c),e)[1] == "FAIL", "changed byte accepted")
    require(evaluate(observe(a,b[:-1]),e)[1] == "FAIL", "truncation accepted")
    require(evaluate(observe(a,a),e)[1] == "FAIL", "missing diff accepted")
    invalid = copy.deepcopy(reg)
    invalid["claims"][0]["expected"]["extra"] = True
    try:
        validate(invalid)
    except ValueError:
        pass
    else:
        raise ValueError("invalid registry accepted")
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        owner = root / "0 file"
        leaf = owner / "0 Raw section"
        leaf.mkdir(parents=True)
        selector = reg["claims"][0]["selector"]
        (owner / "info.txt").write_text("File GUID: " + selector["guid"])
        (leaf / "body.bin").write_bytes(a)
        require(locate(root, selector) == leaf / "body.bin", "locator positive")
        other = owner / "1 Raw section"
        other.mkdir()
        (other / "body.bin").write_bytes(b)
        try:
            locate(root, selector)
        except ValueError:
            pass
        else:
            raise ValueError("ambiguous locator accepted")
    print("self-test PASS (synthetic only)")


def run(args, raw, reg):
    receipt = {
        "schema_version": 1,
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "registry_sha256": digest(raw),
        "verifier_sha256": file_digest(pathlib.Path(__file__)),
        "source_commit": reg["source_commit"],
        "python": sys.version,
        "platform": platform.platform(),
        "artifacts": {},
        "extractor_sha256": None,
        "results": [],
    }
    try:
        paths = [pathlib.Path(x).resolve(strict=True) for x in (args.rom132,args.rom133)]
        extractor = pathlib.Path(args.extractor).resolve(strict=True)
        receipt["extractor_sha256"] = file_digest(extractor)
        with tempfile.TemporaryDirectory(prefix="m75n-evidence-") as d:
            wd = pathlib.Path(d)
            roots = []
            for key, src in zip(("rom132","rom133"), paths):
                target = wd / (key + ".rom")
                shutil.copyfile(src, target)
                actual = {"size":target.stat().st_size,"sha256":file_digest(target)}
                receipt["artifacts"][key] = actual
                require(actual == reg["artifacts"][key], "input identity mismatch: " + key)
                log = wd / (key + ".extract.log")
                with log.open("wb") as f:
                    completed = subprocess.run([str(extractor),target.name,"all"],cwd=wd,stdout=f,stderr=subprocess.STDOUT,timeout=600,check=False)
                receipt["artifacts"][key]["extract_exit"] = completed.returncode
                receipt["artifacts"][key]["extract_log_sha256"] = file_digest(log)
                require(completed.returncode == 0, "extraction exit " + str(completed.returncode) + ": " + key)
                require(file_digest(target) == actual["sha256"], "extractor modified working copy")
                root = wd / (target.name + ".dump")
                require(root.is_dir(), "missing extraction tree")
                roots.append(root)
            for c in reg["claims"]:
                r = {"id":c["id"],"claim_sha256":digest(json.dumps(c,sort_keys=True,separators=(",",":")).encode())}
                try:
                    p = [locate(root,c["selector"]) for root in roots]
                    r["selected_paths"] = [str(x.relative_to(root)) for x,root in zip(p,roots)]
                    r["observed"] = observe(*(x.read_bytes() for x in p))
                    r["checks"],r["verdict"] = evaluate(r["observed"],c["expected"])
                except (OSError,ValueError) as exc:
                    r.update(verdict="BLOCKED",error=str(exc))
                receipt["results"].append(r)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        receipt["error"] = str(exc)
        done = {r["id"] for r in receipt["results"]}
        receipt["results"].extend({"id":c["id"],"verdict":"BLOCKED","error":"input/extraction prerequisite failed"} for c in reg["claims"] if c["id"] not in done)
    return receipt


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--rom132")
    p.add_argument("--rom133")
    p.add_argument("--extractor")
    p.add_argument("--out",type=pathlib.Path)
    args = p.parse_args()
    raw = (HERE / "claims.json").read_bytes()
    reg = validate(json.loads(raw,object_pairs_hook=no_duplicate_keys))
    if args.self_test:
        self_test(reg)
        return 0
    if not all((args.rom132,args.rom133,args.extractor,args.out)):
        p.error("all four input/output options required")
    if args.out.exists():
        p.error("output already exists")
    receipt = run(args,raw,reg)
    with args.out.open("x",encoding="utf-8") as f:
        json.dump(receipt,f,indent=2)
        f.write("\n")
    for r in receipt["results"]:
        print(r["id"],r["verdict"])
    states = {r["verdict"] for r in receipt["results"]}
    return 2 if "BLOCKED" in states else 1 if "FAIL" in states else 0


if __name__ == "__main__":
    sys.exit(main())
