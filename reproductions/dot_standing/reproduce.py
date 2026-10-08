#!/usr/bin/env python3
"""Re-run a published DOT-STANDING elimination from its frozen code and check the result.

Every DOT-STANDING page on kryptosbot.com is backed by this directory. For one campaign the
runner:

1. checks the SHA-256 of every frozen source file and every recorded input against
   manifest.json (frozen sources are byte-identical to the files that ran);
2. copies them into a fresh work directory, rewriting only the declared absolute paths of
   the original machine (manifest "rewrites");
3. starts a replay clock at the original run's start instant, because the frozen code
   refuses to run after its authorization window closed (2026-10-06 23:30 UTC);
4. rebuilds any route bank the search reads and checks its SHA-256 against the bank that
   was used;
5. runs the target pass exactly as recorded (or, for the earliest runs whose launch command
   was not logged, the inferred call named in the manifest);
6. compares the result with the published record. Every key the frozen code emits must be
   equal; timing keys are ignored; keys present only in the published record must be on the
   campaign's declared list of orchestration annotations.

Layout: campaigns.json (what to run and the expected hashes), frozen/ redacted/ shims/ (code),
inputs/<run>/ (recorded files the search reads), records/<run>/ (the published result record).

Exit status is 0 only if every requested campaign reproduces.

Usage:
    python3 reproductions/dot_standing/reproduce.py DOT-STANDING-001 [DOT-STANDING-002 ...]
    python3 reproductions/dot_standing/reproduce.py --all
    python3 reproductions/dot_standing/reproduce.py --list
Requires: pip install -r reproductions/dot_standing/requirements.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "campaigns.json"

# Installed as sitecustomize.py in the work directory. Shifts time.time() so the frozen
# code sees the clock it ran under; elapsed time still advances at the real rate.
REPLAY_CLOCK = '''import os
_EPOCH = os.environ.get("DOT_REPLAY_EPOCH")
if _EPOCH:
    import time as _time
    _base, _start = float(_EPOCH), _time.monotonic()
    _time.time = lambda: _base + (_time.monotonic() - _start)
'''


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text())


def rewrite(text: str, rules: list[list[str]], work: Path) -> str:
    for old, new in rules:
        text = text.replace(old, new.replace("{PY}", sys.executable).replace("{WORK}", str(work)))
    return text


def canonical_json_sha256(path: Path, volatile: re.Pattern[str]) -> str:
    """SHA-256 of a JSON file with timing keys removed and keys sorted."""
    obj = canon(json.loads(path.read_text()), volatile)
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def check_hashes(files: dict[str, Any], base: Path, label: str, volatile: re.Pattern[str] | None = None) -> list[str]:
    """Each value is a raw SHA-256, or {"canonical_json_sha256": ...} for JSON whose only drift is timing."""
    bad = []
    for rel, want in files.items():
        path = base / rel
        if not path.is_file():
            bad.append(f"{label} missing: {rel}")
        elif isinstance(want, dict):
            if canonical_json_sha256(path, volatile or re.compile("$^")) != want["canonical_json_sha256"]:
                bad.append(f"{label} content mismatch (timing keys ignored): {rel}")
        elif sha256(path) != want:
            bad.append(f"{label} hash mismatch: {rel}")
    return bad


TREES = {"frozen": "frozen", "redacted": "redacted", "shim": "shims"}


def input_path(rel: str) -> Path:
    """Recorded inputs are stored as inputs/<run>/<file>; the work directory has analysis_runs/<run>/<file>."""
    return HERE / "inputs" / rel.removeprefix("analysis_runs/")


def code_problems(c: dict[str, Any]) -> list[str]:
    bad = []
    for kind, tree in TREES.items():
        files = {rel: e["sha256"] for rel, e in c["code"].items() if e["kind"] == kind}
        bad += check_hashes(files, HERE / tree, kind)
    return bad


def materialize(c: dict[str, Any], m: dict[str, Any], work: Path) -> None:
    rules = m["rewrites"]
    for rel, entry in c["code"].items():
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(rewrite((HERE / TREES[entry["kind"]] / rel).read_text(), rules, work))
    for rel in c["inputs"]:
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(input_path(rel), dst)
    for d in ("_outcomes", "_campaign", "_replay", "analysis_runs/" + c["run"]):
        (work / d).mkdir(parents=True, exist_ok=True)
    (work / "_replay" / "sitecustomize.py").write_text(REPLAY_CLOCK)


def step_env(c: dict[str, Any], work: Path, workers: int | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "K4_", "OMP_", "MKL_", "OPENBLAS_"))}
    env.update({"PYTHONPATH": str(work / "_replay"), "PYTHONDONTWRITEBYTECODE": "1",
                "DOT_REPLAY_EPOCH": repr(c["epoch"]), "OMP_NUM_THREADS": "1",
                "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", **c.get("env", {})})
    if workers:
        # Only parallelism: these knobs size the worker pool and never change the scope.
        env.update({"K4_NUMERIC_WORKERS": str(workers), "K4_WORKERS": str(workers)})
    return env


def run_step(argv: list[str], m: dict[str, Any], work: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    argv = [rewrite(a, m["rewrites"], work) for a in argv]
    argv[0] = sys.executable
    return subprocess.run(argv, cwd=work, env=env, capture_output=True, text=True, timeout=timeout)


def canon(obj: Any, volatile: re.Pattern[str]) -> Any:
    if isinstance(obj, dict):
        return {k: canon(v, volatile) for k, v in obj.items() if not volatile.search(k)}
    if isinstance(obj, list):
        return [canon(v, volatile) for v in obj]
    return obj


def compare(ref: Any, new: Any, annotations: set[str], volatile: re.Pattern[str], path: str = "") -> list[str]:
    """Strict structural comparison; returns human-readable differences."""
    if isinstance(ref, dict) and isinstance(new, dict):
        out = []
        for k in sorted(set(ref) | set(new)):
            if volatile.search(k):
                continue
            if k not in new:
                # Declared annotations are top-level keys the private queue added to the record.
                if path or k not in annotations:
                    out.append(f"{path}/{k}: in published record only")
            elif k not in ref:
                out.append(f"{path}/{k}: produced but not in published record")
            else:
                out += compare(ref[k], new[k], annotations, volatile, f"{path}/{k}")
        return out
    if isinstance(ref, list) and isinstance(new, list):
        if len(ref) != len(new):
            return [f"{path}: length {len(ref)} != {len(new)}"]
        return [d for a, b in zip(ref, new) for d in compare(a, b, annotations, volatile, path + "[]")]
    return [] if ref == new else [f"{path}: {str(ref)[:60]!r} != {str(new)[:60]!r}"]


def select(obj: Any, key: str | None) -> Any:
    return obj if not key else obj[key]


def reproduce(cid: str, m: dict[str, Any], args: argparse.Namespace) -> bool:
    c = m["campaigns"][cid]
    print(f"== {cid}: {c['title']}")
    problems = code_problems(c)
    problems += [f"input hash mismatch: {rel}" for rel, want in c["inputs"].items()
                 if not input_path(rel).is_file() or sha256(input_path(rel)) != want]
    problems += check_hashes({"target.json": c["compare"]["reference_sha256"]}, HERE / "records" / c["run"], "record")
    if problems:
        print("   FAIL integrity\n   " + "\n   ".join(problems))
        return False
    kinds = [e["kind"] for e in c["code"].values()]
    print(f"   integrity ok: {kinds.count('frozen')} byte-identical frozen files, {kinds.count('redacted')} redacted "
          f"library files, {kinds.count('shim')} shims, {len(c['inputs'])} recorded inputs")
    if args.verify_only:
        return True
    root = Path(args.work_dir) if args.work_dir else Path(tempfile.mkdtemp(prefix="dot_repro_"))
    work = root / c["run"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    try:
        materialize(c, m, work)
        env = step_env(c, work, args.workers)
        for bank in c.get("banks", []):
            t0 = time.perf_counter()
            if "copy" in bank:
                # The same bank bytes are read from a second directory; copy, then check them
                # against that directory's own recorded hashes.
                src, dst = work / bank["copy"]["from"], work / bank["copy"]["to"]
                dst.mkdir(parents=True, exist_ok=True)
                for name in bank["copy"]["files"]:
                    shutil.copyfile(src / name, dst / name)
                bad = []
            else:
                r = run_step(bank["argv"], m, work, env, args.timeout)
                bad = [] if r.returncode == 0 else [f"exit {r.returncode}: {r.stderr.strip()[-300:]}"]
            bad += check_hashes(bank["expect"], work, "bank", re.compile(m["volatile_key_regex"], re.I))
            print(f"   bank {bank['name']}: {'ok' if not bad else 'FAIL'} ({time.perf_counter() - t0:.1f}s)")
            if bad:
                print("   " + "\n   ".join(bad))
                return False
        t0 = time.perf_counter()
        r = run_step(c["target"]["argv"], m, work, env, args.timeout)
        secs = time.perf_counter() - t0
        if r.returncode:
            print(f"   FAIL target pass exit {r.returncode} after {secs:.1f}s\n   {r.stderr.strip()[-600:]}")
            return False
        produced_path = work / "analysis_runs" / c["run"] / "target.json"
        if c["target"].get("stdout_is_result"):
            produced = json.loads(r.stdout.strip().splitlines()[-1])
        else:
            produced = json.loads(produced_path.read_text())
        ref = json.loads((HERE / "records" / c["run"] / "target.json").read_text())
        volatile = re.compile(m["volatile_key_regex"], re.I)
        cmp = c["compare"]
        ref_part, new_part = select(ref, cmp.get("reference_key")), select(produced, cmp.get("produced_key"))
        if cmp.get("sort"):
            ref_part = sorted(ref_part, key=lambda x: json.dumps(canon(x, volatile), sort_keys=True))
            new_part = sorted(new_part, key=lambda x: json.dumps(canon(x, volatile), sort_keys=True))
        diffs = compare(ref_part, new_part, set(cmp.get("annotations", [])), volatile)
        if diffs:
            print(f"   FAIL result differs from the published record ({len(diffs)} differences):")
            print("   " + "\n   ".join(diffs[:20]))
            return False
        skipped = sorted(set(cmp.get("annotations", [])) & set(ref_part if isinstance(ref_part, dict) else {}))
        if skipped:
            print(f"   not re-derived (added to the record by the private orchestrator after the pass): {', '.join(skipped)}")
        print(f"   REPRODUCED in {secs:.1f}s: {c['claim']}")
        return True
    finally:
        if not args.keep and not args.work_dir:
            shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("ids", nargs="*", help="campaign ids, e.g. DOT-STANDING-001")
    ap.add_argument("--all", action="store_true", help="reproduce every published campaign")
    ap.add_argument("--list", action="store_true", help="list published campaigns and exit")
    ap.add_argument("--verify-only", action="store_true", help="check SHA-256 integrity only, run nothing")
    ap.add_argument("--workers", type=int, help="worker-pool size for probes that read it (does not change scope)")
    ap.add_argument("--work-dir", help="keep work directories here instead of a temp dir")
    ap.add_argument("--keep", action="store_true", help="keep the temporary work directory")
    ap.add_argument("--timeout", type=int, default=7200, help="seconds allowed per step")
    args = ap.parse_args(argv)
    m = load_manifest()
    if args.list:
        for cid, c in m["campaigns"].items():
            print(f"{cid}  {c['title']}")
        return 0
    ids = list(m["campaigns"]) if args.all else [i.upper() for i in args.ids]
    unknown = [i for i in ids if i not in m["campaigns"]]
    if not ids or unknown:
        ap.error(f"unknown campaign(s): {unknown}" if unknown else "give campaign ids, --all or --list")
    if not args.verify_only:
        missing = [mod for mod in m["requires_modules"] if subprocess.run(
            [sys.executable, "-c", f"import {mod}"], capture_output=True).returncode]
        if missing:
            print(f"Missing Python packages {missing}; run: pip install -r {HERE.relative_to(Path.cwd()) if HERE.is_relative_to(Path.cwd()) else HERE}/requirements.txt")
            return 2
    ok = [reproduce(i, m, args) for i in ids]
    print(f"\n{sum(ok)}/{len(ok)} {'passed integrity checks (nothing was run)' if args.verify_only else 'reproduced'}")
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
