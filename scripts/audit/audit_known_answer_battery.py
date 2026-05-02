#!/usr/bin/env python3
"""Known-answer audit battery for hand-cipher solver claims."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_SELF_TEST = REPO_ROOT / "results" / "audit" / "known_answer_self_test_raw.json"
RESULT_PATH = REPO_ROOT / "results" / "audit" / "known_answer_battery.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "known_answer_battery.md"
STATIC_CORPUS_PATH = REPO_ROOT / "tests" / "audit" / "known_answer_corpus.json"
COMPOSITE_CORPUS_PATH = REPO_ROOT / "tests" / "audit" / "known_answer_composites.json"
EXTERNAL_CORPUS_PATH = REPO_ROOT / "tests" / "audit" / "external_known_answer_corpus.json"
EXTERNAL_COMPOSITE_CORPUS_PATH = REPO_ROOT / "tests" / "audit" / "external_known_answer_composites.json"
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def clean(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPH)


def shift_char(ch: str, shift: int) -> str:
    return ALPH[(ALPH.index(ch) + shift) % 26]


def caesar_encrypt(pt: str, shift: int) -> str:
    return "".join(shift_char(ch, shift) for ch in clean(pt))


def affine_encrypt(pt: str, a: int, b: int) -> str:
    return "".join(ALPH[(a * ALPH.index(ch) + b) % 26] for ch in clean(pt))


def vig_encrypt(pt: str, key: str) -> str:
    key_nums = [ALPH.index(ch) for ch in clean(key)]
    return "".join(ALPH[(ALPH.index(ch) + key_nums[i % len(key_nums)]) % 26] for i, ch in enumerate(clean(pt)))


def beaufort_encrypt(pt: str, key: str) -> str:
    key_nums = [ALPH.index(ch) for ch in clean(key)]
    return "".join(ALPH[(key_nums[i % len(key_nums)] - ALPH.index(ch)) % 26] for i, ch in enumerate(clean(pt)))


def variant_beaufort_encrypt(pt: str, key: str) -> str:
    key_nums = [ALPH.index(ch) for ch in clean(key)]
    return "".join(ALPH[(ALPH.index(ch) - key_nums[i % len(key_nums)]) % 26] for i, ch in enumerate(clean(pt)))


def columnar_encrypt(pt: str, width: int, order: list[int]) -> str:
    text = clean(pt)
    rows = [text[i : i + width] for i in range(0, len(text), width)]
    out = []
    for col in order:
        for row in rows:
            if col < len(row):
                out.append(row[col])
    return "".join(out)


def route_boustrophedon_encrypt(pt: str, width: int) -> str:
    rows = [clean(pt)[i : i + width] for i in range(0, len(clean(pt)), width)]
    out = []
    for i, row in enumerate(rows):
        out.append(row if i % 2 == 0 else row[::-1])
    return "".join(out)


def synthetic_fixtures() -> list[dict[str, Any]]:
    pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRUNSNORTH"
    fixtures = [
        {"family": "caesar", "plaintext": pt, "ciphertext": caesar_encrypt(pt, 8), "params": {"shift": 8}},
        {"family": "affine", "plaintext": pt, "ciphertext": affine_encrypt(pt, 5, 7), "params": {"a": 5, "b": 7}},
        {"family": "vigenere", "plaintext": pt, "ciphertext": vig_encrypt(pt, "ORBIT"), "params": {"keyword": "ORBIT"}},
        {"family": "beaufort", "plaintext": pt, "ciphertext": beaufort_encrypt(pt, "ORBIT"), "params": {"keyword": "ORBIT"}},
        {"family": "variant_beaufort", "plaintext": pt, "ciphertext": variant_beaufort_encrypt(pt, "ORBIT"), "params": {"keyword": "ORBIT"}},
        {"family": "columnar", "plaintext": pt, "ciphertext": columnar_encrypt(pt, 7, [2, 0, 5, 1, 6, 3, 4]), "params": {"width": 7, "order": [2, 0, 5, 1, 6, 3, 4]}},
        {"family": "route_boustrophedon", "plaintext": pt, "ciphertext": route_boustrophedon_encrypt(pt, 9), "params": {"width": 9}},
        {"family": "two_layer_caesar_columnar", "plaintext": pt, "ciphertext": columnar_encrypt(caesar_encrypt(pt, 3), 6, [4, 2, 0, 5, 1, 3]), "params": {"shift": 3, "width": 6, "order": [4, 2, 0, 5, 1, 3]}},
    ]
    for fixture in fixtures:
        fixture["negative_controls"] = [
            "wrong_alphabet_KA_or_IJ_merge",
            "wrong_crib_positions",
            "wrong_variant_direction",
            "random_ciphertext_same_length",
        ]
    return fixtures


def static_corpus() -> list[dict[str, Any]]:
    if not STATIC_CORPUS_PATH.exists():
        return []
    return json.loads(STATIC_CORPUS_PATH.read_text())


def composite_corpus() -> list[dict[str, Any]]:
    if not COMPOSITE_CORPUS_PATH.exists():
        return []
    return json.loads(COMPOSITE_CORPUS_PATH.read_text())


def external_corpus() -> list[dict[str, Any]]:
    if not EXTERNAL_CORPUS_PATH.exists():
        return []
    return json.loads(EXTERNAL_CORPUS_PATH.read_text())


def external_composite_corpus() -> list[dict[str, Any]]:
    if not EXTERNAL_COMPOSITE_CORPUS_PATH.exists():
        return []
    return json.loads(EXTERNAL_COMPOSITE_CORPUS_PATH.read_text())


def run_self_test() -> dict[str, Any]:
    cmd = [
        sys.executable,
        "kryptosbot/self_test.py",
        "--panel",
        "all",
        "--mode",
        "dry-run",
        "--cycles",
        "10000",
        "--report-path",
        str(RAW_SELF_TEST),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, env=env)
    parsed = None
    if RAW_SELF_TEST.exists():
        parsed = json.loads(RAW_SELF_TEST.read_text())
    return {
        "command": "PYTHONPATH=src " + " ".join(cmd),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-2000:],
        "report_path": str(RAW_SELF_TEST),
        "parsed_report": parsed,
    }


def write_markdown(payload: dict[str, Any]) -> None:
    self_test = payload["existing_self_test"]
    results = (self_test.get("parsed_report") or {}).get("results", [])
    static_families = sorted({item["family"] for item in payload["static_corpus"]})
    composite_families = sorted({
        layer["kind"]
        for item in payload["composite_corpus"]
        for layer in item["pipeline"]
    })
    external_families = sorted({item["family"] for item in payload["external_corpus"]})
    external_sources = sorted({
        item.get("source_name", item.get("source_url", "unknown"))
        for item in payload["external_corpus"]
    })
    external_composite_families = sorted({
        layer["kind"]
        for item in payload["external_composite_corpus"]
        for layer in item["pipeline"]
    })
    external_composite_sources = sorted({
        item.get("source_name", item.get("source_url", "unknown"))
        for item in payload["external_composite_corpus"]
    })
    lines = [
        "# Known-Answer Battery Audit",
        "",
        "## Verdict",
        "",
        "The repo has a useful K1/K2/K3 dry-run self-test, but that is not yet "
        "a general hand-cipher solver proof. It proves selected known public "
        "keys are reachable in scripted strategy schedules.",
        "",
        "## Existing Self-Test",
        "",
        f"- Command exit code: {self_test['exit_code']}",
    ]
    for item in results:
        lines.append(
            f"- {item['panel']}: discovered={item['discovered']} "
            f"cycles={item['cycles_to_discovery']} peak={item['peak_score']}/{item['pseudo_crib_total']}"
        )
    lines += [
        "",
        "## Synthetic Fixtures Added To Audit Artifact",
        "",
        f"- Fixture count: {len(payload['synthetic_fixtures'])}",
        "- Families include Caesar, affine, Vigenere, Beaufort, Variant Beaufort, columnar, route, and a two-layer composite.",
        "",
        "## Dispatcher Challenge Path",
        "",
        "A separate pytest battery now runs independent known-answer "
        "challenges through `job_dispatcher.execute(..., challenge_ciphertext=..., "
        "challenge_crib_dict=...)` at both K4 length and non-97 lengths for "
        "identity, Caesar, Vigenere, Beaufort, Variant Beaufort, Atbash, "
        "columnar, rail fence, route, Myszkowski, Bifid, Quagmire, grille, "
        "reverse blocks, skip route, boustrophedon, row reversal, and a "
        "procedural identity recipe. It also includes a wrong-variant negative "
        "control, wrong-crib scoring check, wrong-column-order control, "
        "randomized-ciphertext controls, wrong-parameter controls, non-A-Z "
        "input rejection, exact cardinality checks, and confirms `key_tape` "
        "remains explicitly deferred.",
        "",
        "## Static Known-Answer Corpus",
        "",
        f"- Corpus path: `{STATIC_CORPUS_PATH.relative_to(REPO_ROOT)}`",
        f"- Corpus fixture count: {len(payload['static_corpus'])}",
        f"- Families include: {', '.join(static_families)}.",
        "",
        "## External Known-Answer Corpus",
        "",
        f"- Corpus path: `{EXTERNAL_CORPUS_PATH.relative_to(REPO_ROOT)}`",
        f"- External fixture count: {len(payload['external_corpus'])}",
        f"- Families include: {', '.join(external_families)}.",
        f"- Source count: {len(external_sources)}.",
        "- These fixtures are still known-key semantic checks, not autonomous solving benchmarks.",
        "",
        "## External Composite Corpus",
        "",
        f"- Corpus path: `{EXTERNAL_COMPOSITE_CORPUS_PATH.relative_to(REPO_ROOT)}`",
        f"- External composite fixture count: {len(payload['external_composite_corpus'])}",
        f"- Families exercised in external composites: {', '.join(external_composite_families)}.",
        f"- Source count: {len(external_composite_sources)}.",
        "- Includes a layer-order negative control for the published double-columnar example.",
        "",
        "## Static Composite Corpus",
        "",
        f"- Corpus path: `{COMPOSITE_CORPUS_PATH.relative_to(REPO_ROOT)}`",
        f"- Composite fixture count: {len(payload['composite_corpus'])}",
        f"- Families exercised in composites: {', '.join(composite_families)}.",
        "- Includes a layer-order negative control and a six-point enumerated composite universe check.",
        "",
        "## Remaining Gap",
        "",
        "The challenge path now supports arbitrary A-Z lengths and has local, "
        "external, and composite known-answer corpora. The external corpus "
        "covers several live families and one published double-columnar "
        "composite, but it is still a known-key semantic battery rather "
        "than a proof of autonomous solving power. The next step is broader "
        "external coverage for grille/procedural families and larger "
        "pre-registered multi-layer searches.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_known_answer_battery.py",
        "PYTHONPATH=src python3 -m pytest tests/audit/test_dispatcher_known_answer_challenges.py -q",
        "```",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main() -> int:
    self_test = run_self_test()
    payload = {
        "schema_version": 1,
        "existing_self_test": self_test,
        "synthetic_fixtures": synthetic_fixtures(),
        "static_corpus": static_corpus(),
        "composite_corpus": composite_corpus(),
        "external_corpus": external_corpus(),
        "external_composite_corpus": external_composite_corpus(),
        "assessment": {
            "k1_k2_k3_value": "useful regression and sanity check",
            "not_proven": "general autonomous hand-cipher solving power",
            "key_leakage_risk": "known keys are present in self-test code by design; audit tests should keep them out of live controller prompts and dispatch specs",
        },
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_known_answer_battery.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown(payload)
    print(json.dumps({"wrote": [str(RESULT_PATH), str(DOC_PATH)], "self_test_exit": self_test["exit_code"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
