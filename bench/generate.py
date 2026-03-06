"""Benchmark suite generator — create JSONL suites with deterministic seeds.

Usage:
    PYTHONPATH=src python bench/generate.py --tiers 0,1,2,3 --n 25 --seed 42 --out bench/suites/
    PYTHONPATH=src python -m kryptos bench generate --tiers 0 --n 10 --seed 1

Tiers:
    0 — Easy:   Caesar, Affine, Atbash, Rail fence, Vigenère (known key)
    1 — Medium: Vigenère (unknown key), Simple substitution, Columnar transposition
    2 — Hard:   Short/weak-stats ciphertexts (len 15–30)
    3 — Adversarial: Null insertion, bait cribs, polyalphabetic with noise
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# ── Corpus loader ────────────────────────────────────────────────────────

_CORPUS_PATH = Path(__file__).resolve().parent / "corpus" / "plaintext.txt"

_ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _load_corpus() -> str:
    """Load and normalize the bundled plaintext corpus to A-Z only."""
    raw = _CORPUS_PATH.read_text()
    return "".join(c for c in raw.upper() if c in _ALPH)


# ── Cipher implementations (self-contained, no kernel dependency) ────────

def _caesar_encrypt(pt: str, shift: int) -> str:
    return "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in pt)


def _affine_encrypt(pt: str, a: int, b: int) -> str:
    return "".join(chr((a * (ord(c) - 65) + b) % 26 + 65) for c in pt)


def _atbash_encrypt(pt: str) -> str:
    return "".join(chr(25 - (ord(c) - 65) + 65) for c in pt)


def _vigenere_encrypt(pt: str, key: str) -> str:
    key_nums = [ord(c) - 65 for c in key.upper()]
    klen = len(key_nums)
    return "".join(
        chr((ord(p) - 65 + key_nums[i % klen]) % 26 + 65)
        for i, p in enumerate(pt)
    )


def _rail_fence_encrypt(pt: str, depth: int) -> str:
    if depth <= 1 or depth >= len(pt):
        return pt
    rails: list[list[str]] = [[] for _ in range(depth)]
    rail, direction = 0, 1
    for ch in pt:
        rails[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == depth - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in rails)


def _columnar_encrypt(pt: str, col_order: List[int]) -> str:
    width = len(col_order)
    # Build columns
    cols: dict[int, list[str]] = {i: [] for i in range(width)}
    for i, ch in enumerate(pt):
        cols[i % width].append(ch)
    # Read by rank order
    out: list[str] = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        out.extend(cols[col_idx])
    return "".join(out)


def _keyword_to_order(keyword: str) -> List[int]:
    indexed = [(ch, i) for i, ch in enumerate(keyword.upper())]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def _simple_sub_encrypt(pt: str, perm: List[int]) -> str:
    return "".join(chr(perm[ord(c) - 65] + 65) for c in pt)


def _random_sub_perm(rng: random.Random) -> List[int]:
    perm = list(range(26))
    rng.shuffle(perm)
    return perm


def _sub_perm_to_key(perm: List[int]) -> str:
    return "".join(chr(p + 65) for p in perm)


def _insert_nulls(pt: str, rng: random.Random, rate: float = 0.15) -> Tuple[str, str]:
    """Insert random null characters. Returns (modified_text, description)."""
    result: list[str] = []
    for ch in pt:
        result.append(ch)
        if rng.random() < rate:
            result.append(chr(rng.randint(0, 25) + 65))
    return "".join(result), f"null_rate={rate:.2f}"


# ── Case generators per tier ────────────────────────────────────────────

AFFINE_VALID_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

SCRIPT_MAP = {
    "caesar": "scripts/examples/e_caesar_standard.py",
    "affine": "scripts/examples/e_caesar_standard.py",  # Caesar covers affine search
    "atbash": "scripts/examples/e_caesar_standard.py",
    "rail_fence": "scripts/examples/e_caesar_standard.py",
    "vigenere": "scripts/examples/e_caesar_standard.py",
    "columnar": "scripts/examples/e_caesar_standard.py",
    "substitution": "scripts/examples/e_caesar_standard.py",
}


def _extract_snippet(corpus: str, rng: random.Random, min_len: int, max_len: int) -> str:
    length = rng.randint(min_len, max_len)
    if length >= len(corpus):
        return corpus[:length]
    start = rng.randint(0, len(corpus) - length)
    return corpus[start:start + length]


def _generate_tier0(corpus: str, n: int, rng: random.Random) -> List[Dict]:
    """Tier 0: Easy — Caesar, Affine, Atbash, Rail fence, Vigenère (known key)."""
    cases: list[dict] = []
    cipher_choices = ["caesar", "affine", "atbash", "rail_fence", "vigenere"]

    for i in range(n):
        cipher = cipher_choices[i % len(cipher_choices)]
        pt = _extract_snippet(corpus, rng, 30, 80)

        if cipher == "caesar":
            shift = rng.randint(1, 25)
            ct = _caesar_encrypt(pt, shift)
            key = str(shift)
            family = "substitution"
            label = f"Caesar ROT-{shift}"

        elif cipher == "affine":
            a = rng.choice(AFFINE_VALID_A)
            b = rng.randint(0, 25)
            ct = _affine_encrypt(pt, a, b)
            key = f"a={a},b={b}"
            family = "substitution"
            label = f"Affine a={a} b={b}"

        elif cipher == "atbash":
            ct = _atbash_encrypt(pt)
            key = "atbash"
            family = "substitution"
            label = "Atbash"

        elif cipher == "rail_fence":
            depth = rng.randint(2, 5)
            ct = _rail_fence_encrypt(pt, depth)
            key = str(depth)
            family = "transposition"
            label = f"Rail fence depth={depth}"

        else:  # vigenere
            kw_len = rng.randint(3, 6)
            kw = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw_len))
            ct = _vigenere_encrypt(pt, kw)
            key = kw
            family = "substitution"
            label = f"Vigenère key={kw}"

        cases.append({
            "case_id": f"tier0_{cipher}_{i:03d}",
            "ciphertext": ct,
            "script": SCRIPT_MAP.get(cipher, SCRIPT_MAP["caesar"]),
            "expected_plaintext": pt,
            "expected_key": key,
            "expected_family": family,
            "label": label,
        })

    return cases


def _generate_tier1(corpus: str, n: int, rng: random.Random) -> List[Dict]:
    """Tier 1: Medium — Vigenère unknown key, simple substitution, columnar."""
    cases: list[dict] = []
    cipher_choices = ["vigenere", "substitution", "columnar"]

    for i in range(n):
        cipher = cipher_choices[i % len(cipher_choices)]
        pt = _extract_snippet(corpus, rng, 50, 120)

        if cipher == "vigenere":
            kw_len = rng.randint(5, 10)
            kw = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw_len))
            ct = _vigenere_encrypt(pt, kw)
            key = kw
            family = "substitution"
            label = f"Vigenère key={kw} (unknown)"

        elif cipher == "substitution":
            perm = _random_sub_perm(rng)
            ct = _simple_sub_encrypt(pt, perm)
            key = _sub_perm_to_key(perm)
            family = "substitution"
            label = "Simple substitution"

        else:  # columnar
            kw_len = rng.randint(4, 8)
            kw = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw_len))
            col_order = _keyword_to_order(kw)
            ct = _columnar_encrypt(pt, col_order)
            key = kw
            family = "transposition"
            label = f"Columnar key={kw}"

        cases.append({
            "case_id": f"tier1_{cipher}_{i:03d}",
            "ciphertext": ct,
            "script": SCRIPT_MAP.get(cipher, SCRIPT_MAP["caesar"]),
            "expected_plaintext": pt,
            "expected_key": key,
            "expected_family": family,
            "label": label,
        })

    return cases


def _generate_tier2(corpus: str, n: int, rng: random.Random) -> List[Dict]:
    """Tier 2: Hard — Short/weak-stats ciphertexts (len 15–30)."""
    cases: list[dict] = []
    cipher_choices = ["caesar", "vigenere", "rail_fence", "columnar"]

    for i in range(n):
        cipher = cipher_choices[i % len(cipher_choices)]
        pt = _extract_snippet(corpus, rng, 15, 30)

        if cipher == "caesar":
            shift = rng.randint(1, 25)
            ct = _caesar_encrypt(pt, shift)
            key = str(shift)
            family = "substitution"
            label = f"Short Caesar ROT-{shift}"

        elif cipher == "vigenere":
            kw_len = rng.randint(3, 6)
            kw = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw_len))
            ct = _vigenere_encrypt(pt, kw)
            key = kw
            family = "substitution"
            label = f"Short Vigenère key={kw}"

        elif cipher == "rail_fence":
            depth = rng.randint(2, 4)
            ct = _rail_fence_encrypt(pt, depth)
            key = str(depth)
            family = "transposition"
            label = f"Short rail fence depth={depth}"

        else:  # columnar
            kw_len = rng.randint(3, 5)
            kw = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw_len))
            col_order = _keyword_to_order(kw)
            ct = _columnar_encrypt(pt, col_order)
            key = kw
            family = "transposition"
            label = f"Short columnar key={kw}"

        cases.append({
            "case_id": f"tier2_{cipher}_{i:03d}",
            "ciphertext": ct,
            "script": SCRIPT_MAP.get(cipher, SCRIPT_MAP["caesar"]),
            "expected_plaintext": pt,
            "expected_key": key,
            "expected_family": family,
            "label": label,
        })

    return cases


def _generate_tier3(corpus: str, n: int, rng: random.Random) -> List[Dict]:
    """Tier 3: Adversarial — null insertion, double encryption, bait cribs."""
    cases: list[dict] = []
    cipher_choices = ["null_caesar", "double_vigenere", "bait_sub"]

    for i in range(n):
        cipher = cipher_choices[i % len(cipher_choices)]
        pt = _extract_snippet(corpus, rng, 40, 80)

        if cipher == "null_caesar":
            shift = rng.randint(1, 25)
            ct_clean = _caesar_encrypt(pt, shift)
            ct, null_desc = _insert_nulls(ct_clean, rng, rate=0.12)
            key = f"shift={shift},{null_desc}"
            family = "substitution"
            label = f"Caesar ROT-{shift} + nulls"

        elif cipher == "double_vigenere":
            kw1_len = rng.randint(3, 5)
            kw2_len = rng.randint(3, 5)
            kw1 = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw1_len))
            kw2 = "".join(chr(rng.randint(0, 25) + 65) for _ in range(kw2_len))
            ct = _vigenere_encrypt(_vigenere_encrypt(pt, kw1), kw2)
            key = f"{kw1}+{kw2}"
            family = "substitution"
            label = f"Double Vigenère {kw1}+{kw2}"

        else:  # bait_sub — substitution with planted bait pattern
            perm = _random_sub_perm(rng)
            ct_chars = list(_simple_sub_encrypt(pt, perm))
            # Plant a bait crib at a random position
            bait = "EASTNORTHEAST"
            if len(ct_chars) > len(bait) + 5:
                pos = rng.randint(0, len(ct_chars) - len(bait))
                for j, ch in enumerate(bait):
                    ct_chars[pos + j] = ch
            ct = "".join(ct_chars)
            key = _sub_perm_to_key(perm)
            family = "substitution"
            label = "Substitution + bait crib"

        cases.append({
            "case_id": f"tier3_{cipher}_{i:03d}",
            "ciphertext": ct,
            "script": SCRIPT_MAP.get("caesar", SCRIPT_MAP["caesar"]),
            "expected_plaintext": pt,
            "expected_key": key,
            "expected_family": family,
            "label": label,
        })

    return cases


# ── Public API ───────────────────────────────────────────────────────────

TIER_GENERATORS = {
    0: _generate_tier0,
    1: _generate_tier1,
    2: _generate_tier2,
    3: _generate_tier3,
}


def generate_suite(
    tiers: List[int],
    n: int = 25,
    seed: int = 42,
) -> Dict[int, List[Dict]]:
    """Generate benchmark cases for the requested tiers.

    Args:
        tiers: Which tiers to generate (0–3).
        n: Number of cases per tier.
        seed: RNG seed for reproducibility.

    Returns:
        Dict mapping tier number to list of case dicts.
    """
    corpus = _load_corpus()
    results: dict[int, list[dict]] = {}
    for tier in sorted(tiers):
        if tier not in TIER_GENERATORS:
            raise ValueError(f"Unknown tier: {tier} (valid: 0–3)")
        rng = random.Random(seed + tier)
        results[tier] = TIER_GENERATORS[tier](corpus, n, rng)
    return results


def write_suite(cases: List[Dict], path: Path) -> None:
    """Write cases to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for case in cases:
            f.write(json.dumps(case, separators=(",", ":")) + "\n")


# ── CLI ──────────────────────────────────────────────────────────────────

def cmd_generate(args) -> int:
    """CLI handler for bench generate."""
    tiers = [int(t.strip()) for t in args.tiers.split(",")]
    out_dir = Path(args.out)

    suites = generate_suite(tiers=tiers, n=args.n, seed=args.seed)

    total = 0
    for tier, cases in sorted(suites.items()):
        out_path = out_dir / f"tier{tier}_generated.jsonl"
        write_suite(cases, out_path)
        total += len(cases)
        print(f"Tier {tier}: {len(cases)} cases → {out_path}")

    print(f"Total: {total} cases generated (seed={args.seed})")
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="bench-generate",
        description="Generate benchmark suites",
    )
    parser.add_argument(
        "--tiers", default="0,1,2,3",
        help="Comma-separated tier numbers (default: 0,1,2,3)",
    )
    parser.add_argument(
        "--n", type=int, default=25,
        help="Number of cases per tier (default: 25)",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="RNG seed (default: 42)",
    )
    parser.add_argument(
        "--out", default="bench/suites/",
        help="Output directory (default: bench/suites/)",
    )
    args = parser.parse_args()
    return cmd_generate(args)


if __name__ == "__main__":
    sys.exit(main())
