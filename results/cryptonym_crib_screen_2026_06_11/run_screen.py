"""Cryptonym-crib keystream back-derivation screen.

Prereg: docs/campaigns/cryptonym_crib_screen_2026_06_11.md
"""
import json, os, random, sys, subprocess

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_DICT, VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.scoring.ngram import get_default_scorer

SEED = 20260611
CRIBS = ["KUBARK", "FLUTTER", "OVERLORD"]
VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
ALPHABETS = {"AZ": AZ.sequence, "KA": KA.sequence}
OUT = os.path.dirname(os.path.abspath(__file__))

def derive(ct_s, pt_s, variant, alpha):
    idx = {c: i for i, c in enumerate(alpha)}
    out = []
    for c, p in zip(ct_s, pt_s):
        ci, pi = idx[c], idx[p]
        if variant == "vigenere":
            k = (ci - pi) % 26
        elif variant == "beaufort":
            k = (ci + pi) % 26
        else:
            k = (pi - ci) % 26
        out.append(alpha[k])
    return "".join(out)

# ── Known-answer gate (fail-closed): reproduce kernel keystreams at ENE/BC, AZ
ene_ct = "".join(CT[i] for i in range(21, 34))
ene_pt = "".join(CRIB_DICT[i] for i in range(21, 34))
bc_ct = "".join(CT[i] for i in range(63, 74))
bc_pt = "".join(CRIB_DICT[i] for i in range(63, 74))
az = ALPHABETS["AZ"]
checks = [
    (derive(ene_ct, ene_pt, "vigenere", az), VIGENERE_KEY_ENE),
    (derive(bc_ct, bc_pt, "vigenere", az), VIGENERE_KEY_BC),
    (derive(ene_ct, ene_pt, "beaufort", az), BEAUFORT_KEY_ENE),
    (derive(bc_ct, bc_pt, "beaufort", az), BEAUFORT_KEY_BC),
]
for got, want in checks:
    want_s = "".join(az[v] for v in want)
    assert got == want_s, f"KNOWN-ANSWER GATE FAILED: {got} != {want_s}"
print("known-answer gate: PASS (4/4 kernel keystreams reproduced)")

# ── Dictionary
words = set()
with open(os.path.join(_ROOT, "wordlists", "english.txt")) as f:
    for line in f:
        w = line.strip().upper()
        if w.isalpha():
            words.add(w)
prefixes = set()
for w in words:
    for i in range(3, min(len(w), 9) + 1):
        prefixes.add(w[:i])
print(f"dictionary: {len(words):,} words")

scorer = get_default_scorer()

# ── Tier-1 fragments
rows = []
for crib in CRIBS:
    L = len(crib)
    for p in range(0, 21 - L + 1):
        ct_s = CT[p:p + L]
        for var in VARIANTS:
            for aname, alpha in ALPHABETS.items():
                frag = derive(ct_s, crib, var, alpha)
                rows.append({
                    "crib": crib, "pos": p, "variant": var, "alphabet": aname,
                    "fragment": frag,
                    "is_word": frag in words,
                    "is_prefix": frag in prefixes,
                    "quadgram_pc": round(scorer.score_per_char(frag), 3),
                })
n_tests = len(rows)
obs_words = sum(r["is_word"] for r in rows)
obs_prefix = sum(r["is_prefix"] for r in rows)

# ── Null rates: random L-grams (uniform; exact null for uniform random crib)
rng = random.Random(SEED)
null_rates = {}
M = 200_000
for L in sorted({len(c) for c in CRIBS}):
    w = pf = 0
    for _ in range(M):
        g = "".join(az[rng.randrange(26)] for _ in range(L))
        if g in words: w += 1
        if g in prefixes: pf += 1
    null_rates[L] = {"p_word": w / M, "p_prefix": pf / M}
exp_words = sum(null_rates[len(r["crib"])]["p_word"] for r in rows)
exp_prefix = sum(null_rates[len(r["crib"])]["p_prefix"] for r in rows)

summary = {
    "campaign_id": "cryptonym_crib_screen_2026_06_11",
    "prereg": "docs/campaigns/cryptonym_crib_screen_2026_06_11.md",
    "git_head": subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, cwd=_ROOT).stdout.strip(),
    "n_tests": n_tests,
    "observed_exact_words": obs_words,
    "expected_exact_words": round(exp_words, 4),
    "observed_prefix_hits": obs_prefix,
    "expected_prefix_hits": round(exp_prefix, 4),
    "null_rates": null_rates,
    "word_hits": [r for r in rows if r["is_word"]],
    "prefix_hits": [r for r in rows if r["is_prefix"] and not r["is_word"]],
    "top_quadgram": sorted(rows, key=lambda r: -r["quadgram_pc"])[:10],
    "all_rows": rows,
}
with open(os.path.join(OUT, "screen_results.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(f"tests: {n_tests} | exact-word fragments: {obs_words} (exp {exp_words:.3f}) "
      f"| prefix hits: {obs_prefix} (exp {exp_prefix:.2f})")
for r in summary["word_hits"]:
    print("  WORD:", r)
for r in summary["prefix_hits"][:10]:
    print("  prefix:", r)
