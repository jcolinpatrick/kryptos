"""Tier 2a: Quagmire III cryptonym-crib back-derivation screen.

Prereg: docs/campaigns/cryptonym_crib_screen_2026_06_11.md (Tier 2a section).
"""
import json, os, random, subprocess, sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT
from kryptos.kernel.transforms.quagmire import (
    quagmire_encrypt, quagmire_recover_key,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.scoring.ngram import get_default_scorer

SEED = 20260611
CRIBS = ["KUBARK", "FLUTTER", "OVERLORD"]
TABLEAUS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC", "COMPASS"]
INDICATORS = ["K", "A", "R"]
OUT = os.path.dirname(os.path.abspath(__file__))

def key_letter(ct_char, pt_char, kw, indicator, ct_alpha, ct_idx):
    shift = quagmire_recover_key(ct_char, pt_char, kw, kw, indicator)
    return ct_alpha[(shift + ct_idx[indicator]) % 26]

# ── Known-answer gate: exhaustive single-char inversion per convention cell
for kw in TABLEAUS:
    ct_alpha = keyword_mixed_alphabet(kw)
    ct_idx = {c: i for i, c in enumerate(ct_alpha)}
    for ind in INDICATORS:
        for p in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            for k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                c = quagmire_encrypt(p, k, indicator=ind,
                                     ct_alphabet_keyword=kw, pt_alphabet_keyword=kw)
                got = key_letter(c, p, kw, ind, ct_alpha, ct_idx)
                assert got == k, f"GATE FAIL {kw}/{ind}: pt={p} key={k} got={got}"
print("known-answer gate: PASS (exhaustive inversion, 18 cells x 676 pairs)")

# ── Dictionary + null rates (same construction/seed as Tier 1)
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
rng = random.Random(SEED)
AZS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
null_rates = {}
for L in sorted({len(c) for c in CRIBS}):
    wc = pf = 0
    for _ in range(200_000):
        g = "".join(AZS[rng.randrange(26)] for _ in range(L))
        if g in words: wc += 1
        if g in prefixes: pf += 1
    null_rates[L] = {"p_word": wc / 200_000, "p_prefix": pf / 200_000}

scorer = get_default_scorer()
rows = []
for kw in TABLEAUS:
    ct_alpha = keyword_mixed_alphabet(kw)
    ct_idx = {c: i for i, c in enumerate(ct_alpha)}
    for ind in INDICATORS:
        for crib in CRIBS:
            L = len(crib)
            for p in range(0, 21 - L + 1):
                frag = "".join(
                    key_letter(CT[p + j], crib[j], kw, ind, ct_alpha, ct_idx)
                    for j in range(L))
                rows.append({
                    "crib": crib, "pos": p, "tableau": kw, "indicator": ind,
                    "fragment": frag,
                    "is_word": frag in words,
                    "is_prefix": frag in prefixes,
                    "quadgram_pc": round(scorer.score_per_char(frag), 3),
                })
obs_w = sum(r["is_word"] for r in rows)
obs_p = sum(r["is_prefix"] for r in rows)
exp_w = sum(null_rates[len(r["crib"])]["p_word"] for r in rows)
exp_p = sum(null_rates[len(r["crib"])]["p_prefix"] for r in rows)

summary = {
    "campaign_id": "cryptonym_crib_screen_qiii_2026_06_11",
    "prereg": "docs/campaigns/cryptonym_crib_screen_2026_06_11.md#tier-2a",
    "git_head": subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, cwd=_ROOT).stdout.strip(),
    "n_tests": len(rows),
    "observed_exact_words": obs_w, "expected_exact_words": round(exp_w, 4),
    "observed_prefix_hits": obs_p, "expected_prefix_hits": round(exp_p, 4),
    "null_rates": null_rates,
    "word_hits": [r for r in rows if r["is_word"]],
    "prefix_hits": [r for r in rows if r["is_prefix"] and not r["is_word"]],
    "top_quadgram": sorted(rows, key=lambda r: -r["quadgram_pc"])[:10],
    "all_rows": rows,
}
with open(os.path.join(OUT, "screen_results_qiii.json"), "w") as f:
    json.dump(summary, f, indent=1)
print(f"tests: {len(rows)} | exact words: {obs_w} (exp {exp_w:.3f}) "
      f"| prefixes: {obs_p} (exp {exp_p:.3f})")
for r in summary["word_hits"]:
    print("  WORD:", r)
for r in summary["prefix_hits"]:
    print("  prefix:", r)
