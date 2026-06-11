"""Tiers 2b+2c: gap-region and key-phase-robust cryptonym-crib screen.

Prereg: docs/campaigns/cryptonym_crib_screen_2026_06_11.md (Tiers 2b+2c).
"""
import json, os, random, subprocess, sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_DICT, VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.transforms.quagmire import quagmire_encrypt, quagmire_recover_key, quagmire_decrypt
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.scoring.aggregate import score_candidate

SEED = 20260611
CRIBS = ["KUBARK", "FLUTTER", "OVERLORD"]
TABLEAUS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "LATITUDE", "MAGNETIC", "COMPASS"]
INDICATORS = ["K", "A", "R"]
VARIANTS = ["vigenere", "beaufort", "var_beaufort"]
ALPHABETS = {"AZ": AZ.sequence, "KA": KA.sequence}
REGIONS = {"preENE_0_20": (0, 20), "gap_34_62": (34, 62), "tail_74_96": (74, 96)}
OUT = os.path.dirname(os.path.abspath(__file__))
AZS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def derive_add(ct_s, pt_s, variant, alpha):
    idx = {c: i for i, c in enumerate(alpha)}
    out = []
    for c, p in zip(ct_s, pt_s):
        ci, pi = idx[c], idx[p]
        k = (ci - pi) % 26 if variant == "vigenere" else (
            (ci + pi) % 26 if variant == "beaufort" else (pi - ci) % 26)
        out.append(alpha[k])
    return "".join(out)

# ── Gates (fail-closed): Tier-1 additive constants + Tier-2a QIII inversion
az = ALPHABETS["AZ"]
ene_ct = "".join(CT[i] for i in range(21, 34)); ene_pt = "".join(CRIB_DICT[i] for i in range(21, 34))
bc_ct = "".join(CT[i] for i in range(63, 74)); bc_pt = "".join(CRIB_DICT[i] for i in range(63, 74))
for got, want in [(derive_add(ene_ct, ene_pt, "vigenere", az), VIGENERE_KEY_ENE),
                  (derive_add(bc_ct, bc_pt, "vigenere", az), VIGENERE_KEY_BC),
                  (derive_add(ene_ct, ene_pt, "beaufort", az), BEAUFORT_KEY_ENE),
                  (derive_add(bc_ct, bc_pt, "beaufort", az), BEAUFORT_KEY_BC)]:
    assert got == "".join(az[v] for v in want), "ADDITIVE GATE FAILED"
def qiii_key_letter(ct_char, pt_char, kw, indicator, ct_alpha, ct_idx):
    shift = quagmire_recover_key(ct_char, pt_char, kw, kw, indicator)
    return ct_alpha[(shift + ct_idx[indicator]) % 26]
for kw in TABLEAUS[:2]:  # spot 2 tableaus x all letters (full battery ran in 2a)
    ca = keyword_mixed_alphabet(kw); ci = {c: i for i, c in enumerate(ca)}
    for p in AZS:
        for k in AZS:
            c = quagmire_encrypt(p, k, indicator="K", ct_alphabet_keyword=kw, pt_alphabet_keyword=kw)
            assert qiii_key_letter(c, p, kw, "K", ca, ci) == k, "QIII GATE FAILED"
print("gates: PASS (additive constants 4/4; QIII inversion spot battery)")

# ── Dictionary structures
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
LENS = sorted({len(c) for c in CRIBS})
subs = {L: set() for L in LENS}
for w in words:
    for L in LENS:
        for i in range(0, len(w) - L + 1):
            subs[L].add(w[i:i + L])
print("dict ready:", {L: len(s) for L, s in subs.items()})

def rotations(s):
    return {s[i:] + s[:i] for i in range(len(s))}

def stats(frag):
    return {
        "is_word": frag in words,
        "is_prefix": frag in prefixes,
        "is_substring": frag in subs[len(frag)],
        "rotation_word": any(r in words for r in rotations(frag)),
    }

# ── Null rates per length per statistic
rng = random.Random(SEED)
M = 200_000
null_rates = {}
for L in LENS:
    c = {"is_word": 0, "is_prefix": 0, "is_substring": 0, "rotation_word": 0}
    for _ in range(M):
        g = "".join(AZS[rng.randrange(26)] for _ in range(L))
        st = stats(g)
        for k in c:
            c[k] += st[k]
    null_rates[L] = {k: v / M for k, v in c.items()}
print("null rates:", json.dumps(null_rates))

# ── Fragments: all regions x all 24 cells
scorer = get_default_scorer()
rows = []
for rname, (lo, hi) in REGIONS.items():
    for crib in CRIBS:
        L = len(crib)
        for p in range(lo, hi - L + 2):
            ct_s = CT[p:p + L]
            cells = []
            for var in VARIANTS:
                for aname, alpha in ALPHABETS.items():
                    cells.append((f"add:{var}:{aname}", derive_add(ct_s, crib, var, alpha)))
            for kw in TABLEAUS:
                ca = keyword_mixed_alphabet(kw); ci = {ch: i for i, ch in enumerate(ca)}
                for ind in INDICATORS:
                    frag = "".join(qiii_key_letter(ct_s[j], crib[j], kw, ind, ca, ci) for j in range(L))
                    cells.append((f"qiii:{kw}:{ind}", frag))
            for cell, frag in cells:
                r = {"region": rname, "crib": crib, "pos": p, "cell": cell,
                     "fragment": frag, **stats(frag),
                     "quadgram_pc": round(scorer.score_per_char(frag), 3)}
                rows.append(r)

# region-aware expected/observed (pre-ENE word/prefix excluded from claims: already reported)
def agg(rs, key):
    return sum(1 for r in rs if r[key]), sum(null_rates[len(r["crib"])][key] for r in rs)
report = {}
for rname in REGIONS:
    rs = [r for r in rows if r["region"] == rname]
    rep = {}
    for key in ("is_word", "is_prefix", "is_substring", "rotation_word"):
        o, e = agg(rs, key)
        rep[key] = {"observed": o, "expected": round(e, 3)}
    rep["n"] = len(rs)
    report[rname] = rep

# ── Decrypt-confirm candidates: S1 exact-word + S4 rotation-word (frozen rule)
def decrypt_add(ct, key, variant, alpha, phase):
    idx = {c: i for i, c in enumerate(alpha)}
    m = len(key)
    out = []
    for i, c in enumerate(ct):
        k = idx[key[(i + phase) % m]]
        ci = idx[c]
        p = (ci - k) % 26 if variant == "vigenere" else (
            (k - ci) % 26 if variant == "beaufort" else (ci + k) % 26)
        out.append(alpha[p])
    return "".join(out)

candidates = [r for r in rows if r["is_word"] or r["rotation_word"]]
confirms = []
for r in candidates:
    cand_words = ({r["fragment"]} if r["is_word"] else set()) | {
        w for w in rotations(r["fragment"]) if w in words}
    best = {"crib_score": -1}
    for word in cand_words:
        m = len(word)
        for phase in range(m):
            if r["cell"].startswith("add:"):
                _, var, aname = r["cell"].split(":")
                pt = decrypt_add(CT, word, var, ALPHABETS[aname], phase)
            else:
                _, kw, ind = r["cell"].split(":")
                key_rot = word[phase:] + word[:phase]
                pt = quagmire_decrypt(CT, key_rot, indicator=ind,
                                      ct_alphabet_keyword=kw, pt_alphabet_keyword=kw)
            br = score_candidate(pt)
            cs = int(getattr(br, "crib_score", 0) or 0)
            if cs > best["crib_score"]:
                best = {"crib_score": cs, "word": word, "phase": phase,
                        "pt_head": pt[:30]}
    confirms.append({**{k: r[k] for k in ("region", "crib", "pos", "cell", "fragment")},
                     "hit_type": "word" if r["is_word"] else "rotation",
                     "decrypt_confirm": best})

summary = {
    "campaign_id": "cryptonym_crib_screen_phase_gap_2026_06_11",
    "prereg": "docs/campaigns/cryptonym_crib_screen_2026_06_11.md#tiers-2b--2c",
    "git_head": subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, cwd=_ROOT).stdout.strip(),
    "n_fragments": len(rows),
    "null_rates": null_rates,
    "region_report": report,
    "candidates": confirms,
    "max_decrypt_confirm_crib": max((c["decrypt_confirm"]["crib_score"] for c in confirms), default=0),
}
with open(os.path.join(OUT, "screen_results_phase_gap.json"), "w") as f:
    json.dump({**summary, "all_rows": rows}, f, indent=1)
print(json.dumps({k: summary[k] for k in ("n_fragments", "region_report", "max_decrypt_confirm_crib")}, indent=1))
for c in confirms:
    print("CANDIDATE:", c["hit_type"], c["crib"], c["region"], c["pos"], c["cell"],
          c["fragment"], "->", c["decrypt_confirm"])
