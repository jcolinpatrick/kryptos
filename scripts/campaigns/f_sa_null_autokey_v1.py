#!/usr/bin/env python3
"""SA over null masks + autokey Vigenère/Beaufort.

Null mask + periodic sub is PROVEN IMPOSSIBLE (periods 1-23).
This script tests: remove 24 nulls → autokey decrypt 73-char CT.
Autokey in the 73-char null-removal model has NOT been exhaustively explored with SA.

Two SA modes:
  (A) fix_w=True: W-positions [20,36,48,58,74] are forced nulls, find 19 more
  (B) fix_w=False: unconstrained 24-null search

Scoring: IC (fast, smooth gradient) guides SA; quadgram + crib at checkpoints.
"""

import sys, random, math, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

# ── Constants ─────────────────────────────────────────────────────────────────
CT97       = CT
N          = 97; N_NULLS = 24; N_PT = 73
ENE_WORD   = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START  = 21; BCL_START = 63
W_POS      = frozenset([20, 36, 48, 58, 74])
NON_CRIB   = [i for i in range(N) if i not in CRIB_POSITIONS]   # 73 positions
assert len(NON_CRIB) == 73

KEYWORDS = [
    'KRYPTOS', 'KOMPASS', 'DEFECTOR', 'PARALLAX', 'COLOPHON',
    'ABSCISSA', 'BERLIN', 'CLOCK', 'SHADOW', 'SANBORN',
    'KRYPTEIA', 'KLEPSYDRA', 'KRYPTA', 'KOLOPHON',
    'K', 'KR', 'KRY', 'KRIP',   # short-key autokey variants
]

# ── Quadgrams ─────────────────────────────────────────────────────────────────
import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try:
        QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError:
        pass
if QG is None:
    raise FileNotFoundError("english_quadgrams.json not found")
QG_FLOOR = -10.0

def qg_score(t: str) -> float:
    return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t) - 3))

def ic(t: str) -> float:
    c = [0] * 26
    for ch in t: c[ord(ch) - 65] += 1
    n = len(t)
    return sum(x * (x - 1) for x in c) / (n * (n - 1)) if n > 1 else 0.0

# ── Cipher functions ─────────────────────────────────────────────────────────
def autokey_decrypt(ct73: str, kw: str, beaufort: bool = False) -> str:
    """Autokey Vigenère (beaufort=False) or Beaufort (beaufort=True)."""
    pt  = []
    kw_n = [ord(c) - 65 for c in kw.upper()]
    L    = len(kw_n)
    for i, c in enumerate(ct73):
        ci = ord(c) - 65
        ki = kw_n[i] if i < L else (ord(pt[i - L]) - 65)
        pt.append(chr(((ki - ci) if beaufort else (ci - ki)) % 26 + 65))
    return ''.join(pt)

# ── Scoring helpers ───────────────────────────────────────────────────────────
def count_crib_hits(pt: str, ene_s: int, bcl_s: int) -> int:
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < N_PT and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < N_PT and pt[bcl_s + j] == c)
    return e + b

def free_crib_hits(pt: str) -> int:
    """Position-independent: how many chars of ENE/BCL appear anywhere."""
    hits = 0
    if ENE_WORD in pt: hits += len(ENE_WORD)
    if BCL_WORD in pt: hits += len(BCL_WORD)
    return hits

def eval_mask(null_set: frozenset) -> tuple:
    """Full evaluation: all keywords × both variants."""
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    n1   = sum(1 for p in null_set if p < ENE_START)
    n2   = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    best_crib = 0; best_sc = -1e9; best_pt = ''; best_kw = ''
    for kw in KEYWORDS:
        for beau in (False, True):
            pt  = autokey_decrypt(ct73, kw, beau)
            ch  = count_crib_hits(pt, ene_s, bcl_s)
            fc  = free_crib_hits(pt)
            sc  = ch * 100 + fc * 10 + qg_score(pt) / N_PT
            if sc > best_sc:
                best_sc = sc; best_crib = ch; best_pt = pt
                best_kw = f"{kw}:{'beau' if beau else 'vig'}"
    return best_crib, best_sc, best_pt, best_kw, ct73

def fast_ic_score(null_set: frozenset) -> float:
    """Fast IC-only score for SA guidance (KRYPTOS autokey vig only)."""
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    pt   = autokey_decrypt(ct73, 'KRYPTOS', False)
    return ic(pt)

# ── SA ────────────────────────────────────────────────────────────────────────
def sa_run(seed: int, fix_w: bool = True, steps: int = 120_000) -> dict:
    rng = random.Random(seed)

    # Initialise null set
    if fix_w:
        fixed     = W_POS & frozenset(NON_CRIB)
        free_pool = [p for p in NON_CRIB if p not in fixed]
        extra     = set(rng.sample(free_pool, N_NULLS - len(fixed)))
        null_set  = fixed | extra
    else:
        null_set  = set(rng.sample(NON_CRIB, N_NULLS))

    non_null_nc = set(NON_CRIB) - null_set

    score     = fast_ic_score(frozenset(null_set))
    best_ic   = score
    best_null = frozenset(null_set)

    T0, Tf = 0.006, 0.00008
    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)

        # Choose a null to swap out (if fix_w, never touch W positions)
        swap_out_candidates = [p for p in null_set
                                if not (fix_w and p in W_POS)]
        if not swap_out_candidates or not non_null_nc:
            break

        out  = rng.choice(swap_out_candidates)
        into = rng.choice(list(non_null_nc))

        null_set    = (null_set    - {out})  | {into}
        non_null_nc = (non_null_nc - {into}) | {out}

        new_sc = fast_ic_score(frozenset(null_set))
        delta  = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / T):
            score = new_sc
            if score > best_ic:
                best_ic   = score
                best_null = frozenset(null_set)
        else:
            # revert
            null_set    = (null_set    - {into}) | {out}
            non_null_nc = (non_null_nc - {out})  | {into}

    # Full evaluation of best null set
    crib, sc, pt, kw, ct73 = eval_mask(best_null)
    return {
        'ic': best_ic, 'crib': crib, 'sc': sc,
        'pt': pt, 'kw': kw, 'mask': sorted(best_null),
        'ct73': ct73, 'fix_w': fix_w, 'seed': seed,
    }

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 60)
    print("SA NULL MASK + AUTOKEY VIGENERE/BEAUFORT")
    print("=" * 60)
    print(f"CT97  = {CT97}")
    print(f"Non-crib positions: {len(NON_CRIB)}, choose {N_NULLS} nulls")
    print(f"Keywords: {KEYWORDS}")
    print()

    t0      = time.time()
    results = []
    N_RESTART = 20

    for restart in range(N_RESTART):
        for fix_w in (True, False):
            r = sa_run(seed=restart * 13 + int(fix_w), fix_w=fix_w, steps=120_000)
            results.append(r)
            if r['crib'] >= 8 or restart % 4 == 0:
                print(f"  restart={restart:2d} fix_w={fix_w}"
                      f"  ic={r['ic']:.5f}  crib={r['crib']:2d}/24"
                      f"  kw={r['kw']}")
                print(f"    PT={r['pt'][:60]}...")
                if r['crib'] >= 10:
                    print(f"    *** HIGH CRIB HIT: {r['crib']}/24 ***")
                    print(f"    FULL PT: {r['pt']}")
                    print(f"    MASK: {r['mask']}")

    results.sort(key=lambda x: (-x['crib'], -x['ic']))
    elapsed = time.time() - t0

    print()
    print(f"=== TOP 5 RESULTS (elapsed {elapsed:.1f}s) ===")
    for r in results[:5]:
        print(f"  crib={r['crib']:2d}/24  ic={r['ic']:.5f}  kw={r['kw']}"
              f"  fix_w={r['fix_w']}  seed={r['seed']}")
        print(f"    PT  = {r['pt']}")
        print(f"    CT73= {r['ct73']}")
        print(f"    mask= {r['mask']}")
        print()

    best = results[0]
    print("verdict:", json.dumps({
        "verdict_status": "inconclusive",
        "score": best['crib'],
        "summary": f"SA null+autokey best {best['crib']}/24 crib hits",
        "evidence": f"ic={best['ic']:.5f} kw={best['kw']}",
        "best_plaintext": best['pt'],
    }))
