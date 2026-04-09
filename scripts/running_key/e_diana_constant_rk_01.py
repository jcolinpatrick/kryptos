#!/usr/bin/env python3
"""
Cipher: Extended Diana (Beaufort+constant) + Egyptian Section 151B
Family: running_key
Status: exhausted
Keyspace: corpus_texts × offsets × 3_variants × 26_constants
Last run: 2026-04-05
Best score: 0.0 (crib_score)
Credit: community contribution — constant-term extension to running key,
        Section 151B (Words of Isis, Tut death mask) as running key text
"""
import sys
import os
import re
import time
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ,
    STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Key recovery functions ─────────────────────────────────────────────────

def _vig_key(c, p):
    return (c - p) % MOD

def _beau_key(c, p):
    return (c + p) % MOD

def _varbeau_key(c, p):
    return (p - c) % MOD

# Decrypt functions: given (C, K) -> P
def _vig_dec(c, k):
    return (c - k) % MOD

def _beau_dec(c, k):
    return (k - c) % MOD

def _varbeau_dec(c, k):
    return (c + k) % MOD  # P = C + K for var_beaufort decrypt? Let me verify:
    # Var Beaufort: C = (P - K) mod 26, so P = (C + K) mod 26. Yes.

VARIANTS = {
    "vigenere":     (_vig_key, _vig_dec),
    "beaufort":     (_beau_key, _beau_dec),
    "var_beaufort": (_varbeau_key, _varbeau_dec),
}

# Pre-compute numeric values
CT_NUMS = [ALPH_IDX[c] for c in CT]
CRIB_POS_SORTED = sorted(CRIB_DICT.keys())
PT_NUMS_AT_CRIBS = {p: ALPH_IDX[CRIB_DICT[p]] for p in CRIB_POS_SORTED}

# Bean equality
BEAN_POS_A, BEAN_POS_B = BEAN_EQ[0]

# ENE positions (21-33) and BC positions (63-73)
ENE_POSITIONS = [p for p in CRIB_POS_SORTED if 21 <= p <= 33]
BC_POSITIONS = [p for p in CRIB_POS_SORTED if 63 <= p <= 73]

# ── Egyptian Section 151B — Words of Isis (Community's suggestion) ─────────────
# Transliterated hieroglyphic text from Tutankhamun's golden death mask
# Manuel de Codage transliteration, alpha characters only

SECTION_151B_TRANSLIT = re.sub(r'[^A-Z]', '', """
DDMDWINISTIINIKMSAKHWNITAWRSRTK
MHYTPRTMITMSAQNINKHTYTRDINKWNNTR
XFTYWKXRTBWTYSMAAXRWKMPTNTRXRA
WSRTIMMNTRKXNMTIMTSTRIRISMKSMT
HRMAAXXRW
""".upper())

SECTION_151B_ENGLISH = re.sub(r'[^A-Z]', '', """
WORDSSPOKENBYISIS
IHAVECOMEASKYOURPROTECTIONIHAVEDRIVENBREATHTO
YOURNOS TRILTHE NORTHWINDTHATCOMESFROMATUM
IHAVEGATHEREDYOURNECKFORYOUIHAVECAUSEDYOUTO
EXISTASAGODYOURENEMIESAREUNDERYOURSANDALS
YOURVOICEISMADETRUEINTHE SKYBEFORERA
MIGHTYAMONGGODSJOINEDINTHEKNOTTOMAKYOUGO
THEWAYOFHORUSTRUEOFVOICE
""".upper())

# Additional Egyptian texts to test (key passages)
BOOK_OF_DEAD_CH125 = re.sub(r'[^A-Z]', '', """
IHAVENOTTOLDALIEIKNOWINGLYI HAVENOTMADEANY ONETOCRY
IHAVENOTSLAINMANORWOMANIHAVENOTROBBED
IHAVENOTDONETHATWHICHTHEGODSABOMINATE
IHAVENOTCAUSEDPAINIHAVENOTDEFRAUDED
""".upper())

# Carter's famous words at the tomb opening
CARTER_WONDERFUL = re.sub(r'[^A-Z]', '', """
ATFIRSTICOULDSEENOTHINGTHEHOTAIRESC APINGFROMTHECHAMBER
CAUSINGTHECANDLE FLAMETOFLICKERBUTPRESENTLYASMYEYES
GREWACCUSTOMEDTOTHELIGHTSDETAILSOFTHEROOMWITHINEMERGED
SLOWLYFROMTHEMISTSTRANGEANIMALS STATUESANDGOLDEVERYWHERE
THEGLITTEROFGOLD
""".upper())

# Compile all test texts
KIMMO_TEXTS = [
    ("Section_151B_translit", SECTION_151B_TRANSLIT),
    ("Section_151B_english", SECTION_151B_ENGLISH),
    ("Book_of_Dead_ch125", BOOK_OF_DEAD_CH125),
    ("Carter_wonderful", CARTER_WONDERFUL),
]


# ── Constant-detection running key check ───────────────────────────────────

def constant_crib_check(text_nums, offset, variant_key_fn):
    """Check if crib positions match with a consistent constant C.

    For each crib position p, compute:
      actual_key = variant_key_fn(CT[p], PT[p])
      running_key = text_nums[offset + p]
      residual = (actual_key - running_key) mod 26

    If all residuals are the same value C, we have a constant-term match.
    Returns (n_ene_match, n_bc_match, best_C, total_match) or None.
    """
    if offset + CT_LEN > len(text_nums):
        return None

    # Compute residuals for ENE group
    ene_residuals = []
    for p in ENE_POSITIONS:
        actual_k = variant_key_fn(CT_NUMS[p], PT_NUMS_AT_CRIBS[p])
        running_k = text_nums[offset + p]
        residual = (actual_k - running_k) % MOD
        ene_residuals.append(residual)

    # Check if ENE residuals are all the same
    ene_c = ene_residuals[0]
    ene_match = sum(1 for r in ene_residuals if r == ene_c)

    # Compute residuals for BC group
    bc_residuals = []
    for p in BC_POSITIONS:
        actual_k = variant_key_fn(CT_NUMS[p], PT_NUMS_AT_CRIBS[p])
        running_k = text_nums[offset + p]
        residual = (actual_k - running_k) % MOD
        bc_residuals.append(residual)

    bc_c = bc_residuals[0]
    bc_match = sum(1 for r in bc_residuals if r == bc_c)

    # Check if both groups have same constant
    if ene_c == bc_c:
        total = ene_match + bc_match
        return (ene_match, bc_match, ene_c, total)

    # Report best group even if they differ
    best = max(ene_match, bc_match)
    if best >= 8:  # At least 8/13 or 8/11 match
        return (ene_match, bc_match, ene_c if ene_match >= bc_match else bc_c,
                ene_match + bc_match)

    return None


def decrypt_with_constant(text_nums, offset, constant_c, variant_dec_fn):
    """Decrypt full CT using running key text at offset with constant C."""
    pt = []
    for i in range(CT_LEN):
        if offset + i >= len(text_nums):
            pt.append('?')
            continue
        k = (text_nums[offset + i] + constant_c) % MOD
        p = variant_dec_fn(CT_NUMS[i], k)
        pt.append(ALPH[p])
    return "".join(pt)


def process_text(args):
    """Process a single text through all variants and offsets."""
    text_name, text_str, min_crib_match = args
    text_nums = [ALPH_IDX[c] for c in text_str if c in ALPH_IDX]

    if len(text_nums) < CT_LEN:
        return []

    hits = []
    max_offset = len(text_nums) - CT_LEN

    for variant_name, (key_fn, dec_fn) in VARIANTS.items():
        for offset in range(max_offset + 1):
            result = constant_crib_check(text_nums, offset, key_fn)
            if result is None:
                continue

            ene_match, bc_match, best_c, total = result

            if total >= min_crib_match:
                # Decrypt and score
                pt = decrypt_with_constant(text_nums, offset, best_c, dec_fn)
                sb = score_candidate(pt)

                hits.append((
                    float(sb.crib_score),
                    pt,
                    f"diana_const({variant_name},C={best_c})/"
                    f"text={text_name}/off={offset} "
                    f"ene={ene_match}/13 bc={bc_match}/11 "
                    f"bean={'PASS' if sb.bean_passed else 'FAIL'} "
                    f"{sb.summary}"
                ))

    return hits


def load_gutenberg_corpus():
    """Load Egyptian Gutenberg texts if available."""
    corpus_dir = os.path.join(_ROOT, "data", "corpus")
    texts = []

    if not os.path.exists(corpus_dir):
        return texts

    for fname in os.listdir(corpus_dir):
        if fname.endswith(".txt"):
            path = os.path.join(corpus_dir, fname)
            try:
                with open(path, encoding='utf-8', errors='ignore') as f:
                    content = re.sub(r'[^A-Z]', '', f.read().upper())
                if len(content) >= CT_LEN:
                    texts.append((fname, content))
            except Exception:
                pass

    return texts


def attack(ciphertext: str = CT, **params):
    """Extended Diana running key with constant term."""
    min_crib_match = params.get("min_crib_match", 8)
    n_workers = params.get("workers", max(1, cpu_count() - 2))

    # Phase 1: Test Community's specific texts (quick)
    print("Phase 1: Testing Community's specific texts...")
    all_hits = []

    for text_name, text_str in KIMMO_TEXTS:
        print(f"  {text_name}: {len(text_str)} chars")
        hits = process_text((text_name, text_str, min_crib_match))
        all_hits.extend(hits)
        if hits:
            print(f"    → {len(hits)} hits!")
        else:
            print(f"    → no hits")

    # Also test C=0 explicitly for standard running key (sanity check)
    for text_name, text_str in KIMMO_TEXTS:
        text_nums = [ALPH_IDX[c] for c in text_str if c in ALPH_IDX]
        if len(text_nums) < CT_LEN:
            continue
        for variant_name, (key_fn, dec_fn) in VARIANTS.items():
            for offset in range(len(text_nums) - CT_LEN + 1):
                pt = decrypt_with_constant(text_nums, offset, 0, dec_fn)
                sb = score_candidate(pt)
                if sb.crib_score >= STORE_THRESHOLD:
                    all_hits.append((
                        float(sb.crib_score), pt,
                        f"standard_rk({variant_name})/text={text_name}/off={offset} "
                        f"{sb.summary}"
                    ))

    # Phase 2: Load and test Egyptian Gutenberg corpus
    print("\nPhase 2: Loading Gutenberg corpus...")
    corpus_texts = load_gutenberg_corpus()
    print(f"  Found {len(corpus_texts)} corpus texts")

    # Also check reference/ for large text files
    ref_dir = os.path.join(_ROOT, "reference")
    if os.path.exists(ref_dir):
        for fname in os.listdir(ref_dir):
            if fname.endswith(".txt") and not fname.startswith('.'):
                path = os.path.join(ref_dir, fname)
                try:
                    with open(path, encoding='utf-8', errors='ignore') as f:
                        content = re.sub(r'[^A-Z]', '', f.read().upper())
                    if len(content) >= CT_LEN * 2:
                        corpus_texts.append((f"ref/{fname}", content))
                except Exception:
                    pass

    if corpus_texts:
        print(f"  Total texts to test: {len(corpus_texts)}")
        work = [(name, text, min_crib_match) for name, text in corpus_texts]

        t0 = time.time()
        if len(corpus_texts) > 1 and n_workers > 1:
            with Pool(min(n_workers, len(corpus_texts))) as pool:
                for hits in pool.imap_unordered(process_text, work):
                    all_hits.extend(hits)
        else:
            for item in work:
                hits = process_text(item)
                all_hits.extend(hits)
        t1 = time.time()
        print(f"  Corpus sweep: {t1 - t0:.1f}s")

    all_hits.sort(reverse=True)
    return all_hits


def main():
    print("=" * 70)
    print("EXTENDED DIANA — Running key with constant term + Egyptian texts")
    print("Credit: Community (community idea)")
    print("=" * 70)

    # Show the test texts
    print("\nCommunity's texts:")
    for name, text in KIMMO_TEXTS:
        print(f"  {name}: {len(text)} chars — {text[:50]}...")

    print()
    results = attack()

    print(f"\nTotal results: {len(results)}")
    if results:
        print("\nTop 30 results:")
        print("-" * 70)
        for i, (score, pt, desc) in enumerate(results[:30]):
            print(f"  [{i+1:2d}] score={score:.0f}  {desc}")
            if score >= 10:
                print(f"        PT: {pt}")

    print("\n" + "=" * 70)
    signal = [r for r in results if r[0] >= 18]
    if signal:
        print(f"SIGNAL: {len(signal)} results with crib_score >= 18!")
    else:
        print("VERDICT: No signal found")
    print("=" * 70)


if __name__ == "__main__":
    main()
