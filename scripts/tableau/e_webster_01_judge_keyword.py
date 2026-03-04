#!/usr/bin/env python3
"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-WEBSTER-01: Test JUDGE and Webster-related keywords in multi-layer K4 decryption.

Hypothesis: William H. Webster was CIA director when Kryptos was installed (1987-1991).
His preferred title was "Judge" (from his federal judge tenure). JUDGE (5 letters) and
other Webster-related keywords may serve as substitution or transposition keys in a
multi-layer cipher.

Methods tested:
  A) Vigenere/Beaufort/VarBeaufort decrypt with keyword, then columnar transposition
  B) Columnar transposition first, then Vigenere/Beaufort/VarBeaufort decrypt with keyword
  C) Two-keyword Vigenere: JUDGE combined with KRYPTOS/PALIMPSEST/ABSCISSA
  D) Keyword-derived columnar transposition (keyword as column ordering)
  E) Double substitution: two keywords applied sequentially
  F) Reverse CT, then substitution with keyword

All scoring uses the canonical score_candidate() path.
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import List, Tuple, Optional, Dict, Any

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_WORDS, CRIB_DICT, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant, remove_additive_mask,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm, keyword_to_order,
    rail_fence_perm, myszkowski_perm,
)
from kryptos.kernel.constraints.bean import verify_bean, BeanResult


# ── Configuration ────────────────────────────────────────────────────────────

RESULTS_DIR = "results/webster_judge_01"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Webster-related keywords
WEBSTER_KEYWORDS = [
    "JUDGE",           # His preferred title, 5 letters
    "WEBSTER",         # Surname, 7 letters
    "WILLIAM",         # First name, 7 letters
    "HEDGCOCK",        # Middle name, 8 letters
    "JUDGEW",          # 5 letters (JUDGE + W initial)
    "AMHERST",         # His college, 7 letters
    "STLOUIS",         # Hometown, 7 letters
    "DRUSILLA",        # First wife, 8 letters
    "TEASDALE",        # Law firm, 8 letters
    "PSIUPSILON",      # Fraternity, 10 letters
    "MISSOURI",        # Home state, 8 letters
    "WARRENTON",       # Death location, 9 letters
    "DIRECTOR",        # His role, 8 letters
    "WILLIAMWEBSTER",  # Full name, 14 letters
    "JUDGEWEBSTER",    # Title + name, 12 letters
]

# Combination keywords (Webster + Kryptos themes)
COMBO_KEYWORDS = [
    "JUDGEKRYPTOS",
    "KRYPTOSJUDGE",
    "JUDGEPALIMPSEST",
    "PALIMPSESTJUDGE",
    "JUDGEABSCISSA",
    "ABSCISSAJUDGE",
    "JUDGESHADOW",
    "SHADOWJUDGE",
    "JUDGESANBORN",
    "SANBORNJUDGE",
]

# Secondary Kryptos keywords for double-substitution
KRYPTOS_KEYWORDS = [
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "SHADOW",
    "LUCID",
    "MEMORY",
    "DESPARATE",      # Sanborn's misspelling
    "IQLUSION",       # Sanborn's misspelling
    "VIRTUALLY",
    "INVISIBLE",
    "UNDERGROUND",
]

CIPHER_VARIANTS = [
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
]

VARIANT_NAMES = {
    CipherVariant.VIGENERE: "vig",
    CipherVariant.BEAUFORT: "beau",
    CipherVariant.VAR_BEAUFORT: "varbeau",
}

# Transposition widths to test
WIDTHS = list(range(5, 16))  # 5 through 15


# ── Helper functions ─────────────────────────────────────────────────────────

def keyword_to_numeric_key(kw: str) -> List[int]:
    """Convert keyword string to numeric key values (A=0, B=1, ...)."""
    return [ALPH_IDX[c] for c in kw.upper()]


def keyword_to_ka_key(kw: str) -> List[int]:
    """Convert keyword using KA alphabet ordering."""
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    return [ka_idx[c] for c in kw.upper()]


def columnar_decrypt(ct_text: str, width: int, col_order: List[int]) -> str:
    """Decrypt columnar transposition: undo the read-by-columns operation.

    Encryption: write into rows, read by column order.
    Decryption: inverse permutation to recover original row-order text.
    """
    perm = columnar_perm(width, col_order, len(ct_text))
    inv = invert_perm(perm)
    return apply_perm(ct_text, inv)


def columnar_encrypt(pt_text: str, width: int, col_order: List[int]) -> str:
    """Apply columnar transposition (encrypt direction)."""
    perm = columnar_perm(width, col_order, len(pt_text))
    return apply_perm(pt_text, perm)


def check_bean_from_plaintext(plaintext: str, variant: CipherVariant) -> BeanResult:
    """Derive keystream from candidate plaintext and check Bean constraints."""
    from kryptos.kernel.transforms.vigenere import KEY_RECOVERY
    fn = KEY_RECOVERY[variant]
    ks = [0] * CT_LEN
    for i in range(CT_LEN):
        c = ord(CT[i]) - 65
        p = ord(plaintext[i]) - 65
        ks[i] = fn(c, p)
    return verify_bean(ks)


def score_result(plaintext: str, variant: CipherVariant = CipherVariant.VIGENERE) -> Tuple[ScoreBreakdown, BeanResult]:
    """Score a candidate plaintext through the canonical path + Bean check."""
    bean = check_bean_from_plaintext(plaintext, variant)
    score = score_candidate(plaintext, bean_result=bean)
    return score, bean


def find_english_words(text: str, min_len: int = 4) -> List[str]:
    """Quick check for common English words in plaintext."""
    common = {
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN", "HER",
        "WAS", "ONE", "OUR", "OUT", "HAVE", "THAT", "THIS", "WITH", "FROM",
        "THEY", "BEEN", "SAID", "EACH", "WHICH", "THEIR", "THERE", "WILL",
        "OTHER", "ABOUT", "MANY", "THEN", "THEM", "SOME", "COULD", "WOULD",
        "MAKE", "LIKE", "TIME", "JUST", "KNOW", "TAKE", "COME", "WHAT",
        "EAST", "NORTH", "SOUTH", "WEST", "BERLIN", "CLOCK", "JUDGE",
        "SECRET", "HIDDEN", "BURIED", "LAYER", "SHADOW", "LIGHT",
        "UNDERGROUND", "INVISIBLE", "MEMORY", "BETWEEN", "SUBTLE",
        "SLOWLY", "DESPERATELY", "TOTALLY", "IMPOSSIBLE",
    }
    found = []
    for word in common:
        if len(word) >= min_len and word in text:
            found.append(word)
    return found


# ── Result tracking ──────────────────────────────────────────────────────────

@dataclass
class ExperimentResult:
    method: str
    keyword1: str
    keyword2: str
    variant: str
    width: int
    crib_score: int
    ic_value: float
    bean_passed: bool
    plaintext: str
    classification: str
    english_words: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResultTracker:
    def __init__(self):
        self.results: List[ExperimentResult] = []
        self.best_score = 0
        self.best_result: Optional[ExperimentResult] = None
        self.configs_tested = 0
        self.method_counts: Dict[str, int] = defaultdict(int)
        self.method_best: Dict[str, int] = defaultdict(int)
        self.bean_pass_count = 0
        self.above_noise = 0

    def add(self, result: ExperimentResult):
        self.results.append(result)
        self.configs_tested += 1
        self.method_counts[result.method] += 1

        if result.crib_score > self.method_best[result.method]:
            self.method_best[result.method] = result.crib_score

        if result.bean_passed:
            self.bean_pass_count += 1

        if result.crib_score > NOISE_FLOOR:
            self.above_noise += 1

        if result.crib_score > self.best_score:
            self.best_score = result.crib_score
            self.best_result = result
            if result.crib_score > NOISE_FLOOR:
                print(f"  *** NEW BEST: {result.crib_score}/24 | "
                      f"{result.method} | {result.variant} | "
                      f"kw1={result.keyword1} kw2={result.keyword2} w={result.width} | "
                      f"bean={'PASS' if result.bean_passed else 'FAIL'} | "
                      f"IC={result.ic_value:.4f}")
                print(f"      PT: {result.plaintext[:60]}...")
                words = result.english_words
                if words:
                    print(f"      Words: {', '.join(words)}")

    def summary(self) -> Dict[str, Any]:
        top_results = sorted(self.results, key=lambda r: -r.crib_score)[:20]
        return {
            "total_configs": self.configs_tested,
            "best_score": self.best_score,
            "best_result": self.best_result.to_dict() if self.best_result else None,
            "above_noise_count": self.above_noise,
            "bean_pass_count": self.bean_pass_count,
            "method_counts": dict(self.method_counts),
            "method_best_scores": dict(self.method_best),
            "top_20": [r.to_dict() for r in top_results],
        }


tracker = ResultTracker()


# ── Method A: Substitution then Columnar Transposition ───────────────────────

def test_sub_then_trans():
    """First apply substitution decrypt, then columnar transposition decrypt."""
    print("\n=== Method A: Substitution -> Columnar Transposition ===")
    count = 0

    for kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
        key_az = keyword_to_numeric_key(kw)
        key_ka = keyword_to_ka_key(kw)

        for variant in CIPHER_VARIANTS:
            vname = VARIANT_NAMES[variant]

            # Decrypt substitution first (AZ alphabet)
            intermediate = decrypt_text(CT, key_az, variant)

            for width in WIDTHS:
                # Try all column orderings derived from keywords
                for trans_kw in WEBSTER_KEYWORDS:
                    if len(trans_kw) < width:
                        continue
                    col_order = keyword_to_order(trans_kw, width)
                    if col_order is None:
                        continue

                    # Undo columnar transposition
                    pt = columnar_decrypt(intermediate, width, list(col_order))
                    if len(pt) != CT_LEN:
                        continue

                    sc, bean = score_result(pt, variant)
                    words = find_english_words(pt)

                    result = ExperimentResult(
                        method="A_sub_then_trans_az",
                        keyword1=kw,
                        keyword2=trans_kw,
                        variant=vname,
                        width=width,
                        crib_score=sc.crib_score,
                        ic_value=sc.ic_value,
                        bean_passed=sc.bean_passed,
                        plaintext=pt,
                        classification=sc.crib_classification,
                        english_words=words,
                    )
                    tracker.add(result)
                    count += 1

            # Also try with KA alphabet key
            intermediate_ka = decrypt_text(CT, key_ka, variant)

            for width in WIDTHS:
                for trans_kw in WEBSTER_KEYWORDS:
                    if len(trans_kw) < width:
                        continue
                    col_order = keyword_to_order(trans_kw, width)
                    if col_order is None:
                        continue

                    pt = columnar_decrypt(intermediate_ka, width, list(col_order))
                    if len(pt) != CT_LEN:
                        continue

                    sc, bean = score_result(pt, variant)
                    words = find_english_words(pt)

                    result = ExperimentResult(
                        method="A_sub_then_trans_ka",
                        keyword1=kw,
                        keyword2=trans_kw,
                        variant=vname,
                        width=width,
                        crib_score=sc.crib_score,
                        ic_value=sc.ic_value,
                        bean_passed=sc.bean_passed,
                        plaintext=pt,
                        classification=sc.crib_classification,
                        english_words=words,
                    )
                    tracker.add(result)
                    count += 1

    print(f"  Method A complete: {count} configs tested")


# ── Method B: Columnar Transposition then Substitution ───────────────────────

def test_trans_then_sub():
    """First undo columnar transposition, then apply substitution decrypt."""
    print("\n=== Method B: Columnar Transposition -> Substitution ===")
    count = 0

    for trans_kw in WEBSTER_KEYWORDS:
        for width in WIDTHS:
            if len(trans_kw) < width:
                continue
            col_order = keyword_to_order(trans_kw, width)
            if col_order is None:
                continue

            # Undo transposition first
            intermediate = columnar_decrypt(CT, width, list(col_order))
            if len(intermediate) != CT_LEN:
                continue

            for kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
                key_az = keyword_to_numeric_key(kw)

                for variant in CIPHER_VARIANTS:
                    vname = VARIANT_NAMES[variant]

                    # Then decrypt substitution
                    pt = decrypt_text(intermediate, key_az, variant)

                    sc, bean = score_result(pt, variant)
                    words = find_english_words(pt)

                    result = ExperimentResult(
                        method="B_trans_then_sub_az",
                        keyword1=kw,
                        keyword2=trans_kw,
                        variant=vname,
                        width=width,
                        crib_score=sc.crib_score,
                        ic_value=sc.ic_value,
                        bean_passed=sc.bean_passed,
                        plaintext=pt,
                        classification=sc.crib_classification,
                        english_words=words,
                    )
                    tracker.add(result)
                    count += 1

    print(f"  Method B complete: {count} configs tested")


# ── Method C: Two-keyword Vigenere ───────────────────────────────────────────

def test_two_keyword_vigenere():
    """Apply two Vigenere decryptions sequentially with different keywords."""
    print("\n=== Method C: Two-keyword Vigenere ===")
    count = 0

    # JUDGE + each Kryptos keyword
    for kw1 in ["JUDGE", "WEBSTER", "WILLIAM", "JUDGEWEBSTER", "HEDGCOCK"]:
        key1 = keyword_to_numeric_key(kw1)
        for kw2 in KRYPTOS_KEYWORDS:
            key2 = keyword_to_numeric_key(kw2)

            for v1 in CIPHER_VARIANTS:
                # First decryption
                inter = decrypt_text(CT, key1, v1)
                for v2 in CIPHER_VARIANTS:
                    # Second decryption
                    pt = decrypt_text(inter, key2, v2)

                    sc, bean = score_result(pt, CipherVariant.VIGENERE)
                    words = find_english_words(pt)

                    result = ExperimentResult(
                        method="C_double_vig",
                        keyword1=kw1,
                        keyword2=kw2,
                        variant=f"{VARIANT_NAMES[v1]}+{VARIANT_NAMES[v2]}",
                        width=0,
                        crib_score=sc.crib_score,
                        ic_value=sc.ic_value,
                        bean_passed=sc.bean_passed,
                        plaintext=pt,
                        classification=sc.crib_classification,
                        english_words=words,
                    )
                    tracker.add(result)
                    count += 1

    print(f"  Method C complete: {count} configs tested")


# ── Method D: Keyword-ordered columnar with sequential numeric widths ────────

def test_keyword_columnar():
    """Use Webster keywords directly as columnar transposition keys, then sub."""
    print("\n=== Method D: Keyword columnar + substitution ===")
    count = 0

    for trans_kw in WEBSTER_KEYWORDS:
        width = len(trans_kw)
        if width < 5 or width > 20:
            continue
        col_order = keyword_to_order(trans_kw, width)
        if col_order is None:
            continue

        # Undo transposition
        intermediate = columnar_decrypt(CT, width, list(col_order))

        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                pt = decrypt_text(intermediate, key, variant)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="D_kw_columnar_sub",
                    keyword1=sub_kw,
                    keyword2=trans_kw,
                    variant=vname,
                    width=width,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

        # Also try: substitution first, then this keyword transposition
        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                inter2 = decrypt_text(CT, key, variant)
                pt = columnar_decrypt(inter2, width, list(col_order))

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="D_sub_kw_columnar",
                    keyword1=sub_kw,
                    keyword2=trans_kw,
                    variant=vname,
                    width=width,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

    print(f"  Method D complete: {count} configs tested")


# ── Method E: Myszkowski transposition + substitution ────────────────────────

def test_myszkowski():
    """Myszkowski transposition with Webster keywords (handles tied columns)."""
    print("\n=== Method E: Myszkowski transposition + substitution ===")
    count = 0

    for trans_kw in WEBSTER_KEYWORDS:
        if len(trans_kw) < 5 or len(trans_kw) > 15:
            continue

        perm = myszkowski_perm(trans_kw, CT_LEN)
        if len(perm) != CT_LEN:
            continue
        inv = invert_perm(perm)
        intermediate = apply_perm(CT, inv)

        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                pt = decrypt_text(intermediate, key, variant)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="E_myszkowski_sub",
                    keyword1=sub_kw,
                    keyword2=trans_kw,
                    variant=vname,
                    width=len(trans_kw),
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

        # Also: sub first, then Myszkowski
        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                inter2 = decrypt_text(CT, key, variant)
                pt = apply_perm(inter2, inv)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="E_sub_myszkowski",
                    keyword1=sub_kw,
                    keyword2=trans_kw,
                    variant=vname,
                    width=len(trans_kw),
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

    print(f"  Method E complete: {count} configs tested")


# ── Method F: Rail fence + substitution ──────────────────────────────────────

def test_rail_fence():
    """Rail fence transposition with various depths + Webster substitution."""
    print("\n=== Method F: Rail fence + substitution ===")
    count = 0

    for depth in range(3, 20):
        perm = rail_fence_perm(CT_LEN, depth)
        inv = invert_perm(perm)
        intermediate = apply_perm(CT, inv)

        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                pt = decrypt_text(intermediate, key, variant)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="F_railfence_sub",
                    keyword1=sub_kw,
                    keyword2=f"depth_{depth}",
                    variant=vname,
                    width=depth,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

        # Sub first, then rail fence
        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                inter2 = decrypt_text(CT, key, variant)
                pt = apply_perm(inter2, inv)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="F_sub_railfence",
                    keyword1=sub_kw,
                    keyword2=f"depth_{depth}",
                    variant=vname,
                    width=depth,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

    print(f"  Method F complete: {count} configs tested")


# ── Method G: Small-width columnar exhaustive (JUDGE=5 letters) ──────────────

def test_judge_exhaustive_small():
    """For JUDGE (5 letters), test ALL 120 column permutations + substitution."""
    print("\n=== Method G: JUDGE width-5 exhaustive permutations ===")
    count = 0

    all_perms_5 = list(itertools.permutations(range(5)))

    for col_order in all_perms_5:
        # Undo transposition with this column order
        intermediate = columnar_decrypt(CT, 5, list(col_order))

        for sub_kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
            key = keyword_to_numeric_key(sub_kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                pt = decrypt_text(intermediate, key, variant)

                sc, bean = score_result(pt, variant)
                words = find_english_words(pt)

                result = ExperimentResult(
                    method="G_judge_w5_exhaustive_trans_sub",
                    keyword1=sub_kw,
                    keyword2=str(col_order),
                    variant=vname,
                    width=5,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=words,
                )
                tracker.add(result)
                count += 1

    # Also: sub with JUDGE first, then all w5 perms
    for variant in CIPHER_VARIANTS:
        vname = VARIANT_NAMES[variant]
        judge_key = keyword_to_numeric_key("JUDGE")
        inter_judge = decrypt_text(CT, judge_key, variant)

        for col_order in all_perms_5:
            pt = columnar_decrypt(inter_judge, 5, list(col_order))

            sc, bean = score_result(pt, variant)
            words = find_english_words(pt)

            result = ExperimentResult(
                method="G_judge_sub_w5_exhaustive",
                keyword1="JUDGE",
                keyword2=str(col_order),
                variant=vname,
                width=5,
                crib_score=sc.crib_score,
                ic_value=sc.ic_value,
                bean_passed=sc.bean_passed,
                plaintext=pt,
                classification=sc.crib_classification,
                english_words=words,
            )
            tracker.add(result)
            count += 1

    print(f"  Method G complete: {count} configs tested")


# ── Method H: Reversed CT + substitution ─────────────────────────────────────

def test_reversed_ct():
    """Reverse the CT, then apply substitution with Webster keywords."""
    print("\n=== Method H: Reversed/shifted CT + substitution ===")
    count = 0

    ct_reversed = CT[::-1]

    for kw in WEBSTER_KEYWORDS + COMBO_KEYWORDS:
        key = keyword_to_numeric_key(kw)
        for variant in CIPHER_VARIANTS:
            vname = VARIANT_NAMES[variant]
            pt = decrypt_text(ct_reversed, key, variant)

            sc, bean = score_result(pt, variant)
            words = find_english_words(pt)

            result = ExperimentResult(
                method="H_reverse_sub",
                keyword1=kw,
                keyword2="reversed",
                variant=vname,
                width=0,
                crib_score=sc.crib_score,
                ic_value=sc.ic_value,
                bean_passed=sc.bean_passed,
                plaintext=pt,
                classification=sc.crib_classification,
                english_words=words,
            )
            tracker.add(result)
            count += 1

    # Also test cyclic shifts of CT
    for shift in range(1, CT_LEN):
        ct_shifted = CT[shift:] + CT[:shift]
        for kw in ["JUDGE", "WEBSTER", "KRYPTOS"]:
            key = keyword_to_numeric_key(kw)
            for variant in CIPHER_VARIANTS:
                vname = VARIANT_NAMES[variant]
                pt = decrypt_text(ct_shifted, key, variant)

                sc, bean = score_result(pt, variant)

                result = ExperimentResult(
                    method="H_shift_sub",
                    keyword1=kw,
                    keyword2=f"shift_{shift}",
                    variant=vname,
                    width=shift,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=find_english_words(pt),
                )
                tracker.add(result)
                count += 1

    print(f"  Method H complete: {count} configs tested")


# ── Method I: JUDGE as numeric offset patterns ──────────────────────────────

def test_judge_numeric_patterns():
    """Use JUDGE letter positions as numeric parameters for transposition."""
    print("\n=== Method I: JUDGE numeric patterns ===")
    count = 0

    # JUDGE in various encodings
    judge_az = [ord(c) - 65 for c in "JUDGE"]  # [9, 20, 3, 6, 4]
    judge_ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    judge_ka = [judge_ka_idx[c] for c in "JUDGE"]  # KA-indexed

    # Use JUDGE values as skip/interval pattern
    for key_vals in [judge_az, judge_ka]:
        for variant in CIPHER_VARIANTS:
            vname = VARIANT_NAMES[variant]

            # Progressive key: start with JUDGE, increment each cycle
            for offset in range(26):
                prog_key = [(v + offset + (i // 5)) % 26 for i, v in
                           enumerate(key_vals * ((CT_LEN // 5) + 1))][:CT_LEN]
                pt = decrypt_text(CT, prog_key, variant)
                sc, bean = score_result(pt, variant)

                result = ExperimentResult(
                    method="I_progressive_judge",
                    keyword1=f"JUDGE_offset_{offset}",
                    keyword2="progressive",
                    variant=vname,
                    width=5,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=find_english_words(pt),
                )
                tracker.add(result)
                count += 1

            # Autokey: start with JUDGE, then use PT as key
            for start_offset in range(26):
                key_so_far = [(v + start_offset) % 26 for v in key_vals]
                pt_chars = []
                for i in range(CT_LEN):
                    if i < len(key_so_far):
                        k = key_so_far[i]
                    else:
                        # Use previous plaintext char as key
                        k = ord(pt_chars[i - 5]) - 65
                    from kryptos.kernel.transforms.vigenere import DECRYPT_FN
                    p = DECRYPT_FN[variant](ord(CT[i]) - 65, k)
                    pt_chars.append(chr(p + 65))
                    if i >= len(key_so_far):
                        pass  # Already used autokey

                pt = "".join(pt_chars)
                sc, bean = score_result(pt, variant)

                result = ExperimentResult(
                    method="I_autokey_judge",
                    keyword1=f"JUDGE_auto_{start_offset}",
                    keyword2="autokey",
                    variant=vname,
                    width=5,
                    crib_score=sc.crib_score,
                    ic_value=sc.ic_value,
                    bean_passed=sc.bean_passed,
                    plaintext=pt,
                    classification=sc.crib_classification,
                    english_words=find_english_words(pt),
                )
                tracker.add(result)
                count += 1

    print(f"  Method I complete: {count} configs tested")


# ── Method J: Triple layer — sub + trans + sub ───────────────────────────────

def test_triple_layer():
    """Three-layer: outer sub (JUDGE) + transposition + inner sub (KRYPTOS etc)."""
    print("\n=== Method J: Triple layer (sub + trans + sub) ===")
    count = 0

    # Outer keyword always JUDGE (or WEBSTER), inner varies
    for outer_kw in ["JUDGE", "WEBSTER", "WILLIAM"]:
        outer_key = keyword_to_numeric_key(outer_kw)

        for variant in CIPHER_VARIANTS:
            vname = VARIANT_NAMES[variant]
            # Strip outer substitution
            inter1 = decrypt_text(CT, outer_key, variant)

            for width in [5, 7, 8, 9, 10, 11, 12, 13]:
                for trans_kw in ["JUDGE", "WEBSTER", "KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    if len(trans_kw) < width:
                        continue
                    col_order = keyword_to_order(trans_kw, width)
                    if col_order is None:
                        continue

                    # Strip transposition
                    inter2 = columnar_decrypt(inter1, width, list(col_order))

                    for inner_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "JUDGE", "WEBSTER"]:
                        inner_key = keyword_to_numeric_key(inner_kw)
                        for v2 in CIPHER_VARIANTS:
                            pt = decrypt_text(inter2, inner_key, v2)

                            sc, _ = score_result(pt, v2)

                            result = ExperimentResult(
                                method="J_triple",
                                keyword1=f"{outer_kw}+{inner_kw}",
                                keyword2=trans_kw,
                                variant=f"{vname}+{VARIANT_NAMES[v2]}",
                                width=width,
                                crib_score=sc.crib_score,
                                ic_value=sc.ic_value,
                                bean_passed=sc.bean_passed,
                                plaintext=pt,
                                classification=sc.crib_classification,
                                english_words=find_english_words(pt),
                            )
                            tracker.add(result)
                            count += 1

    print(f"  Method J complete: {count} configs tested")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 78)
    print("E-WEBSTER-01: JUDGE & Webster keywords in multi-layer K4 decryption")
    print("=" * 78)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Webster keywords: {len(WEBSTER_KEYWORDS)}")
    print(f"Combo keywords: {len(COMBO_KEYWORDS)}")
    print(f"Kryptos keywords: {len(KRYPTOS_KEYWORDS)}")
    print(f"Cipher variants: {len(CIPHER_VARIANTS)}")
    print(f"Transposition widths: {WIDTHS}")
    print()

    t0 = time.time()

    # Run all methods
    test_sub_then_trans()
    test_trans_then_sub()
    test_two_keyword_vigenere()
    test_keyword_columnar()
    test_myszkowski()
    test_rail_fence()
    test_judge_exhaustive_small()
    test_reversed_ct()
    test_judge_numeric_patterns()
    test_triple_layer()

    elapsed = time.time() - t0

    # ── Final summary ────────────────────────────────────────────────────
    print("\n" + "=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)
    print(f"Total configs tested: {tracker.configs_tested:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    print(f"Best score: {tracker.best_score}/24")
    print(f"Above noise (>{NOISE_FLOOR}): {tracker.above_noise}")
    print(f"Bean pass count: {tracker.bean_pass_count}")
    print()

    print("Method breakdown:")
    for method, count in sorted(tracker.method_counts.items()):
        best = tracker.method_best[method]
        print(f"  {method}: {count:,} configs, best={best}/24")
    print()

    if tracker.best_result:
        br = tracker.best_result
        print(f"BEST RESULT:")
        print(f"  Method: {br.method}")
        print(f"  Variant: {br.variant}")
        print(f"  Keyword1: {br.keyword1}")
        print(f"  Keyword2: {br.keyword2}")
        print(f"  Width: {br.width}")
        print(f"  Crib score: {br.crib_score}/24")
        print(f"  IC: {br.ic_value:.4f}")
        print(f"  Bean: {'PASS' if br.bean_passed else 'FAIL'}")
        print(f"  Classification: {br.classification}")
        print(f"  Plaintext: {br.plaintext}")
        if br.english_words:
            print(f"  English words: {', '.join(br.english_words)}")
    print()

    # Top 20
    top20 = sorted(tracker.results, key=lambda r: (-r.crib_score, -r.ic_value))[:20]
    print("Top 20 results:")
    for i, r in enumerate(top20, 1):
        print(f"  {i:2d}. score={r.crib_score}/24 IC={r.ic_value:.4f} "
              f"bean={'P' if r.bean_passed else 'F'} "
              f"{r.method} {r.variant} kw1={r.keyword1} kw2={r.keyword2} w={r.width}")
        print(f"      PT: {r.plaintext[:70]}...")
    print()

    # Save results
    summary = tracker.summary()
    summary["elapsed_seconds"] = elapsed
    summary["experiment_id"] = "e_webster_01_judge_keyword"

    results_path = os.path.join(RESULTS_DIR, "summary.json")
    with open(results_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Results saved to {results_path}")

    # Verdict
    if tracker.best_score >= SIGNAL_THRESHOLD:
        print(f"\n*** SIGNAL DETECTED: {tracker.best_score}/24 — investigate further ***")
    elif tracker.best_score > NOISE_FLOOR:
        print(f"\nAbove noise floor ({tracker.best_score}/24) but below signal threshold.")
    else:
        print(f"\nAll results at or below noise floor ({tracker.best_score}/24). "
              f"Webster keywords do not produce signal in tested configurations.")


if __name__ == "__main__":
    main()
