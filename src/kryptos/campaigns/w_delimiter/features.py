"""Multi-feature extraction for W-delimiter candidates.

Every feature is computed independently and reported separately so that
the composite cannot hide which channel does the work. The single cheap
feature we already know is weak — `new_zero_count` — is retained but
capped in the composite weighting (see composite.py).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Tuple

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, CRIB_DICT

from kryptos.campaigns.w_delimiter.slot_model import (
    WDelimiterModel,
    canonical_w_delimiter_model,
)
from kryptos.campaigns.w_delimiter.populations import FillCandidate


# ── Helpers ─────────────────────────────────────────────────────────

_VARIANTS = ("vig", "beau", "vbeau")


def _ks_value(ct_idx: int, pt_idx: int, variant: str) -> int:
    if variant == "vig":
        return (ct_idx - pt_idx) % MOD
    if variant == "beau":
        return (ct_idx + pt_idx) % MOD
    if variant == "vbeau":
        return (pt_idx - ct_idx) % MOD
    raise ValueError(f"unknown variant: {variant}")


# ── English fragment heuristics ─────────────────────────────────────

_COMMON_BIGRAMS = frozenset(
    "TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR ST TO NT NG SE HA AS OU IO LE VE CO ME DE HI RI RO IC NE EA RA CE LI CH LL BE MA SI OM UR".split()
)
_COMMON_TRIGRAMS = frozenset(
    "THE AND ING ION TIO ENT FOR HER ATE VER TER HAT THA ERE ATI HIS CON RES FRO INT ONE OUT ALL PER EST WIT ATE OVE ITH NOT NCE".split()
)

_KNOWN_KEYWORDS = ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SANBORN")

# English frequency proxy: a small set of top English words for the
# complexity penalty. Words outside these lists get a low weight.
_TOP_100 = frozenset("""
THE OF AND TO IN IS IT YOU THAT HE WAS FOR ON ARE AS WITH HIS THEY AT BE
THIS HAVE FROM OR ONE HAD BY WORD BUT NOT WHAT ALL WERE WE WHEN YOUR CAN
SAID THERE USE AN EACH WHICH SHE DO HOW THEIR IF WILL UP OTHER ABOUT OUT
MANY THEN THEM THESE SO SOME HER WOULD MAKE LIKE HIM INTO TIME HAS LOOK
TWO MORE WRITE GO SEE NUMBER NO WAY COULD PEOPLE MY THAN FIRST WATER
BEEN CALL WHO OIL ITS NOW FIND LONG DOWN DAY DID GET COME MADE MAY PART
NEAR OVER BACK HERE AWAY UPON INTO
""".split())
_TOP_1000 = frozenset("""
AT TO IS BY UP AN OR IT HE WE US ME MY IF SO NO DO BE GO ON OF IN AS
ATOP PAST FROM ONCE NOON HOUR ZONE WHEN THIS THAT EACH SOME TIME EDGE
SIDE AREA FACE WALL GATE DOOR WEST EAST TRUE REAL MAIN READ SEEK KEEP
HOLD SHOW MEET TELL VIEW LOOK FIND BACK AWAY DOWN HERE NEAR UPON INTO
ONTO
""".split())


def _fill_complexity(word: str) -> float:
    """1.0 / log(1 + frequency_score). Smaller = more common = cheaper."""
    if word in _TOP_100:
        freq = 1.0
    elif word in _TOP_1000:
        freq = 0.5
    else:
        freq = 0.1
    return 1.0 / math.log(1.0 + freq + 1.0)  # rough proxy


def _semantic_coherence(a: str, b: str) -> float:
    """Rule-based coherence in [0,1].

    1.0  — both fillers are functional words AND together fit
           "[direction] <A> ... <B> [location]" (A preposition/copula,
           B spatial preposition).
    0.5  — one of the two fits its role but not the other.
    0.0  — neither fits.
    """
    a_ok = a in _TOP_100 or a in _TOP_1000
    b_ok = b in _TOP_100 or b in _TOP_1000
    a_strong = a in ("TO", "AT", "IN", "ON", "OF", "BY", "IS", "BE", "UP", "AS")
    b_strong = b in ("NEAR", "ATOP", "UPON", "OVER", "ONTO", "INTO", "PAST", "FROM")
    if a_strong and b_strong:
        return 1.0
    if a_ok and b_ok:
        return 0.5
    if a_ok or b_ok:
        return 0.25
    return 0.0


def _max_run(s: str) -> int:
    if not s:
        return 0
    best = cur = 1
    prev = s[0]
    for ch in s[1:]:
        if ch == prev:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
            prev = ch
    return best


def _contains_keyword(s: str) -> str:
    for kw in _KNOWN_KEYWORDS:
        if kw in s:
            return kw
    return ""


def _ngram_count(s: str, ngrams: frozenset, n: int) -> int:
    return sum(1 for i in range(len(s) - n + 1) if s[i:i + n] in ngrams)


# ── FeatureRecord ───────────────────────────────────────────────────

@dataclass
class FeatureRecord:
    candidate: FillCandidate
    variant: str

    # Cheap feature (known-weak)
    new_zero_count: int
    new_zero_positions: Tuple[int, ...]

    # Augmented keystream
    slot_a_keystream: str
    slot_b_keystream: str
    full_aug_keystream: str  # length 30, in position order over the 30-char augmented crib set

    # Bean compatibility
    bean_eq_holds: bool

    # Key-equality structure
    new_equality_pairs: int
    new_equality_with_27_or_65: int

    # Local regularity
    distinct_letters: int
    max_run_length: int

    # Periodic-key consistency (smaller = more consistent)
    period_consistency_38: int
    period_consistency_3: int
    period_consistency_5: int
    period_consistency_7: int

    # English fragment likeness
    common_bigram_count: int
    common_trigram_count: int
    contains_known_keyword: str

    # Semantic coherence + description-length
    slot_a_pt: str
    slot_b_pt: str
    semantic_coherence_score: float
    fill_complexity: float


# ── Core computation ────────────────────────────────────────────────

_MODEL = canonical_w_delimiter_model()
_SLOT_A_POS: Tuple[int, ...] = _MODEL.constrained_slots[0].positions
_SLOT_B_POS: Tuple[int, ...] = _MODEL.constrained_slots[1].positions
_NEW_POSITIONS: Tuple[int, ...] = _SLOT_A_POS + _SLOT_B_POS
_ORIG_CRIB_POSITIONS: Tuple[int, ...] = tuple(sorted(CRIB_DICT.keys()))
_ALL_AUG_POSITIONS: Tuple[int, ...] = tuple(sorted(set(_ORIG_CRIB_POSITIONS) | set(_NEW_POSITIONS)))


def compute_features(candidate: FillCandidate, variant: str) -> FeatureRecord:
    if variant not in _VARIANTS:
        raise ValueError(f"unknown variant: {variant}")
    if len(candidate.slot_a_pt) != len(_SLOT_A_POS):
        raise ValueError("slot A length mismatch")
    if len(candidate.slot_b_pt) != len(_SLOT_B_POS):
        raise ValueError("slot B length mismatch")

    # Augmented PT dict
    aug: dict[int, str] = dict(CRIB_DICT)
    for i, p in enumerate(_SLOT_A_POS):
        aug[p] = candidate.slot_a_pt[i]
    for i, p in enumerate(_SLOT_B_POS):
        aug[p] = candidate.slot_b_pt[i]

    # Keystream over all 30 augmented positions
    ks: dict[int, int] = {}
    for p, pt in aug.items():
        ks[p] = _ks_value(ALPH_IDX[CT[p]], ALPH_IDX[pt], variant)

    # Feature: new_zero_count
    new_zero_positions = tuple(p for p in _NEW_POSITIONS if ks[p] == 0)
    new_zero_count = len(new_zero_positions)

    # Feature: Bean equality
    bean_eq_holds = ks[27] == ks[65]

    # Feature: new_equality_pairs and equality with k[27]/k[65]
    new_equality_pairs = 0
    new_equality_with_27_or_65 = 0
    canonical_k = ks[27]  # (same as ks[65] iff Bean eq holds; use 27 as reference)
    for p in _NEW_POSITIONS:
        kp = ks[p]
        for q in _ORIG_CRIB_POSITIONS:
            if ks[q] == kp:
                new_equality_pairs += 1
        if kp == canonical_k or kp == ks[65]:
            new_equality_with_27_or_65 += 1

    # Slot keystream strings
    slot_a_keystream = "".join(ALPH[ks[p]] for p in _SLOT_A_POS)
    slot_b_keystream = "".join(ALPH[ks[p]] for p in _SLOT_B_POS)
    full_aug_keystream = "".join(ALPH[ks[p]] for p in _ALL_AUG_POSITIONS)

    # Local regularity
    distinct_letters = len(set(full_aug_keystream))
    max_run_length = _max_run(full_aug_keystream)

    # Periodic-key consistency (disagreements at lag L)
    def _period_disagreements(lag: int) -> int:
        bad = 0
        for p in aug:
            q = p + lag
            if q in aug and ks[p] != ks[q]:
                bad += 1
        return bad

    pc38 = _period_disagreements(38)
    pc3 = _period_disagreements(3)
    pc5 = _period_disagreements(5)
    pc7 = _period_disagreements(7)

    # English fragment likeness
    common_bigram_count = _ngram_count(full_aug_keystream, _COMMON_BIGRAMS, 2)
    common_trigram_count = _ngram_count(full_aug_keystream, _COMMON_TRIGRAMS, 3)
    contains_known_keyword = _contains_keyword(full_aug_keystream)

    # Semantic + complexity
    semantic = _semantic_coherence(candidate.slot_a_pt, candidate.slot_b_pt)
    complexity = _fill_complexity(candidate.slot_a_pt) + _fill_complexity(candidate.slot_b_pt)

    return FeatureRecord(
        candidate=candidate,
        variant=variant,
        new_zero_count=new_zero_count,
        new_zero_positions=new_zero_positions,
        slot_a_keystream=slot_a_keystream,
        slot_b_keystream=slot_b_keystream,
        full_aug_keystream=full_aug_keystream,
        bean_eq_holds=bean_eq_holds,
        new_equality_pairs=new_equality_pairs,
        new_equality_with_27_or_65=new_equality_with_27_or_65,
        distinct_letters=distinct_letters,
        max_run_length=max_run_length,
        period_consistency_38=pc38,
        period_consistency_3=pc3,
        period_consistency_5=pc5,
        period_consistency_7=pc7,
        common_bigram_count=common_bigram_count,
        common_trigram_count=common_trigram_count,
        contains_known_keyword=contains_known_keyword,
        slot_a_pt=candidate.slot_a_pt,
        slot_b_pt=candidate.slot_b_pt,
        semantic_coherence_score=semantic,
        fill_complexity=complexity,
    )
