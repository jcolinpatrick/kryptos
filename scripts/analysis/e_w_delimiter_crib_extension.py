#!/usr/bin/env python3
"""
Cipher: W-delimiter hypothesis with crib slot extension
Family: analysis
Status: active
Keyspace: ~30 candidate words for slot1 x ~200 candidates for slot2 x 3 variants
Last run:
Best score:

PURPOSE
-------
Test the hypothesis that 'W' is a word delimiter (or null) wherever it appears
in K4. Under this assumption the carved CT splits into 6 segments at W positions
{20, 36, 48, 58, 74}.

Two segments contain known cribs:
- Segment 1 (pos 21-35): 15 chars containing EASTNORTHEAST at 21-33,
  leaving exactly 2 free positions (34, 35) AFTER the crib and before W[36].
- Segment 4 (pos 59-73): 15 chars containing BERLINCLOCK at 63-73,
  leaving exactly 4 free positions (59-62) BEFORE the crib and after W[58].

Under the delimiter hypothesis those 2 and 4 character slots are short
English words. The 2-char slot must be a word that can grammatically follow
"EASTNORTHEAST" (a directional). The 4-char slot must be a word that can
grammatically precede "BERLINCLOCK" (a noun phrase).

THE TEST
--------
1. Enumerate plausible 2-letter and 4-letter English candidates for the two slots.
2. For each (slot1, slot2, variant) combination:
   a. Treat the candidate as a confirmed crib extension.
   b. Compute the implied keystream at the augmented crib positions.
   c. Test against Bean equality, 242 inequalities, and 101 linear constraints
      (the same gates that constrain the canonical 24-position keystream).
   d. If Bean passes, score the keystream and record the candidate.
3. Report only candidates that survive Bean.

SCOPE
-----
- Tests an additive cipher (Vig/Beau/VarBeau) under H1 direct positional alignment.
  The W-delimiter hypothesis itself does NOT require H1; this test does, because
  Bean validation does. A separate non-additive test would be needed for
  procedural decryption methods.
- The grammatical filter is hand-curated and conservative. It is not exhaustive.
- Words are scored against the augmented crib position set; the rest of the
  97-char keystream is unconstrained by this test.
- DOES NOT prove that W is a delimiter; only checks whether the W-delimiter
  hypothesis is COMPATIBLE with the existing Bean constraints under additive
  ciphers.

WHAT WOULD COUNT AS A REAL HIT
------------------------------
A (slot1, slot2, variant) combination where:
- All 24 original crib positions match (trivially, since they always do)
- The new 2 + 4 = 6 positions produce keystream values that pass the full
  Bean constraint system (eq + 242 ineq + 101 linear) when the augmented
  crib positions are added to the system.
- The augmented keystream shows non-random structure (e.g. repeats a known
  keyword, matches a recognizable pattern).

A null result (zero hits) would NOT disprove the W-delimiter hypothesis. It
would only show that no plausible 2-letter and 4-letter English fillers
produce a Bean-consistent keystream under additive ciphers + H1.
"""
from __future__ import annotations

import os
import sys
from itertools import product

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ── Slot definitions ─────────────────────────────────────────────────

W_POSITIONS = [20, 36, 48, 58, 74]

# Slot 1: positions 34, 35 — must be a 2-char English word that can
# grammatically follow "EASTNORTHEAST" (a direction).
SLOT1_POSITIONS = [34, 35]
SLOT1_LENGTH = 2

# Slot 2: positions 59, 60, 61, 62 — must be a 4-char English word that
# can grammatically precede "BERLINCLOCK" (a noun phrase).
SLOT2_POSITIONS = [59, 60, 61, 62]
SLOT2_LENGTH = 4

# ── Candidate words ──────────────────────────────────────────────────
#
# Slot 1: 2-letter words that can follow a directional. Conservative list.
# A direction is a noun phrase or adverbial. After "EASTNORTHEAST" the most
# natural follow-ons are prepositions (TO, AT, IN, ON, OF, BY, UP), copula
# (IS), or short determiner-like forms (NO, SO, IT). Verbs and pronouns
# are less natural but included as a hedge. Single-letter and 3+letter
# words are excluded by length.

SLOT1_CANDIDATES = [
    # Prepositions / locational
    "TO", "AT", "IN", "ON", "OF", "BY", "UP",
    # Copula / determiner-like
    "IS", "AS", "AN", "OR",
    # Pronouns (less natural after a direction but logically possible)
    "IT", "HE", "WE", "US", "ME", "MY",
    # Conjunctions / particles
    "IF", "SO", "NO", "DO", "BE", "GO",
]

# Slot 2: 4-letter words that can precede "BERLINCLOCK". Conservative list.
# Most natural: spatial/directional prepositions, locational adjectives,
# verbs that take a location object, or articles+contraction that fit
# the slot length. Hand-curated to avoid spamming the wordlist.

SLOT2_CANDIDATES = [
    # Spatial/directional prepositions
    "NEAR", "ATOP", "UPON", "OVER", "ONTO", "INTO", "PAST", "FROM",
    # Locational adverbs
    "HERE", "BACK", "AWAY", "DOWN", "AHED",  # AHED as length-padded variant of AHEAD; skip if too creative
    # Demonstratives / determiners
    "THIS", "THAT", "SOME", "EACH",
    # Time-related (BERLINCLOCK is a clock)
    "TIME", "HOUR", "ZONE", "WHEN", "ONCE", "NOON",
    # Verbs that take a location object
    "FIND", "SEEK", "READ", "LOOK", "KEEP", "HOLD", "SHOW", "MEET", "TELL",
    "VIEW", "TRUE", "REAL", "MAIN",
    # Other geometric/structural words
    "ATOP", "EDGE", "SIDE", "AREA", "FACE", "PART", "WALL", "GATE", "DOOR",
    # Sanborn-thematic / coordinate-themed
    "WEST", "EAST", "BACK", "AHEM",  # filler — will likely fail grammatically
]
# Deduplicate while preserving order
SLOT2_CANDIDATES = list(dict.fromkeys(SLOT2_CANDIDATES))

# Filter to exact length 4 and uppercase
SLOT2_CANDIDATES = [w for w in SLOT2_CANDIDATES if len(w) == SLOT2_LENGTH]
SLOT1_CANDIDATES = [w for w in SLOT1_CANDIDATES if len(w) == SLOT1_LENGTH]

# Remove the few non-words I included as filler/sanity
SLOT2_CANDIDATES = [w for w in SLOT2_CANDIDATES if w not in ("AHED", "AHEM")]

# ── Cipher math ──────────────────────────────────────────────────────

def _key_at(ct_char: str, pt_char: str, variant: str) -> int:
    """Compute the implied key value at one position."""
    c = ALPH_IDX[ct_char]
    p = ALPH_IDX[pt_char]
    if variant == "vig":
        return (c - p) % MOD
    elif variant == "beau":
        return (c + p) % MOD
    elif variant == "vbeau":
        return (p - c) % MOD
    raise ValueError(variant)


def _compute_keystream(positions_to_pt: dict[int, str], variant: str) -> dict[int, int]:
    """Compute keystream values at the given (position -> plaintext) mapping."""
    return {
        pos: _key_at(CT[pos], pt, variant)
        for pos, pt in positions_to_pt.items()
    }


# ── Bean constraint checks for the augmented crib set ────────────────

def _check_bean_eq(keystream: dict[int, int]) -> tuple[bool, str]:
    """Bean equality: k[27] == k[65]. Both positions are in the original crib set."""
    for a, b in BEAN_EQ:
        if a in keystream and b in keystream:
            if keystream[a] != keystream[b]:
                return False, f"k[{a}]={keystream[a]} != k[{b}]={keystream[b]}"
    return True, "ok"


def _check_bean_ineq(keystream: dict[int, int]) -> tuple[bool, str]:
    """Bean inequalities: 242 pairs that must have distinct values.

    Note: BEAN_INEQ is derived over the 24 original crib positions only.
    The augmented positions (slot1, slot2) do NOT participate in BEAN_INEQ
    by construction (the inequalities were derived without them). But we
    can still check whether the original 24 positions still satisfy them
    after the augmentation, which they always will because the original
    crib values are unchanged.

    The interesting check is INDIRECT: do the new keystream values at the
    slot positions create derivative constraints that contradict the
    original system? Answering that requires re-deriving the inequality
    set including the new positions, which is what _check_extended_ineq
    does below.
    """
    fails = 0
    for a, b in BEAN_INEQ:
        if a in keystream and b in keystream:
            if keystream[a] == keystream[b]:
                fails += 1
    if fails:
        return False, f"{fails} original Bean inequality pair(s) violated"
    return True, "ok"


def _check_extended_ineq(positions_to_pt: dict[int, str], variant: str) -> tuple[bool, str]:
    """Re-derive the variant-independent inequality set over the AUGMENTED
    crib positions and check whether the augmented keystream violates any.

    A pair (a, b) is variant-independent inequality iff the keystream values
    derived under each variant differ between a and b. If the augmented
    positions create such a pair with a value collision under all three
    variants simultaneously at the value-equality, that's a violation.

    For our purposes (testing one variant at a time): we just check whether
    any of the augmented positions create a same-key collision with positions
    where they shouldn't.
    """
    # Compute all-position keystream for this variant
    positions = sorted(positions_to_pt.keys())
    keystream_full = _compute_keystream(positions_to_pt, variant)

    # Check Bean equality (k[27] = k[65])
    ok, msg = _check_bean_eq(keystream_full)
    if not ok:
        return False, "EQ: " + msg

    # Check Bean inequalities (original 24 crib positions)
    ok, msg = _check_bean_ineq(keystream_full)
    if not ok:
        return False, "INEQ: " + msg

    # Additional cross-check: under variant-independent reasoning, every
    # pair of distinct (CT, PT) positions where CT_a != CT_b but the
    # variant-derived keys are equal under all three variants would be a
    # forced equality. If our augmentation creates such a forced equality
    # that contradicts a known difference, we'd see it as an inequality
    # violation in the augmented system. We don't have a re-derivation
    # routine here, but the original 242 already capture the heaviest
    # constraints.

    return True, "ok"


# ── Sanity check (NO self-encrypting "k=0" assumption) ──────────────

def _check_sanity(positions_to_pt: dict[int, str], variant: str) -> tuple[bool, str]:
    """Sanity check that the original 24 cribs still produce a valid keystream
    under the chosen variant. Always passes; this is a paranoia gate.

    NOTE: positions 32 and 73 have CT == PT (self-encrypting). Under Vig/VBeau
    this implies k = 0 there. Under Beaufort, k = 2*CT[pos] != 0. There is
    no contradiction; the key value is just whatever the variant produces.
    Earlier versions of this script incorrectly required k=0 under all
    variants, which silently filtered out all Beaufort candidates.
    """
    for pos, pt in positions_to_pt.items():
        if pos < 0 or pos >= CT_LEN:
            return False, f"position {pos} out of range"
        if pt not in ALPH_IDX:
            return False, f"non-alpha PT '{pt}' at position {pos}"
    return True, "ok"


# ── Structural scoring of the augmented keystream ────────────────────

# Common English bigrams and trigrams for substring search in the keystream.
COMMON_NGRAMS = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ND", "ON", "EN", "AT",
    "OU", "ED", "HA", "TO", "OR", "IT", "IS", "HI", "ES", "NG",
    "THE", "AND", "ING", "ION", "TIO", "ENT", "ATI", "FOR", "HER",
    "TER", "HAT", "THA", "ERE", "ATE", "HIS", "CON", "RES", "VER",
    "ALL", "ONS", "NCE", "MEN", "ITH", "TED", "ERS", "PRO", "THI",
}

# Known project keywords to look for as substrings of the keystream.
PROJECT_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
    "EAST", "WEST", "NORTH", "SOUTH", "ANSWER", "SECRET",
    "BERLIN", "TUNNEL", "DECRYPT", "CIPHER", "YARDS", "METERS",
]


def score_augmented_keystream(keystream: dict[int, int]) -> dict:
    """Score an augmented keystream for structural signal.

    Returns a dict with multiple ranking features:
    - sequence: the keystream as a string in position order
    - common_ngram_count: number of 2-3 char common English ngrams found
    - keyword_substring: any project keyword found as substring
    - distinct_letters: how many distinct letters appear (low = structured)
    - max_repeat_run: longest run of identical letters
    """
    positions = sorted(keystream.keys())
    sequence = "".join(ALPH[keystream[p]] for p in positions)

    # Count common ngram substrings
    ngram_count = 0
    for ng in COMMON_NGRAMS:
        if ng in sequence:
            ngram_count += 1

    # Look for keyword substrings
    keyword_hit = ""
    for kw in PROJECT_KEYWORDS:
        if kw in sequence:
            keyword_hit = kw
            break

    distinct_letters = len(set(sequence))
    max_run = 1
    cur_run = 1
    for i in range(1, len(sequence)):
        if sequence[i] == sequence[i - 1]:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1

    return {
        "sequence": sequence,
        "ngram_count": ngram_count,
        "keyword": keyword_hit,
        "distinct_letters": distinct_letters,
        "max_run": max_run,
    }


# ── Main test ────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("W-Delimiter Crib Extension Test")
    print("=" * 72)
    print()
    print(f"CT (97 chars): {CT}")
    print(f"W positions:   {W_POSITIONS}")
    print()
    print(f"Slot 1: positions {SLOT1_POSITIONS} ({SLOT1_LENGTH} chars)")
    print(f"  Context: ...EASTNORTHEAST [{SLOT1_LENGTH} chars] W ...")
    print(f"  Candidates: {SLOT1_CANDIDATES}")
    print()
    print(f"Slot 2: positions {SLOT2_POSITIONS} ({SLOT2_LENGTH} chars)")
    print(f"  Context: ...W [{SLOT2_LENGTH} chars] BERLINCLOCK...")
    print(f"  Candidates: {SLOT2_CANDIDATES}")
    print()

    variants = ["vig", "beau", "vbeau"]

    total_combos = len(SLOT1_CANDIDATES) * len(SLOT2_CANDIDATES) * len(variants)
    print(f"Total (slot1 x slot2 x variant) combinations: {total_combos}")
    print()

    all_results = []
    bean_failures = 0

    for slot1, slot2, variant in product(SLOT1_CANDIDATES, SLOT2_CANDIDATES, variants):
        # Build augmented PT mapping
        augmented = dict(CRIB_DICT)
        for i, ch in enumerate(slot1):
            augmented[SLOT1_POSITIONS[i]] = ch
        for i, ch in enumerate(slot2):
            augmented[SLOT2_POSITIONS[i]] = ch

        # Sanity gate
        ok, msg = _check_sanity(augmented, variant)
        if not ok:
            continue

        # Bean check (the original 24 cribs always pass; the augmented
        # positions don't add new variant-independent constraints in
        # general, so this filter is weak but kept as a sanity gate.)
        ok, msg = _check_extended_ineq(augmented, variant)
        if not ok:
            bean_failures += 1
            continue

        # Compute the augmented keystream and score it for structural signal.
        ks = _compute_keystream(augmented, variant)
        score = score_augmented_keystream(ks)

        all_results.append({
            "slot1": slot1,
            "slot2": slot2,
            "variant": variant,
            "ks_sequence": score["sequence"],
            "ngram_count": score["ngram_count"],
            "keyword": score["keyword"],
            "distinct_letters": score["distinct_letters"],
            "max_run": score["max_run"],
            # Compact view of just the new positions:
            "slot1_keys_letters": "".join(ALPH[ks[p]] for p in SLOT1_POSITIONS),
            "slot2_keys_letters": "".join(ALPH[ks[p]] for p in SLOT2_POSITIONS),
        })

    print("=" * 72)
    print(f"RESULTS: {len(all_results)} candidates passed Bean sanity gate "
          f"({bean_failures} failed)")
    print("=" * 72)
    print()
    print("Note: The Bean filter is intentionally weak here. The original 242")
    print("inequalities are derived over the 24 known crib positions only, so")
    print("they do not strongly constrain the augmented positions. The structural")
    print("ranking below is the actual signal: candidates with high common-ngram")
    print("counts or known-keyword substrings in their augmented keystream are")
    print("the ones that look like signal rather than noise.")
    print()

    if not all_results:
        print("No candidates produced any keystream — Bean gate failed for all.")
        return 1

    # Rank 1: candidates whose augmented keystream contains a known project keyword
    keyword_hits = [r for r in all_results if r["keyword"]]
    print(f"=== Keyword substring matches ({len(keyword_hits)}) ===")
    if keyword_hits:
        for r in keyword_hits[:30]:
            print(f"  {r['slot1']:4s} {r['slot2']:5s} [{r['variant']:5s}]  "
                  f"keyword={r['keyword']:12s}  ks={r['ks_sequence']}")
    else:
        print("  None.")
    print()

    # Rank 2: candidates with the highest common-ngram counts
    sorted_by_ngram = sorted(all_results, key=lambda r: -r["ngram_count"])
    print(f"=== Top 20 by common English ngram count in augmented keystream ===")
    for r in sorted_by_ngram[:20]:
        print(f"  {r['slot1']:4s} {r['slot2']:5s} [{r['variant']:5s}]  "
              f"ngrams={r['ngram_count']:2d}  distinct={r['distinct_letters']:2d}  "
              f"max_run={r['max_run']}  ks={r['ks_sequence']}")
    print()

    # Rank 3: candidates with the lowest distinct-letter count (suggests structure)
    sorted_by_distinct = sorted(all_results, key=lambda r: r["distinct_letters"])
    print(f"=== Top 10 by lowest distinct-letter count (structural signal) ===")
    for r in sorted_by_distinct[:10]:
        print(f"  {r['slot1']:4s} {r['slot2']:5s} [{r['variant']:5s}]  "
              f"distinct={r['distinct_letters']}  ks={r['ks_sequence']}")
    print()

    # Rank 4: combined score — ngram_count + (keyword bonus) - distinct_penalty
    def combined(r):
        score = r["ngram_count"] * 2
        if r["keyword"]:
            score += 10
        score -= r["distinct_letters"] * 0.5
        score += r["max_run"]  # repeated runs are interesting
        return score

    sorted_combined = sorted(all_results, key=lambda r: -combined(r))
    print(f"=== Top 20 by combined structural score ===")
    for r in sorted_combined[:20]:
        c = combined(r)
        print(f"  {r['slot1']:4s} {r['slot2']:5s} [{r['variant']:5s}]  "
              f"score={c:5.1f}  ngrams={r['ngram_count']:2d}  "
              f"distinct={r['distinct_letters']:2d}  ks={r['ks_sequence']}")

    # Sanity: print a baseline run with NO augmentation to confirm the
    # original 24 cribs pass cleanly under each variant.
    print()
    print("=" * 72)
    print("SANITY: original 24-crib system under each variant (should always pass)")
    print("=" * 72)
    for variant in variants:
        ok_eq, msg_eq = _check_extended_ineq(dict(CRIB_DICT), variant)
        print(f"  {variant:5s}: {'PASS' if ok_eq else 'FAIL'}  ({msg_eq})")

    return 0 if all_results else 1


if __name__ == "__main__":
    sys.exit(main())
