"""Candidate populations for the W-delimiter null test.

Four populations:

1. RANDOM UNIFORM       — uniform A-Z x A-Z, no English filter
2. DICTIONARY           — every ASCII 2-letter word x every ASCII 4-letter word
3. GRAMMATICAL FIT      — rule-based lists scoped to slot context
4. CURATED BEST         — strict spatial-preposition subset

Populations 3 and 4 are explicit lists so they are fully reproducible. The
source rule for each list is documented inline.
"""
from __future__ import annotations

import os
import random
import string
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class FillCandidate:
    """A (slot A fill, slot B fill) candidate under the W-delimiter model."""

    slot_a_pt: str  # 2 letters
    slot_b_pt: str  # 4 letters
    source: str     # "random" | "dictionary" | "grammatical" | "curated"


# ── Population 1: uniform random ─────────────────────────────────────

def population_random(n: int, seed: int) -> List[FillCandidate]:
    """Uniform random A-Z x A-Z. Reproducible under seed."""
    rng = random.Random(seed)
    out: List[FillCandidate] = []
    alphabet = string.ascii_uppercase
    for _ in range(n):
        a = "".join(rng.choice(alphabet) for _ in range(2))
        b = "".join(rng.choice(alphabet) for _ in range(4))
        out.append(FillCandidate(slot_a_pt=a, slot_b_pt=b, source="random"))
    return out


# ── Population 2: dictionary cartesian ───────────────────────────────

def _find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "wordlists").is_dir():
            return parent
    return here.parents[3]


def _load_words_by_len() -> tuple[list[str], list[str]]:
    root = _find_repo_root()
    wl_path = root / "wordlists" / "english.txt"
    twos: list[str] = []
    fours: list[str] = []
    if not wl_path.exists():
        return twos, fours
    ascii_upper = set(string.ascii_uppercase)
    seen2: set[str] = set()
    seen4: set[str] = set()
    with wl_path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip().upper()
            if not w or not all(c in ascii_upper for c in w):
                continue
            if len(w) == 2 and w not in seen2:
                seen2.add(w)
                twos.append(w)
            elif len(w) == 4 and w not in seen4:
                seen4.add(w)
                fours.append(w)
    twos.sort()
    fours.sort()
    return twos, fours


def population_dictionary(max_pairs: int, seed: int) -> List[FillCandidate]:
    """Cartesian of 2-letter x 4-letter English words, capped to max_pairs.

    If the full cartesian exceeds max_pairs, sample without replacement
    deterministically under seed. Uses ASCII-only A-Z entries.
    """
    twos, fours = _load_words_by_len()
    if not twos or not fours:
        return []
    full_size = len(twos) * len(fours)
    if full_size <= max_pairs:
        return [
            FillCandidate(slot_a_pt=t, slot_b_pt=f, source="dictionary")
            for t in twos
            for f in fours
        ]
    rng = random.Random(seed)
    seen: set[tuple[str, str]] = set()
    while len(seen) < max_pairs:
        t = rng.choice(twos)
        f = rng.choice(fours)
        seen.add((t, f))
    return [
        FillCandidate(slot_a_pt=t, slot_b_pt=f, source="dictionary")
        for (t, f) in sorted(seen)
    ]


# ── Population 3: grammatical fit (rule-based) ───────────────────────

# Slot A allowed lists — rule: short functional words that can follow
# a direction phrase ("EASTNORTHEAST ..."). POS classes: preposition(2),
# pronoun(2), conjunction(2), particle(2), copula(2).
GRAMMATICAL_SLOT_A: tuple[str, ...] = (
    # prepositions
    "TO", "AT", "IN", "ON", "OF", "BY", "UP",
    # copula / aux
    "IS", "AS", "AN", "BE",
    # conjunctions / particles
    "OR", "IF", "SO", "NO", "DO", "GO",
    # pronouns
    "IT", "HE", "WE", "US", "ME", "MY",
)

# Slot B allowed lists — rule: 4-letter words that can precede a
# location name ("... BERLINCLOCK"). Classes: spatial preposition,
# locational adverb, demonstrative, location-taking verb, time noun,
# structural noun.
GRAMMATICAL_SLOT_B: tuple[str, ...] = (
    # spatial prepositions
    "NEAR", "ATOP", "UPON", "OVER", "ONTO", "INTO", "PAST", "FROM",
    # locational adverbs
    "HERE", "BACK", "AWAY", "DOWN",
    # demonstratives / quantifiers
    "THIS", "THAT", "SOME", "EACH",
    # time nouns
    "TIME", "HOUR", "ZONE", "WHEN", "ONCE", "NOON",
    # location-taking verbs
    "FIND", "SEEK", "READ", "LOOK", "KEEP", "HOLD", "SHOW", "MEET", "TELL", "VIEW",
    # adjectives
    "TRUE", "REAL", "MAIN",
    # structural nouns
    "EDGE", "SIDE", "AREA", "FACE", "PART", "WALL", "GATE", "DOOR",
    # cardinal directions
    "WEST", "EAST",
)


def population_grammatical_fit() -> List[FillCandidate]:
    """Deterministic rule-based grammatical population (cartesian)."""
    out: List[FillCandidate] = []
    for a in GRAMMATICAL_SLOT_A:
        for b in GRAMMATICAL_SLOT_B:
            out.append(FillCandidate(slot_a_pt=a, slot_b_pt=b, source="grammatical"))
    return out


# ── Population 4: curated best (tightest) ────────────────────────────

# Rule: slot A must be a preposition or copula (no pronouns, no particles).
# Rule: slot B must be a spatial preposition (no verbs, no nouns, no adverbs).
# These are the words that most tightly fit "[direction] <A> W ... W <B> BERLINCLOCK".
CURATED_SLOT_A: tuple[str, ...] = ("TO", "AT", "IS", "BY")
CURATED_SLOT_B: tuple[str, ...] = ("NEAR", "ATOP", "UPON", "INTO", "PAST", "FROM")


def population_curated_best() -> List[FillCandidate]:
    """Tightest curated population. Every element MUST also be in the
    grammatical population (enforced structurally by construction)."""
    out: List[FillCandidate] = []
    for a in CURATED_SLOT_A:
        for b in CURATED_SLOT_B:
            out.append(FillCandidate(slot_a_pt=a, slot_b_pt=b, source="curated"))
    return out
