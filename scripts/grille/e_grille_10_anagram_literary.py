#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-10: Is the Cardan grille extract scrambled English?

HYPOTHESIS:
  The 106-char extract is an anagram of a meaningful English message.
  No crypto — just rearranged letters, like a crossword puzzle.

TESTS:
  1. Letter frequency comparison to English (does distribution match?)
  2. Find all English words formable from available letters (respecting counts)
  3. Find the longest words possible
  4. Greedy word-packing: what's the best English message from these letters?
  5. Check against known Kryptos-relevant phrases and literary passages
  6. 97-letter subset analysis: removing 9 letters, does it get closer to English?
"""

from __future__ import annotations
import json
import sys
from collections import Counter
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_LEN = 106

LETTER_COUNTS = Counter(GRILLE_EXTRACT)

# English letter frequencies (proportion)
ENGLISH_FREQ = {
    'E': 0.1270, 'T': 0.0906, 'A': 0.0817, 'O': 0.0751, 'I': 0.0697,
    'N': 0.0675, 'S': 0.0633, 'H': 0.0609, 'R': 0.0599, 'D': 0.0425,
    'L': 0.0403, 'C': 0.0278, 'U': 0.0276, 'M': 0.0241, 'W': 0.0236,
    'F': 0.0223, 'G': 0.0202, 'Y': 0.0197, 'P': 0.0193, 'B': 0.0129,
    'V': 0.0098, 'K': 0.0077, 'J': 0.0015, 'X': 0.0015, 'Q': 0.0010,
    'Z': 0.0007,
}


# ── Load wordlist ───────────────────────────────────────────────────────────

def load_wordlist() -> list[str]:
    """Load English wordlist, return uppercase words."""
    for p in [Path("wordlists/english.txt"), Path("../wordlists/english.txt")]:
        if p.exists():
            words = [w.strip().upper() for w in p.read_text().splitlines() if w.strip()]
            return [w for w in words if w.isalpha()]
    print("WARNING: No wordlist found, using minimal built-in list")
    return []


def can_spell(word: str, available: Counter) -> bool:
    """Can we spell this word using available letter counts?"""
    for letter, count in Counter(word).items():
        if available.get(letter, 0) < count:
            return False
    return True


# ── Test 1: Frequency analysis ─────────────────────────────────────────────

def test_frequency_match():
    print("=" * 70)
    print("TEST 1: Letter frequency — Grille Extract vs English")
    print("=" * 70)
    print()

    # Expected counts for 106-char English text
    print(f"  {'Letter':>6} {'Grille':>6} {'Eng Exp':>7} {'Delta':>6} {'Assessment'}")
    print(f"  {'-'*6:>6} {'-'*6:>6} {'-'*7:>7} {'-'*6:>6} {'-'*10}")

    total_chi2 = 0
    anomalies = []

    for letter in "ETAOINSHRDLCUMWFGYPBVKJXQZ":
        actual = LETTER_COUNTS.get(letter, 0)
        expected = ENGLISH_FREQ.get(letter, 0) * GRILLE_LEN
        delta = actual - expected
        if expected > 0:
            chi2_contrib = (delta ** 2) / expected
            total_chi2 += chi2_contrib
        else:
            chi2_contrib = 0

        assessment = ""
        if abs(delta) > expected * 0.8 and expected > 1:
            assessment = "ANOMALY"
            anomalies.append((letter, actual, expected, delta))
        elif abs(delta) > expected * 0.5 and expected > 1:
            assessment = "notable"

        print(f"  {letter:>6} {actual:>6} {expected:>7.1f} {delta:>+6.1f} {assessment}")

    print(f"\n  Chi-squared: {total_chi2:.2f}")
    print(f"  (English text ~20-30; random ~80-120; cipher ~150+)")

    if anomalies:
        print(f"\n  Anomalies (>{'>'}80% deviation from expected):")
        for letter, actual, expected, delta in anomalies:
            print(f"    {letter}: have {actual}, expected {expected:.1f} ({delta:+.1f})")

    # Overall assessment
    # For 106 chars of English, IC should be ~0.065
    n = GRILLE_LEN
    ic = sum(c * (c - 1) for c in LETTER_COUNTS.values()) / (n * (n - 1))
    print(f"\n  IC: {ic:.4f} (English ~0.066, random ~0.038)")
    print(f"  IC suggests: {'closer to English than random' if ic > 0.050 else 'between random and English' if ic > 0.042 else 'close to random'}")
    print()


# ── Test 2: Find all spellable words ──────────────────────────────────────

def test_find_words(wordlist: list[str]) -> list[str]:
    print("=" * 70)
    print("TEST 2: English words spellable from grille extract letters")
    print("=" * 70)
    print()

    if not wordlist:
        print("  No wordlist available.")
        return []

    spellable = []
    for word in wordlist:
        if len(word) >= 3 and can_spell(word, LETTER_COUNTS):
            spellable.append(word)

    # Sort by length descending
    spellable.sort(key=lambda w: -len(w))

    print(f"  Total spellable words (3+ letters): {len(spellable)}")
    print(f"  Longest words:")
    for w in spellable[:50]:
        if len(w) >= 8:
            print(f"    {len(w):>2} letters: {w}")

    # Words by length distribution
    by_len = Counter(len(w) for w in spellable)
    print(f"\n  Distribution by length:")
    for length in sorted(by_len.keys(), reverse=True):
        if length >= 6:
            print(f"    {length:>2} letters: {by_len[length]} words")

    print()
    return spellable


# ── Test 3: Greedy word packing ───────────────────────────────────────────

def test_greedy_pack(spellable: list[str]):
    """Greedily pack the longest words that fit the available letters."""
    print("=" * 70)
    print("TEST 3: Greedy word packing — best English message from these letters")
    print("=" * 70)
    print()

    if not spellable:
        print("  No words available.")
        return

    # Strategy: try multiple greedy approaches
    # A) Longest-first
    remaining = Counter(LETTER_COUNTS)
    packed_a = []
    for word in sorted(spellable, key=lambda w: -len(w)):
        if can_spell(word, remaining):
            packed_a.append(word)
            remaining -= Counter(word)

    leftover_a = sum(remaining.values())
    print(f"  Strategy A (longest-first):")
    print(f"    Words: {' '.join(packed_a[:20])}")
    print(f"    Letters used: {GRILLE_LEN - leftover_a}/{GRILLE_LEN}")
    print(f"    Leftover: {''.join(sorted(remaining.elements()))}")
    print()

    # B) Prioritize Kryptos-relevant words
    kryptos_words = [
        "BERLIN", "CLOCK", "EAST", "NORTH", "SHADOW", "LIGHT", "BURIED",
        "LAYER", "CIPHER", "FIELD", "AGENCY", "LANGLEY", "KRYPTOS",
        "PALIMPSEST", "ABSCISSA", "MORSE", "VIGENERE", "ENIGMA",
        "UNDERGRUUND", "UNDERGROUND", "IQLUSION", "ILLUSION",
        "SLOWLY", "DESPERATELY", "VIRTUAL", "INVISIBLE",
        "ARCHAELOGY", "ARCHAEOLOGY", "CARTER", "HOWARD", "KING",
        "DELIVERED", "MESSAGE", "WALL", "EGYPT", "PYRAMID",
        "RUINS", "ANCIENT", "REVEAL", "HIDDEN", "MASK", "GRILLE",
        "NEEDLE", "CLUE", "GUIDE", "CIPHER", "DECODE", "PLAIN",
        "WIND", "CALM", "DARK", "DAWN", "DUSK", "EQUINOX",
    ]

    remaining_b = Counter(LETTER_COUNTS)
    packed_b = []

    # First try Kryptos words
    for word in sorted(kryptos_words, key=lambda w: -len(w)):
        word = word.upper()
        if can_spell(word, remaining_b):
            packed_b.append(word)
            remaining_b -= Counter(word)

    # Then fill with longest remaining
    for word in sorted(spellable, key=lambda w: -len(w)):
        if can_spell(word, remaining_b):
            packed_b.append(word)
            remaining_b -= Counter(word)

    leftover_b = sum(remaining_b.values())
    print(f"  Strategy B (Kryptos-relevant first):")
    print(f"    Kryptos words found: {[w for w in packed_b if w.upper() in [k.upper() for k in kryptos_words]]}")
    print(f"    All words: {' '.join(packed_b[:20])}")
    print(f"    Letters used: {GRILLE_LEN - leftover_b}/{GRILLE_LEN}")
    print(f"    Leftover: {''.join(sorted(remaining_b.elements()))}")
    print()


# ── Test 4: Kryptos-themed phrases ────────────────────────────────────────

def test_known_phrases():
    """Check if specific known phrases/quotes can be anagrammed from the extract."""
    print("=" * 70)
    print("TEST 4: Known phrases and literary references")
    print("=" * 70)
    print()

    # Phrases to test (no spaces, uppercase, only alpha)
    phrases = [
        # K1-K3 related
        ("K1 PT opening", "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHT"),
        ("K1 PT snippet", "IUSEDTHEINFORMATIONGATHERED"),
        ("K2 PT opening", "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE"),
        ("K2 IDBYROWS", "IDBYROWS"),
        ("K2 XLAYERTWO", "XLAYERTWO"),
        ("K3 PT opening", "SLOWLYDESPERATLYSLOWLY"),
        # Sanborn quotes
        ("Buried out there", "ITSBURIEDOUTTHERESOMEWHERE"),
        ("Delivering message", "DELIVERINGAMESSAGE"),
        # Berlin / Egypt themes
        ("Berlin Wall fell", "THEBERLINWALLFELL"),
        ("East North East", "EASTNORTHEAST"),
        ("Berlin Clock", "BERLINCLOCK"),
        # Howard Carter
        ("Carter at tomb", "HOWARDCARTERATTHEKINGTOMB"),
        ("Wonderful things", "CANYOUSEEANYTHINGYES WONDERFULTHINGS"),
        ("Breaking the seal", "BREAKINGTHESEAL"),
        # Scheidt / CIA
        ("Masked the English", "IMASKEDTHEENGLISHLANGUAGE"),
        ("Two separate systems", "TWOSEPARATESYSTEMS"),
        # Le Carré
        ("The Russia House", "THERUSSIAHOUSE"),
        ("A Perfect Spy", "APERFECTSPY"),
        # Equinox / Light
        ("Equinox shadow", "EQUINOXSHADOW"),
        ("Shadow and light", "SHADOWANDLIGHT"),
        # K5 related
        ("Ninety seven characters", "NINETYSEVENCHARACTERS"),
        # Generic
        ("Solve the technique", "SOLVETHETECHNIQUEFIRSTTHENTHEPUZZLE"),
        ("Who says math", "WHOSAYSITISEVENAMATH"),
    ]

    for label, phrase in phrases:
        phrase_clean = "".join(c for c in phrase.upper() if c.isalpha())

        # Can we spell it?
        phrase_counts = Counter(phrase_clean)
        missing = {}
        for letter, need in phrase_counts.items():
            have = LETTER_COUNTS.get(letter, 0)
            if have < need:
                missing[letter] = need - have

        if not missing:
            remaining = Counter(LETTER_COUNTS) - phrase_counts
            leftover = sum(remaining.values())
            leftover_str = "".join(sorted(remaining.elements()))
            print(f"  CAN SPELL: '{label}' ({len(phrase_clean)} chars)")
            print(f"    Phrase: {phrase_clean}")
            print(f"    Leftover: {leftover} chars = {leftover_str}")
            print()
        else:
            total_missing = sum(missing.values())
            if total_missing <= 3:
                print(f"  CLOSE: '{label}' — missing {missing}")


    # Also check: what 97-106 char phrases from literature could match?
    print()
    print("  Note: Phrases containing T cannot be formed (T count = 0)")
    print("  This eliminates: THE, THAT, THIS, IT, AT, TO, NOT, BUT, ...")
    print(f"  Available letters: {dict(LETTER_COUNTS.most_common())}")
    print()


# ── Test 5: T-free literary search ────────────────────────────────────────

def test_t_free_analysis():
    """What meaningful English text avoids T entirely?"""
    print("=" * 70)
    print("TEST 5: T-free English analysis")
    print("=" * 70)
    print()

    # How constraining is no-T?
    # Common words without T: AND, OF, IN, IS, FOR, ON, ARE, AS, HE, SHE,
    # HIS, HER, BY, AN, OR, WAS, HAS, HAD, FROM, HAVE, WERE, BEEN, CAN,
    # MAY, WILL, ALSO, DO, IF, NO, UP, MORE, WHEN, WHO, WHICH, ONE,
    # EACH, USE, HOW, ALL, MUCH, MAKE, LIKE, LONG, LOOK, MANY, SOME, ...
    #
    # Common words WITH T that are excluded:
    # THE, TO, THAT, THIS, IT, AT, NOT, BUT, WITH, THEY, WAS, WHAT,
    # THEIR, ABOUT, THAN, THEM, MOST, INTO, ...

    print("  NO T available — this is extremely constraining for English.")
    print("  Impossible words: THE, TO, THAT, THIS, IT, AT, NOT, BUT, WITH,")
    print("    THEY, WHAT, THEIR, ABOUT, THAN, INTO, MOST, JUST, THESE, ...")
    print()
    print("  Possible function words: AND, OF, IN, IS, FOR, ON, ARE, AS, BY,")
    print("    AN, OR, WAS, HIS, HER, FROM, HAS, HAD, HAVE, WERE, BEEN,")
    print("    CAN, MAY, WILL, ALSO, DO, IF, NO, UP, MORE, WHO, WHICH, ...")
    print()

    # Count how many of the 50 most common English words contain T
    common_50 = [
        "THE", "BE", "TO", "OF", "AND", "A", "IN", "THAT", "HAVE", "I",
        "IT", "FOR", "NOT", "ON", "WITH", "HE", "AS", "YOU", "DO", "AT",
        "THIS", "BUT", "HIS", "BY", "FROM", "THEY", "WE", "SAY", "HER", "SHE",
        "OR", "AN", "WILL", "MY", "ONE", "ALL", "WOULD", "THERE", "THEIR", "WHAT",
        "SO", "UP", "OUT", "IF", "ABOUT", "WHO", "GET", "WHICH", "GO", "ME",
    ]
    t_words = [w for w in common_50 if 'T' in w]
    no_t_words = [w for w in common_50 if 'T' not in w]
    print(f"  Of 50 most common English words: {len(t_words)} contain T, {len(no_t_words)} don't")
    print(f"  T-free common words: {', '.join(no_t_words)}")
    print()

    # Is this more like a cipher or like constrained English (lipogram)?
    print("  A 106-char T-free English message is called a LIPOGRAM.")
    print("  Famous example: Ernest Vincent Wright's 'Gadsby' (50K words, no E).")
    print("  A deliberate T-avoidance lipogram IS possible for a skilled writer.")
    print("  Sanborn is an artist who works with language — lipogram is plausible.")
    print()

    # Check IC excluding T (already done in extract since T=0)
    # For English lipogram without T, the remaining letters would be
    # redistributed, raising some frequencies
    print("  If this IS a T-free lipogram:")
    print("    - IC should be above random (we have 0.0408 — slightly above 0.0385)")
    print("    - E should be the most common letter")
    print()
    print(f"  Actual most common: {LETTER_COUNTS.most_common(5)}")
    print(f"  I=10 is most common (not E=4). This is unusual for English.")
    print(f"  High I, X, K, Z counts suggest this is NOT standard English.")
    print()


# ── Test 6: 97-of-106 subset optimization ────────────────────────────────

def test_97_subset():
    """If 97 of 106 chars form the message, which 9 to remove to best match English?"""
    print("=" * 70)
    print("TEST 6: Optimal 97-letter subset (remove 9 to match English)")
    print("=" * 70)
    print()

    # Which letters are most "over-represented" vs English expectations for 97 chars?
    print("  Over-represented letters (candidates for removal):")
    overrep = []
    for letter, count in LETTER_COUNTS.most_common():
        expected_97 = ENGLISH_FREQ.get(letter, 0) * 97
        excess = count - expected_97
        if excess > 1:
            overrep.append((letter, count, expected_97, excess))
            print(f"    {letter}: have {count}, expected {expected_97:.1f} for 97-char English, excess {excess:.1f}")

    print()

    # Best 9 to remove: take from most over-represented
    to_remove = Counter()
    budget = 9
    for letter, count, expected, excess in sorted(overrep, key=lambda x: -x[3]):
        can_remove = min(int(excess), budget, count - max(1, int(expected)))
        if can_remove > 0:
            to_remove[letter] = can_remove
            budget -= can_remove
        if budget <= 0:
            break

    # If budget remains, remove from least common in English
    if budget > 0:
        for letter in "ZQXJK":
            if LETTER_COUNTS.get(letter, 0) > 0 and budget > 0:
                can_remove = min(budget, LETTER_COUNTS[letter] - to_remove.get(letter, 0))
                if can_remove > 0:
                    to_remove[letter] += can_remove
                    budget -= can_remove

    print(f"  Suggested removals: {dict(to_remove)} (total: {sum(to_remove.values())})")

    subset_counts = Counter(LETTER_COUNTS) - to_remove
    subset_len = sum(subset_counts.values())
    print(f"  Remaining: {subset_len} letters")

    # Recompute chi-squared for subset
    chi2 = 0
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        actual = subset_counts.get(letter, 0)
        expected = ENGLISH_FREQ.get(letter, 0) * subset_len
        if expected > 0:
            chi2 += (actual - expected) ** 2 / expected
    print(f"  Chi-squared after removal: {chi2:.2f} (original: see Test 1)")
    print()


# ── Test 7: Wordlist-based long word search (T-free) ─────────────────────

def test_long_t_free_words(wordlist: list[str]):
    """Find longest T-free words spellable from the extract."""
    print("=" * 70)
    print("TEST 7: Longest T-free English words from grille letters")
    print("=" * 70)
    print()

    if not wordlist:
        print("  No wordlist available.")
        return

    # Filter to T-free words, then check spellability
    t_free_spellable = []
    for word in wordlist:
        if 'T' in word:
            continue
        if len(word) >= 5 and can_spell(word, LETTER_COUNTS):
            t_free_spellable.append(word)

    t_free_spellable.sort(key=lambda w: -len(w))

    print(f"  Total T-free spellable words (5+ letters): {len(t_free_spellable)}")
    print(f"\n  Longest T-free words:")
    for w in t_free_spellable[:40]:
        if len(w) >= 8:
            print(f"    {len(w):>2}: {w}")

    # Kryptos-relevant T-free words?
    kryptos_relevant = []
    kw = ["CIPHER", "SHADOW", "BURIED", "HIDDEN", "REVEAL", "GRILLE",
          "PUZZLE", "CLUE", "KEY", "LOCK", "WALL", "MASK", "VEIL",
          "DAWN", "DUSK", "EQUINOX", "BERLIN", "CAIRO", "AGENCY",
          "SPY", "CIPHER", "CODE", "PLAIN", "DARK", "INVISIBLE",
          "UNDERGROUND", "DELIVER", "MESSAGE", "WIND", "CALM",
          "RUIN", "ANCIENT", "CRAWL", "DIG", "FIND", "SEEK",
          "GUIDE", "FOLLOW", "RIDDLE", "ENIGMA", "SKILL",
          "KING", "RIUM", "COLUMNAR", "ROW", "COLUMN"]
    for word in kw:
        word = word.upper()
        if 'T' not in word and can_spell(word, LETTER_COUNTS):
            kryptos_relevant.append(word)

    if kryptos_relevant:
        print(f"\n  Kryptos-relevant T-free words spellable:")
        for w in kryptos_relevant:
            print(f"    {w}")
    print()


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print()
    print("#" * 70)
    print("#  E-GRILLE-10: Is the grille extract scrambled English?")
    print("#" * 70)
    print()
    print(f"  Extract: {GRILLE_EXTRACT}")
    print(f"  Length: {GRILLE_LEN}")
    print(f"  Letter counts: {dict(LETTER_COUNTS.most_common())}")
    print(f"  Missing: T")
    print()

    wordlist = load_wordlist()
    print(f"  Wordlist: {len(wordlist)} words loaded")
    print()

    test_frequency_match()
    spellable = test_find_words(wordlist)
    test_greedy_pack(spellable)
    test_known_phrases()
    test_t_free_analysis()
    test_97_subset()
    test_long_t_free_words(wordlist)

    print("=" * 70)
    print("FINAL ASSESSMENT")
    print("=" * 70)
    print()
    print("  Key indicators for 'scrambled English' hypothesis:")
    print(f"    IC = {sum(c*(c-1) for c in LETTER_COUNTS.values()) / (GRILLE_LEN*(GRILLE_LEN-1)):.4f}")
    print(f"    (English ~0.066, random ~0.038, this extract ~0.041)")
    print(f"    T = 0 (extremely unusual for English, unless deliberate lipogram)")
    print(f"    I = 10 (most common letter — English expects E)")
    print(f"    X = 7, Z = 5, K = 5 (high counts for rare English letters)")
    print()


if __name__ == "__main__":
    main()
