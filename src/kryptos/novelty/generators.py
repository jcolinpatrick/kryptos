"""Hypothesis generators — produce candidate hypotheses for testing.

Generators are structured, not random. Each generator targets specific
research questions and produces hypotheses with metadata.

Generator categories:
1. Transform recombination (compose existing transforms in new ways)
2. Running key from known texts (Carter, Sanborn writings)
3. Artifact-driven (clock readings, coordinates, dates)
4. Geometric (reading orders, grid shapes)
5. Procedural (manual cipher operations Sanborn could have done)
6. Keystream analysis (patterns in known keystream)
7. K3 method variants (modifications of the known K3 method)
8. Non-standard alphabets (IJ merge, etc.)
9. "The point" hypotheses (interpretations of Sanborn's clue)
"""
from __future__ import annotations

import itertools
from pathlib import Path
from typing import Iterator, List, Optional

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.text import sanitize
from kryptos.novelty.hypothesis import (
    Hypothesis, HypothesisStatus, ResearchQuestion,
)


# ── Running key generators ──────────────────────────────────────────────

def running_key_from_text(
    source_path: str,
    source_name: str,
    max_offsets: int = 0,
) -> Iterator[Hypothesis]:
    """Generate running-key hypotheses from a text file.

    Tests the source text at every possible offset as a Vigenere/Beaufort
    running key against K4.

    Args:
        source_path: Path to the source text file
        source_name: Human-readable name (e.g., "Carter Vol 1")
        max_offsets: Max offsets to test (0 = all)
    """
    try:
        raw = Path(source_path).read_text(errors="replace")
    except FileNotFoundError:
        return

    clean = sanitize(raw)
    if len(clean) < CT_LEN:
        return

    n_offsets = len(clean) - CT_LEN + 1
    if max_offsets > 0:
        n_offsets = min(n_offsets, max_offsets)

    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        yield Hypothesis(
            description=(
                f"Running key from '{source_name}' as {variant} key "
                f"({n_offsets} offsets)"
            ),
            transform_stack=[
                {
                    "type": variant,
                    "params": {
                        "key_source": "running_key",
                        "source_path": source_path,
                        "source_name": source_name,
                        "n_offsets": n_offsets,
                    },
                }
            ],
            research_questions=[
                ResearchQuestion.RQ2_KEY_SOURCE,
                ResearchQuestion.RQ1_CIPHER_TYPE,
            ],
            assumptions=[
                f"K4 uses a running key from '{source_name}'",
                f"The cipher is {variant}",
                "No transposition layer",
            ],
            provenance=f"Running key hypothesis: Sanborn associated with {source_name}",
            expected_signatures={
                "crib_score_threshold": 18,
                "bean_pass": True,
            },
            triage_tests=[
                {"test": "sample_offsets", "n": 100, "threshold": 8},
            ],
            estimated_configs=n_offsets,
            estimated_seconds=n_offsets * 0.001,
            tags=["running_key", source_name.lower().replace(" ", "_")],
        )


# ── Date-derived key generators ─────────────────────────────────────────

def date_derived_keys() -> Iterator[Hypothesis]:
    """Generate hypotheses using historically significant dates as keys.

    Sanborn clues: 1986 Egypt trip, 1989 Berlin Wall fall.
    """
    dates = [
        ("1986", "Egypt trip year", [1, 9, 8, 6]),
        ("1989", "Berlin Wall year", [1, 9, 8, 9]),
        ("11091989", "Berlin Wall fall date", [1, 1, 0, 9, 1, 9, 8, 9]),
        ("09111989", "Berlin Wall fall US format", [0, 9, 1, 1, 1, 9, 8, 9]),
        ("19861989", "Egypt-Berlin combined", [1, 9, 8, 6, 1, 9, 8, 9]),
        ("19891986", "Berlin-Egypt combined", [1, 9, 8, 9, 1, 9, 8, 6]),
        ("3817N7709W", "CIA HQ coordinates",
         [3, 8, 1, 7, 13, 7, 7, 0, 9, 22]),
        ("385709N0770706W", "Precise coords",
         [3, 8, 5, 7, 0, 9, 13, 0, 7, 7, 0, 7, 0, 6, 22]),
        # Nov 4 1922 — Carter discovers Tutankhamun's tomb
        ("11041922", "Carter tomb discovery date", [1, 1, 0, 4, 1, 9, 2, 2]),
        ("04111922", "Carter tomb EU format", [0, 4, 1, 1, 1, 9, 2, 2]),
        # Feb 16 1923 — burial chamber opened
        ("02161923", "Burial chamber opened", [0, 2, 1, 6, 1, 9, 2, 3]),
        # 1990 — Kryptos installation year
        ("1990", "Kryptos installation year", [1, 9, 9, 0]),
        ("11031990", "Kryptos dedication Nov 3 1990", [1, 1, 0, 3, 1, 9, 9, 0]),
    ]

    for date_str, desc, key_vals in dates:
        for variant in ["vigenere", "beaufort", "var_beaufort"]:
            yield Hypothesis(
                description=f"Date-derived key '{date_str}' ({desc}) as {variant}",
                transform_stack=[
                    {"type": variant, "params": {"key": key_vals, "source": desc}},
                ],
                research_questions=[
                    ResearchQuestion.RQ5_EGYPT_BERLIN,
                    ResearchQuestion.RQ2_KEY_SOURCE,
                ],
                assumptions=[
                    f"Key derived from date: {desc}",
                    f"Cipher is {variant}",
                ],
                provenance=f"Sanborn 2025: two events in solution — {desc}",
                estimated_configs=1,
                estimated_seconds=0.01,
                tags=["date_key", "artifact_driven"],
            )


# ── Transform recombination generators ──────────────────────────────────

def transform_recombination() -> Iterator[Hypothesis]:
    """Generate hypotheses by composing transforms in new ways.

    Tests orderings and combinations that haven't been tried:
    - Transposition then substitution (standard)
    - Substitution then transposition (reversed)
    - Double transposition
    - Substitution with different alphabets per segment
    """
    trans_types = [
        ("columnar", {"widths": [7, 8, 9, 10, 11, 13, 14]}),
        ("rail_fence", {"depths": [3, 4, 5, 6, 7, 8, 9]}),
        ("serpentine", {"grids": [(7, 14), (8, 13), (9, 11), (10, 10)]}),
    ]

    for trans_name, trans_params in trans_types:
        for variant in ["vigenere", "beaufort"]:
            # Standard order: undo transposition, then test substitution
            yield Hypothesis(
                description=f"Undo {trans_name} then test {variant} substitution",
                transform_stack=[
                    {"type": "transposition_full", "params": {"family": trans_name, **trans_params}},
                    {"type": variant, "params": {"direction": "recover_key"}},
                ],
                research_questions=[
                    ResearchQuestion.RQ3_TRANSPOSITION,
                    ResearchQuestion.RQ1_CIPHER_TYPE,
                ],
                assumptions=[
                    f"K4 uses {trans_name} transposition",
                    f"Followed by {variant} substitution",
                ],
                provenance="Transform recombination: standard cipher layering",
                estimated_configs=sum(len(v) if isinstance(v, list) else 1
                                     for v in trans_params.values()) * 26,
                estimated_seconds=5.0,
                tags=["recombination", trans_name, variant],
            )


# ── Pre-ENE segment generators ──────────────────────────────────────────

def pre_ene_segment_hypotheses() -> Iterator[Hypothesis]:
    """Generate hypotheses specifically for positions 0-20.

    The pre-ENE segment has IC=0.0667 (English-like), suggesting
    it might be differently encoded.
    """
    yield Hypothesis(
        description="Pre-ENE (pos 0-20) is simple Caesar shift",
        transform_stack=[
            {"type": "caesar", "params": {"shifts": list(range(26)), "positions": "0-20"}},
        ],
        research_questions=[ResearchQuestion.RQ7_PRE_ENE],
        assumptions=["First 21 chars use a different, simpler cipher"],
        provenance="IC=0.0667 at positions 0-20 suggests English-like distribution",
        estimated_configs=26,
        estimated_seconds=0.1,
        tags=["pre_ene", "caesar"],
    )

    yield Hypothesis(
        description="Pre-ENE (pos 0-20) is plaintext with null cipher",
        transform_stack=[
            {"type": "identity", "params": {"positions": "0-20"}},
        ],
        research_questions=[ResearchQuestion.RQ7_PRE_ENE],
        assumptions=["First 21 chars are unencrypted"],
        provenance="IC=0.0667 at positions 0-20 is exactly English IC",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["pre_ene", "null"],
    )

    yield Hypothesis(
        description="Pre-ENE (pos 0-20) is Atbash cipher",
        transform_stack=[
            {"type": "atbash", "params": {"positions": "0-20"}},
        ],
        research_questions=[ResearchQuestion.RQ7_PRE_ENE],
        assumptions=["First 21 chars use simple reciprocal cipher"],
        provenance="Atbash preserves IC; position 0-20 IC is English-like",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["pre_ene", "atbash"],
    )

    yield Hypothesis(
        description="Pre-ENE uses different Vigenere key period than rest",
        transform_stack=[
            {"type": "vigenere", "params": {
                "positions": "0-20",
                "key_periods": list(range(1, 11)),
            }},
        ],
        research_questions=[ResearchQuestion.RQ7_PRE_ENE, ResearchQuestion.RQ1_CIPHER_TYPE],
        assumptions=["First 21 chars use periodic Vigenere with short key"],
        provenance="IC=0.0667 is consistent with period-1 (Caesar) or very short period Vigenere",
        estimated_configs=26 * 10,
        estimated_seconds=1.0,
        tags=["pre_ene", "vigenere_segment"],
    )


# ── Artifact-driven generators ──────────────────────────────────────────

def artifact_driven_hypotheses() -> Iterator[Hypothesis]:
    """Generate hypotheses from physical sculpture features.

    Tests parameters derived from the Kryptos sculpture itself:
    compass, lodestone, quartz, coordinates, Morse code panel, etc.
    """
    compass_bearings = [
        ("N", 0), ("NE", 45), ("E", 90), ("SE", 135),
        ("S", 180), ("SW", 225), ("W", 270), ("NW", 315),
    ]

    for name, bearing in compass_bearings:
        key_val = bearing % 26
        yield Hypothesis(
            description=f"Compass bearing {name} ({bearing}) as additive mask offset",
            transform_stack=[
                {"type": "additive_mask", "params": {"offset": key_val, "source": f"compass_{name}"}},
            ],
            research_questions=[ResearchQuestion.RQ10_PHYSICAL, ResearchQuestion.RQ4_THE_POINT],
            assumptions=[f"The compass bearing {name} provides a key parameter"],
            provenance="Sculpture includes a compass — 'What's the point?' may refer to compass point",
            estimated_configs=1,
            estimated_seconds=0.01,
            tags=["artifact", "compass"],
        )

    # Morse code values from the sculpture
    morse_fragments = [
        "VIRTUALLYINVISIBLE",
        "DIGETAL",
        "IQLUSION",
        "SHADOWFORCES",
        "LUCID",
        "DESPARATLY",
    ]

    for fragment in morse_fragments:
        yield Hypothesis(
            description=f"Morse fragment '{fragment}' as key seed",
            transform_stack=[
                {"type": "vigenere", "params": {"key_source": "morse_fragment", "fragment": fragment}},
            ],
            research_questions=[ResearchQuestion.RQ10_PHYSICAL, ResearchQuestion.RQ2_KEY_SOURCE],
            assumptions=[f"Morse fragment '{fragment}' is used to derive the key"],
            provenance="Kryptos sculpture contains Morse code panels with misspellings",
            estimated_configs=3,  # 3 cipher variants
            estimated_seconds=0.03,
            tags=["artifact", "morse"],
        )


# ── "The Point" hypotheses (RQ-4) ───────────────────────────────────────

def the_point_hypotheses() -> Iterator[Hypothesis]:
    """Generate hypotheses about 'What's the point?'

    Sanborn's deliberate clue. Multiple interpretations to test.
    """
    # A: Compass point → specific position or bearing as key
    yield Hypothesis(
        description="'The point' = compass EAST → EASTNORTHEAST direction as key seed",
        transform_stack=[
            {"type": "vigenere", "params": {
                "key": [4, 0, 18, 19],  # E=4, A=0, S=18, T=19
                "source": "compass_east",
            }},
        ],
        research_questions=[ResearchQuestion.RQ4_THE_POINT, ResearchQuestion.RQ2_KEY_SOURCE],
        assumptions=["'The point' = compass point, specifically EAST (matching ENE crib)"],
        provenance="Sanborn 2025: 'What's the point?' + ENE crib = compass direction",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["the_point", "compass"],
    )

    # B: Decimal point → number interpretation change
    yield Hypothesis(
        description="'The point' = decimal point: coordinates as fractional key values",
        transform_stack=[
            {"type": "vigenere", "params": {
                "key": [3, 8, 9, 5, 1, 7],  # 38.9517 → digits
                "source": "lat_decimal",
            }},
        ],
        research_questions=[ResearchQuestion.RQ4_THE_POINT, ResearchQuestion.RQ10_PHYSICAL],
        assumptions=["'The point' = decimal point in coordinate system"],
        provenance="Sanborn 2025: 'What's the point?' — decimal point in latitude",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["the_point", "decimal"],
    )

    # C: A specific position in the ciphertext
    for pos in [0, 20, 21, 32, 33, 48, 62, 63, 73, 96]:
        yield Hypothesis(
            description=f"'The point' = CT position {pos} ('{CT[pos]}') as key pivot",
            transform_stack=[
                {"type": "pivot_key", "params": {
                    "pivot_pos": pos,
                    "pivot_char": CT[pos],
                }},
            ],
            research_questions=[ResearchQuestion.RQ4_THE_POINT],
            assumptions=[f"Position {pos} in CT is 'the point' — a structural pivot"],
            provenance=f"Sanborn 2025: 'What's the point?' — testing position {pos}",
            estimated_configs=1,
            estimated_seconds=0.01,
            tags=["the_point", "position"],
        )

    # D: Period/full stop as punctuation in plaintext
    yield Hypothesis(
        description="'The point' = period (.) in plaintext changes reading/key",
        transform_stack=[
            {"type": "punctuation_key_change", "params": {
                "trigger": "period",
            }},
        ],
        research_questions=[ResearchQuestion.RQ4_THE_POINT, ResearchQuestion.RQ1_CIPHER_TYPE],
        assumptions=["The plaintext contains periods that control key changes"],
        provenance="Sanborn: 'What's the point?' — literal punctuation mark",
        estimated_configs=1,
        estimated_seconds=0.1,
        tags=["the_point", "punctuation"],
    )

    # E: "The point" = the word POINT in the plaintext
    yield Hypothesis(
        description="'The point' = word POINT appears in K4 plaintext as structural marker",
        transform_stack=[
            {"type": "word_search", "params": {"target_word": "POINT"}},
        ],
        research_questions=[ResearchQuestion.RQ4_THE_POINT],
        assumptions=["POINT appears in the plaintext at a structurally significant position"],
        provenance="Sanborn 2025: 'What's the point?' — self-referential",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["the_point", "word_search"],
    )


# ── K3 method variant generators (RQ-8) ─────────────────────────────────

def k3_method_variants() -> Iterator[Hypothesis]:
    """Generate hypotheses based on modifications to the known K3 method.

    K3 was: double-length key Vigenere + columnar transposition.
    The 'change in methodology' must be something specific.
    """
    # K3 used KRYPTOS-keyed alphabet for Vigenere + columnar trans
    # What if K4 modifies ONE aspect?

    yield Hypothesis(
        description="K3 method with Beaufort instead of Vigenere",
        transform_stack=[
            {"type": "columnar_beaufort", "params": {
                "widths": [7, 8, 9, 10, 11, 13, 14, 97],
                "alphabet": "KRYPTOS-keyed",
            }},
        ],
        research_questions=[ResearchQuestion.RQ8_K3_CHANGE, ResearchQuestion.RQ1_CIPHER_TYPE],
        assumptions=["K4 uses the same structure as K3 but with Beaufort substitution"],
        provenance="Scheidt: intentional 'change in methodology' — could be substitution type",
        estimated_configs=500,
        estimated_seconds=5.0,
        tags=["k3_variant", "beaufort"],
    )

    yield Hypothesis(
        description="K3 method with non-periodic key (running key) instead of repeated keyword",
        transform_stack=[
            {"type": "columnar_running_key", "params": {
                "widths": [7, 8, 9, 10, 11, 13, 14],
                "key_source": "unknown",
            }},
        ],
        research_questions=[ResearchQuestion.RQ8_K3_CHANGE, ResearchQuestion.RQ2_KEY_SOURCE],
        assumptions=["K4 uses K3 structure but key is a running key instead of repeated keyword"],
        provenance="Scheidt: 'change in methodology' — key generation change",
        estimated_configs=700,
        estimated_seconds=7.0,
        tags=["k3_variant", "running_key"],
    )

    yield Hypothesis(
        description="K3 method with reversed operations: Vigenere first, then transposition",
        transform_stack=[
            {"type": "vigenere_then_columnar", "params": {
                "widths": [7, 8, 9, 10, 11, 13, 14],
                "key_periods": list(range(3, 15)),
            }},
        ],
        research_questions=[ResearchQuestion.RQ8_K3_CHANGE, ResearchQuestion.RQ3_TRANSPOSITION],
        assumptions=["K4 reverses K3 layer order: substitute first, then transpose"],
        provenance="Scheidt: 'change in methodology' — operation order reversal",
        estimated_configs=1000,
        estimated_seconds=10.0,
        tags=["k3_variant", "reversed_order"],
    )

    yield Hypothesis(
        description="K3 method with double transposition instead of single",
        transform_stack=[
            {"type": "double_columnar", "params": {
                "widths_1": [7, 8, 9, 10, 11],
                "widths_2": [7, 8, 9, 10, 11],
            }},
        ],
        research_questions=[ResearchQuestion.RQ8_K3_CHANGE, ResearchQuestion.RQ3_TRANSPOSITION],
        assumptions=["K4 adds a second transposition layer to the K3 structure"],
        provenance="Scheidt: 'change in methodology' — added transposition layer",
        estimated_configs=2500,
        estimated_seconds=25.0,
        tags=["k3_variant", "double_trans"],
    )

    yield Hypothesis(
        description="K3 method with Quagmire III cipher instead of standard Vigenere",
        transform_stack=[
            {"type": "quagmire_iii", "params": {
                "pt_alphabet": "KRYPTOS-keyed",
                "ct_alphabet": "KRYPTOS-keyed",
                "key_periods": list(range(3, 15)),
            }},
        ],
        research_questions=[
            ResearchQuestion.RQ8_K3_CHANGE,
            ResearchQuestion.RQ1_CIPHER_TYPE,
            ResearchQuestion.RQ12_NONSTANDARD_ALPHABET,
        ],
        assumptions=["K4 uses Quagmire III (both alphabets keyed) instead of standard Vigenere"],
        provenance="Scheidt was a CIA cipher expert; Quagmire is a natural escalation from Vigenere",
        estimated_configs=500,
        estimated_seconds=5.0,
        tags=["k3_variant", "quagmire"],
    )


# ── Keystream pattern analysis (RQ-11) ──────────────────────────────────

def keystream_pattern_hypotheses() -> Iterator[Hypothesis]:
    """Generate hypotheses about patterns in the known keystream.

    Known Vigenere keystream at crib positions:
    ENE (21-33): (1,11,25,2,3,2,24,24,6,2,10,0,25)
    BC  (63-73): (12,20,24,10,11,6,10,14,17,13,0)
    Bean equality: k[27]=k[65]=24=Y
    """
    # A: Keystream as positions in KRYPTOS-keyed alphabet
    yield Hypothesis(
        description="Keystream values index into KRYPTOS-keyed alphabet",
        transform_stack=[
            {"type": "keyed_alphabet_lookup", "params": {
                "alphabet": KRYPTOS_ALPHABET,
                "known_key_ene": list(VIGENERE_KEY_ENE),
                "known_key_bc": list(VIGENERE_KEY_BC),
            }},
        ],
        research_questions=[ResearchQuestion.RQ11_KEYSTREAM, ResearchQuestion.RQ2_KEY_SOURCE],
        assumptions=["Key values are positions in the KRYPTOS-keyed alphabet, not standard A-Z"],
        provenance="Kryptos uses keyed alphabets for K1-K3; key might be in keyed alphabet space",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["keystream", "alphabet_mapping"],
    )

    # B: Difference sequence analysis
    yield Hypothesis(
        description="Keystream differences form a recognizable pattern",
        transform_stack=[
            {"type": "difference_analysis", "params": {
                "known_key_ene": list(VIGENERE_KEY_ENE),
                "known_key_bc": list(VIGENERE_KEY_BC),
            }},
        ],
        research_questions=[ResearchQuestion.RQ11_KEYSTREAM],
        assumptions=["The first differences of the keystream have structure"],
        provenance="Difference sequences can reveal running key or recurrence patterns",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["keystream", "differences"],
    )

    # C: Keystream mod smaller moduli
    for mod in [5, 7, 9, 10, 13]:
        yield Hypothesis(
            description=f"Keystream values mod {mod} reveal period or structure",
            transform_stack=[
                {"type": "modular_analysis", "params": {
                    "modulus": mod,
                    "known_key_ene": list(VIGENERE_KEY_ENE),
                    "known_key_bc": list(VIGENERE_KEY_BC),
                }},
            ],
            research_questions=[ResearchQuestion.RQ11_KEYSTREAM],
            assumptions=[f"Key generation uses mod-{mod} arithmetic underneath mod-26"],
            provenance="Multi-modulus analysis can detect composite key generation",
            estimated_configs=1,
            estimated_seconds=0.01,
            tags=["keystream", f"mod{mod}"],
        )

    # D: Key as running key from K1-K3 plaintext
    k1_pt = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    k2_pt = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
    k3_pt = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    for name, text in [("K1 plaintext", k1_pt), ("K2 plaintext", k2_pt), ("K3 plaintext", k3_pt)]:
        if len(text) >= CT_LEN:
            yield Hypothesis(
                description=f"Running key from {name}",
                transform_stack=[
                    {"type": "vigenere", "params": {
                        "key_source": "running_key_inline",
                        "source_text": text[:CT_LEN],
                        "source_name": name,
                    }},
                ],
                research_questions=[ResearchQuestion.RQ11_KEYSTREAM, ResearchQuestion.RQ2_KEY_SOURCE],
                assumptions=[f"K4 key is derived from {name}"],
                provenance=f"Self-referential: K4 key derived from earlier Kryptos section",
                estimated_configs=len(text) - CT_LEN + 1,
                estimated_seconds=0.1,
                tags=["keystream", "self_referential"],
            )


# ── Delivering a message hypotheses (RQ-6) ──────────────────────────────

def delivering_message_hypotheses() -> Iterator[Hypothesis]:
    """Hypotheses about 'delivering a message' as cipher method clue.

    Sanborn says codes are about 'delivering a message' — this may
    describe the encryption procedure itself, not just the plaintext.
    """
    yield Hypothesis(
        description="Cipher simulates message routing: different keys per 'hop'",
        transform_stack=[
            {"type": "segmented_cipher", "params": {
                "segments": [(0, 20), (21, 33), (34, 62), (63, 73), (74, 96)],
                "description": "Each segment uses a different key as if re-encrypted at each relay",
            }},
        ],
        research_questions=[ResearchQuestion.RQ6_DELIVERING_MESSAGE, ResearchQuestion.RQ1_CIPHER_TYPE],
        assumptions=[
            "The ciphertext was encrypted in segments with different keys",
            "This models message relay/forwarding in intelligence tradecraft",
        ],
        provenance="Sanborn 2025: codes are about 'delivering a message' — routing metaphor",
        estimated_configs=100,
        estimated_seconds=1.0,
        tags=["delivering_message", "segmented"],
    )

    yield Hypothesis(
        description="Message delivery = one-time pad fragment with structured source",
        transform_stack=[
            {"type": "otp_structured", "params": {
                "description": "OTP-like but key from a structured (non-random) source",
            }},
        ],
        research_questions=[ResearchQuestion.RQ6_DELIVERING_MESSAGE, ResearchQuestion.RQ2_KEY_SOURCE],
        assumptions=["Cipher is essentially an OTP where the pad is a known text"],
        provenance="Intelligence message delivery often uses OTP — K4 may simulate this",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["delivering_message", "otp"],
    )

    yield Hypothesis(
        description="Plaintext includes routing/addressing header in positions 0-20",
        transform_stack=[
            {"type": "header_analysis", "params": {
                "header_positions": "0-20",
                "expected_format": "addressee_routing",
            }},
        ],
        research_questions=[
            ResearchQuestion.RQ6_DELIVERING_MESSAGE,
            ResearchQuestion.RQ7_PRE_ENE,
        ],
        assumptions=["Positions 0-20 contain a message header (TO/FROM/DATE format)"],
        provenance="Pre-ENE IC=0.0667 + 'delivering a message' = message format header",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["delivering_message", "header"],
    )


# ── Non-standard alphabet hypotheses (RQ-12) ────────────────────────────

def nonstandard_alphabet_hypotheses() -> Iterator[Hypothesis]:
    """Test non-standard alphabets: IJ merge, Polybius square variants, etc."""
    # IJ merge → 25-letter alphabet
    yield Hypothesis(
        description="Vigenere with IJ-merged 25-letter alphabet",
        transform_stack=[
            {"type": "vigenere_ij_merge", "params": {
                "alphabet_size": 25,
                "merge": "IJ",
            }},
        ],
        research_questions=[ResearchQuestion.RQ12_NONSTANDARD_ALPHABET, ResearchQuestion.RQ1_CIPHER_TYPE],
        assumptions=["K4 uses a 25-letter alphabet with I=J"],
        provenance="Classical ciphers often use 25-letter alphabets; K4 may do the same",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["alphabet", "ij_merge"],
    )

    # Polybius 5x5 grid as substitution
    yield Hypothesis(
        description="Bifid cipher with KRYPTOS-keyed 5x5 Polybius square",
        transform_stack=[
            {"type": "bifid", "params": {
                "alphabet": KRYPTOS_ALPHABET,
                "grid_size": 5,
                "period_range": list(range(3, 20)),
            }},
        ],
        research_questions=[
            ResearchQuestion.RQ12_NONSTANDARD_ALPHABET,
            ResearchQuestion.RQ1_CIPHER_TYPE,
        ],
        assumptions=["K4 uses bifid cipher with KRYPTOS-keyed Polybius square"],
        provenance="Fractionation ciphers produce very low IC (matching K4's 0.0361)",
        estimated_configs=17,
        estimated_seconds=1.0,
        tags=["alphabet", "bifid", "polybius"],
    )

    yield Hypothesis(
        description="Trifid cipher with 27-symbol alphabet (A-Z + null)",
        transform_stack=[
            {"type": "trifid", "params": {
                "alphabet_size": 27,
                "period_range": list(range(3, 15)),
            }},
        ],
        research_questions=[
            ResearchQuestion.RQ12_NONSTANDARD_ALPHABET,
            ResearchQuestion.RQ1_CIPHER_TYPE,
        ],
        assumptions=["K4 uses trifid cipher with 3x3x3 grid"],
        provenance="Trifid produces very low IC; Delastelle cipher family",
        estimated_configs=12,
        estimated_seconds=1.0,
        tags=["alphabet", "trifid"],
    )

    # Reversed KRYPTOS alphabet
    yield Hypothesis(
        description="Vigenere with REVERSED Kryptos-keyed alphabet",
        transform_stack=[
            {"type": "vigenere", "params": {
                "key": list(range(26)),
                "alphabet": KRYPTOS_ALPHABET[::-1],
            }},
        ],
        research_questions=[ResearchQuestion.RQ12_NONSTANDARD_ALPHABET],
        assumptions=["K4 uses the KRYPTOS-keyed alphabet in reverse order"],
        provenance="Sanborn used keyed alphabets; reversed version is a natural variant",
        estimated_configs=26,
        estimated_seconds=0.5,
        tags=["alphabet", "reversed"],
    )


# ── Reading direction hypotheses (RQ-13) ─────────────────────────────────

def reading_direction_hypotheses() -> Iterator[Hypothesis]:
    """Test alternative reading orders of the sculpture text."""
    # Reversed ciphertext
    yield Hypothesis(
        description="Read CT in reverse (R to O) then apply standard cipher",
        transform_stack=[
            {"type": "reverse_ct", "params": {"direction": "full_reverse"}},
        ],
        research_questions=[ResearchQuestion.RQ13_READING_DIRECTION, ResearchQuestion.RQ3_TRANSPOSITION],
        assumptions=["The ciphertext should be read right-to-left or bottom-to-top"],
        provenance="Sculpture text layout allows alternative reading directions",
        estimated_configs=1,
        estimated_seconds=0.01,
        tags=["reading_direction", "reverse"],
    )

    # Boustrophedon (serpentine) reading
    for width in [7, 8, 9, 10, 11, 13, 14]:
        yield Hypothesis(
            description=f"Boustrophedon reading with width {width}",
            transform_stack=[
                {"type": "boustrophedon", "params": {"width": width}},
            ],
            research_questions=[ResearchQuestion.RQ13_READING_DIRECTION, ResearchQuestion.RQ3_TRANSPOSITION],
            assumptions=[f"The sculpture text is read in boustrophedon with line width {width}"],
            provenance="Boustrophedon is attested in classical inscription reading",
            estimated_configs=1,
            estimated_seconds=0.01,
            tags=["reading_direction", "boustrophedon"],
        )

    # Spiral reading
    for grid in [(7, 14), (8, 13), (9, 11), (10, 10)]:
        yield Hypothesis(
            description=f"Spiral reading on {grid[0]}x{grid[1]} grid",
            transform_stack=[
                {"type": "spiral", "params": {"rows": grid[0], "cols": grid[1]}},
            ],
            research_questions=[ResearchQuestion.RQ13_READING_DIRECTION, ResearchQuestion.RQ3_TRANSPOSITION],
            assumptions=[f"CT arranged in {grid[0]}x{grid[1]} grid, read in spiral order"],
            provenance="Route ciphers use spiral/diagonal reading orders",
            estimated_configs=4,  # 4 spiral directions
            estimated_seconds=0.1,
            tags=["reading_direction", "spiral"],
        )

    # Diagonal reading
    for grid in [(7, 14), (8, 13), (9, 11), (10, 10)]:
        yield Hypothesis(
            description=f"Diagonal reading on {grid[0]}x{grid[1]} grid",
            transform_stack=[
                {"type": "diagonal", "params": {"rows": grid[0], "cols": grid[1]}},
            ],
            research_questions=[ResearchQuestion.RQ13_READING_DIRECTION, ResearchQuestion.RQ3_TRANSPOSITION],
            assumptions=[f"CT arranged in {grid[0]}x{grid[1]} grid, read diagonally"],
            provenance="Route ciphers use diagonal reading orders",
            estimated_configs=2,  # 2 diagonal directions
            estimated_seconds=0.1,
            tags=["reading_direction", "diagonal"],
        )


# ── Egypt trip / Carter hypotheses (RQ-5 expanded) ──────────────────────

def egypt_carter_hypotheses() -> Iterator[Hypothesis]:
    """Hypotheses connecting the 1986 Egypt trip to the cipher method.

    Sanborn's 1986 Egypt trip is one of two events embedded in the solution.
    Carter's Tomb of Tutankhamun is now available as reference text.
    """
    # Key phrases from Carter that might be used as keys
    carter_phrases = [
        ("WONDERFULTHINGS", "Carter's famous exclamation"),
        ("TOMBOFTUTANKHAMEN", "Title of the book"),
        ("VALLEYOFTHEKINGS", "Location of the tomb"),
        ("HOWARDCARTER", "Author name"),
        ("LORDCARNARVON", "Expedition sponsor"),
        ("ANTECHAMBER", "Room where discovery was made"),
        ("BURIALCHAMBER", "Location of sarcophagus"),
        ("GOLDENMASK", "Famous artifact"),
        ("CANOPICJARS", "Burial artifacts"),
        ("SEALEDDOORWAY", "The sealed passage"),
    ]

    for phrase, desc in carter_phrases:
        key = [ord(c) - 65 for c in phrase]
        for variant in ["vigenere", "beaufort"]:
            yield Hypothesis(
                description=f"Carter phrase '{phrase}' as {variant} key ({desc})",
                transform_stack=[
                    {"type": variant, "params": {
                        "key": key,
                        "source": f"carter_{desc.replace(' ', '_')}",
                    }},
                ],
                research_questions=[
                    ResearchQuestion.RQ5_EGYPT_BERLIN,
                    ResearchQuestion.RQ2_KEY_SOURCE,
                ],
                assumptions=[
                    f"K4 uses the phrase '{phrase}' from Carter as repeating key",
                    f"The cipher is {variant}",
                ],
                provenance=f"Sanborn's 1986 Egypt trip + Carter's book: '{desc}'",
                estimated_configs=1,
                estimated_seconds=0.01,
                tags=["egypt", "carter_phrase", variant],
            )

    # Running key from Carter with transposition first
    for width in [7, 8, 9, 10, 11]:
        yield Hypothesis(
            description=f"Columnar (w={width}) then Carter running key",
            transform_stack=[
                {"type": "columnar", "params": {"width": width}},
                {"type": "vigenere", "params": {
                    "key_source": "running_key",
                    "source_path": "reference/carter_vol1.txt",
                    "source_name": f"Carter Vol1 + col w={width}",
                }},
            ],
            research_questions=[
                ResearchQuestion.RQ5_EGYPT_BERLIN,
                ResearchQuestion.RQ2_KEY_SOURCE,
                ResearchQuestion.RQ3_TRANSPOSITION,
            ],
            assumptions=[
                f"K4 uses columnar transposition (width {width}) then Carter running key",
            ],
            provenance="Carter + transposition: combining RQ-3 and RQ-5",
            estimated_configs=5000,
            estimated_seconds=50.0,
            tags=["egypt", "compound", "carter_running_key"],
        )


# ── Master generator ────────────────────────────────────────────────────

def all_generators() -> Iterator[Hypothesis]:
    """Yield hypotheses from all registered generators."""
    # Running key from Carter (both text extractions)
    yield from running_key_from_text(
        "reference/carter_vol1.txt",
        "Carter Tomb of Tutankhamun Vol 1 (1st ed OCR)",
        max_offsets=0,
    )
    yield from running_key_from_text(
        "reference/carter_gutenberg.txt",
        "Carter Gutenberg Edition",
        max_offsets=0,
    )

    # Date-derived keys (expanded with Carter/Kryptos dates)
    yield from date_derived_keys()

    # Transform recombination
    yield from transform_recombination()

    # Pre-ENE hypotheses (expanded)
    yield from pre_ene_segment_hypotheses()

    # Artifact-driven
    yield from artifact_driven_hypotheses()

    # "The point" hypotheses (NEW — RQ-4)
    yield from the_point_hypotheses()

    # K3 method variants (NEW — RQ-8)
    yield from k3_method_variants()

    # Keystream pattern analysis (NEW — RQ-11)
    yield from keystream_pattern_hypotheses()

    # Delivering a message (NEW — RQ-6)
    yield from delivering_message_hypotheses()

    # Non-standard alphabets (NEW — RQ-12)
    yield from nonstandard_alphabet_hypotheses()

    # Reading direction (NEW — RQ-13)
    yield from reading_direction_hypotheses()

    # Egypt/Carter expanded (NEW — RQ-5 deep dive)
    yield from egypt_carter_hypotheses()
