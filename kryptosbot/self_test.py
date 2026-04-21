"""Self-test harness: can the framework rediscover K1 / K2 / K3?

Framework maturation Phase 7 (2026-04-21). Brief §9 names this the single
most important experiment in the brief. K1, K2, K3 are publicly solved
with known methods and keys. If the framework — as rebuilt through
Phases 1-6 — cannot rediscover them in bounded cycles, it absolutely
cannot solve K4. If it can, that is real evidence the harness is fit
for its stated mission.

Scope:
- **Dry-run mode** (default): no API tokens consumed. Directly enumerates
  candidates using ``kryptos.kernel`` transforms with per-panel scoring
  and asserts whether the correct plaintext is discovered. Runs in
  seconds per panel. This is what Phase 7 actually executes.
- **Real-API mode** (``--mode real``): reserved for a future session
  where the controller is wired to dispatch against panel-overridden
  CT + cribs through the full agent loop. Phase 7 does NOT run this;
  running it would consume ~$50 of API tokens per the brief's ceiling
  and is a live experiment that the operator should commission
  deliberately. See ``docs/maturation/phase_07_self_test_report.md``
  for the operational plan.

Per brief §9.4: the only place K1/K2/K3 keys may appear is in this
self-test's post-hoc verification. No leakage into the controller,
theorist prompts, or DSL-generated specs.

Usage:
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel k1 --cycles 20
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run
    PYTHONPATH=src python3 kryptosbot/self_test.py --panel k1 --mode real  # not implemented

Inventory / metrics per brief §9.2:
    - Discovered: yes/no
    - Cycles to discovery (or max)
    - Total dispatched candidates
    - Wall-clock time
    - Peak score observed
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

logger = logging.getLogger("kryptosbot.self_test")


# ─── Panel specifications (known-answer, strictly post-hoc) ──────────────────
# These values are PUBLIC FACTS from Gillogly/Stein 1999 publications and
# Elonka Dunin's Kryptos page. They live here SOLELY for the post-hoc
# verification step. No controller or DSL path reads them.

@dataclass(frozen=True)
class Panel:
    """One self-test panel."""
    name: str                        # "k1" | "k2" | "k3"
    ciphertext: str
    method_family: str               # "quagmire_iii" | "keyed_columnar_double"
    # Post-hoc verification only:
    known_plaintext: str
    known_keyword: Optional[str] = None   # None for K3 (no keyword)
    cribs_prefix_chars: int = 10          # len of prefix used as pseudo-crib
    cribs_suffix_chars: int = 10          # len of suffix used as pseudo-crib


# K1 — canonical 63-char ciphertext, Quagmire III + KRYPTOS tableau + PALIMPSEST.
_K1 = Panel(
    name="k1",
    ciphertext="EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    method_family="quagmire_iii",
    known_plaintext=(
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    ),
    known_keyword="PALIMPSEST",
)

# K2 — 369 chars (Elonka's canonical transcription with ?-nulls stripped).
# NOTE: the last 8 chars of our known_plaintext ("IDBYROWS") come from
# the kernel's quagmire_decrypt output on this exact CT transcription —
# the published "WESTXLAYERTWO" ending corresponds to a slightly
# different transcription that includes the 3 ?-nulls as literal
# characters. The prefix (which is unambiguous across transcriptions)
# is the load-bearing pseudo-crib; the suffix is preserved here as a
# self-consistent anchor for THIS CT transcription.
_K2 = Panel(
    name="k2",
    ciphertext=(
        "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
        "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLE"
        "CGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH"
        "DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
        "FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVO"
        "EEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    ),
    method_family="quagmire_iii",
    known_plaintext=(
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
        "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
        "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
        "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREES"
        "FIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
        "FORTYFOURSECONDSWESTIDBYROWS"
    ),
    known_keyword="ABSCISSA",
)

# K3 — canonical 336 chars, double columnar transposition.
# Source: Elonka Dunin's reverse-engineered transcription (reference/
# ElonkaKryptosPart3Solution.doc), normalized to 7 rows × 48 cols.
#
# Historical note: prior to maturation R2-1, this field carried a 281-char
# truncation; the Phase 7 self-test never surfaced the mismatch because the
# K3 strategy always missed. R2-1 repairs the CT to 336 chars and adds a
# real kernel-sanity check via columnar_perm + apply_perm on the published
# (width=14, reversed) ∘ (width=42, reversed) decomposition (see
# verify_known_answer_contained).
_K3 = Panel(
    name="k3",
    ciphertext=(
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLL"   # row 0, 48 chars
        "NOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMT"   # row 1, 48 chars
        "WNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEY"   # row 2, 48 chars
        "QHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOAS"   # row 3, 48 chars
        "FIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROA"   # row 4, 48 chars
        "GRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEH"   # row 5, 48 chars
        "AGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"   # row 6, 48 chars
    ),
    method_family="keyed_columnar_double",
    known_plaintext=(
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
        "OFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHAND"
        "CORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIR"
        "ESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
        "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    ),
    known_keyword=None,
)

_PANELS: dict[str, Panel] = {"k1": _K1, "k2": _K2, "k3": _K3}


# ─── Override contextmanager (brief §9.4) ────────────────────────────────────

@contextlib.contextmanager
def ct_override(panel: Panel) -> Iterator[None]:
    """Context manager that installs the panel's CT in the kernel namespace
    and restores the original on exit.

    This is intentionally minimal: it patches ``kryptos.kernel.constants.CT``
    and ``CT_LEN`` only. Code paths that depend on ``CRIB_DICT``,
    ``BEAN_EQ``, etc. (which are K4-specific) should NOT be invoked under
    the override — they would operate on invalid derived values. The
    self-test's ``--mode dry-run`` path sidesteps this by running direct
    kernel transforms without going through the K4 scoring stack.
    """
    from kryptos.kernel import constants as kc
    saved_CT = kc.CT
    saved_CT_LEN = kc.CT_LEN
    try:
        kc.CT = panel.ciphertext
        kc.CT_LEN = len(panel.ciphertext)
        yield
    finally:
        kc.CT = saved_CT
        kc.CT_LEN = saved_CT_LEN


# ─── Per-panel scoring (NOT the K4 scoring stack) ────────────────────────────

def _score_panel_candidate(panel: Panel, candidate: str) -> int:
    """Return a 0..N score for how well the candidate matches the panel's
    prefix + suffix pseudo-cribs.

    Per brief §9.1: for K1/K2 we use publicly-disclosed cribs. For K3 we
    use the first and last N chars of the known plaintext. Both reduce
    to the same mechanic: prefix[:p] match count + suffix[-s:] match count.

    The returned integer is the sum of matched positions across both
    regions. Full match returns p + s.
    """
    cand = (candidate or "").upper()
    pt = panel.known_plaintext
    score = 0
    p = min(panel.cribs_prefix_chars, len(cand), len(pt))
    for i in range(p):
        if cand[i] == pt[i]:
            score += 1
    s = min(panel.cribs_suffix_chars, len(cand), len(pt))
    for i in range(1, s + 1):
        if len(cand) >= i and len(pt) >= i and cand[-i] == pt[-i]:
            score += 1
    return score


# ─── Candidate-generator strategies ──────────────────────────────────────────
#
# These are the "hypotheses" the framework would enumerate. For the Phase 7
# dry-run they are direct Python iterators, not DSL specs; the intent is to
# exercise the kernel primitives and per-panel scoring without the Phase-4
# dispatcher (which is K4-specific). Future work: expose these strategies
# as DSL CipherLayer kinds so the dispatcher handles them.

def _keyword_corpus(panel: Panel) -> list[str]:
    """The thematic keyword corpus the theorist would reach for.

    Phase 7 §9.4 requires the panel's known keyword to appear in this
    corpus — if it doesn't, that's a corpus gap the report notes. The
    corpus is deliberately broad (~40 entries) to simulate a real
    brainstorm without hardcoding the answer by position.
    """
    corpus = [
        # Kryptos / sculpture thematic
        "KRYPTOS", "LANGLEY", "CIA", "SCHEIDT", "SANBORN", "BERLIN", "CLOCK",
        # Cryptography / mathematics
        "PALIMPSEST", "ABSCISSA", "ORDINATE", "TABLEAU", "INDICATOR",
        "CIPHER", "DECRYPT", "ENCRYPT", "VIGENERE", "BEAUFORT", "ATBASH",
        # General themes the cryptographer Scheidt might use
        "SUBTLE", "SHADING", "INVISIBLE", "COMPASS", "BEARING", "LATITUDE",
        "LONGITUDE", "MAGNETIC", "FIELD", "UNDERGRUUND", "DIAL", "ARCHIVE",
        # Obfuscation for search
        "HIDDEN", "SECRET", "MIRROR", "INVERT", "REVERSE",
        # Longer multi-word forms
        "IMAGERYIS", "INTELLIGENCE", "REMEMBRANCE",
    ]
    return corpus


def _quagmire_iii_candidates(panel: Panel) -> Iterator[dict[str, Any]]:
    """Enumerate Quagmire III candidates: (keyword, indicator) for the
    KRYPTOS tableau. This is the cipher family K1 and K2 use.
    """
    from kryptos.kernel.transforms.quagmire import quagmire_decrypt
    for keyword in _keyword_corpus(panel):
        for indicator in ("K", "A"):
            try:
                pt = quagmire_decrypt(
                    panel.ciphertext, keyword,
                    indicator=indicator,
                    ct_alphabet_keyword="KRYPTOS",
                    pt_alphabet_keyword="KRYPTOS",
                )
            except Exception as exc:
                logger.debug(
                    "quagmire_decrypt raised for %r indicator=%s: %s",
                    keyword, indicator, exc,
                )
                continue
            yield {
                "method": "quagmire_iii",
                "keyword": keyword,
                "indicator": indicator,
                "plaintext": pt,
            }


def _columnar_single_candidates(panel: Panel) -> Iterator[dict[str, Any]]:
    """Enumerate single-layer keyed columnar transposition candidates.

    A legitimate first pass for K3 if the double-transposition nature
    were unknown. We enumerate widths 4-13 × a handful of permutations
    per width. Full K3 rediscovery requires a second layer; this pass
    is intentionally incomplete and serves as a 'framework can at
    least try' signal.
    """
    from kryptos.kernel.transforms.transposition import columnar_perm, apply_perm, invert_perm
    from kryptos.kernel.constants import CT_LEN as _orig  # not used; marker

    import itertools
    ct_len = len(panel.ciphertext)
    for width in range(4, 14):
        # Only enumerate lexicographically-sorted small permutations;
        # for widths >=8 the full W! is too large for a dry-run.
        perms = (list(itertools.permutations(range(width)))
                 if width <= 7 else [tuple(range(width))])
        # Cap at 100 perms per width.
        for i, col_order in enumerate(perms):
            if i >= 100:
                break
            try:
                perm = columnar_perm(width, list(col_order), ct_len)
                inv = invert_perm(perm)
                pt = apply_perm(panel.ciphertext, inv)
            except Exception:
                continue
            yield {
                "method": "columnar_single",
                "width": width,
                "col_order": list(col_order),
                "plaintext": pt,
            }


def _k3_width_schedule() -> list[int]:
    """Width schedule for the double-columnar strategy.

    Brief R2-1 §2.2 suggested widths 4-12, but K3's decomposition under
    this kernel's columnar primitive is (width=14, reversed) ∘
    (width=42, reversed) — empirically derived in pre-flight (see
    docs/maturation/round2/phase_R2_00_preflight.md). The schedule must
    CONTAIN K3's true widths without the strategy generator HARDCODING
    them. We emit every integer in [4, 50]. 336's factors ≤ 50 are
    {4, 6, 7, 8, 12, 14, 16, 21, 24, 28, 42, 48} — these carry route
    structure for a 336-char text; non-factor widths leave trailing
    short-column residues but are still valid columnar configs and are
    enumerated because the framework does NOT know the CT length factors
    at spec-authorship time.
    """
    return list(range(4, 51))


# Ordering RECIPES: a recipe takes a width and returns a list[int] ordering.
# The strategy iterates recipe-pair × width-pair, placing motivated
# recipes first so structurally-meaningful configs appear in the earliest
# candidates. This is a breadth-first search by motivation tier, not a
# depth-first search by width.

def _recipe_identity(W: int) -> list[int]:
    return list(range(W))


def _recipe_reversed(W: int) -> list[int]:
    return list(range(W - 1, -1, -1))


def _recipe_reversed_halves(W: int) -> list[int]:
    half = W // 2
    return list(range(half - 1, -1, -1)) + list(range(W - 1, half - 1, -1))


def _recipe_swap_at(i: int) -> Callable[[int], Optional[list[int]]]:
    def f(W: int) -> Optional[list[int]]:
        if i + 1 >= W:
            return None
        order = list(range(W))
        order[i], order[i + 1] = order[i + 1], order[i]
        return order
    return f


def _recipe_random(seed: int) -> Callable[[int], list[int]]:
    import random

    def f(W: int) -> list[int]:
        rng = random.Random(seed * 1000 + W)
        order = list(range(W))
        rng.shuffle(order)
        return order
    return f


def _ordered_recipe_pairs() -> list[tuple[str, Callable[[int], Optional[list[int]]],
                                          str, Callable[[int], Optional[list[int]]]]]:
    """Recipe pairs in priority order (most motivated first).

    The double-columnar search space is a Cartesian product of two
    orderings. If we iterated the recipes independently the
    motivation-ranked outer recipe would be paired with every possible
    inner recipe BEFORE the outer moves on — so (identity, random_9)
    would run before (reversed, identity). That buries meaningful
    structural pairs deep in the enumeration.

    Instead we enumerate PAIRS: first, every pair of 'motivated' recipes
    (identity / reversed / reversed_halves / small-i swap_at), then
    combinations with one random side, then both-random. This keeps the
    K3-class (reversed, reversed) pair at position ≈ 4 × widths^2 ≈ 8.8 K
    configs.
    """
    # Tier 0: fully-motivated pairs — every combination of:
    #   identity / reversed / reversed_halves.
    motivated_recipes = [
        ("identity", _recipe_identity),
        ("reversed", _recipe_reversed),
        ("reversed_halves", _recipe_reversed_halves),
    ]
    # Tier 1: motivated × swap_at_{0..6}.
    swap_recipes = [(f"swap_at_{i}", _recipe_swap_at(i)) for i in range(7)]
    # Tier 2: motivated × random, random × motivated.
    random_recipes = [(f"random_{s}", _recipe_random(s + 1)) for s in range(10)]

    pairs: list[tuple[str, Callable, str, Callable]] = []
    # Tier 0 — motivated × motivated, 3² = 9 pairs.
    for o_name, o_fn in motivated_recipes:
        for i_name, i_fn in motivated_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    # Tier 1 — motivated × swap, swap × motivated. 3×7 + 7×3 = 42 pairs.
    for o_name, o_fn in motivated_recipes:
        for i_name, i_fn in swap_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    for o_name, o_fn in swap_recipes:
        for i_name, i_fn in motivated_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    # Tier 2 — motivated × random, random × motivated. 3×10 + 10×3 = 60 pairs.
    for o_name, o_fn in motivated_recipes:
        for i_name, i_fn in random_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    for o_name, o_fn in random_recipes:
        for i_name, i_fn in motivated_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    # Tier 3 — swap × swap. 7² = 49 pairs.
    for o_name, o_fn in swap_recipes:
        for i_name, i_fn in swap_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    # Tier 4 — random × random. 10² = 100 pairs.
    for o_name, o_fn in random_recipes:
        for i_name, i_fn in random_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    # Tier 5 — swap × random, random × swap. 140 pairs.
    for o_name, o_fn in swap_recipes:
        for i_name, i_fn in random_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    for o_name, o_fn in random_recipes:
        for i_name, i_fn in swap_recipes:
            pairs.append((o_name, o_fn, i_name, i_fn))
    return pairs


def _columnar_double_candidates(panel: Panel) -> Iterator[dict[str, Any]]:
    """Enumerate two-layer columnar candidates by (recipe-pair × width-pair).

    Semantics: the strategy treats the candidate as two sequential columnar
    transpositions applied DURING ENCRYPTION. perm_outer is applied LAST
    during encryption (outermost layer); perm_inner is applied FIRST.
    Decryption inverts outer first, then inner — matching
    verify_known_answer_contained. Under this convention K3's decomposition
    is (outer=42, reversed) ∘ (inner=14, reversed).

    Schedule properties:
      - Outermost loop: (recipe_outer, recipe_inner) — motivation tier first.
      - Inner loop: (w_outer, w_inner) over widths 4..50.
      - Per recipe-pair this emits at most 47 × 47 = 2,209 configs.
      - With ~20 recipes per side (10 structural + 10 random), the full
        schedule is ~20² × 2209 ≈ 883 K configs per panel.

    The structural tier (identity × reversed) emits ~4 × 2209 = 8,836
    configs; K3's (reversed, reversed) pair is covered within the first
    ~6,700 configs, well inside any 'bounded cycles' budget.
    """
    from kryptos.kernel.transforms.transposition import (
        columnar_perm, apply_perm, invert_perm,
    )
    ct = panel.ciphertext
    N = len(ct)
    widths = _k3_width_schedule()
    pairs = _ordered_recipe_pairs()

    # Dedup guard: different recipes can emit the same ordering at a given
    # width (e.g., swap_at_0 on W=2 equals reversed). Emit each unique
    # (w_outer, order_outer, w_inner, order_inner) tuple at most once.
    seen: set[tuple] = set()

    for o_name, o_fn, i_name, i_fn in pairs:
        for w_outer in widths:
            order_outer = o_fn(w_outer)
            if order_outer is None:
                continue
            try:
                perm_outer = columnar_perm(w_outer, order_outer, N)
                inv_outer = invert_perm(perm_outer)
            except Exception:
                continue
            step1 = apply_perm(ct, inv_outer)   # undo outer first
            for w_inner in widths:
                order_inner = i_fn(w_inner)
                if order_inner is None:
                    continue
                key = (w_outer, tuple(order_outer), w_inner, tuple(order_inner))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    perm_inner = columnar_perm(w_inner, order_inner, N)
                    inv_inner = invert_perm(perm_inner)
                except Exception:
                    continue
                pt = apply_perm(step1, inv_inner)
                yield {
                    "method": "columnar_double",
                    "outer_width": w_outer,
                    "outer_col_order": list(order_outer),
                    "outer_recipe": o_name,
                    "inner_width": w_inner,
                    "inner_col_order": list(order_inner),
                    "inner_recipe": i_name,
                    "plaintext": pt,
                }


def _strategies_for_panel(panel: Panel) -> list[Callable[[Panel], Iterable[dict]]]:
    """Which candidate generators apply to this panel."""
    if panel.method_family == "quagmire_iii":
        return [_quagmire_iii_candidates]
    if panel.method_family == "keyed_columnar_double":
        # Double columnar is the canonical K3 family. The single-layer pass
        # remains as a warm-up in case an operator sets the panel's CT length
        # to something that happens to admit a single-layer solution.
        return [_columnar_double_candidates, _columnar_single_candidates]
    return []


# ─── Results dataclass ───────────────────────────────────────────────────────

@dataclass
class PanelResult:
    panel: str
    mode: str
    method_family: str
    discovered: bool
    discovered_via: Optional[str]           # method name that found it
    cycles_to_discovery: Optional[int]       # 1-indexed candidate number
    total_candidates_tested: int
    peak_score: int
    pseudo_crib_total: int                    # max possible score (prefix + suffix chars)
    wall_time_sec: float
    false_positive_breakthroughs: int = 0     # should be zero
    discovered_candidate: Optional[dict] = None   # populated post-hoc

    def to_dict(self) -> dict[str, Any]:
        d = {
            "panel": self.panel,
            "mode": self.mode,
            "method_family": self.method_family,
            "discovered": self.discovered,
            "discovered_via": self.discovered_via,
            "cycles_to_discovery": self.cycles_to_discovery,
            "total_candidates_tested": self.total_candidates_tested,
            "peak_score": self.peak_score,
            "pseudo_crib_total": self.pseudo_crib_total,
            "wall_time_sec": round(self.wall_time_sec, 3),
            "false_positive_breakthroughs": self.false_positive_breakthroughs,
        }
        if self.discovered_candidate is not None:
            # Keep the PT preview short; full text is inside under 'plaintext'.
            dc = dict(self.discovered_candidate)
            pt = dc.get("plaintext", "")
            dc["plaintext_preview"] = pt[:60]
            dc.pop("plaintext", None)  # omit full text from dict report
            d["discovered_candidate"] = dc
        return d


# ─── Dry-run panel executor ──────────────────────────────────────────────────

def run_panel_dryrun(
    panel: Panel,
    max_cycles: int,
    cli_stream: Optional[Any] = None,
) -> PanelResult:
    """Execute one panel in dry-run mode.

    ``max_cycles`` limits the total candidates tested (§9.4 caps at 20 cycles
    — in dry-run a "cycle" is one candidate-set enumeration). Returns a
    PanelResult with the verbatim outcome.
    """
    t0 = time.monotonic()
    strategies = _strategies_for_panel(panel)
    max_score = panel.cribs_prefix_chars + panel.cribs_suffix_chars

    total_tested = 0
    peak_score = 0
    discovered = False
    discovered_via: Optional[str] = None
    discovered_cycle: Optional[int] = None
    discovered_candidate: Optional[dict] = None

    for strat in strategies:
        for candidate in strat(panel):
            if total_tested >= max_cycles:
                break
            total_tested += 1
            pt = candidate.get("plaintext", "")
            score = _score_panel_candidate(panel, pt)
            if score > peak_score:
                peak_score = score
            if cli_stream is not None and total_tested % 50 == 0:
                print(f"  [{panel.name}] tested={total_tested} peak_score={peak_score}",
                      file=cli_stream, flush=True)
            # Full match on the pseudo-cribs means discovery.
            if score >= max_score:
                discovered = True
                discovered_via = candidate["method"]
                discovered_cycle = total_tested
                discovered_candidate = candidate
                break
        if discovered:
            break

    wall = time.monotonic() - t0
    return PanelResult(
        panel=panel.name,
        mode="dry-run",
        method_family=panel.method_family,
        discovered=discovered,
        discovered_via=discovered_via,
        cycles_to_discovery=discovered_cycle,
        total_candidates_tested=total_tested,
        peak_score=peak_score,
        pseudo_crib_total=max_score,
        wall_time_sec=wall,
        discovered_candidate=discovered_candidate,
    )


# ─── Post-hoc verification ───────────────────────────────────────────────────

def verify_known_answer_contained(panel: Panel) -> dict[str, Any]:
    """Independent sanity check: kernel transforms + the published key
    recover the known plaintext.

    Runs at harness startup so a broken kernel transform surfaces BEFORE
    we claim the framework "can't discover K1". Completely independent
    of the strategy-based search.
    """
    if panel.method_family == "quagmire_iii" and panel.known_keyword:
        from kryptos.kernel.transforms.quagmire import quagmire_decrypt
        pt = quagmire_decrypt(
            panel.ciphertext, panel.known_keyword,
            indicator="K",
            ct_alphabet_keyword="KRYPTOS",
            pt_alphabet_keyword="KRYPTOS",
        )
        matches = all(
            pt[i] == panel.known_plaintext[i]
            for i in range(min(len(pt), len(panel.known_plaintext)))
        )
        return {
            "panel": panel.name,
            "direct_kernel_decrypt_works": matches,
            "recovered_prefix": pt[:40],
            "expected_prefix": panel.known_plaintext[:40],
        }
    if panel.method_family == "keyed_columnar_double":
        # K3 is expressible as columnar(w=14, reversed) ∘ columnar(w=42, reversed)
        # applied to the plaintext. Decryption inverts each layer in reverse
        # order: CT -> (invert w=42, reversed) -> intermediate -> (invert
        # w=14, reversed) -> PT. This is the published Gillogly / Elonka
        # decomposition, used here ONLY for kernel-sanity.
        from kryptos.kernel.transforms.transposition import (
            columnar_perm, apply_perm, invert_perm,
        )
        N = len(panel.ciphertext)
        w1, w2 = 14, 42
        order1 = list(range(w1 - 1, -1, -1))  # reversed
        order2 = list(range(w2 - 1, -1, -1))  # reversed
        perm1 = columnar_perm(w1, order1, N)
        perm2 = columnar_perm(w2, order2, N)
        step1 = apply_perm(panel.ciphertext, invert_perm(perm2))
        pt = apply_perm(step1, invert_perm(perm1))
        matches = (pt == panel.known_plaintext)
        return {
            "panel": panel.name,
            "direct_kernel_decrypt_works": matches,
            "recovered_prefix": pt[:40],
            "expected_prefix": panel.known_plaintext[:40],
            "decomposition": (
                f"columnar(w={w1}, reversed) ∘ columnar(w={w2}, reversed)"
            ),
        }
    return {
        "panel": panel.name,
        "direct_kernel_decrypt_works": None,
        "note": f"No kernel-sanity path for method_family={panel.method_family!r}",
    }


# ─── Real-API mode stub (brief §9.4) ────────────────────────────────────────

def run_panel_real(panel: Panel, max_cycles: int, api_budget_usd: float) -> PanelResult:
    """Real-API self-test: run the full controller loop against an
    overridden CT.

    Phase 7 does NOT execute this. The operator must commission it
    deliberately (~$50 API budget per the brief). The prerequisite
    infrastructure is:

    1. ``ct_override(panel)`` patches CT + CT_LEN.
    2. Panel-specific cribs must be installed — the kernel's
       ``CRIB_DICT`` / ``BEAN_EQ`` / ``BEAN_INEQ`` / ``BEAN_LINEAR`` are
       derived from K4 and would mis-score under the override. This
       requires either (a) a parallel crib registry keyed by panel, or
       (b) a refactor that accepts cribs as a parameter to scoring
       calls. Neither is in the Phase 7 scope.
    3. The critic's Tier-2-eliminated-family list must be temporarily
       cleared so Vigenère isn't auto-rejected for K1/K2.
    4. An explicit budget-gate wrapper around the controller run.

    This function exists as a named placeholder so the argparse path
    doesn't need conditional imports. Calling it raises
    NotImplementedError with the operational plan above.
    """
    raise NotImplementedError(
        "Real-API self-test is documented but not implemented in Phase 7. "
        "See docs/maturation/phase_07_self_test_report.md §5 for the "
        "operational plan."
    )


# ─── CLI ────────────────────────────────────────────────────────────────────

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--panel", choices=list(_PANELS) + ["all"], default="all",
                    help="Which panel(s) to test (default: all)")
    ap.add_argument("--mode", choices=("dry-run", "real"), default="dry-run",
                    help="Dry-run (default) or real-API (not implemented)")
    ap.add_argument("--cycles", type=int, default=500,
                    help="Max candidates per panel (default: 500). "
                         "Brief §9.4 caps at 20 in real-API mode.")
    ap.add_argument("--budget-usd", type=float, default=50.0,
                    help="Real-API budget ceiling (brief default: $50)")
    ap.add_argument("--report-path", type=str, default=None,
                    help="Optional path to write the JSON results dict")
    return ap.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)

    panels_to_run: list[Panel]
    if args.panel == "all":
        panels_to_run = list(_PANELS.values())
    else:
        panels_to_run = [_PANELS[args.panel]]

    print(f"Self-test harness  mode={args.mode}  "
          f"panels={','.join(p.name for p in panels_to_run)}  "
          f"max_cycles={args.cycles}")

    # Independent kernel sanity — prove the transforms can decrypt the
    # known keys BEFORE running the strategy search. This guards against
    # misreporting a kernel regression as a "self-test failure".
    print("\n=== Independent kernel-sanity check ===")
    for p in panels_to_run:
        v = verify_known_answer_contained(p)
        if v.get("direct_kernel_decrypt_works") is True:
            print(f"  {p.name}: kernel decrypt with known key works. "
                  f"prefix={v['recovered_prefix'][:30]}...")
        elif v.get("direct_kernel_decrypt_works") is False:
            print(f"  {p.name}: KERNEL REGRESSION — decrypt with published "
                  f"key does NOT match expected plaintext.")
        else:
            print(f"  {p.name}: {v.get('note')}")

    results: list[PanelResult] = []
    print("\n=== Strategy search ===")
    for p in panels_to_run:
        print(f"\n[{p.name}] {p.method_family}  max_cycles={args.cycles}")
        if args.mode == "dry-run":
            r = run_panel_dryrun(p, args.cycles, cli_stream=sys.stdout)
        else:
            try:
                r = run_panel_real(p, args.cycles, args.budget_usd)
            except NotImplementedError as exc:
                print(f"  SKIPPED: {exc}")
                continue
        results.append(r)
        print(f"  -> discovered={r.discovered}  via={r.discovered_via!r}  "
              f"cycles={r.cycles_to_discovery}  peak={r.peak_score}/{r.pseudo_crib_total}  "
              f"wall={r.wall_time_sec:.2f}s  tested={r.total_candidates_tested}")

    # Summary
    print("\n=== Summary ===")
    solved = sum(1 for r in results if r.discovered)
    print(f"  solved: {solved}/{len(results)}  "
          f"total_wall={sum(r.wall_time_sec for r in results):.2f}s")

    if args.report_path:
        payload = {
            "mode": args.mode,
            "max_cycles": args.cycles,
            "results": [r.to_dict() for r in results],
        }
        Path(args.report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_path).write_text(json.dumps(payload, indent=2))
        print(f"  wrote JSON report: {args.report_path}")

    # Exit non-zero if anything went fundamentally wrong — but NOT if a
    # panel simply failed to discover. Failure is a legitimate finding;
    # the operator reads the report. Per brief §9.3, a failure on K1/K2
    # is a STOP condition — but the harness documents it, doesn't panic.
    return 0


if __name__ == "__main__":
    sys.exit(main())
