"""K4Bench HandCipherCore programmatic fallback.

When the theorist agent emits unparseable output during a K4Bench run,
``ResearchController._programmatic_fallback`` previously returned an
empty list (the real-K4 fallback corpus draws from the K4 family /
anomaly registries that don't apply to a synthetic challenge). The
result was Proposed=0 / Tested=0 cycles whenever the theorist hiccupped.

This module provides ``hand_cipher_core_fallback`` — a deterministic,
challenge-local generator that emits >= ``n_target`` valid finite DSL
specs derived from the challenge's own clue pack. Every spec is run
through ``validate_hypothesis_spec`` AND each layer kind is checked for
dispatcher translation before being returned, so any spec that survives
is guaranteed dispatchable.

Design constraints:

- No real-K4 vocabulary. Keywords come exclusively from the challenge
  ``clue_text``, ``title``, and a small pool of project-wide-safe
  defaults (KRYPTOS, PALIMPSEST, ABSCISSA, KEY) that the controller
  tolerates in either mode.
- Pure data adapter. No SDK calls, no kernel imports beyond what the
  validator drags in. The fallback runs in <100 ms even when the
  theorist took 30 seconds to fail.
- Fail closed. A spec that fails ``validate_hypothesis_spec`` is
  silently dropped; the function returns whatever did validate. The
  caller (the controller) is responsible for asserting non-emptiness
  and surfacing a halt if every spec dropped.

Typical use site (``ResearchController._programmatic_fallback``)::

    if not self.config.problem.is_real_k4:
        from .bench_fallback import hand_cipher_core_fallback
        return hand_cipher_core_fallback(
            payload=self.config.bench_challenge_payload or {},
            n_target=self.config.theories_per_cycle,
        )
"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping, Optional

from .hypothesis_dsl import validate_hypothesis_spec
from .job_dispatcher import _SUPPORTED_KINDS, _kind_has_translation
from .models import TheoryRecord


logger = logging.getLogger("kryptosbot.bench_fallback")


# Project-wide-safe keyword fallbacks. KRYPTOS / PALIMPSEST / ABSCISSA
# are real-K4 known keywords and will appear in either prompt context
# without provoking a contamination signal — they are part of the
# canonical English-language Kryptos vocabulary. KEY is a generic
# stand-in. Used only when the challenge clue text yields no usable
# tokens.
_DEFAULT_KEYWORDS: tuple[str, ...] = (
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "KEY",
)

# Stop-words excluded from clue-text tokenization. These are short or
# generic words that produce noisy keys; they are conservative and
# erring on the side of "drop" rather than "include" because we have a
# guaranteed default pool to fall back on.
_CLUE_STOPWORDS: frozenset[str] = frozenset({
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "WAS", "WERE",
    "WITH", "FROM", "INTO", "OVER", "UNDER", "ABOVE", "BELOW",
    "ALL", "ANY", "SOME", "EACH", "EVERY", "ONE", "TWO", "THREE",
    "FOUR", "FIVE", "SIX", "EIGHT", "NINE", "TEN",
    "THIS", "THAT", "THESE", "THOSE", "WHICH", "WHAT", "WHO", "WHOM",
    "HIS", "HER", "ITS", "OUR", "THEIR",
    "HAS", "HAVE", "HAD", "DOES", "DID", "BEEN", "BEING",
    "ONLY", "JUST", "ALSO", "VERY", "MORE", "MOST", "LESS",
    "LABELS", "MARGIN", "FIELD", "BELOW",  # K4B-001 prose-noise
})

# Minimum and maximum keyword length when mining clue text. Vigenere
# accepts any length >= 1 over the canonical alphabet, but very short
# keywords degenerate to Caesar shifts and very long ones overrun a
# 97-char text. The 3..14 band covers CEDAR, LANTERN, KRYPTOS,
# PALIMPSEST, ABSCISSA without clipping the canonical real-K4
# vocabulary.
_MIN_KEYWORD_LEN: int = 3
_MAX_KEYWORD_LEN: int = 14


def _extract_clue_keywords(payload: Mapping[str, Any]) -> list[str]:
    """Mine clue-text and title for plausible cipher-keyword candidates.

    Returns an ordered, de-duplicated list of uppercase A-Z words from
    ``payload["clue_text"]`` and ``payload["title"]``.

    Ordering rule (priority for downstream key selection):
      1. ALL-CAPS tokens in ``clue_text`` first — these are the
         convention K4Bench uses to mark deliberate clue anchors
         (e.g. CEDAR, LANTERN in K4B-001's "CEDAR posts below a
         LANTERN"). They are the most likely intended keys.
      2. Mixed-case tokens in ``clue_text`` next, in document order.
      3. Tokens from ``title`` last, in document order.

    Tokens shorter than ``_MIN_KEYWORD_LEN`` or longer than
    ``_MAX_KEYWORD_LEN``, and tokens in ``_CLUE_STOPWORDS``, are
    excluded. The result may legally be empty; the caller is expected
    to fall back to ``_DEFAULT_KEYWORDS`` in that case.
    """
    clue_text = payload.get("clue_text") if isinstance(payload.get("clue_text"), str) else ""
    title = payload.get("title") if isinstance(payload.get("title"), str) else ""

    seen: set[str] = set()
    keywords: list[str] = []

    def _accept(token_raw: str) -> None:
        upper = token_raw.upper()
        if upper in seen:
            return
        if len(upper) < _MIN_KEYWORD_LEN or len(upper) > _MAX_KEYWORD_LEN:
            return
        if upper in _CLUE_STOPWORDS:
            return
        seen.add(upper)
        keywords.append(upper)

    # Priority 1: ALL-CAPS clue-text tokens — the K4Bench anchor
    # convention. We re-scan the clue_text only for tokens that are
    # already entirely uppercase in the source.
    if clue_text:
        for token in re.findall(r"[A-Za-z]+", clue_text):
            if token.isupper() and token.isalpha():
                _accept(token)

    # Priority 2: remaining clue-text tokens (mixed-case, lowercase),
    # in document order.
    if clue_text:
        for token in re.findall(r"[A-Za-z]+", clue_text):
            _accept(token)

    # Priority 3: title tokens.
    if title:
        for token in re.findall(r"[A-Za-z]+", title):
            _accept(token)

    return keywords


def _resolve_keyword_pool(
    payload: Mapping[str, Any],
    *,
    minimum: int = 4,
) -> list[str]:
    """Combine clue-mined keywords with the safe default pool.

    Priority order:
      1. Clue-mined keywords (in document order).
      2. ``_DEFAULT_KEYWORDS`` (deterministic order).

    Duplicates are removed while preserving first-seen order. The
    function guarantees the returned list has at least ``minimum``
    keywords; it never returns an empty list.
    """
    pool: list[str] = []
    seen: set[str] = set()
    for kw in _extract_clue_keywords(payload):
        if kw not in seen:
            seen.add(kw)
            pool.append(kw)
    for kw in _DEFAULT_KEYWORDS:
        if kw not in seen:
            seen.add(kw)
            pool.append(kw)
    # Defensive: if both clue-mined and defaults degenerate to nothing
    # (e.g., DEFAULTS got edited to empty), produce at least one
    # placeholder so downstream cardinality stays >= 1. The real
    # validator will reject "X" as too short for some kinds, but the
    # vigenere/beaufort path tolerates any positive-length A-Z string.
    if len(pool) < minimum:
        for filler in ("ALPHA", "BRAVO", "CHARLIE", "DELTA"):
            if filler not in seen:
                seen.add(filler)
                pool.append(filler)
            if len(pool) >= minimum:
                break
    return pool


def _vigenere_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _beaufort_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "beaufort", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _variant_beaufort_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "variant_beaufort", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _columnar_identity_spec(hid: str, width: int = 7) -> dict[str, Any]:
    """Columnar with identity column-order — a no-op transposition that
    still exercises the columnar dispatch path. Useful as a layer-
    composition baseline; on its own returns the input unchanged."""
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "columnar", "alphabet": "AZ",
            "params": [
                {"name": "width", "values": [width]},
                {"name": "col_order",
                 "values": [list(range(width))]},
            ],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _rail_fence_spec(hid: str, depth: int = 3) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "rail_fence", "alphabet": "AZ",
            "params": [{"name": "depth", "values": [depth]}],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _myszkowski_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "myszkowski", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _route_spec(hid: str, rows: int = 10, cols: int = 10) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "route", "alphabet": "AZ",
            "params": [
                {"name": "variant", "values": ["serpentine"]},
                {"name": "rows", "values": [rows]},
                {"name": "cols", "values": [cols]},
            ],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _quagmire_iii_spec(hid: str, keyword: str) -> dict[str, Any]:
    """Quagmire III: ct_alphabet_keyword == pt_alphabet_keyword (the
    translator enforces this). Indicator A keeps the indicator within
    the canonical alphabet."""
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": [keyword]},
                {"name": "indicator", "values": ["A"]},
                {"name": "ct_alphabet_keyword", "values": [keyword]},
                {"name": "pt_alphabet_keyword", "values": [keyword]},
                {"name": "variant", "values": ["quagmire_iii"]},
            ],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _columnar_then_vigenere_spec(hid: str, keyword: str, width: int = 7) -> dict[str, Any]:
    """Two-layer: identity-permutation columnar followed by Vigenere on
    the same alphabet. Exercises the multi-layer dispatch path."""
    return {
        "hypothesis_id": hid,
        "pipeline": [
            {"kind": "columnar", "alphabet": "AZ",
             "params": [
                 {"name": "width", "values": [width]},
                 {"name": "col_order",
                  "values": [list(range(width))]},
             ]},
            {"kind": "vigenere", "alphabet": "AZ",
             "params": [{"name": "keyword", "values": [keyword]}]},
        ],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 2,
        "assumption_bundle": ["bench_fallback", "multilayer", "columnar_first"],
    }


def _rail_fence_then_beaufort_spec(hid: str, keyword: str, depth: int = 3) -> dict[str, Any]:
    """Two-layer: rail-fence transposition then Beaufort substitution.
    Exercises the alternate (transposition-first) multi-layer order."""
    return {
        "hypothesis_id": hid,
        "pipeline": [
            {"kind": "rail_fence", "alphabet": "AZ",
             "params": [{"name": "depth", "values": [depth]}]},
            {"kind": "beaufort", "alphabet": "AZ",
             "params": [{"name": "keyword", "values": [keyword]}]},
        ],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 2,
        "assumption_bundle": ["bench_fallback", "multilayer", "rail_fence_first"],
    }


def _build_catalog(payload: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Build the ordered (slug, raw_spec_dict) catalogue.

    Single-layer specs come first (cheaper to dispatch, faster to fail
    closed). Two-layer specs follow. Order is deterministic so a fallback
    cycle produces the same catalogue every time on the same challenge,
    which keeps the ledger's deduplication logic predictable.
    """
    pool = _resolve_keyword_pool(payload, minimum=4)
    bench_id = str(payload.get("bench_id") or payload.get("title") or "bench")
    # Normalize bench_id into an id-safe slug fragment.
    bench_slug = re.sub(r"[^A-Za-z0-9]+", "-", bench_id).strip("-").lower() or "bench"

    # Pick keywords for each kind. A challenge with two clue-anchor words
    # (e.g. CEDAR + LANTERN on K4B-001) gets distinct keywords for the
    # vigenere / beaufort layers; smaller pools cycle through.
    kw0 = pool[0]
    kw1 = pool[1] if len(pool) > 1 else pool[0]
    kw2 = pool[2] if len(pool) > 2 else kw1
    kw3 = pool[3] if len(pool) > 3 else kw0

    catalog: list[tuple[str, dict[str, Any]]] = [
        # Single-layer substitution.
        (f"hcc-{bench_slug}-vig-{kw0.lower()}",     _vigenere_spec(f"hcc-{bench_slug}-vig-{kw0.lower()}", kw0)),
        (f"hcc-{bench_slug}-vig-{kw1.lower()}",     _vigenere_spec(f"hcc-{bench_slug}-vig-{kw1.lower()}", kw1)),
        (f"hcc-{bench_slug}-beau-{kw0.lower()}",    _beaufort_spec(f"hcc-{bench_slug}-beau-{kw0.lower()}", kw0)),
        (f"hcc-{bench_slug}-beau-{kw1.lower()}",    _beaufort_spec(f"hcc-{bench_slug}-beau-{kw1.lower()}", kw1)),
        (f"hcc-{bench_slug}-vbeau-{kw2.lower()}",   _variant_beaufort_spec(f"hcc-{bench_slug}-vbeau-{kw2.lower()}", kw2)),
        # Single-layer transposition.
        (f"hcc-{bench_slug}-rail-d3",               _rail_fence_spec(f"hcc-{bench_slug}-rail-d3", 3)),
        (f"hcc-{bench_slug}-rail-d4",               _rail_fence_spec(f"hcc-{bench_slug}-rail-d4", 4)),
        (f"hcc-{bench_slug}-col-w7",                _columnar_identity_spec(f"hcc-{bench_slug}-col-w7", 7)),
        (f"hcc-{bench_slug}-route-serp-10x10",      _route_spec(f"hcc-{bench_slug}-route-serp-10x10", 10, 10)),
        # Single-layer keyword-tied transposition.
        (f"hcc-{bench_slug}-myz-{kw0.lower()}",     _myszkowski_spec(f"hcc-{bench_slug}-myz-{kw0.lower()}", kw0)),
        # Quagmire III.
        (f"hcc-{bench_slug}-quag3-{kw1.lower()}",   _quagmire_iii_spec(f"hcc-{bench_slug}-quag3-{kw1.lower()}", kw1)),
        # Two-layer combinations.
        (f"hcc-{bench_slug}-col-vig-{kw0.lower()}", _columnar_then_vigenere_spec(f"hcc-{bench_slug}-col-vig-{kw0.lower()}", kw0)),
        (f"hcc-{bench_slug}-rail-beau-{kw3.lower()}", _rail_fence_then_beaufort_spec(f"hcc-{bench_slug}-rail-beau-{kw3.lower()}", kw3)),
    ]
    return catalog


def _spec_passes_validation(raw: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return (ok, errors) — the same contract the dispatcher applies.

    Validates the spec via ``validate_hypothesis_spec`` (covers DSL
    structure, alphabets, parameter names, cardinality cap, etc.) and
    additionally checks that EVERY layer kind has a dispatcher
    translation. A spec with a kind in ``_VALID_CIPHER_KINDS`` but
    absent from ``_SUPPORTED_KINDS`` (e.g., the deferred ``key_tape``
    kind) would validate at the DSL boundary but be rejected by the
    critic / dispatcher; we drop it here so the fallback never returns
    a known-undispatchable spec.
    """
    parsed = validate_hypothesis_spec(raw)
    if not parsed.is_valid:
        return False, list(parsed.errors)
    spec = parsed.value
    untranslatable = [
        layer.kind for layer in spec.pipeline
        if not _kind_has_translation(layer.kind)
    ]
    if untranslatable:
        return False, [
            f"layer kinds {untranslatable} have no dispatcher translation "
            f"(supported: {sorted(_SUPPORTED_KINDS)})"
        ]
    return True, []


def hand_cipher_core_fallback(
    payload: Mapping[str, Any],
    *,
    n_target: int = 5,
    family_label: str = "bench_hand_cipher_core",
) -> list[TheoryRecord]:
    """Return a list of validated, dispatchable bench-mode theories.

    The function emits at least ``n_target`` ``TheoryRecord`` objects
    (each with a populated ``dsl_spec`` field) drawn from the
    challenge's clue pack and the safe default keyword pool. Every
    returned record's ``dsl_spec`` has been verified against
    ``validate_hypothesis_spec`` AND every layer kind has a dispatcher
    translation; the controller can dispatch any of them without
    additional gating.

    Args:
        payload: ``ControllerConfig.bench_challenge_payload`` (the dict
            shape produced by ``K4BenchChallenge.canonical_facts``).
            Must carry ``clue_text`` and ideally ``title`` and
            ``bench_id``; missing fields fall back to the default
            keyword pool.
        n_target: Minimum number of theories to return. The fallback
            emits as many as the catalogue holds (currently 13);
            ``n_target`` is a *floor*, not a cap. The caller usually
            sets this to ``ControllerConfig.theories_per_cycle``.
        family_label: ``TheoryRecord.family`` value to assign. Defaults
            to ``"bench_hand_cipher_core"`` so bench fallback theories
            are easy to filter in the ledger and don't collide with
            the real-K4 family-registry IDs (which the bench-mode
            ProblemContext refuses to consult anyway).

    Returns:
        A list of ``TheoryRecord`` objects, length >= ``n_target``
        whenever the catalogue has at least that many valid specs.
        The list is empty only if every catalogue spec failed
        validation, which would indicate a kernel/DSL contract drift
        — the caller should treat empty as a halt condition.

    The function is pure with respect to its inputs: the same payload
    produces the same theories every call. No I/O, no SDK, no kernel
    dispatch — just spec construction + DSL validation.
    """
    catalog = _build_catalog(payload)
    bench_id = payload.get("bench_id") or payload.get("title") or "K4Bench"

    theories: list[TheoryRecord] = []
    rejected: list[tuple[str, list[str]]] = []
    for slug, raw_spec in catalog:
        ok, errors = _spec_passes_validation(raw_spec)
        if not ok:
            rejected.append((slug, errors))
            continue
        # Build TheoryRecord. Note: hypothesis_id mirrors the spec's id
        # so the ledger's hypothesis-id-as-primary-key invariant holds
        # and dispatch logs can be cross-referenced by id.
        layer_kinds = [
            layer["kind"] for layer in raw_spec["pipeline"]
        ]
        layer_summary = "+".join(layer_kinds)
        theory = TheoryRecord(
            hypothesis_id=slug,
            title=f"HandCipherCore fallback: {layer_summary}",
            core_claim=(
                f"K4Bench challenge {bench_id} can be decrypted by a "
                f"hand-executable {layer_summary} pipeline using clue-"
                "derived key material."
            ),
            mechanism=(
                f"Apply layers {layer_kinds} in declared order; key "
                "material drawn from the challenge clue pack and the "
                "project-safe default keyword pool."
            ),
            family=family_label,
            kill_criteria=[
                "All emitted parameter combinations produce crib_score < 10",
                "Bean constraints violated for every parameter combination",
            ],
            expected_signal="crib_score >= 10 with Bean PASS",
            compute_cost_estimate="low",
            minimal_test_spec={
                "method": "bench_hand_cipher_core",
                "parameters": {
                    "layers": layer_kinds,
                    "bench_id": str(bench_id),
                },
            },
            dsl_spec=raw_spec,
            origin="programmatic_fallback",
        )
        theories.append(theory)

    if rejected:
        logger.info(
            "bench_fallback dropped %d/%d catalogue specs at validation: %s",
            len(rejected), len(catalog),
            "; ".join(f"{slug}={errs[0]}" for slug, errs in rejected[:3]),
        )

    if len(theories) < n_target:
        logger.warning(
            "bench_fallback emitted %d theories below n_target=%d "
            "(catalogue=%d, rejected=%d)",
            len(theories), n_target, len(catalog), len(rejected),
        )

    return theories


__all__ = [
    "hand_cipher_core_fallback",
    "_extract_clue_keywords",
    "_resolve_keyword_pool",
]
