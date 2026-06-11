"""Deterministic clue-bounded solver for K4-shaped challenges.

The controller's documented failure mode (project_controller_solver_gap_2026_05_31)
is that it leaned on an LLM theorist to GUESS one exact composition. The LLM is
reliable at one thing — extracting the clue INGREDIENTS — and unreliable at the
other — authoring a correct, complete sweep. This module splits that labor:

    extract_ingredients()   # deterministic: keywords, families, numbers, alphabets
    build_sweep_specs()     # deterministic: bounded ParamRange sweep HypothesisSpecs
    solve()                 # dispatch each sweep via the fast kernel path; pick best
                            # and escalate (widen) until solved or budget is spent

No LLM is in the solve loop, and no challenge answer is hardcoded: the solution
is *discovered* by sweeping the clue-derived ingredients and scoring against the
known cribs through ``job_dispatcher.execute``.
"""

from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from .bench_fallback import _extract_clue_keywords
from .hypothesis_dsl import HypothesisSpec, CipherLayer, ParamRange, NullBaselineSpec
from .job_dispatcher import execute

# Candidate primitives the solver sweeps when the clue does not name the cipher.
# Ordered by corpus frequency (columnar+substitution dominate the K4Bench set).
_TRANSPOSITION_FAMILIES = (
    "columnar", "rail_fence", "reverse_blocks", "route_boustrophedon",
    "route_diagonal", "skip_route",
)
_SUBSTITUTION_FAMILIES = ("vigenere", "beaufort", "variant_beaufort", "atbash", "caesar")
_KEYWORD_SUBSTITUTIONS = frozenset({"vigenere", "beaufort", "variant_beaufort"})

_DEFAULT_BLOCK_SIZES = (4, 6, 7, 9)
_DEFAULT_ROUTE_WIDTHS = (6, 7, 8, 9, 10, 11)
_DEFAULT_SKIP_STEPS = (2, 3, 5, 7, 9, 11, 13)
_DEFAULT_SKIP_OFFSETS = (0, 1, 2, 3, 4)
_MAX_SPEC_CARDINALITY = 2000  # drop combos that exceed this (auto-bounds sweeps)

_NUMBER_WORDS = {
    "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15,
}

_MAX_KEYWORDS = 6           # cap the keyword sweep so cardinality stays bounded
_DEFAULT_RAIL_DEPTHS = (3, 4, 5, 7)


@dataclass
class Ingredients:
    keywords: list[str]
    families: list[str]
    number_hints: list[int]
    layer_count_range: tuple[int, int]
    alphabets: list[str]


@dataclass
class SolveResult:
    solved: bool
    best_score: int
    n_cribs: int
    best_config: Optional[dict] = None
    best_spec_id: Optional[str] = None
    specs_tried: int = 0
    configs_tried: int = 0
    rounds: int = 0
    history: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Ingredient extraction (deterministic)
# ---------------------------------------------------------------------------

def _parse_numbers(text: str) -> list[int]:
    nums: list[int] = []
    for tok in re.findall(r"\d+", text):
        try:
            n = int(tok)
            if 2 <= n <= 30:
                nums.append(n)
        except ValueError:
            pass
    low = text.lower()
    for word, val in _NUMBER_WORDS.items():
        if re.search(rf"\b{word}\b", low):
            nums.append(val)
    # de-dup preserving order
    seen: set[int] = set()
    out: list[int] = []
    for n in nums:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _parse_layer_count_range(constraint_summary: tuple[str, ...]) -> tuple[int, int]:
    blob = " ".join(constraint_summary).lower()
    # explicit digit range "2 to 3" / "between 2 and 3"
    m = re.search(r"(\d+)\s*(?:to|and|-|through)\s*(\d+)", blob)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if 1 <= lo <= hi <= 5:
            return (lo, hi)
    # english "two and three" / "between two and three"
    words = [w for w in _NUMBER_WORDS if re.search(rf"\b{w}\b", blob)]
    vals = sorted({_NUMBER_WORDS[w] for w in words if _NUMBER_WORDS[w] <= 5})
    if len(vals) >= 2:
        return (vals[0], vals[-1])
    return (2, 3)


def extract_ingredients(
    *,
    clue_text: str,
    title: str = "",
    constraint_summary: tuple[str, ...] = (),
) -> Ingredients:
    """Deterministically mine the clue pack into solver ingredients."""
    keywords = _extract_clue_keywords({"clue_text": clue_text, "title": title})
    keywords = keywords[:_MAX_KEYWORDS]

    number_hints = _parse_numbers(clue_text)
    blob = f"{clue_text} {' '.join(constraint_summary)}".lower()

    # Candidate family set: the clue rarely names the cipher, so sweep the
    # dominant primitives. Clue hints only ADD specificity, never prune the
    # core set (false pruning is how a giveaway gets missed).
    families = list(_TRANSPOSITION_FAMILIES) + list(_SUBSTITUTION_FAMILIES)
    if "route" in blob or "spiral" in blob or "diagonal" in blob:
        families.append("route")

    # Always sweep AZ + KA on substitution layers: KRYPTOS-strip challenges are
    # common and KA is cheap (it only multiplies the keyword-substitution specs).
    alphabets = ["AZ", "KA"]

    return Ingredients(
        keywords=keywords,
        families=families,
        number_hints=number_hints,
        layer_count_range=_parse_layer_count_range(constraint_summary),
        alphabets=alphabets,
    )


# ---------------------------------------------------------------------------
# 2. Bounded sweep-spec construction (deterministic)
# ---------------------------------------------------------------------------

def _null_baseline() -> NullBaselineSpec:
    # Small n_samples: the solver gates on crib_score, not p-value precision.
    return NullBaselineSpec(method="shuffled_ct", n_samples=64)


# Alignments the solver will author. post_transposition is deliberately
# excluded: the solver's decrypt pipelines already physically undo the outer
# layer, so anchored scoring of the final PT gives the identical crib_score as
# direct_positional — re-running under that label adds no crib information.
# "free" is the genuinely distinct surface (cribs matched anywhere; presence
# point-values {0,11,13,24}, only comparable to free-matched nulls).
_SOLVER_ALIGNMENTS = ("direct_positional", "free")


def _bundle_for(crib_alignment: str) -> list[str]:
    if crib_alignment == "free":
        # Convention bundle matches f_free_alignment_classical_2026_06_10:
        # non-direct, detection-level free matching on a length-97 stream.
        return [
            "az_a0", "transposed", "no_null_mask", "non_direct_alignment",
            "crib_alignment_free_detection_level", "fixed_len_97_stream",
        ]
    return ["ct97_direct_positional", "az_a0", "no_null_mask"]


def _spec(
    hyp_id: str, pipeline: list[CipherLayer], *,
    crib_alignment: str = "direct_positional",
) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hyp_id,
        pipeline=pipeline,
        crib_alignment=crib_alignment,
        scoring="crib_plus_bean",
        null_baseline=_null_baseline(),
        compute_budget_cpu_minutes=10,
        assumption_bundle=_bundle_for(crib_alignment),
    )


def _sub_layer(family: str, ing: Ingredients, alphabet: str) -> CipherLayer:
    if family == "atbash":
        return CipherLayer(kind="atbash", alphabet="AZ", params=[])
    if family == "caesar":
        # caesar translator requires AZ; sweep the full shift space (cheap).
        return CipherLayer(
            kind="caesar", alphabet="AZ",
            params=[ParamRange(name="shift", values=list(range(1, 26)))],
        )
    return CipherLayer(
        kind=family, alphabet=alphabet,
        params=[ParamRange(name="keyword", values=list(ing.keywords))],
    )


def _trans_layer(family: str, ing: Ingredients) -> CipherLayer:
    if family == "columnar":
        # keyword-derived width + col_order (no hand-authored permutation)
        return CipherLayer(
            kind="columnar", alphabet="AZ",
            params=[ParamRange(name="keyword", values=list(ing.keywords))],
        )
    if family == "rail_fence":
        depths = sorted({d for d in (list(ing.number_hints) + list(_DEFAULT_RAIL_DEPTHS)) if 2 <= d < 49})
        return CipherLayer(
            kind="rail_fence", alphabet="AZ",
            params=[ParamRange(name="depth", values=depths)],
        )
    if family == "reverse_blocks":
        sizes = sorted({b for b in (list(ing.number_hints) + list(_DEFAULT_BLOCK_SIZES)) if 2 <= b <= 12})
        return CipherLayer(
            kind="reverse_blocks", alphabet="AZ",
            params=[ParamRange(name="block_size", values=sizes)],
        )
    if family == "route_boustrophedon":
        widths = sorted({w for w in (list(ing.number_hints) + list(_DEFAULT_ROUTE_WIDTHS)) if 2 <= w < 49})
        return CipherLayer(
            kind="route_boustrophedon", alphabet="AZ",
            params=[ParamRange(name="width", values=widths)],
        )
    if family == "route_diagonal":
        widths = sorted({w for w in (list(ing.number_hints) + list(_DEFAULT_ROUTE_WIDTHS)) if 2 <= w < 49})
        return CipherLayer(
            kind="route", alphabet="AZ",
            params=[ParamRange(name="variant", values=["diagonal_canonical"]),
                    ParamRange(name="width", values=widths)],
        )
    if family == "skip_route":
        steps = sorted({s for s in (list(ing.number_hints) + list(_DEFAULT_SKIP_STEPS)) if 2 <= s < 49})
        offsets = sorted({o for o in (list(ing.number_hints) + list(_DEFAULT_SKIP_OFFSETS)) if 0 <= o < 20})
        return CipherLayer(
            kind="skip_route", alphabet="AZ",
            params=[ParamRange(name="step", values=steps),
                    ParamRange(name="offset", values=offsets)],
        )
    raise ValueError(f"unsupported transposition family {family!r}")


def _sub_variants(ing: Ingredients) -> list[tuple[str, str]]:
    """(family, alphabet) substitution variants to sweep.

    Keyword substitutions get every candidate alphabet; atbash and caesar are
    AZ-only (their translators ignore / require AZ).
    """
    variants: list[tuple[str, str]] = []
    for sf in ing.families:
        if sf not in _SUBSTITUTION_FAMILIES:
            continue
        if sf in _KEYWORD_SUBSTITUTIONS:
            for alph in ing.alphabets:
                variants.append((sf, alph))
        else:  # atbash, caesar
            variants.append((sf, "AZ"))
    return variants


def _two_layer_specs(
    ing: Ingredients, *, crib_alignment: str = "direct_positional"
) -> list[HypothesisSpec]:
    """Two-layer transposition+substitution sweeps, both decrypt orders."""
    specs: list[HypothesisSpec] = []
    mark = "" if crib_alignment == "direct_positional" else f"-{crib_alignment}"
    trans_families = [f for f in ing.families if f in _TRANSPOSITION_FAMILIES]
    for tf in trans_families:
        for sf, alphabet in _sub_variants(ing):
            tag = f"{tf}-{sf}-{alphabet}".lower()
            specs.append(_spec(f"solver-{tag}-subfirst{mark}",
                               [_sub_layer(sf, ing, alphabet), _trans_layer(tf, ing)],
                               crib_alignment=crib_alignment))
            specs.append(_spec(f"solver-{tag}-transfirst{mark}",
                               [_trans_layer(tf, ing), _sub_layer(sf, ing, alphabet)],
                               crib_alignment=crib_alignment))
    return specs


def _three_layer_specs(
    ing: Ingredients, *, crib_alignment: str = "direct_positional"
) -> list[HypothesisSpec]:
    """Three-layer sweeps: two transpositions + one substitution.

    Covers the dominant gold structure (two transpositions composed with a
    substitution). Emits the substitution OUTERMOST (encryption = trans,trans,
    sub) and MIDDLE (encryption = trans,sub,trans) in decrypt order, over every
    ordered pair of distinct transposition families. Sub innermost is rare and
    omitted to keep the spec count bounded.
    """
    import itertools

    specs: list[HypothesisSpec] = []
    mark = "" if crib_alignment == "direct_positional" else f"-{crib_alignment}"
    trans_families = [f for f in ing.families if f in _TRANSPOSITION_FAMILIES]
    for t1, t2 in itertools.permutations(trans_families, 2):
        for sf, alphabet in _sub_variants(ing):
            tag = f"{t1}-{t2}-{sf}-{alphabet}".lower()
            specs.append(_spec(
                f"solver3-{tag}-subouter{mark}",
                [_sub_layer(sf, ing, alphabet), _trans_layer(t1, ing), _trans_layer(t2, ing)],
                crib_alignment=crib_alignment,
            ))
            specs.append(_spec(
                f"solver3-{tag}-submid{mark}",
                [_trans_layer(t1, ing), _sub_layer(sf, ing, alphabet), _trans_layer(t2, ing)],
                crib_alignment=crib_alignment,
            ))
    return specs


def build_sweep_specs(
    ing: Ingredients, *, text_length: int = 97, round_idx: int = 0,
    crib_alignment: str = "direct_positional",
) -> list[HypothesisSpec]:
    """Build bounded ParamRange sweep specs over the clue-bounded space.

    round_idx 0 -> two-layer transposition+substitution (both orders).
    round_idx >=1 -> three-layer (two transpositions + one substitution).
    Layer order, keyword->layer assignment, variant, alphabet, width/depth/
    block-size are all SWEPT rather than guessed.

    crib_alignment must be in _SOLVER_ALIGNMENTS (see the note there for why
    post_transposition is excluded).
    """
    if crib_alignment not in _SOLVER_ALIGNMENTS:
        raise ValueError(
            f"crib_alignment {crib_alignment!r} not supported by the solver; "
            f"expected one of {_SOLVER_ALIGNMENTS}"
        )
    if not ing.keywords:
        return []
    specs = (
        _two_layer_specs(ing, crib_alignment=crib_alignment)
        if round_idx <= 0
        else _three_layer_specs(ing, crib_alignment=crib_alignment)
    )
    # Drop combos whose product exceeds the cap (e.g. caesar x skip_route x
    # trans). The bounded combos still cover the clue-bounded space; this keeps
    # every dispatched spec fast and within the dispatcher's budget gate.
    return [s for s in specs if s.expected_cardinality() <= _MAX_SPEC_CARDINALITY]


# ---------------------------------------------------------------------------
# 3. Solve loop (dispatch + select + escalate; no LLM, no human)
# ---------------------------------------------------------------------------

def _dispatch_one_spec(spec: HypothesisSpec, ciphertext: str, crib_dict: dict[int, str]):
    """Dispatch ONE spec serially (no inner pool) — a process-pool worker.

    ``parallel=False`` suppresses execute()'s own multiprocessing pool so the
    only parallelism is ACROSS specs (one level, no nesting). ``store_threshold``
    is set high so the solver never writes candidates to the ledger/artifacts.
    Returns a lightweight, picklable tuple.

    Routing: free-alignment specs dispatch through the REAL-K4 path (no
    challenge args) because the challenge scoring branch has no free matcher —
    it scores anchored regardless of the spec's crib_alignment. The real path
    routes free to score_candidate_free (Lever B1). Guarded: free + a
    non-kernel ciphertext would silently score anchored, so it fails loudly.
    """
    if spec.crib_alignment == "free":
        from kryptos.kernel import constants as C

        if ciphertext != C.CT:
            raise ValueError(
                "free-alignment dispatch is real-K4 only: the challenge "
                "scoring path has no free matcher (scores anchored)"
            )
        result = execute(spec, parallel=False, store_threshold=999)
    else:
        result = execute(
            spec, bench_mode=True, parallel=False, store_threshold=999,
            challenge_ciphertext=ciphertext, challenge_crib_dict=crib_dict,
        )
    cand = result.best_candidate
    score = int(cand.get("crib_score", 0)) if cand else 0
    return score, cand, spec.hypothesis_id, int(result.total_tested or 0)


def _solver_workers(workers: Optional[int]) -> int:
    if workers is not None:
        return max(1, workers)
    n = max(1, (os.cpu_count() or 2) - 2)
    if os.getenv("PYTEST_CURRENT_TEST"):  # avoid xdist oversubscription in tests
        n = min(n, 4)
    return n


def _dispatch_best(
    specs: list[HypothesisSpec], ciphertext: str, crib_dict: dict[int, str],
    *, workers: Optional[int] = None, per_spec_timeout: float = 180.0,
    parallel: bool = True,
):
    """Dispatch every spec; reduce to the best crib_score.

    parallel=True (default): fan specs across a process pool (28-core), for the
    standalone solver. parallel=False: dispatch serially in-process — REQUIRED
    when called from an async/threaded context (e.g. the controller's in-loop
    MCP tool handler), where forking a pool is unsafe. A hung spec is skipped.
    """
    if not specs:
        return 0, None, None, 0
    best_score, best_config, best_spec_id, configs = 0, None, None, 0
    if not parallel:
        for spec in specs:
            try:
                score, cand, spec_id, tested = _dispatch_one_spec(spec, ciphertext, crib_dict)
            except Exception:
                continue
            configs += tested
            if score > best_score:
                best_score, best_config, best_spec_id = score, cand, spec_id
        return best_score, best_config, best_spec_id, configs
    n = _solver_workers(workers)
    with ProcessPoolExecutor(max_workers=n) as pool:
        futures = {
            pool.submit(_dispatch_one_spec, spec, ciphertext, crib_dict): spec
            for spec in specs
        }
        for fut in as_completed(futures):
            try:
                score, cand, spec_id, tested = fut.result(timeout=per_spec_timeout)
            except Exception:
                continue  # hung/failed spec — skip, don't stall the solve
            configs += tested
            if score > best_score:
                best_score, best_config, best_spec_id = score, cand, spec_id
    return best_score, best_config, best_spec_id, configs


def _escalate(ing: Ingredients, round_idx: int) -> Ingredients:
    """Widen the search deterministically for the next round (no human).

    Round 0 already sweeps all 2-layer families over AZ+KA. Escalation rounds
    add 3-layer compositions (handled in build_sweep_specs via the round index).
    For now this is a no-op passthrough; 3-layer breadth is a planned round.
    """
    return ing


def solve(
    *,
    ciphertext: str,
    crib_dict: dict[int, str],
    clue_text: str,
    title: str = "",
    constraint_summary: tuple[str, ...] = (),
    max_rounds: int = 1,
) -> SolveResult:
    """Autonomously attempt a clue-bounded solve. No human, no LLM in the loop."""
    ing = extract_ingredients(
        clue_text=clue_text, title=title, constraint_summary=constraint_summary,
    )
    return _solve_loop(ciphertext, crib_dict, ing, max_rounds=max_rounds)


def _solve_loop(
    ciphertext: str, crib_dict: dict[int, str], ing: Ingredients, *,
    max_rounds: int, crib_alignment: str = "direct_positional",
) -> SolveResult:
    n_cribs = len(crib_dict)
    history: list[dict] = []
    best_score, best_config, best_spec_id, total_configs, total_specs = 0, None, None, 0, 0

    # Quiet the dispatcher's per-spec INFO logging for the duration of the solve
    # (otherwise each of the hundreds of swept specs prints an "admissibility:"
    # line, ×forked workers, burying the report). Scoped + restored; set BEFORE
    # the pool forks so workers inherit it.
    _disp_logger = logging.getLogger("kryptosbot.job_dispatcher")
    _prev_level = _disp_logger.level
    _disp_logger.setLevel(logging.WARNING)
    try:
        for rnd in range(max_rounds):
            ing = _escalate(ing, rnd)
            specs = build_sweep_specs(
                ing, text_length=len(ciphertext), round_idx=rnd,
                crib_alignment=crib_alignment,
            )
            total_specs += len(specs)
            score, config, spec_id, configs = _dispatch_best(specs, ciphertext, crib_dict)
            total_configs += configs
            history.append({"round": rnd, "specs": len(specs), "configs": configs, "best": score})
            if score > best_score:
                best_score, best_config, best_spec_id = score, config, spec_id
            tag = " — SOLVED" if best_score >= n_cribs else ""
            print(
                f"  [solver] round {rnd}: {len(specs)} specs / {configs} configs "
                f"dispatched, best {best_score}/{n_cribs}{tag}",
                flush=True,
            )
            if best_score >= n_cribs:
                break
    finally:
        _disp_logger.setLevel(_prev_level)

    return SolveResult(
        solved=best_score >= n_cribs,
        best_score=best_score,
        n_cribs=n_cribs,
        best_config=best_config,
        best_spec_id=best_spec_id,
        specs_tried=total_specs,
        configs_tried=total_configs,
        rounds=len(history),
        history=history,
    )


# Curated real-K4 keyword seed (K1/K2 keys, disclosed crib content, attested
# place/object terms). Not exhaustive — the real-K4 search is open; this is the
# bounded-sweep entry, extend via the ``keywords`` argument. Reject
# Sanborn-self-reference terms per feedback_k4_keywords_must_fit_public_art_context.
_K4_KEYWORD_SEED = (
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "LANGLEY",
    "NORTHEAST", "SHADOW", "FORCES", "LUCID", "MEMORY", "IQLUSION",
)


def _k4_ingredients(keywords=None, max_keywords: int = 12) -> Ingredients:
    """Build the real-K4 ingredient set (no clue pack — K4 has none)."""
    kws = list(keywords) if keywords else list(_K4_KEYWORD_SEED)
    kws = [str(k).strip().upper() for k in kws if str(k).strip()]
    return Ingredients(
        keywords=kws[:max_keywords],
        families=list(_TRANSPOSITION_FAMILIES) + list(_SUBSTITUTION_FAMILIES),
        number_hints=[],  # K4 has no clue numbers; family default ranges apply
        layer_count_range=(2, 3),
        alphabets=["AZ", "KA"],
    )


def solve_real_k4(
    *, keywords=None, max_rounds: int = 2, max_keywords: int = 12,
    crib_alignment: str = "direct_positional",
) -> SolveResult:
    """Run the bounded clue-sweep methodology against the REAL K4 kernel.

    The "chance at K4" entry: sweeps the bounded composition space over a
    curated K4 keyword/family set against the carved K4 CT and its disclosed
    cribs (kernel.constants.CRIB_DICT). Honest about scope — a bounded sweep,
    not a guarantee; K4's true space is far larger. Widen via ``keywords`` /
    ``max_keywords`` / ``max_rounds``.

    crib_alignment="free" sweeps the SAME composition universe but matches the
    disclosed cribs ANYWHERE in the candidate PT (score_candidate_free via the
    real-K4 dispatcher path). Free crib scores are presence point-values
    ({0,11,13,24}); never compare them to anchored scores or anchored nulls.
    """
    from kryptos.kernel import constants as C

    if crib_alignment not in _SOLVER_ALIGNMENTS:
        raise ValueError(
            f"crib_alignment {crib_alignment!r} not supported by solve_real_k4; "
            f"expected one of {_SOLVER_ALIGNMENTS}"
        )
    ing = _k4_ingredients(keywords=keywords, max_keywords=max_keywords)
    return _solve_loop(
        C.CT, dict(C.CRIB_DICT), ing, max_rounds=max_rounds,
        crib_alignment=crib_alignment,
    )


def best_verified_finding(findings: list[dict]) -> Optional[dict]:
    """Pick the most authoritative kernel-verified sweep finding.

    Prefers a solve, then the highest crib_score. These findings come from
    ``run_clue_sweep`` (execute() = kernel-verified), so this is trusted ground
    truth — independent of any LLM prose claim.
    """
    if not findings:
        return None
    return max(
        findings,
        key=lambda f: (1 if f.get("solved") else 0, int(f.get("best_score", 0) or 0)),
    )


def run_clue_sweep(
    ciphertext: str,
    crib_dict: dict[int, str],
    *,
    families: list[str],
    keywords: list[str],
    alphabets: tuple[str, ...] = ("AZ", "KA"),
    max_rounds: int = 1,
) -> dict:
    """Test ONE focused clue hypothesis (the LLM's idea) by sweeping its
    bounded parameter space SERIALLY (no process pool — async-safe for the
    in-loop MCP tool). ``families`` is the LLM's chosen composition (e.g.
    ["columnar", "vigenere"]); width/order/alphabet/keyword are swept.

    Returns a small JSON-able dict: best crib_score, recovered plaintext, the
    winning config id, and how many configs were tested. The LLM uses this as a
    calculator to test ideas and iterate — it never hand-authors the sweep.
    """
    kws = [str(k).strip().upper() for k in keywords if str(k).strip()]
    fams = [f for f in families if f in _TRANSPOSITION_FAMILIES or f in _SUBSTITUTION_FAMILIES]
    if not kws or not any(f in _TRANSPOSITION_FAMILIES for f in fams):
        return {"best_score": 0, "best_config": None, "best_spec_id": None,
                "configs": 0, "note": "need >=1 keyword and >=1 transposition family"}
    ing = Ingredients(
        keywords=kws[:_MAX_KEYWORDS],
        families=fams,
        number_hints=[],
        layer_count_range=(2, 3),
        alphabets=list(alphabets),
    )
    n_cribs = len(crib_dict)
    best_score, best_config, best_spec_id, total = 0, None, None, 0
    for rnd in range(max(1, max_rounds)):
        specs = build_sweep_specs(ing, text_length=len(ciphertext), round_idx=rnd)
        s, cand, sid, cfg = _dispatch_best(specs, ciphertext, crib_dict, parallel=False)
        total += cfg
        if s > best_score:
            best_score, best_config, best_spec_id = s, cand, sid
        if best_score >= n_cribs:
            break
    return {
        "best_score": best_score,
        "n_cribs": n_cribs,
        "solved": best_score >= n_cribs,
        "plaintext": (best_config or {}).get("candidate_pt"),
        "best_config_id": (best_config or {}).get("config_id"),
        "best_spec_id": best_spec_id,
        "configs": total,
        "best_config": best_config,
    }


def solve_challenge(challenge, *, max_rounds: int = 2) -> SolveResult:
    """Autonomously solve a challenge object (duck-typed).

    ``challenge`` must expose ``ciphertext``, ``crib_dict`` (Mapping[int,str]),
    ``clue_text``, and optionally ``title`` / ``constraint_summary`` — the shape
    of ``bench_loader.K4BenchChallenge``. This is the controller's no-human
    entry point: it never sees the answer, only the public challenge surface.
    """
    return solve(
        ciphertext=challenge.ciphertext,
        crib_dict=dict(challenge.crib_dict),
        clue_text=getattr(challenge, "clue_text", "") or "",
        title=getattr(challenge, "title", "") or "",
        constraint_summary=tuple(getattr(challenge, "constraint_summary", ()) or ()),
        max_rounds=max_rounds,
    )
