#!/usr/bin/env python3
"""CT-Perturbation Stage A — Hamming-1 sweep CLI.

Preregistered campaign runner for the CT-perturbation hypothesis (Stage A).

Treat the carved 97-character K4 ciphertext as observation, not ground
truth: enumerate every Hamming-1 perturbation and run each through the
periodic additive families (Vigenère / Beaufort / Variant Beaufort) ×
two alphabets (AZ, KA) × a curated keyword pool, with CT-parametric
Bean re-derivation and per-cell scoring.

Stage A scope (binding):
    OUT: running-key, autokey, non-English source text, CorpusLicense,
         multi-layer compositions, position-dependent selectors.

Default behavior is conservative: writing the preregistration manifest
and a tiny smoke subset. Full execution (all 2,425 H1 variants × full
keyword pool) requires the explicit ``--execute-full`` flag.

Usage:
    PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_a.py \\
        --keywords wordlists/thematic_keywords_v2.txt \\
        --workers 26 \\
        --artifact-root results/ct_perturbation_stage_a \\
        --run-id manual_$(date -u +%Y%m%dT%H%M%SZ) \\
        --dry-run
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import logging
import multiprocessing as mp
import os
import random
import re
import sys
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


# Standalone bootstrap (script lives 2 levels deep under repo root).
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


from kryptos.kernel.constants import (  # noqa: E402
    ALPH,
    CRIB_DICT as CANONICAL_CRIB_DICT,
    CT as CANONICAL_CT,
    CT_LEN,
)
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.transforms.vigenere import CipherVariant  # noqa: E402

from kryptosbot.ct_perturbation import (  # noqa: E402
    ARTIFACT_SCHEMA_VERSION,
    AlertPolicy,
    CAMPAIGN_ID,
    CRIB_POSITION_H1_VARIANTS,
    CTVariant,
    CandidateScore,
    H0_VARIANT_COUNT,
    H1_VARIANT_COUNT,
    NONCRIB_POSITION_H1_VARIANTS,
    ScorerContext,
    SUPPORTED_ALPHABET_KINDS,
    SUPPORTED_FAMILIES,
    TopNHeap,
    UniverseDimensions,
    assert_canonical_bean_reproduction,
    canonical_variant,
    ct_position_class,
    ct_variant_position_class_counts,
    decrypt_with_keyword,
    derive_bean_constraints,
    enumerate_hamming1_variants,
    score_candidate_ct_parametric,
)


# ── Logging ──────────────────────────────────────────────────────────────

logger = logging.getLogger("ct_perturbation_stage_a")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


# ── Atomic JSON write ────────────────────────────────────────────────────

def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


# ── Scope guard ──────────────────────────────────────────────────────────
#
# The scope-exclusion contract for Stage A (no running-key, no non-English
# source text, no CorpusLicense paths) is enforced by the test suite at
# tests/test_ct_perturbation_stage_a.py — see TestScopeExclusion. Tests
# verify that this script and kryptosbot/ct_perturbation imports nothing
# from those branches and exposes no parameters that select them.
#
# A runtime regex sweep was tried first but tripped on its own exclusion
# documentation strings; the test-level check is more precise (it inspects
# the actual import graph) and is the canonical guard.


# ── Keyword loading ──────────────────────────────────────────────────────

@dataclass
class KeywordSource:
    """Loaded, normalized, capped keyword list with provenance."""
    path: Path
    raw_line_count: int
    raw_token_count: int
    accepted_before_cap_count: int
    normalized: List[str]
    source_sha256: str
    normalized_sha256: str
    cap: int
    duplicate_count: int = 0
    rejected_count: int = 0
    discarded_examples: List[Dict[str, str]] = field(default_factory=list)

    def to_manifest_dict(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "raw_line_count": self.raw_line_count,
            "raw_token_count": self.raw_token_count,
            "accepted_before_cap_count": self.accepted_before_cap_count,
            "normalized_count": len(self.normalized),
            "deduped_count": self.accepted_before_cap_count,
            "final_count": len(self.normalized),
            "duplicate_count": self.duplicate_count,
            "rejected_count": self.rejected_count,
            "discarded_examples": self.discarded_examples[:20],
            "cap": self.cap,
            "source_sha256": self.source_sha256,
            "normalized_sha256": self.normalized_sha256,
            "keyword_hash": self.normalized_sha256,
            "first_20_normalized_keywords": self.normalized[:20],
            "last_20_normalized_keywords": self.normalized[-20:],
            "normalization_rules": [
                "Strip whitespace per line",
                "Skip blank lines and lines beginning with '#'",
                "Uppercase",
                "Reject any token that is not pure A-Z",
                "Deduplicate preserving first-seen order",
                f"Cap at {self.cap} keywords after deduplication",
            ],
        }


def load_keywords(path: Path, cap: int) -> KeywordSource:
    """Load and normalize keywords. Fails closed if the file is missing
    or contains zero usable tokens."""
    if not path.exists():
        raise FileNotFoundError(
            f"Keyword file {path} not found. Provide a path with --keywords."
        )
    raw = path.read_bytes()
    source_sha = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", errors="strict")
    raw_lines = text.splitlines()
    seen: set = set()
    out: List[str] = []
    all_accepted: List[str] = []
    duplicate_count = 0
    rejected_count = 0
    raw_token_count = 0
    discarded_examples: List[Dict[str, str]] = []
    for line in raw_lines:
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        raw_token_count += 1
        original = token
        token = token.upper()
        if not token.isalpha() or not all(c in ALPH for c in token):
            rejected_count += 1
            if len(discarded_examples) < 20:
                discarded_examples.append({
                    "token": original,
                    "reason": "not pure A-Z after uppercasing",
                })
            continue
        if token in seen:
            duplicate_count += 1
            if len(discarded_examples) < 20:
                discarded_examples.append({
                    "token": original,
                    "reason": "duplicate after normalization",
                })
            continue
        seen.add(token)
        all_accepted.append(token)
    out = all_accepted[:cap]
    for token in all_accepted[cap:cap + max(0, 20 - len(discarded_examples))]:
        discarded_examples.append({
            "token": token,
            "reason": f"beyond post-dedup cap {cap}",
        })
    if not out:
        raise ValueError(
            f"Keyword file {path} produced 0 usable A-Z tokens after "
            f"normalization. The campaign cannot run with an empty pool."
        )
    norm_text = "\n".join(out).encode("utf-8")
    norm_sha = hashlib.sha256(norm_text).hexdigest()
    return KeywordSource(
        path=path,
        raw_line_count=len(raw_lines),
        raw_token_count=raw_token_count,
        accepted_before_cap_count=len(all_accepted),
        normalized=out,
        source_sha256=source_sha,
        normalized_sha256=norm_sha,
        cap=cap,
        duplicate_count=duplicate_count,
        rejected_count=rejected_count,
        discarded_examples=discarded_examples,
    )


# ── Manifest ─────────────────────────────────────────────────────────────

def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_ROOT, capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _module_sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unknown"


def build_preregistration_manifest(
    *,
    run_id: str,
    canonical_ct: str,
    keyword_source: KeywordSource,
    universe: UniverseDimensions,
    policy: AlertPolicy,
    cli_argv: Sequence[str],
    null_status: Dict[str, str],
    h0_baseline_included: bool,
    h1_variants_requested: int,
    h1_variants_executed: int,
    explicit_ct_path: Optional[Path],
) -> Dict[str, Any]:
    h0_variants_executed = H0_VARIANT_COUNT if h0_baseline_included else 0
    position_counts = ct_variant_position_class_counts(
        include_h0=h0_baseline_included,
        h1_variants=h1_variants_executed,
    )
    return {
        "campaign_id": CAMPAIGN_ID,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "run_id": run_id,
        "timestamp_utc": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_commit": _git_commit(),
        "canonical_ct_sha256": hashlib.sha256(canonical_ct.encode()).hexdigest(),
        "canonical_ct_length": len(canonical_ct),
        "ct_source": (
            "canonical (kryptos.kernel.constants.CT carved 97-char observation)"
            if explicit_ct_path is None else f"explicit override: {explicit_ct_path}"
        ),
        "ct_variant_policy": (
            "Hamming-1 single-position substitutions over A-Z, "
            "deterministic order (position ascending, replacement letter "
            "ascending excluding original); optional Hamming-0 baseline."
        ),
        "hamming_distance_set": [0, 1] if h0_baseline_included else [1],
        "max_ct_variants_semantics": (
            "--max-ct-variants is an H1-only cap. H0 is controlled "
            "separately by --include-h0-baseline."
        ),
        "h1_variants_requested": h1_variants_requested,
        "h1_variants_executed": h1_variants_executed,
        "h0_variants_executed": h0_variants_executed,
        "total_ct_variants_executed": universe.ct_variants,
        "number_of_ct_variants": universe.ct_variants,
        "crib_position_h1_variants": position_counts["crib_position_h1_variants"],
        "noncrib_position_h1_variants": position_counts["noncrib_position_h1_variants"],
        "cipher_families": [f.value for f in SUPPORTED_FAMILIES],
        "alphabets": list(SUPPORTED_ALPHABET_KINDS),
        "period_policy": {
            "rule": "period_equals_keyword_length",
            "rationale": (
                "kryptos.kernel.transforms.vigenere.decrypt_text takes a "
                "numeric key whose length is the period; the kernel has "
                "no independent period parameter for these families. "
                "Distinct periods in the universe arise only from the "
                "lengths of the keywords in the curated pool."
            ),
            "is_independent_dimension": False,
        },
        "period_values_observed_in_pool": sorted(set(
            len(kw) for kw in keyword_source.normalized
        )),
        "keyword_source_paths": [str(keyword_source.path)],
        "keyword_list_normalized_sha256": keyword_source.normalized_sha256,
        "keyword_hash": keyword_source.normalized_sha256,
        "keyword_count": len(keyword_source.normalized),
        "config_cardinality_per_ct_variant": universe.per_ct_variant,
        "total_config_cardinality": universe.total,
        "scoring_policy": {
            "crib_score": "kryptos.kernel.scoring.crib_score.score_cribs (PT-only)",
            "bean": (
                "CT-parametric: BEAN_EQ / BEAN_INEQ / BEAN_LINEAR are "
                "RE-DERIVED for each CT variant from the perturbed CT and "
                "canonical cribs (kryptosbot.ct_perturbation.derive_bean_"
                "constraints). Identity-reproduction asserted vs the "
                "kernel's frozen canonical sets for Hamming-0 inputs."
            ),
            "ngram": "kryptos.kernel.scoring.ngram.NgramScorer.score_per_char",
            "ic": "not used in Stage-A scoring",
        },
        "null_policy": {
            "crib_p_raw": "exact Binomial(n=24, p=1/26) right tail",
            "ngram_p_raw": (
                "lookup of "
                "kryptosbot.null_baselines.get_cached('ngram_score', "
                "'random_text', n_chars=97, alphabet) — empirical normal-"
                "approx tail. None when cache missing."
            ),
            "p_combined_raw": (
                "Fisher's combined probability test (chi-square upper tail "
                "with 2k df). None when any input is None."
            ),
            "multiplicity": "Bonferroni over total_config_cardinality",
            "status_at_launch": null_status,
            "require_null_recommendation": (
                "Use --require-null for solution-grade alert runs. "
                "With --allow-null-unavailable, missing alphabet nulls "
                "can produce watchlist_null_unavailable rows but not alerts."
            ),
        },
        "perturbation_penalty_policy": {
            "h1_min_crib_score_watchlist": policy.h1_min_crib_score_watchlist,
            "h1_p_adjusted_threshold": policy.h1_p_adjusted_threshold,
            "h1_ngram_floor": policy.h1_ngram_floor,
            "h1_require_full_cribs": policy.h1_require_full_cribs,
            "h1_require_bean_pass": policy.h1_require_bean_pass,
            "h1_require_ngram_floor": policy.h1_require_ngram_floor,
            "h0_p_adjusted_threshold": policy.h0_p_adjusted_threshold,
            "h0_require_bean_pass": policy.h0_require_bean_pass,
            "rationale": (
                "Hamming-1 candidates carry an extra search dimension "
                "(2425 ways to perturb), so they are held to the strict "
                "alert bar. The H0 baseline is graded against a more "
                "permissive bar because its universe is the keyword "
                "pool only."
            ),
        },
        "alert_policy": policy.to_dict(),
        "alert_class_ladder": [
            "alert (full preregistered bar)",
            "watchlist (crib_score >= 18, fails one or more bar criteria)",
            "watchlist_null_unavailable (nulls missing, suspicious score)",
            "none",
        ],
        "checkpoint_policy": {
            "ct_variant_chunk": "atomic JSON checkpoint after each CT variant",
            "resumable": False,
            "resume_status": "disabled; --resume fails before compute",
        },
        "exclusions": {
            "running_key": "Out of scope by directive 2026-05-01.",
            "non_english_source_text": "Out of scope by directive 2026-05-01.",
            "corpus_license": "Out of scope by directive 2026-05-01.",
            "stage_c_running_key": "Out of scope; Stage C, when implemented, must not include running-key.",
            "multilayer_cipher": "Out of scope for Stage A.",
        },
        "cli_invocation": list(cli_argv),
        "module_versions": {
            "ct_perturbation_module_sha256": _module_sha(
                _ROOT / "kryptosbot" / "ct_perturbation.py"
            ),
            "this_runner_sha256": _module_sha(_HERE),
        },
        "negative_claim_template": (
            "No candidate survived the preregistered thresholds under "
            "Hamming-1 single-character substitutions of the 97-character "
            "carved CT × {Vigenère, Beaufort, Variant Beaufort} × "
            "{AZ, KA} × the curated keyword pool × the specified "
            "CT-parametric scoring and null model."
        ),
    }


def build_universe_manifest(
    *,
    universe: UniverseDimensions,
    include_h0: bool,
    h1_variants_requested: int,
    h1_variants_executed: int,
    keyword_source: Optional[KeywordSource],
) -> Dict[str, Any]:
    h0_variants_executed = H0_VARIANT_COUNT if include_h0 else 0
    position_counts = ct_variant_position_class_counts(
        include_h0=include_h0,
        h1_variants=h1_variants_executed,
    )
    payload = universe.to_dict()
    payload.update({
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "max_ct_variants_semantics": "H1-only; H0 is added separately when requested.",
        "h1_variants_requested": h1_variants_requested,
        "h1_variants_executed": h1_variants_executed,
        "h0_variants_executed": h0_variants_executed,
        "total_ct_variants_executed": universe.ct_variants,
        "crib_position_h1_variants": position_counts["crib_position_h1_variants"],
        "noncrib_position_h1_variants": position_counts["noncrib_position_h1_variants"],
        "full_h1_variant_count": H1_VARIANT_COUNT,
        "full_crib_position_h1_variants": CRIB_POSITION_H1_VARIANTS,
        "full_noncrib_position_h1_variants": NONCRIB_POSITION_H1_VARIANTS,
        "keyword_hash": keyword_source.normalized_sha256 if keyword_source else "empty",
        "period_values": (
            sorted(set(len(kw) for kw in keyword_source.normalized))
            if keyword_source else []
        ),
        "period_values_independent_dimension": None,
        "period_policy": "keyword_length",
        "period_policy_note": (
            "The implemented Stage-A keyword model uses effective period "
            "len(keyword). The original independent period 1-26 proposal "
            "was not implemented or run."
        ),
    })
    return payload


def build_coverage_report(
    *,
    run_id: str,
    universe: UniverseDimensions,
    include_h0: bool,
    h1_variants_executed: int,
    keyword_source: Optional[KeywordSource],
    null_status: Dict[str, str],
    candidates_evaluated: Optional[int] = None,
    bean_pass_total: Optional[int] = None,
) -> Dict[str, Any]:
    position_counts = ct_variant_position_class_counts(
        include_h0=include_h0,
        h1_variants=h1_variants_executed,
    )
    keyword_count = len(keyword_source.normalized) if keyword_source else 0
    return {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "run_id": run_id,
        "scope": {
            "tested_ct_error_type": "Hamming-1 substitution over A-Z plus optional H0 baseline",
            "not_tested": [
                "insertions",
                "deletions",
                "reading-order/transcription reorderings",
                "wrong public crib placement",
                "plaintext clue disclosure errors",
                "running-key",
                "non-English source text",
                "CorpusLicense branches",
                "Stage B / Hamming-2",
                "Stage C / procedural composite search",
                "source-text bijections",
                "independent period 1-26 expansion",
            ],
            "families": [f.value for f in SUPPORTED_FAMILIES],
            "alphabets": list(SUPPORTED_ALPHABET_KINDS),
            "keyword_count": keyword_count,
            "keyword_hash": keyword_source.normalized_sha256 if keyword_source else "empty",
            "period_policy": "keyword_length",
            "period_values": (
                sorted(set(len(kw) for kw in keyword_source.normalized))
                if keyword_source else []
            ),
        },
        "position_class_effect": {
            "crib_positions": sorted(CANONICAL_CRIB_DICT.keys()),
            "crib_position_count": len(CANONICAL_CRIB_DICT),
            "crib_position_h1_variants": position_counts["crib_position_h1_variants"],
            "noncrib_position_h1_variants": position_counts["noncrib_position_h1_variants"],
            "h0_baseline": position_counts["h0_baseline"],
            "full_crib_position_h1_variants": CRIB_POSITION_H1_VARIANTS,
            "full_noncrib_position_h1_variants": NONCRIB_POSITION_H1_VARIANTS,
            "explanation": (
                "Under H1/direct positional crib mapping, only substitutions "
                "at crib positions can change crib-derived keystream and "
                "Bean feasibility. Non-crib substitutions can affect only "
                "downstream plaintext/ngram scoring after a crib/Bean survivor exists."
            ),
        },
        "coverage_matrix": [
            {
                "hypothesis": "H0 canonical additive keyword",
                "covered": bool(include_h0),
                "evidence": "H0 baseline variant included" if include_h0 else "H0 baseline not requested",
                "caveat": "limited to curated keyword list and direct positional cribs",
            },
            {
                "hypothesis": "H1 substitution at crib position",
                "covered": position_counts["crib_position_h1_variants"] > 0,
                "evidence": f"{position_counts['crib_position_h1_variants']} H1 crib-position variants executed",
                "caveat": "full coverage is 600 only when all H1 variants are executed",
            },
            {
                "hypothesis": "H1 substitution outside crib position affecting Bean",
                "covered": False,
                "evidence": "Bean constraints are derived only from fixed crib CT/PT positions",
                "caveat": "non-crib CT changes cannot alter crib/Bean gates under direct positional alignment",
            },
            {
                "hypothesis": "H1 substitution outside crib position affecting ngram after survivor",
                "covered": position_counts["noncrib_position_h1_variants"] > 0,
                "evidence": f"{position_counts['noncrib_position_h1_variants']} non-crib H1 variants executed",
                "caveat": "only meaningful if a candidate survives crib/Bean gates",
            },
            {
                "hypothesis": "H1 insertion/deletion",
                "covered": False,
                "evidence": "variant generator performs substitutions only",
                "caveat": "not Stage A",
            },
            {
                "hypothesis": "H2 archive-anchored substitution",
                "covered": False,
                "evidence": "no Hamming-2 enumerator is exposed",
                "caveat": "Stage B only",
            },
            {
                "hypothesis": "independent period 1-26",
                "covered": False,
                "evidence": "period_policy is keyword_length",
                "caveat": "period-expanded search not implemented",
            },
            {
                "hypothesis": "keyword outside curated list",
                "covered": False,
                "evidence": f"keyword_count={keyword_count}",
                "caveat": "negative evidence applies only to the loaded keyword list",
            },
            {
                "hypothesis": "correct key is not keyword-periodic",
                "covered": False,
                "evidence": "only finite repeated keywords are tested",
                "caveat": "running-key and other non-periodic branches remain out of scope",
            },
            {
                "hypothesis": "outer transposition before direct positional cribs",
                "covered": False,
                "evidence": "crib positions are fixed direct CT/PT coordinates",
                "caveat": "a transposition could invalidate direct crib placement assumptions",
            },
        ],
        "observed_counts": {
            "expected_total_config_cardinality": universe.total,
            "candidates_evaluated": candidates_evaluated,
            "bean_pass_total": bean_pass_total,
        },
        "null_status": null_status,
        "narrow_negative_template": (
            "No Bean-consistent candidate was found under H0 plus all "
            "Hamming-1 single-character substitutions of the 97-character "
            "carved K4 CT, across {Vigenere, Beaufort, Variant Beaufort} "
            "x {AZ, KA} x the curated project list, using direct positional "
            "crib alignment and CT-parametric Bean derivation."
        ),
    }


# ── Sweep core ──────────────────────────────────────────────────────────

@dataclass
class SweepConfig:
    """Internal config bundle for the sweep driver."""
    ct: str
    keywords: List[str]
    families: Tuple[CipherVariant, ...] = SUPPORTED_FAMILIES
    alphabet_kinds: Tuple[str, ...] = SUPPORTED_ALPHABET_KINDS
    universe_size: int = 1
    policy: AlertPolicy = field(default_factory=AlertPolicy)
    include_h0: bool = False
    max_ct_variants: Optional[int] = None
    max_configs: Optional[int] = None
    keyword_limit: Optional[int] = None
    crib_dict: Dict[int, str] = field(default_factory=lambda: dict(CANONICAL_CRIB_DICT))
    run_id_for_logging: str = ""


def _iter_variants(cfg: SweepConfig) -> Iterator[CTVariant]:
    if cfg.include_h0:
        yield canonical_variant(cfg.ct)
    seen = 0
    for v in enumerate_hamming1_variants(cfg.ct):
        yield v
        seen += 1
        if cfg.max_ct_variants is not None and seen >= cfg.max_ct_variants:
            return


def _effective_keywords(cfg: SweepConfig) -> List[str]:
    if cfg.keyword_limit is not None:
        return cfg.keywords[:cfg.keyword_limit]
    return cfg.keywords


@dataclass
class SweepResults:
    candidates_evaluated: int = 0
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    watchlist: List[Dict[str, Any]] = field(default_factory=list)
    top_n: TopNHeap = field(default_factory=lambda: TopNHeap(capacity=100))
    bean_pass_count: int = 0
    by_family_alert_count: Dict[str, int] = field(default_factory=dict)
    by_alphabet_alert_count: Dict[str, int] = field(default_factory=dict)
    rejection_reason_counts: Dict[str, int] = field(default_factory=dict)
    variants_completed: int = 0
    last_completed_variant_id: Optional[str] = None
    errors: List[str] = field(default_factory=list)


@dataclass
class VariantEvalResult:
    variant_id: str
    n_evaluated: int
    alerts: List[Dict[str, Any]]
    watchlist: List[Dict[str, Any]]
    top_candidates: List[Tuple[float, Dict[str, Any]]]
    bean_pass_count: int
    rejection_reason_counts: Dict[str, int]
    trace_rows: List[Dict[str, Any]]


def evaluate_one_variant(
    variant: CTVariant,
    cfg: SweepConfig,
    *,
    ngram_scorer: Any,
    ngram_dist_az: Any,
    ngram_dist_ka: Any,
    trace_first_configs: int = 0,
) -> VariantEvalResult:
    """Evaluate every (family × alphabet × keyword) cell for one variant.

    Returns (n_evaluated, alerts, watchlist_rows, top_candidates_for_heap,
    bean_pass_count). The ``top_candidates_for_heap`` list contains
    ``(score_key, payload)`` tuples for the caller's global heap.
    """
    keywords = _effective_keywords(cfg)
    alerts: List[Dict[str, Any]] = []
    watch: List[Dict[str, Any]] = []
    heap_items: List[Tuple[float, Dict[str, Any]]] = []
    bean_pass = 0
    n_eval = 0
    rejection_counts: Dict[str, int] = {}
    trace_rows: List[Dict[str, Any]] = []

    ctx_by_kind = {
        "AZ": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_az, alphabet_kind="AZ",
        ),
        "KA": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_ka, alphabet_kind="KA",
        ),
    }

    for family in cfg.families:
        for kind in cfg.alphabet_kinds:
            ctx = ctx_by_kind[kind]
            for keyword in keywords:
                if cfg.max_configs is not None and n_eval >= cfg.max_configs:
                    return VariantEvalResult(
                        variant_id=variant.variant_id,
                        n_evaluated=n_eval,
                        alerts=alerts,
                        watchlist=watch,
                        top_candidates=heap_items,
                        bean_pass_count=bean_pass,
                        rejection_reason_counts=rejection_counts,
                        trace_rows=trace_rows,
                    )
                score, pt = score_candidate_ct_parametric(
                    ctx, keyword=keyword, family=family,
                    alphabet_kind=kind, universe_size=cfg.universe_size,
                    policy=cfg.policy, ngram_scorer=ngram_scorer,
                )
                n_eval += 1
                reason = _rejection_reason_bucket(score.rejection_reason)
                rejection_counts[reason] = rejection_counts.get(reason, 0) + 1
                if score.bean_passed:
                    bean_pass += 1
                if len(trace_rows) < trace_first_configs:
                    trace_rows.append({
                        "variant_id": variant.variant_id,
                        "variant_distance": variant.distance,
                        "variant_position_class": ct_position_class(
                            variant.pos, cfg.crib_dict,
                        ),
                        "family": family.value,
                        "alphabet": kind,
                        "keyword": keyword,
                        "effective_keyword_period": len(keyword),
                        "period_policy": "keyword_length",
                        "crib_checked": True,
                        "bean_checked": True,
                        "ngram_checked": ngram_scorer is not None,
                        "rejection_reason": score.rejection_reason,
                        "alert_class": score.alert_class,
                    })

                if score.alert_class in ("alert", "watchlist", "watchlist_null_unavailable"):
                    payload = _candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    if score.alert_class == "alert":
                        alerts.append(payload)
                    else:
                        watch.append(payload)

                # Heap key: prioritize crib_score, then ngram, then -p_adjusted.
                key = float(score.crib_score) * 1000.0 + float(
                    score.ngram_score if score.ngram_score is not None else -10.0
                )
                if score.crib_score >= 10:
                    payload = _candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    heap_items.append((key, payload))

    return VariantEvalResult(
        variant_id=variant.variant_id,
        n_evaluated=n_eval,
        alerts=alerts,
        watchlist=watch,
        top_candidates=heap_items,
        bean_pass_count=bean_pass,
        rejection_reason_counts=rejection_counts,
        trace_rows=trace_rows,
    )


def _rejection_reason_bucket(reason: str) -> str:
    """Normalize rejection reasons so summary counts stay human-auditable."""
    if not reason:
        return "alert"
    reason = re.sub(r"ngram -?\d+(?:\.\d+)? below floor -?\d+(?:\.\d+)?", "ngram below floor", reason)
    reason = re.sub(r"p_adjusted (?:None|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?) above (?:-?\d+(?:\.\d+)?)", "p_adjusted above threshold", reason)
    return reason


def _candidate_row(
    run_id: str,
    variant: CTVariant,
    family: CipherVariant,
    alphabet_kind: str,
    keyword: str,
    score: CandidateScore,
    plaintext: str,
) -> Dict[str, Any]:
    config_id = "|".join([
        variant.variant_id, family.value, alphabet_kind, keyword,
    ])
    return {
        "run_id": run_id,
        "config_id": config_id,
        "variant_id": variant.variant_id,
        "distance": variant.distance,
        "pos": variant.pos,
        "position_class": ct_position_class(variant.pos),
        "old_char": variant.old_char,
        "new_char": variant.new_char,
        "ct_sha256": variant.ct_sha256,
        "family": family.value,
        "alphabet": alphabet_kind,
        "period": len(keyword),
        "effective_keyword_period": len(keyword),
        "period_policy": "keyword_length",
        "keyword": keyword,
        "score": score.to_dict(),
        "plaintext": plaintext,
    }


# ── Driver ──────────────────────────────────────────────────────────────

def run_sweep(
    cfg: SweepConfig,
    *,
    artifact_dir: Path,
    run_id: str,
    workers: int,
    progress_every_n_variants: int = 25,
    run_metadata: Optional[Dict[str, Any]] = None,
    trace_first_configs: int = 0,
) -> SweepResults:
    """Drive the sweep over CT variants. Writes JSONL artifacts and a
    progress checkpoint after each variant. Single-process by default;
    multiprocessing engages when ``workers > 1``.
    """
    cfg.run_id_for_logging = run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    run_metadata = dict(run_metadata or {})

    alerts_path = artifact_dir / "alerts.jsonl"
    watch_path = artifact_dir / "watchlist.jsonl"
    top_path = artifact_dir / "top_candidates.jsonl"
    trace_path = artifact_dir / "trace_first_configs.jsonl"
    progress_path = artifact_dir / "progress.json"
    summary_path = artifact_dir / "summary.json"
    chk_dir = artifact_dir / "checkpoints"
    chk_dir.mkdir(parents=True, exist_ok=True)
    for jsonl_path in (alerts_path, watch_path, top_path):
        jsonl_path.touch(exist_ok=True)
    if trace_first_configs:
        trace_path.write_text("")

    # Pre-build scorer + null distribution lookups once.
    try:
        ngram_scorer = get_default_scorer()
    except FileNotFoundError:
        logger.warning("ngram quadgram file missing; ngram scoring disabled")
        ngram_scorer = None

    try:
        from kryptosbot.null_baselines import get_cached as _get_cached
        ngram_dist_az = _get_cached("ngram_score", "random_text", 97, "AZ")
        ngram_dist_ka = _get_cached("ngram_score", "random_text", 97, "KA")
    except Exception:  # pragma: no cover — defensive
        ngram_dist_az = None
        ngram_dist_ka = None

    logger.info(
        "null cache: ngram_AZ=%s ngram_KA=%s",
        "present" if ngram_dist_az is not None else "missing",
        "present" if ngram_dist_ka is not None else "missing",
    )

    results = SweepResults()

    # Iterate variants. We use a simple in-process loop here; per-variant
    # work is small enough that sub-process granularity at the variant
    # level is the natural unit when workers > 1. For workers == 1 we
    # avoid multiprocessing overhead entirely.
    started_at = time.time()
    started_at_iso = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    variants_total = int(run_metadata.get("total_ct_variants_executed", 0))
    expected_total = int(run_metadata.get("expected_total_config_cardinality", cfg.universe_size))
    trace_remaining = max(0, trace_first_configs)

    def _write_trace(rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        with trace_path.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

    def _merge_variant_result(result: VariantEvalResult) -> None:
        results.candidates_evaluated += result.n_evaluated
        results.bean_pass_count += result.bean_pass_count
        results.variants_completed += 1
        results.last_completed_variant_id = result.variant_id
        for reason, count in result.rejection_reason_counts.items():
            results.rejection_reason_counts[reason] = (
                results.rejection_reason_counts.get(reason, 0) + count
            )
        for row in result.alerts:
            with alerts_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            results.alerts.append(_summary_only(row))
            fam = row["family"]; alpha = row["alphabet"]
            results.by_family_alert_count[fam] = results.by_family_alert_count.get(fam, 0) + 1
            results.by_alphabet_alert_count[alpha] = results.by_alphabet_alert_count.get(alpha, 0) + 1
        for row in result.watchlist:
            with watch_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
            results.watchlist.append(_summary_only(row))
        for key, payload in result.top_candidates:
            results.top_n.push(key, payload)
        _write_trace(result.trace_rows)

    def _process_one(variant: CTVariant, trace_limit: int = 0) -> VariantEvalResult:
        return evaluate_one_variant(
            variant, cfg,
            ngram_scorer=ngram_scorer,
            ngram_dist_az=ngram_dist_az,
            ngram_dist_ka=ngram_dist_ka,
            trace_first_configs=trace_limit,
        )

    _checkpoint(
        progress_path, results, started_at, started_at_iso,
        variants_total=variants_total, expected_total=expected_total,
        workers=workers, status="running",
    )

    try:
        if workers <= 1 or trace_first_configs:
            for variant in _iter_variants(cfg):
                trace_limit = trace_remaining
                result = _process_one(variant, trace_limit=trace_limit)
                if trace_remaining:
                    trace_remaining = max(0, trace_remaining - len(result.trace_rows))
                _merge_variant_result(result)
                if results.variants_completed % progress_every_n_variants == 0:
                    _checkpoint(
                        progress_path, results, started_at, started_at_iso,
                        variants_total=variants_total, expected_total=expected_total,
                        workers=workers, status="running",
                    )
        else:
            # Multiprocessing path: workers receive (variant, cfg) and
            # return the per-variant artefact bundle for the parent to merge.
            with mp.get_context("spawn").Pool(workers) as pool:
                iterable = ((v, cfg) for v in _iter_variants(cfg))
                for result in pool.imap_unordered(
                    _worker_evaluate, iterable, chunksize=1,
                ):
                    _merge_variant_result(result)
                    if results.variants_completed % progress_every_n_variants == 0:
                        _checkpoint(
                            progress_path, results, started_at, started_at_iso,
                            variants_total=variants_total, expected_total=expected_total,
                            workers=workers, status="running",
                        )
    except Exception as exc:
        results.errors.append(f"{type(exc).__name__}: {exc}")
        _checkpoint(
            progress_path, results, started_at, started_at_iso,
            variants_total=variants_total, expected_total=expected_total,
            workers=workers, status="failed",
        )
        summary = _build_summary(
            run_id=run_id,
            results=results,
            started_at=started_at,
            status="failed",
            workers=workers,
            expected_total=expected_total,
            run_metadata=run_metadata,
        )
        atomic_write_json(summary_path, summary)
        raise

    # Finalize artifacts.
    with top_path.open("w", encoding="utf-8") as fh:
        for payload in results.top_n.sorted_payloads():
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    status = "completed" if results.candidates_evaluated == expected_total else "incomplete"
    summary = _build_summary(
        run_id=run_id,
        results=results,
        started_at=started_at,
        status=status,
        workers=workers,
        expected_total=expected_total,
        run_metadata=run_metadata,
    )
    atomic_write_json(summary_path, summary)
    _checkpoint(
        progress_path, results, started_at, started_at_iso,
        variants_total=variants_total, expected_total=expected_total,
        workers=workers, status=status,
    )
    return results


def _build_summary(
    *,
    run_id: str,
    results: SweepResults,
    started_at: float,
    status: str,
    workers: int,
    expected_total: int,
    run_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    wall_time = time.time() - started_at
    configs_per_sec = (
        results.candidates_evaluated / wall_time if wall_time > 0 else 0.0
    )
    summary = {
        "run_id": run_id,
        "campaign_id": CAMPAIGN_ID,
        "status": status,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "canonical_ct_sha256": run_metadata.get("canonical_ct_sha256"),
        "h1_variants_executed": run_metadata.get("h1_variants_executed", 0),
        "h0_variants_executed": run_metadata.get("h0_variants_executed", 0),
        "total_ct_variants_executed": run_metadata.get("total_ct_variants_executed", results.variants_completed),
        "crib_position_h1_variants": run_metadata.get("crib_position_h1_variants", 0),
        "noncrib_position_h1_variants": run_metadata.get("noncrib_position_h1_variants", 0),
        "families": [f.value for f in SUPPORTED_FAMILIES],
        "alphabets": list(SUPPORTED_ALPHABET_KINDS),
        "keyword_count": run_metadata.get("keyword_count", 0),
        "keyword_hash": run_metadata.get("keyword_hash", "empty"),
        "period_policy": "keyword_length",
        "period_values": run_metadata.get("period_values"),
        "expected_total_config_cardinality": expected_total,
        "candidates_evaluated": results.candidates_evaluated,
        "bean_pass_total": results.bean_pass_count,
        "bean_pass_count": results.bean_pass_count,
        "watchlist_total": len(results.watchlist),
        "alerts_total": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "alerts_count": len(results.alerts),
        "rejection_reason_counts": results.rejection_reason_counts,
        "by_family_alert_count": results.by_family_alert_count,
        "by_alphabet_alert_count": results.by_alphabet_alert_count,
        "null_status": run_metadata.get("null_status", {}),
        "null_policy_note": run_metadata.get("null_policy_note"),
        "workers": workers,
        "variants_completed": results.variants_completed,
        "variants_total": run_metadata.get("total_ct_variants_executed", results.variants_completed),
        "configs_evaluated": results.candidates_evaluated,
        "wall_time_sec": wall_time,
        "configs_per_sec": configs_per_sec,
        "estimated_full_wall_time_sec": (
            expected_total / configs_per_sec if configs_per_sec > 0 else None
        ),
        "cpu_count": os.cpu_count(),
        "variant_chunk_size": 1,
        "git_commit": _git_commit(),
        "errors": results.errors,
        "position_class_interpretation": (
            "Only crib-position H1 substitutions can change crib/Bean "
            "feasibility under direct positional crib mapping; non-crib "
            "substitutions affect downstream plaintext/ngram only after "
            "a crib/Bean survivor exists."
        ),
    }
    summary.update({
        k: v for k, v in run_metadata.items()
        if k not in summary and k not in {"null_status"}
    })
    return summary


def _worker_evaluate(args: Tuple[CTVariant, SweepConfig]) -> VariantEvalResult:
    """Multiprocessing worker entry. Imports the heavy pieces lazily."""
    variant, cfg = args
    try:
        ngram_scorer = get_default_scorer()
    except FileNotFoundError:
        ngram_scorer = None
    try:
        from kryptosbot.null_baselines import get_cached as _get_cached
        ngram_dist_az = _get_cached("ngram_score", "random_text", 97, "AZ")
        ngram_dist_ka = _get_cached("ngram_score", "random_text", 97, "KA")
    except Exception:
        ngram_dist_az = None
        ngram_dist_ka = None
    return evaluate_one_variant(
        variant, cfg,
        ngram_scorer=ngram_scorer,
        ngram_dist_az=ngram_dist_az,
        ngram_dist_ka=ngram_dist_ka,
    )


def _summary_only(row: Dict[str, Any]) -> Dict[str, Any]:
    """Compact in-memory copy of a row for the summary artifact."""
    return {
        "variant_id": row["variant_id"],
        "family": row["family"],
        "alphabet": row["alphabet"],
        "keyword": row["keyword"],
        "crib_score": row["score"]["crib_score"],
        "bean_passed": row["score"]["bean_passed"],
        "ngram_score": row["score"]["ngram_score"],
        "p_adjusted": row["score"]["p_adjusted"],
        "alert_class": row["score"]["alert_class"],
    }


def _checkpoint(
    path: Path,
    results: SweepResults,
    started_at: float,
    started_at_iso: str,
    *,
    variants_total: int,
    expected_total: int,
    workers: int,
    status: str,
) -> None:
    updated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "started_at": started_at_iso,
        "updated_at": updated_at,
        "status": status,
        "variants_completed": results.variants_completed,
        "variants_processed": results.variants_completed,
        "variants_total": variants_total,
        "candidates_evaluated": results.candidates_evaluated,
        "expected_total_config_cardinality": expected_total,
        "bean_pass_count": results.bean_pass_count,
        "alerts_count": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "elapsed_seconds": time.time() - started_at,
        "workers": workers,
        "last_completed_variant_id": results.last_completed_variant_id,
        "errors": results.errors,
    }
    atomic_write_json(path, payload)


# ── Synthetic recovery test ─────────────────────────────────────────────

def synthetic_recovery_test(
    *,
    artifact_dir: Path,
    keyword: str = "PALIMPSEST",
    family: CipherVariant = CipherVariant.VIGENERE,
    alphabet_kind: str = "AZ",
    perturb_pos: int = 5,
) -> Dict[str, Any]:
    """Run structural and selective planted-correction recovery tests."""
    from kryptos.kernel.transforms.vigenere import encrypt_text
    from kryptos.kernel.alphabet import AZ as _AZ, KA as _KA

    # Build a 97-char synthetic plaintext that includes both K4 cribs.
    pt = (
        "X" * 21
        + "EASTNORTHEAST"
        + "Y" * (63 - 34)
        + "BERLINCLOCK"
        + "Z" * (CT_LEN - 74)
    )
    assert len(pt) == CT_LEN

    alpha = _AZ if alphabet_kind == "AZ" else _KA
    key = alpha.encode(keyword)
    true_ct = encrypt_text(pt, key, variant=family, alphabet=alpha)
    def _h1_index_for_correction(corrupt_ct: str, pos: int, expected_new: str) -> int:
        rank = 0
        for ch in ALPH:
            if ch == corrupt_ct[pos]:
                continue
            if ch == expected_new:
                return pos * (len(ALPH) - 1) + rank
            rank += 1
        raise ValueError("expected correction not present in H1 alphabet")

    def _case(
        *,
        case_name: str,
        corrupt_pos: int,
        include_h0: bool,
        max_ct_variants: Optional[int],
        kw_pool: List[str],
    ) -> Dict[str, Any]:
        bad_char = "A" if true_ct[corrupt_pos] != "A" else "B"
        corrupt_ct = true_ct[:corrupt_pos] + bad_char + true_ct[corrupt_pos + 1:]
        expected_old = corrupt_ct[corrupt_pos]
        expected_new = true_ct[corrupt_pos]
        if max_ct_variants is None:
            h1_executed = H1_VARIANT_COUNT
        else:
            h1_executed = min(H1_VARIANT_COUNT, max_ct_variants)
        h0_executed = H0_VARIANT_COUNT if include_h0 else 0
        universe_size = (
            (h1_executed + h0_executed)
            * len(SUPPORTED_FAMILIES)
            * len(SUPPORTED_ALPHABET_KINDS)
            * len(kw_pool)
        )
        cfg = SweepConfig(
            ct=corrupt_ct,
            keywords=kw_pool,
            universe_size=universe_size,
            policy=AlertPolicy(
                h1_require_full_cribs=True,
                h1_require_bean_pass=True,
                h1_require_ngram_floor=False,
                h1_p_adjusted_threshold=1.0,
                require_null_for_alert=False,
            ),
            include_h0=include_h0,
            max_ct_variants=max_ct_variants,
        )
        subdir = artifact_dir / f"_synthetic_recovery_{case_name}"
        metadata = {
            "canonical_ct_sha256": hashlib.sha256(corrupt_ct.encode()).hexdigest(),
            "h1_variants_executed": h1_executed,
            "h0_variants_executed": h0_executed,
            "total_ct_variants_executed": h1_executed + h0_executed,
            "expected_total_config_cardinality": universe_size,
            "keyword_count": len(kw_pool),
            "keyword_hash": hashlib.sha256("\n".join(kw_pool).encode()).hexdigest(),
            "period_values": sorted(set(len(kw) for kw in kw_pool)),
            "null_status": {"ngram_AZ": "synthetic_optional", "ngram_KA": "synthetic_optional"},
            **ct_variant_position_class_counts(
                include_h0=include_h0, h1_variants=h1_executed,
            ),
        }
        results = run_sweep(
            cfg, artifact_dir=subdir,
            run_id=f"synthetic_recovery_{case_name}", workers=1,
            progress_every_n_variants=10000,
            run_metadata=metadata,
        )
        alert_path = subdir / "alerts.jsonl"
        matches: List[Dict[str, Any]] = []
        if alert_path.exists():
            for line in alert_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if (row["distance"] == 1
                        and row["pos"] == corrupt_pos
                        and row["old_char"] == expected_old
                        and row["new_char"] == expected_new
                        and row["keyword"] == keyword
                        and row["family"] == family.value
                        and row["alphabet"] == alphabet_kind
                        and row["score"]["crib_score"] == 24
                        and row["score"]["bean_passed"]):
                    matches.append(row)
        return {
            "passed": len(matches) >= 1,
            "case": case_name,
            "keyword_used": keyword,
            "family": family.value,
            "alphabet": alphabet_kind,
            "perturb_pos": corrupt_pos,
            "position_class": ct_position_class(corrupt_pos),
            "expected_old_char": expected_old,
            "expected_new_char": expected_new,
            "matching_alert_count": len(matches),
            "alerts_total": len(results.alerts),
            "watchlist_total": len(results.watchlist),
            "candidates_evaluated": results.candidates_evaluated,
            "bean_pass_total": results.bean_pass_count,
            "true_ct_sha256": hashlib.sha256(true_ct.encode()).hexdigest(),
            "corrupt_ct_sha256": hashlib.sha256(corrupt_ct.encode()).hexdigest(),
            "degeneracy_note": (
                "Synthetic filler is low-information, so many candidates can "
                "satisfy relaxed synthetic alert gates."
                if len(results.alerts) > 100 else ""
            ),
        }

    structural = _case(
        case_name="structural",
        corrupt_pos=perturb_pos,
        include_h0=True,
        max_ct_variants=None,
        kw_pool=[keyword, "OTHER", "DUMMYWORD", "NOISE"],
    )
    selective_pos = 21
    selective_bad = "A" if true_ct[selective_pos] != "A" else "B"
    selective_corrupt = (
        true_ct[:selective_pos] + selective_bad + true_ct[selective_pos + 1:]
    )
    selective_max = _h1_index_for_correction(
        selective_corrupt, selective_pos, true_ct[selective_pos],
    ) + 1
    selective = _case(
        case_name="selective",
        corrupt_pos=selective_pos,
        include_h0=False,
        max_ct_variants=selective_max,
        kw_pool=[keyword, "OTHER", "DUMMYWORD", "NOISE"],
    )

    passed = structural["passed"] and selective["passed"] and selective["alerts_total"] < 100
    report = {
        "passed": passed,
        "structural_recovery": structural,
        "selective_recovery": selective,
        "keyword_used": keyword,
        "family": family.value,
        "alphabet": alphabet_kind,
        "perturb_pos": perturb_pos,
        "expected_old_char": structural["expected_old_char"],
        "expected_new_char": structural["expected_new_char"],
        "matching_alert_count": structural["matching_alert_count"],
        "alerts_total": structural["alerts_total"],
        "candidates_evaluated": structural["candidates_evaluated"],
        "explanation": (
            "structural_recovery preserves the broad planted-correction "
            "test and can be degenerate; selective_recovery corrupts a "
            "crib position and bounds the expected alert count."
        ),
        "true_ct_sha256": hashlib.sha256(true_ct.encode()).hexdigest(),
        "corrupt_ct_sha256": structural["corrupt_ct_sha256"],
    }
    out_path = artifact_dir / "recovery_test_report.json"
    atomic_write_json(out_path, report)
    return report


# ── Artifact audit ──────────────────────────────────────────────────────

REQUIRED_JSON_ARTIFACTS = (
    "preregistration.json",
    "universe_manifest.json",
    "progress.json",
    "summary.json",
    "coverage_report.json",
)
REQUIRED_JSONL_ARTIFACTS = (
    "top_candidates.jsonl",
    "watchlist.jsonl",
    "alerts.jsonl",
)


def _load_json_file(path: Path, errors: List[str]) -> Optional[Dict[str, Any]]:
    if not path.exists():
        errors.append(f"missing {path.name}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path.name} does not parse as JSON: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{path.name} is not a JSON object")
        return None
    return payload


def audit_run_artifacts(artifact_dir: Path) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    parsed_json: Dict[str, Dict[str, Any]] = {}
    parsed_jsonl_counts: Dict[str, int] = {}

    for name in REQUIRED_JSON_ARTIFACTS:
        payload = _load_json_file(artifact_dir / name, errors)
        if payload is not None:
            parsed_json[name] = payload
    for name in REQUIRED_JSONL_ARTIFACTS:
        path = artifact_dir / name
        if not path.exists():
            errors.append(f"missing {name}")
            continue
        count = 0
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"{name}:{lineno} invalid JSONL: {exc}")
            count += 1
        parsed_jsonl_counts[name] = count

    summary = parsed_json.get("summary.json", {})
    universe = parsed_json.get("universe_manifest.json", {})
    prereg = parsed_json.get("preregistration.json", {})
    progress = parsed_json.get("progress.json", {})

    required_summary_fields = (
        "run_id", "campaign_id", "status", "canonical_ct_sha256",
        "h1_variants_executed", "h0_variants_executed",
        "total_ct_variants_executed", "crib_position_h1_variants",
        "noncrib_position_h1_variants", "families", "alphabets",
        "keyword_count", "keyword_hash", "period_policy",
        "expected_total_config_cardinality", "candidates_evaluated",
        "bean_pass_total", "watchlist_total", "alerts_total",
        "rejection_reason_counts", "null_status", "workers",
        "wall_time_sec", "configs_per_sec", "git_commit",
        "artifact_schema_version",
    )
    for field_name in required_summary_fields:
        if field_name not in summary:
            errors.append(f"summary.json missing {field_name}")

    if summary and universe:
        expected = summary.get("expected_total_config_cardinality")
        if expected is None:
            expected = universe.get("total_config_cardinality")
        actual = summary.get("candidates_evaluated")
        if expected is not None and actual is not None and expected != actual:
            errors.append(
                f"expected cardinality {expected} != candidates_evaluated {actual}"
            )
        h1 = summary.get("h1_variants_executed")
        h0 = summary.get("h0_variants_executed")
        total = summary.get("total_ct_variants_executed")
        if None not in (h1, h0, total) and h1 + h0 != total:
            errors.append(f"H1/H0 variant math mismatch: {h1}+{h0}!={total}")
        if h1 is not None:
            include_h0 = bool(h0)
            counts = ct_variant_position_class_counts(
                include_h0=include_h0, h1_variants=int(h1),
            )
            if summary.get("crib_position_h1_variants") != counts["crib_position_h1_variants"]:
                errors.append("crib-position H1 count mismatch")
            if summary.get("noncrib_position_h1_variants") != counts["noncrib_position_h1_variants"]:
                errors.append("non-crib-position H1 count mismatch")

    keyword_manifest = _load_json_file(artifact_dir / "keyword_source_manifest.json", warnings)
    if keyword_manifest and summary:
        if keyword_manifest.get("keyword_hash") != summary.get("keyword_hash"):
            errors.append("keyword hash mismatch between summary and keyword manifest")

    if progress and summary:
        if progress.get("candidates_evaluated") != summary.get("candidates_evaluated"):
            errors.append("progress candidates_evaluated disagrees with summary")
        if progress.get("variants_completed") != summary.get("variants_completed"):
            errors.append("progress variants_completed disagrees with summary")

    if "null_status" not in summary and "null_policy" not in prereg:
        errors.append("null status not recorded")
    if summary.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
        warnings.append("artifact_schema_version is missing or older than current schema")

    recovery_exists = (artifact_dir / "recovery_test_report.json").exists()
    cli_args = prereg.get("cli_invocation", []) if isinstance(prereg, dict) else []
    if any("--synthetic-recovery-test" == arg for arg in cli_args) and not recovery_exists:
        errors.append("synthetic recovery was requested but recovery_test_report.json is missing")

    formula_only_suspect = False
    if summary and progress:
        if (
            summary.get("candidates_evaluated") == summary.get("expected_total_config_cardinality")
            and progress.get("variants_completed", 0) == 0
        ):
            formula_only_suspect = True
            errors.append("formula-only evaluated bug suspected: zero completed variants")

    report = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "artifact_dir": str(artifact_dir),
        "passed": not errors,
        "errors": errors,
        "warnings": warnings,
        "jsonl_counts": parsed_jsonl_counts,
        "summary_run_id": summary.get("run_id"),
        "expected_total_config_cardinality": summary.get("expected_total_config_cardinality"),
        "candidates_evaluated": summary.get("candidates_evaluated"),
        "formula_only_evaluated_suspected": formula_only_suspect,
    }
    atomic_write_json(artifact_dir / "audit_report.json", report)
    return report


def print_audit_report(report: Dict[str, Any]) -> None:
    status = "PASS" if report["passed"] else "FAIL"
    print(f"Stage-A artifact audit: {status}")
    print(f"artifact_dir: {report['artifact_dir']}")
    print(f"run_id: {report.get('summary_run_id')}")
    print(
        "cardinality: "
        f"expected={report.get('expected_total_config_cardinality')} "
        f"evaluated={report.get('candidates_evaluated')}"
    )
    if report["errors"]:
        print("errors:")
        for err in report["errors"]:
            print(f"  - {err}")
    if report["warnings"]:
        print("warnings:")
        for warn in report["warnings"]:
            print(f"  - {warn}")
    print("jsonl_counts:")
    for name, count in sorted(report.get("jsonl_counts", {}).items()):
        print(f"  - {name}: {count}")


# ── CLI ─────────────────────────────────────────────────────────────────

def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ct_perturbation_stage_a.py",
        description=(
            "Stage A of the CT-perturbation campaign for K4. "
            "Default behavior writes manifests + tiny smoke; full "
            "execution requires --execute-full."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--keywords", type=Path, required=False,
                   help="Path to a keyword file (one keyword per line, "
                        "uppercase A-Z). Required for any non-dry run.")
    p.add_argument("--keyword-cap", type=int, default=1000,
                   help="Maximum keywords retained after dedup (cap).")
    p.add_argument("--workers", type=int, default=1,
                   help="Number of worker processes.")
    p.add_argument("--artifact-root", type=Path,
                   default=Path("results") / "ct_perturbation_stage_a",
                   help="Root directory for artifacts (sub-dir per run_id).")
    p.add_argument("--run-id", type=str, default=None,
                   help="Explicit run id (default: auto from UTC).")
    p.add_argument("--ct-path", type=Path, default=None,
                   help="Optional explicit CT file (97 char A-Z). "
                        "Defaults to canonical kryptos.kernel.constants.CT.")
    p.add_argument("--max-ct-variants", type=int, default=None,
                   help="Limit Hamming-1 variants tested (smoke).")
    p.add_argument("--max-configs", type=int, default=None,
                   help="Per-variant cap on (family×alphabet×keyword) cells.")
    p.add_argument("--keyword-limit", type=int, default=None,
                   help="Use only the first K keywords (smoke).")
    p.add_argument("--include-h0-baseline", action="store_true",
                   help="Include the canonical Hamming-0 variant.")
    p.add_argument("--trace-first-configs", type=int, default=0,
                   help="Write trace_first_configs.jsonl with the first N visited configs.")

    null_group = p.add_mutually_exclusive_group()
    null_group.add_argument("--require-null", action="store_true",
                            help="Fail closed if the null cache is missing.")
    null_group.add_argument("--allow-null-unavailable", action="store_true",
                            help="Proceed without nulls; only emit watchlist_null_unavailable alerts.")

    p.add_argument("--synthetic-recovery-test", action="store_true",
                   help="Run the synthetic recovery test first; abort on failure.")
    p.add_argument("--dry-run", action="store_true", default=False,
                   help="Write manifest + manifest only; no candidate evaluation.")
    p.add_argument("--execute-full", action="store_true", default=False,
                   help="REQUIRED to run the full Hamming-1 sweep. "
                        "Without this flag, default behavior is smoke (max-ct-variants=2).")
    p.add_argument("--resume", type=Path, default=None,
                   help="(Reserved) resume from an existing artifact dir's "
                        "checkpoint. Stage A treats variants as the resume "
                        "unit; not yet implemented in this milestone.")
    p.add_argument("--audit-run", type=Path, default=None,
                   help="Audit an existing Stage-A artifact directory and exit.")
    p.add_argument("--verbose", action="store_true", default=False,
                   help="Verbose logging.")
    return p


def _resolve_run_id(arg: Optional[str]) -> str:
    if arg:
        return arg
    return "manual_" + _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _load_explicit_ct(path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    raw = path.read_text(encoding="utf-8").strip().upper()
    if len(raw) != CT_LEN:
        raise ValueError(f"Explicit CT at {path} must be {CT_LEN} chars, got {len(raw)}")
    if not raw.isalpha():
        raise ValueError(f"Explicit CT at {path} must be A-Z only")
    return raw


def _ngram_null_status() -> Dict[str, str]:
    status = {"ngram_AZ": "missing", "ngram_KA": "missing"}
    try:
        from kryptosbot.null_baselines import get_cached as _get_cached
        az = _get_cached("ngram_score", "random_text", 97, "AZ")
        ka = _get_cached("ngram_score", "random_text", 97, "KA")
        status["ngram_AZ"] = "present" if az is not None else "missing"
        status["ngram_KA"] = "present" if ka is not None else "missing"
    except Exception as exc:
        status["ngram_AZ"] = f"error:{type(exc).__name__}"
        status["ngram_KA"] = f"error:{type(exc).__name__}"
    return status


def _null_status_line(status: Dict[str, str]) -> str:
    return f"AZ={status.get('ngram_AZ', 'unknown')} KA={status.get('ngram_KA', 'unknown')}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    if args.audit_run is not None:
        report = audit_run_artifacts(args.audit_run)
        print_audit_report(report)
        return 0 if report["passed"] else 1

    if args.resume is not None:
        raise SystemExit("--resume is not implemented for Stage A; refusing to compute.")

    assert_canonical_bean_reproduction()

    explicit_ct = _load_explicit_ct(args.ct_path)
    ct = explicit_ct if explicit_ct is not None else CANONICAL_CT
    if len(ct) != CT_LEN:
        raise SystemExit(f"CT must be {CT_LEN} chars, got {len(ct)}")

    run_id = _resolve_run_id(args.run_id)
    artifact_dir = args.artifact_root / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)

    # Default conservative behavior: smoke unless --execute-full.
    if not args.execute_full and not args.dry_run:
        if args.max_ct_variants is None:
            args.max_ct_variants = 2
            logger.info("Default smoke mode: capping max-ct-variants=2 "
                        "(use --execute-full for the full sweep)")

    # Keyword load (skip for dry-run if no --keywords given).
    keyword_source: Optional[KeywordSource] = None
    if args.keywords is not None:
        keyword_source = load_keywords(args.keywords, cap=args.keyword_cap)
    elif not args.dry_run:
        raise SystemExit(
            "--keywords PATH is required for any non-dry run. "
            "Pass --dry-run to write manifest only."
        )

    # Synthetic recovery test (independent of main sweep).
    recovery_report: Optional[Dict[str, Any]] = None
    if args.synthetic_recovery_test:
        logger.info("Running synthetic recovery test...")
        recovery_report = synthetic_recovery_test(artifact_dir=artifact_dir)
        logger.info("Synthetic recovery: passed=%s alerts=%d candidates=%d",
                    recovery_report["passed"],
                    recovery_report["matching_alert_count"],
                    recovery_report["candidates_evaluated"])
        if not recovery_report["passed"]:
            logger.error("Synthetic recovery failed; aborting.")
            return 2

    # Cardinality.
    n_keywords = len(keyword_source.normalized) if keyword_source else 0
    if args.keyword_limit is not None:
        n_keywords = min(n_keywords, args.keyword_limit)
    n_h1 = (CT_LEN * (len(ALPH) - 1))
    if args.max_ct_variants is not None:
        n_h1 = min(n_h1, args.max_ct_variants)
    n_h0 = 1 if args.include_h0_baseline else 0
    # ct_variants in the universe counts EVERY CT variant we will
    # actually evaluate (H0 + H1). Bonferroni adjustment is over the
    # full evaluated universe per spec §5.4.
    universe = UniverseDimensions(
        families=len(SUPPORTED_FAMILIES),
        alphabet_kinds=len(SUPPORTED_ALPHABET_KINDS),
        keywords=n_keywords,
        ct_variants=n_h0 + n_h1,
    )

    # Null status reporting.
    null_status = _ngram_null_status()
    if args.require_null and any(v != "present" for v in null_status.values()):
        raise SystemExit(
            "Null cache missing and --require-null was passed. "
            "Run scripts/_infra/calibrate_null_baselines.py to build it, "
            "or pass --allow-null-unavailable."
        )

    policy = AlertPolicy(
        require_null_for_alert=True,
    )
    effective_keyword_list = (
        keyword_source.normalized[:args.keyword_limit]
        if keyword_source and args.keyword_limit is not None
        else (keyword_source.normalized if keyword_source else [])
    )
    h1_requested = H1_VARIANT_COUNT if args.max_ct_variants is None else args.max_ct_variants
    h1_position_counts = ct_variant_position_class_counts(
        include_h0=args.include_h0_baseline,
        h1_variants=n_h1,
    )
    run_metadata = {
        "canonical_ct_sha256": hashlib.sha256(ct.encode()).hexdigest(),
        "h1_variants_requested": h1_requested,
        "h1_variants_executed": n_h1,
        "h0_variants_executed": n_h0,
        "total_ct_variants_executed": n_h0 + n_h1,
        "expected_total_config_cardinality": universe.total,
        "crib_position_h1_variants": h1_position_counts["crib_position_h1_variants"],
        "noncrib_position_h1_variants": h1_position_counts["noncrib_position_h1_variants"],
        "keyword_count": n_keywords,
        "keyword_hash": keyword_source.normalized_sha256 if keyword_source else "empty",
        "period_values": sorted(set(len(kw) for kw in effective_keyword_list)),
        "null_status": null_status,
        "null_policy_note": (
            "KA ngram null missing is irrelevant to a bean_pass_total=0 "
            "Bean-layer negative, but it prevents solution-grade KA alerts; "
            "missing-null candidates are downgraded to watchlist_null_unavailable."
        ),
    }

    # Manifest write (always).
    manifest = build_preregistration_manifest(
        run_id=run_id, canonical_ct=ct,
        keyword_source=keyword_source if keyword_source else KeywordSource(
            path=Path("/dev/null"), raw_line_count=0, raw_token_count=0,
            accepted_before_cap_count=0, normalized=[],
            source_sha256="empty", normalized_sha256="empty", cap=0,
        ),
        universe=universe, policy=policy, cli_argv=(["script"] + list(argv or sys.argv[1:])),
        null_status=null_status,
        h0_baseline_included=args.include_h0_baseline,
        h1_variants_requested=h1_requested,
        h1_variants_executed=n_h1,
        explicit_ct_path=args.ct_path,
    )
    atomic_write_json(artifact_dir / "preregistration.json", manifest)
    if keyword_source:
        atomic_write_json(
            artifact_dir / "keyword_source_manifest.json",
            keyword_source.to_manifest_dict(),
        )
    atomic_write_json(
        artifact_dir / "universe_manifest.json",
        build_universe_manifest(
            universe=universe,
            include_h0=args.include_h0_baseline,
            h1_variants_requested=h1_requested,
            h1_variants_executed=n_h1,
            keyword_source=keyword_source,
        ),
    )
    coverage_report = build_coverage_report(
        run_id=run_id,
        universe=universe,
        include_h0=args.include_h0_baseline,
        h1_variants_executed=n_h1,
        keyword_source=keyword_source,
        null_status=null_status,
    )
    atomic_write_json(
        artifact_dir / "coverage_report.json",
        coverage_report,
    )

    if args.dry_run:
        logger.info("DRY RUN complete. Manifest at %s", artifact_dir / "preregistration.json")
        for jsonl_name in REQUIRED_JSONL_ARTIFACTS:
            (artifact_dir / jsonl_name).touch(exist_ok=True)
        started_at = time.time()
        empty_results = SweepResults()
        dry_summary = _build_summary(
            run_id=run_id,
            results=empty_results,
            started_at=started_at,
            status="completed",
            workers=args.workers,
            expected_total=universe.total,
            run_metadata=run_metadata,
        )
        dry_summary["dry_run"] = True
        dry_summary["manifest_path"] = str(artifact_dir / "preregistration.json")
        atomic_write_json(
            artifact_dir / "summary.json",
            dry_summary,
        )
        atomic_write_json(
            artifact_dir / "progress.json",
            {
                "started_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "updated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": "completed",
                "variants_completed": 0,
                "variants_total": n_h0 + n_h1,
                "candidates_evaluated": 0,
                "expected_total_config_cardinality": universe.total,
                "workers": args.workers,
                "last_completed_variant_id": None,
                "errors": [],
            },
        )
        return 0

    if keyword_source is None:
        raise SystemExit("--keywords is required for non-dry runs.")

    cfg = SweepConfig(
        ct=ct,
        keywords=keyword_source.normalized,
        universe_size=universe.total or 1,
        policy=policy,
        include_h0=args.include_h0_baseline,
        max_ct_variants=args.max_ct_variants,
        max_configs=args.max_configs,
        keyword_limit=args.keyword_limit,
    )

    logger.info(
        "Stage A run %s: h1_variants=%d h0_baseline=%d total_ct_variants=%d keywords=%d total_universe=%d workers=%d",
        run_id, n_h1, n_h0, n_h0 + n_h1, n_keywords, universe.total, args.workers,
    )
    results = run_sweep(
        cfg, artifact_dir=artifact_dir, run_id=run_id, workers=args.workers,
        run_metadata=run_metadata,
        trace_first_configs=args.trace_first_configs,
    )
    coverage_report = build_coverage_report(
        run_id=run_id,
        universe=universe,
        include_h0=args.include_h0_baseline,
        h1_variants_executed=n_h1,
        keyword_source=keyword_source,
        null_status=null_status,
        candidates_evaluated=results.candidates_evaluated,
        bean_pass_total=results.bean_pass_count,
    )
    atomic_write_json(artifact_dir / "coverage_report.json", coverage_report)
    logger.info(
        "Done. evaluated=%d alerts=%d watchlist=%d bean_pass=%d",
        results.candidates_evaluated, len(results.alerts),
        len(results.watchlist), results.bean_pass_count,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
