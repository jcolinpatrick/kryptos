"""
Critic stage for the KryptosBot research controller.

Evaluates proposed theories BEFORE expensive compute. Rejects hypotheses
that are duplicates, contradicted by known facts, underconstrained, or
unlikely to produce actionable information gain.

All decisions are deterministic and based on ledger state + kernel constants.
No API calls. No free-text parsing.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from .models import (
    TheoryRecord, TheoryStatus,
    CriticVerdict, CriticDecision,
    FamilyStatus,
)
from .theory_ledger import TheoryLedger
from .claims_registry import CANONICAL_CLAIMS_BY_ID
from .claim_policy import (
    can_use_as_hard_constraint,
    can_use_as_elimination_basis,
)
from .provenance import EpistemicClass

logger = logging.getLogger("kryptosbot.critic")


# Families proven impossible (tier 1) — structural impossibility
TIER_1_FAMILIES = frozenset({
    "caesar", "affine", "atbash", "bifid",
    "autokey_vigenere", "autokey_beaufort",
    "ct_autokey_vigenere", "ct_autokey_beaufort",
    "quagmire_ii_autokey", "periodic_substitution",
    "rot13",
})

# Families exhaustively searched as single-layer (tier 2)
TIER_2_FAMILIES = frozenset({
    "vigenere", "beaufort", "variant_beaufort",
    "gronsfeld", "porta", "four_square", "gromark",
    "columnar_single", "rail_fence",
})

# Families that are methodological or investigative rather than
# cipher-computational. Theories in these families do not describe a
# decrypt operation; they describe evidence gathering, spatial analysis,
# or cross-sculpture relationships. The hybrid fallback policy routes
# them through the legacy SDK-worker path (worker_role=
# "agent_sdk_non_dsl_category") while cipher theories route through the
# DSL dispatcher. Defined by R3-1 Option γ; landed by R3-0.5-1 for the
# R3-2 cutover to consume. Additions require a separate brief.
NON_DSL_FAMILIES: frozenset[str] = frozenset({
    "geometry",
    "k2_coords",
    "geodetic",
    "antipodes",
    "archive_evidence",
    "crib_analysis",
    "k3_continuity",
})

# Families that name a deferred DSL cipher kind outright. These must not carry
# a supported-kind dsl_spec to bypass the honest unsupported boundary.
#
# B-DSL-expanded (2026-04-22) shrank this set from 5 to 1: rail_fence,
# route, myszkowski, and quagmire all got first-class dispatcher
# translators. key_tape was the last deferred kind; its kernel transform +
# dispatcher translator landed in Tasks 1-9 (2026-05-03). The set is now
# empty — every DSL-valid kind has a translator and no family is deferred.
_DEFERRED_DSL_FAMILY_NAMES: frozenset[str] = frozenset()

# Minimum fields required for a theory to be testable
REQUIRED_FIELDS = {"core_claim", "mechanism", "family"}

# Similarity threshold for deduplication (Jaccard on mechanism + claim words)
SIMILARITY_THRESHOLD = 0.7

_WIDTH_10_RE = re.compile(r"\b(width[\s-]?10|10[\s-]?column)\b", re.IGNORECASE)
_WIDTH_21_RE = re.compile(r"\b(width[\s-]?21|21[\s-]?column)\b", re.IGNORECASE)
_CT73_RE = re.compile(r"\bct73\b|73[\s-]?(?:char|character)", re.IGNORECASE)
_CT97_RE = re.compile(
    r"\bct97\b|97[\s-]?(?:char|character)|full ciphertext|full grid",
    re.IGNORECASE,
)
_AMBIGUOUS_KILL_CRITERIA_RE = re.compile(r"\bquasi-periodic\b", re.IGNORECASE)
_ESCAPE_HATCH_RE = re.compile(
    r"\bfails?\b.*\bsurviv(?:e|es|ing)\b|\bsurviv(?:e|es|ing)\b.*\bfails?\b",
    re.IGNORECASE,
)
_COORDINATE_DELTA_RE = re.compile(
    r"\b(coordinate[-\s]?delta|delta digits|he lied|discrepancy|false[-\s]?vs[-\s]?true)\b",
    re.IGNORECASE,
)
_DIRECT_PERIODIC_KEY_RE = re.compile(
    r"\b(beaufort|vigen(?:e|è)re|variant beaufort|gronsfeld|direct key|raw key|raw digits|identity[-\s]?transposition|no transposition)\b",
    re.IGNORECASE,
)
_PHYSICAL_REASSEMBLY_RE = re.compile(
    r"\b(cut[-\s]?up|cut and rearrange|reassembl(?:e|y)|chunk(?:ed|ing|s)?|strip(?:s)?|tape(?:d)?|splice(?:d)?)\b",
    re.IGNORECASE,
)
_DELIMITER_RE = re.compile(r"\bdelimiter(?:s)?\b|\b[wW][-\s]?delimiter", re.IGNORECASE)
_BOUNDARY_SPEC_RE = re.compile(
    r"\b(boundar(?:y|ies)|split into|fixed[-\s]?length|positions?|indices?|chunk count|max(?:imum)? chunks?|perm(?:utation)? budget)\b",
    re.IGNORECASE,
)
_SEGMENTED_TAPE_RE = re.compile(r"\bsegmented tape\b|\bsegment boundar(?:y|ies)\b", re.IGNORECASE)
_SELF_ENCRYPTING_POSITIONS_RE = re.compile(
    r"\bself[-\s]?encrypting positions?\b|\bpositions? 32 and 73\b|\bzero[-\s]?key positions?\b",
    re.IGNORECASE,
)
_ANCHORED_ALIGNMENT_RE = re.compile(
    r"\b(non[-\s]?sequential tape[-\s]?to[-\s]?message mapping|align(?:ment)?|map(?:ping)?)\b",
    re.IGNORECASE,
)
_KNOWN_CRIB_TARGET_RE = re.compile(
    r"\bknown (?:tape|key) values?\b.*\bknown crib positions?\b|\bknown crib positions?\b.*\bknown (?:tape|key) values?\b",
    re.IGNORECASE,
)

# ── Retired-palette revival matcher ─────────────────────────────────────────
#
# Belt-and-suspenders check for the null_palette_retired claim
# (claim_id: null_palette_retired, retired 2026-04-14). The claim_policy
# gates in claim_policy.py prevent retired claims from being used as hard
# constraints / elimination bases / ranking features, but only if a theory
# is correctly MATCHED to the retired claim_id first. This matcher handles
# the gap: a theorist may propose the retired letter set without using
# the word "palette" or the claim_id verbatim.
#
# Match logic: within a 100-character window of any trigger token
# ("null", "palette", "mask", "filler", "separator"), look for a
# comma/space/brace-delimited set of single uppercase letters. If >= 5 of
# the 7 retired palette letters {B,G,I,K,O,W,Z} appear as single-letter
# tokens in the window, flag as retired-palette revival.
#
# The matcher is INTENTIONALLY loose (5/7 overlap, not exact match) so that
# theorists who propose a single-letter substitution like "swap Z for K" or
# "palette = B,G,K,O,W,Z,X" (one swap) are still caught. False positives
# are acceptable: a legitimate theory that happens to mention 5+ of these
# letters near a stego-related word will hit the matcher and can be
# explicitly routed as a retired-revival for further review.
_RETIRED_PALETTE_LETTERS = frozenset("BGIKOWZ")
_RETIRED_PALETTE_TRIGGER_RE = re.compile(
    r"\b(null|palette|mask|filler|separator|stego|filler character|letter set|letter subset)\b",
    re.IGNORECASE,
)
# Single letter surrounded by non-letter characters (commas, spaces,
# braces, newlines, start/end of string). Case-insensitive on purpose:
# theorist prose will often spell candidate letter sets in lowercase.
_SINGLE_LETTER_TOKEN_RE = re.compile(r"(?:^|[^A-Za-z])([A-Za-z])(?=[^A-Za-z]|$)")


def _detect_retired_palette_revival(text: str) -> Optional[str]:
    """Return a human-readable reason string if the theory text reads as a
    revival of the retired null-palette / null-mask family, else None.

    See module-level comment above for matching logic. This is a
    belt-and-suspenders check against *textual* revival in theorist output;
    the primary retirement infrastructure is the null_palette_retired
    claim in claims_registry.py and the claim_policy.py gates that enforce
    RETIRED_CLAIM semantics.

    Import-level revival (i.e. a module adding
    `from kryptos.kernel.retired import NULL_PALETTE` outside the
    allow-list) is caught by `tests/test_retired_usage.py`, not here.
    The constants themselves moved to `kryptos.kernel.retired` in
    framework maturation Phase 2 (2026-04-20).
    """
    if not text:
        return None
    # Find every position where a trigger token appears.
    triggers = list(_RETIRED_PALETTE_TRIGGER_RE.finditer(text))
    if not triggers:
        return None
    for m in triggers:
        start = max(0, m.start() - 100)
        end = min(len(text), m.end() + 100)
        window = text[start:end]
        # Extract single-letter tokens from the window and normalize them
        # to uppercase so lowercase palette revivals are not missed.
        letters = {
            match.group(1).upper()
            for match in _SINGLE_LETTER_TOKEN_RE.finditer(window)
        }
        overlap = letters & _RETIRED_PALETTE_LETTERS
        if len(overlap) >= 5:
            sorted_overlap = ",".join(sorted(overlap))
            return (
                f"Retired palette revival: theory contains {{{sorted_overlap}}} "
                f"(>=5 of {{B,G,I,K,O,W,Z}}) within 100 characters of "
                f"'{m.group(0).lower()}'. This is the null_palette_retired "
                f"claim (RETIRED 2026-04-14). See "
                f"memory/project_consensus_nulls_epistemic_status_2026_04_14.md."
            )
    return None


# ── CONSENSUS_NULL_POSITIONS revival matcher ────────────────────────────────
#
# Closes the generator leak observed 2026-04-17 (cycles 94-102 of the run
# killed that day): theories kept invoking the 17-position null mask despite
# memory/project_consensus_nulls_epistemic_status_2026_04_14.md flagging it
# as pending retraction. The palette matcher above only catches the 7-letter
# subset {B,G,I,K,O,W,Z}; theories that invoked the position mask without
# naming the letter subset slipped through as red-team CONCERNED and
# dispatched anyway, burning compute on a foundation that has no independent
# verification.
#
# Matches are deliberately narrow to avoid false positives on legitimate
# stego work (which must be able to discuss "null masks" and "null positions"
# in general terms):
#   1. Literal symbol: "CONSENSUS_NULL_POSITIONS" (case-insensitive).
#   2. "17-position null mask" / "17 position null mask" / "17-position mask"
#      near a stego trigger word.
#   3. "consensus null mask" / "consensus null positions" as a phrase.
_CONSENSUS_NULL_MASK_PATTERNS = [
    re.compile(r"\bCONSENSUS[_\s]+NULL[_\s]+POSITIONS?\b", re.IGNORECASE),
    re.compile(r"\b17[-\s]?position[-\s]+(?:null[-\s]+)?mask\b", re.IGNORECASE),
    re.compile(r"\b17[-\s]?position[-\s]+null[-\s]+positions?\b", re.IGNORECASE),
    re.compile(r"\bconsensus[-\s]+null[-\s]+(?:mask|positions?)\b", re.IGNORECASE),
]

# Disclaimer-context check (2026-05-04): the original regex caught any
# mention of "17-position mask" as a revival, including disclaimers like
# "(NOT the retired 17-position mask)" used by personas to explicitly
# distinguish their own non-retired derivation from the retired construct.
# Cycle 203 of long_run 2026-05-03 saw a legitimate keystream-forensics
# proposal (411d202fdf25, "Beaufort-KA finite tape using K1 plaintext...")
# get rejected because its mechanism text said:
#   "...under a preregistered W-position null mask drawn from the
#    W_DELIMITER_SEGMENTS anchor (NOT the retired 17-position mask)."
# This is the OPPOSITE of revival — the persona was being careful. The
# context check below treats matches that fall within a ~50-char window
# preceded by an exclusion phrase as disclaimers rather than revivals.
_DISCLAIMER_CONTEXT_PHRASES = (
    "not the retired",
    "not retired",
    "not the deprecated",
    "not deprecated",
    "without invoking",
    "without the retired",
    "without using the retired",
    "excluding the retired",
    "rather than the retired",
    "instead of the retired",
    "distinct from the retired",
    "separate from the retired",
    "independent of the retired",
    "unlike the retired",
    "superseded by",
    "no longer relying on",
    "(not ",  # parenthetical disclaimer pattern, e.g., "(NOT the retired 17-position mask)"
)


def _is_disclaimer_context(text: str, match_start: int) -> bool:
    """Return True if the match at ``match_start`` is preceded within ~50
    chars by a disclaimer phrase. The window covers parenthetical
    disclaimers ("(NOT the retired 17-position mask)") and inline
    rejections ("which is distinct from the retired 17-position mask").
    Case-insensitive.
    """
    window_start = max(0, match_start - 50)
    preceding = text[window_start:match_start].lower()
    return any(phrase in preceding for phrase in _DISCLAIMER_CONTEXT_PHRASES)


def _detect_consensus_null_positions_revival(text: str) -> Optional[str]:
    """Return a human-readable reason string if the theory text invokes the
    17-position CONSENSUS_NULL_POSITIONS mask, else None.

    The 17-position mask is a pending-retraction construct derived from the
    retired palette hypothesis. It has no independent verification. Per
    memory/project_consensus_nulls_epistemic_status_2026_04_14.md any theory
    that rests on it is building on historical weight, not epistemic support.

    The palette matcher above handles the 7-letter letter-set revival. This
    matcher handles theories that invoke the position mask without the
    letter subset.

    Disclaimer mentions (e.g., "(NOT the retired 17-position mask)") are
    excluded by the context check — these are the OPPOSITE of revival,
    they're personas explicitly distinguishing their own non-retired
    derivation from the retired construct.

    Import-level revival (i.e. a module adding
    `from kryptos.kernel.retired import CONSENSUS_NULL_POSITIONS` outside
    the allow-list) is caught by `tests/test_retired_usage.py`, not here.
    The constant itself moved to `kryptos.kernel.retired` in framework
    maturation Phase 2 (2026-04-20).
    """
    if not text:
        return None
    for pattern in _CONSENSUS_NULL_MASK_PATTERNS:
        m = pattern.search(text)
        if m is not None:
            if _is_disclaimer_context(text, m.start()):
                continue
            return (
                f"CONSENSUS_NULL_POSITIONS revival: theory references "
                f"'{m.group(0)}'. The 17-position null mask is pending "
                f"retraction (derived from the retired palette hypothesis, "
                f"no independent verification). See "
                f"memory/project_consensus_nulls_epistemic_status_2026_04_14.md."
            )
    return None

# NOTE (2026-04-13 Day 3 Pantheon integration): the CT_PERTURBATION_MARKERS
# and BUDGET_MARKERS lexical-rule sets that lived here have been removed.
# The judgment of "is this CT-perturbation-class theory going to spin without
# a budget?" is now handled by the red-team-disprover sibling call invoked
# from controller._red_team_filter, which uses a real adversarial agent
# instead of a hand-rolled marker list. The lexical rule was Option A in
# the original Day 2 fix; red-team is Option C done properly.


class TheoryCritic:
    """
    Evaluates proposed theories against the ledger and known constraints.

    Usage:
        critic = TheoryCritic(ledger)
        verdict = critic.evaluate(theory)
        # verdict.decision is APPROVE, REJECT_*, or DEFER

    K4Bench input mode (2026-04-26): construct with ``bench_mode=True``
    to suppress real-K4 elimination-tier rejections. Spec-shape checks
    (completeness, duplicate, override-duplicate, dsl_untranslatable)
    still fire normally; what's skipped is every check whose evidence
    lives in the real-K4 elimination ledger or registries (TIER_1/TIER_2
    families, FamilyRecord.elimination_tier, retired-palette / consensus-
    null-mask revival, K4-anomaly-keyed prompt-surface scope, K4-specific
    contradictions). The synthetic K4Bench challenge is independent of
    K4; a family eliminated for K4 may still be the right answer for
    the synthetic challenge.
    """

    def __init__(
        self,
        ledger: TheoryLedger,
        *,
        bench_mode: bool = False,
    ) -> None:
        self.ledger = ledger
        self.bench_mode = bench_mode

        # Yield-feedback Phase 1: per-cycle indices injected by the
        # controller before evaluate-batch starts. Defaults to empty so
        # standalone-test construction works.
        self.yield_index: dict[str, "FamilyYieldVerdict"] = {}
        self.prior_subfamilies: dict[str, frozenset[str]] = {}
        self.prior_signatures: dict[str, frozenset[str]] = {}
        from kryptosbot.family_yield import DEFAULT_POLICY
        self.policy = DEFAULT_POLICY

    def evaluate(self, theory: TheoryRecord) -> CriticVerdict:
        """
        Run all critic checks on a theory. Returns a CriticVerdict.

        Checks are ordered from cheapest/most decisive to most expensive,
        with the strongest-reason-first principle:
        1. Completeness check (are required fields present?)
        2. Family elimination check (is this family proven impossible?)
        3. Duplicate detection (is this the same idea we already tested?)
        4. Contradiction check (does this violate known constraints?)
        4.5. Prompt-surface scope check (is the theory falsifiable as
             framed?)
        5. (R3-2) Category-A/C DSL translatability — runs last among
           reject-producing checks so stronger rejection reasons fire
           first (a Tier-1 eliminated cipher-family theory is better
           reported as "eliminated" than as "no DSL spec")
        6. Information gain estimation

        R3-2 note: the DSL-translatability check was placed after the
        existing reject-producing checks intentionally. Tests that
        target prior rejection paths continue to fire on their intended
        code path; Category-C enforcement applies to theories that
        survive every other gate.
        """
        reasons: list[str] = []

        # --- Check 1: Completeness ---
        missing = REQUIRED_FIELDS - {
            f for f in REQUIRED_FIELDS
            if getattr(theory, f, "")
        }
        if missing:
            return CriticVerdict(
                decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                confidence=1.0,
                reasons=[f"Missing required fields: {', '.join(missing)}"],
            )

        # --- Check 2: Family elimination ---
        family_lower = theory.family.lower().replace(" ", "_").replace("/", "_")

        # K4Bench input mode (2026-04-26): every Check-2 gate below is a
        # real-K4 elimination grounded in real-K4 evidence. Skip them
        # under bench_mode so a synthetic K4Bench challenge can dispatch
        # families that K4 happens to have eliminated. Spec-shape checks
        # below (Check 3 onward) still fire.
        if not self.bench_mode:
            # Generic family-tier refusal from the bootstrapped family registry.
            # Runs BEFORE the hardcoded TIER_1/TIER_2 sets so newly-bridged
            # historical eliminations (imported via campaign manifests) are
            # honoured without having to touch this file again. KEEP NARROW:
            # only consults FamilyRecord.elimination_tier, no semantic parsing.
            tier_refusal = self._check_family_tier_eliminated(theory, family_lower)
            if tier_refusal is not None:
                return tier_refusal

            if family_lower in TIER_1_FAMILIES:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_ELIMINATED,
                    confidence=1.0,
                    reasons=[
                        f"Family '{theory.family}' is Tier 1 eliminated (structurally impossible)",
                    ],
                )

            # Tier 2: eliminated as single-layer, but OPEN as part of multi-layer
            if family_lower in TIER_2_FAMILIES:
                is_multi_layer = (
                    "multi" in theory.mechanism.lower()
                    or "layer" in theory.mechanism.lower()
                    or "composite" in theory.mechanism.lower()
                    or theory.family.lower() == "multi_layer"
                    or any("multi" in t.lower() for t in theory.tags)
                )
                if not is_multi_layer:
                    return CriticVerdict(
                        decision=CriticDecision.REJECT_ELIMINATED,
                        confidence=0.95,
                        reasons=[
                            f"Family '{theory.family}' is Tier 2 eliminated as single-layer",
                            "Would pass if framed as one layer of a multi-layer hypothesis",
                        ],
                    )
                else:
                    reasons.append(
                        f"Family '{theory.family}' is Tier 2 single-layer eliminated "
                        "but allowed as component of multi-layer hypothesis"
                    )

            # Check family status from ledger
            fam_record = self.ledger.get_family(family_lower)
            if fam_record and fam_record.status == FamilyStatus.EXHAUSTED:
                # Allow if explicitly multi-layer
                is_multi = "multi" in theory.mechanism.lower() or "layer" in theory.mechanism.lower()
                if not is_multi:
                    return CriticVerdict(
                        decision=CriticDecision.REJECT_ELIMINATED,
                        confidence=0.9,
                        reasons=[
                            f"Family '{theory.family}' marked exhausted in ledger",
                            f"Evidence: {fam_record.elimination_evidence}",
                        ],
                    )

            # --- Check 2.5: Retired-palette revival (belt-and-suspenders) ---
            # Matches theories that revive the null_palette_retired claim
            # without using the claim_id verbatim (so the claim_policy gates
            # would miss them). See module-level matcher docstring.
            combined_text_for_retired = " ".join([
                theory.title or "",
                theory.core_claim or "",
                theory.mechanism or "",
                " ".join(theory.tags or []),
            ])
            retired_reason = _detect_retired_palette_revival(combined_text_for_retired)
            if retired_reason is not None:
                logger.info(
                    "Critic rejected %s as retired-palette revival: %s",
                    theory.hypothesis_id[:8], retired_reason[:120],
                )
                return CriticVerdict(
                    decision=CriticDecision.REJECT_ELIMINATED,
                    confidence=0.95,
                    reasons=[retired_reason],
                )

            # --- Check 2.6: CONSENSUS_NULL_POSITIONS revival (belt-and-suspenders) ---
            # Closes the generator leak observed 2026-04-17: theorists kept
            # invoking the 17-position null mask despite red-team flagging it
            # as pending-retraction. See matcher docstring above.
            mask_reason = _detect_consensus_null_positions_revival(combined_text_for_retired)
            if mask_reason is not None:
                logger.info(
                    "Critic rejected %s as CONSENSUS_NULL_POSITIONS revival: %s",
                    theory.hypothesis_id[:8], mask_reason[:120],
                )
                return CriticVerdict(
                    decision=CriticDecision.REJECT_ELIMINATED,
                    confidence=0.95,
                    reasons=[mask_reason],
                )

        # --- Check 3: Duplicate detection ---
        # Bench-mode HCC seeds carry deterministic hypothesis_id slugs
        # that are already deduplicated at generation time
        # (``_merge_hcc_seeds_into_candidates``); the family-grouped
        # Jaccard similarity check is O(N²/F) on the running ledger
        # and dominates the per-cycle budget on large catalogues
        # (2.5k+ seeds → tens of minutes of pure tokenization vs. a
        # few seconds of dispatch). Skip the slow path for HCC seeds
        # in bench mode; the deterministic-coverage contract already
        # guarantees uniqueness, and the dispatcher's own ledger
        # dedup catches re-emissions across cycles. The override-
        # justification dup check (3b) below is preserved because it
        # only fires for theories that explicitly carry the override
        # claim, which HCC seeds do not.
        is_hcc_bench_seed = (
            self.bench_mode
            and (theory.minimal_test_spec or {}).get("method")
            == "bench_hand_cipher_core"
        )
        similar = (
            [] if is_hcc_bench_seed
            else self._find_similar_theories(theory)
        )
        if similar:
            sim_ids = [s.hypothesis_id for s in similar]
            sim_titles = [s.title or s.core_claim[:50] for s in similar]

            # If ALL similar theories were already tested, reject
            all_tested = all(
                s.status in (TheoryStatus.COMPLETED, TheoryStatus.ELIMINATED)
                for s in similar
            )
            if all_tested:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_DUPLICATE,
                    confidence=0.85,
                    reasons=[
                        f"Similar to {len(similar)} previously tested theories",
                        f"Most similar: {sim_titles[0]}",
                    ],
                    similar_hypotheses=sim_ids,
                )
            else:
                reasons.append(
                    f"Similar to {len(similar)} existing theories "
                    f"(not all tested): {sim_titles[0]}"
                )

        # --- Check 3b (R2-3): override-justification duplicate check ---
        # If this theory claims an exhaustion-override, its justification
        # must be genuinely new — not a rephrasing of a prior theory's
        # justification. Prevents the override from becoming a bypass
        # mechanism for re-running noise under new wording.
        override_dup = self._check_override_duplicate(theory)
        if override_dup is not None:
            dup_id, dup_justification = override_dup
            return CriticVerdict(
                decision=CriticDecision.REJECT_DUPLICATE,
                confidence=0.9,
                reasons=[
                    "override_justification duplicates a prior theory's "
                    f"justification (Jaccard ≥ {SIMILARITY_THRESHOLD})",
                    f"Prior theory: {dup_id}",
                    f"Prior justification: {dup_justification[:100]}",
                ],
                similar_hypotheses=[dup_id],
            )

        # --- Check 4: Contradiction check ---
        # Skip in bench mode: the contradictions are all keyed to real-K4
        # facts (Bifid alphabet, autokey crib feedback, K4 IC). The
        # synthetic K4Bench challenge has its own A-Z 97-char structure
        # but no shared factual constraint with these checks.
        if not self.bench_mode:
            contradictions = self._check_contradictions(theory)
            if contradictions:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_CONTRADICTED,
                    confidence=0.9,
                    reasons=contradictions,
                    contradicting_facts=contradictions,
                )

            # --- Check 4.5: Narrow prompt-surface / falsifiability hygiene ---
            # Skip in bench mode: every clause keys on real-K4 anomaly ids
            # (width21_vertical_bigrams, aaa_coordinate_lie, w_delimiter_segments)
            # or on K4-specific text patterns. None of these apply to a
            # synthetic K4Bench challenge.
            scope_reasons = self._check_prompt_surface_scope(theory)
            if scope_reasons:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                    confidence=0.85,
                    reasons=scope_reasons,
                )

        # --- Check 4.6 (R3-2): Category-A/C DSL translatability ---
        #
        # Per DSL_CUTOVER_CONTRACT §2.1, placed after the existing
        # reject-producing checks so stronger rejection reasons fire
        # first (e.g., a Tier-1 eliminated family theory is better
        # reported as "eliminated" than as "no DSL spec"):
        #   Category A (cipher-family, DSL-expressible) → must carry
        #       a translatable dsl_spec
        #   Category B (family ∈ NON_DSL_FAMILIES) → skip DSL check;
        #       routes to legacy path during dispatch
        #   Category C (cipher-family, no / malformed / untranslatable
        #       spec) → reject with REJECT_UNDERCONSTRAINED and reason
        #       "dsl_untranslatable"
        family_lower_for_category = (theory.family or "").lower()
        if family_lower_for_category not in NON_DSL_FAMILIES:
            from .hypothesis_dsl import (
                repair_spec_shape,
                validate_hypothesis_spec,
            )
            from .job_dispatcher import _kind_has_translation, _SUPPORTED_KINDS

            if theory.dsl_spec and family_lower_for_category in _DEFERRED_DSL_FAMILY_NAMES:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                    confidence=1.0,
                    reasons=[
                        "dsl_untranslatable: deferred cipher family "
                        f"{theory.family!r} must not carry an executable dsl_spec. "
                        "This looks like family/spec mismatch or kind smuggling; "
                        "deferred families must stay honestly deferred until a "
                        "translator brief lands."
                    ],
                )

            if not theory.dsl_spec:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                    confidence=1.0,
                    reasons=[
                        "dsl_untranslatable: cipher-family theory declared "
                        "dsl_spec=null or empty; DSL requires a spec for "
                        "Category-A dispatch "
                        "(see DSL_CUTOVER_CONTRACT §2)",
                    ],
                )

            # K4Bench wiring (2026-04-26): run the narrow shape-repair
            # pass before validation. Repairs fix two well-known LLM
            # mistakes: (1) quagmire variant Roman numerals "III"/"IV"
            # rewritten to canonical "quagmire_iii"/"quagmire_iv";
            # (2) empty/placeholder hypothesis_id substituted with the
            # TheoryRecord.hypothesis_id. Anything else is left untouched
            # for the validator to reject explicitly. The repair report
            # is logged so silent rewrites are auditable. Subsumes the
            # R3-2 hypothesis_id substitution that lived inline here.
            spec_for_validation, repair_report = repair_spec_shape(
                theory.dsl_spec,
                default_hypothesis_id=theory.hypothesis_id,
            )
            if repair_report.applied():
                logger.info(
                    "Critic repaired dsl_spec for theory %s: %s",
                    theory.hypothesis_id[:8],
                    "; ".join(repair_report.entries)[:300],
                )

            parsed = validate_hypothesis_spec(spec_for_validation)
            if not parsed.is_valid:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                    confidence=1.0,
                    reasons=[
                        "dsl_untranslatable: dsl_spec failed validation",
                        *parsed.errors,
                    ],
                )

            spec = parsed.value
            untranslatable = [
                layer.kind for layer in spec.pipeline
                if not _kind_has_translation(layer.kind)
            ]
            if untranslatable:
                return CriticVerdict(
                    decision=CriticDecision.REJECT_UNDERCONSTRAINED,
                    confidence=1.0,
                    reasons=[
                        f"dsl_untranslatable: kinds {untranslatable} have "
                        f"no dispatcher translation in R3 "
                        f"(supported: {sorted(_SUPPORTED_KINDS)})",
                    ],
                )

        # NOTE: Day 2 had a Check 4b here that lexically detected
        # CT-perturbation-class theories and rejected them if no
        # bounded budget was stated in the kill criteria. As of Day 3,
        # that check has been removed in favor of the red-team-disprover
        # sibling call in controller._red_team_filter, which makes a
        # real adversarial judgment using the Pantheon agent's priors
        # rather than a hand-rolled marker list. Red-team is invoked
        # AFTER the deterministic critic approves a theory, so any
        # CT-perturbation rejection now happens at that stage.

        # --- Check 5: Discriminability ---
        if not theory.kill_criteria:
            reasons.append("No kill criteria specified — theory may be unfalsifiable")

        if not theory.expected_signal:
            reasons.append("No expected signal specified — hard to evaluate outcome")

        # --- Check 6: Information gain ---
        info_gain = self._estimate_information_gain(theory)

        # K4Bench input mode (2026-04-26): the LOW_INFORMATION rejection
        # rests on (a) "low" info gain estimated against the real-K4
        # ledger's family-status table and (b) the absence of
        # anomalies_exploited, which is itself a real-K4 concept (the
        # anomaly registry catalogues real-K4 anomalies). Both inputs
        # are real-K4 evidence; neither applies to a synthetic K4Bench
        # challenge. A concrete DSL spec with valid pipeline layers,
        # finite cardinality, and challenge-local clue anchors should
        # be approved unless malformed (Check 1), duplicate (Check 3),
        # overbudget (downstream admissibility), or unsupported by the
        # dispatcher (Check 4.6). Skip this check in bench mode.
        if (
            info_gain == "low"
            and not theory.anomalies_exploited
            and not self.bench_mode
        ):
            return CriticVerdict(
                decision=CriticDecision.REJECT_LOW_INFORMATION,
                confidence=0.7,
                reasons=[
                    "Low expected information gain",
                    "Does not exploit any known anomalies",
                    *reasons,
                ],
                estimated_information_gain=info_gain,
            )

        # --- Approve ---
        confidence = 0.8
        if theory.kill_criteria and theory.expected_signal:
            confidence = 0.9
        if theory.anomalies_exploited:
            confidence = min(confidence + 0.05, 1.0)

        return CriticVerdict(
            decision=CriticDecision.APPROVE,
            confidence=confidence,
            reasons=[
                "Passed all critic checks",
                *reasons,
            ],
            similar_hypotheses=[s.hypothesis_id for s in similar] if similar else [],
            estimated_information_gain=info_gain,
        )

    def evaluate_batch(
        self, theories: list[TheoryRecord]
    ) -> list[tuple[TheoryRecord, CriticVerdict]]:
        """Evaluate a batch. Returns (theory, verdict) pairs."""
        return [(t, self.evaluate(t)) for t in theories]

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_override_duplicate(
        self, theory: TheoryRecord,
    ) -> Optional[tuple[str, str]]:
        """R2-3: detect override_justification collision with a prior theory.

        Returns ``None`` when no collision. Returns ``(prior_id, prior_just)``
        when this theory's override_justification (first 100 chars,
        tokenized) has Jaccard similarity ≥ SIMILARITY_THRESHOLD with a
        previously-tested theory's override_justification.

        The guard only fires for theories that actually carry an
        override_justification (i.e., claim the exhaustion override);
        theories without the claim skip this check entirely.
        """
        just = (theory.override_justification or "").strip()
        if not just:
            return None
        head = just[:100]
        this_tokens = self._tokenize(head)
        if not this_tokens:
            return None
        # Walk every tested theory in the ledger. This is O(n) on tested
        # theory count; fine in practice — the ledger rarely exceeds a
        # few hundred entries.
        for status in (TheoryStatus.COMPLETED, TheoryStatus.ELIMINATED):
            for prior in self.ledger.get_theories_by_status(status):
                if prior.hypothesis_id == theory.hypothesis_id:
                    continue
                prior_just = (prior.override_justification or "").strip()
                if not prior_just:
                    continue
                prior_head = prior_just[:100]
                prior_tokens = self._tokenize(prior_head)
                if not prior_tokens:
                    continue
                jaccard = (
                    len(this_tokens & prior_tokens)
                    / len(this_tokens | prior_tokens)
                )
                if jaccard >= SIMILARITY_THRESHOLD:
                    return (prior.hypothesis_id, prior_just)
        return None

    def _find_similar_theories(self, theory: TheoryRecord) -> list[TheoryRecord]:
        """Find theories with similar mechanism + claim."""
        # Search by family first (cheap)
        candidates = self.ledger.get_theories_by_family(theory.family)
        if not candidates:
            return []

        # Compute Jaccard similarity on mechanism + claim words
        theory_words = self._tokenize(theory.core_claim + " " + theory.mechanism)
        if not theory_words:
            return []

        similar = []
        for cand in candidates:
            if cand.hypothesis_id == theory.hypothesis_id:
                continue
            cand_words = self._tokenize(cand.core_claim + " " + cand.mechanism)
            if not cand_words:
                continue
            jaccard = len(theory_words & cand_words) / len(theory_words | cand_words)
            if jaccard >= SIMILARITY_THRESHOLD:
                similar.append(cand)

        return similar

    def _claim_permits_elimination(self, claim_id: str, h1_context: bool = False) -> bool:
        """Gate: may a registered ProvenanceClaim be used as an elimination basis?

        Routes every claim-based elimination through claim_policy so that
        BEAN_REPORTED_NOT_RERUN, INTERPRETIVE_PHYSICAL_OBSERVATION,
        PROJECT_REVERIFIED_STATISTICAL_ANOMALY, and RETIRED claims cannot
        silently become contradiction grounds.
        """
        claim = CANONICAL_CLAIMS_BY_ID.get(claim_id)
        if claim is None:
            return False
        allowed_elim, _ = can_use_as_elimination_basis(claim, h1_context=h1_context)
        allowed_hard, _ = can_use_as_hard_constraint(claim, h1_context=h1_context)
        return allowed_elim or allowed_hard

    def _check_family_tier_eliminated(
        self, theory: TheoryRecord, family_lower: str
    ) -> Optional[CriticVerdict]:
        """Refuse a theory if its target family has elimination_tier in {1,2}.

        This is a generic structural gate that uses the bootstrapped family
        registry. Tiers 1 (algebraic) and 2 (empirical-saturated) families
        should not have new single-layer theories proposed against them.
        Tiers 3 (partial) and 4 (untested) are still allowed.

        Theories explicitly framed as multi-layer are allowed through so
        Tier 1/2 families remain legal as COMPONENTS of a composite.

        KEEP NARROW. Do NOT let this become a semantic classifier. It only
        checks the family_id field of the theory against the family
        registry's elimination_tier field. No string matching, no inference.
        """
        family = self.ledger.get_family(family_lower)
        if family is None:
            return None  # unknown family — no opinion here
        if family.elimination_tier not in (1, 2):
            return None

        # Allow explicitly multi-layer framings (matches the existing
        # Tier 2 -> multi-layer escape hatch below).
        mech_lower = theory.mechanism.lower()
        is_multi_layer = (
            "multi" in mech_lower
            or "layer" in mech_lower
            or "composite" in mech_lower
            or theory.family.lower() == "multi_layer"
            or any("multi" in t.lower() for t in theory.tags)
        )
        if is_multi_layer and family.elimination_tier == 2:
            # Tier 2 is single-layer exhausted; multi-layer framing survives.
            return None

        evidence = (family.elimination_evidence or "")[:200]
        return CriticVerdict(
            decision=CriticDecision.REJECT_ELIMINATED,
            confidence=0.95,
            reasons=[
                f"Family '{theory.family}' is at elimination_tier "
                f"{family.elimination_tier} per the family registry.",
                f"Evidence: {evidence}..." if evidence else "Evidence: (none recorded)",
            ],
        )

    def _check_family_empirically_dead(
        self,
        theory: TheoryRecord,
        family_lower: str,
    ) -> Optional[CriticVerdict]:
        """Reject theories in empirically-dead families unless structurally novel.

        Returns a CriticVerdict with REJECT_EMPIRICALLY_DEAD when:
          - family_lower is classified empirically_dead in self.yield_index, AND
          - the theory does not satisfy structural-novelty bypass.

        Returns None (fall-through) when:
          - the family is not in yield_index, OR
          - the family's status is not empirically_dead, OR
          - the theory is bypass-eligible, OR
          - shadow_mode is enabled (logs would-reject and returns None).

        Reads only self.yield_index / self.prior_subfamilies /
        self.prior_signatures / self.policy. Never queries the ledger.
        """
        from kryptosbot.family_yield import (
            check_bypass_eligibility,
            mechanism_signature_for_theory,
            _normalize_subfamily,
        )
        from kryptosbot.models import EmpiricalDeathRejectionPayload

        verdict = (self.yield_index or {}).get(family_lower)
        if verdict is None or verdict.status != "empirically_dead":
            return None

        # Reconstruct a theory dict shape for mechanism_signature_for_theory.
        theory_for_sig = {
            "family": theory.family,
            "subfamily": theory.subfamily or "",
            "mechanism": theory.mechanism or "",
            "dsl_spec": theory.dsl_spec,
            "anomalies_exploited": theory.anomalies_exploited or [],
            "clue_anchors_used": theory.clue_anchors_used or [],
            "novelty_basis": theory.novelty_basis or "",
            "minimal_test_spec": theory.minimal_test_spec or {},
        }
        sig = mechanism_signature_for_theory(theory_for_sig)

        eligible, reasons = check_bypass_eligibility(
            family=family_lower,
            subfamily=_normalize_subfamily(theory.subfamily or ""),
            mechanism_signature=sig,
            prior_subfamilies_in_family=(self.prior_subfamilies or {}).get(
                family_lower, frozenset(),
            ),
            prior_mechanism_signatures_in_family=(self.prior_signatures or {}).get(
                family_lower, frozenset(),
            ),
        )
        if eligible:
            return None

        if getattr(self.policy, "shadow_mode", False):
            logger.warning(
                "[shadow] would_reject_empirically_dead: family=%s reasons=%s",
                family_lower, reasons,
            )
            return None

        s = verdict.stats
        return CriticVerdict(
            decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
            confidence=0.9,
            reasons=[
                f"Family '{theory.family}' empirically dead "
                f"(n={s.trials}, mean={s.mean_score:.2f}, "
                f"best={s.best_score:.1f}, promotions={s.promotions}); "
                f"bypass not satisfied",
                *reasons,
            ],
            empirical_death=EmpiricalDeathRejectionPayload(
                family=family_lower,
                verdict=verdict,
                bypass_failed_reasons=tuple(reasons),
                suggested_mechanisms=(),  # Phase 2 populates
            ),
        )

    def _check_contradictions(self, theory: TheoryRecord) -> list[str]:
        """Check if theory contradicts known facts.

        Any contradiction grounded in a claim from the canonical registry is
        routed through claim_policy (_claim_permits_elimination). Structural
        impossibilities (bifid alphabet mismatch, autokey feedback) remain
        hardcoded because they correspond to STRUCTURAL_ELIMINATION claims
        whose policy gate permits elimination use unconditionally.
        """
        contradictions = []
        mech_lower = theory.mechanism.lower()
        claim_lower = theory.core_claim.lower()

        # Check: Bifid requires 25-letter alphabet
        # Backed by fractionation_eliminated_structural (STRUCTURAL_ELIMINATION).
        if "bifid" in mech_lower and "26" not in claim_lower:
            if self._claim_permits_elimination("fractionation_eliminated_structural"):
                contradictions.append(
                    "Bifid requires 25-letter alphabet (I/J merge) but K4 uses all 26 letters"
                )

        # Check: Autokey has structural impossibility
        # Backed by autokey_eliminated (STRUCTURAL_ELIMINATION).
        if "autokey" in mech_lower and "multi" not in mech_lower:
            if self._claim_permits_elimination("autokey_eliminated"):
                contradictions.append(
                    "Autokey ciphers have structural impossibility: "
                    "crib feedback contradiction at positions 27/65"
                )

        # Check: Claims about IC being high
        # Backed by ic_not_significant (PROJECT_REVERIFIED_STATISTICAL_ANOMALY).
        # This is NOT permitted as an elimination basis — it is a ranking feature
        # only. So we do NOT append it to contradictions; we record it as advisory.
        # (See claim_policy.can_use_as_elimination_basis: statistical anomalies cannot
        # eliminate theories.) The previous hardcoded behavior was a policy leak.
        if "high ic" in claim_lower or "english-like ic" in claim_lower:
            if "pre-ene" not in claim_lower and "segment" not in claim_lower:
                if self._claim_permits_elimination("ic_not_significant"):
                    contradictions.append(
                        "K4's overall IC (0.0361) is below random (0.0385), not English-like."
                    )
                # else: policy blocks elimination; statistical claim remains advisory.

        # Check: Retired palette revival.
        # Backed by null_palette_retired (RETIRED_CLAIM). Policy gate blocks ALL
        # elimination uses, but retired claims are caught by a separate rule:
        # any theory that tries to revive the palette is rejected on retirement
        # grounds, not contradiction grounds. So no append here — higher-level
        # code checks RETIRED separately.
        return contradictions

    def _estimate_information_gain(self, theory: TheoryRecord) -> str:
        """Rough estimate of expected information gain."""
        # Theories that exploit anomalies are more informative
        if theory.anomalies_exploited:
            return "high"

        # Theories in partially explored families have medium gain
        fam = self.ledger.get_family(
            theory.family.lower().replace(" ", "_").replace("/", "_")
        )
        if fam and fam.status == FamilyStatus.PARTIALLY_EXPLORED:
            return "medium"

        # Novel/unclassified families
        if fam and fam.status == FamilyStatus.ACTIVE:
            if fam.total_theories < 5:
                return "high"
            return "medium"

        # Well-explored families without anomaly exploitation
        return "low"

    def _check_prompt_surface_scope(self, theory: TheoryRecord) -> list[str]:
        """Reject narrow classes of theory drift seen in live controller runs.

        Keep these checks concrete and local. They are not a general semantic
        classifier; they only catch specific mismatch patterns that create false
        confidence or non-falsifiable dispatches.
        """
        reasons: list[str] = []
        combined_text = " ".join(
            [
                theory.title or "",
                theory.core_claim or "",
                theory.mechanism or "",
                theory.expected_signal or "",
                " ".join(theory.kill_criteria or []),
            ]
        )

        if "width21_vertical_bigrams" in theory.anomalies_exploited:
            if _WIDTH_10_RE.search(combined_text):
                reasons.append(
                    "width21_vertical_bigrams cannot anchor a width-10 / 10-column theory."
                )
            if _CT73_RE.search(combined_text) and not _CT97_RE.search(combined_text):
                reasons.append(
                    "width21_vertical_bigrams is a full-ciphertext / CT97 anomaly; "
                    "CT73-only framing must state the CT97/full-ciphertext mapping explicitly."
                )

        ambiguous_kills = [
            criterion for criterion in theory.kill_criteria
            if _AMBIGUOUS_KILL_CRITERIA_RE.search(criterion)
        ]
        if ambiguous_kills:
            reasons.append(
                "Kill criteria use undefined 'quasi-periodic' language; falsification must be operationalized."
            )

        escape_hatch_fields = [theory.expected_signal or "", *theory.kill_criteria]
        if any(_ESCAPE_HATCH_RE.search(field) for field in escape_hatch_fields):
            reasons.append(
                "Kill criteria contain a survival escape hatch; a failed test must actually kill the stated mechanism."
            )

        if "aaa_coordinate_lie" in theory.anomalies_exploited:
            if _COORDINATE_DELTA_RE.search(combined_text) and _DIRECT_PERIODIC_KEY_RE.search(combined_text):
                reasons.append(
                    "Coordinate-delta / discrepancy digits used as a direct Beaufort/Vigenere/Gronsfeld-style key "
                    "overlap already-eliminated direct periodic-key space."
                )

        if _PHYSICAL_REASSEMBLY_RE.search(combined_text):
            if not _BOUNDARY_SPEC_RE.search(combined_text):
                reasons.append(
                    "Physical cut/chunk/reassembly theories must specify a finite boundary rule, "
                    "chunk count or lengths, and permutation budget."
                )
            if (
                _DELIMITER_RE.search(combined_text)
                and not any(
                    anom_id == "w_delimiter_segments" or anom_id.startswith("w_delimiter")
                    for anom_id in theory.anomalies_exploited
                )
            ):
                reasons.append(
                    "Delimiter-driven reassembly theories must cite an explicit finite boundary rule, "
                    "not free-form delimiter lore."
                )

        if _SEGMENTED_TAPE_RE.search(combined_text) and _SELF_ENCRYPTING_POSITIONS_RE.search(combined_text):
            reasons.append(
                "Segmented-tape proposals keyed to self-encrypting positions overlap the active "
                "e_segmented_tape_01 lane and are not novel enough to dispatch as a new theory."
            )

        if _ANCHORED_ALIGNMENT_RE.search(combined_text) and _KNOWN_CRIB_TARGET_RE.search(combined_text):
            reasons.append(
                "Anchored alignment theories that map known tape/key values back onto the known crib positions "
                "can manufacture 24/24 by construction and must be rejected unless they specify a free-crib "
                "or displaced-crib evaluation frame."
            )

        return reasons

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        """Simple word tokenization for similarity comparison."""
        # Remove punctuation, lowercase, split
        words = set()
        for word in text.lower().split():
            cleaned = "".join(c for c in word if c.isalnum())
            if len(cleaned) >= 3:  # skip very short words
                words.add(cleaned)
        return words
