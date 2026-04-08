"""Constraint propagation engine for composition search.

Reasons about how K4 constraints behave under layer composition.
Separates exact pruning (mathematically proven) from heuristic
pruning (statistically motivated) and unmodeled cases.

Key constraints considered:
  - Crib position consistency (after transposition, cribs move)
  - Bean equality: k[27] == k[65] must hold under any valid decryption
  - Bean inequalities: 242 pairs must have distinct key values
  - IC expectations: transposition preserves IC, additive shifts don't
  - Frequency preservation: transposition preserves, substitution doesn't
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from kryptos.composition.models import (
    CompositionStack,
    LayerFamily,
    LayerInstance,
    LayerSemantics,
    PeelOrder,
    PruneResult,
    PruneType,
)


# ── Individual pruning checks ──────────────────────────────────────────

def check_bean_equality_under_additive(
    outer: LayerInstance,
) -> PruneResult:
    """Check if an additive outer mask preserves Bean equality k[27]=k[65].

    [EXACT] For additive mask with keyword K of length L:
    The effective key shifts are mask[27] and mask[65].
    Bean equality k[27]=k[65] holds in the masked text iff
    the original key equality holds AND mask[27 % L] == mask[65 % L].

    Since we require the downstream cipher to produce k[27]=k[65],
    and the mask adds mask_val to each key position, equality is
    preserved iff mask[27 % L] == mask[65 % L].
    """
    periodic_families = {
        LayerFamily.ADDITIVE_MASK,
        LayerFamily.VIGENERE,
        LayerFamily.BEAUFORT,
        LayerFamily.VAR_BEAUFORT,
    }
    if outer.family not in periodic_families:
        return PruneResult.pass_()

    keyword = outer.params.get("keyword", "A")
    if not keyword or keyword == "NONE":
        return PruneResult.pass_()

    from kryptos.kernel.constants import ALPH_IDX

    kw_vals = [ALPH_IDX[c] for c in keyword.upper()]
    kw_len = len(kw_vals)

    mask_27 = kw_vals[27 % kw_len]
    mask_65 = kw_vals[65 % kw_len]

    if mask_27 != mask_65:
        return PruneResult.exact(
            reason=(
                f"Periodic keyword {keyword!r} (len={kw_len}) "
                f"gives key[27]={mask_27}, key[65]={mask_65}. "
                f"Bean equality k[27]=k[65] cannot hold because the "
                f"keyword gives different values at these positions."
            ),
            keyword=keyword,
            mask_27=mask_27,
            mask_65=mask_65,
        )

    return PruneResult.pass_()


def check_bean_inequalities_under_periodic(
    layer: LayerInstance,
) -> PruneResult:
    """Check if a periodic substitution layer violates Bean inequalities.

    [EXACT] For a periodic keyword cipher with keyword of length L,
    keystream value at position i is keyword[i % L].
    Bean inequalities require k[a] != k[b] for 242 crib-position pairs.
    If keyword[a % L] == keyword[b % L] for any such pair, the
    composition is impossible (the inner cipher would need to produce
    equal keystream values where they must differ).

    This applies to Vigenere, Beaufort, Variant Beaufort, and additive masks
    when used as the substitution layer whose key positions must satisfy
    Bean constraints.
    """
    periodic_families = {
        LayerFamily.ADDITIVE_MASK,
        LayerFamily.VIGENERE,
        LayerFamily.BEAUFORT,
        LayerFamily.VAR_BEAUFORT,
    }
    if layer.family not in periodic_families:
        return PruneResult.pass_()

    keyword = layer.params.get("keyword", "A")
    if not keyword or keyword == "NONE":
        return PruneResult.pass_()

    from kryptos.kernel.constants import ALPH_IDX, BEAN_INEQ

    kw_vals = [ALPH_IDX[c] for c in keyword.upper()]
    kw_len = len(kw_vals)

    for a, b in BEAN_INEQ:
        if kw_vals[a % kw_len] == kw_vals[b % kw_len]:
            return PruneResult.exact(
                reason=(
                    f"Keyword {keyword!r} (len={kw_len}) gives equal key "
                    f"values at positions {a} and {b} (both map to "
                    f"keyword[{a % kw_len}]=keyword[{b % kw_len}]="
                    f"{kw_vals[a % kw_len]}), violating Bean inequality."
                ),
                keyword=keyword,
                pos_a=a,
                pos_b=b,
            )

    return PruneResult.pass_()


def check_bean_equality_under_transposition(
    outer: LayerInstance,
) -> PruneResult:
    """Check if a transposition outer layer preserves Bean equality.

    [EXACT] After inverse-transposing, the crib positions move.
    The new positions of CT[27] and CT[65] in the intermediate text
    must still allow the downstream cipher to produce equal keys.

    This is a necessary condition: the transposition must map positions
    27 and 65 such that Bean equality can be satisfied by the inner layer.
    We cannot prune based on this alone (the inner layer's key schedule
    determines satisfaction), but we CAN check if the transposition
    separates these positions in a way that makes periodicity impossible
    at common periods.
    """
    # Transposition doesn't change the values, just moves them.
    # Bean equality is about key values at positions, which depend on
    # the inner cipher. We can't prune here without knowing the inner
    # layer's key schedule. Return pass.
    return PruneResult.pass_()


def check_ic_expectation(
    stack: CompositionStack,
    ct_ic: float = 0.0361,
) -> PruneResult:
    """Heuristic IC check on the composition.

    [HEURISTIC] If the outer layer preserves frequencies (transposition),
    the intermediate text should have IC near K4's IC (~0.0361).
    If IC of intermediate is significantly higher, the outer layer
    may have accidentally created structure.

    Note: IC below random is NOT statistically significant for 97 chars
    (see E-FRAC-04), so we only flag very high IC.
    """
    # This is evaluated at runtime after peeling the outer layer.
    # Cannot evaluate statically. Return pass for static check.
    return PruneResult.pass_()


def check_length_compatibility(
    stack: CompositionStack,
    input_length: int = 97,
) -> PruneResult:
    """Check that all layers preserve length consistently.

    [EXACT] If any layer changes length and the next layer expects
    a specific length, the composition is invalid.
    """
    for layer in stack.layers:
        if not layer.semantics.preserves_length:
            return PruneResult.exact(
                reason=f"Layer {layer.display_label} does not preserve length",
                layer=layer.display_label,
            )
    return PruneResult.pass_()


def check_transposition_crib_displacement(
    outer: LayerInstance,
    crib_positions: Optional[frozenset] = None,
) -> PruneResult:
    """Analyze how a transposition outer layer displaces crib positions.

    [HEURISTIC] If the outer transposition scatters the 24 crib positions
    such that no contiguous crib fragment survives (ENE or BC), the
    downstream anchored scorer will always score 0. However, the
    *intermediate* text is what the inner cipher produces, and cribs
    in the intermediate text are at the *displaced* positions.

    This check is informational — it identifies compositions where
    anchored crib scoring is inappropriate and free-crib scoring
    should be used instead.
    """
    if outer.semantics.preserves_positions:
        return PruneResult.pass_()

    # We cannot prune — we just note that free scoring is needed.
    return PruneResult.pass_()


# ── Composite pruning engine ───────────────────────────────────────────

def evaluate_pruning(
    stack: CompositionStack,
    aggressive: bool = False,
    ct_length: int = 97,
) -> PruneResult:
    """Run all applicable pruning checks on a composition stack.

    Returns the first pruning result that triggers, or PruneResult.pass_()
    if no check prunes the branch.

    Args:
        stack: The composition to check.
        aggressive: If True, apply heuristic pruning in addition to exact.
        ct_length: Length of the ciphertext being processed. Bean constraints
            only apply to the standard 97-char K4 CT.
    """
    checks: list[PruneResult] = []

    # Length compatibility (exact)
    checks.append(check_length_compatibility(stack))

    # Bean checks only valid for standard 97-char K4 CT
    if ct_length == 97:
        # Bean equality under additive/periodic outer (exact)
        if stack.depth >= 1:
            outer = stack.outer
            periodic_families = {
                LayerFamily.ADDITIVE_MASK,
                LayerFamily.VIGENERE,
                LayerFamily.BEAUFORT,
                LayerFamily.VAR_BEAUFORT,
            }
            if outer.family in periodic_families:
                checks.append(check_bean_equality_under_additive(outer))

        # Bean inequalities under periodic substitution layers (exact)
        # Only applies when the ENTIRE composition is a single periodic
        # substitution (all other layers are identity). In multi-layer
        # compositions, the effective keystream is the sum of both layers'
        # contributions, so individual-layer Bean inequality checks are invalid.
        if stack.preserves_positions and stack.depth <= 2:
            non_identity = [l for l in stack.layers if l.family != LayerFamily.IDENTITY]
            if len(non_identity) == 1:
                checks.append(check_bean_inequalities_under_periodic(non_identity[0]))

    # Bean equality under transposition outer (informational)
    if stack.depth >= 1:
        outer = stack.outer
        if not outer.semantics.preserves_positions:
            checks.append(check_bean_equality_under_transposition(outer))

    # Return first pruning hit
    for result in checks:
        if result.pruned:
            return result

    return PruneResult.pass_()


def evaluate_intermediate_pruning(
    intermediate_text: str,
    stack: CompositionStack,
    aggressive: bool = False,
) -> PruneResult:
    """Runtime pruning on the intermediate text after peeling the outer layer.

    This is called after the outer layer has been inverted, producing
    an intermediate ciphertext that the inner layer should decrypt to
    plaintext with cribs.

    Checks:
    - IC of intermediate (heuristic)
    - Quick crib pre-screen on intermediate (heuristic)
    """
    from kryptos.kernel.scoring.ic import ic

    ic_val = ic(intermediate_text)

    # If outer was a transposition (preserves IC), intermediate IC should
    # still be near K4's IC. If it's drastically different, something is wrong.
    if stack.outer.semantics.preserves_unigram_frequencies:
        # IC should be close to K4's observed IC (0.0361)
        # Allow wide tolerance for 97-char text (IC variance is high)
        if aggressive and ic_val > 0.055:
            return PruneResult.heuristic(
                reason=(
                    f"Intermediate IC={ic_val:.4f} is unusually high after "
                    f"frequency-preserving outer layer. Expected near 0.036."
                ),
                ic_value=ic_val,
            )

    return PruneResult.pass_()


# ── Scoring mode selection ─────────────────────────────────────────────

def select_scoring_mode(stack: CompositionStack) -> str:
    """Determine which scoring path to use for a composition.

    Returns:
        "anchored" — use score_candidate() with fixed crib positions
        "free"     — use score_candidate_free() searching anywhere
        "both"     — run both and take the best

    Logic:
        If ALL layers preserve positions, cribs remain at standard positions
        → use anchored scoring.

        If any layer is a transposition (position-destroying), the plaintext
        cribs may not be at standard positions → use free scoring.

        When in doubt, use both.
    """
    if stack.preserves_positions:
        return "anchored"

    # If outer is transposition and inner is substitution:
    # After inverting outer transposition, we get intermediate CT.
    # Inner substitution decrypts position-by-position.
    # Cribs in the PLAINTEXT are at positions determined by the
    # inverse transposition applied to the original crib positions.
    # Use "both" to catch either case.
    has_transposition = any(
        not l.semantics.preserves_positions for l in stack.layers
    )
    if has_transposition:
        return "both"

    return "anchored"
