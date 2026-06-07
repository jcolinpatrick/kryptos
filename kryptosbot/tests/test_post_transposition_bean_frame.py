"""Task A — post-transposition Bean keystream-frame correctness.

The dispatcher already honours ``crib_alignment``:

* ``free`` routes to ``score_candidate_free`` (Lever B1, test_free_alignment.py).
* ``post_transposition`` is anchored-scored because a ``route`` layer translates
  to ``transposition_full`` with ``direction="undo"``, which physically inverts
  the outer reordering, landing the candidate (and its cribs) back in PT reading
  order at 21-33 / 63-73.

BUT a residual correctness gap remained for the *Bean* check. ``_candidate_bean_status``
derives the keystream as ``derive(ct[i], pt[i])`` — so the CT frame is
load-bearing. Under ``post_transposition`` the keystream that Bean constrains is
the one applied in the PT frame, i.e. against the **route-undone** intermediate
``route_undo(carved_CT)``, NOT the carved CT. Reading Bean off the carved CT is
the exact AUDIT-1 / alignment-model error: a direct-positional Bean evaluation
silently applied under a non-direct alignment.

Known-answer construction (fully synthetic, self-contained):

    K      : Bean-valid vigenere keystream — real-K4 values at the 24 crib
             positions (K[i] = (CT_real[i] - crib[i]) % 26), 0 elsewhere.
    PT     : 97 chars, EASTNORTHEAST @21-33 and BERLINCLOCK @63-73, 'X' filler.
    inter  : vigenere-encrypt(PT, K) = (PT + K) % 26  (the PT-frame ciphertext).
    carved : route_forward(inter)                      (the carved/visible CT).

Decrypt pipeline [route(undo), vigenere(decrypt, key=K)] recovers PT, and the
correct Bean frame is route_undo(carved) == inter. Bean(inter, PT) PASSES;
Bean(carved, PT) FAILS. Same candidate PT, opposite verdict — so the verdict is
a pure function of the keystream frame.
"""

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.text import text_to_nums, nums_to_text
from kryptos.kernel.transforms.transposition import apply_perm

from kryptos.kernel.transforms.transposition import columnar_perm

from kryptosbot.job_dispatcher import (
    _evaluate_one, _score_real_k4_candidate, _keystream_frame_ct,
)


_CRIB_POSITIONS = list(range(21, 34)) + list(range(63, 74))


def _build_known_answer():
    """Return (carved_CT, PT, K, perm, intermediate) for the fixture."""
    pt_chars = ["X"] * CT_LEN
    for start, word in ((21, "EASTNORTHEAST"), (63, "BERLINCLOCK")):
        for j, ch in enumerate(word):
            pt_chars[start + j] = ch
    PT = "".join(pt_chars)

    ct_nums = text_to_nums(CT)
    pt_nums = text_to_nums(PT)
    K = [0] * CT_LEN
    for i in _CRIB_POSITIONS:
        K[i] = (ct_nums[i] - pt_nums[i]) % 26
    assert verify_bean_simple(K), "fixture keystream must be Bean-valid"

    intermediate = nums_to_text([(pt_nums[i] + K[i]) % 26 for i in range(CT_LEN)])
    perm = [CT_LEN - 1 - i for i in range(CT_LEN)]  # reverse route (involution)
    carved_CT = apply_perm(intermediate, perm)
    return carved_CT, PT, K, perm, intermediate


def _work_item(carved_CT, K, perm, crib_alignment):
    return {
        "config_id": "task-a-known-answer",
        "pipeline_dict": {
            "name": "task_a_post_transposition",
            "direction": "decrypt",
            "steps": [
                {"type": "transposition_full",
                 "params": {"perm": perm, "direction": "undo"}},
                {"type": "vigenere",
                 "params": {"key": K, "direction": "decrypt"}},
            ],
        },
        # Synthetic carved CT on the REAL-K4 scorer path (no challenge_crib_dict
        # => Lever B1 real-K4 branch with the kernel's real cribs).
        "challenge_ciphertext": carved_CT,
        "challenge_crib_dict": None,
        "crib_alignment": crib_alignment,
    }


# ── Worker integration (the primary known-answer test) ──────────────────────

def test_worker_post_transposition_rederives_bean_in_pt_frame():
    carved_CT, PT, K, perm, _inter = _build_known_answer()
    result = _evaluate_one(_work_item(carved_CT, K, perm, "post_transposition"))
    assert "error" not in result, result
    # Pipeline recovers the exact plaintext, cribs anchored at canonical spots.
    assert result["candidate_pt"] == PT
    assert result["crib_score"] == 24
    # Bean re-derived in the route-undone (PT) frame => PASS.
    assert result["bean_passed"] is True
    assert result["bean_variant"] == "vigenere"
    assert result["scoring_mode"] == "post_transposition"


def test_worker_direct_positional_uses_carved_ct_frame():
    """Control: the SAME pipeline labelled direct_positional reads Bean off the
    carved CT (the historical frame) and therefore does NOT pass — proving the
    only behavioural difference is the keystream frame, gated on the alignment."""
    carved_CT, PT, K, perm, _inter = _build_known_answer()
    result = _evaluate_one(_work_item(carved_CT, K, perm, "direct_positional"))
    assert "error" not in result, result
    assert result["candidate_pt"] == PT          # pipeline output identical
    assert result["crib_score"] == 24            # cribs still anchored
    assert result["bean_passed"] is False        # wrong frame for this candidate
    assert result["scoring_mode"] == "direct_positional"


# ── Unit-level scorer (explicit bean_frame_ct) ──────────────────────────────

def test_scorer_post_transposition_with_pt_frame_passes_bean():
    carved_CT, PT, _K, _perm, intermediate = _build_known_answer()
    scored = _score_real_k4_candidate(
        carved_CT, PT, "post_transposition", bean_frame_ct=intermediate,
    )
    assert scored["crib_score"] == 24
    assert scored["bean_passed"] is True
    assert scored["bean_variant"] == "vigenere"
    assert scored["scoring_mode"] == "post_transposition"
    assert scored["canonical_positions"] is True


def test_scorer_post_transposition_with_carved_frame_fails_bean():
    carved_CT, PT, _K, _perm, _inter = _build_known_answer()
    scored = _score_real_k4_candidate(
        carved_CT, PT, "post_transposition", bean_frame_ct=carved_CT,
    )
    assert scored["crib_score"] == 24
    assert scored["bean_passed"] is False  # carved frame => keystream not Bean-valid


def test_scorer_post_transposition_without_frame_is_bean_unavailable():
    """Without the route-undone frame Bean cannot bind; never report a PASS off
    the carved CT (conservative: no false Bean under an unknown frame)."""
    carved_CT, PT, _K, _perm, _inter = _build_known_answer()
    scored = _score_real_k4_candidate(carved_CT, PT, "post_transposition")
    assert scored["crib_score"] == 24
    assert scored["bean_passed"] is False
    assert scored["scoring_mode"] == "post_transposition_bean_unavailable"


def test_scorer_direct_positional_unchanged_regression():
    """direct_positional still reads Bean off the supplied CT (no frame remap)."""
    carved_CT, PT, _K, _perm, intermediate = _build_known_answer()
    # On the intermediate (which IS a direct vigenere solve), direct scoring passes.
    scored = _score_real_k4_candidate(intermediate, PT, "direct_positional")
    assert scored["crib_score"] == 24
    assert scored["bean_passed"] is True
    assert scored["scoring_mode"] == "direct_positional"


def test_same_pt_opposite_bean_verdict_by_frame():
    """The crux invariant: ONE candidate PT yields OPPOSITE Bean verdicts solely
    by the keystream frame — PASS in the route-undone PT frame, FAIL in the carved
    frame. A fix that ignored the frame could not satisfy both."""
    carved_CT, PT, _K, _perm, intermediate = _build_known_answer()
    pt_frame = _score_real_k4_candidate(carved_CT, PT, "post_transposition",
                                        bean_frame_ct=intermediate)
    carved_frame = _score_real_k4_candidate(carved_CT, PT, "post_transposition",
                                            bean_frame_ct=carved_CT)
    assert pt_frame["crib_score"] == carved_frame["crib_score"] == 24  # same candidate
    assert pt_frame["bean_passed"] is True
    assert carved_frame["bean_passed"] is False


# ── _keystream_frame_ct unit behaviour (the frame extractor) ────────────────

def _vig_step(key=None):
    return {"type": "vigenere", "params": {"key": key or [0] * CT_LEN, "direction": "decrypt"}}


def _route_step(perm, direction="undo"):
    return {"type": "transposition_full", "params": {"perm": perm, "direction": direction}}


def test_frame_route_then_additive_returns_route_undone_intermediate():
    carved_CT, _PT, K, perm, intermediate = _build_known_answer()
    frame = _keystream_frame_ct(carved_CT, [_route_step(perm), _vig_step(K)])
    assert frame == intermediate  # leading reorder applied, additive frame recovered


def test_frame_no_leading_reorder_returns_none():
    """First step is the additive (no outer reorder) => frame undefined => None."""
    carved_CT, _PT, K, _perm, _inter = _build_known_answer()
    assert _keystream_frame_ct(carved_CT, [_vig_step(K), _route_step(
        [CT_LEN - 1 - i for i in range(CT_LEN)])]) is None


def test_frame_no_trailing_additive_returns_none():
    """All steps are reorders (no additive) => no keystream frame => None."""
    carved_CT, _PT, _K, perm, _inter = _build_known_answer()
    assert _keystream_frame_ct(carved_CT, [_route_step(perm)]) is None


def test_frame_identity_leading_is_carved_ct():
    """identity is a (trivial) reorder; identity-then-additive => frame == carved CT."""
    carved_CT, _PT, K, _perm, _inter = _build_known_answer()
    frame = _keystream_frame_ct(carved_CT, [{"type": "identity", "params": {}}, _vig_step(K)])
    assert frame == carved_CT


# ── columnar route (route-like reorder, not just reverse) ───────────────────

def test_worker_post_transposition_columnar_route_rederives_bean():
    """Same known-answer construction but with a COLUMNAR route perm (a
    route-like reorder distinct from reverse) — Bean still re-derived correctly."""
    pt_chars = ["X"] * CT_LEN
    for start, word in ((21, "EASTNORTHEAST"), (63, "BERLINCLOCK")):
        for j, ch in enumerate(word):
            pt_chars[start + j] = ch
    PT = "".join(pt_chars)
    ct_nums = text_to_nums(CT)
    pt_nums = text_to_nums(PT)
    K = [0] * CT_LEN
    for i in _CRIB_POSITIONS:
        K[i] = (ct_nums[i] - pt_nums[i]) % 26
    assert verify_bean_simple(K)
    intermediate = nums_to_text([(pt_nums[i] + K[i]) % 26 for i in range(CT_LEN)])
    perm = columnar_perm(7, [3, 1, 5, 0, 6, 2, 4], CT_LEN)  # keyed columnar route
    carved_CT = apply_perm(intermediate, perm)
    result = _evaluate_one(_work_item(carved_CT, K, perm, "post_transposition"))
    assert "error" not in result, result
    assert result["candidate_pt"] == PT
    assert result["crib_score"] == 24
    assert result["bean_passed"] is True          # correct (PT) frame
    assert result["scoring_mode"] == "post_transposition"


def test_worker_post_transposition_no_outer_route_is_bean_unavailable():
    """A post_transposition spec whose pipeline has NO leading reorder (additive
    only) => frame undefined => Bean N/A, never a guessed carved-CT PASS."""
    carved_CT, PT, K, _perm, _inter = _build_known_answer()
    wi = {
        "config_id": "no-route", "challenge_ciphertext": carved_CT,
        "challenge_crib_dict": None, "crib_alignment": "post_transposition",
        "pipeline_dict": {"name": "no_route", "direction": "decrypt",
                          "steps": [_vig_step(K)]},
    }
    result = _evaluate_one(wi)
    assert "error" not in result, result
    assert result["scoring_mode"] == "post_transposition_bean_unavailable"
    assert result["bean_passed"] is False
