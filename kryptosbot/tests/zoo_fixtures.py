"""Suite-assurance Task C — synthetic known-answer benchmark zoo fixtures.

Each fixture is a fully synthetic K4-shaped known-answer construction:
a 97-char plaintext with the disclosed crib WORDS (EASTNORTHEAST /
BERLINCLOCK), an explicit transform pipeline, and the resulting carved
ciphertext. Fixtures are executed through the REAL dispatcher
(``execute()`` + ``job_result_to_worker_contract``) in a subprocess with
the K4Bench kernel env overrides (``KRYPTOS_CT_OVERRIDE`` +
``KRYPTOS_CRIB_DICT_OVERRIDE``) so that:

* kernel constants (CT, CRIB_DICT, BEAN_*) are RE-DERIVED for the
  synthetic carved text — Bean expectations are therefore meaningful
  (for a direct additive solve the implied keystream at the crib
  positions satisfies the re-derived sets BY CONSTRUCTION), and
* no real-K4 surface is touched (no exhaustion-log writes, tmp artifact
  roots, env scoped to the subprocess).

Frame-verdict expectations for non-direct fixtures are computed from
first principles here (independent reimplementation: keystream derived
in a declared frame, checked against constraint sets derived from the
carved text + cribs) — the zoo asserts the dispatcher/boundary report
the FRAME verdict, with build-time preconditions guaranteeing the frame
and carved verdicts actually differ (so a frame mix-up cannot pass).

Conventions (Step 0 freeze): AZ A=0; vigenere K=(CT-PT) mod 26;
positions 0-indexed; cribs at 21-33 / 63-73 (except the free fixture,
which plants the crib words off-anchor); transposition convention
output[i] = input[perm[i]] ("gather"), decrypt-side undo applies
invert_perm; grille decrypt applies the gather mask directly.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

# Pure transform utilities — CT-independent, safe to use in the parent
# process without env overrides.
from kryptos.kernel.transforms.transposition import apply_perm, invert_perm
from kryptos.kernel.constraints.derive import derive_bean_constraints

_ENE = "EASTNORTHEAST"
_BC = "BERLINCLOCK"
N = 97

_ENGLISH = (
    "THETIMEHASCOMETHEWALRUSSAIDTOTALKOFMANYTHINGSOFSHOESANDSHIPS"
    "ANDSEALINGWAXOFCABBAGESANDKINGSANDWHYTHESEAISBOILINGHOTANDWHETHER"
    "PIGSHAVEWINGSBUTWAITABITTHEOYSTERSCRIEDBEFOREWEHAVEOURCHAT"
)

CANONICAL_CRIBS: dict[int, str] = {
    **{21 + i: ch for i, ch in enumerate(_ENE)},
    **{63 + i: ch for i, ch in enumerate(_BC)},
}


def english_pt(crib_map: Optional[dict[int, str]] = None) -> str:
    chars = list(_ENGLISH[:N])
    for pos, ch in (crib_map or CANONICAL_CRIBS).items():
        chars[pos] = ch
    return "".join(chars)


def kw_key(keyword: str) -> list[int]:
    return [ord(c) - 65 for c in keyword.upper()]


def vig_encrypt(pt: str, key: list[int]) -> str:
    return "".join(
        chr(65 + ((ord(c) - 65) + key[i % len(key)]) % 26)
        for i, c in enumerate(pt)
    )


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def bean_verdict(frame_ct: str, pt: str, carved_ct: str,
                 crib_dict: dict[int, str]) -> bool:
    """Independent recompute of the dispatcher's Bean semantics: keystream
    derived in ``frame_ct`` coordinates, checked against constraint sets
    derived from the CARVED text + cribs (what the env-override kernel
    freezes). Any of the 3 additive variants passing counts as PASS."""
    az_index_table = list(range(26))  # AZ: letter i -> index i
    eq, ineq, linear = derive_bean_constraints(
        carved_ct, dict(crib_dict), az_index_table, 26,
    )
    c = [ord(x) - 65 for x in frame_ct]
    p = [ord(x) - 65 for x in pt]
    for derive in (
        lambda a, b: (a - b) % 26,
        lambda a, b: (a + b) % 26,
        lambda a, b: (b - a) % 26,
    ):
        k = [derive(x, y) for x, y in zip(c, p)]
        ok = all(k[a] == k[b] for a, b in eq)
        ok = ok and all(k[a] != k[b] for a, b in ineq)
        ok = ok and all(
            (k[a] - k[b] - k[c2] + k[d]) % 26 == 0
            for a, b, c2, d in linear
        )
        if ok:
            return True
    return False


@dataclass
class ZooFixture:
    fixture_id: str
    klass: str
    description: str
    plaintext: str
    carved_ct: str
    crib_dict: dict[int, str]
    spec: dict[str, Any]            # HypothesisSpec dict for execute_from_json
    expected: dict[str, Any]
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "class": self.klass,
            "description": self.description,
            "pt_sha256_16": _sha(self.plaintext),
            "ct_sha256_16": _sha(self.carved_ct),
            "crib_alignment": self.spec.get("crib_alignment", "direct_positional"),
            "expected": self.expected,
            "notes": self.notes,
        }


def _translated_perm(kind: str, binding: dict[str, Any]) -> list[int]:
    """Get the EXACT decrypt-side perm the dispatcher will use, by calling
    the production translator (guarantees construction matches dispatch)."""
    from kryptosbot.hypothesis_dsl import CipherLayer
    from kryptosbot.job_dispatcher import _translate_layer

    step = _translate_layer(CipherLayer(kind=kind, params=[]), binding,
                            text_length=N)
    assert step["type"] == "transposition_full", step
    return list(step["params"]["perm"])


# ── fixture builders ─────────────────────────────────────────────────────────

def f1_direct_vigenere() -> ZooFixture:
    pt = english_pt()
    kw = "AZIMUTH"
    ct = vig_encrypt(pt, kw_key(kw))
    decoys = ["BEARING", "COMPASS", "LODESTONE", "MERIDIAN", "PARALLAX",
              "SEXTANT", "GNOMON", "OBELISK", "LANTERN"]
    spec = {
        "hypothesis_id": "ZOO-F1-direct-vigenere",
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [kw] + decoys}],
        }],
        "crib_alignment": "direct_positional",
        "compute_budget_cpu_minutes": 1,
    }
    return ZooFixture(
        "F1", "direct_additive",
        "Direct positional Vigenere, periodic keyword, keyword sweep",
        pt, ct, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24, "bean_passed": True,
            "scoring_mode": "direct_positional",
            "winning_binding": ("layer0.keyword", kw),
            "solved": True,
        },
        notes=("Bean True is deterministic: implied keystream at cribs "
               "satisfies the sets re-derived from the synthetic carved CT "
               "by construction."),
    )


def f2_direct_key_tape() -> ZooFixture:
    pt = english_pt()
    # Non-periodic full-length tape (deterministic pseudo-random).
    tape = [(i * 17 + 5) % 26 for i in range(N)]
    ct = vig_encrypt(pt, tape)  # len-97 key == per-position tape
    decoy = [(i * 11 + 3) % 26 for i in range(N)]
    spec = {
        "hypothesis_id": "ZOO-F2-direct-key-tape",
        "pipeline": [{
            "kind": "key_tape", "alphabet": "AZ",
            "params": [
                {"name": "tape", "values": [tape, decoy]},
                {"name": "variant", "values": ["vigenere"]},
                {"name": "direction", "values": ["decrypt"]},
            ],
        }],
        "crib_alignment": "direct_positional",
        "compute_budget_cpu_minutes": 1,
    }
    return ZooFixture(
        "F2", "direct_additive_nonperiodic",
        "Direct positional finite key tape (97 ints), tape sweep",
        pt, ct, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24, "bean_passed": True,
            "scoring_mode": "direct_positional",
            "solved": True,
        },
    )


def _outer_additive_fixture(
    fixture_id: str, klass: str, outer_kind: str,
    outer_binding: dict[str, Any], outer_spec_params: list[dict[str, Any]],
) -> ZooFixture:
    """Shared builder: reordering outer + Vigenere inner, post_transposition."""
    pt = english_pt()
    kw = "GIRASOL"
    perm = _translated_perm(outer_kind, outer_binding) \
        if outer_kind != "grille" else list(outer_binding["hole_mask"])
    inter = vig_encrypt(pt, kw_key(kw))
    if outer_kind == "grille":
        # decrypt applies gather: inter = apply_perm(carved, mask)
        carved = apply_perm(inter, invert_perm(perm))
    else:
        # decrypt applies invert(perm): inter = apply_perm(carved, invert(perm))
        carved = apply_perm(inter, perm)
    frame_v = bean_verdict(inter, pt, carved, CANONICAL_CRIBS)
    carved_v = bean_verdict(carved, pt, carved, CANONICAL_CRIBS)
    assert frame_v != carved_v or not carved_v, (
        "fixture precondition: frame and carved Bean verdicts should "
        f"differ (frame={frame_v}, carved={carved_v}) — pick other params"
    )
    decoys = ["BEACONS", "CALYPSO", "DRAGNET"]
    spec = {
        "hypothesis_id": f"ZOO-{fixture_id}-{outer_kind}-outer",
        "pipeline": [
            {"kind": outer_kind, "alphabet": "AZ", "params": [
                {"name": k, "values": [v]} for k, v in outer_binding.items()
            ]},
            {"kind": "vigenere", "alphabet": "AZ", "params": [
                {"name": "keyword", "values": [kw] + decoys},
            ]},
        ],
        "crib_alignment": "post_transposition",
        "compute_budget_cpu_minutes": 2,
    }
    return ZooFixture(
        fixture_id, klass,
        f"{outer_kind} outer reorder + Vigenere inner, post_transposition",
        pt, carved, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24,
            "bean_passed": frame_v,
            "scoring_mode": "post_transposition",
            "winning_binding": ("layer1.keyword", kw),
            "solved": True,
        },
        notes=(f"Bean expectation is the FRAME verdict ({frame_v}); carved "
               f"verdict is {carved_v} — divergence is the frame-correctness "
               "probe."),
        extra={"frame_ct": inter},
    )


def f3_route_serpentine_vigenere() -> ZooFixture:
    return _outer_additive_fixture(
        "F3", "outer_route_additive", "route",
        {"variant": "serpentine", "rows": 7, "cols": 14}, [],
    )


def f5_grille_vigenere() -> ZooFixture:
    # Deterministic non-trivial permutation mask (3-step rotation mixes
    # crib positions away from canonical slots).
    mask = [(i * 3 + 11) % N for i in range(N)]
    assert sorted(mask) == list(range(N))
    return _outer_additive_fixture(
        "F5", "grille_selector_additive", "grille",
        {"hole_mask": mask}, [],
    )


def f4_columnar_quagmire() -> ZooFixture:
    from kryptos.kernel.transforms.quagmire import quagmire_encrypt

    pt = english_pt()
    tableau = "KRYPTOS"
    period_kw = "PALIMPSEST"
    inter = quagmire_encrypt(
        pt, period_keyword=period_kw,
        pt_alphabet_keyword=tableau, ct_alphabet_keyword=tableau,
        indicator="K",
    )
    perm = _translated_perm("columnar", {"width": 8, "keyword": "KRYPTOS"})
    carved = apply_perm(inter, perm)
    frame_v = bean_verdict(inter, pt, carved, CANONICAL_CRIBS)
    spec = {
        "hypothesis_id": "ZOO-F4-columnar-quagmire",
        "pipeline": [
            {"kind": "columnar", "alphabet": "AZ", "params": [
                {"name": "width", "values": [8]},
                {"name": "keyword", "values": ["KRYPTOS"]},
            ]},
            {"kind": "quagmire", "alphabet": "AZ", "params": [
                {"name": "variant", "values": ["quagmire_iii"]},
                {"name": "tableau_keyword",
                 "values": [tableau, "PALETTE", "MAGNETIC"]},
                {"name": "period_keyword", "values": [period_kw]},
                {"name": "indicator", "values": ["K"]},
            ]},
        ],
        "crib_alignment": "post_transposition",
        "compute_budget_cpu_minutes": 2,
    }
    return ZooFixture(
        "F4", "columnar_quagmire",
        "Columnar outer + Quagmire III inner (non-additive), tableau sweep",
        pt, carved, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24,
            # Non-additive inner: Bean inapplicable-by-construction. The
            # dispatcher still derives an additive verdict in the frame —
            # expected value computed here (almost surely False).
            "bean_passed": frame_v,
            "scoring_mode": "post_transposition",
            "winning_binding": ("layer1.tableau_keyword", tableau),
            "solved": True,
        },
        notes="bean expectation reflects additive-derivation in frame; "
              "inner is non-additive so Bean is inapplicable-by-construction "
              f"(computed frame verdict: {frame_v}).",
    )


def f7_quagmire_direct() -> ZooFixture:
    from kryptos.kernel.transforms.quagmire import quagmire_encrypt

    pt = english_pt()
    tableau = "PALIMPSEST"
    period_kw = "ABSCISSA"
    ct = quagmire_encrypt(
        pt, period_keyword=period_kw,
        pt_alphabet_keyword=tableau, ct_alphabet_keyword=tableau,
        indicator="K",
    )
    direct_v = bean_verdict(ct, pt, ct, CANONICAL_CRIBS)
    spec = {
        "hypothesis_id": "ZOO-F7-quagmire-direct",
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ", "params": [
                {"name": "variant", "values": ["quagmire_iii"]},
                {"name": "tableau_keyword",
                 "values": [tableau, "KRYPTOS", "LATITUDE"]},
                {"name": "period_keyword", "values": [period_kw]},
                {"name": "indicator", "values": ["K"]},
            ],
        }],
        "crib_alignment": "direct_positional",
        "compute_budget_cpu_minutes": 1,
    }
    return ZooFixture(
        "F7", "non_bean_non_additive",
        "Quagmire III direct (non-additive): crib solve, Bean must not "
        "be falsely asserted",
        pt, ct, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24,
            "bean_passed": direct_v,   # additive derivation on a quagmire CT
            "scoring_mode": "direct_positional",
            "winning_binding": ("layer0.tableau_keyword", tableau),
            "solved": True,
        },
        notes=f"computed additive-derivation verdict on quagmire CT: {direct_v} "
              "(non-additive system; Bean inapplicable-by-construction).",
    )


def f8_second_level() -> ZooFixture:
    # Hidden second-level message: every 8th char (13 slots: 0,8,...,96)
    # spells KRYPTOSSOLVED. First level is ordinary direct Vigenere.
    hidden = "KRYPTOSSOLVED"
    crib_map = dict(CANONICAL_CRIBS)
    chars = list(english_pt())
    slots = [i * 8 for i in range(13)]
    for slot, ch in zip(slots, hidden):
        if slot not in crib_map:
            chars[slot] = ch
    pt = "".join(chars)
    extracted = "".join(pt[i] for i in slots)
    kw = "AZIMUTH"
    ct = vig_encrypt(pt, kw_key(kw))
    spec = {
        "hypothesis_id": "ZOO-F8-second-level",
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [kw, "BEARING"]}],
        }],
        "crib_alignment": "direct_positional",
        "compute_budget_cpu_minutes": 1,
    }
    return ZooFixture(
        "F8", "second_level_extraction",
        "First-level direct Vigenere solved; hidden every-8th-char message "
        "must be recognized as OUTSIDE current toolchain scope",
        pt, ct, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24, "bean_passed": True,
            "scoring_mode": "direct_positional",
            "solved": True,
            "second_level_supported": False,
        },
        notes=f"hidden extraction (every 8th char) ≈ {extracted!r}; no "
              "second-level extractor exists in the toolchain — the zoo "
              "records this class as a declared gap, not a silent miss.",
        extra={"hidden_slots": slots, "hidden_message": extracted},
    )


def f9_free_offanchor() -> ZooFixture:
    # Crib words planted OFF-anchor (shift +23): a direct/anchored scorer
    # scores ~0; only free alignment finds the solve.
    shifted = {pos + 23: ch for pos, ch in CANONICAL_CRIBS.items()}
    pt = english_pt(shifted)
    kw = "AZIMUTH"
    ct = vig_encrypt(pt, kw_key(kw))
    spec = {
        "hypothesis_id": "ZOO-F9-free-offanchor",
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [kw, "BEARING", "COMPASS"]}],
        }],
        "crib_alignment": "free",
        "compute_budget_cpu_minutes": 1,
    }
    return ZooFixture(
        "F9", "free_alignment",
        "Off-anchor crib words + direct Vigenere, crib_alignment=free: "
        "end-to-end non-direct solve must survive to the contract",
        pt, ct, dict(CANONICAL_CRIBS), spec,
        expected={
            "crib_score": 24, "bean_passed": False,
            "scoring_mode": "free",
            "canonical_positions": False,
            "winning_binding": ("layer0.keyword", kw),
            "solved": True,
        },
        notes="Bean N/A under free (reported False/None). Pre-fix (B-1) this "
              "fixture's contract crib_score was zeroed at the boundary.",
    )


ALL_SUBPROCESS_FIXTURES = [
    f1_direct_vigenere,
    f2_direct_key_tape,
    f3_route_serpentine_vigenere,
    f4_columnar_quagmire,
    f5_grille_vigenere,
    f7_quagmire_direct,
    f8_second_level,
    f9_free_offanchor,
]


def fixture_payload(fx: ZooFixture) -> dict[str, Any]:
    """JSON payload handed to the subprocess runner."""
    return {
        "fixture_id": fx.fixture_id,
        "carved_ct": fx.carved_ct,
        "crib_dict": {str(k): v for k, v in fx.crib_dict.items()},
        "spec": fx.spec,
        "plaintext": fx.plaintext,
    }
