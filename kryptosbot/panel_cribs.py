"""Panel-specific crib registries for self-test mode.

Round 2 Phase R2-5 (2026-04-21). The kernel's ``CRIB_DICT``,
``BEAN_EQ``, ``BEAN_INEQ``, ``BEAN_LINEAR`` are derived from K4's
published cribs. When the controller runs against a different panel
(K1, K2, or K3) for a real-API self-test, it needs an alternative
crib set that reflects what the theorist would have known about that
panel — NOT the K4-specific constraints.

Design choice per brief §6.1: the kernel stays K4-specific. Panel
mode is a controller-level override; this module supplies the
override data structures.

For K1 / K2 we use the first + last 10 chars of the known plaintext
as the "pseudo-cribs" — giving the controller comparable information
density to K4's 24 cribs. The Bean equality / inequality / linear
sets are derived from those pseudo-cribs via the same kernel helpers
that built the K4 constraints.

Usage:

    from kryptosbot.panel_cribs import load_panel_cribs

    cribs = load_panel_cribs("k1")
    assert cribs.ct.startswith("EMUFPH")
    assert len(cribs.crib_dict) == 20  # 10 prefix + 10 suffix
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class PanelCribs:
    """All crib-derived constraints for one Kryptos panel.

    Fields mirror the structure of ``kryptos.kernel.constants`` for K4
    but target a different panel's CT + PT. The controller installs
    these under ``self_test_mode`` and routes scoring decisions through
    them.

    Fields:
        panel_id:      "k1" | "k2" | "k3"
        ct:            the panel's canonical ciphertext
        crib_dict:     position → expected plaintext letter (0-indexed)
        bean_eq:       list of (pos_a, pos_b) pairs where k[a] == k[b]
                       (variant-independent equality)
        bean_ineq:     list of (pos_a, pos_b) pairs where k[a] != k[b]
                       under all three Vig/Beau/VarBeau variants
        bean_linear:   list of (a, b, c, d) 4-tuples encoding the
                       variant-independent linear constraints
                       k[a] - k[b] == k[c] - k[d]  (mod 26)
    """
    panel_id: str
    ct: str
    crib_dict: dict[int, str]
    bean_eq: tuple[tuple[int, int], ...] = ()
    bean_ineq: tuple[tuple[int, int], ...] = ()
    bean_linear: tuple[tuple[int, int, int, int], ...] = ()

    def n_cribs(self) -> int:
        return len(self.crib_dict)

    def crib_positions(self) -> tuple[int, ...]:
        return tuple(sorted(self.crib_dict.keys()))


# ─── Panel raw data (public facts) ──────────────────────────────────────────
# These are the published K1 / K2 / K3 ciphertexts and plaintexts. They
# are PUBLIC FACTS from Gillogly/Stein 1999 publications and Elonka
# Dunin's Kryptos page — NOT research-state content.

_K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
_K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
assert len(_K1_CT) == len(_K1_PT) == 63

_K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
    "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLE"
    "CGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH"
    "DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
    "FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVO"
    "EEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
_K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
    "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREES"
    "FIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTIDBYROWS"
)
assert len(_K2_CT) == len(_K2_PT), (
    f"K2 CT len {len(_K2_CT)} != PT len {len(_K2_PT)} — transcription drift"
)

_K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLL"
    "NOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMT"
    "WNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEY"
    "QHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOAS"
    "FIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROA"
    "GRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEH"
    "AGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"
)
_K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPART"
    "OFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHAND"
    "CORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIR"
    "ESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
    "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)
assert len(_K3_CT) == 336
assert len(_K3_PT) == 336


# ─── Crib derivation ────────────────────────────────────────────────────────

def _prefix_suffix_cribs(pt: str, prefix_len: int, suffix_len: int) -> dict[int, str]:
    """Build a position→letter crib dict from the PT's first/last N chars.

    This is how we derive pseudo-cribs for K1 / K2 / K3 in panel mode.
    The rationale (brief §6.1): real Kryptos cribs leaked via quotes,
    plaintext length guesses, thematic hints, etc. 10 prefix + 10 suffix
    characters are a reasonable public-fact information density — in
    the same ballpark as K4's 24 cribs (20 ≈ 24).
    """
    if prefix_len + suffix_len > len(pt):
        raise ValueError(
            f"prefix_len={prefix_len} + suffix_len={suffix_len} exceeds "
            f"PT len {len(pt)}"
        )
    cribs: dict[int, str] = {}
    for i in range(prefix_len):
        cribs[i] = pt[i]
    for i in range(suffix_len):
        cribs[len(pt) - 1 - i] = pt[len(pt) - 1 - i]
    return cribs


def _derive_bean_equalities(
    ct: str, crib_dict: dict[int, str],
) -> tuple[tuple[int, int], ...]:
    """Variant-independent Bean equalities: pairs (a, b) where CT[a]==CT[b]
    AND PT[a]==PT[b]. The key at a must equal the key at b regardless of
    cipher variant (Vig / Beau / VarBeau).
    """
    positions = sorted(crib_dict.keys())
    out: list[tuple[int, int]] = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            if ct[a] == ct[b] and crib_dict[a] == crib_dict[b]:
                out.append((a, b))
    return tuple(out)


def _derive_bean_inequalities(
    ct: str, crib_dict: dict[int, str],
) -> tuple[tuple[int, int], ...]:
    """Variant-independent Bean inequalities: pairs (a, b) where the key
    at a CANNOT equal the key at b under any of the three Vig/Beau/VarBeau
    variants. The construction mirrors the approach in
    ``kryptos.kernel.constraints.derive.derive_bean_constraints`` (the
    canonical shared implementation, which superseded the deleted
    ``kryptos.kernel.constants._derive_bean_ineq``).
    """
    positions = sorted(crib_dict.keys())

    def _key_under_variant(variant: str, c: int, p: int) -> int:
        if variant == "vigenere":
            return (c - p) % 26
        if variant == "beaufort":
            return (c + p) % 26
        if variant == "var_beaufort":
            return (p - c) % 26
        raise ValueError(variant)

    out: list[tuple[int, int]] = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ca, cb = ord(ct[a]) - 65, ord(ct[b]) - 65
            pa, pb = ord(crib_dict[a]) - 65, ord(crib_dict[b]) - 65
            # The pair is a variant-independent inequality if under every
            # variant, the implied key values differ.
            all_distinct = True
            for v in ("vigenere", "beaufort", "var_beaufort"):
                if _key_under_variant(v, ca, pa) == _key_under_variant(v, cb, pb):
                    all_distinct = False
                    break
            if all_distinct:
                out.append((a, b))
    return tuple(out)


# ─── Registry ───────────────────────────────────────────────────────────────

def load_panel_cribs(panel_id: str) -> PanelCribs:
    """Build the PanelCribs object for the named panel.

    Deterministic: the returned object depends only on the published
    panel CT/PT and the brief §6.1 prefix/suffix-10 convention.

    Raises ValueError for unknown panel_ids. Does NOT fall through to
    K4 — panel mode is explicit.
    """
    if panel_id == "k1":
        cribs = _prefix_suffix_cribs(_K1_PT, 10, 10)
        return PanelCribs(
            panel_id="k1",
            ct=_K1_CT,
            crib_dict=cribs,
            bean_eq=_derive_bean_equalities(_K1_CT, cribs),
            bean_ineq=_derive_bean_inequalities(_K1_CT, cribs),
            bean_linear=(),  # linear constraints not ported to self-test; cribs alone suffice
        )
    if panel_id == "k2":
        cribs = _prefix_suffix_cribs(_K2_PT, 10, 10)
        return PanelCribs(
            panel_id="k2",
            ct=_K2_CT,
            crib_dict=cribs,
            bean_eq=_derive_bean_equalities(_K2_CT, cribs),
            bean_ineq=_derive_bean_inequalities(_K2_CT, cribs),
            bean_linear=(),
        )
    if panel_id == "k3":
        cribs = _prefix_suffix_cribs(_K3_PT, 10, 10)
        return PanelCribs(
            panel_id="k3",
            ct=_K3_CT,
            crib_dict=cribs,
            bean_eq=_derive_bean_equalities(_K3_CT, cribs),
            bean_ineq=_derive_bean_inequalities(_K3_CT, cribs),
            bean_linear=(),
        )
    raise ValueError(
        f"unknown panel_id {panel_id!r}; expected one of 'k1', 'k2', 'k3'"
    )


def score_candidate_against_panel(
    candidate_pt: str, panel: PanelCribs,
) -> int:
    """Panel-specific pseudo-crib score: count of positions where the
    candidate plaintext matches the panel's crib_dict.

    Max score is ``panel.n_cribs()``. Used by the real-API self-test
    runner to compute a panel-appropriate analog of K4's
    ``kryptos.kernel.scoring.crib_score.score_cribs``.
    """
    if len(candidate_pt) < len(panel.ct):
        return 0
    hits = 0
    for pos, expected in panel.crib_dict.items():
        if pos < len(candidate_pt) and candidate_pt[pos] == expected:
            hits += 1
    return hits
