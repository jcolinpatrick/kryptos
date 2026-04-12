"""Communique register models for Kryptos K4 grammar prior.

A "register" is a stylistic mode of compressed operational English. Each
register has preferences over POS at different sentence positions, article
suppression, copula omission, and relative prior weight.

The POS tag set used throughout ``kryptos.language``:

    PREP         — preposition (AT, TO, OF, BY, ...)
    ART          — article / determiner (A, AN, THE, THIS, THAT)
    AUX          — auxiliary verb (IS, WAS, HAS, ...)
    VERB_OP      — operational / imperative verb (GO, MEET, MOVE, ...)
    NOUN_LOC     — location noun (SITE, POINT, GATE, ...)
    NOUN_STATUS  — status / actor noun (ASSET, AGENT, SIGNAL, ...)
    DIRECTION    — compass / directional (NORTH, EAST, ...)
    ADJ          — adjective / participle-as-adjective (SAFE, READY, ARMED)
    ADV          — adverb (NOW, HERE, THERE, SOON)
    PARTICLE     — particle (OFF, OUT, UP, DOWN when particle-like)
    PRONOUN      — pronoun (IT, WE, US, ...)
    CONJ         — conjunction (AND, OR, IF, BUT)
    NUM          — numeric word (ONE, TWO, ...)

This tag set is intentionally small and hand-curated. It is not a general
POS tagger — it is a constrained vocabulary for ranking short candidate
phrases around the known K4 anchors.
"""
from dataclasses import dataclass, field
from enum import Enum

POS_TAGS = (
    "PREP", "ART", "AUX", "VERB_OP", "NOUN_LOC", "NOUN_STATUS",
    "DIRECTION", "ADJ", "ADV", "PARTICLE", "PRONOUN", "CONJ", "NUM",
)


class RegisterStyle(str, Enum):
    DIRECTIVE = "directive"
    STATUS_REPORT = "status_report"
    TELEGRAPHIC = "telegraphic"
    HYBRID = "hybrid"


@dataclass(frozen=True)
class CommuniqueRegister:
    """A register model for compressed operational English.

    Attributes:
        style: RegisterStyle enum
        name: human-readable short name
        description: prose description of the register
        article_suppression: 0.0 = always keep articles, 1.0 = always drop
        copula_omission: 0.0 = always keep copula (IS/ARE), 1.0 = always drop
        initial_pos_weights: weight per POS tag at sentence-initial position
        midclause_pos_weights: weight per POS tag mid-clause
        final_pos_weights: weight per POS tag at sentence-final position
        prior_weight: overall weight of this register relative to others
    """
    style: RegisterStyle
    name: str
    description: str
    article_suppression: float
    copula_omission: float
    initial_pos_weights: dict
    midclause_pos_weights: dict
    final_pos_weights: dict
    prior_weight: float = 1.0


def _weights(**kw) -> dict:
    """Fill unspecified POS tags with a floor weight."""
    base = {tag: 0.1 for tag in POS_TAGS}
    base.update(kw)
    return base


def directive_register() -> CommuniqueRegister:
    return CommuniqueRegister(
        style=RegisterStyle.DIRECTIVE,
        name="directive",
        description=(
            "Imperative / operational. Sentence-initial VERB_OP or DIRECTION, "
            "often followed by a prepositional phrase naming a landmark. "
            "Example: GO EASTNORTHEAST / MEET AT BERLINCLOCK."
        ),
        article_suppression=0.55,
        copula_omission=0.8,
        initial_pos_weights=_weights(
            VERB_OP=1.0, DIRECTION=0.8, PREP=0.3, ADV=0.4, NOUN_LOC=0.3,
        ),
        midclause_pos_weights=_weights(
            PREP=0.9, ART=0.5, NOUN_LOC=0.9, DIRECTION=0.7, ADJ=0.5, NUM=0.4,
        ),
        final_pos_weights=_weights(
            NOUN_LOC=1.0, DIRECTION=0.9, NOUN_STATUS=0.5, ADJ=0.4, ADV=0.3,
        ),
        prior_weight=1.0,
    )


def status_report_register() -> CommuniqueRegister:
    return CommuniqueRegister(
        style=RegisterStyle.STATUS_REPORT,
        name="status_report",
        description=(
            "Status / situation report. Sentence-initial NOUN_STATUS followed "
            "by an ADJ/participle. Example: ASSET COMPROMISED / SIGNAL LOST."
        ),
        article_suppression=0.85,
        copula_omission=0.95,
        initial_pos_weights=_weights(
            NOUN_STATUS=1.0, PRONOUN=0.5, NOUN_LOC=0.4, AUX=0.2,
        ),
        midclause_pos_weights=_weights(
            AUX=0.7, PREP=0.6, ADJ=0.7, NOUN_LOC=0.5, VERB_OP=0.4, ART=0.2,
        ),
        final_pos_weights=_weights(
            ADJ=1.0, VERB_OP=0.6, NOUN_LOC=0.4, ADV=0.3,
        ),
        prior_weight=0.9,
    )


def telegraphic_register() -> CommuniqueRegister:
    return CommuniqueRegister(
        style=RegisterStyle.TELEGRAPHIC,
        name="telegraphic",
        description=(
            "Article-suppressed, compressed-to-minimum English. Drops articles, "
            "copulas, and prepositions where possible. Example: MEET BERLINCLOCK."
        ),
        article_suppression=0.95,
        copula_omission=1.0,
        initial_pos_weights=_weights(
            VERB_OP=0.9, NOUN_STATUS=0.8, NOUN_LOC=0.6, DIRECTION=0.6,
        ),
        midclause_pos_weights=_weights(
            NOUN_LOC=0.9, DIRECTION=0.8, ADJ=0.6, NOUN_STATUS=0.5, PREP=0.3, ART=0.05,
        ),
        final_pos_weights=_weights(
            NOUN_LOC=1.0, DIRECTION=0.9, ADJ=0.6, NOUN_STATUS=0.4,
        ),
        prior_weight=1.0,
    )


def hybrid_register() -> CommuniqueRegister:
    return CommuniqueRegister(
        style=RegisterStyle.HYBRID,
        name="hybrid",
        description=(
            "Mixed register: may combine directive clauses with status fragments. "
            "Used as a fallback when no single register dominates."
        ),
        article_suppression=0.7,
        copula_omission=0.85,
        initial_pos_weights=_weights(
            VERB_OP=0.8, NOUN_STATUS=0.8, DIRECTION=0.6, NOUN_LOC=0.5, PREP=0.3,
        ),
        midclause_pos_weights=_weights(
            PREP=0.7, NOUN_LOC=0.8, DIRECTION=0.7, ADJ=0.6, ART=0.3, VERB_OP=0.5,
        ),
        final_pos_weights=_weights(
            NOUN_LOC=0.9, DIRECTION=0.8, ADJ=0.6, NOUN_STATUS=0.5,
        ),
        prior_weight=0.7,
    )


def all_registers() -> list:
    return [
        directive_register(),
        status_report_register(),
        telegraphic_register(),
        hybrid_register(),
    ]


def register_by_style(style) -> CommuniqueRegister:
    if isinstance(style, str):
        style = RegisterStyle(style)
    for r in all_registers():
        if r.style == style:
            return r
    raise KeyError(style)
