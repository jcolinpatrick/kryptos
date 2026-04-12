"""Phrase template system for K4 grammar prior."""
from dataclasses import dataclass
from typing import Optional

from .communique_models import RegisterStyle


@dataclass(frozen=True)
class Slot:
    name: str
    allowed_pos: tuple
    optional: bool = False
    length_constraint: tuple = ()
    semantic_role: str = ""


@dataclass(frozen=True)
class PhraseTemplate:
    template_id: str
    name: str
    register: str
    slots: tuple
    description: str
    example: str
    prior_weight: float = 1.0


DIRECTIVE_VERB_DIRECTION = PhraseTemplate(
    template_id="directive_verb_direction",
    name="VERB + DIRECTION",
    register=RegisterStyle.DIRECTIVE.value,
    slots=(
        Slot("verb", ("VERB_OP",), optional=False, semantic_role="action"),
        Slot("direction", ("DIRECTION",), optional=False, semantic_role="heading"),
    ),
    description="Imperative verb followed by a compass direction.",
    example="GO EASTNORTHEAST",
    prior_weight=1.1,
)

DIRECTIVE_VERB_PREP_LANDMARK = PhraseTemplate(
    template_id="directive_verb_prep_landmark",
    name="VERB + PREP + LANDMARK",
    register=RegisterStyle.DIRECTIVE.value,
    slots=(
        Slot("verb", ("VERB_OP",), optional=False, semantic_role="action"),
        Slot("prep", ("PREP",), optional=False, semantic_role="relation"),
        Slot("landmark", ("NOUN_LOC",), optional=False, semantic_role="landmark"),
    ),
    description="Imperative verb, preposition, and locative landmark.",
    example="MEET AT BERLINCLOCK",
    prior_weight=1.0,
)

LANDMARK_PREP_DESTINATION = PhraseTemplate(
    template_id="landmark_prep_destination",
    name="LANDMARK + PREP + DESTINATION",
    register=RegisterStyle.DIRECTIVE.value,
    slots=(
        Slot("landmark", ("NOUN_LOC",), optional=False),
        Slot("prep", ("PREP",), optional=False),
        Slot("destination", ("NOUN_LOC", "DIRECTION"), optional=False),
    ),
    description="Landmark referenced relative to a destination or heading.",
    example="BERLINCLOCK TO EAST",
    prior_weight=0.8,
)

STATUS_NOUN_PARTICIPLE = PhraseTemplate(
    template_id="status_noun_participle",
    name="STATUS + PARTICIPLE",
    register=RegisterStyle.STATUS_REPORT.value,
    slots=(
        Slot("status", ("NOUN_STATUS",), optional=False),
        Slot("participle", ("ADJ", "VERB_OP"), optional=False),
    ),
    description="Status noun followed by adjective/participle.",
    example="ASSET COMPROMISED",
    prior_weight=1.1,
)

DIRECTIVE_LOCATIVE_TARGET = PhraseTemplate(
    template_id="directive_locative_target",
    name="VERB + (PREP)? + LOCATIVE",
    register=RegisterStyle.TELEGRAPHIC.value,
    slots=(
        Slot("verb", ("VERB_OP",), optional=False),
        Slot("prep", ("PREP",), optional=True),
        Slot("locative", ("NOUN_LOC",), optional=False),
    ),
    description="Imperative verb with optional preposition (telegraphic).",
    example="MEET BERLINCLOCK",
    prior_weight=0.95,
)

COMPRESSED_HEADLINE = PhraseTemplate(
    template_id="compressed_headline",
    name="NOUN + VERB / HEADLINE",
    register=RegisterStyle.TELEGRAPHIC.value,
    slots=(
        Slot("subject", ("NOUN_STATUS", "NOUN_LOC"), optional=False),
        Slot("action", ("VERB_OP", "ADJ"), optional=False),
    ),
    description="Telegraphic headline form.",
    example="SIGNAL LOST",
    prior_weight=0.9,
)

ANCHOR_LEFT_PREP = PhraseTemplate(
    template_id="anchor_left_prep",
    name="PREP + ANCHOR",
    register=RegisterStyle.DIRECTIVE.value,
    slots=(
        Slot("prep", ("PREP",), optional=False),
        Slot("anchor", ("NOUN_LOC", "DIRECTION"), optional=False),
    ),
    description="Preposition followed by anchor (for left-context queries).",
    example="AT BERLINCLOCK",
    prior_weight=0.95,
)

ANCHOR_RIGHT_PREP = PhraseTemplate(
    template_id="anchor_right_prep",
    name="ANCHOR + PREP",
    register=RegisterStyle.DIRECTIVE.value,
    slots=(
        Slot("anchor", ("NOUN_LOC", "DIRECTION"), optional=False),
        Slot("prep", ("PREP",), optional=False),
    ),
    description="Anchor followed by a preposition leading to next phrase.",
    example="BERLINCLOCK TO",
    prior_weight=0.7,
)

ANCHOR_LEFT_VERB = PhraseTemplate(
    template_id="anchor_left_verb",
    name="VERB + ANCHOR",
    register=RegisterStyle.TELEGRAPHIC.value,
    slots=(
        Slot("verb", ("VERB_OP",), optional=False),
        Slot("anchor", ("NOUN_LOC", "DIRECTION"), optional=False),
    ),
    description="Verb directly followed by anchor (telegraphic).",
    example="GO EASTNORTHEAST",
    prior_weight=1.0,
)


_ALL = [
    DIRECTIVE_VERB_DIRECTION,
    DIRECTIVE_VERB_PREP_LANDMARK,
    LANDMARK_PREP_DESTINATION,
    STATUS_NOUN_PARTICIPLE,
    DIRECTIVE_LOCATIVE_TARGET,
    COMPRESSED_HEADLINE,
    ANCHOR_LEFT_PREP,
    ANCHOR_RIGHT_PREP,
    ANCHOR_LEFT_VERB,
]


def all_templates() -> list:
    return list(_ALL)


def templates_by_register(register) -> list:
    if hasattr(register, "value"):
        key = register.value
    else:
        key = str(register)
    return [t for t in _ALL if t.register == key]


def template_by_id(tid: str) -> Optional[PhraseTemplate]:
    for t in _ALL:
        if t.template_id == tid:
            return t
    return None
