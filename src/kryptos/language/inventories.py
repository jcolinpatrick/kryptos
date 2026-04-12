"""Hand-curated POS-tagged word inventories for K4 grammar prior.

Every entry is explicitly tagged with a single POS, a length, and per-register
prior weights. The inventories are small and deterministic by design — this
is a constrained grammar prior, not a general dictionary.
"""
from dataclasses import dataclass, field
from typing import Optional

from .communique_models import POS_TAGS, RegisterStyle


@dataclass(frozen=True)
class WordEntry:
    word: str
    pos: str
    length: int
    register_priors: tuple  # tuple of (style_value, weight) for hashability
    notes: str = ""

    @property
    def priors(self) -> dict:
        return dict(self.register_priors)


def _e(word: str, pos: str, priors: dict, notes: str = "") -> WordEntry:
    assert pos in POS_TAGS, f"bad POS {pos}"
    # normalize priors to all 4 registers
    full = {
        RegisterStyle.DIRECTIVE.value: priors.get("directive", 0.5),
        RegisterStyle.STATUS_REPORT.value: priors.get("status_report", 0.5),
        RegisterStyle.TELEGRAPHIC.value: priors.get("telegraphic", 0.5),
        RegisterStyle.HYBRID.value: priors.get("hybrid", 0.5),
    }
    return WordEntry(word=word, pos=pos, length=len(word),
                     register_priors=tuple(sorted(full.items())), notes=notes)


# ---- Prepositions ---------------------------------------------------------
PREPOSITIONS_2: list = [
    _e("AT", "PREP", dict(directive=0.95, status_report=0.7, telegraphic=0.8, hybrid=0.9),
       "locative; strong with landmarks (AT BERLINCLOCK)"),
    _e("TO", "PREP", dict(directive=0.85, status_report=0.6, telegraphic=0.7, hybrid=0.8),
       "directional; GO TO X"),
    _e("IN", "PREP", dict(directive=0.6, status_report=0.7, telegraphic=0.55, hybrid=0.65)),
    _e("ON", "PREP", dict(directive=0.5, status_report=0.6, telegraphic=0.45, hybrid=0.55)),
    _e("OF", "PREP", dict(directive=0.35, status_report=0.55, telegraphic=0.3, hybrid=0.45),
       "weak as pre-landmark; stronger post-landmark (EAST OF X)"),
    _e("BY", "PREP", dict(directive=0.55, status_report=0.5, telegraphic=0.5, hybrid=0.55)),
    _e("UP", "PREP", dict(directive=0.5, status_report=0.3, telegraphic=0.5, hybrid=0.45)),
]

PREPOSITIONS_3_4: list = [
    _e("FOR", "PREP", dict(directive=0.55, status_report=0.55, telegraphic=0.5, hybrid=0.55)),
    _e("OFF", "PREP", dict(directive=0.5, status_report=0.45, telegraphic=0.5, hybrid=0.5)),
    _e("OUT", "PREP", dict(directive=0.55, status_report=0.45, telegraphic=0.55, hybrid=0.55)),
    _e("NEAR", "PREP", dict(directive=0.8, status_report=0.55, telegraphic=0.75, hybrid=0.75),
       "locative; strong with landmark"),
    _e("FROM", "PREP", dict(directive=0.75, status_report=0.55, telegraphic=0.65, hybrid=0.7)),
    _e("INTO", "PREP", dict(directive=0.7, status_report=0.45, telegraphic=0.6, hybrid=0.65)),
    _e("OVER", "PREP", dict(directive=0.6, status_report=0.4, telegraphic=0.55, hybrid=0.55)),
    _e("WITH", "PREP", dict(directive=0.5, status_report=0.6, telegraphic=0.45, hybrid=0.55)),
    _e("UPON", "PREP", dict(directive=0.55, status_report=0.4, telegraphic=0.45, hybrid=0.5),
       "archaic/formal; less telegraphic"),
    _e("ATOP", "PREP", dict(directive=0.55, status_report=0.3, telegraphic=0.55, hybrid=0.5)),
    _e("PAST", "PREP", dict(directive=0.7, status_report=0.4, telegraphic=0.65, hybrid=0.65)),
    _e("ONTO", "PREP", dict(directive=0.6, status_report=0.35, telegraphic=0.55, hybrid=0.55)),
]

# ---- Articles -------------------------------------------------------------
ARTICLES: list = [
    _e("A", "ART", dict(directive=0.4, status_report=0.2, telegraphic=0.05, hybrid=0.35)),
    _e("AN", "ART", dict(directive=0.35, status_report=0.2, telegraphic=0.05, hybrid=0.3)),
    _e("THE", "ART", dict(directive=0.6, status_report=0.3, telegraphic=0.05, hybrid=0.5),
       "standard definite; suppressed in telegraphic register"),
    _e("THIS", "ART", dict(directive=0.4, status_report=0.4, telegraphic=0.1, hybrid=0.4)),
    _e("THAT", "ART", dict(directive=0.4, status_report=0.4, telegraphic=0.1, hybrid=0.4)),
]

# ---- Operational verbs ----------------------------------------------------
OPERATIONAL_VERBS: list = [
    _e("GO", "VERB_OP", dict(directive=0.95, status_report=0.3, telegraphic=0.9, hybrid=0.85),
       "canonical directive verb with directions"),
    _e("IS", "AUX", dict(directive=0.3, status_report=0.7, telegraphic=0.1, hybrid=0.4),
       "copula; often suppressed in telegraphic"),
    _e("BE", "AUX", dict(directive=0.4, status_report=0.5, telegraphic=0.2, hybrid=0.4)),
    _e("DO", "VERB_OP", dict(directive=0.6, status_report=0.4, telegraphic=0.5, hybrid=0.55)),
    _e("GET", "VERB_OP", dict(directive=0.8, status_report=0.4, telegraphic=0.75, hybrid=0.7)),
    _e("RUN", "VERB_OP", dict(directive=0.8, status_report=0.5, telegraphic=0.75, hybrid=0.7)),
    _e("USE", "VERB_OP", dict(directive=0.7, status_report=0.4, telegraphic=0.6, hybrid=0.65)),
    _e("MOVE", "VERB_OP", dict(directive=0.9, status_report=0.4, telegraphic=0.85, hybrid=0.8)),
    _e("MEET", "VERB_OP", dict(directive=0.9, status_report=0.4, telegraphic=0.85, hybrid=0.8),
       "canonical directive with landmark"),
    _e("HEAD", "VERB_OP", dict(directive=0.85, status_report=0.4, telegraphic=0.8, hybrid=0.8)),
    _e("FIND", "VERB_OP", dict(directive=0.8, status_report=0.45, telegraphic=0.75, hybrid=0.75)),
    _e("PASS", "VERB_OP", dict(directive=0.7, status_report=0.4, telegraphic=0.65, hybrid=0.65)),
    _e("KEEP", "VERB_OP", dict(directive=0.75, status_report=0.5, telegraphic=0.7, hybrid=0.7)),
    _e("HOLD", "VERB_OP", dict(directive=0.8, status_report=0.5, telegraphic=0.75, hybrid=0.7)),
    _e("TURN", "VERB_OP", dict(directive=0.85, status_report=0.3, telegraphic=0.8, hybrid=0.75)),
    _e("TAKE", "VERB_OP", dict(directive=0.8, status_report=0.4, telegraphic=0.75, hybrid=0.75)),
    _e("READ", "VERB_OP", dict(directive=0.7, status_report=0.4, telegraphic=0.65, hybrid=0.65)),
    _e("LOOK", "VERB_OP", dict(directive=0.75, status_report=0.4, telegraphic=0.7, hybrid=0.7)),
    _e("SHOW", "VERB_OP", dict(directive=0.6, status_report=0.4, telegraphic=0.55, hybrid=0.55)),
    _e("TELL", "VERB_OP", dict(directive=0.6, status_report=0.45, telegraphic=0.55, hybrid=0.55)),
    _e("VIEW", "VERB_OP", dict(directive=0.7, status_report=0.4, telegraphic=0.65, hybrid=0.65)),
    _e("SEEK", "VERB_OP", dict(directive=0.8, status_report=0.4, telegraphic=0.75, hybrid=0.7)),
    _e("PROCEED", "VERB_OP", dict(directive=0.85, status_report=0.3, telegraphic=0.6, hybrid=0.7)),
    _e("REPORT", "VERB_OP", dict(directive=0.6, status_report=0.85, telegraphic=0.5, hybrid=0.7)),
    _e("DEPART", "VERB_OP", dict(directive=0.8, status_report=0.4, telegraphic=0.65, hybrid=0.7)),
    _e("RETURN", "VERB_OP", dict(directive=0.8, status_report=0.4, telegraphic=0.7, hybrid=0.7)),
    _e("ADVANCE", "VERB_OP", dict(directive=0.85, status_report=0.4, telegraphic=0.7, hybrid=0.75)),
]

# ---- Status nouns ---------------------------------------------------------
STATUS_NOUNS: list = [
    _e("ASSET", "NOUN_STATUS", dict(directive=0.4, status_report=0.95, telegraphic=0.85, hybrid=0.75),
       "canonical status-report subject"),
    _e("AGENT", "NOUN_STATUS", dict(directive=0.45, status_report=0.9, telegraphic=0.8, hybrid=0.75)),
    _e("CONTACT", "NOUN_STATUS", dict(directive=0.5, status_report=0.85, telegraphic=0.75, hybrid=0.7)),
    _e("SIGNAL", "NOUN_STATUS", dict(directive=0.4, status_report=0.9, telegraphic=0.8, hybrid=0.7)),
    _e("STATUS", "NOUN_STATUS", dict(directive=0.3, status_report=0.85, telegraphic=0.7, hybrid=0.65)),
    _e("REPORT", "NOUN_STATUS", dict(directive=0.3, status_report=0.85, telegraphic=0.7, hybrid=0.65)),
    _e("OPERATIVE", "NOUN_STATUS", dict(directive=0.35, status_report=0.85, telegraphic=0.65, hybrid=0.65)),
    _e("PACKAGE", "NOUN_STATUS", dict(directive=0.45, status_report=0.8, telegraphic=0.75, hybrid=0.7)),
    _e("TARGET", "NOUN_STATUS", dict(directive=0.5, status_report=0.8, telegraphic=0.75, hybrid=0.7)),
    _e("MISSION", "NOUN_STATUS", dict(directive=0.35, status_report=0.85, telegraphic=0.7, hybrid=0.65)),
]

# ---- Status adjectives / participles --------------------------------------
STATUS_ADJECTIVES: list = [
    _e("COMPROMISED", "ADJ", dict(directive=0.2, status_report=0.95, telegraphic=0.85, hybrid=0.7),
       "canonical STATUS + ADJ pattern"),
    _e("LOST", "ADJ", dict(directive=0.3, status_report=0.9, telegraphic=0.85, hybrid=0.7)),
    _e("DEAD", "ADJ", dict(directive=0.3, status_report=0.85, telegraphic=0.8, hybrid=0.65)),
    _e("SAFE", "ADJ", dict(directive=0.4, status_report=0.85, telegraphic=0.75, hybrid=0.7)),
    _e("READY", "ADJ", dict(directive=0.5, status_report=0.85, telegraphic=0.75, hybrid=0.7)),
    _e("ARMED", "ADJ", dict(directive=0.4, status_report=0.85, telegraphic=0.8, hybrid=0.7)),
    _e("ACTIVE", "ADJ", dict(directive=0.4, status_report=0.85, telegraphic=0.75, hybrid=0.7)),
    _e("CLEAR", "ADJ", dict(directive=0.5, status_report=0.85, telegraphic=0.8, hybrid=0.7)),
    _e("DOWN", "ADJ", dict(directive=0.4, status_report=0.8, telegraphic=0.75, hybrid=0.65)),
    _e("GONE", "ADJ", dict(directive=0.3, status_report=0.8, telegraphic=0.75, hybrid=0.65)),
    _e("RECEIVED", "ADJ", dict(directive=0.3, status_report=0.85, telegraphic=0.7, hybrid=0.65)),
]

# ---- Location nouns -------------------------------------------------------
LOCATION_NOUNS: list = [
    _e("POINT", "NOUN_LOC", dict(directive=0.85, status_report=0.5, telegraphic=0.8, hybrid=0.75)),
    _e("SITE", "NOUN_LOC", dict(directive=0.85, status_report=0.6, telegraphic=0.8, hybrid=0.75)),
    _e("AREA", "NOUN_LOC", dict(directive=0.7, status_report=0.55, telegraphic=0.65, hybrid=0.65)),
    _e("ZONE", "NOUN_LOC", dict(directive=0.8, status_report=0.6, telegraphic=0.75, hybrid=0.7)),
    _e("GRID", "NOUN_LOC", dict(directive=0.75, status_report=0.55, telegraphic=0.7, hybrid=0.7)),
    _e("PLACE", "NOUN_LOC", dict(directive=0.75, status_report=0.5, telegraphic=0.7, hybrid=0.7)),
    _e("MARK", "NOUN_LOC", dict(directive=0.75, status_report=0.5, telegraphic=0.7, hybrid=0.7)),
    _e("EDGE", "NOUN_LOC", dict(directive=0.65, status_report=0.5, telegraphic=0.6, hybrid=0.6)),
    _e("GATE", "NOUN_LOC", dict(directive=0.8, status_report=0.5, telegraphic=0.75, hybrid=0.7)),
    _e("DOOR", "NOUN_LOC", dict(directive=0.75, status_report=0.5, telegraphic=0.7, hybrid=0.7)),
    _e("WALL", "NOUN_LOC", dict(directive=0.8, status_report=0.5, telegraphic=0.75, hybrid=0.7)),
    _e("ROOM", "NOUN_LOC", dict(directive=0.7, status_report=0.5, telegraphic=0.65, hybrid=0.65)),
]

# ---- Directions -----------------------------------------------------------
DIRECTIONS: list = [
    _e("NORTH", "DIRECTION", dict(directive=0.9, status_report=0.45, telegraphic=0.85, hybrid=0.8)),
    _e("SOUTH", "DIRECTION", dict(directive=0.9, status_report=0.45, telegraphic=0.85, hybrid=0.8)),
    _e("EAST", "DIRECTION", dict(directive=0.9, status_report=0.45, telegraphic=0.85, hybrid=0.8)),
    _e("WEST", "DIRECTION", dict(directive=0.9, status_report=0.45, telegraphic=0.85, hybrid=0.8)),
    _e("EASTNORTHEAST", "DIRECTION", dict(directive=0.95, status_report=0.4, telegraphic=0.9, hybrid=0.85),
       "K4 released crib, 21-33 (0-indexed)"),
]

# ---- Pronouns -------------------------------------------------------------
PRONOUNS: list = [
    _e("IT", "PRONOUN", dict(directive=0.4, status_report=0.6, telegraphic=0.35, hybrid=0.5)),
    _e("WE", "PRONOUN", dict(directive=0.45, status_report=0.7, telegraphic=0.35, hybrid=0.55)),
    _e("US", "PRONOUN", dict(directive=0.4, status_report=0.55, telegraphic=0.3, hybrid=0.45)),
    _e("ME", "PRONOUN", dict(directive=0.4, status_report=0.5, telegraphic=0.3, hybrid=0.45)),
    _e("MY", "PRONOUN", dict(directive=0.3, status_report=0.45, telegraphic=0.25, hybrid=0.4)),
    _e("HE", "PRONOUN", dict(directive=0.3, status_report=0.6, telegraphic=0.3, hybrid=0.5)),
    _e("HIM", "PRONOUN", dict(directive=0.3, status_report=0.55, telegraphic=0.25, hybrid=0.45)),
    _e("OUR", "PRONOUN", dict(directive=0.35, status_report=0.6, telegraphic=0.3, hybrid=0.5)),
    _e("YOU", "PRONOUN", dict(directive=0.5, status_report=0.55, telegraphic=0.4, hybrid=0.55)),
]

# ---- Conjunctions ---------------------------------------------------------
CONJUNCTIONS: list = [
    _e("AND", "CONJ", dict(directive=0.7, status_report=0.7, telegraphic=0.6, hybrid=0.7)),
    _e("OR", "CONJ", dict(directive=0.55, status_report=0.55, telegraphic=0.5, hybrid=0.55)),
    _e("IF", "CONJ", dict(directive=0.55, status_report=0.5, telegraphic=0.45, hybrid=0.55)),
    _e("SO", "CONJ", dict(directive=0.5, status_report=0.45, telegraphic=0.4, hybrid=0.5)),
    _e("BUT", "CONJ", dict(directive=0.5, status_report=0.55, telegraphic=0.45, hybrid=0.55)),
]


_ALL_LISTS = [
    PREPOSITIONS_2, PREPOSITIONS_3_4, ARTICLES, OPERATIONAL_VERBS,
    STATUS_NOUNS, STATUS_ADJECTIVES, LOCATION_NOUNS, DIRECTIONS,
    PRONOUNS, CONJUNCTIONS,
]


def all_entries() -> list:
    out = []
    seen = set()
    for lst in _ALL_LISTS:
        for e in lst:
            key = (e.word, e.pos)
            if key in seen:
                continue
            seen.add(key)
            out.append(e)
    return out


def entries_by_length(length: int) -> list:
    return [e for e in all_entries() if e.length == length]


def entries_by_pos(pos: str) -> list:
    return [e for e in all_entries() if e.pos == pos]


def entries_by_length_and_pos(length: int, pos: str) -> list:
    return [e for e in all_entries() if e.length == length and e.pos == pos]


def entries_by_register(register) -> list:
    if hasattr(register, "value"):
        key = register.value
    else:
        key = str(register)
    out = []
    for e in all_entries():
        if e.priors.get(key, 0.0) >= 0.5:
            out.append(e)
    return out


def find_word(word: str) -> Optional[WordEntry]:
    word = word.upper()
    for e in all_entries():
        if e.word == word:
            return e
    return None
