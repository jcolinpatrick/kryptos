"""Core grammar-prior scorer for K4 candidate phrases.

This is a SOFT PRIOR. It must never promote candidates to "signal" or "crib"
status. It produces transparent, rule-based score breakdowns for ranking short
phrases around the known K4 anchors.
"""
from dataclasses import dataclass, field
from typing import Optional

from .communique_models import (
    CommuniqueRegister, RegisterStyle, all_registers, register_by_style,
)
from .templates import (
    PhraseTemplate, Slot, all_templates, template_by_id,
    ANCHOR_LEFT_PREP, ANCHOR_LEFT_VERB, ANCHOR_RIGHT_PREP,
    DIRECTIVE_VERB_DIRECTION, DIRECTIVE_VERB_PREP_LANDMARK,
    STATUS_NOUN_PARTICIPLE, DIRECTIVE_LOCATIVE_TARGET,
)
from .inventories import WordEntry, all_entries, entries_by_length, find_word


# ---- Known anchors --------------------------------------------------------
KNOWN_ANCHORS = {"BERLINCLOCK", "EASTNORTHEAST"}


# Hand-curated anchor context table:
#   (anchor, neighbor_word, side) -> plausibility in [0.0, 1.0]
# Left side = word immediately before anchor; right side = after.
ANCHOR_CONTEXT_PRIORS = {
    # BERLINCLOCK left context
    ("BERLINCLOCK", "AT", "left"):   0.95,
    ("BERLINCLOCK", "NEAR", "left"): 0.90,
    ("BERLINCLOCK", "TO", "left"):   0.80,
    ("BERLINCLOCK", "FROM", "left"): 0.75,
    ("BERLINCLOCK", "BY", "left"):   0.70,
    ("BERLINCLOCK", "PAST", "left"): 0.70,
    ("BERLINCLOCK", "THE", "left"):  0.60,
    ("BERLINCLOCK", "UPON", "left"): 0.55,
    ("BERLINCLOCK", "OF", "left"):   0.30,
    ("BERLINCLOCK", "A", "left"):    0.25,
    ("BERLINCLOCK", "MEET", "left"): 0.85,
    ("BERLINCLOCK", "FIND", "left"): 0.75,
    ("BERLINCLOCK", "SEEK", "left"): 0.75,
    ("BERLINCLOCK", "REACH", "left"):0.80,
    # BERLINCLOCK right context
    ("BERLINCLOCK", "TO", "right"):   0.75,
    ("BERLINCLOCK", "AT", "right"):   0.35,
    ("BERLINCLOCK", "AND", "right"):  0.70,
    ("BERLINCLOCK", "OR", "right"):   0.55,
    ("BERLINCLOCK", "GO", "right"):   0.65,
    ("BERLINCLOCK", "IS", "right"):   0.40,
    ("BERLINCLOCK", "FOR", "right"):  0.55,
    # EASTNORTHEAST left context
    ("EASTNORTHEAST", "GO", "left"):     0.90,
    ("EASTNORTHEAST", "HEAD", "left"):   0.85,
    ("EASTNORTHEAST", "MOVE", "left"):   0.85,
    ("EASTNORTHEAST", "TURN", "left"):   0.80,
    ("EASTNORTHEAST", "PROCEED", "left"):0.80,
    ("EASTNORTHEAST", "RUN", "left"):    0.70,
    ("EASTNORTHEAST", "TO", "left"):     0.55,
    ("EASTNORTHEAST", "AT", "left"):     0.35,
    ("EASTNORTHEAST", "OF", "left"):     0.20,
    ("EASTNORTHEAST", "THE", "left"):    0.20,
    # EASTNORTHEAST right context
    ("EASTNORTHEAST", "TO", "right"):    0.75,
    ("EASTNORTHEAST", "OF", "right"):    0.50,
    ("EASTNORTHEAST", "AND", "right"):   0.65,
    ("EASTNORTHEAST", "FROM", "right"):  0.45,
    ("EASTNORTHEAST", "AT", "right"):    0.30,
    ("EASTNORTHEAST", "IS", "right"):    0.30,
    ("EASTNORTHEAST", "GO", "right"):    0.40,
}


# Hand-curated semantic coherence rules for (verb, prep, noun) triples.
COHERENT_VERB_PREP = {
    ("MEET", "AT"): 1.0, ("MEET", "NEAR"): 0.9, ("MEET", "BY"): 0.7,
    ("GO", "TO"):   1.0, ("GO", "PAST"):  0.8, ("GO", "NEAR"): 0.7,
    ("HEAD", "TO"): 1.0, ("HEAD", "FOR"): 0.85,
    ("MOVE", "TO"): 0.95, ("MOVE", "PAST"):0.8,
    ("FIND", "AT"): 0.9, ("FIND", "NEAR"): 0.85,
    ("SEEK", "AT"): 0.85,
    ("PASS", "BY"): 0.9, ("PASS", "THROUGH"): 0.85,
    ("LOOK", "AT"): 0.9, ("LOOK", "TO"):   0.7,
    ("TURN", "AT"): 0.85, ("TURN", "TO"):   0.8,
    ("RETURN", "TO"): 0.95,
    ("PROCEED", "TO"): 0.95,
    ("DEPART", "FROM"): 0.95,
    ("REPORT", "TO"): 0.9,
}


DEFAULT_WEIGHTS = {
    "slot_length_compat": 1.5,
    "pos_compat": 2.0,
    "template_fit": 1.5,
    "anchor_context_plausibility": 2.5,
    "register_plausibility": 1.5,
    "article_suppression_consistency": 0.5,
    "semantic_coherence": 1.0,
}


@dataclass
class ScoreBreakdown:
    candidate: str
    template_id: str
    register: str
    slot_length_compat: float = 0.0
    pos_compat: float = 0.0
    template_fit: float = 0.0
    anchor_context_plausibility: float = 0.0
    register_plausibility: float = 0.0
    article_suppression_consistency: float = 0.0
    semantic_coherence: float = 0.0
    aggregate: float = 0.0
    components: dict = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate,
            "template_id": self.template_id,
            "register": self.register,
            "slot_length_compat": self.slot_length_compat,
            "pos_compat": self.pos_compat,
            "template_fit": self.template_fit,
            "anchor_context_plausibility": self.anchor_context_plausibility,
            "register_plausibility": self.register_plausibility,
            "article_suppression_consistency": self.article_suppression_consistency,
            "semantic_coherence": self.semantic_coherence,
            "aggregate": self.aggregate,
            "components": dict(self.components),
            "notes": self.notes,
        }


@dataclass
class CandidateFill:
    slot_words: tuple
    template: PhraseTemplate
    register: CommuniqueRegister

    @property
    def phrase(self) -> str:
        return " ".join(w for w in self.slot_words if w)


# ---- Component scoring ----------------------------------------------------

def _resolve_entries(words: tuple):
    out = []
    for w in words:
        if not w:
            out.append(None)
            continue
        wu = w.upper()
        if wu in KNOWN_ANCHORS:
            pos = "NOUN_LOC" if wu == "BERLINCLOCK" else "DIRECTION"
            out.append(WordEntry(word=wu, pos=pos, length=len(wu),
                                 register_priors=(), notes="anchor"))
        else:
            out.append(find_word(wu))
    return out


def _slot_length_compat(template: PhraseTemplate, words: tuple) -> float:
    if not template.slots:
        return 0.0
    hits = 0
    total = 0
    for slot, word in zip(template.slots, words):
        if slot.optional and not word:
            continue
        total += 1
        if not word:
            continue
        if not slot.length_constraint or len(word) in slot.length_constraint:
            hits += 1
    return hits / total if total else 0.0


def _pos_compat(template: PhraseTemplate, entries: list) -> float:
    if not template.slots:
        return 0.0
    hits = 0
    total = 0
    for slot, ent in zip(template.slots, entries):
        if slot.optional and ent is None:
            continue
        total += 1
        if ent is None:
            continue
        if ent.pos in slot.allowed_pos:
            hits += 1
    return hits / total if total else 0.0


def _template_fit(length_c: float, pos_c: float, template: PhraseTemplate,
                  words: tuple) -> float:
    # all mandatory slots filled?
    ok = True
    for slot, w in zip(template.slots, words):
        if not slot.optional and not w:
            ok = False
            break
    factor = 1.0 if ok else 0.5
    return length_c * pos_c * factor


def _anchor_context(words: tuple, entries: list,
                    anchor: str, anchor_pos: str) -> float:
    if not anchor:
        return 0.5
    anchor_u = anchor.upper()
    # find neighbor words based on anchor_pos
    neighbors = []  # list of (word, side)
    phrase_words = [w.upper() for w in words if w]
    if anchor_u in phrase_words:
        idx = phrase_words.index(anchor_u)
        if idx > 0:
            neighbors.append((phrase_words[idx - 1], "left"))
        if idx < len(phrase_words) - 1:
            neighbors.append((phrase_words[idx + 1], "right"))
    else:
        # no explicit anchor in phrase — use anchor_pos hint
        if anchor_pos == "left" and phrase_words:
            neighbors.append((phrase_words[-1], "left"))
        elif anchor_pos == "right" and phrase_words:
            neighbors.append((phrase_words[0], "right"))
        elif anchor_pos == "center" and len(phrase_words) >= 2:
            neighbors.append((phrase_words[0], "left"))
            neighbors.append((phrase_words[-1], "right"))
        elif phrase_words:
            neighbors.append((phrase_words[0], "left"))

    if not neighbors:
        return 0.4
    scores = []
    for nw, side in neighbors:
        key = (anchor_u, nw, side)
        if key in ANCHOR_CONTEXT_PRIORS:
            scores.append(ANCHOR_CONTEXT_PRIORS[key])
        else:
            # fallback: POS-based default
            ent = find_word(nw)
            if ent is None:
                scores.append(0.35)
            elif ent.pos == "PREP":
                scores.append(0.55)
            elif ent.pos == "VERB_OP":
                scores.append(0.55 if side == "left" else 0.35)
            elif ent.pos == "ART":
                scores.append(0.4)
            elif ent.pos == "CONJ":
                scores.append(0.55)
            else:
                scores.append(0.4)
    return sum(scores) / len(scores)


def _register_plausibility(register: CommuniqueRegister, entries: list) -> float:
    live = [e for e in entries if e is not None]
    if not live:
        return 0.0
    weights = []
    for i, ent in enumerate(live):
        if i == 0:
            w = register.initial_pos_weights.get(ent.pos, 0.1)
        elif i == len(live) - 1:
            w = register.final_pos_weights.get(ent.pos, 0.1)
        else:
            w = register.midclause_pos_weights.get(ent.pos, 0.1)
        weights.append(w)
    return sum(weights) / len(weights)


def _article_suppression_consistency(register: CommuniqueRegister,
                                     entries: list) -> float:
    live = [e for e in entries if e is not None]
    if not live:
        return 0.5
    art_present = any(e.pos == "ART" for e in live)
    supp = register.article_suppression
    # expected presence prob = 1 - supp
    if art_present:
        # reward if register tolerates articles
        return 1.0 - supp
    else:
        return supp


def _semantic_coherence(entries: list) -> float:
    live = [e for e in entries if e is not None]
    if len(live) < 2:
        return 0.6
    # scan for verb+prep adjacency
    score = 0.6
    hits = 0
    for i in range(len(live) - 1):
        a, b = live[i], live[i + 1]
        if a.pos == "VERB_OP" and b.pos == "PREP":
            key = (a.word, b.word)
            if key in COHERENT_VERB_PREP:
                score = max(score, COHERENT_VERB_PREP[key])
                hits += 1
            else:
                score = max(score, 0.55)
        elif a.pos == "PREP" and b.pos in ("NOUN_LOC", "DIRECTION"):
            score = max(score, 0.85)
            hits += 1
        elif a.pos == "VERB_OP" and b.pos == "DIRECTION":
            score = max(score, 0.9)
            hits += 1
        elif a.pos == "VERB_OP" and b.pos == "NOUN_LOC":
            score = max(score, 0.75)  # telegraphic
            hits += 1
        elif a.pos == "NOUN_STATUS" and b.pos in ("ADJ", "VERB_OP"):
            score = max(score, 0.9)
            hits += 1
    return score


# ---- Public scoring API ---------------------------------------------------

def score_candidate(candidate: CandidateFill,
                    anchor: str = "",
                    anchor_position: str = "",
                    weights: Optional[dict] = None) -> ScoreBreakdown:
    weights = weights or DEFAULT_WEIGHTS
    template = candidate.template
    register = candidate.register
    words = tuple(candidate.slot_words)
    entries = _resolve_entries(words)

    slc = _slot_length_compat(template, words)
    pc = _pos_compat(template, entries)
    tf = _template_fit(slc, pc, template, words)
    ac = _anchor_context(words, entries, anchor, anchor_position)
    rp = _register_plausibility(register, entries)
    asc = _article_suppression_consistency(register, entries)
    sc = _semantic_coherence(entries)

    components = {
        "slot_length_compat": slc,
        "pos_compat": pc,
        "template_fit": tf,
        "anchor_context_plausibility": ac,
        "register_plausibility": rp,
        "article_suppression_consistency": asc,
        "semantic_coherence": sc,
    }
    total_w = sum(weights.values())
    agg = sum(weights[k] * components[k] for k in components) / total_w

    return ScoreBreakdown(
        candidate=candidate.phrase,
        template_id=template.template_id,
        register=register.name,
        slot_length_compat=slc,
        pos_compat=pc,
        template_fit=tf,
        anchor_context_plausibility=ac,
        register_plausibility=rp,
        article_suppression_consistency=asc,
        semantic_coherence=sc,
        aggregate=agg,
        components=components,
    )


def rank_candidates(candidates: list,
                    anchor: str = "",
                    anchor_position: str = "",
                    top_k: int = 20) -> list:
    scored = [score_candidate(c, anchor, anchor_position) for c in candidates]
    scored.sort(key=lambda s: s.aggregate, reverse=True)
    return scored[:top_k]


# ---- Anchor-aware queries -------------------------------------------------

def _anchor_is_location(anchor: str) -> bool:
    return anchor.upper() == "BERLINCLOCK"


def _pick_template_for_left(anchor: str) -> PhraseTemplate:
    return ANCHOR_LEFT_PREP if _anchor_is_location(anchor) else ANCHOR_LEFT_VERB


def left_context_candidates(anchor: str, slot_length: int,
                            role: Optional[str] = None,
                            register: Optional[RegisterStyle] = None,
                            top_k: int = 20) -> list:
    """Rank words that could appear immediately BEFORE the anchor."""
    candidates = []
    pool = entries_by_length(slot_length)
    if role:
        pool = [e for e in pool if e.pos == role]
    registers = [register_by_style(register)] if register else all_registers()
    for ent in pool:
        for tmpl in all_templates():
            # need a 2-slot template where slot 1 accepts this ent and slot 2 is the anchor
            if len(tmpl.slots) != 2:
                continue
            if ent.pos not in tmpl.slots[0].allowed_pos:
                continue
            anchor_pos = "NOUN_LOC" if _anchor_is_location(anchor) else "DIRECTION"
            if anchor_pos not in tmpl.slots[1].allowed_pos:
                continue
            for reg in registers:
                candidates.append(CandidateFill(
                    slot_words=(ent.word, anchor.upper()),
                    template=tmpl, register=reg,
                ))
    return rank_candidates(candidates, anchor=anchor, anchor_position="right", top_k=top_k)


def right_context_candidates(anchor: str, slot_length: int,
                             role: Optional[str] = None,
                             register: Optional[RegisterStyle] = None,
                             top_k: int = 20) -> list:
    candidates = []
    pool = entries_by_length(slot_length)
    if role:
        pool = [e for e in pool if e.pos == role]
    registers = [register_by_style(register)] if register else all_registers()
    for ent in pool:
        for tmpl in all_templates():
            if len(tmpl.slots) != 2:
                continue
            anchor_pos = "NOUN_LOC" if _anchor_is_location(anchor) else "DIRECTION"
            if anchor_pos not in tmpl.slots[0].allowed_pos:
                continue
            if ent.pos not in tmpl.slots[1].allowed_pos:
                continue
            for reg in registers:
                candidates.append(CandidateFill(
                    slot_words=(anchor.upper(), ent.word),
                    template=tmpl, register=reg,
                ))
    return rank_candidates(candidates, anchor=anchor, anchor_position="left", top_k=top_k)


def compare_anchor_phrases(phrases: list, anchor: str) -> dict:
    out = {}
    for phr in phrases:
        words = tuple(w.upper() for w in phr.split())
        # pick best template by trying all
        best = None
        for tmpl in all_templates():
            if len(tmpl.slots) != len(words):
                continue
            for reg in all_registers():
                cand = CandidateFill(slot_words=words, template=tmpl, register=reg)
                side = ""
                if anchor.upper() in words:
                    idx = words.index(anchor.upper())
                    if idx == 0:
                        side = "left"
                    elif idx == len(words) - 1:
                        side = "right"
                    else:
                        side = "center"
                sb = score_candidate(cand, anchor=anchor, anchor_position=side)
                if best is None or sb.aggregate > best.aggregate:
                    best = sb
        if best is None:
            # template-agnostic fallback
            best = ScoreBreakdown(candidate=phr, template_id="(none)",
                                  register="(none)", aggregate=0.0,
                                  notes="no matching template arity")
        out[phr] = best
    return out


def score_sequence(sequence: str,
                   register: Optional[RegisterStyle] = None) -> ScoreBreakdown:
    """Score a multi-word sequence. Picks the best-fitting template/register."""
    words = tuple(w.upper() for w in sequence.split())
    registers = [register_by_style(register)] if register else all_registers()
    best = None
    # try exact-arity templates first
    for tmpl in all_templates():
        if len(tmpl.slots) != len(words):
            continue
        for reg in registers:
            cand = CandidateFill(slot_words=words, template=tmpl, register=reg)
            # detect anchor
            anchor = ""
            side = ""
            for a in KNOWN_ANCHORS:
                if a in words:
                    anchor = a
                    idx = words.index(a)
                    side = "left" if idx == 0 else ("right" if idx == len(words) - 1 else "center")
                    break
            sb = score_candidate(cand, anchor=anchor, anchor_position=side)
            if best is None or sb.aggregate > best.aggregate:
                best = sb
    if best is None:
        # flex: pad/truncate against larger templates. Fall back: per-window scoring.
        entries = _resolve_entries(words)
        live = [e for e in entries if e is not None]
        # synthetic "sequence" breakdown
        reg = registers[0]
        rp = _register_plausibility(reg, entries)
        asc = _article_suppression_consistency(reg, entries)
        sc = _semantic_coherence(entries)
        # simple aggregate w/o template
        components = {
            "slot_length_compat": 0.7,
            "pos_compat": 0.7 if live else 0.0,
            "template_fit": 0.5,
            "anchor_context_plausibility": 0.5,
            "register_plausibility": rp,
            "article_suppression_consistency": asc,
            "semantic_coherence": sc,
        }
        tw = sum(DEFAULT_WEIGHTS.values())
        agg = sum(DEFAULT_WEIGHTS[k] * components[k] for k in components) / tw
        best = ScoreBreakdown(
            candidate=sequence, template_id="(sequence)",
            register=reg.name,
            slot_length_compat=components["slot_length_compat"],
            pos_compat=components["pos_compat"],
            template_fit=components["template_fit"],
            anchor_context_plausibility=components["anchor_context_plausibility"],
            register_plausibility=rp,
            article_suppression_consistency=asc,
            semantic_coherence=sc,
            aggregate=agg,
            components=components,
            notes="no template arity match; sliding sequence score",
        )
    return best
