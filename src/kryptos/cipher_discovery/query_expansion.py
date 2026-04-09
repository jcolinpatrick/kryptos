"""Query expansion for cipher discovery.

Generates search queries from seed terms using multiple strategies:
- Synonym expansion
- Pairwise concept queries
- Historical context queries
- Multi-hop expansion from discovered terms
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class ExpandedQuery:
    """A search query generated from seed expansion."""
    query: str
    strategy: str  # "synonym", "pairwise", "historical", "patent", "educational", "cross_ref"
    source_term: str
    priority: int = 0
    depth: int = 0


def expand_synonyms(term: str, synonyms: list[str]) -> list[ExpandedQuery]:
    """Generate queries from term synonyms."""
    queries = []
    # Exact phrase search for the term itself
    queries.append(ExpandedQuery(
        query=f'"{term}"',
        strategy="synonym",
        source_term=term,
        priority=1,
    ))
    # Each synonym as an exact phrase
    for syn in synonyms[:5]:  # limit to top 5 synonyms
        queries.append(ExpandedQuery(
            query=f'"{syn}"',
            strategy="synonym",
            source_term=term,
            priority=2,
        ))
    return queries


def expand_pairwise(term: str, context_terms: list[str]) -> list[ExpandedQuery]:
    """Generate pairwise concept queries.

    Pairs the cipher term with contextual modifiers.
    """
    context_modifiers = [
        "manual encryption",
        "hand cipher",
        "pencil paper cipher",
        "secret writing",
        "classical cryptography",
        "field cipher",
        "historical cipher",
        "encrypt by hand",
    ]
    queries = []
    for modifier in context_modifiers:
        queries.append(ExpandedQuery(
            query=f'"{term}" {modifier}',
            strategy="pairwise",
            source_term=term,
            priority=3,
        ))
    # Also pair with provided context terms
    for ct in context_terms[:3]:
        if ct.lower() != term.lower():
            queries.append(ExpandedQuery(
                query=f'"{term}" "{ct}"',
                strategy="pairwise",
                source_term=term,
                priority=3,
            ))
    return queries


def expand_historical(term: str) -> list[ExpandedQuery]:
    """Generate historical context queries."""
    contexts = [
        "19th century",
        "World War I",
        "World War II",
        "Cold War",
        "Civil War cipher",
        "Renaissance",
        "medieval",
        "Victorian era",
    ]
    queries = []
    for ctx in contexts:
        queries.append(ExpandedQuery(
            query=f'"{term}" {ctx}',
            strategy="historical",
            source_term=term,
            priority=4,
        ))
    return queries


def expand_patent(term: str) -> list[ExpandedQuery]:
    """Generate patent/invention queries."""
    queries = [
        ExpandedQuery(
            query=f'"{term}" patent secret writing',
            strategy="patent",
            source_term=term,
            priority=5,
        ),
        ExpandedQuery(
            query=f'"{term}" inventor cryptography',
            strategy="patent",
            source_term=term,
            priority=5,
        ),
    ]
    return queries


def expand_educational(term: str) -> list[ExpandedQuery]:
    """Generate educational/amateur context queries."""
    queries = [
        ExpandedQuery(
            query=f'"{term}" scout secret message',
            strategy="educational",
            source_term=term,
            priority=5,
        ),
        ExpandedQuery(
            query=f'"{term}" how to encrypt',
            strategy="educational",
            source_term=term,
            priority=5,
        ),
        ExpandedQuery(
            query=f'"{term}" tutorial encrypt',
            strategy="educational",
            source_term=term,
            priority=6,
        ),
    ]
    return queries


def expand_cross_reference(term: str, related_terms: list[str]) -> list[ExpandedQuery]:
    """Generate cross-reference queries between cipher systems."""
    queries = []
    for related in related_terms[:5]:
        if related.lower() != term.lower():
            queries.append(ExpandedQuery(
                query=f'"{term}" OR "{related}" cipher',
                strategy="cross_ref",
                source_term=term,
                priority=4,
            ))
    return queries


def expand_k4_specific(term: str) -> list[ExpandedQuery]:
    """Generate K4-specific context queries."""
    k4_contexts = [
        "Kryptos",
        "CIA sculpture cipher",
        "Jim Sanborn",
        "Ed Scheidt",
        "compass bearing",
        "Morse code encryption",
        "transposition substitution combination",
    ]
    queries = []
    for ctx in k4_contexts:
        queries.append(ExpandedQuery(
            query=f'"{term}" {ctx}',
            strategy="k4_specific",
            source_term=term,
            priority=2,
        ))
    return queries


def generate_all_queries(
    term: str,
    synonyms: list[str],
    related_terms: list[str] | None = None,
    include_historical: bool = True,
    include_patent: bool = False,
    include_educational: bool = False,
    include_k4: bool = True,
    max_queries: int = 20,
) -> list[ExpandedQuery]:
    """Generate all query expansions for a term, limited by max_queries."""
    all_queries = []

    all_queries.extend(expand_synonyms(term, synonyms))
    all_queries.extend(expand_pairwise(term, related_terms or []))

    if include_k4:
        all_queries.extend(expand_k4_specific(term))

    if include_historical:
        all_queries.extend(expand_historical(term))

    if include_patent:
        all_queries.extend(expand_patent(term))

    if include_educational:
        all_queries.extend(expand_educational(term))

    if related_terms:
        all_queries.extend(expand_cross_reference(term, related_terms))

    # Sort by priority and limit
    all_queries.sort(key=lambda q: q.priority)
    return all_queries[:max_queries]


def normalize_term(term: str) -> str:
    """Normalize a cipher term for comparison."""
    t = term.lower().strip()
    # Remove common suffixes
    for suffix in [" cipher", " code", " system", " method", " technique"]:
        if t.endswith(suffix):
            t = t[:-len(suffix)].strip()
    # Normalize spacing
    t = " ".join(t.split())
    return t


def terms_match(term_a: str, term_b: str) -> bool:
    """Check if two terms refer to the same concept."""
    return normalize_term(term_a) == normalize_term(term_b)
