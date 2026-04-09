"""Deduplication and alias resolution for cipher records.

Entity resolution logic for merging obvious duplicates while preserving
alias chains and flagging ambiguous cases for human review.
"""
from __future__ import annotations

from .schema import CipherRecord, Taxonomy
from .query_expansion import normalize_term


def build_alias_index(records: list[CipherRecord]) -> dict[str, list[int]]:
    """Build an index mapping normalized terms to record indices.

    Returns {normalized_term: [record_index, ...]}
    """
    index: dict[str, list[int]] = {}
    for i, rec in enumerate(records):
        # Index canonical name
        norm = normalize_term(rec.canonical_name)
        index.setdefault(norm, []).append(i)
        # Index all aliases
        for alias in rec.alias_names:
            norm_alias = normalize_term(alias)
            index.setdefault(norm_alias, []).append(i)
    return index


def find_duplicates(records: list[CipherRecord]) -> list[tuple[int, int, str]]:
    """Find pairs of records that are likely duplicates.

    Returns [(index_a, index_b, reason), ...]
    """
    index = build_alias_index(records)
    dupes = []
    seen_pairs = set()

    for term, indices in index.items():
        if len(indices) > 1:
            for i in range(len(indices)):
                for j in range(i + 1, len(indices)):
                    a, b = min(indices[i], indices[j]), max(indices[i], indices[j])
                    if (a, b) not in seen_pairs:
                        seen_pairs.add((a, b))
                        dupes.append((a, b, f"shared normalized term: '{term}'"))

    # Also check if canonical name of one is an alias of another
    canonical_norms = {}
    for i, rec in enumerate(records):
        canonical_norms[normalize_term(rec.canonical_name)] = i

    for i, rec in enumerate(records):
        for alias in rec.alias_names:
            norm_alias = normalize_term(alias)
            if norm_alias in canonical_norms:
                j = canonical_norms[norm_alias]
                if i != j:
                    a, b = min(i, j), max(i, j)
                    if (a, b) not in seen_pairs:
                        seen_pairs.add((a, b))
                        dupes.append((a, b, f"alias '{alias}' matches canonical name"))

    return dupes


def merge_records(primary: CipherRecord, secondary: CipherRecord) -> CipherRecord:
    """Merge secondary record into primary, preserving all information.

    The primary record's canonical_name is kept. All unique aliases,
    sources, and notes from secondary are added to primary.
    """
    # Merge alias names (preserve order, deduplicate)
    seen_aliases = set(a.lower() for a in primary.alias_names)
    seen_aliases.add(primary.canonical_name.lower())
    # Add secondary's canonical name as alias if different
    if secondary.canonical_name.lower() not in seen_aliases:
        primary.alias_names.append(secondary.canonical_name)
        seen_aliases.add(secondary.canonical_name.lower())
    for alias in secondary.alias_names:
        if alias.lower() not in seen_aliases:
            primary.alias_names.append(alias)
            seen_aliases.add(alias.lower())

    # Merge source URLs
    existing_urls = set(primary.source_urls)
    for url in secondary.source_urls:
        if url not in existing_urls:
            primary.source_urls.append(url)
            existing_urls.add(url)

    # Merge quote snippets
    existing_quotes = set(primary.quote_snippets)
    for quote in secondary.quote_snippets:
        if quote not in existing_quotes:
            primary.quote_snippets.append(quote)

    # Merge tools/materials
    existing_tools = set(t.lower() for t in primary.tools_required)
    for tool in secondary.tools_required:
        if tool.lower() not in existing_tools:
            primary.tools_required.append(tool)

    # Take higher confidence scores
    primary.confidence_real_system = max(
        primary.confidence_real_system, secondary.confidence_real_system
    )
    primary.confidence_distinct_from_known = max(
        primary.confidence_distinct_from_known, secondary.confidence_distinct_from_known
    )
    primary.confidence_relevance_to_k4 = max(
        primary.confidence_relevance_to_k4, secondary.confidence_relevance_to_k4
    )

    # Merge description if secondary has more info
    if len(secondary.description) > len(primary.description):
        primary.description = secondary.description

    # Merge operational mechanics
    if secondary.operational_mechanics and not primary.operational_mechanics:
        primary.operational_mechanics = secondary.operational_mechanics

    # Merge flags (OR logic)
    primary.historically_attested = primary.historically_attested or secondary.historically_attested
    primary.pedagogical_amateur = primary.pedagogical_amateur or secondary.pedagogical_amateur
    primary.bespoke = primary.bespoke or secondary.bespoke

    # Merge unresolved questions
    existing_q = set(primary.unresolved_questions)
    for q in secondary.unresolved_questions:
        if q not in existing_q:
            primary.unresolved_questions.append(q)

    # Merge ambiguity flags
    existing_flags = set(primary.ambiguity_flags)
    for f in secondary.ambiguity_flags:
        if f not in existing_flags:
            primary.ambiguity_flags.append(f)

    # Merge exhaustion info
    existing_ids = set(primary.exhaustion_log_ids)
    for eid in secondary.exhaustion_log_ids:
        if eid not in existing_ids:
            primary.exhaustion_log_ids.append(eid)
    if secondary.tested_in_project:
        primary.tested_in_project = True

    return primary


def deduplicate_records(
    records: list[CipherRecord],
    auto_merge_threshold: float = 0.9,
) -> tuple[list[CipherRecord], list[tuple[int, int, str]]]:
    """Deduplicate a list of cipher records.

    Returns (deduplicated_records, flagged_for_review).
    Records with exact normalized name matches are auto-merged.
    Ambiguous cases are flagged for human review.
    """
    if not records:
        return [], []

    dupes = find_duplicates(records)

    # Build union-find for auto-merge clusters
    parent = list(range(len(records)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    flagged_for_review = []

    for idx_a, idx_b, reason in dupes:
        # Auto-merge if both have the same normalized canonical name
        norm_a = normalize_term(records[idx_a].canonical_name)
        norm_b = normalize_term(records[idx_b].canonical_name)
        if norm_a == norm_b:
            union(idx_a, idx_b)
        else:
            # Flag for review: alias overlap but different canonical names
            flagged_for_review.append((idx_a, idx_b, reason))

    # Build merged records
    clusters: dict[int, list[int]] = {}
    for i in range(len(records)):
        root = find(i)
        clusters.setdefault(root, []).append(i)

    merged = []
    for root, members in clusters.items():
        primary = records[members[0]]
        for i in members[1:]:
            primary = merge_records(primary, records[i])
        merged.append(primary)

    return merged, flagged_for_review
