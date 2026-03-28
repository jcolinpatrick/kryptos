"""Assign eliminations to browse categories based on keywords, tags, and overrides."""
from __future__ import annotations

from .data_loader import SiteElimination


# Category → subcategory → keyword patterns (matched against title, description, tags)
CATEGORY_RULES: dict[str, dict[str, list[str]]] = {
    "substitution": {
        "vigenere": [
            "vigenere", "vigenère", "vig_", "vig-", "periodic sub",
            "periodic key", "polyalphabetic",
        ],
        "beaufort": ["beaufort", "beau_", "beau-", "var_beaufort", "variant beaufort"],
        "quagmire": ["quagmire"],
        "gromark-vimark": ["gromark", "vimark"],
        "porta": ["porta"],
        "gronsfeld": ["gronsfeld"],
        "hill": ["hill cipher", "hill 2x2", "hill 3x3", "hill2", "hill3"],
        "caesar-affine": ["caesar", "affine", "rot13", "rot-"],
        "monoalphabetic": ["monoalphabetic", "mono_sub", "simple sub"],
        "mixed-alphabet": ["mixed_alphabet", "mixed alphabet", "latin_square", "position_alphabet"],
        "keystream-analysis": [
            "keystream structure", "key bigram", "keystream analysis",
            "keystream language", "keystream scan", "bcl palette keystream",
            "bean keystream", "cipher model", "digraph",
        ],
    },
    "transposition": {
        "columnar": [
            "columnar", "column_", "width-5", "width-6", "width-7",
            "width-8", "width-9", "width-10", "width 5", "width 6",
            "width 7", "width 8", "width 9", "w5", "w6", "w7", "w8", "w9",
        ],
        "double-columnar": ["double columnar", "double_columnar", "compound columnar"],
        "myszkowski": ["myszkowski"],
        "amsco": ["amsco"],
        "nihilist-transposition": ["nihilist trans", "nihilist_trans", "swapped columnar"],
        "rail-fence": ["rail fence", "rail_fence", "railfence"],
        "route-cipher": [
            "route cipher", "route cipher", "spiral", "serpentine",
            "route transposition", "grid route", "incomplete route",
            "cylindrical rotation", "vertical wordlock", "counter directional",
            "accordion fold",
        ],
        "turning-grille": ["turning grille", "grille", "fleissner"],
        "grid-rotation": ["grid rotation", "rotation grid", "k3 style", "k3 method",
                          "grid asymmetry", "width10", "width21", "width 10", "width 21",
                          "row sequence", "8 row grid"],
        "cyclic-affine": ["cyclic shift", "affine perm", "block reversal"],
        "reading-order": ["boustrophedon", "reading order", "reading dir", "reverse ct",
                         "delimiter", "72+1"],
        "sa-optimization": [
            "sa quadgram", "simulated annealing", "sa keyspace",
            "manifold sa", "bean manifold", "blitz v7", "blitz v8",
            "blitz v9", "blitz wildcard", "blitz numeric",
        ],
    },
    "fractionation": {
        "bifid": ["bifid"],
        "trifid": ["trifid"],
        "adfgvx": ["adfgvx", "adfgx"],
        "playfair": ["playfair"],
        "two-square": ["two-square", "two_square"],
        "four-square": ["four-square", "four_square"],
        "polybius": ["polybius"],
        "straddling-checkerboard": ["straddling", "checkerboard"],
    },
    "multi-layer": {
        "transposition-plus-substitution": [
            "trans+sub", "trans + sub", "jts", "joint transposition",
            "multi-layer", "multi layer", "two-layer", "two layer",
            "three-layer", "three layer", "sub+trans+sub",
            "mitm", "strip cipher", "blitz strip",
        ],
        "null-extraction": [
            "null cipher", "null cipher", "null extraction", "skip cipher",
            "doubled letter", "deletion", "null mask", "null position",
            "null resolution", "null discrimination", "bruteforce 7remaining",
            "brute force", "7 remaining", "stego",
        ],
        "cascade": ["cascade", "onion", "progressive onion", "compose", "multi stage",
                   "layered verify", "mono trans sa", "team mono"],
        "three-layer": ["three layer", "sub+trans+sub"],
        "mask-extraction": ["three layer mask"],
        "joint-transposition": ["joint sa", "jts"],
        "constraint-propagation": ["constraint propagation", "csp"],
        "homophonic-hybrid": [
            "homophonic", "homo contradiction", "homo trans",
            "nomenclator", "superencipherment",
        ],
    },
    "key-models": {
        "running-key": [
            "running key", "running_key", "runkey", "carter",
            "gutenberg", "reference text",
        ],
        "autokey": ["autokey", "auto_key", "auto-key"],
        "progressive": ["progressive key", "progressive_key"],
        "date-derived": [
            "date key", "date_key", "date-derived", "1986", "1989",
            "artifact_driven", "artifact-driven",
        ],
        "keyword-derived": [
            "keyword", "thematic", "kryptos key", "palimpsest key",
            "abscissa key", "operation gold", "stopwatch",
            "carter phrase", "egypt",
        ],
        "fibonacci-polynomial": [
            "fibonacci", "polynomial", "quadratic key", "lcg",
            "nonlinear_recurrence", "nonlinear recurrence",
        ],
        "seriated": ["seriated", "seriated_key"],
        "extended-key": ["extended_key", "extended key", "key_fragment", "key fragment"],
        "sculpture-derived": ["sculpture_key", "sculpture key", "grid_position_key", "additive_grid"],
        "thematic": ["thematic_key", "thematic key", "themed", "creative_key"],
        "k123-derived": ["k123", "k1k2k3", "k98 running", "k1 running", "k2 running", "ckm", "credential"],
    },
    "bespoke": {
        "physical-sculpture": [
            "physical", "sculpture", "compass", "lodestone",
            "coordinate", "morse", "anomaly", "berlin clock",
            "weltzeituhr", "2d matrix", "punch card",
        ],
        "misspelling-derived": [
            "misspelling", "misspell", "desparatly", "undergruund",
        ],
        "tableau-methods": [
            "tableau", "non-standard tableau", "column read",
        ],
        "nato-comsec": [
            "nato", "comsec", "dryad", "batco", "vic cipher", "vic ",
            "one-time pad", "otp", "rs44", "wheatstone",
            "ita 2", "ita2", "baudot", "ubchi", "soviet",
            "wilson prime", "sawtooth", "interrupted key",
        ],
        "roman-numeral": ["roman numeral", "roman_", "roman-"],
        "abscissa": ["abscissa"],
        "weltzeituhr": ["weltzeituhr", "world clock", "orrery"],
        "checkpoint-charlie": ["checkpoint charlie", "checkpoint", "99char", "98char", "cc insertion"],
        "point-analysis": ["the point", "point placement", "point end", "whats the point", "compass east", "direction as key"],
        "k3-derived": ["k3_variant", "k3 variant", "k3_method", "k3 method", "k3_outer", "progressive_bridge"],
        "community-proposals": ["community proposal"],
        "enrichment-analysis": [
            "enrichment", "palette", "topology", "exclusion rule",
            "dmpq", "gko", "crib keystream", "ct80",
            "letter shape", "null correlation",
        ],
        "structural-analysis": [
            "stehle", "delta4", "ap constrained", "ap investigation",
            "ap significance", "ap followup", "statistical validation",
            "statistical appendix", "model b", "deep investigation",
            "gap filling", "memory audit", "mod35", "positional keying",
            "d13 hybrid", "global delta", "grid key generation",
            "table generation", "berlin cable", "berlin wall crib",
            "error hypothesis", "period6", "p13 deep",
            "null insertion structure", "null char assignment",
            "null seq key", "argenti", "prosign", "interleave",
            "mcmc attack", "tkas",
        ],
        "ndyahr": [
            "ndyahr",
        ],
    },
}


def categorize_elimination(elim: SiteElimination) -> None:
    """Assign category and subcategory to a SiteElimination based on keyword matching.

    If the elimination already has a category set (e.g. from overrides), skip it.
    """
    if elim.category and elim.category != "uncategorized":
        return

    # Build the text corpus to match against.
    # Normalize underscores/hyphens to spaces so patterns like "date key"
    # match tags like "date_key" and IDs like "date-key".
    raw = " ".join([
        elim.title.lower(),
        elim.description.lower(),
        elim.cipher_type.lower(),
        " ".join(t.lower() for t in elim.tags),
        elim.key_model.lower(),
        elim.transposition_family.lower(),
        elim.id.lower(),
        elim.experiment_script.lower(),
    ])
    search_text = raw.replace("_", " ").replace("-", " ")

    best_cat = ""
    best_subcat = ""
    best_score = 0

    for category, subcategories in CATEGORY_RULES.items():
        for subcategory, patterns in subcategories.items():
            score = sum(1 for p in patterns if p in search_text)
            if score > best_score:
                best_score = score
                best_cat = category
                best_subcat = subcategory

    if best_cat:
        elim.category = best_cat
        elim.subcategory = best_subcat
    else:
        elim.category = "uncategorized"
        elim.subcategory = ""


def categorize_all(eliminations: list[SiteElimination]) -> dict[str, dict[str, list[SiteElimination]]]:
    """Categorize all eliminations and return a nested dict for browsing.

    Returns:
        {category: {subcategory: [eliminations...]}}
    """
    for elim in eliminations:
        categorize_elimination(elim)

    tree: dict[str, dict[str, list[SiteElimination]]] = {}
    for elim in eliminations:
        cat = elim.category
        subcat = elim.subcategory or "(general)"
        tree.setdefault(cat, {}).setdefault(subcat, []).append(elim)

    # Sort within each subcategory by configs_tested descending
    for cat in tree:
        for subcat in tree[cat]:
            tree[cat][subcat].sort(key=lambda e: e.configs_tested, reverse=True)

    return tree


def get_category_stats(tree: dict[str, dict[str, list[SiteElimination]]]) -> list[dict]:
    """Get summary statistics per category for the browse page."""
    stats = []
    for cat, subcats in sorted(tree.items()):
        total = sum(len(elims) for elims in subcats.values())
        total_configs = sum(
            e.configs_tested for elims in subcats.values() for e in elims
        )
        best = max(
            (e.best_score for elims in subcats.values() for e in elims),
            default=0,
        )
        stats.append({
            "category": cat,
            "display_name": cat.replace("-", " ").title(),
            "subcategories": sorted(subcats.keys()),
            "count": total,
            "total_configs": total_configs,
            "best_score": best,
        })
    return stats
