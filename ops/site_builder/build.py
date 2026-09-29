#!/usr/bin/env python3
"""Build the kryptosbot.com static site from databases, docs, and templates."""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import shutil
import sys
import time
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("ERROR: jinja2 is required. Install with: pip install jinja2")
    sys.exit(1)

# Ensure both kryptos kernel and site_builder are importable
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_project_root, "src"))
sys.path.insert(0, _project_root)

from ops.site_builder.data_loader import load_all, SiteElimination, generate_all_plain_summaries
from ops.site_builder.categorizer import categorize_all, get_category_stats
from ops.site_builder.search_index import write_search_index


# --- Configuration ---

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "site")
# Canonical public origin. www is the host CloudFront serves; the apex exists
# only as a GoDaddy 301 onto it.
SITE_ORIGIN = "https://www.kryptosbot.com"

# Category descriptions for browse pages
CATEGORY_DESCRIPTIONS = {
    "substitution": "Methods that replace each letter with a different letter using a key or pattern, like a secret alphabet. Includes Vigen\u00e8re, Beaufort, Quagmire, Hill, and more.",
    "transposition": "Methods that scramble the order of letters without changing them, like writing a message into a grid and reading it back in a different order. Includes columnar, rail fence, route, and grille ciphers.",
    "fractionation": "Methods that break each letter into smaller pieces (like grid coordinates), scramble those pieces, then reassemble them into new letters. Includes Bifid, Playfair, Four-Square, and ADFGVX.",
    "multi-layer": "Combined approaches that stack multiple encryption steps. For example, replacing letters first, then scrambling their order. Includes filler-letter removal, cascaded layers, and joint optimization.",
    "key-models": "Different ways to generate the secret key: from a passage in a book, from a date, from a mathematical formula, or from the sculpture itself. Includes running keys, self-keying (autokey) ciphers, and keyword-derived approaches.",
    "bespoke": "Non-standard methods inspired by the physical sculpture or military cipher systems. These approaches don't fit neatly into classical categories. Includes DRYAD charts, Morse code analysis, and coordinate-based approaches.",
    "uncategorized": "Eliminations not yet assigned to a specific category.",
}

# Plain-English "Have you thought of this?" guides per category.
# These address the most common community questions for each category.
CATEGORY_PLAIN_GUIDES = {
    "substitution": (
        "Every repeating key 1 to 26 letters long has been ruled out for K4 as "
        "carved (each ciphertext letter hiding the plaintext letter in the same "
        "position) under Vigen\u00e8re, Beaufort and Variant Beaufort, on both the "
        "ordinary A to Z alphabet and the sculpture's KRYPTOS alphabet: not just "
        "searched, but ruled out directly from the known plaintext. With any "
        "keyword-mixed alphabet used the way K1 and K2 use the KRYPTOS alphabet (the "
        "same mixed alphabet for plaintext and ciphertext), keys of 1 to 22, 24 and 25 "
        "letters are ruled out the same way. Versions that use two different mixed "
        "alphabets, and Gromark ciphers with mixed alphabets on both sides, are not "
        "fully ruled out. A repeating key combined with a letter-rearrangement step "
        "is a separate question (see Multi Layer)."
    ),
    "transposition": (
        "Many standard letter-rearrangement methods have been tested: columnar grids at many "
        "widths, rail fence, spiral, zigzag, route ciphers, and more (the table below "
        "lists each record and, where recorded, how many settings it tried). None "
        "produced a solution. Pure "
        "rearrangement alone is also independently impossible: the ciphertext has 2 E's "
        "but the known plaintext needs 3, so some letter-replacement must also be involved."
    ),
    "fractionation": (
        "Bifid, Playfair, Four-Square and similar ciphers built on a 5×5 square are "
        "impossible for K4 in their standard form, because the square holds only 25 "
        "letters (I and J are usually merged) but all 26 letters appear in K4's "
        "ciphertext. ADFGVX is ruled out for a different reason: its output uses only "
        "the six letters A, D, F, G, V and X and always has an even length, while K4 "
        "uses all 26 letters and has 97. These are logical impossibilities, not just "
        "search results."
    ),
    "multi-layer": (
        "Combinations of two or more layers are one of the main remaining search areas "
        "for K4. We have tested a large but bounded part of that space, including many "
        "structured rearrangement methods paired with keyed substitution, and found no "
        "signal. Much remains open: combinations beyond the grid widths, key lengths and "
        "alphabets searched so far; self-keying (autokey) ciphers combined with a "
        "letter-rearrangement step, which the known letters alone cannot rule out; and "
        "non-standard procedures or key sources."
    ),
    "key-models": (
        "Running keys from over 60,000 publicly available texts have been tested, "
        "including the Bible, Shakespeare, Carter's \"Tomb of Tutankhamun,\" and the "
        "English-language Project Gutenberg library as scanned in March 2026. The "
        "Gutenberg scan made about 106 billion checks (every starting position in every "
        "text, under Vigenère, Beaufort and Variant Beaufort, on the standard A to "
        "Z alphabet): about half against the carved text as it stands, and half against "
        "shortened 73-letter versions with presumed filler letters removed. Zero signal. "
        "Self-keying (autokey) ciphers applied directly to the carved text are ruled out "
        "for starting keys of 1 to 25 letters on the standard and KRYPTOS alphabets. A "
        "running key from a non-public or non-English source is still possible, but the "
        "April 2026 audit treats it as a checklist item rather than the project's "
        "leading hypothesis."
    ),
    "bespoke": (
        "VIC ciphers, DRYAD military charts, Morse code interpretations, "
        "coordinate-based approaches, and many other non-standard ideas have all been "
        "tested in the forms described in the records below. None of the textbook cipher "
        "families tested so far has produced a solution. Public clues and unexplained "
        "features of the sculpture keep hand procedures and physically guided methods in "
        "play, but the site treats those as hypotheses to test, not as established facts."
    ),
}



def format_configs(n: int) -> str:
    """Format a large number with B/M/K suffix."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B+"
    elif n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M+"
    elif n >= 1_000:
        return f"{n / 1_000:.0f}K+"
    return str(n)


def _prepare_output_dir(output_dir: str) -> None:
    """Prepare the output directory for a site rebuild.

    If old root-owned content blocks cleanup, rotate the whole tree aside and
    create a fresh output directory owned by the current user.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        return

    try:
        for entry in os.listdir(output_dir):
            if entry in ("stats", "static"):
                continue
            entry_path = os.path.join(output_dir, entry)
            if os.path.isdir(entry_path):
                shutil.rmtree(entry_path)
            else:
                os.remove(entry_path)
        return
    except PermissionError:
        parent_dir = os.path.dirname(output_dir)
        base_name = os.path.basename(output_dir.rstrip(os.sep))
        rotated = os.path.join(parent_dir, f"{base_name}.stale-{int(time.time())}")
        print(
            f"  [WARN] Output directory contains unwritable entries; "
            f"rotating {output_dir} -> {rotated}"
        )
        os.rename(output_dir, rotated)
        os.makedirs(output_dir, exist_ok=True)
        stale_stats = os.path.join(rotated, "stats")
        if os.path.isdir(stale_stats):
            shutil.copytree(stale_stats, os.path.join(output_dir, "stats"), dirs_exist_ok=True)



def _newest_result_date() -> str:
    """Most recent mtime among the research inputs the site builder reads.

    Reported in the footer beside the build date so a rebuild that adds no new
    research cannot masquerade as fresh findings.
    """
    import glob
    newest = 0.0
    for pattern in ("results/*.json", "results/*/results.json"):
        for path in glob.glob(os.path.join(PROJECT_ROOT, pattern)):
            try:
                newest = max(newest, os.path.getmtime(path))
            except OSError:
                continue
    if not newest:
        return ""
    return _dt.date.fromtimestamp(newest).isoformat()


def _bean_frame_retracted_scripts() -> set:
    """Script ids whose Bean verdict was retracted on 2026-08-24.

    Read from the authoritative exhaustion log rather than hardcoded, so the
    site stays in sync automatically if the retraction set changes. A page for
    one of these must NOT display a Bean FAIL: that verdict came from applying
    the frozen Bean sets across a layer that moves crib coordinates, where they
    do not hold, so the "failure" is an artifact.
    """
    import json as _json
    path = os.path.join(PROJECT_ROOT, "exhaustion_log.json")
    out = set()
    try:
        with open(path) as fh:
            for sid, entry in _json.load(fh).items():
                if "Bean frame error" in str(entry.get("notes", "")):
                    out.add(sid)
    except Exception:
        return set()
    return out


# Per-section ciphertext LETTER counts. The section_bars figure scales its bar
# widths from these, so the reader sees the real proportions rather than being
# told them. Note K1 is the shortest section at 63 characters, not K4 at 97.
#
# Authoritative source: kryptosbot/panel_cribs.py, which asserts these at import
# time because the K1/K2/K3 self-test round-trips them
#   (`assert len(_K1_CT) == len(_K1_PT) == 63`, `... len(_K3_CT) == 336`).
# Verify with:
#   PYTHONPATH=src python3 -c "from kryptosbot import panel_cribs as p; \
#     print(len(p._K1_CT), len(p._K2_CT), len(p._K3_CT))"
#
# 63 + 369 + 336 + 97 = 865 letters. The screen also carries four question marks,
# which is why the whole text is usually quoted as 869 characters. 869 is the count
# for the ENTIRE screen: it is NOT K1's length, and it sat here as K1's length from
# 2026-08-23 to 2026-08-24. Do not "fix" it back.
#
# Bar widths live in style.css (.fig-bar-N) because the site's CSP forbids inline
# styles; tests/test_site_builder_build.py pins them to these counts.
#
# Cipher labels use plain vocabulary, not ACA taxonomy. CIA's published
# description calls the tableau a "chart" ("Vigeneries Tableaux") used "in
# combination with matrix coding systems" (reference/cia_kryptos_page.md).
# The contrast "not a substitution system like Vigenere ... a transposition
# system" (said of K3) comes from notes on Elonka Dunin's PN26 talk
# (reference/elonka_pn26_kryptos.md), where it is not attributed to Sanborn:
# do not present it as his words. Solvers catalogue K1/K2 as Quagmire III;
# Sanborn does not.
K4_SECTIONS = [
    {"name": "K1", "chars": 63, "cipher": "keyed Vigenère, sculpture tableau", "key": "PALIMPSEST",
     "solved": "solved 1990s", "opening": "Between subtle shading and the absence of light lies the nuance of iqlusion."},
    {"name": "K2", "chars": 369, "cipher": "keyed Vigenère, sculpture tableau", "key": "ABSCISSA",
     "solved": "solved 1990s", "opening": "It was totally invisible. How's that possible?"},
    {"name": "K3", "chars": 336, "cipher": "unkeyed transposition, two grid rotations", "key": None,
     "solved": "solved 1990s", "opening": "Slowly, desparatly slowly, the remains of passage debris that encumbered the lower part of the doorway was removed."},
    {"name": "K4", "chars": 97, "cipher": "unknown", "key": None,
     "solved": None, "opening": None},
]


def build():
    """Run the full site build pipeline."""
    print("=" * 60)
    print("kryptosbot.com — Static Site Build")
    print("=" * 60)

    # 1) Load all data
    eliminations, rq_coverage, research_questions, tier_assignments = load_all(PROJECT_ROOT)

    # Mark experiments whose Bean verdict was invalidated by the 2026-08-24
    # frame-error retraction, so their pages cannot publish a FAIL that was an
    # artifact of applying frozen Bean across a crib-moving layer.
    _retracted = _bean_frame_retracted_scripts()
    if _retracted:
        _n = 0
        for _e in eliminations:
            _sid = os.path.splitext(os.path.basename(_e.experiment_script or ""))[0]
            if _sid and _sid in _retracted:
                _e.bean_frame_retracted = True
                _n += 1
        print(f"  Bean-frame retraction: flagged {_n} elimination page(s)")

    # 2) Categorize
    print("\nCategorizing eliminations...")
    tree = categorize_all(eliminations)
    cat_stats = get_category_stats(tree)
    print(f"  Categories: {len(tree)}")
    for cs in cat_stats:
        print(f"    {cs['display_name']}: {cs['count']} eliminations")

    # 2b) Generate plain-English summaries (after categorization so subcategory is available)
    print("\nGenerating plain-English summaries...")
    generate_all_plain_summaries(eliminations)
    summaries_generated = sum(1 for e in eliminations if e.plain_summary)
    print(f"  Summaries generated: {summaries_generated}/{len(eliminations)}")

    # 3) Compute aggregate stats
    total_configs = sum(e.configs_tested for e in eliminations)
    total_experiments = len(eliminations)
    total_categories = len([c for c in tree if c != "uncategorized"])

    # Count total scripts from exhaustion log (authoritative source)
    exhaustion_log_path = os.path.join(PROJECT_ROOT, "exhaustion_log.json")
    total_scripts = 0
    if os.path.exists(exhaustion_log_path):
        import json as _json
        with open(exhaustion_log_path) as _f:
            total_scripts = len(_json.load(_f))

    # Build the formatted disproven counter
    total_configs_disproven = format_configs(total_configs)

    print(f"\n  Total experiments (with results): {total_experiments}")
    print(f"  Total scripts tracked: {total_scripts}")
    print(f"  Total configs tested: {total_configs:,} ({total_configs_disproven})")

    # 4) Group research questions by tier
    rq_by_tier = _group_research_questions(research_questions, rq_coverage)

    # 5) Set up Jinja2
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
    )

    def _format_date(val: str) -> str:
        """Format an ISO date string to a readable date."""
        if not val:
            return ""
        # Strip timezone and time portion
        return val[:10]

    env.filters["format_date"] = _format_date

    # K4 ciphertext. Every derived figure below needs it, so it is imported once
    # here at the head of the section rather than beside the page that uses it.
    try:
        from kryptos.kernel.constants import CT
    except ImportError:
        CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

    # W-delimiter segmentation. The five carved Ws sit at 20, 36, 48, 58 and 74,
    # cutting the 97 characters into six runs totalling 92. This is a claim about
    # where line breaks fall, so describing it without showing the breaks is the
    # purest possible mismatch of medium to content.
    _w_positions = [i for i, ch in enumerate(CT) if ch == "W"]
    _bounds = [-1] + _w_positions + [len(CT)]
    w_segments = []
    for _a, _b in zip(_bounds, _bounds[1:]):
        _start, _end = _a + 1, _b - 1
        w_segments.append({
            "start": _start,
            "end": _end,
            "len": _end - _start + 1,
            "cells": [
                {"i": i, "ch": CT[i],
                 "known": 21 <= i <= 33 or 63 <= i <= 73}
                for i in range(_start, _end + 1)
            ],
            # the delimiter that closed this run, if any
            "w": _b if _b < len(CT) else None,
        })
    w_delimiter = {
        "segments": w_segments,
        "positions": _w_positions,
        "total": sum(s_["len"] for s_ in w_segments),
        "after_ene": [w for w in _w_positions if w > 33][0] - 33 - 1,
        "before_bcl": 63 - [w for w in _w_positions if w < 63][-1] - 1,
    }

    # Bean constraints. One repeated ciphertext letter yields one equality and a
    # web of 242 inequalities; the figure shows the density rather than listing it.
    try:
        from kryptos.kernel.constants import BEAN_EQ as _BEQ, BEAN_INEQ as _BINEQ, BEAN_LINEAR as _BLIN
    except ImportError:
        _BEQ, _BINEQ, _BLIN = ((27, 65),), (), ()
    _BX0, _BX1, _BAX = 40.0, 720.0, 104.0     # axis span and baseline y
    def _bx(i): return _BX0 + i * (_BX1 - _BX0) / (len(CT) - 1)
    _eq_a, _eq_b = _BEQ[0]
    bean_figure = {
        "x0": _BX0, "x1": _BX1, "axis_y": _BAX,
        "ticks": [{"x": _bx(i), "label": i} for i in (0, 21, 33, 63, 73, 96)],
        "cribs": [{"x": _bx(i)} for i in sorted({p for pair in _BINEQ for p in pair})],
        # 242 inequality pairs as faint chords under the axis
        "chords": [
            {"d": f"M {_bx(a):.1f} {_BAX} Q {(_bx(a)+_bx(b))/2:.1f} "
                  f"{_BAX + min(48, 8 + abs(_bx(b)-_bx(a)) * 0.15):.1f} {_bx(b):.1f} {_BAX}"}
            for a, b in _BINEQ
        ],
        # the single equality, drawn above and bold
        "eq": {
            "a": _eq_a, "b": _eq_b,
            "ax": _bx(_eq_a), "bx": _bx(_eq_b),
            "ct": CT[_eq_a],
            "pt": "EASTNORTHEAST"[_eq_a - 21] if 21 <= _eq_a <= 33 else "?",
            "d": f"M {_bx(_eq_a):.1f} {_BAX} Q {(_bx(_eq_a)+_bx(_eq_b))/2:.1f} 24 {_bx(_eq_b):.1f} {_BAX}",
            "mid_x": (_bx(_eq_a) + _bx(_eq_b)) / 2,
        },
        "n_ineq": len(_BINEQ),
        "n_linear": len(_BLIN),
    }

    # Transposition shapes. The site names many letter-rearrangement methods, and
    # "rail fence", "spiral" and "zigzag" are the names of shapes, so four are drawn
    # here. Permutations come from the kernel, so the pictures are the
    # real transforms rather than an illustrator's idea of them.
    _SAMPLE = "ABCDEFGHIJKL"          # 12 letters, a 3x4 grid
    try:
        from kryptos.kernel.transforms.transposition import (
            columnar_perm as _cp, rail_fence_perm as _rf,
            serpentine_perm as _sp, spiral_perm as _spi,
            apply_perm as _ap, invert_perm as _inv)
        _have_transp = True
    except ImportError:
        _have_transp = False

    transposition_shapes = []
    if _have_transp:
        def _grid(perm, rows, cols):
            """Cells in write-in order, each carrying its read-out position."""
            order = _inv(perm)          # order[j] = where input letter j lands in the output
            out = []
            for r in range(rows):
                row = []
                for c in range(cols):
                    j = r * cols + c
                    row.append({"ch": _SAMPLE[j], "n": order[j] + 1} if j < len(_SAMPLE) else None)
                out.append(row)
            return out

        def _railgrid(perm, depth, n):
            order = _inv(perm)
            rail, direction, rows = 0, 1, [[None] * n for _ in range(depth)]
            for j in range(n):
                rows[rail][j] = {"ch": _SAMPLE[j], "n": order[j] + 1}
                if rail == 0: direction = 1
                elif rail == depth - 1: direction = -1
                rail += direction
            return rows

        _col = _cp(4, [2, 0, 3, 1], length=12)
        _rail = _rf(12, 3)
        _ser = _sp(3, 4, 12)
        _spir = _spi(3, 4, 12)
        transposition_shapes = [
            {"name": "Rail fence", "note": "write in a zigzag across three rails, read each rail",
             "grid": _railgrid(_rail, 3, 12), "out": _ap(_SAMPLE, _rail), "wide": True},
            {"name": "Columnar", "note": "write in rows, read the columns in key order",
             "grid": _grid(_col, 3, 4), "out": _ap(_SAMPLE, _col), "wide": False},
            {"name": "Serpentine", "note": "write in rows, read alternating left to right and back",
             "grid": _grid(_ser, 3, 4), "out": _ap(_SAMPLE, _ser), "wide": False},
            {"name": "Spiral", "note": "write in rows, read inward from the top-left corner",
             "grid": _grid(_spir, 3, 4), "out": _ap(_SAMPLE, _spir), "wide": False},
        ]

    # Scoring bands against the random-key baseline, derived rather than
    # transcribed. A periodic key forces every crib position in one residue class
    # to share a key value, and a search picks the value satisfying the most
    # positions in that class. So the expected score of a RANDOM configuration is
    # the sum over residue classes of E[max multiplicity]. The class structure
    # comes from the real crib positions; only the per-class expectation is a
    # precomputed constant (exact, m items uniformly into 26 bins).
    # Reproduces the figures in CLAUDE.md: 17.3 at period 17, 19.2 at period 24.
    _EMAX = [0.0, 1.0, 1.038462, 1.113905, 1.220642, 1.349863, 1.491292, 1.635016,
             1.773068, 1.900414, 2.015179, 2.118179, 2.211997, 2.299926, 2.385069,
             2.469762, 2.555359, 2.642304, 2.730362, 2.818908, 2.907171, 2.994426,
             3.080103, 3.163845, 3.245508]
    try:
        from kryptos.kernel.constants import CRIB_POSITIONS as _CRIBPOS
        _crib_positions = sorted(_CRIBPOS)
    except ImportError:
        _crib_positions = list(range(21, 34)) + list(range(63, 74))

    def _expected_random(period: int) -> float:
        classes: dict[int, int] = {}
        for x in _crib_positions:
            classes[x % period] = classes.get(x % period, 0) + 1
        return sum(_EMAX[n] for n in classes.values())

    _PERIODS = list(range(2, 27))
    _curve = [(k, _expected_random(k)) for k in _PERIODS]
    # SVG geometry, computed here so the template stays declarative.
    _X0, _X1, _Y0, _Y1 = 54.0, 736.0, 26.0, 274.0
    def _px(k): return _X0 + (k - _PERIODS[0]) * (_X1 - _X0) / (_PERIODS[-1] - _PERIODS[0])
    def _py(v): return _Y1 - (v / 24.0) * (_Y1 - _Y0)
    scoring_chart = {
        "bands": [
            {"label": "NOISE", "lo": 0,  "hi": 9,  "cls": "noise",
             "y": _py(10), "h": _py(0) - _py(10)},
            {"label": "INTERESTING", "lo": 10, "hi": 17, "cls": "store",
             "y": _py(18), "h": _py(10) - _py(18)},
            {"label": "SIGNAL", "lo": 18, "hi": 23, "cls": "signal",
             "y": _py(24), "h": _py(18) - _py(24)},
        ],
        "points": " ".join(f"{_px(k):.1f},{_py(v):.1f}" for k, v in _curve),
        "dots": [{"x": _px(k), "y": _py(v), "period": k, "value": round(v, 1),
                  "hot": v >= 18} for k, v in _curve],
        "xticks": [{"x": _px(k), "label": k} for k in (2, 7, 12, 17, 21, 24, 26)],
        "yticks": [{"y": _py(v), "label": v} for v in (0, 6, 12, 18, 24)],
        "signal_y": _py(18),
        "x0": _X0, "x1": _X1, "y0": _Y0, "y1": _Y1,
        "at7": round(_expected_random(7), 1),
        "at17": round(_expected_random(17), 1),
        "at21": round(_expected_random(21), 1),
        "at24": round(_expected_random(24), 1),
        "at26": round(_expected_random(26), 1),
    }

    # Quagmire III tableau, derived from the kernel rather than transcribed, so the
    # figure cannot drift from the implementation that reproduces K1 and K2.
    # Verified convention (tests/test_transforms.py::test_k1_groundtruth): both the
    # plaintext and ciphertext alphabets are KRYPTOS-mixed, the indicator is K, and
    # PALIMPSEST is the cycleword, not an alphabet keyword.
    try:
        from kryptos.kernel.alphabet import keyword_mixed_alphabet as _kma
        _KA = _kma("KRYPTOS")
    except ImportError:
        _KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    _kidx = {c: i for i, c in enumerate(_KA)}
    _IND = _kidx["K"]
    _CYCLEWORD = "PALIMPSEST"
    tableau = {
        "alphabet": _KA,
        "indicator": "K",
        "cycleword": _CYCLEWORD,
        # One row per DISTINCT cycleword letter: K1 only ever uses these eight of
        # the twenty-six rows, which is the point the figure makes.
        "rows": [
            {
                "key": ch,
                "shift": (_kidx[ch] - _IND) % 26,
                "letters": [_KA[(i + (_kidx[ch] - _IND)) % 26] for i in range(26)],
            }
            for ch in dict.fromkeys(_CYCLEWORD)
        ],
        # The worked lookup the caption walks through: B + key P -> E, which is
        # literally K1's first character.
        "example": {"pt": "B", "key": "P", "ct": "E"},
    }

    # Global context available to all templates
    # Two dates, deliberately. "Rebuilt" is when this HTML was generated;
    # "newest experiment" is the freshest research input the loader actually
    # saw. They diverge whenever the site is republished without new results,
    # and conflating them is what let a 24-day drift go unnoticed in 2026-08.
    _build_date = _dt.date.today().isoformat()
    _newest_result = _newest_result_date()
    # A GA4 measurement ID is public configuration, not a credential.  Keep it
    # out of templates so analytics can be enabled per environment and omitted
    # entirely until the production measurement property is ready.
    _ga4_measurement_id = os.environ.get("GA4_MEASUREMENT_ID", "").strip()
    if _ga4_measurement_id and not re.fullmatch(r"G-[A-Z0-9]+", _ga4_measurement_id):
        raise ValueError("GA4_MEASUREMENT_ID must use the GA4 G-XXXXXXXXXX format")
    # The AdSense publisher ID is public configuration exactly like the GA4 ID,
    # and is env-driven for the same reason: the site must build, and ship no ad
    # code at all, on a machine that has no AdSense account.
    _adsense_client_id = os.environ.get("ADSENSE_CLIENT_ID", "").strip()
    if _adsense_client_id and not re.fullmatch(r"ca-pub-[0-9]+", _adsense_client_id):
        raise ValueError("ADSENSE_CLIENT_ID must use the ca-pub-0000000000000000 format")
    global_ctx = {
        "ct": CT,
        "tableau": tableau,
        "scoring_chart": scoring_chart,
        "w_delimiter": w_delimiter,
        "bean_figure": bean_figure,
        "transposition_shapes": transposition_shapes,
        "transposition_sample": _SAMPLE,
        "k4_cribs": [
            {"start": 21, "text": "EASTNORTHEAST"},
            {"start": 63, "text": "BERLINCLOCK"},
        ],
        "k4_sections": K4_SECTIONS,
        "total_configs_disproven": total_configs_disproven,
        "total_configs_exact": total_configs,
        "total_experiments_exact": total_experiments,
        "total_scripts": total_scripts,
        "build_date": _build_date,
        "newest_result_date": _newest_result,
        "ga4_measurement_id": _ga4_measurement_id,
        "adsense_client_id": _adsense_client_id,
        # Ads are on by default and switched OFF per page. Defaulting the other
        # way would mean a new page silently carries no ads; defaulting this way
        # means a new page carrying archival third-party imagery must be opted
        # out deliberately, which is the mistake we want to be loud.
        "show_ads": True,
        # Pages that are data records rather than articles (the elimination
        # cards, the JS shells) are rendered through _unindexed(), which flips
        # this on and show_ads off. See tests/test_site_builder_build.py.
        "noindex": False,
        # The apex 301s to www, so a canonical pointing at the apex points at a
        # redirect. Single source for canonical, og:url and the sitemap, which
        # had already drifted apart as three separate literals.
        "site_origin": SITE_ORIGIN,
    }
    print(f"  Build date: {_build_date} | newest research input: {_newest_result or 'unknown'}")

    # 6) Prepare output directory
    #    Preserve stats/ (GoAccess) and static/ (avoid transient 404s for
    #    fonts/CSS/JS while HTML pages are being regenerated — static assets
    #    are overwritten in step 10 anyway).
    _prepare_output_dir(OUTPUT_DIR)

    # 7) Build category browse data
    categories_for_browse = []
    for cs in cat_stats:
        cat_name = cs["category"]
        categories_for_browse.append({
            "name": cs["display_name"],
            "slug": cat_name,
            "description": CATEGORY_DESCRIPTIONS.get(cat_name, ""),
            "count": cs["count"],
            "total_configs": cs["total_configs"],
            "best_score": cs["best_score"],
        })

    # 8) Render pages
    pages_built = 0

    # Home
    _render(env, "home.html", "index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
        "total_scripts": total_scripts,
        "total_configs": total_configs_disproven,
        "total_categories": total_categories,
        "categories": categories_for_browse,
    })
    pages_built += 1

    # Browse index
    _render(env, "browse.html", "browse/index.html", {
        **global_ctx,
        "categories": categories_for_browse,
    })
    pages_built += 1

    # Per-category pages
    for cat_name, subcats in tree.items():
        all_elims_in_cat = []
        for subcat_elims in subcats.values():
            all_elims_in_cat.extend(subcat_elims)
        all_elims_in_cat.sort(key=lambda e: e.configs_tested, reverse=True)

        display_name = cat_name.replace("-", " ").title()
        _render(env, "category.html", f"browse/{cat_name}/index.html", {
            **global_ctx,
            "category": {
                "name": display_name,
                "slug": cat_name,
                "description": CATEGORY_DESCRIPTIONS.get(cat_name, ""),
                "plain_guide": CATEGORY_PLAIN_GUIDES.get(cat_name, ""),
            },
            "eliminations": all_elims_in_cat,
        })
        pages_built += 1

    # Individual elimination pages
    for e in eliminations:
        # Ensure scope_limitations and assumptions are lists for template
        if isinstance(e.scope_limitations, str):
            cleaned = e.scope_limitations.strip()
            if cleaned in ("", "[]", "None"):
                e.scope_limitations = []
            else:
                e.scope_limitations = [s.strip() for s in cleaned.split(";") if s.strip()]
        elif not e.scope_limitations:
            e.scope_limitations = []

        if isinstance(e.assumptions, str):
            cleaned = e.assumptions.strip()
            if cleaned in ("", "[]", "None"):
                e.assumptions = []
            else:
                e.assumptions = [a.strip() for a in cleaned.split(";") if a.strip()]
        elif not e.assumptions:
            e.assumptions = []

        _render(env, "elimination.html", f"elimination/{e.slug}/index.html", {
            **_unindexed(global_ctx),
            "e": e,
        })
        pages_built += 1

    # Submit
    _render(env, "submit.html", "submit/index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
    })
    pages_built += 1

    # Submission Status
    _render(env, "status.html", "status/index.html", _unindexed(global_ctx))
    pages_built += 1

    # Methodology
    _render(env, "methodology.html", "methodology/index.html", {
        **global_ctx,
        "ct": CT,
        "total_experiments": total_experiments,
        "total_configs": total_configs_disproven,
    })
    pages_built += 1

    # FAQ
    _render(env, "faq.html", "faq/index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
    })
    pages_built += 1

    # Research Questions
    _render(env, "research_questions.html", "research-questions/index.html", {
        **global_ctx,
        "tiers": rq_by_tier,
    })
    pages_built += 1

    # Recent
    recent = sorted(
        [e for e in eliminations if e.date_tested],
        key=lambda e: e.date_tested,
        reverse=True,
    )[:50]
    _render(env, "recent.html", "recent/index.html", {
        **global_ctx,
        "recent_eliminations": recent,
    })
    pages_built += 1

    # About Kryptos
    _render(env, "about_kryptos.html", "about-kryptos/index.html", global_ctx)
    pages_built += 1

    # About Me
    _render(env, "about_me.html", "about-me/index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
    })
    pages_built += 1

    # Findings
    _findings_ctx = _build_findings_context(CT, global_ctx)
    _render(env, "findings.html", "findings/index.html", _findings_ctx)
    pages_built += 1

    # Workbench
    _render(env, "workbench.html", "workbench/index.html", global_ctx)
    pages_built += 1

    # VIC Workbench
    _render(env, "vic_workbench.html", "vic-workbench/index.html", global_ctx)
    pages_built += 1

    # Cylinder Viewer (standalone HTML — Jinja2 corrupts inline JS)
    _build_cylinder_viewer(global_ctx)
    pages_built += 1

    # Archive Research Photos
    _render(env, "archive.html", "archive/index.html", {**global_ctx, "show_ads": False})
    pages_built += 1

    # The K1/K2 encoding chart, examined (article; indexed, ads on)
    _render(env, "encoding_chart.html", "encoding-chart/index.html", global_ctx)
    pages_built += 1

    # Challenge K4
    _render(env, "challenge.html", "challenge/index.html", global_ctx)
    pages_built += 1

    # Report error
    # A 180-word form linked from every footer: a shell, not an article.
    _render(env, "report_error.html", "report-error/index.html", _unindexed(global_ctx))
    pages_built += 1

    # 404 page (at root for nginx error_page directive). An error screen is
    # the textbook "screen without publisher content"; no ad code on it.
    _render(env, "404.html", "404.html", _unindexed(global_ctx))
    pages_built += 1

    # Search
    _render(env, "search.html", "search/index.html", _unindexed(global_ctx))
    pages_built += 1

    # Terms of Use
    _render(env, "terms.html", "terms/index.html", global_ctx)
    pages_built += 1

    # A posted privacy policy is an AdSense prerequisite, and terms.html has
    # incorporated "any posted Privacy Policy" by reference since before one
    # existed. Ads are off here: a policy page carrying ads reads badly and
    # adds nothing.
    _render(env, "privacy.html", "privacy/index.html", {**global_ctx, "show_ads": False})
    pages_built += 1

    # 9) Generate search index
    search_index_path = os.path.join(OUTPUT_DIR, "search-index.json")
    n_indexed = write_search_index(eliminations, search_index_path)
    print(f"\n  Search index: {n_indexed} documents → {search_index_path}")

    # 9a2) ads.txt. Google reads https://<domain>/ads.txt to confirm which
    #      networks may sell this site's inventory; without it AdSense reports
    #      the site as unauthorised and demand drops. Written only when a
    #      publisher ID is configured, so a build without one ships no file
    #      rather than a file naming an empty publisher.
    _write_ads_txt(_adsense_client_id, OUTPUT_DIR)

    # 9b) Generate sitemap.xml
    _write_sitemap(tree, OUTPUT_DIR)
    print("  sitemap.xml generated")

    # 10) Copy static assets (including subdirectories like fonts/)
    # Also copy robots.txt to site root (not under /static/)
    print("\nCopying static assets...")
    static_out = os.path.join(OUTPUT_DIR, "static")
    os.makedirs(static_out, exist_ok=True)
    for fname in os.listdir(STATIC_DIR):
        src = os.path.join(STATIC_DIR, fname)
        # robots.txt and Google verification files go to site root, not /static/
        if fname in ("robots.txt", "favicon.ico") or fname.startswith("google") and fname.endswith(".html"):
            shutil.copy2(src, os.path.join(OUTPUT_DIR, fname))
            print(f"  {fname} (→ site root)")
            continue
        dst = os.path.join(static_out, fname)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
            print(f"  {fname}/")
        elif os.path.isfile(src):
            shutil.copy2(src, dst)
            print(f"  {fname}")

    # 10b) Copy reference PDFs to static output
    ref_pdf = os.path.join(PROJECT_ROOT, "reference", "Number-One-From-Moscow.pdf")
    if os.path.isfile(ref_pdf):
        shutil.copy2(ref_pdf, os.path.join(static_out, "Number-One-From-Moscow.pdf"))
        print("  Number-One-From-Moscow.pdf (from reference/)")

    # 10c) Banned-phrase guard: fail the build if any rendered page contains
    # off-limits topics (site content policy). Catches policy leaks arriving
    # via script metadata / results JSON before they can ship.
    # 10c) Cache-bust static asset URLs. Must run AFTER every page is written
    # and after the static copy, since the hash is taken from the built file.
    n_files, n_refs, missing = _cache_bust_assets(OUTPUT_DIR)
    print(f"\n  Cache-busted {n_refs} asset refs across {n_files} pages")
    for m in missing:
        print(f"  WARNING: referenced static asset not found, left unversioned: {m}")

    _check_banned_phrases(OUTPUT_DIR)

    # 11) Summary
    print("\n" + "=" * 60)
    print(f"BUILD COMPLETE")
    print(f"  Pages built: {pages_built}")
    print(f"  Eliminations: {len(eliminations)}")
    print(f"  Output directory: {OUTPUT_DIR}")
    print(f"  Total configs disproven: {total_configs_disproven}")
    print("=" * 60)


# Site content policy: these topics must never appear on any page. Phrases are
# matched case-insensitively against rendered HTML. Keep the list short and
# unambiguous to avoid false positives on legitimate archival content.
BANNED_PHRASES = (
    "auction",
    "962,500",
    "sealed until 2075",
    "anonymous buyer",
)


# ── Static-asset cache busting ───────────────────────────────────────────────
#
# nginx serves /static/ with `Cache-Control: public, immutable, max-age=604800`.
# `immutable` tells the browser never to revalidate, not even on a normal
# refresh. With a stable URL like /static/style.css that means a returning
# visitor keeps last week's stylesheet for up to seven days.
#
# That is not theoretical. On 2026-08-23 the scoring chart and Bean arc figures
# shipped as SVG whose every colour comes from `fig-*` CSS classes and which
# carry no inline styles (CSP is `style-src 'self'`, so they cannot). Visitors
# holding the pre-figure stylesheet rendered those SVGs with no rules at all,
# and an unstyled <rect>/<path> falls back to the SVG default fill: black.
#
# Appending a content hash makes the URL change whenever the bytes change, so
# `immutable` becomes correct instead of harmful. This runs as a post-pass over
# the built HTML rather than as a template helper, because asset references are
# authored in three different places (Jinja templates, f-strings in this file,
# and regex injection into the standalone viewers) and a single pass cannot
# drift out of sync the way hand-maintained `?v=7` suffixes did.

# Matched against BYTES, not str: the built tree contains at least one
# non-UTF-8 HTML artifact (site/stats/index.html is copied in verbatim), and a
# bytes pass preserves every file's original encoding exactly instead of
# forcing a decode that would either fail the build or corrupt the file.
_ASSET_REF_RE = re.compile(
    rb'(?P<attr>\b(?:href|src))="(?P<path>/static/[^"?#]+\.(?:css|js))(?:\?[^"#]*)?"'
)


def _asset_fingerprint(output_dir: str, url_path: bytes,
                       cache: dict[bytes, bytes | None]) -> bytes | None:
    """Short content hash for a built static asset, or None if it is missing."""
    if url_path in cache:
        return cache[url_path]
    fs_path = os.path.join(output_dir, url_path.decode("ascii").lstrip("/"))
    try:
        with open(fs_path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()[:8].encode("ascii")
    except OSError:
        digest = None
    cache[url_path] = digest
    return digest


def _cache_bust_assets(output_dir: str) -> tuple[int, int, list[str]]:
    """Rewrite every /static/*.css|js reference in built HTML to carry ?v=<hash>.

    Idempotent: an existing query string is replaced, not appended to, so
    rebuilding does not accumulate suffixes. Returns
    (files_rewritten, refs_rewritten, sorted missing asset paths).
    """
    cache: dict[bytes, bytes | None] = {}
    missing: set[str] = set()
    files_changed = 0
    refs = 0

    def _sub(m: "re.Match[bytes]") -> bytes:
        nonlocal refs
        path = m.group("path")
        digest = _asset_fingerprint(output_dir, path, cache)
        if digest is None:
            missing.add(path.decode("ascii", "replace"))
            return m.group(0)
        refs += 1
        return m.group("attr") + b'="' + path + b"?v=" + digest + b'"'

    for root, _dirs, files in os.walk(output_dir):
        for fname in files:
            if not fname.endswith(".html"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "rb") as fh:
                html = fh.read()
            new_html = _ASSET_REF_RE.sub(_sub, html)
            if new_html != html:
                with open(fpath, "wb") as fh:
                    fh.write(new_html)
                files_changed += 1

    return files_changed, refs, sorted(missing)


def _check_banned_phrases(output_dir: str) -> None:
    """Fail the build if any rendered .html contains a banned phrase.

    Skips stats/ (GoAccess log report: contains attacker-controlled request
    paths from access logs, not authored site content).
    """
    hits = []
    for root, dirs, files in os.walk(output_dir):
        dirs[:] = [d for d in dirs if d != "stats"]
        for fname in files:
            if not fname.endswith(".html"):
                continue
            path = os.path.join(root, fname)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    content = f.read().lower()
            except OSError:
                continue
            for phrase in BANNED_PHRASES:
                if phrase in content:
                    hits.append((os.path.relpath(path, output_dir), phrase))
    if hits:
        print("\nBUILD FAILED: banned phrase(s) found in rendered pages:")
        for rel, phrase in hits:
            print(f"  {rel}: contains {phrase!r}")
        print("Fix the source (overrides.toml / results JSON / template) and rebuild.")
        sys.exit(1)
    print("  Banned-phrase guard: clean")


def _build_standalone_viewer(
    src_name: str,
    out_slug: str,
    title: str,
    css_file: str,
    js_file: str,
    page_class: str,
    global_ctx: dict,
):
    """Build a standalone HTML viewer into the site with CSP compliance.

    Strips inline <style> and <script>, injects site chrome (banner, nav,
    footer), wraps body content in a scoping class, and links to external
    CSS/JS files.
    """
    import re

    standalone_dir = os.path.join(os.path.dirname(__file__), "standalone")
    src_path = os.path.join(standalone_dir, src_name)
    with open(src_path) as f:
        html = f.read()

    # Extract body content (between <body> and </body>)
    body_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL)
    if not body_match:
        print(f"  WARNING: Could not extract body from {src_name}")
        return
    body_content = body_match.group(1)

    # Remove any inline <script> blocks from body content
    body_content = re.sub(r'<script\b[^>]*>.*?</script>', '', body_content, flags=re.DOTALL)

    # Remove onclick attributes (CSP: event listeners are in external JS)
    body_content = re.sub(r'\s+onclick="[^"]*"', '', body_content)

    # Build the full page with site chrome
    counter = global_ctx.get("total_configs_disproven", "")

    page_html = f'''<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="kryptosbot.com | The K4 Elimination Database.">
  <meta property="og:title" content="{title}">
  <meta property="og:site_name" content="kryptosbot.com">
  <meta property="og:image" content="https://kryptosbot.com/static/kryptosbot-og.jpg">
  <link rel="icon" href="/favicon.ico" sizes="any">
  <link rel="icon" type="image/webp" href="/static/kryptosbot-nav.webp">
  <link rel="stylesheet" href="/static/fonts/fonts.css">
  <link rel="stylesheet" href="/static/style.css">
  <link rel="stylesheet" href="/static/{css_file}">
  <title>{title}</title>
</head>
<body>
  <div class="disproven-banner">
    <span class="disproven-count">{counter}</span>
    <span class="disproven-label">configurations evaluated across recorded experiments</span>
  </div>

  <nav>
    <ul>
      <li><strong><a href="/" class="nav-brand"><img src="/static/kryptosbot-nav.webp" alt="" class="nav-logo" width="28" height="28">kryptosbot</a></strong></li>
    </ul>
    <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Toggle navigation">
    <label for="nav-toggle" class="nav-toggle-label" aria-hidden="true">
      <span></span><span></span><span></span>
    </label>
    <ul class="nav-links">
      <li><a href="/findings/">What We Learned</a></li>
      <li><a href="/browse/">Eliminations</a></li>
      <li><a href="/methodology/">How We Test</a></li>
      <li><a href="/research-questions/">Open Questions</a></li>
      <li class="nav-group">
        <a href="/workbench/" class="nav-group-label">Tools</a>
        <ul class="nav-dropdown">
          <li><a href="/workbench/">Cipher Workbench</a></li>
          <li><a href="/vic-workbench/">VIC Cipher</a></li>
          <li><a href="/cylinder-viewer/">Cylinder Viewer</a></li>
        </ul>
      </li>
      <li><a href="/submit/">Submit</a></li>
      <li><a href="/faq/">FAQ</a></li>
      <li><a href="/archive/">Archive Photos</a></li>
      <li><a href="/about-kryptos/">About</a></li>
    </ul>
  </nav>

  <main class="container">
    <div class="{page_class}">
{body_content}
    </div>
  </main>

  <footer class="container">
    <hr>
    <p>
      Built by <a href="/about-me/">Colin Patrick</a> &amp; <a href="https://claude.ai">Claude</a>
      &middot; <a href="https://github.com/jcolinpatrick/kryptos">Source</a>
      &middot; <a href="/terms/">Terms</a>
      &middot; <a href="/privacy/">Privacy</a>
      &middot; <a href="mailto:contact@kryptosbot.com">Contact</a>
      &middot; <a href="/report-error/">Report error</a>
    </p>
    <p><small>Not affiliated with the CIA, Jim Sanborn, Ed Scheidt, or Paradigm Operations LP. This site does not know the solution.</small></p>
  </footer>

  <script src="/static/{js_file}"></script>
</body>
</html>'''

    out_dir = os.path.join(OUTPUT_DIR, out_slug)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w") as f:
        f.write(page_html)


def _build_cylinder_viewer(global_ctx: dict):
    """Build the cylinder viewer from the standalone HTML, injecting site nav.

    The standalone file has inline JS that Jinja2 autoescape corrupts, so we
    build it outside the template engine.  We inject the site's banner, nav,
    and footer via string replacement, and externalise inline style/script
    for the nginx CSP (script-src / style-src 'self').
    """
    import re

    src_html = os.path.join(os.path.dirname(__file__), "standalone", "cylinder_viewer.html")
    with open(src_html) as f:
        html = f.read()

    # -- 1. Replace <head> internals: add site stylesheets before the inline <style>
    site_head = (
        '<meta name="description" content="Explore the Kryptos cipher panel as 28 rotatable rings, like a Jefferson cipher wheel. Slide rows and look for alignments.">\n'
        '<meta property="og:title" content="Cylinder Viewer | kryptosbot.com">\n'
        f'<meta property="og:image" content="{SITE_ORIGIN}/static/kryptosbot-og.jpg">\n'
        f'<meta property="og:url" content="{SITE_ORIGIN}/cylinder-viewer/">\n'
        f'<link rel="canonical" href="{SITE_ORIGIN}/cylinder-viewer/">\n'
        # This page bypasses Jinja entirely, so base.html's analytics and ad
        # blocks never reached it: /cylinder-viewer/ was the one page invisible
        # to GA4, which would have been a silent hole in the traffic baseline.
        + (f'<script src="/static/ga4.js" data-measurement-id="{global_ctx["ga4_measurement_id"]}"></script>\n'
           if global_ctx.get("ga4_measurement_id") else '')
        + (f'<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client={global_ctx["adsense_client_id"]}" crossorigin="anonymous"></script>\n'
           if global_ctx.get("adsense_client_id") and global_ctx.get("show_ads") else '')
        + '<link rel="stylesheet" href="/static/fonts/fonts.css">\n'
        '<link rel="stylesheet" href="/static/style.css">\n'
        '<link rel="icon" href="/favicon.ico" sizes="any">\n'
        '<link rel="icon" type="image/webp" href="/static/kryptosbot-nav.webp">\n'
    )
    html = html.replace('<title>Kryptos Cylinder Viewer</title>', f'<title>Cylinder Viewer | kryptosbot.com</title>\n{site_head}', 1)

    # -- 1b. Add the explanatory intro after the one-line subtitle
    intro_html = (
        '<div class="cv-intro">\n'
        '  <p>\n'
        '    The Kryptos cipher panel as 28 rotatable rings in a 31-column window.\n'
        '    The rows are the panel&rsquo;s characters, with one of the four question marks\n'
        '    left out, re-wrapped at an even 31 per row. The carved lines vary in length\n'
        '    (the K1 and K2 lines alone run 30 to 32), so not every row here matches a\n'
        '    line on the copper.\n'
        '    The idea comes from two margin marks on Sanborn&rsquo;s K1/K2 encoding chart,\n'
        '    an arrow pointing right beside row 1 and one pointing left beside row 2, which\n'
        '    some read as rows sliding independently, like a Jefferson cipher wheel or\n'
        '    combination lock. Our study of the chart found no non-letter mark on it that\n'
        '    clearly points beyond ordinary place-keeping, so this viewer is for exploration,\n'
        '    not a known method.\n'
        '    On that chart, row 5 (starting IMVMZJA) holds 32 letters instead of 31\n'
        '    (<a href="/encoding-chart/">see the chart</a>).\n'
        '  </p>\n'
        '  <p>\n'
        '    Rotate any row with the arrow buttons or by click-dragging. The offset badge\n'
        '    on the right tracks how far each row has shifted. Look for vertical alignments,\n'
        '    repeating patterns, or columnar relationships that emerge as you slide rows\n'
        '    relative to each other.\n'
        '  </p>\n'
        '</div>\n'
    )
    subtitle_line = '<div class="subtitle">Cipher panel: 28 rows &times; 31 columns. Each row is a rotatable ring</div>'
    html = html.replace(subtitle_line, subtitle_line + '\n' + intro_html, 1)

    # -- 2. Externalise inline <style> and <script> for CSP
    html = re.sub(
        r'<style>\n.*?</style>',
        '<link rel="stylesheet" href="/static/cylinder_viewer.css">',
        html, flags=re.DOTALL, count=1,
    )
    html = re.sub(
        r'<script>\n// ── DATA.*?</script>',
        '<script src="/static/cylinder_viewer.js"></script>',
        html, flags=re.DOTALL,
    )

    # -- 2c. Strip inline onclick handlers (blocked by nginx CSP: script-src 'self')
    #    The JS attaches listeners via addEventListener instead.
    html = html.replace(' onclick="resetAll()"', '')
    html = html.replace(' onclick="toggleNullHighlight()"', '')
    html = html.replace(' onclick="togglePositions()"', '')
    # Add an ID to the Reset All button so JS can find it
    html = html.replace(
        '<button>Reset All</button>',
        '<button id="btn-reset">Reset All</button>',
        1,
    )

    # -- 2c. Remap standalone CSS variables to scoped names in inline styles
    html = html.replace('var(--highlight-ene)', 'var(--cv-ene)')
    html = html.replace('var(--highlight-bcl)', 'var(--cv-bcl)')
    html = html.replace('var(--anomaly)', 'var(--cv-anomaly)')
    html = html.replace('var(--cell)', 'var(--cv-cell)')

    # -- 2d. Replace the legend swatches' inline style attributes with classes.
    #    nginx serves this site under CSP `style-src 'self'` (no 'unsafe-inline'),
    #    which blocks style="" attributes outright, so the three swatches rendered
    #    as colourless boxes. The classes are defined in static/cylinder_viewer.css.
    html = re.sub(
        r'<div class="legend-swatch" style="background:var\(--cv-ene\)"\s*></div>',
        '<div class="legend-swatch sw-ene"></div>', html, count=1,
    )
    html = re.sub(
        r'<div class="legend-swatch" style="background:var\(--cv-bcl\)"\s*></div>',
        '<div class="legend-swatch sw-bcl"></div>', html, count=1,
    )
    html = re.sub(
        r'<div class="legend-swatch" style="background:var\(--cv-cell\);\s*'
        r'border-color:var\(--cv-anomaly\)"\s*></div>',
        '<div class="legend-swatch sw-filler"></div>', html, count=1,
    )

    # -- 3. Inject banner + nav after <body>
    configs = global_ctx.get("total_configs_disproven", "")
    nav_html = f"""
  <div class="disproven-banner">
    <span class="disproven-count">{configs}</span>
    <span class="disproven-label">configurations evaluated across recorded experiments</span>
  </div>

  <nav>
    <ul>
      <li><strong><a href="/" class="nav-brand"><img src="/static/kryptosbot-nav.webp" alt="" class="nav-logo" width="28" height="28">kryptosbot</a></strong></li>
    </ul>
    <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Toggle navigation">
    <label for="nav-toggle" class="nav-toggle-label" aria-hidden="true">
      <span></span><span></span><span></span>
    </label>
    <ul class="nav-links">
      <li><a href="/findings/">What We Learned</a></li>
      <li><a href="/browse/">Eliminations</a></li>
      <li><a href="/methodology/">How We Test</a></li>
      <li><a href="/research-questions/">Open Questions</a></li>
      <li class="nav-group">
        <a href="/workbench/" class="nav-group-label">Tools</a>
        <ul class="nav-dropdown">
          <li><a href="/workbench/">Cipher Workbench</a></li>
          <li><a href="/vic-workbench/">VIC Cipher</a></li>
          <li><a href="/cylinder-viewer/">Cylinder Viewer</a></li>
        </ul>
      </li>
      <li><a href="/submit/">Submit</a></li>
      <li><a href="/faq/">FAQ</a></li>
      <li><a href="/archive/">Archive Photos</a></li>
      <li><a href="/about-kryptos/">About</a></li>
    </ul>
  </nav>

  <main class="container">
"""
    html = html.replace('<body>\n', f'<body>\n{nav_html}', 1)

    # -- 3b. Wrap viewer body content in .cv-page scope
    #    Load-bearing: static/cylinder_viewer.css scopes 42 of its 59 rules under
    #    .cv-page AND defines every --cv-* custom property there. Without this
    #    wrapper the entire viewer renders unstyled. This previously matched an
    #    ALL-CAPS <h1> that the standalone had since retitled to title case, so
    #    the opening tag silently vanished while the closing </div> below still
    #    landed, leaving both an unstyled viewer and unbalanced markup. Match
    #    case-insensitively and assert, so a future retitle fails the build
    #    instead of quietly shipping a broken page.
    _h1 = re.search(r'<h1>\s*Kryptos\s+Cylinder\s+Viewer\s*</h1>', html, re.I)
    if not _h1:
        raise RuntimeError(
            "cylinder viewer: could not find the <h1> to open the .cv-page wrapper. "
            "The heading in standalone/cylinder_viewer.html was probably retitled. "
            "Without the wrapper every .cv-page-scoped CSS rule and every --cv-* "
            "variable stops applying and the viewer renders unstyled."
        )
    html = html[:_h1.start()] + '<div class="cv-page">\n' + html[_h1.start():]

    _script_tag = '<script src="/static/cylinder_viewer.js"></script>'
    if _script_tag not in html:
        raise RuntimeError(
            "cylinder viewer: script tag not found; cannot close the .cv-page wrapper."
        )
    html = html.replace(_script_tag, '</div>\n' + _script_tag, 1)

    # -- 4. Inject footer before </body>
    footer_html = """
  </main>

  <footer class="container">
    <hr>
    <p>
      Built by <a href="/about-me/">Colin Patrick</a> &amp; <a href="https://claude.ai">Claude</a>
      &middot; <a href="https://github.com/jcolinpatrick/kryptos">Source</a>
      &middot; <a href="/terms/">Terms</a>
      &middot; <a href="/privacy/">Privacy</a>
      &middot; <a href="mailto:contact@kryptosbot.com">Contact</a>
      &middot; <a href="/report-error/">Report error</a>
    </p>
    <p><small>Not affiliated with the CIA, Jim Sanborn, Ed Scheidt, or Paradigm Operations LP. This site does not know the solution.</small></p>
  </footer>
"""
    html = html.replace('</body>', f'{footer_html}</body>', 1)

    # -- 5. Add data-theme="dark" to <html> for consistency with rest of site
    html = html.replace('<html lang="en">', '<html lang="en" data-theme="dark">', 1)

    out_dir = os.path.join(OUTPUT_DIR, "cylinder-viewer")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w") as f:
        f.write(html)


def _build_findings_context(ct: str, global_ctx: dict) -> dict:
    """Build template context for the findings page."""
    # Stehle anomaly: positions 55-63, lag-4 difference = 5
    stehle_positions = list(range(55, 64))
    stehle_values = [ord(ct[p]) - ord('A') for p in stehle_positions]
    stehle_diffs = [(stehle_values[i] - stehle_values[i - 4]) % 26
                    for i in range(4, len(stehle_values))]

    return {
        **global_ctx,
        "ct": ct,
        "stehle_positions": stehle_positions,
        "stehle_values": stehle_values,
        "stehle_diffs": stehle_diffs,
    }


def _unindexed(context: dict) -> dict:
    """Context for a page that is published but not part of the site's indexed
    or monetised surface: noindex,follow in the head and no AdSense tag.

    Used for the ~530 per-experiment elimination records and the search/status
    JS shells. AdSense's 2026-09-04 "low value content" rejection sampled the
    records (703 crawler fetches vs 6 per written page); Google's inventory
    policy forbids ads on low-content screens regardless of what else the site
    holds, so the records carry no ad code even after the site is approved.
    """
    return {**context, "show_ads": False, "noindex": True}


def _render(env: Environment, template_name: str, output_path: str, context: dict):
    """Render a Jinja2 template to a file in the output directory."""
    tmpl = env.get_template(template_name)
    html = tmpl.render(**context)

    out_file = os.path.join(OUTPUT_DIR, output_path)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w") as f:
        f.write(html)


def _group_research_questions(
    rqs: list[dict],
    rq_coverage: list,
) -> list[tuple[str, list[dict]]]:
    """Group research questions by tier for the template.

    Returns a list of (tier_name, [rq_dicts]) tuples.
    """
    # Build coverage lookup
    cov_map = {}
    for rc in rq_coverage:
        cov_map[rc.research_question] = rc

    # Enrich RQs with coverage data
    for rq in rqs:
        rc = cov_map.get(rq["id"])
        if rc:
            rq["hypotheses_total"] = rc.total_hypotheses
            rq["hypotheses_eliminated"] = rc.eliminated

    # Group by tier based on RQ number
    tier_1 = []  # RQ-1 to RQ-3
    tier_2 = []  # RQ-4 to RQ-7
    tier_3 = []  # RQ-8, RQ-10
    tier_4 = []  # RQ-9, RQ-11 to RQ-13

    for rq in rqs:
        rq_num = int(rq["id"].replace("RQ-", "")) if rq["id"].startswith("RQ-") else 99
        if rq_num <= 3:
            tier_1.append(rq)
        elif rq_num <= 7:
            tier_2.append(rq)
        elif rq_num in (8, 10):
            tier_3.append(rq)
        else:
            tier_4.append(rq)

    result = []
    if tier_1:
        result.append(("Tier 1: Maximum Leverage", tier_1))
    if tier_2:
        result.append(("Tier 2: High Leverage", tier_2))
    if tier_3:
        result.append(("Tier 3: Moderate Leverage", tier_3))
    if tier_4:
        result.append(("Tier 4: Background", tier_4))

    return result


def _write_ads_txt(adsense_client_id: str, output_dir: str) -> None:
    """Write /ads.txt declaring Google as an authorised seller.

    The ads.txt publisher ID drops the "ca-" prefix that the ad tag uses:
    the tag says ca-pub-123, ads.txt says pub-123. Getting that wrong is a
    silent failure - the file parses, Google just does not match it.
    f08c47fec0942fa0 is Google's own certification authority ID and is the
    same for every publisher.
    """
    if not adsense_client_id:
        return
    publisher = adsense_client_id.removeprefix("ca-")
    with open(os.path.join(output_dir, "ads.txt"), "w") as f:
        f.write(f"google.com, {publisher}, DIRECT, f08c47fec0942fa0\n")
    print(f"  ads.txt written for {publisher}")


def _write_sitemap(tree: dict, output_dir: str):
    """Generate sitemap.xml for search engine discovery.

    Lists only pages meant to be indexed: the written pages and the category
    browse pages. Elimination records and the search/status JS shells render
    with noindex (see _unindexed) and are deliberately absent; a sitemap entry
    for a noindex page is a Search Console error, not a hint.
    """
    base = SITE_ORIGIN

    urls = []

    # Static pages with priority
    static_pages = [
        ("/", "1.0", "weekly"),
        ("/browse/", "0.9", "weekly"),
        ("/methodology/", "0.7", "monthly"),
        ("/research-questions/", "0.7", "weekly"),
        ("/findings/", "0.8", "monthly"),
        ("/recent/", "0.8", "daily"),
        ("/submit/", "0.6", "monthly"),
        ("/workbench/", "0.6", "monthly"),
        ("/vic-workbench/", "0.5", "monthly"),
        ("/cylinder-viewer/", "0.5", "monthly"),
        ("/faq/", "0.4", "monthly"),
        ("/about-kryptos/", "0.5", "monthly"),
        ("/archive/", "0.7", "monthly"),
        ("/encoding-chart/", "0.7", "monthly"),
        ("/challenge/", "0.7", "weekly"),
        ("/about-me/", "0.3", "monthly"),
        ("/terms/", "0.1", "yearly"),
        ("/privacy/", "0.2", "yearly"),
    ]
    for path, priority, freq in static_pages:
        urls.append(f'  <url>\n    <loc>{base}{path}</loc>\n'
                     f'    <changefreq>{freq}</changefreq>\n'
                     f'    <priority>{priority}</priority>\n  </url>')

    # Category pages
    for cat_name in tree:
        urls.append(f'  <url>\n    <loc>{base}/browse/{cat_name}/</loc>\n'
                     f'    <changefreq>weekly</changefreq>\n'
                     f'    <priority>0.7</priority>\n  </url>')

    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           + '\n'.join(urls) + '\n</urlset>\n')

    with open(os.path.join(output_dir, "sitemap.xml"), "w") as f:
        f.write(xml)


if __name__ == "__main__":
    build()
