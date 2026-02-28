#!/usr/bin/env python3
"""Build the kryptosbot.com static site from databases, docs, and templates."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("ERROR: jinja2 is required. Install with: pip install jinja2")
    sys.exit(1)

# Ensure both kryptos kernel and site_builder are importable
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(_project_root, "src"))
sys.path.insert(0, _project_root)

from site_builder.data_loader import load_all, SiteElimination
from site_builder.categorizer import categorize_all, get_category_stats
from site_builder.search_index import write_search_index


# --- Configuration ---

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "site")

# Category descriptions for browse pages
CATEGORY_DESCRIPTIONS = {
    "substitution": "Classical substitution ciphers that replace plaintext letters using alphabetic mappings — Vigenere, Beaufort, Quagmire, Hill, and more.",
    "transposition": "Ciphers that rearrange letter positions — columnar, double columnar, Myszkowski, AMSCO, rail fence, route ciphers, turning grilles.",
    "fractionation": "Ciphers that split letters into components before rearranging — Bifid, Trifid, ADFGVX, Playfair, Two-Square, Four-Square.",
    "multi-layer": "Combined approaches using multiple cipher steps — substitution + transposition, null extraction + re-encipherment, cascaded layers.",
    "key-models": "Different key generation strategies — running keys from known texts, autokey, progressive, date-derived, keyword-derived, mathematical sequences.",
    "bespoke": "Non-standard methods inspired by the physical sculpture — DRYAD charts, NATO/COMSEC systems, Morse-derived parameters, coordinate-based approaches.",
    "uncategorized": "Eliminations not yet assigned to a specific category.",
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


def build():
    """Run the full site build pipeline."""
    print("=" * 60)
    print("kryptosbot.com — Static Site Build")
    print("=" * 60)

    # 1) Load all data
    eliminations, rq_coverage, research_questions, tier_assignments = load_all(PROJECT_ROOT)

    # 2) Categorize
    print("\nCategorizing eliminations...")
    tree = categorize_all(eliminations)
    cat_stats = get_category_stats(tree)
    print(f"  Categories: {len(tree)}")
    for cs in cat_stats:
        print(f"    {cs['display_name']}: {cs['count']} eliminations")

    # 3) Compute aggregate stats
    total_configs = sum(e.configs_tested for e in eliminations)
    total_experiments = len(eliminations)
    total_categories = len([c for c in tree if c != "uncategorized"])

    # Build the formatted disproven counter
    total_configs_disproven = format_configs(total_configs)

    print(f"\n  Total experiments: {total_experiments}")
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

    # Global context available to all templates
    global_ctx = {
        "total_configs_disproven": total_configs_disproven,
    }

    # 6) Prepare output directory
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

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
                "description": CATEGORY_DESCRIPTIONS.get(cat_name, ""),
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
            **global_ctx,
            "e": e,
        })
        pages_built += 1

    # Search
    _render(env, "search.html", "search/index.html", global_ctx)
    pages_built += 1

    # Submit
    _render(env, "submit.html", "submit/index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
    })
    pages_built += 1

    # Methodology
    try:
        from kryptos.kernel.constants import CT
    except ImportError:
        CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

    _render(env, "methodology.html", "methodology/index.html", {
        **global_ctx,
        "ct": CT,
    })
    pages_built += 1

    # FAQ
    _render(env, "faq.html", "faq/index.html", global_ctx)
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
    _render(env, "about_me.html", "about-me/index.html", global_ctx)
    pages_built += 1

    # Report error
    _render(env, "report_error.html", "report-error/index.html", global_ctx)
    pages_built += 1

    # 9) Build search index
    print("\nBuilding search index...")
    index_path = os.path.join(OUTPUT_DIR, "search-index.json")
    n_indexed = write_search_index(eliminations, index_path)
    print(f"  Indexed {n_indexed} documents → {index_path}")

    # Also copy to static dir for the search page
    static_index = os.path.join(OUTPUT_DIR, "static", "search-index.json")
    os.makedirs(os.path.dirname(static_index), exist_ok=True)
    shutil.copy2(index_path, static_index)

    # 10) Copy static assets
    print("\nCopying static assets...")
    static_out = os.path.join(OUTPUT_DIR, "static")
    os.makedirs(static_out, exist_ok=True)
    for fname in os.listdir(STATIC_DIR):
        src = os.path.join(STATIC_DIR, fname)
        dst = os.path.join(static_out, fname)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
            print(f"  {fname}")

    # 11) Summary
    print("\n" + "=" * 60)
    print(f"BUILD COMPLETE")
    print(f"  Pages built: {pages_built}")
    print(f"  Eliminations indexed: {n_indexed}")
    print(f"  Output directory: {OUTPUT_DIR}")
    print(f"  Total configs disproven: {total_configs_disproven}")
    print("=" * 60)


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


if __name__ == "__main__":
    build()
