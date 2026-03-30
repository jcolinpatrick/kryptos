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
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_project_root, "src"))
sys.path.insert(0, _project_root)

from ops.site_builder.data_loader import load_all, SiteElimination
from ops.site_builder.categorizer import categorize_all, get_category_stats
from ops.site_builder.search_index import write_search_index


# --- Configuration ---

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "site")

# Category descriptions for browse pages
CATEGORY_DESCRIPTIONS = {
    "substitution": "Methods that replace each letter with a different letter using a key or pattern, like a secret alphabet. Includes Vigen\u00e8re, Beaufort, Quagmire, Hill, and more.",
    "transposition": "Methods that scramble the order of letters without changing them, like writing a message into a grid and reading it back in a different order. Includes columnar, rail fence, route, and grille ciphers.",
    "fractionation": "Methods that break each letter into smaller pieces (like grid coordinates), scramble those pieces, then reassemble them into new letters. Includes Bifid, Playfair, Four-Square, and ADFGVX.",
    "multi-layer": "Combined approaches that stack multiple encryption steps. For example, replacing letters first, then scrambling their order. Includes null extraction, cascaded layers, and joint optimization.",
    "key-models": "Different ways to generate the secret key: from a passage in a book, from a date, from a mathematical formula, or from the sculpture itself. Includes running keys, autokey, and keyword-derived approaches.",
    "bespoke": "Non-standard methods inspired by the physical sculpture or military cipher systems. These approaches don't fit neatly into classical categories. Includes DRYAD charts, Morse code analysis, and coordinate-based approaches.",
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

    # Global context available to all templates
    global_ctx = {
        "total_configs_disproven": total_configs_disproven,
    }

    # 6) Prepare output directory
    #    Preserve stats/ (GoAccess) and static/ (avoid transient 404s for
    #    fonts/CSS/JS while HTML pages are being regenerated — static assets
    #    are overwritten in step 10 anyway).
    if os.path.exists(OUTPUT_DIR):
        for entry in os.listdir(OUTPUT_DIR):
            if entry in ("stats", "static"):
                continue
            entry_path = os.path.join(OUTPUT_DIR, entry)
            if os.path.isdir(entry_path):
                shutil.rmtree(entry_path)
            else:
                os.remove(entry_path)

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

    # Submit
    _render(env, "submit.html", "submit/index.html", {
        **global_ctx,
        "total_experiments": total_experiments,
    })
    pages_built += 1

    # Submission Status
    _render(env, "status.html", "status/index.html", global_ctx)
    pages_built += 1

    # Methodology
    try:
        from kryptos.kernel.constants import CT
    except ImportError:
        CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

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

    # Polybius Walk Viewer (standalone → CSP-compliant with site chrome)
    _build_standalone_viewer(
        src_name="polybius_walk.html",
        out_slug="polybius-walk",
        title="Polybius Grid Walk | kryptosbot.com",
        css_file="polybius_walk.css",
        js_file="polybius_walk.js",
        page_class="pw-page",
        global_ctx=global_ctx,
    )
    pages_built += 1

    # K3 Jefferson Viewer (standalone → CSP-compliant with site chrome)
    _build_standalone_viewer(
        src_name="k3_jefferson_viewer.html",
        out_slug="k3-jefferson-viewer",
        title="K3 Jefferson Viewer | kryptosbot.com",
        css_file="k3_jefferson_viewer.css",
        js_file="k3_jefferson_viewer.js",
        page_class="jv-page",
        global_ctx=global_ctx,
    )
    pages_built += 1

    # Archive Research Photos
    _render(env, "archive.html", "archive/index.html", global_ctx)
    pages_built += 1

    # Report error
    _render(env, "report_error.html", "report-error/index.html", global_ctx)
    pages_built += 1

    # 404 page (at root for nginx error_page directive)
    _render(env, "404.html", "404.html", global_ctx)
    pages_built += 1

    # Search
    _render(env, "search.html", "search/index.html", global_ctx)
    pages_built += 1

    # Terms of Use
    _render(env, "terms.html", "terms/index.html", global_ctx)
    pages_built += 1

    # 9) Generate search index
    search_index_path = os.path.join(OUTPUT_DIR, "search-index.json")
    n_indexed = write_search_index(eliminations, search_index_path)
    print(f"\n  Search index: {n_indexed} documents → {search_index_path}")

    # 9b) Generate sitemap.xml
    _write_sitemap(eliminations, tree, OUTPUT_DIR)
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

    # 11) Summary
    print("\n" + "=" * 60)
    print(f"BUILD COMPLETE")
    print(f"  Pages built: {pages_built}")
    print(f"  Eliminations: {len(eliminations)}")
    print(f"  Output directory: {OUTPUT_DIR}")
    print(f"  Total configs disproven: {total_configs_disproven}")
    print("=" * 60)


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
  <link rel="icon" type="image/webp" href="/static/kryptosbot.webp">
  <link rel="stylesheet" href="/static/fonts/fonts.css">
  <link rel="stylesheet" href="/static/style.css">
  <link rel="stylesheet" href="/static/{css_file}">
  <title>{title}</title>
</head>
<body>
  <div class="disproven-banner">
    <span class="disproven-count">{counter}</span>
    <span class="disproven-label">configurations tested and eliminated</span>
  </div>

  <nav>
    <ul>
      <li><strong><a href="/" class="nav-brand"><img src="/static/kryptosbot.webp" alt="" class="nav-logo">kryptosbot</a></strong></li>
    </ul>
    <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Toggle navigation">
    <label for="nav-toggle" class="nav-toggle-label" aria-hidden="true">
      <span></span><span></span><span></span>
    </label>
    <ul class="nav-links">
      <li><a href="/findings/">Findings</a></li>
      <li><a href="/browse/">Eliminations</a></li>
      <li><a href="/methodology/">How We Test</a></li>
      <li><a href="/research-questions/">Open Questions</a></li>
      <li class="nav-group">
        <a href="/workbench/" class="nav-group-label">Tools</a>
        <ul class="nav-dropdown">
          <li><a href="/workbench/">Cipher Workbench</a></li>
          <li><a href="/vic-workbench/">VIC Cipher</a></li>
          <li><a href="/cylinder-viewer/">Cylinder Viewer</a></li>
          <li><a href="/polybius-walk/">Polybius Walk</a></li>
          <li><a href="/k3-jefferson-viewer/">K3 Jefferson</a></li>
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
      &middot; <a href="mailto:contact@kryptosbot.com">Contact</a>
      &middot; <a href="/report-error/">Report error</a>
    </p>
    <p><small>Not affiliated with the CIA, Jim Sanborn, Ed Scheidt, or the Kryptos Keepers. This site does not know the solution.</small></p>
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

    src_html = os.path.join(PROJECT_ROOT, "reference", "tools", "cylinder_viewer.html")
    with open(src_html) as f:
        html = f.read()

    # -- 1. Replace <head> internals: add site stylesheets before the inline <style>
    site_head = (
        '<meta name="description" content="kryptosbot.com | The K4 Elimination Database.">\n'
        '<link rel="stylesheet" href="/static/fonts/fonts.css">\n'
        '<link rel="stylesheet" href="/static/style.css">\n'
        '<link rel="icon" href="/favicon.ico" sizes="any">\n'
        '<link rel="icon" type="image/webp" href="/static/kryptosbot.webp">\n'
    )
    html = html.replace('<title>Kryptos Cylinder Viewer</title>', f'<title>Cylinder Viewer | kryptosbot.com</title>\n{site_head}', 1)

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

    # -- 2b. Remove the legend (color key) — static swatches look like broken checkboxes
    legend_start = html.find('<div class="legend">')
    if legend_start != -1:
        # Find the closing </div> that ends the legend block
        # Structure: <div class="legend"> ... 3x <div class="legend-item">...</div> ... </div>
        # Count div open/close to find the matching end
        depth = 0
        i = legend_start
        while i < len(html):
            if html[i:i+4] == '<div':
                depth += 1
            elif html[i:i+6] == '</div>':
                depth -= 1
                if depth == 0:
                    legend_end = i + 6
                    # Strip trailing whitespace/newline
                    while legend_end < len(html) and html[legend_end] in '\n\r':
                        legend_end += 1
                    html = html[:legend_start] + html[legend_end:]
                    break
            i += 1

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

    # -- 3. Inject banner + nav after <body>
    configs = global_ctx.get("total_configs_disproven", "")
    nav_html = f"""
  <div class="disproven-banner">
    <span class="disproven-count">{configs}</span>
    <span class="disproven-label">configurations tested and eliminated</span>
  </div>

  <nav>
    <ul>
      <li><strong><a href="/" class="nav-brand"><img src="/static/kryptosbot.webp" alt="" class="nav-logo">kryptosbot</a></strong></li>
    </ul>
    <input type="checkbox" id="nav-toggle" class="nav-toggle" aria-label="Toggle navigation">
    <label for="nav-toggle" class="nav-toggle-label" aria-hidden="true">
      <span></span><span></span><span></span>
    </label>
    <ul class="nav-links">
      <li><a href="/findings/">Findings</a></li>
      <li><a href="/browse/">Eliminations</a></li>
      <li><a href="/methodology/">How We Test</a></li>
      <li><a href="/research-questions/">Open Questions</a></li>
      <li class="nav-group">
        <a href="/workbench/" class="nav-group-label">Tools</a>
        <ul class="nav-dropdown">
          <li><a href="/workbench/">Cipher Workbench</a></li>
          <li><a href="/vic-workbench/">VIC Cipher</a></li>
          <li><a href="/cylinder-viewer/">Cylinder Viewer</a></li>
          <li><a href="/polybius-walk/">Polybius Walk</a></li>
          <li><a href="/k3-jefferson-viewer/">K3 Jefferson</a></li>
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
    html = html.replace(
        '<h1>KRYPTOS CYLINDER VIEWER</h1>',
        '<div class="cv-page">\n<h1>KRYPTOS CYLINDER VIEWER</h1>',
        1,
    )
    html = html.replace(
        '<script src="/static/cylinder_viewer.js"></script>',
        '</div>\n<script src="/static/cylinder_viewer.js"></script>',
        1,
    )

    # -- 4. Inject footer before </body>
    footer_html = """
  </main>

  <footer class="container">
    <hr>
    <p>
      Built by <a href="/about-me/">Colin Patrick</a> &amp; <a href="https://claude.ai">Claude</a>
      &middot; <a href="https://github.com/jcolinpatrick/kryptos">Source</a>
      &middot; <a href="/terms/">Terms</a>
      &middot; <a href="mailto:contact@kryptosbot.com">Contact</a>
      &middot; <a href="/report-error/">Report error</a>
    </p>
    <p><small>Not affiliated with the CIA, Jim Sanborn, Ed Scheidt, or the Kryptos Keepers. This site does not know the solution.</small></p>
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
    """Build template context for the Confirmed Findings page."""
    # Consensus null positions (17 positions where researchers agree)
    null_positions = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

    # KA Polybius grid (KRYPTOS keyword-mixed alphabet in 5 columns)
    ka = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    polybius_rows = []
    for r in range(6):
        row = []
        for c in range(5):
            idx = r * 5 + c
            if idx < len(ka):
                row.append({"letter": ka[idx], "row": r, "col": c})
        polybius_rows.append(row)

    # Stehle anomaly: positions 55-63, lag-4 difference = 5
    stehle_positions = list(range(55, 64))
    stehle_values = [ord(ct[p]) - ord('A') for p in stehle_positions]
    stehle_diffs = [(stehle_values[i] - stehle_values[i - 4]) % 26
                    for i in range(4, len(stehle_values))]

    # KRYPTOS x SEVEN lookup table
    ks_table = [
        ["?", "R", "R", "-", "N"],   # K (0)
        ["N", "N", "-", "N", "-"],   # R (1)
        ["R", "R", "N", "?", "-"],   # Y (2)
        ["R", "R", "N", "R", "N"],   # P (3)
        ["-", "R", "-", "R", "N"],   # T (4)
        ["N", "-", "?", "-", "R"],   # O (5)
        ["N", "-", "R", "R", "R"],   # S (6)
    ]
    ks_row_labels = list("KRYPTOS")

    return {
        **global_ctx,
        "ct": ct,
        "null_positions": null_positions,
        "polybius_rows": polybius_rows,
        "stehle_positions": stehle_positions,
        "stehle_values": stehle_values,
        "stehle_diffs": stehle_diffs,
        "ks_table": ks_table,
        "ks_row_labels": ks_row_labels,
    }


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


def _write_sitemap(eliminations: list, tree: dict, output_dir: str):
    """Generate sitemap.xml for search engine discovery."""
    from datetime import date

    base = "https://kryptosbot.com"
    today = date.today().isoformat()

    urls = []

    # Static pages with priority
    static_pages = [
        ("/", "1.0", "weekly"),
        ("/browse/", "0.9", "weekly"),
        ("/methodology/", "0.7", "monthly"),
        ("/research-questions/", "0.7", "weekly"),
        ("/findings/", "0.8", "monthly"),
        ("/recent/", "0.8", "daily"),
        ("/search/", "0.5", "monthly"),
        ("/submit/", "0.6", "monthly"),
        ("/status/", "0.3", "monthly"),
        ("/workbench/", "0.6", "monthly"),
        ("/vic-workbench/", "0.5", "monthly"),
        ("/cylinder-viewer/", "0.5", "monthly"),
        ("/faq/", "0.4", "monthly"),
        ("/about-kryptos/", "0.5", "monthly"),
        ("/archive/", "0.7", "monthly"),
        ("/about-me/", "0.3", "monthly"),
        ("/terms/", "0.1", "yearly"),
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

    # Elimination pages
    for e in eliminations:
        lastmod = e.date_tested[:10] if e.date_tested else today
        urls.append(f'  <url>\n    <loc>{base}/elimination/{e.slug}/</loc>\n'
                     f'    <lastmod>{lastmod}</lastmod>\n'
                     f'    <changefreq>monthly</changefreq>\n'
                     f'    <priority>0.5</priority>\n  </url>')

    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           + '\n'.join(urls) + '\n</urlset>\n')

    with open(os.path.join(output_dir, "sitemap.xml"), "w") as f:
        f.write(xml)


if __name__ == "__main__":
    build()
