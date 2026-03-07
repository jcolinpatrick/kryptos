"""Load elimination data from multiple sources and merge into SiteElimination objects."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class SiteElimination:
    """A single elimination entry for the website."""

    id: str = ""
    slug: str = ""
    title: str = ""
    description: str = ""
    category: str = "uncategorized"
    subcategory: str = ""
    tags: list[str] = field(default_factory=list)
    cipher_type: str = ""
    period_range: str = ""
    key_model: str = ""
    transposition_family: str = ""
    alphabet: str = ""
    configs_tested: int = 0
    best_score: int = 0
    expected_random: float = 0.0
    bean_passed: bool = False
    verdict: str = ""
    confidence_tier: int = 0
    scope_limitations: str = ""
    assumptions: str = ""
    repro_command: str = ""
    truth_tag: str = ""
    artifact_path: str = ""
    date_tested: str = ""
    experiment_script: str = ""
    research_questions: list[str] = field(default_factory=list)
    github_issue_url: str = ""

    # Searchable keywords tested in this experiment
    keywords_tested: list[str] = field(default_factory=list)

    # Extra fields from results JSON (unstructured)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("extra", None)
        return d


@dataclass
class RQCoverage:
    """Research question coverage from the novelty ledger."""

    research_question: str = ""
    total_hypotheses: int = 0
    eliminated: int = 0
    survived: int = 0
    promoted: int = 0


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")[:80]


def load_hypotheses_from_db(db_path: str) -> list[dict[str, Any]]:
    """Load hypotheses from the novelty_ledger.sqlite database."""
    if not os.path.exists(db_path):
        print(f"  [WARN] DB not found: {db_path}")
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT hypothesis_id, description, status, transform_stack, "
            "research_questions, assumptions, triage_score, elimination_reason, "
            "tags, created_at, updated_at FROM hypotheses"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"  [WARN] Failed to load hypotheses from {db_path}: {e}")
        return []


def load_eliminations_from_db(db_path: str) -> list[dict[str, Any]]:
    """Load eliminations from the novelty_ledger.sqlite database."""
    if not os.path.exists(db_path):
        print(f"  [WARN] DB not found: {db_path}")
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, experiment_id, hypothesis, configs_tested, best_score, "
            "verdict, evidence, timestamp FROM eliminations"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"  [WARN] Failed to load eliminations from {db_path}: {e}")
        return []


def load_rq_coverage(db_path: str) -> list[RQCoverage]:
    """Load research question coverage from the novelty_ledger.sqlite database."""
    if not os.path.exists(db_path):
        print(f"  [WARN] DB not found: {db_path}")
        return []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT research_question, total_hypotheses, eliminated, survived, promoted "
            "FROM rq_coverage ORDER BY research_question"
        ).fetchall()
        conn.close()
        return [
            RQCoverage(
                research_question=r["research_question"],
                total_hypotheses=r["total_hypotheses"],
                eliminated=r["eliminated"],
                survived=r["survived"],
                promoted=r["promoted"],
            )
            for r in rows
        ]
    except Exception as e:
        print(f"  [WARN] Failed to load rq_coverage from {db_path}: {e}")
        return []


def load_results_json(results_dir: str) -> list[dict[str, Any]]:
    """Load all JSON result files from the results directory.

    Scans both top-level .json files and results.json inside immediate
    subdirectories (e.g. results/tableau_keystream/results.json).
    """
    results = []
    if not os.path.isdir(results_dir):
        print(f"  [WARN] Results directory not found: {results_dir}")
        return results
    for entry in sorted(os.listdir(results_dir)):
        entry_path = os.path.join(results_dir, entry)
        if os.path.isfile(entry_path) and entry.endswith(".json"):
            try:
                with open(entry_path) as f:
                    data = json.load(f)
                data["_source_file"] = entry
                results.append(data)
            except Exception as e:
                print(f"  [WARN] Failed to load {entry_path}: {e}")
        elif os.path.isdir(entry_path):
            # Check for results.json inside subdirectory
            sub_results = os.path.join(entry_path, "results.json")
            if os.path.isfile(sub_results):
                try:
                    with open(sub_results) as f:
                        data = json.load(f)
                    data["_source_file"] = f"{entry}/results.json"
                    results.append(data)
                except Exception as e:
                    print(f"  [WARN] Failed to load {sub_results}: {e}")
    return results


def load_overrides(overrides_path: str) -> dict[str, dict[str, Any]]:
    """Load manual overrides from a TOML file. Returns dict keyed by elimination ID."""
    if not os.path.exists(overrides_path):
        print(f"  [WARN] Overrides file not found: {overrides_path}")
        return {}
    try:
        with open(overrides_path, "rb") as f:
            data = tomllib.load(f)
        return data.get("elimination", {})
    except Exception as e:
        print(f"  [WARN] Failed to load overrides from {overrides_path}: {e}")
        return {}


def _parse_tags(raw: str | list | None) -> list[str]:
    """Parse tags from DB string (JSON list) or list."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(t) for t in parsed]
    except (json.JSONDecodeError, TypeError):
        pass
    return [t.strip() for t in str(raw).split(",") if t.strip()]


def _parse_research_questions(raw: str | list | None) -> list[str]:
    """Parse research questions from DB string."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(rq) for rq in parsed]
    except (json.JSONDecodeError, TypeError):
        pass
    # Try comma-separated
    return [rq.strip() for rq in str(raw).split(",") if rq.strip()]


def _extract_keywords(res: dict[str, Any]) -> list[str]:
    """Extract tested keyword names from a results JSON dict.

    Scans structured fields (keyword, keyword_results, new_keywords_list,
    top_results labels) and the key_finding narrative for uppercase keyword
    mentions.
    """
    kws: set[str] = set()

    # 1) Explicit keyword field
    kw = res.get("keyword")
    if isinstance(kw, str) and kw.strip():
        kws.add(kw.strip().upper())

    # 2) keyword_results list (e.g. e_kasiski_00)
    kr = res.get("keyword_results")
    if isinstance(kr, list):
        for entry in kr:
            if isinstance(entry, dict):
                k = entry.get("keyword", "")
                if isinstance(k, str) and k.strip():
                    kws.add(k.strip().upper())

    # 3) new_keywords_list (e.g. e_poly_03)
    nkl = res.get("new_keywords_list")
    if isinstance(nkl, list):
        for k in nkl:
            if isinstance(k, str) and k.strip():
                kws.add(k.strip().upper())

    # 4) top_results labels containing "kw-" (e.g. tableau_keystream)
    tr = res.get("top_results")
    if isinstance(tr, list):
        for entry in tr:
            if isinstance(entry, dict):
                lbl = entry.get("label", "")
                if "kw-" in lbl:
                    parts = lbl.split("kw-")
                    if len(parts) > 1:
                        kw_name = parts[1].split("-")[0].strip()
                        if kw_name:
                            kws.add(kw_name.upper())

    # 5) Scan key_finding / description for well-known thematic keywords
    _THEMATIC = {
        "URANIA", "WELTZEITUHR", "ALEXANDERPLATZ", "HOROLOGE",
        "PALIMPSEST", "ABSCISSA", "KRYPTOS", "BERLINCLOCK",
        "EASTNORTHEAST", "SANBORN", "SCHEIDT", "VERDIGRIS",
        "LODESTONE", "COMPASS", "SHADOW", "SPHINX", "PHARAOH",
        "TUTANKHAMUN", "CARNARVON", "DRUSILLA", "IDBYROWS",
        "DESPARATLY", "IQLUSION", "DIGETAL", "PARALLAX",
        "COLOPHON", "DEFECTOR", "MAGNETIC", "ANTIPODES",
        "UNDERGRUUND", "GROMARK",
    }
    for field in ("key_finding", "key_findings", "description"):
        val = res.get(field)
        if isinstance(val, str):
            upper = val.upper()
            for tk in _THEMATIC:
                if tk in upper:
                    kws.add(tk)
        elif isinstance(val, list):
            combined = " ".join(str(v) for v in val).upper()
            for tk in _THEMATIC:
                if tk in combined:
                    kws.add(tk)

    return sorted(kws)


def _detect_experiment_script(experiment_id: str, scripts_dir: str) -> str:
    """Try to find the experiment script file for an experiment ID.

    Recursively searches subdirectories under scripts_dir.
    """
    if not experiment_id:
        return ""
    # Normalize: E-CHART-01 -> e_chart_01
    normalized = experiment_id.lower().replace("-", "_")
    if not os.path.isdir(scripts_dir):
        return ""
    for dirpath, _dirnames, filenames in os.walk(scripts_dir):
        for fname in filenames:
            if fname.endswith(".py") and normalized in fname.replace("-", "_"):
                # Return path relative to project root
                full = os.path.join(dirpath, fname)
                try:
                    rel = os.path.relpath(full, os.path.dirname(scripts_dir))
                except ValueError:
                    rel = full
                return rel
    return ""


def build_eliminations_from_hypotheses(
    hypotheses: list[dict[str, Any]],
    results_by_id: dict[str, dict[str, Any]],
    overrides: dict[str, dict[str, Any]],
    scripts_dir: str,
) -> list[SiteElimination]:
    """Convert DB hypotheses + results JSON into SiteElimination objects."""
    elims: list[SiteElimination] = []

    for hyp in hypotheses:
        if hyp.get("status") != "eliminated":
            continue

        hyp_id = hyp.get("hypothesis_id", "")
        desc = hyp.get("description", "")
        tags = _parse_tags(hyp.get("tags"))
        rqs = _parse_research_questions(hyp.get("research_questions"))

        elim = SiteElimination(
            id=hyp_id,
            slug=_slugify(desc[:60] if desc else hyp_id),
            title=desc[:120] if desc else hyp_id,
            description=desc,
            tags=tags,
            research_questions=rqs,
            verdict=hyp.get("elimination_reason", "eliminated"),
            assumptions=hyp.get("assumptions", "") or "",
            date_tested=hyp.get("updated_at", hyp.get("created_at", "")),
        )

        # Parse transform_stack for cipher_type
        ts_raw = hyp.get("transform_stack", "")
        if ts_raw:
            try:
                ts = json.loads(ts_raw) if isinstance(ts_raw, str) else ts_raw
                if isinstance(ts, list) and ts:
                    elim.cipher_type = ts[0].get("type", "")
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass

        elims.append(elim)

    return elims


def _extract_best_score(res: dict[str, Any]) -> int:
    """Extract best score from a results JSON, handling nested structures.

    If an explicit `best_score` integer is present at the top level, it is
    treated as authoritative (manually curated) and returned immediately.
    Otherwise, heuristic extraction is used across nested structures.
    """
    # Authoritative: explicit best_score integer takes priority
    explicit = res.get("best_score")
    if isinstance(explicit, int):
        return explicit

    best = 0

    # 1) Top-level score fields (excluding best_score, already checked)
    for key in ("best_cribs", "global_best_score", "max_score",
                "phase1_best", "overall_best"):
        val = res.get(key)
        if isinstance(val, (int, float)) and val > best:
            best = int(val)

    # 2) Nested dict fields with score/matches
    for key in ("global_best", "best_config", "mc_best", "ct_feedback_best",
                "direct_best", "targeted_best"):
        val = res.get(key)
        if isinstance(val, dict):
            for score_key in ("score", "matches", "best_score", "cribs"):
                s = val.get(score_key)
                if isinstance(s, (int, float)) and s > best:
                    best = int(s)

    # 3) Grouped results (best_by_type, best_by_family, etc.)
    for key in ("best_by_type", "best_by_family", "best_by_variant"):
        val = res.get(key)
        if isinstance(val, dict):
            for group_data in val.values():
                if isinstance(group_data, dict):
                    for score_key in ("score", "matches", "best_score"):
                        s = group_data.get(score_key)
                        if isinstance(s, (int, float)) and s > best:
                            best = int(s)

    # 4) Top results lists
    for key in ("top_results", "top_20", "top_10", "top_hits"):
        val = res.get(key)
        if isinstance(val, list) and val:
            first = val[0]
            if isinstance(first, dict):
                for score_key in ("score", "matches", "cribs"):
                    s = first.get(score_key)
                    if isinstance(s, (int, float)) and s > best:
                        best = int(s)

    # 5) Score distribution keys (e.g. {"15": 2, "14": 29})
    dist = res.get("score_distribution")
    if isinstance(dist, dict):
        for k in dist:
            try:
                s = int(k)
                if s > best:
                    best = s
            except (ValueError, TypeError):
                pass

    # 6) Phase-level scores
    phases = res.get("phases", {})
    if isinstance(phases, dict):
        for phase_data in phases.values():
            if isinstance(phase_data, dict):
                for score_key in ("best_score", "best_cribs"):
                    s = phase_data.get(score_key)
                    if isinstance(s, (int, float)) and s > best:
                        best = int(s)

    return best


def build_eliminations_from_results(
    results: list[dict[str, Any]],
    existing_ids: set[str],
    overrides: dict[str, dict[str, Any]],
    scripts_dir: str,
) -> list[SiteElimination]:
    """Build SiteElimination objects from results JSON files not already in DB."""
    elims: list[SiteElimination] = []

    for res in results:
        exp_id = res.get("experiment", res.get("experiment_id", ""))
        if not exp_id:
            # Try to derive from filename
            fname = res.get("_source_file", "")
            if fname:
                exp_id = fname.replace(".json", "").upper().replace("_", "-")

        if not exp_id:
            continue

        # Skip checkpoint files
        if "checkpoint" in res.get("_source_file", "").lower():
            continue

        desc = res.get("description", res.get("hypothesis", ""))
        verdict = res.get("verdict", res.get("classification", ""))

        # Extract score fields — check top-level and nested structures
        best_score = _extract_best_score(res)

        configs_tested = 0
        for key in ("total_configs", "total_tests", "total_tested", "total_keys",
                     "n_configs", "n_tested", "configs_tested"):
            val = res.get(key)
            if isinstance(val, (int, float)) and val > configs_tested:
                configs_tested = int(val)

        script = _detect_experiment_script(exp_id, scripts_dir)
        repro_cmd = res.get("repro_command", res.get("repro", ""))
        if not repro_cmd and script:
            repro_cmd = f"PYTHONPATH=src python3 -u {script}"

        elim = SiteElimination(
            id=exp_id,
            slug=_slugify(exp_id + "-" + (desc[:40] if desc else "")),
            title=f"{exp_id}: {desc}" if desc else exp_id,
            description=desc or "",
            configs_tested=configs_tested,
            best_score=best_score,
            verdict=verdict or "NOISE",
            date_tested=res.get("timestamp", ""),
            experiment_script=script,
            repro_command=repro_cmd if isinstance(repro_cmd, str) else "",
            extra={
                k: v
                for k, v in res.items()
                if k not in ("experiment", "experiment_id", "description",
                             "hypothesis", "verdict", "classification",
                             "_source_file")
            },
        )

        # Try to extract tags from known fields
        tags = []
        if "sources" in res:
            tags.append("running_key")
        if "period" in res or "periods" in res:
            tags.append("periodic")
        if "width" in res or "widths_tested" in res:
            tags.append("transposition")
        elim.tags = tags

        # Extract tested keywords for search
        elim.keywords_tested = _extract_keywords(res)

        elims.append(elim)

    return elims


def apply_overrides(
    eliminations: list[SiteElimination],
    overrides: dict[str, dict[str, Any]],
) -> None:
    """Apply manual overrides from overrides.toml onto SiteElimination objects."""
    for elim in eliminations:
        ovr = overrides.get(elim.id)
        if not ovr:
            continue

        for attr in (
            "title", "description", "category", "subcategory", "cipher_type",
            "period_range", "key_model", "transposition_family", "alphabet",
            "confidence_tier", "scope_limitations", "assumptions",
            "repro_command", "truth_tag", "verdict",
            "configs_tested", "best_score",
        ):
            if attr in ovr:
                setattr(elim, attr, ovr[attr])

        if "tags" in ovr:
            # Merge, don't replace
            existing = set(elim.tags)
            for t in ovr["tags"]:
                existing.add(t)
            elim.tags = sorted(existing)

        if "keywords_tested" in ovr:
            existing = set(elim.keywords_tested)
            for k in ovr["keywords_tested"]:
                existing.add(k.upper())
            elim.keywords_tested = sorted(existing)

        if "research_questions" in ovr:
            elim.research_questions = ovr["research_questions"]


def parse_elimination_tiers(doc_path: str) -> dict[str, int]:
    """Parse docs/elimination_tiers.md to extract tier assignments.

    Returns a dict mapping cipher family name -> tier number (1-4).
    """
    tiers: dict[str, int] = {}
    if not os.path.exists(doc_path):
        print(f"  [WARN] Tiers doc not found: {doc_path}")
        return tiers

    current_tier = 0
    with open(doc_path) as f:
        for line in f:
            # Detect tier headers
            m = re.match(r"^## Tier (\d):", line)
            if m:
                current_tier = int(m.group(1))
                continue
            # Table rows: | Family | ...
            if current_tier > 0 and line.startswith("|") and not line.startswith("|--"):
                cols = [c.strip() for c in line.split("|")]
                if len(cols) >= 3:
                    family = cols[1].strip()
                    # Skip header rows
                    if family and family not in ("Proof", "Family", "Hypothesis", "Claimed Signal"):
                        # Clean strikethrough
                        family = re.sub(r"~~([^~]+)~~", r"\1", family)
                        family = family.strip("* ")
                        if family:
                            tiers[family] = current_tier

    return tiers


def parse_research_questions(doc_path: str) -> list[dict[str, str]]:
    """Parse docs/research_questions.md into structured RQ entries."""
    rqs: list[dict[str, str]] = []
    if not os.path.exists(doc_path):
        print(f"  [WARN] RQ doc not found: {doc_path}")
        return rqs

    with open(doc_path) as f:
        content = f.read()

    # Split on ### RQ- headers
    parts = re.split(r"### (RQ-\d+):", content)
    for i in range(1, len(parts) - 1, 2):
        rq_id = parts[i].strip()
        body = parts[i + 1].strip()

        # Extract title (first line)
        lines = body.split("\n")
        title = lines[0].strip() if lines else ""

        # Extract current state
        state_match = re.search(
            r"\*\*Current state\*\*:\s*(.+?)(?=\n\n|\n\*\*|\Z)",
            body,
            re.DOTALL,
        )
        current_state = state_match.group(1).strip() if state_match else ""

        rqs.append({
            "id": rq_id,
            "title": title,
            "body": body,
            "current_state": current_state,
        })

    return rqs


def load_all(
    project_root: str,
) -> tuple[list[SiteElimination], list[RQCoverage], list[dict[str, str]], dict[str, int]]:
    """Load all data sources and return merged SiteElimination objects.

    Returns:
        (eliminations, rq_coverage, research_questions, tier_assignments)
    """
    db_path = os.path.join(project_root, "db", "novelty_ledger.sqlite")
    results_dir = os.path.join(project_root, "results")
    overrides_path = os.path.join(project_root, "site_builder", "overrides.toml")
    scripts_dir = os.path.join(project_root, "scripts")
    tiers_doc = os.path.join(project_root, "docs", "elimination_tiers.md")
    rq_doc = os.path.join(project_root, "docs", "research_questions.md")

    print("Loading data sources...")

    # 1) Load from DB
    hypotheses = load_hypotheses_from_db(db_path)
    print(f"  Hypotheses from DB: {len(hypotheses)}")
    db_elims = load_eliminations_from_db(db_path)
    print(f"  Eliminations from DB: {len(db_elims)}")
    rq_coverage = load_rq_coverage(db_path)
    print(f"  RQ coverage entries: {len(rq_coverage)}")

    # 2) Load results JSON
    results = load_results_json(results_dir)
    print(f"  Results JSON files: {len(results)}")

    # 3) Load overrides
    overrides = load_overrides(overrides_path)
    print(f"  Manual overrides: {len(overrides)}")

    # 4) Parse docs
    tier_assignments = parse_elimination_tiers(tiers_doc)
    print(f"  Tier assignments from docs: {len(tier_assignments)}")
    research_questions = parse_research_questions(rq_doc)
    print(f"  Research questions parsed: {len(research_questions)}")

    # 5) Build SiteElimination objects from hypotheses
    site_elims = build_eliminations_from_hypotheses(
        hypotheses, {}, overrides, scripts_dir
    )
    print(f"  Eliminations from hypotheses: {len(site_elims)}")

    # 6) Build from results JSON (skip those already represented by DB)
    existing_ids = {e.id for e in site_elims}
    json_elims = build_eliminations_from_results(
        results, existing_ids, overrides, scripts_dir
    )
    site_elims.extend(json_elims)
    print(f"  Eliminations from results JSON: {len(json_elims)}")

    # 7) Apply overrides
    apply_overrides(site_elims, overrides)

    # 8) Apply tier assignments where possible
    for elim in site_elims:
        if elim.confidence_tier == 0:
            # Try to match by title keywords
            for family, tier in tier_assignments.items():
                family_lower = family.lower()
                if (
                    family_lower in elim.title.lower()
                    or family_lower in elim.description.lower()
                ):
                    elim.confidence_tier = tier
                    break

    # 9) Ensure all slugs are unique
    seen_slugs: dict[str, int] = {}
    for elim in site_elims:
        if not elim.slug:
            elim.slug = _slugify(elim.id or "unknown")
        base = elim.slug
        if base in seen_slugs:
            seen_slugs[base] += 1
            elim.slug = f"{base}-{seen_slugs[base]}"
        else:
            seen_slugs[base] = 0

    total = len(site_elims)
    print(f"\nTotal eliminations loaded: {total}")
    return site_elims, rq_coverage, research_questions, tier_assignments
