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

    # Plain-English summary for non-technical readers
    plain_summary: str = ""

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


def _normalize_verdict(raw: str) -> str:
    """Normalize a verdict string to the canonical set.

    Canonical verdicts: NOISE, ELIMINATED, INTERESTING, SIGNAL, FULL MATCH.
    Everything else is mapped based on the score or intent.
    """
    if not raw:
        return "NOISE"
    if not isinstance(raw, str):
        return "NOISE"
    v = raw.strip().upper()

    # Already canonical
    if v in ("NOISE", "ELIMINATED", "INTERESTING", "SIGNAL", "FULL MATCH"):
        return v

    # Map known non-standard verdicts
    noise_like = {
        "ALL NOISE", "DISPROVED", "TESTED", "TOOL", "NOISE + TOOL",
        "WEAK", "ELEVATED_NOISE", "NEAR_MISS", "LIKELY_OPEN", "OPEN",
        "FEASIBLE_BUT_WEAK", "UNDERDETERMINED", "PROMISING", "INVESTIGATE",
        "STRUCTURALLY_ELIMINATED", "NONE",
    }
    if v in noise_like:
        if v == "STRUCTURALLY_ELIMINATED":
            return "ELIMINATED"
        return "NOISE"

    # "Score X at noise floor" or "Best score X at noise floor"
    if "noise floor" in raw.lower() or "noise" in raw.lower():
        return "NOISE"

    # "INTERESTING (16/24)" etc.
    if v.startswith("INTERESTING"):
        return "NOISE"  # scores below 18 are noise

    # "NOISE -- 6/24" etc.
    if v.startswith("NOISE"):
        return "NOISE"

    # "ELIMINATED (...)" etc.
    if v.startswith("ELIMINATED"):
        return "ELIMINATED"

    # "38 PERIODS SURVIVE" etc. — research results, not decryption verdicts
    if "SURVIVE" in v or "PERIODS" in v:
        return "NOISE"

    # Single letters or very short strings — data parsing errors
    if len(v) <= 2:
        return "NOISE"

    # Default: treat as NOISE
    return "NOISE"


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
            verdict=_normalize_verdict(hyp.get("elimination_reason", "eliminated")),
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
            verdict=_normalize_verdict(verdict),
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
            "configs_tested", "best_score", "plain_summary",
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
    overrides_path = os.path.join(project_root, "ops", "site_builder", "overrides.toml")
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

    # 10) Humanize raw script-name titles for public display
    for elim in site_elims:
        elim.title = _humanize_title(elim)

    # Note: plain-English summaries are generated AFTER categorization in build.py
    # (since they depend on category/subcategory assignments)

    total = len(site_elims)
    print(f"\nTotal eliminations loaded: {total}")
    return site_elims, rq_coverage, research_questions, tier_assignments


def _humanize_title(elim: SiteElimination) -> str:
    """Convert raw script-name titles into readable descriptions for the public site.

    Only transforms titles that look like raw IDs (e.g. E-AUTOKEY-BOOTSTRAP-00,
    BLITZ-V7/RESULTS, e_csp_p23_w15_beau_01). Titles that already contain spaces
    and lowercase words are left alone.
    """
    title = elim.title

    # If title already has a colon with human text after it, extract that part
    if ": " in title:
        prefix, human_part = title.split(": ", 1)
        # If the human part is meaningful (has spaces, mixed case), use it
        if " " in human_part and not human_part.isupper():
            return human_part[0].upper() + human_part[1:]

    # Skip titles that already look human-readable
    if " " in title and not title.isupper() and not title.startswith(("e_", "f_")):
        return title

    # Build a readable title from the description if available
    desc = elim.description or ""
    if desc and desc != title and len(desc) > 10:
        # Use description as the title (truncated sensibly)
        clean = desc.split(". ")[0]  # First sentence
        if len(clean) > 100:
            clean = clean[:97] + "..."
        return clean[0].upper() + clean[1:] if clean else title

    # Fall back to cleaning up the raw ID
    clean = title
    # Strip common prefixes
    clean = re.sub(r"^[eEfF][-_]", "", clean)
    # Strip version suffixes
    clean = re.sub(r"[-_][vV]?\d+$", "", clean)
    # Strip /RESULTS suffix
    clean = re.sub(r"/RESULTS$", "", clean, flags=re.IGNORECASE)
    # Replace separators with spaces
    clean = clean.replace("_", " ").replace("-", " ")
    # Collapse multiple spaces
    clean = re.sub(r"\s+", " ", clean).strip()
    # Title case, but preserve known acronyms
    acronyms = {"vic", "ckm", "sa", "bcl", "csp", "mcmc", "ndyahr", "ita", "otp",
                "xor", "gko", "dmpq", "tkas", "rs44"}
    words = clean.split()
    result = []
    for w in words:
        if w.lower() in acronyms:
            result.append(w.upper())
        else:
            result.append(w.capitalize())
    return " ".join(result) if result else title


# ---------------------------------------------------------------------------
# Plain-English summary generation
# ---------------------------------------------------------------------------

# Maps category/subcategory → plain-English descriptions of the cipher type
_PLAIN_CIPHER_DESCRIPTIONS: dict[str, str] = {
    # Substitution
    "vigenere": "a method that replaces each letter using a repeating keyword (Vigenère cipher)",
    "beaufort": "a method that replaces each letter using a repeating keyword with reversed arithmetic (Beaufort cipher)",
    "quagmire": "a method that uses a scrambled alphabet with a repeating keyword (Quagmire cipher)",
    "gromark-vimark": "a method that generates key numbers using Fibonacci-like sequences (Gromark/Vimark cipher)",
    "porta": "a method that uses 13 paired-letter alphabets selected by a keyword (Porta cipher)",
    "gronsfeld": "a method that uses a numeric key (digits only) to shift letters (Gronsfeld cipher)",
    "hill": "a method that encrypts groups of letters using matrix multiplication (Hill cipher)",
    "caesar-affine": "a simple letter-shifting method (Caesar/ROT cipher or affine substitution)",
    "monoalphabetic": "a method that replaces each letter with a fixed substitute (simple substitution)",
    "mixed-alphabet": "a method using a scrambled alphabet for substitution",
    "keystream-analysis": "analysis of the internal key values the cipher would need to produce",
    # Transposition
    "columnar": "a method that writes text into a grid and reads columns in a keyword-determined order (columnar transposition)",
    "double-columnar": "two rounds of columnar transposition applied back-to-back",
    "myszkowski": "a columnar transposition variant where repeated keyword letters create tied columns",
    "amsco": "a columnar transposition variant that alternates between 1 and 2 characters per cell",
    "nihilist-transposition": "a transposition variant with swapped or modified column reading",
    "rail-fence": "a method that writes text in a zigzag pattern across rows (rail fence cipher)",
    "route-cipher": "a method that writes text into a grid and reads it along a path (spiral, zigzag, etc.)",
    "turning-grille": "a method using a physical card with holes that rotates to select letters (grille cipher)",
    "grid-rotation": "a method that reads text from a grid in various rotated arrangements",
    "cyclic-affine": "simple rearrangements like shifting all letters by a fixed amount or reversing blocks",
    "reading-order": "alternative ways of reading the carved text (backwards, alternating rows, etc.)",
    "sa-optimization": "computer-optimized letter rearrangement using simulated annealing",
    # Fractionation
    "bifid": "a method that breaks letters into grid coordinates, mixes them, and reassembles (Bifid cipher)",
    "trifid": "a method that breaks letters into three-part coordinates and recombines them (Trifid cipher)",
    "adfgvx": "a WWI German cipher that converts letters to pairs of 6 symbols then transposes them (ADFGVX)",
    "playfair": "a method that encrypts pairs of letters using a 5×5 grid (Playfair cipher)",
    "two-square": "a method that encrypts letter pairs using two 5×5 grids (Two-Square cipher)",
    "four-square": "a method that encrypts letter pairs using four 5×5 grids (Four-Square cipher)",
    "polybius": "a method that converts letters to number pairs using a grid (Polybius square)",
    "straddling-checkerboard": "a method that encodes letters as variable-length digit sequences",
    # Multi-layer
    "transposition-plus-substitution": "a combined approach: scramble the letter order AND replace each letter",
    "null-extraction": "the hypothesis that some letters in the carved text are meaningless filler (nulls) inserted to disguise the real message",
    "cascade": "multiple encryption steps applied one after another",
    "three-layer": "three encryption steps: substitute, scramble, then substitute again",
    "joint-transposition": "simultaneous optimization of letter rearrangement and substitution",
    "constraint-propagation": "backward reasoning from known constraints to narrow possibilities",
    "homophonic-hybrid": "a method where each letter can be represented by multiple different symbols",
    # Key models
    "running-key": "using a passage from a book or document as the encryption key",
    "autokey": "a method where the key starts with a short word, then extends using the message itself",
    "progressive": "a key that increases by a fixed amount at each position",
    "date-derived": "a key derived from a date (like when Kryptos was built)",
    "keyword-derived": "a key derived from a thematic word or phrase",
    "fibonacci-polynomial": "a key generated by a mathematical formula (Fibonacci, polynomial, etc.)",
    "sculpture-derived": "a key derived from the physical position of letters on the sculpture",
    "thematic": "a key based on themes from the sculpture (Egypt, CIA, Berlin, etc.)",
    "k123-derived": "a key derived from the solutions to K1, K2, or K3",
    # Bespoke
    "physical-sculpture": "methods based on the physical properties of the sculpture itself",
    "nato-comsec": "military or Cold War era cipher systems (VIC, DRYAD, one-time pads, etc.)",
    "tableau-methods": "non-standard encryption tables or lookup charts",
}

# Maps category → high-level plain-English description
_PLAIN_CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "substitution": "replacing each letter with a different letter",
    "transposition": "rearranging the order of letters",
    "fractionation": "breaking letters into pieces, scrambling, and reassembling",
    "multi-layer": "combining multiple encryption methods",
    "key-models": "different ways of generating the secret key",
    "bespoke": "non-standard or physically-inspired methods",
}


def _format_count(n: int) -> str:
    """Format a large number into a readable string."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f} billion"
    elif n >= 1_000_000:
        return f"{n / 1_000_000:.1f} million"
    elif n >= 1_000:
        return f"{n / 1_000:,.0f} thousand"
    return f"{n:,}"


def _extract_specific_detail(elim: SiteElimination) -> str:
    """Extract the distinguishing detail from an elimination's title/description.

    The goal is to find what makes THIS test different from others in the same
    category — the specific texts tested, the specific parameters, the specific
    twist on the idea. Returns a lowercase phrase suitable for embedding in a
    sentence like "Specifically, we tested ___."
    """
    # Use description first (usually more detailed), fall back to title
    text = elim.description or elim.title or ""
    if not text:
        return ""

    # Clean up common prefixes that don't add information
    import re
    # Strip experiment ID prefixes like "E-FOO-01: "
    text = re.sub(r'^[Ee]-[\w-]+:\s*', '', text)
    # Strip "Running key from " — we'll provide our own framing
    text = re.sub(r'^Running key from\s+', '', text, flags=re.IGNORECASE)

    # If the remaining text is very short or matches title exactly, use title
    if len(text) < 5:
        text = elim.title or ""
        text = re.sub(r'^[Ee]-[\w-]+:\s*', '', text)

    # Truncate to first sentence if long
    first_sentence = text.split('. ')[0].split('; ')[0]
    if len(first_sentence) > 200:
        first_sentence = first_sentence[:197] + "..."

    return first_sentence.strip().rstrip('.')


def _generate_plain_summary(elim: SiteElimination) -> str:
    """Generate a plain-English summary from the technical fields of an elimination.

    Produces 1-3 sentences that a non-cryptographer can understand, covering:
    - What SPECIFICALLY was tested (from title/description, not just category)
    - The technique category (in plain language) for context
    - How thoroughly and what the result was
    """
    parts = []

    # 1. What SPECIFICALLY was tested — the distinguishing detail
    specific = _extract_specific_detail(elim)

    # Get the category-level technique description for context
    technique = ""
    if elim.subcategory:
        technique = _PLAIN_CIPHER_DESCRIPTIONS.get(elim.subcategory, "")
    if not technique and elim.category:
        cat_desc = _PLAIN_CATEGORY_DESCRIPTIONS.get(elim.category, "")
        if cat_desc:
            technique = f"a method based on {cat_desc}"

    # Build the opening sentence combining specifics + technique
    if specific and technique:
        # Specific detail exists — lead with it, add technique as context
        # Avoid "using using" when technique already starts with "using"
        connector = "—" if technique.startswith("using") else "— using"
        parts.append(f"{specific} {connector} {technique}.")
    elif specific:
        # Only specifics, no technique mapping
        parts.append(f"{specific}.")
    elif technique:
        # Only technique, no specifics — generic fallback
        parts.append(f"We tested {technique}.")
    elif elim.cipher_type:
        parts.append(f"We tested {elim.cipher_type}.")
    else:
        parts.append("We tested this encryption approach.")

    # 2. How thoroughly + result combined
    if elim.configs_tested > 0:
        count_str = _format_count(elim.configs_tested)

        if elim.confidence_tier == 1:
            parts.append("Mathematically proven impossible — no key or setting can make it work.")
        elif elim.confidence_tier == 2:
            parts.append(f"Every possible combination was tested ({count_str} configurations) — none produced a valid solution.")
        else:
            parts.append(f"{count_str} key/parameter combinations were tested.")

    elif elim.confidence_tier == 1:
        parts.append("Mathematically proven impossible — no key or setting can make it work.")

    # 3. Score context (only if it adds useful info)
    if elim.best_score is not None and elim.best_score > 0:
        if elim.best_score >= 24:
            parts.append("The best result matched all 24 known letters — under investigation.")
        elif elim.best_score >= 18:
            parts.append(
                f"Best match: {elim.best_score}/24 known letters "
                f"(statistically expected at this key length, not a real signal)."
            )
        elif elim.best_score >= 10:
            parts.append(
                f"Best match: {elim.best_score}/24 known letters — "
                f"slightly above random, almost certainly coincidence."
            )
        # Skip mentioning low scores — "no better than random" is obvious
        # and just adds noise to the summary

    return " ".join(parts)


def generate_all_plain_summaries(eliminations: list[SiteElimination]) -> None:
    """Generate plain-English summaries for all eliminations that don't already have one."""
    for elim in eliminations:
        if not elim.plain_summary:
            elim.plain_summary = _generate_plain_summary(elim)
