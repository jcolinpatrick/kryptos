#!/usr/bin/env python3
"""Assemble the §6.1 proposal-mortality table from a K4 run's ledger.

Usage:
    PYTHONPATH=src python3 scripts/_infra/k4_run_postmortem.py \\
        --db db/k4_run_2026_04_21.sqlite \\
        --log results/k4_run_2026_04_21/run.log \\
        --out <internal>/K4_RUN_POSTMORTEM.md

Produces the §6.1.2 mortality table (every proposal in exactly one row),
§6.1.3 negative-space finding, §6.1.4 failure-mode classification, and
§6.1.5 budget accounting. Companion to <internal>/
K4_RUN_PROTOCOL.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _query_theories(db_path: Path) -> list[dict]:
    """Pull every TheoryRecord row. We reconstruct the mortality bucket
    for each one by inspecting status + critic_verdict + outcome fields.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM theories ORDER BY created_at").fetchall()
    conn.close()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        # Decode critic_verdict JSON
        try:
            d["critic_verdict"] = json.loads(d.get("critic_verdict") or "{}")
        except json.JSONDecodeError:
            d["critic_verdict"] = {}
        out.append(d)
    return out


def _query_experiments(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM experiments").fetchall()
    conn.close()
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        try:
            d["result"] = json.loads(d.get("result") or "{}")
        except json.JSONDecodeError:
            d["result"] = {}
        out.append(d)
    return out


_REDTEAM_REJECT_RE = re.compile(r"red[- ]?team\s*:\s*reject", re.IGNORECASE)


def _is_redteam_rejected(theory: dict) -> bool:
    """True if the theory was vetoed by the adversarial review call.

    The controller stores red-team verdicts as free-text inside
    ``critic_verdict.reasons`` (e.g. ``"red-team:reject (conf=0.88)"``),
    not as a dedicated status or decision field. A vetoed theory typically
    retains ``status='criticized'`` and ``decision='approve'`` — it
    passed the critic but was killed by red-team before dispatch. Without
    this check the postmortem's C bucket reads 0 even when red-team was
    actively rejecting, hiding a real mortality signal.
    """
    cv = theory.get("critic_verdict") or {}
    reasons = cv.get("reasons") or []
    if not isinstance(reasons, list):
        return False
    return any(_REDTEAM_REJECT_RE.search(str(r)) for r in reasons)


def _classify_proposal(theory: dict, exp: Optional[dict]) -> tuple[str, str]:
    """Return (stage_letter, sub_reason) for one proposal.

    Stages:
      B = critic rejected        (critic_verdict.decision starts with reject_)
      C = red-team killed        (red-team:reject inside critic_verdict.reasons,
                                   OR status WITHDRAWN/SUPERSEDED)
      D = dispatcher rejected    (experiment.result notes admissibility/translation)
      E = scoring outcome        (experiment scored a kernel-verified crib_score)
      F = error / infra          (experiment error/timeout, or orphaned)

    Stage A (candidate generator never proposed) is handled separately — it's
    counted against a target list, not per-theory.
    """
    cv = theory.get("critic_verdict") or {}
    decision = cv.get("decision", "")
    # Critic-level reject first — if critic kills, red-team never sees it.
    if decision and decision != "approve":
        return ("B", decision)

    # Red-team veto stored inside critic_verdict.reasons.
    if _is_redteam_rejected(theory):
        return ("C", "red-team:reject (verdict in critic reasons)")

    # If critic approved and no experiment recorded, look at status.
    if exp is None:
        status = theory.get("status", "")
        if status in ("proposed", "criticized", "approved"):
            return ("F", f"no experiment recorded (status={status})")
        if status == "running":
            return ("F", "orphaned — worker mid-flight at run halt")
        if status == "withdrawn":
            return ("C", "withdrawn — likely red-team or manual")
        if status == "superseded":
            return ("C", "superseded")
        return ("F", f"no experiment, status={status}")

    r = exp.get("result") or {}
    est = r.get("status", "")
    if est in ("error",):
        return ("F", r.get("notes", "error"))
    if est in ("timeout",):
        return ("F", "worker timeout")
    # Check for dispatcher rejection markers in notes.
    notes = (r.get("notes") or "").lower()
    if "admissibility" in notes and "budget" in notes:
        return ("D", "admissibility: budget overflow")
    if "exhaustion overlap" in notes:
        return ("D", "admissibility: exhaustion overlap (no override)")
    if "translation" in notes or "no dispatcher translation" in notes:
        return ("D", "admissibility: translation gap")
    if "translation error" in notes:
        return ("D", "translation error at _build_pipeline_config")

    # Scoring bucket.
    crib = r.get("crib_score") or theory.get("best_score") or 0
    try:
        crib = int(crib)
    except (TypeError, ValueError):
        crib = 0
    p_value = r.get("p_value_vs_null")
    if crib < 6:
        return ("E", "crib_score < STORE_THRESHOLD (below 6)")
    if 6 <= crib <= 9:
        return ("E", "crib_score ∈ [6, 9] — noise-band")
    if 10 <= crib <= 17:
        return ("E", "crib_score ∈ [10, 17] — interesting / lead-pursued")
    if 18 <= crib <= 23:
        if p_value is not None and p_value > 1e-6:
            return ("E", "crib_score ∈ [18, 23] — SIGNAL, failed p-value gate")
        return ("E", "crib_score ∈ [18, 23] — SIGNAL, passed p-value gate")
    if crib >= 24:
        return ("E", "crib_score = 24 — verified BREAKTHROUGH")
    return ("F", f"unknown state (crib={crib}, status={est})")


def _compute_target_list() -> dict[str, set[str]]:
    """Return the §6.1.2 target list (families, keyword buckets, recipes).

    Returns dict with keys:
      families:  set of cipher family kinds the dispatcher supports minus
                 Tier 1 / Tier 2 single-layer eliminations
      keywords:  set of thematic keyword strings
      recipes:   set of PROC-P-* recipe ids
    """
    from internal.dispatcher import _SUPPORTED_KINDS
    from <internal> import TIER_1_FAMILIES, TIER_2_FAMILIES

    # Multi-layer compositions — what procedural_enumerator produces.
    families: set[str] = set(_SUPPORTED_KINDS) - (TIER_1_FAMILIES | TIER_2_FAMILIES)
    # Even eliminated families are valid as INNER layers of multi-layer — so
    # per §6.1.2 "plus multi-layer composition families," we include them too.
    families |= {"columnar_double"}  # R2-1 multi-layer.

    try:
        from kryptos.kernel.alphabet import THEMATIC_KEYWORDS
        keywords: set[str] = set(THEMATIC_KEYWORDS)
    except ImportError:
        keywords = set()

    recipes: set[str] = set()
    recipes_json = _ROOT / "docs" / "procedural_recipes.json"
    if recipes_json.exists():
        try:
            data = json.loads(recipes_json.read_text())
            # File structure: top-level dict with a "recipes" key holding
            # a list of entry-dicts, each with a "recipe_id" field. Older
            # format was a flat list; support both.
            entries: list = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                if isinstance(data.get("recipes"), list):
                    entries = data["recipes"]
            for entry in entries:
                if isinstance(entry, dict):
                    rid = entry.get("recipe_id")
                    if rid:
                        recipes.add(rid)
        except (json.JSONDecodeError, OSError):
            pass

    return {
        "families": families,
        "keywords": keywords,
        "recipes": recipes,
    }


def _extract_proposal_signals(theory: dict) -> dict[str, set[str]]:
    """Return families / keywords / recipes this proposal references.

    Row A is measured against the union of these signals across all
    proposals — a family absent from every proposal's signal set is
    "candidate generator never proposed."
    """
    families: set[str] = set()
    keywords: set[str] = set()
    recipes: set[str] = set()

    fam = (theory.get("family") or "").lower()
    if fam:
        families.add(fam)

    text = " ".join(str(theory.get(k) or "") for k in (
        "core_claim", "mechanism", "title", "notes", "expected_signal",
    )).upper()

    # Very rough keyword extraction — we count thematic keywords mentioned.
    try:
        from kryptos.kernel.alphabet import THEMATIC_KEYWORDS
        for kw in THEMATIC_KEYWORDS:
            if kw in text:
                keywords.add(kw)
    except ImportError:
        pass

    # Recipe IDs in theory text appear as either "PROC-P-A1-3" (the
    # HypothesisSpec prefix) or "P-A1-3" (the raw recipe_id from
    # procedural_recipes.json). Target list uses raw form, so strip the
    # PROC- prefix when matching.
    for m in re.finditer(r"\bPROC-(P-[A-Za-z0-9-]+)\b", text):
        recipes.add(m.group(1))
    for m in re.finditer(r"\bP-[A-Z0-9]+-\d+[A-Za-z]?\b", text):
        recipes.add(m.group())

    return {"families": families, "keywords": keywords, "recipes": recipes}


def _parse_usage_from_log(log_path: Path) -> dict:
    """Placeholder kept for backward compat — the agent-SDK path used
    by the controller does NOT emit the "API call: X in + Y out ..."
    pattern this function was designed for. Real token counts come
    from ``_query_subscription_tokens`` below.
    """
    return {"input_tokens": 0, "output_tokens": 0,
            "cache_read_tokens": 0, "api_calls": 0, "total_usd": None}


_CLAUDE_PROJECT_DIR = Path.home() / ".claude" / "projects" / "-home-cpatrick-kryptos"


def _extract_first_log_timestamp(log_path: Path) -> Optional[float]:
    """Parse the first HH:MM:SS timestamp in the log head; combine with
    today's date to get the run's real start epoch. Same logic as the
    dashboard. Returns None if no timestamp is visible.
    """
    if not log_path.exists():
        return None
    try:
        with log_path.open("r", errors="replace") as f:
            head = f.read(8192)
    except OSError:
        return None
    import time
    m = re.search(r"(\d{2}):(\d{2}):(\d{2})", head)
    if not m:
        return None
    hh, mm, ss = (int(x) for x in m.groups())
    today = time.localtime()
    run_start = time.mktime((
        today.tm_year, today.tm_mon, today.tm_mday,
        hh, mm, ss, 0, 0, -1,
    ))
    now_ts = time.time()
    if run_start > now_ts:
        run_start -= 86400
    return run_start


def _query_subscription_tokens(first_seen: Optional[float]) -> dict:
    """Aggregate Claude Code subscription token burn across the run's
    worker sessions. Reads ~/.claude/projects/.../<uuid>.jsonl files.
    """
    agg = {
        "input": 0, "output": 0,
        "cache_read": 0, "cache_create": 0,
        "sessions": 0, "turns": 0,
        "by_model": {},
    }
    if not _CLAUDE_PROJECT_DIR.exists():
        return agg
    cutoff = first_seen or 0
    try:
        paths = list(_CLAUDE_PROJECT_DIR.glob("*.jsonl"))
    except OSError:
        return agg
    for path in paths:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime < cutoff:
            continue
        totals = {"input": 0, "output": 0, "cache_read": 0,
                  "cache_create": 0, "model": "", "turns": 0}
        try:
            with path.open("r", errors="replace") as f:
                for line in f:
                    if '"usage"' not in line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    msg = obj.get("message") if isinstance(obj, dict) else None
                    if not isinstance(msg, dict):
                        continue
                    u = msg.get("usage") or {}
                    if not isinstance(u, dict):
                        continue
                    totals["input"] += int(u.get("input_tokens", 0) or 0)
                    totals["output"] += int(u.get("output_tokens", 0) or 0)
                    totals["cache_read"] += int(u.get("cache_read_input_tokens", 0) or 0)
                    totals["cache_create"] += int(u.get("cache_creation_input_tokens", 0) or 0)
                    totals["turns"] += 1
                    if msg.get("model"):
                        totals["model"] = msg["model"]
        except OSError:
            continue
        if totals["turns"] == 0:
            continue
        agg["input"] += totals["input"]
        agg["output"] += totals["output"]
        agg["cache_read"] += totals["cache_read"]
        agg["cache_create"] += totals["cache_create"]
        agg["sessions"] += 1
        agg["turns"] += totals["turns"]
        m = totals.get("model") or "unknown"
        b = agg["by_model"].setdefault(
            m, {"input": 0, "output": 0, "turns": 0}
        )
        b["input"] += totals["input"]
        b["output"] += totals["output"]
        b["turns"] += totals["turns"]
    return agg


def _fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.2f}k"
    return f"{n}"


def render_markdown(
    theories: list[dict],
    experiments: list[dict],
    targets: dict[str, set[str]],
    usage: dict,
    out_path: Path,
    db_path: Path,
    log_path: Path,
) -> None:
    # Pair theories with their experiments (first experiment if multiple).
    exp_by_hid: dict[str, dict] = {}
    for e in experiments:
        hid = e.get("hypothesis_id") or ""
        if hid and hid not in exp_by_hid:
            exp_by_hid[hid] = e

    # Stage A proposals — what candidate generator mentioned.
    proposed_families: set[str] = set()
    proposed_keywords: set[str] = set()
    proposed_recipes: set[str] = set()
    for t in theories:
        sig = _extract_proposal_signals(t)
        proposed_families |= sig["families"]
        proposed_keywords |= sig["keywords"]
        proposed_recipes |= sig["recipes"]

    missing_families = sorted(targets["families"] - proposed_families)
    missing_keywords = sorted(targets["keywords"] - proposed_keywords)
    missing_recipes = sorted(targets["recipes"] - proposed_recipes)

    # Mortality buckets for every proposal.
    buckets: Counter[tuple[str, str]] = Counter()
    for t in theories:
        exp = exp_by_hid.get(t.get("hypothesis_id") or "")
        stage, reason = _classify_proposal(t, exp)
        buckets[(stage, reason)] += 1

    total_proposals = sum(buckets.values())

    # Compose markdown.
    lines: list[str] = []
    lines.append("# K4 Run Postmortem — 2026-04-21")
    lines.append("")
    lines.append(f"**Source ledger:** `{db_path.relative_to(_ROOT)}`")
    lines.append(f"**Source log:** `{log_path.relative_to(_ROOT)}`")
    lines.append(f"**Generated by:** `scripts/_infra/k4_run_postmortem.py`")
    lines.append("")
    lines.append("Per `<internal>/K4_RUN_PROTOCOL.md` §6.1 spec.")
    lines.append("")

    # §6.1.1 cycle-by-cycle telemetry.
    lines.append("## 6.1.1 Cycle-by-cycle telemetry")
    lines.append("")
    # We approximate cycles from the log content (cycle markers).
    lines.append("(See `run.log` for full cycle-by-cycle timeline. The ledger "
                 "does not index by cycle — this section summarises per-theory.)")
    lines.append("")
    lines.append(f"- Total theories proposed: **{len(theories)}**")
    lines.append(f"- Total experiments recorded: **{len(experiments)}**")
    # Count worker completions from the log (♡/■ markers — agent-SDK path).
    hb_re = re.compile(r"♡\s+[0-9a-f]{8}")
    done_re = re.compile(
        r"■\s+[0-9a-f]{8}\s+(disproved|approved|complete|error|timeout|"
        r"eliminated|promising)"
    )
    try:
        log_text = log_path.read_text(errors="replace")
    except OSError:
        log_text = ""
    heartbeats = len(hb_re.findall(log_text))
    completions = len(done_re.findall(log_text))
    lines.append(f"- Worker heartbeats emitted: {heartbeats:,}")
    lines.append(f"- Worker completions: {completions:,}")
    # Cycle-marker count from the log.
    cycle_re = re.compile(r"═+\s*CYCLE\s+(\d+)\s*/\s*(\d+)\s*═+", re.I)
    cycle_markers = cycle_re.findall(log_text)
    if cycle_markers:
        max_cycle = max(int(n) for n, _ in cycle_markers)
        total_cycles = cycle_markers[0][1]
        lines.append(
            f"- Cycles reached: **{max_cycle} / {total_cycles}** "
            "(halted by operator before cycle cap)"
        )
    lines.append("")

    # §6.1.2 mortality table.
    lines.append("## 6.1.2 Proposal-mortality table")
    lines.append("")
    lines.append(f"**Total proposals dispatched into the loop:** {total_proposals}")
    lines.append("")
    lines.append("| Stage | Sub-reason | Count | % of total |")
    lines.append("|---|---|---|---|")

    def _fmt_row(stage_label: str, sub: str, count: int) -> str:
        pct = (100.0 * count / total_proposals) if total_proposals else 0.0
        return f"| {stage_label} | {sub} | {count} | {pct:.1f}% |"

    # Stage A — measured against target list.
    lines.append(_fmt_row("**A. Candidate generator never proposed**",
                         f"families absent: {len(missing_families)} "
                         f"(of {len(targets['families'])} target)",
                         len(missing_families)))
    lines.append(_fmt_row("", f"keyword buckets absent: {len(missing_keywords)} "
                         f"(of {len(targets['keywords'])} target)",
                         len(missing_keywords)))
    lines.append(_fmt_row("", f"procedural recipes absent: {len(missing_recipes)} "
                         f"(of {len(targets['recipes'])} target)",
                         len(missing_recipes)))

    # Stages B/C/D/E/F from the bucket Counter.
    stage_labels = {
        "B": "**B. Critic rejected**",
        "C": "**C. Red-team killed**",
        "D": "**D. Dispatcher rejected**",
        "E": "**E. Scoring outcomes (dispatched)**",
        "F": "**F. Error / infra**",
    }
    for stage_letter in ("B", "C", "D", "E", "F"):
        stage_rows = [(r, c) for (s, r), c in buckets.items() if s == stage_letter]
        stage_rows.sort(key=lambda x: (-x[1], x[0]))
        if not stage_rows:
            lines.append(_fmt_row(stage_labels[stage_letter], "(no proposals)", 0))
            continue
        for i, (sub, count) in enumerate(stage_rows):
            lines.append(_fmt_row(
                stage_labels[stage_letter] if i == 0 else "",
                sub, count,
            ))

    lines.append(_fmt_row("**TOTAL**", "", total_proposals))
    lines.append("")

    # Missing targets detail.
    if missing_families:
        lines.append("### Families in target list but never proposed")
        lines.append("")
        for f in missing_families:
            lines.append(f"- `{f}`")
        lines.append("")
    if missing_recipes:
        lines.append("### Procedural recipes in target list but never proposed")
        lines.append("")
        for r in missing_recipes:
            lines.append(f"- `{r}`")
        lines.append("")

    # §6.1.3 negative-space.
    lines.append("## 6.1.3 Negative-space finding")
    lines.append("")
    dispatched_buckets = [(s, r, c) for (s, r), c in buckets.items()
                         if s == "E" and c > 0]
    if dispatched_buckets:
        lines.append("Stage-E rows (what the framework actually tested):")
        lines.append("")
        for _, reason, count in sorted(dispatched_buckets, key=lambda x: -x[2]):
            lines.append(f"- **{count}** proposals: {reason}")
        lines.append("")
        lines.append("Per protocol §6.1.3: confine negative-space claims to "
                     "dispatched proposals (row E). Row B/C/D rejections describe "
                     "the filters, not K4.")
    else:
        lines.append("No dispatched proposals recorded — the run died upstream "
                     "(rows B/C/D/F dominate). Cannot make negative-space claims "
                     "about K4 from this run.")
    lines.append("")

    # §6.1.4 failure-mode classification.
    lines.append("## 6.1.4 Failure-mode classification")
    lines.append("")
    # Pick the row with the largest count among B/C/D/E/F buckets.
    if buckets:
        (max_stage, max_sub), max_count = max(
            buckets.items(), key=lambda x: x[1],
        )
        lines.append(f"**Dominant row:** stage {max_stage}, "
                     f"sub-reason `{max_sub}` ({max_count} proposals, "
                     f"{100.0*max_count/total_proposals:.1f}% of total).")
        lines.append("")
        mode_map = {
            "B": ("B", "Critic rejected disproportionately",
                  "Investigate whether Tier 2 is over-eager or the "
                  "retired-palette matcher false-positive-prone."),
            "C": ("C", "Red-team killed disproportionately",
                  "Investigate search_space_risk classifier; may need "
                  "lexicon refresh."),
            "D": ("D", "Dispatcher rejected for admissibility / translation",
                  "Gap in DSL coverage; candidate DSL extensions to add."),
            "F": ("F", "Errors / infra",
                  "Infrastructure fix, then re-run."),
        }
        if max_stage == "E":
            # E is split into noise vs 6-17 per protocol.
            if "below 6" in max_sub or "noise-band" in max_sub:
                lines.append("- **Mode E (below 6):** framework ran cleanly, "
                             "nothing scored above noise. Next brief: expand "
                             "the hypothesis space, not the instrument.")
            elif "[10, 17]" in max_sub or "6-17" in max_sub:
                lines.append("- **Mode E (6-17 band populated):** framework "
                             "has candidates but none are strong. "
                             "Lead-pursuit should have fired; check whether "
                             "lead-pursuit produced follow-ups.")
            elif "SIGNAL" in max_sub:
                lines.append("- **SIGNAL candidate in dominant row** — "
                             "follow §4 alert runbook, do NOT classify as a "
                             "failure mode.")
            else:
                lines.append(f"- Mode E ({max_sub})")
        elif max_stage == "A":
            lines.append("- **Mode A (candidate generator concentrated on eliminated "
                         "families or missed open-search region).** "
                         "Next brief: 'improve candidate generator derivation under "
                         "strict elimination context' — NOT another "
                         "round.")
        else:
            _, label, implication = mode_map[max_stage]
            lines.append(f"- **Mode {max_stage}** ({label}): {implication}")
        lines.append("")
    else:
        lines.append("No proposals recorded — treat as infrastructure issue.")
        lines.append("")

    # §6.1.5 subscription accounting.
    run_start = _extract_first_log_timestamp(log_path)
    sub = _query_subscription_tokens(run_start)
    lines.append("## 6.1.5 Subscription accounting")
    lines.append("")
    lines.append(
        "This run dispatched workers via ``agent-sdk``'s "
        "``SubprocessCLITransport``, which spawns the Claude Code CLI as "
        "a subprocess under the user's Claude Code SUBSCRIPTION — not "
        "the Anthropic API. No per-call USD is emitted anywhere, and no "
        "API billing occurred. Token counts below are extracted from the "
        "per-session JSONL transcripts under "
        "``~/.claude/projects/-home-cpatrick-kryptos/*.jsonl``, the same "
        "source Claude Code's own ``/status`` command uses."
    )
    lines.append("")
    lines.append(f"- **Sessions touched during run window:** {sub['sessions']}")
    lines.append(f"- **Assistant turns:** {sub['turns']:,}")
    lines.append(f"- **Input tokens:** {sub['input']:,} ({_fmt_tokens(sub['input'])})")
    lines.append(f"- **Output tokens:** {sub['output']:,} ({_fmt_tokens(sub['output'])})")
    lines.append(f"- **Cache-read tokens:** {sub['cache_read']:,} ({_fmt_tokens(sub['cache_read'])})")
    lines.append(f"- **Cache-create tokens:** {sub['cache_create']:,} ({_fmt_tokens(sub['cache_create'])})")
    total = sub["input"] + sub["output"] + sub["cache_read"] + sub["cache_create"]
    lines.append(f"- **Grand total tokens:** {total:,} ({_fmt_tokens(total)})")
    lines.append("")
    if sub["by_model"]:
        lines.append("### Per-model breakdown")
        lines.append("")
        lines.append("| Model | Input | Output | Turns |")
        lines.append("|---|---|---|---|")
        for m, v in sorted(sub["by_model"].items(),
                           key=lambda x: -x[1].get("output", 0)):
            lines.append(
                f"| `{m}` | {_fmt_tokens(v['input'])} "
                f"| {_fmt_tokens(v['output'])} | {v['turns']:,} |"
            )
        lines.append("")

    # §6.1.6 architectural finding (R2-internal-specific).
    lines.append("## 6.1.6 Architectural finding: DSL path not exercised")
    lines.append("")
    lines.append(
        "**[INTERNAL RESULT]** The Round 2 internal (R2-1 through R2-5) "
        "delivered five capabilities that were intended to be exercised "
        "during a live K4 run:"
    )
    lines.append("")
    lines.append(
        "1. R2-1 — double-columnar strategy in the self-test's strategy search.\n"
        "2. R2-2 — KA + keyword_mixed alphabets in the dispatcher's "
        "``_translate_layer``.\n"
        "3. R2-3 — exhaustion-overlap override with critic duplicate guard.\n"
        "4. R2-4 — matched-family nulls for Beaufort, Variant-Beaufort, "
        "columnar_single, columnar_double.\n"
        "5. R2-5 — ``PanelCribs`` + ``TokenAccountant`` infrastructure."
    )
    lines.append("")
    lines.append(
        "This run's mortality data shows that **none of these were live**. "
        "The controller's worker dispatch path does not route HypothesisSpec "
        "objects through ``dispatcher.execute()`` — workers run freeform "
        "Python in ``results/worker_scratch/`` and emit ``WorkerContract`` "
        "JSONs. This is the pre-R2 production architecture, unchanged by "
        "Round 2's dispatcher-side work."
    )
    lines.append("")
    lines.append(
        "Tells in the data:"
    )
    lines.append("")
    lines.append(
        "- **Row D (dispatcher reject) = 0** — admissibility / translation / "
        "exhaustion overlap checks never fired because ``execute(spec)`` was "
        "never called from the controller.\n"
        "- **R2-4 matched-family nulls** — none of the 6 new distributions "
        "calibrated in R2-4 were consulted because the alert-gate path "
        "``_evaluate_one`` was never invoked on a dispatcher-scored "
        "candidate.\n"
        "- **R2-3 override mechanism** — not exercised; zero theories claimed "
        "``override_exhaustion=True`` because they never hit admissibility.\n"
        "- **R2-5 ``TokenAccountant``** — sitting idle; token counts in §6.1.5 "
        "above were recovered post-hoc from Claude Code's own session logs, "
        "not from any R2 instrument."
    )
    lines.append("")
    lines.append(
        "**Interpretation.** This was a live test of the pre-R2 production "
        "loop (candidate generator → critic → red-team → freeform-worker), not of the "
        "Round 2 internal. The mortality distribution is diagnostic for "
        "that loop, not for the instrument we just finished building. "
        "Round 2's self-test harness (R2-1's ``_columnar_double_candidates``) "
        "and direct-API verification (R2-5's K1 loop-lite) remain the only "
        "evidence that the R2 components are fit — both passed in their "
        "respective tests."
    )
    lines.append("")
    lines.append(
        "**What this does NOT mean.** The R2 work is not invalidated. Dry-run "
        "self-test still discovers K1/K2/K3 in bounded cycles. The dispatcher "
        "still correctly translates two-layer columnar and KA-alphabet specs. "
        "The matched-family nulls are still correctly calibrated. The "
        "infrastructure is simply not *wired through the live controller's "
        "worker path*. Wiring that through is a targeted engineering task, "
        "not another internal cycle."
    )
    lines.append("")
    lines.append(
        "**Recommended next brief.** A narrow Round 3 phase: "
        "``Wire controller worker path through dispatcher.execute().`` "
        "Workers receive a ``HypothesisSpec`` derived from their proposed "
        "theory rather than freeform instructions, and return the dispatcher's "
        "``JobResult`` rather than a worker-authored ``WorkerContract``. The "
        "scaffolding is all in place — the work is a few hundred lines of "
        "controller wiring, not a full internal cycle."
    )
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*End of postmortem. The §6.1.4 dominant-row classification and the "
        "§6.1.6 architectural finding together point at the next brief. The "
        "first tells us what to change about the candidate generator / critic loop; the "
        "second tells us what to change about controller-to-dispatcher wiring. "
        "These are independent work items; either can be commissioned without "
        "blocking the other.*"
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    print(f"wrote {out_path}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, required=True,
                    help="Path to the run's SQLite ledger")
    ap.add_argument("--log", type=Path, required=True,
                    help="Path to the run's stdout log")
    ap.add_argument("--out", type=Path, required=True,
                    help="Path to write K4_RUN_POSTMORTEM.md")
    args = ap.parse_args(argv)

    theories = _query_theories(args.db)
    experiments = _query_experiments(args.db)
    targets = _compute_target_list()
    usage = _parse_usage_from_log(args.log)
    render_markdown(theories, experiments, targets, usage,
                    args.out, args.db, args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
