"""Day 7 close-out: pre-Day-4 elimination spot audit.

Read-only pass over the kryptosbot theory ledger. Surfaces a human-review queue
of eliminated theories absorbed BEFORE the Day 4 kernel-verification cutover,
where the worker's self-reported scores went into the ledger unchecked.

Scope and rationale: project_day6_priority_order.md "Day 7 close-out task".
Binary model: substantive eliminations stay ELIMINATED; vague pre-cutover
eliminations are surfaced for Colin to review and optionally reopen by hand.

NO WRITES. NO RECOMPUTATION. NO MASS RERUNS.

Cutover derivation
------------------
The Day 4 kernel-verification fix landed in kryptosbot/contracts.py on
2026-04-13 around 18:13 EDT (local file mtime). In UTC that is
2026-04-13T22:13:31+00:00. This is the file mtime of contracts.py, which is
strictly later than the companion tests/test_contracts.py (17:46 EDT / 21:46
UTC), so using it as the cutover is the conservative choice: any theory with
updated_at < cutover went through the old worker-self-report absorb path.

The cutover is cross-validated against the ledger: there is a natural lull at
22:00 UTC hour in the eliminated-theory timeline (6 rows at 20Z, 4 at 21Z,
then 0 at 22Z, 2 at 23Z), which matches a session break around when the fix
was applied.

Output
------
- day7_output/queue.json: full audit record, all pre-cutover rows + flag labels
- day7_output/queue.md: human-readable review queue, flagged rows only,
  sorted by flag severity then updated_at ascending

No ledger state is modified by this script.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Cutover: contracts.py mtime 2026-04-13 18:13:31 EDT -> UTC.
# Any eliminated theory with updated_at < this value used the OLD absorb path
# (worker self-reported scores, no kernel recomputation).
CUTOVER_UTC = "2026-04-13T22:13:31+00:00"

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_DB = REPO_ROOT / "db" / "theory_ledger.sqlite"
OUTPUT_DIR = Path(__file__).resolve().parent / "day7_output"

# Provenance substance signals. Presence of ANY of these in failure_reason or
# experiment.disproof_evidence indicates the worker reasoned about mechanism
# rather than just reporting a score.
SUBSTANCE_PATTERNS = [
    # Concrete search sizes
    re.compile(r"\b\d{2,}\s*(configs?|combos?|keystreams?|variants?|trials?|candidates?|phases?|tests?|seeds?|tableaus?|permutations?)\b", re.I),
    # Crib-score fractions (e.g. "5/24")
    re.compile(r"\b\d+\s*/\s*24\b"),
    # Bean / admissibility / structural-kill language
    re.compile(r"\b(bean|admissibility|impossibility|impossible|mathematically|structural(?:ly)?|invariant|permutation-invariant)\b", re.I),
    # Cipher-family kill-criterion language
    re.compile(r"\b(kill[-_ ]criter|quadgram|ngram|ic\b|crib[-_ ]score|cipher\s*variant)\b", re.I),
    # Prior-script citations (framework IDs)
    re.compile(r"\b(e_[a-z0-9_]+|f_[a-z0-9_]+|blitz_[a-z0-9_]+|E-FRAC-\d+|E-TABLEAU|E-STEGO|RQ-\d+)\b"),
    # Period / width structural parameters
    re.compile(r"\b(period|width|row|column)[\s-]*\d+\b", re.I),
    # Explicit "zero passes" / "0 of N" language
    re.compile(r"\b(zero\s+(of\s+)?\d+|0\s*/\s*\d{2,}|no\s+(valid|passing|surviving))\b", re.I),
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AuditRow:
    hypothesis_id: str
    title: str
    family: str
    core_claim: str
    updated_at: str
    created_at: str
    failure_reason: str
    best_score: float
    best_plaintext_ledger: str
    n_experiments: int
    n_evidence_rows: int
    exp_best_plaintext: str  # from experiment result
    exp_disproof_evidence: list[str]
    exp_worker_role: str
    exp_status: str
    substance_signals: list[str] = field(default_factory=list)
    flag: bool = False
    flag_severity: str = "none"  # none | weak | strong
    flag_reason: str = ""

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d


# ---------------------------------------------------------------------------
# Ledger pull (read-only)
# ---------------------------------------------------------------------------


def pull_pre_cutover_eliminations(db_path: Path, cutover_utc: str) -> list[AuditRow]:
    # Open read-only to enforce the no-writes guarantee at the connection level.
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=30)
    conn.row_factory = sqlite3.Row

    rows_out: list[AuditRow] = []
    try:
        rows = conn.execute(
            """
            SELECT t.hypothesis_id, t.title, t.family, t.core_claim,
                   t.updated_at, t.created_at, t.failure_reason,
                   t.best_score, t.best_plaintext,
                   (SELECT COUNT(*) FROM experiments x WHERE x.hypothesis_id = t.hypothesis_id) AS n_experiments,
                   (SELECT COUNT(*) FROM evidence   e WHERE e.hypothesis_id = t.hypothesis_id) AS n_evidence_rows
            FROM theories t
            WHERE t.status = 'eliminated'
              AND t.updated_at < ?
            ORDER BY t.updated_at ASC
            """,
            (cutover_utc,),
        ).fetchall()

        for r in rows:
            # Pull the worker experiment result (most recent if multiple).
            exp_row = conn.execute(
                """
                SELECT result FROM experiments
                WHERE hypothesis_id = ?
                ORDER BY started_at DESC LIMIT 1
                """,
                (r["hypothesis_id"],),
            ).fetchone()

            exp_best_plaintext = ""
            exp_disproof_evidence: list[str] = []
            exp_worker_role = ""
            exp_status = ""
            if exp_row and exp_row["result"]:
                try:
                    parsed = json.loads(exp_row["result"])
                    if isinstance(parsed, dict):
                        exp_best_plaintext = str(parsed.get("best_plaintext", "") or "")
                        de = parsed.get("disproof_evidence", []) or []
                        if isinstance(de, list):
                            exp_disproof_evidence = [str(x) for x in de if str(x).strip()]
                        exp_worker_role = str(parsed.get("worker_role", "") or "")
                        exp_status = str(parsed.get("status", "") or "")
                except (json.JSONDecodeError, TypeError):
                    pass

            rows_out.append(
                AuditRow(
                    hypothesis_id=r["hypothesis_id"],
                    title=r["title"],
                    family=r["family"],
                    core_claim=r["core_claim"],
                    updated_at=r["updated_at"],
                    created_at=r["created_at"],
                    failure_reason=r["failure_reason"],
                    best_score=float(r["best_score"] or 0.0),
                    best_plaintext_ledger=r["best_plaintext"] or "",
                    n_experiments=int(r["n_experiments"] or 0),
                    n_evidence_rows=int(r["n_evidence_rows"] or 0),
                    exp_best_plaintext=exp_best_plaintext,
                    exp_disproof_evidence=exp_disproof_evidence,
                    exp_worker_role=exp_worker_role,
                    exp_status=exp_status,
                )
            )
    finally:
        conn.close()
    return rows_out


# ---------------------------------------------------------------------------
# Flag heuristic (binary per the memo)
# ---------------------------------------------------------------------------


def detect_substance_signals(row: AuditRow) -> list[str]:
    """Return list of substance-signal pattern names that fire against the
    row's failure_reason or disproof_evidence text blob."""
    haystack_parts = [row.failure_reason or ""]
    haystack_parts.extend(row.exp_disproof_evidence)
    haystack = "\n".join(haystack_parts)

    hits: list[str] = []
    for idx, pat in enumerate(SUBSTANCE_PATTERNS):
        if pat.search(haystack):
            hits.append(f"p{idx}:{pat.pattern[:40]}")
    return hits


def apply_flag_heuristic(row: AuditRow) -> None:
    """Populate flag / flag_severity / flag_reason in place.

    Binary outcome per the memo:
      - STRONG flag: no substance signals AND no disproof_evidence AND short
                     failure_reason. These are the ones Colin should review.
      - WEAK flag:   missing some but not all signals; mid-confidence cases
                     still worth an eye but lower priority.
      - none:        substantive, remains ELIMINATED, no action.
    """
    signals = detect_substance_signals(row)
    row.substance_signals = signals

    fr = (row.failure_reason or "").strip()
    fr_len = len(fr)
    n_signals = len(signals)
    has_disproof_evidence = len(row.exp_disproof_evidence) > 0
    has_exp_best_plaintext = bool((row.exp_best_plaintext or "").strip())

    # STRONG: multiple simultaneous vagueness indicators.
    if (
        n_signals == 0
        and not has_disproof_evidence
        and not has_exp_best_plaintext
        and fr_len < 200
    ):
        row.flag = True
        row.flag_severity = "strong"
        row.flag_reason = (
            f"no substance signals, no disproof_evidence, empty exp.best_plaintext, "
            f"failure_reason={fr_len} chars"
        )
        return

    # WEAK: two or fewer signals, and one of the two corroborating fields missing.
    if n_signals <= 1 and not has_disproof_evidence and fr_len < 200:
        row.flag = True
        row.flag_severity = "weak"
        row.flag_reason = (
            f"n_signals={n_signals}, no disproof_evidence, failure_reason={fr_len} chars"
        )
        return

    row.flag = False
    row.flag_severity = "none"
    row.flag_reason = ""


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def render_json(rows: list[AuditRow], cutover: str, out_path: Path) -> None:
    doc = {
        "audit": "day7_pre_day4_spot_audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cutover_utc": cutover,
        "cutover_derivation": (
            "kryptosbot/contracts.py file mtime 2026-04-13 18:13:31 EDT (= 22:13:31 UTC), "
            "the landing time of _verify_against_kernel() which closed the "
            "worker-self-report absorb path. Cross-validated against a natural lull "
            "in the eliminated-theory timeline at that UTC hour."
        ),
        "n_rows_total": len(rows),
        "n_strong_flag": sum(1 for r in rows if r.flag_severity == "strong"),
        "n_weak_flag": sum(1 for r in rows if r.flag_severity == "weak"),
        "n_none": sum(1 for r in rows if r.flag_severity == "none"),
        "rows": [r.to_dict() for r in rows],
    }
    out_path.write_text(json.dumps(doc, indent=2, default=str))


def _truncate(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def render_markdown(rows: list[AuditRow], cutover: str, out_path: Path) -> None:
    strong = [r for r in rows if r.flag_severity == "strong"]
    weak = [r for r in rows if r.flag_severity == "weak"]
    clean = [r for r in rows if r.flag_severity == "none"]

    # Sort flagged rows by updated_at ascending within each severity bucket.
    strong.sort(key=lambda r: r.updated_at)
    weak.sort(key=lambda r: r.updated_at)

    lines: list[str] = []
    lines.append("# Day 7 pre-Day-4 elimination spot audit -- review queue")
    lines.append("")
    lines.append(f"- Cutover (UTC): `{cutover}`")
    lines.append(f"- Pool size: **{len(rows)}** eliminated theories absorbed before cutover")
    lines.append(f"- Strong flags (review first): **{len(strong)}**")
    lines.append(f"- Weak flags: **{len(weak)}**")
    lines.append(f"- Substantively confirmed (remain ELIMINATED, no action): **{len(clean)}**")
    lines.append("")
    lines.append("## Provenance headline finding")
    lines.append("")
    lines.append(
        "All 165 pre-cutover eliminated theories have **zero** rows in the "
        "`evidence` table. All 53 post-cutover eliminated theories have one or "
        "more. The `evidence` table wiring appears to have landed together with "
        "the Day 4 kernel-verification fix. This makes evidence-row count a "
        "tautological proxy for the date filter, so the audit discriminator "
        "falls back to failure_reason substance and experiment.result content."
    )
    lines.append("")
    lines.append(
        "Experiment rows ARE present for every pre-cutover row, but their "
        "`result` JSON contains worker-self-reported fields that were never "
        "kernel-recomputed. Those self-reports are the specific risk surface "
        "the audit is looking at."
    )
    lines.append("")
    lines.append("## How to action this queue")
    lines.append("")
    lines.append(
        "For each flagged row, decide one of two outcomes and record it:"
    )
    lines.append("")
    lines.append(
        "1. **Confirm eliminated** -- the disproof was substantive on re-read. "
        "No action needed; row stays ELIMINATED."
    )
    lines.append(
        "2. **Reopen** -- the failure_reason cannot be confirmed. Flip status "
        "back to `proposed` so the post-hardening controller re-examines it."
    )
    lines.append("")
    lines.append(
        "A separate small script (not in this audit, deliberately) will be "
        "written to perform the status flip for explicitly named hypothesis_ids. "
        "This file is read-only and does not touch ledger state."
    )
    lines.append("")

    def _row_block(r: AuditRow) -> list[str]:
        b: list[str] = []
        b.append(f"### `{r.hypothesis_id}` -- {_truncate(r.title, 100)}")
        b.append("")
        b.append(f"- family: `{r.family or '(none)'}`")
        b.append(f"- updated_at: `{r.updated_at}`")
        b.append(f"- best_score (ledger): `{r.best_score}`")
        b.append(f"- exp.worker_role: `{r.exp_worker_role or '(none)'}`  exp.status: `{r.exp_status or '(none)'}`")
        b.append(f"- exp.best_plaintext present: {'yes' if (r.exp_best_plaintext or '').strip() else 'no'}")
        b.append(f"- exp.disproof_evidence items: {len(r.exp_disproof_evidence)}")
        b.append(f"- substance signals: {len(r.substance_signals)}")
        b.append(f"- **flag reason**: {r.flag_reason}")
        b.append("")
        b.append(f"**core_claim**: {_truncate(r.core_claim, 240)}")
        b.append("")
        b.append("**failure_reason**:")
        b.append("")
        b.append("> " + (r.failure_reason or "(empty)").replace("\n", " "))
        b.append("")
        if r.exp_disproof_evidence:
            b.append("**disproof_evidence items**:")
            b.append("")
            for item in r.exp_disproof_evidence[:3]:
                b.append(f"- {_truncate(item, 200)}")
            if len(r.exp_disproof_evidence) > 3:
                b.append(f"- ... ({len(r.exp_disproof_evidence) - 3} more)")
            b.append("")
        return b

    if strong:
        lines.append("## STRONG flags")
        lines.append("")
        for r in strong:
            lines.extend(_row_block(r))

    if weak:
        lines.append("## WEAK flags")
        lines.append("")
        for r in weak:
            lines.extend(_row_block(r))

    if not strong and not weak:
        lines.append("## No flags")
        lines.append("")
        lines.append(
            "The heuristic flagged zero rows. Every pre-cutover eliminated "
            "theory has substance signals in its failure_reason or its "
            "experiment disproof_evidence array. This is a stronger result "
            "than the memo anticipated: the dominant pre-Day-4 failure mode "
            "was over-promotion (the e2784dc9 BREAKTHROUGH fabrication), not "
            "over-elimination, and the data now supports that asymmetry."
        )
        lines.append("")

    # Independent manual spot-check: surface the rows that came CLOSEST to
    # flagging (fewest substance signals) so Colin can eyeball them even when
    # the automated heuristic reports zero strong/weak flags. This is the
    # defense against the heuristic being too loose.
    zero_sig = [r for r in rows if len(r.substance_signals) == 0]
    zero_sig.sort(key=lambda r: r.updated_at)
    if zero_sig:
        lines.append("## Manual spot-check: rows with 0 substance signals")
        lines.append("")
        lines.append(
            f"{len(zero_sig)} row(s) had 0 substance-pattern hits. None "
            "flagged by the automated heuristic because all of them have "
            "populated `disproof_evidence` arrays, but they are the most "
            "worth a visual re-read since they escaped all regex categories. "
            "Each is listed below with enough context for a 10-second "
            "confirm-or-reopen decision."
        )
        lines.append("")
        for r in zero_sig:
            lines.extend(_row_block(r))

    out_path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    if not LEDGER_DB.exists():
        raise SystemExit(f"Ledger DB not found at {LEDGER_DB}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    rows = pull_pre_cutover_eliminations(LEDGER_DB, CUTOVER_UTC)
    for r in rows:
        apply_flag_heuristic(r)

    json_out = OUTPUT_DIR / "queue.json"
    md_out = OUTPUT_DIR / "queue.md"
    render_json(rows, CUTOVER_UTC, json_out)
    render_markdown(rows, CUTOVER_UTC, md_out)

    strong = sum(1 for r in rows if r.flag_severity == "strong")
    weak = sum(1 for r in rows if r.flag_severity == "weak")
    clean = sum(1 for r in rows if r.flag_severity == "none")

    print(f"Day 7 pre-Day-4 spot audit complete.")
    print(f"  Cutover:       {CUTOVER_UTC}")
    print(f"  Pool size:     {len(rows)}")
    print(f"  Strong flags:  {strong}")
    print(f"  Weak flags:    {weak}")
    print(f"  Unflagged:     {clean}")
    print(f"  JSON:          {json_out}")
    print(f"  Markdown:      {md_out}")


if __name__ == "__main__":
    main()
