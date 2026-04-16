"""
Terminal display layer for the KryptosBot research controller.

Provides a "command center" console aesthetic using rich Panels, Tables,
Progress bars, and Status spinners. All operator-facing output flows
through this module. The controller core never imports this; only the
CLI entrypoint (run_controller.py) does.

Design language:
    Panel (HEAVY)    → major blocks (startup, completion, status, summary)
    Panel (ROUNDED)  → secondary blocks (landscape, critic table)
    Progress bar     → dispatch worker tracking
    Status spinner   → theorist generation
    Table            → critic verdicts, status breakdown
    Stage labels     → ▸ GENERATE, ▸ CRITIC, ▸ DISPATCH, ▸ OUTCOME

Graceful degradation:
    Non-TTY (pipe, redirect) → plain text, no animation, no color
    Narrow terminals         → rich handles wrapping/truncation
    --quiet mode             → caller suppresses stderr; display still works
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Optional

from rich.bar import Bar
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    MofNCompleteColumn, TimeElapsedColumn,
)
from rich.status import Status
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich import box as rich_box

# ---------------------------------------------------------------------------
# Console singleton — auto-detects TTY, respects NO_COLOR
# ---------------------------------------------------------------------------

console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Display width cap
# ---------------------------------------------------------------------------
# Widened 2026-04-13 after Day 4 verification showed significant truncation
# of red-team verdict reasons and worker event details on a high-resolution
# widescreen terminal. The controller is not public and runs on a single
# high-resolution machine, so we can use generous widths without worrying
# about breakpoints.
#
# MAX_DISPLAY_WIDTH is the upper bound panels and tables will use. If the
# actual terminal is narrower, Rich will use the terminal width; if wider,
# panels will cap at this value to keep layout stable. 200 columns is
# roughly the sweet spot for 4K widescreen — wide enough to show full
# theory titles and reject reasons, narrow enough that long-form content
# doesn't become hard to read.
MAX_DISPLAY_WIDTH = 200

# Style constants
S_DIM = Style(dim=True)
S_BOLD = Style(bold=True)
S_HEADER = Style(bold=True, color="bright_white")
S_STAGE = Style(bold=True, color="cyan", dim=True)
S_SUCCESS = Style(color="green")
S_FAIL = Style(color="red")
S_WARN = Style(color="yellow")
S_INFO = Style(color="cyan")
S_ACTIVE = Style(color="magenta")
S_MUTED = Style(dim=True)

# Legacy color helpers — kept for any residual callers
def dim(t: str) -> str:
    return f"[dim]{t}[/dim]" if console.is_terminal else t

def bold(t: str) -> str:
    return f"[bold]{t}[/bold]" if console.is_terminal else t

def green(t: str) -> str:
    return f"[green]{t}[/green]" if console.is_terminal else t

def red(t: str) -> str:
    return f"[red]{t}[/red]" if console.is_terminal else t

def yellow(t: str) -> str:
    return f"[yellow]{t}[/yellow]" if console.is_terminal else t

def cyan(t: str) -> str:
    return f"[cyan]{t}[/cyan]" if console.is_terminal else t

def magenta(t: str) -> str:
    return f"[magenta]{t}[/magenta]" if console.is_terminal else t


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Current time as HH:MM:SS for telemetry lines."""
    return datetime.now().strftime("%H:%M:%S")


def _resolve_anomaly_display_text(anomaly_entry: dict[str, Any]) -> str:
    """Render an anomaly for the landscape panel.

    If the anomaly has a registered canonical claim_id, return a compact
    form that combines (a) the raw title for context with (b) the
    provenance hedge tag derived from the claim's epistemic class. The
    full rendered claim is too long for a 5-row landscape panel, so we
    extract just the epistemic-status badge.

    The display layer must show the same epistemic framing the theorist
    sees in the prompt — divergence between the two breeds the silent
    drift the provenance system was built to prevent.
    """
    title = anomaly_entry.get("title", "?")
    claim_id = anomaly_entry.get("claim_id", "")
    if not claim_id:
        return title
    try:
        from .claims_registry import CANONICAL_CLAIMS_BY_ID
        from .provenance import EpistemicClass
        claim = CANONICAL_CLAIMS_BY_ID.get(claim_id)
        if claim is None:
            return title
        # Compact epistemic badge based on the claim's class.
        ec = claim.epistemic_class
        if ec == EpistemicClass.BEAN_REPORTED_NOT_RERUN:
            badge = " [Bean-reported, not project-rerun]"
        elif ec == EpistemicClass.PROJECT_REVERIFIED_STATISTICAL_ANOMALY:
            badge = " [project-verified anomaly, ranking feature]"
        elif ec == EpistemicClass.INTERPRETIVE_PHYSICAL_OBSERVATION:
            badge = " [physical fact, crypto role unproven]"
        elif ec == EpistemicClass.PHYSICAL_FACT:
            badge = " [physical existence verified]"
        elif ec == EpistemicClass.H1_CONDITIONAL_DERIVATION:
            badge = " [H1-conditional]"
        elif ec == EpistemicClass.RETIRED_CLAIM:
            badge = " [RETIRED]"
        else:
            badge = ""
        return f"{title}{badge}"
    except Exception:
        # If anything in the provenance layer fails, prefer the raw
        # title over a broken display panel.
        return title


def _stage_label(label: str) -> None:
    """Print a stage label like ▸ GENERATE or ▸ CRITIC."""
    console.print(Text(f"  ▸ {label}", style=S_STAGE))


def _light_rule() -> None:
    """Print a light rule (─) for minor separators."""
    w = min(console.width, MAX_DISPLAY_WIDTH)
    console.print(Text("─" * w, style=S_DIM))


# ---------------------------------------------------------------------------
# Startup banner — Panel
# ---------------------------------------------------------------------------

def print_startup(
    *,
    cycle_start: int,
    max_cycles: int,
    theories_per_cycle: int,
    workers: int,
    timeout_minutes: int,
    proposed: int,
    tested: int,
    eliminated: int,
    dry_run: bool = False,
) -> None:
    """Print the controller startup banner as a rich Panel."""

    # Build content lines
    parts: list[Any] = []

    # Mode badge
    if dry_run:
        parts.append(
            Text("◆ DRY RUN", style="bold yellow")
            + Text("  generate + critic only, no dispatch\n", style=S_DIM)
        )

    # Parameters grid
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=S_DIM, min_width=16)
    grid.add_column(style=S_BOLD)
    grid.add_row("Starting cycle", str(cycle_start))
    grid.add_row("Max cycles", str(max_cycles))
    grid.add_row("Theories/cycle", str(theories_per_cycle))
    grid.add_row("Workers", str(workers))
    grid.add_row("Timeout", f"{timeout_minutes}m per worker")
    parts.append(grid)

    # Prior state
    if proposed > 0 or tested > 0 or eliminated > 0:
        state_line = (
            Text("\n")
            + Text(f"{proposed}", style=S_BOLD) + Text(" proposed  ", style=S_DIM)
            + Text(f"{tested}", style=S_BOLD) + Text(" tested  ", style=S_DIM)
            + Text(f"{eliminated}", style="bold red") + Text(" eliminated", style=S_DIM)
        )
        parts.append(state_line)

    panel = Panel(
        Group(*parts),
        title="[bright_white bold]KRYPTOSBOT CONTROLLER[/]",
        border_style="bright_blue",
        box=rich_box.HEAVY,
        padding=(1, 2),
        width=min(console.width, MAX_DISPLAY_WIDTH),
    )
    console.print()
    console.print(panel)
    console.print()


def print_bootstrap(families: int, anomalies: int, exhaustion: int) -> None:
    """Print bootstrap result as a structured one-liner."""
    parts = []
    if families:
        parts.append(f"{families} families")
    if anomalies:
        parts.append(f"{anomalies} anomalies")
    if exhaustion:
        parts.append(f"{exhaustion} from exhaustion log")
    summary = ", ".join(parts) if parts else "no changes"
    console.print(
        Text("  ✓ Bootstrap  ", style="green dim")
        + Text(summary, style=S_DIM)
    )


# ---------------------------------------------------------------------------
# Cycle presentation
# ---------------------------------------------------------------------------

def print_cycle_header(cycle: int, max_cycle: int) -> None:
    """Print the cycle header — visually clear boundary between cycles."""
    console.print()
    w = min(console.width, MAX_DISPLAY_WIDTH)
    label = f"CYCLE {cycle}/{max_cycle}"
    total_fill = max(0, w - len(label) - 2)
    pad_left = total_fill // 2
    pad_right = total_fill - pad_left
    line = "═" * pad_left + f" {label} " + "═" * pad_right
    console.print(Text(line, style=S_BOLD), no_wrap=True, overflow="ignore")
    console.print()


# ---------------------------------------------------------------------------
# Landscape — Panel with structured content
# ---------------------------------------------------------------------------

def print_landscape(landscape: dict[str, Any]) -> None:
    """Print the research landscape assessment in a Panel."""
    parts: list[Any] = []

    # Cycle delta
    delta = landscape.get("cycle_delta", {})
    new_tested = delta.get("new_tested", 0)
    new_elim = delta.get("new_eliminated", 0)
    if new_tested > 0 or new_elim > 0:
        delta_parts = []
        if new_tested:
            delta_parts.append(f"+{new_tested} tested")
        if new_elim:
            delta_parts.append(f"+{new_elim} eliminated")
        parts.append(
            Text("Δ ", style=S_SUCCESS) + Text(", ".join(delta_parts), style=S_DIM)
        )

    # Standing constraints (compact)
    constraints = landscape.get("standing_constraints", [])
    if constraints:
        parts.append(Text(f"{len(constraints)} standing constraints active", style=S_DIM))

    # Active families as a mini table
    active = landscape.get("active_families", [])
    if active:
        fam_table = Table.grid(padding=(0, 1))
        fam_table.add_column(min_width=26, style=S_DIM)
        fam_table.add_column(min_width=18)
        fam_table.add_column(style=S_DIM, justify="right")
        for f in active[:8]:
            tested = f.get("tested", 0)
            total = f.get("theories", 0)
            name = f["name"]
            if tested > 0:
                bar_text = Text("▪" * min(tested, 15), style=S_SUCCESS)
                count_text = Text(str(tested))
            elif total > 0:
                bar_text = Text("▪" * min(total, 15), style=S_DIM)
                count_text = Text(f"{total} scripts")
            else:
                bar_text = Text("untested", style=S_WARN)
                count_text = Text("")
            fam_table.add_row(name, bar_text, count_text)
        parts.append(Text("Active families:", style=S_DIM))
        parts.append(fam_table)

    # Underexplored
    underexplored = landscape.get("underexplored_families", [])
    if underexplored:
        lines = Text("")
        for i, f in enumerate(underexplored[:5]):
            if i > 0:
                lines.append("\n")
            tested = f.get("tested", 0)
            label = f"{tested} tested" if tested > 0 else "untested"
            lines.append(f"  › {f['name']}", style=S_WARN)
            lines.append(f" ({label})", style=S_DIM)
        parts.append(
            Text(f"Underexplored ({len(underexplored)})", style=S_WARN)
        )
        parts.append(lines)

    # Anomalies — pull display text from the provenance registry when a
    # canonical claim is wired up. Falls back to the raw KNOWN_ANOMALIES title
    # only when no claim is registered. This keeps the operator-facing display
    # in sync with what the theorist actually sees in the prompt — no more
    # silent divergence between display text and prompt text.
    all_anom = landscape.get("open_anomalies", [])
    prompt_count = landscape.get("prompt_anomaly_count", len(all_anom))
    registry_count = landscape.get("registry_open_anomaly_count", prompt_count)
    unaddressed = landscape.get("unaddressed_anomalies", [])
    if all_anom:
        unaddressed_ids = {a["id"] for a in unaddressed}
        lines = Text("")
        for i, a in enumerate(all_anom[:5]):
            if i > 0:
                lines.append("\n")
            explored = a.get("explored_by", 0)
            display_text = _resolve_anomaly_display_text(a)
            if a["id"] in unaddressed_ids:
                lines.append(f"  ? {display_text}", style=S_WARN)
                lines.append("  unaddressed", style="yellow dim")
            else:
                lines.append(f"  · {display_text}", style=S_DIM)
                lines.append(f"  {explored} explored", style=S_DIM)
        parts.append(
            Text(
                f"Prompt anomalies ({prompt_count} active / {registry_count} registry-open)",
                style=S_INFO,
            )
        )
        parts.append(lines)
    elif not all_anom:
        parts.append(
            Text(
                f"✓ No prompt anomalies active ({registry_count} registry-open)",
                style=S_SUCCESS,
            )
        )

    # Recent outcomes
    recent = landscape.get("recent_outcomes", [])
    if recent:
        lines = Text("")
        for i, r in enumerate(recent[:5]):
            if i > 0:
                lines.append("\n")
            status = r.get("status", "")
            icon_map = {
                "eliminated": ("×", S_FAIL),
                "promising": ("★", S_SUCCESS),
                "completed": ("·", S_DIM),
            }
            icon_char, icon_style = icon_map.get(status, ("?", S_DIM))
            lines.append(f"  {icon_char} ", style=icon_style)
            # Widened 2026-04-13 for 4K display — previous 38-char cap
            # truncated most theory titles mid-word.
            lines.append(r.get("title", "?")[:120], style=S_DIM)
            lines.append(f" [{r.get('family', '?')}]", style=S_MUTED)
        parts.append(Text("Recent outcomes:", style=S_DIM))
        parts.append(lines)

    panel = Panel(
        Group(*parts),
        title="[bold dim cyan]LANDSCAPE[/]",
        border_style="dim",
        box=rich_box.ROUNDED,
        padding=(0, 2),
        width=min(console.width, MAX_DISPLAY_WIDTH),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Theory generation — Status spinner
# ---------------------------------------------------------------------------

_theorist_status: Optional[Status] = None
_theorist_state: dict[str, Any] = {"turns": 0, "tools": 0, "start_time": 0.0}


def _stop_theorist_status() -> None:
    """Stop and clear the theorist spinner if it is still active."""
    global _theorist_status
    if _theorist_status:
        _theorist_status.stop()
        _theorist_status = None


def print_generation_start() -> None:
    """Print the generation stage label."""
    _stage_label("GENERATE")


def print_theorist_event(event: str, detail: str) -> None:
    """Display theorist agent progress with a rich Status spinner."""
    global _theorist_status

    if event == "start":
        _theorist_state["turns"] = 0
        _theorist_state["tools"] = 0
        _theorist_state["start_time"] = time.monotonic()
        _theorist_status = console.status(
            "[magenta]Theorist generating hypotheses...[/]",
            spinner="dots",
            spinner_style="magenta",
        )
        _theorist_status.start()
        return

    if event in ("turn", "result"):
        _theorist_state["turns"] += 1
    elif event == "tool_use":
        _theorist_state["tools"] += 1

    if event in ("turn", "result", "tool_use") and _theorist_status:
        elapsed = time.monotonic() - _theorist_state["start_time"]
        turns = _theorist_state["turns"]
        tools = _theorist_state["tools"]
        mins, secs = divmod(int(elapsed), 60)
        _theorist_status.update(
            f"[magenta]Theorist[/]  [dim]{mins}m{secs:02d}s[/]  "
            f"[dim]{turns} turns, {tools} tools[/]"
        )
        return

    # Terminal events — stop spinner, print final status
    _stop_theorist_status()

    if event == "fallback":
        console.print(Text("    ↻ Theorist fell back to programmatic generation", style=S_WARN))
    elif event == "done":
        elapsed = time.monotonic() - _theorist_state["start_time"]
        mins, secs = divmod(int(elapsed), 60)
        console.print(
            Text("    ■ Theorist done  ", style=S_ACTIVE)
            + Text(f"{mins}m{secs:02d}s", style=S_DIM)
        )
    elif event == "error":
        console.print(Text(f"    ! Theorist error: {detail[:180]}", style=S_FAIL))
    else:
        console.print(Text(f"    · Theorist: [{event}] {detail[:180]}", style=S_DIM))


def print_candidates_generated(count: int) -> None:
    """Print how many candidates were generated."""
    console.print(
        Text("    Generated ", style=S_DIM)
        + Text(str(count), style=S_BOLD)
        + Text(" candidate theories", style=S_DIM)
    )
    console.print()


# ---------------------------------------------------------------------------
# Critic pass — Table
# ---------------------------------------------------------------------------

_critic_rows: list[tuple[str, str, float, str]] = []


def print_critic_start() -> None:
    """Print the critic stage label and reset the result buffer."""
    _stage_label("CRITIC")
    _critic_rows.clear()


def print_critic_result(
    title: str, decision: str, confidence: float, reason: str
) -> None:
    """Buffer a critic verdict for table rendering."""
    _critic_rows.append((title, decision, confidence, reason))


def print_critic_summary(approved: int, total: int) -> None:
    """Flush the critic results as a styled table, then print summary."""
    table = Table(
        show_header=True,
        header_style="bold dim",
        box=rich_box.SIMPLE_HEAVY,
        padding=(0, 1),
        width=min(console.width, MAX_DISPLAY_WIDTH),
        show_edge=False,
    )
    table.add_column("", width=1, no_wrap=True)          # icon
    table.add_column("Theory", max_width=90, no_wrap=True, overflow="ellipsis")
    table.add_column("Decision", width=16, no_wrap=True)
    table.add_column("Conf", width=5, justify="right")
    table.add_column("Reason", max_width=70, no_wrap=True, overflow="ellipsis", style=S_DIM)

    for title, decision, confidence, reason in _critic_rows:
        if decision == "approve":
            icon = Text("✓", style=S_SUCCESS)
            title_text = Text(title, style=S_BOLD)
            dec_text = Text("APPROVED", style="bold green")
            reason_text = Text("")
        else:
            icon = Text("✗", style=S_FAIL)
            title_text = Text(title, style=S_DIM)
            dec_label = decision.upper().replace("REJECT_", "")
            dec_text = Text(dec_label, style="red")
            reason_text = Text(reason[:30] if reason else "", style=S_DIM)
        conf_text = Text(f"{confidence:.0%}", style=S_DIM)
        table.add_row(icon, title_text, dec_text, conf_text, reason_text)

    console.print(table)
    _critic_rows.clear()

    # Summary line
    if approved == total:
        color = "green"
    elif approved == 0:
        color = "red"
    else:
        color = "yellow"

    console.print(
        Text("    ")
        + Text(f"{approved}/{total}", style=f"bold {color}")
        + Text(" theories approved", style=S_DIM)
    )
    console.print()


# ---------------------------------------------------------------------------
# Red-team pre-check — one verdict line per theory
# ---------------------------------------------------------------------------


def print_redteam_start(agent_name: str, model: str, count: int) -> None:
    """Print the red-team stage label and the attribution line."""
    _stop_theorist_status()
    _stage_label("RED-TEAM PRE-CHECK")
    word = "theory" if count == 1 else "theories"
    console.print(
        Text("    ")
        + Text(f"{agent_name}", style="bold magenta")
        + Text(f" ({model})", style=S_DIM)
        + Text(f" reviewing {count} {word}", style=S_DIM)
    )
    console.print()


def print_redteam_verdict(
    theory_id: str,
    theory_title: str,
    verdict: str,
    confidence: float,
    wall_time_sec: float,
    turn_count: int,
    tool_count: int,
    reason: str = "",
) -> None:
    """
    Print a single red-team verdict line. One call per theory reviewed.
    The verdict markers match the controller log: ✓ pass, ~ concerned,
    ✗ reject, ? error.
    """
    marker_map = {
        "pass": (Text("✓", style=S_SUCCESS), "bold green"),
        "concerned": (Text("~", style=S_WARN), "bold yellow"),
        "reject": (Text("✗", style=S_FAIL), "bold red"),
        "error": (Text("?", style=S_DIM), "dim"),
    }
    marker, verdict_color = marker_map.get(verdict, (Text("?", style=S_DIM), "dim"))

    # Compact timing: "45s/12t/1tools" format
    timing = f"{wall_time_sec:.0f}s·{turn_count}t·{tool_count}tools"

    # Trim title and reason for terminal width. Widened 2026-04-13 for
    # 4K display — previously 38 chars for title and ~16 for reason,
    # which was unreadable. New budget: title up to 90 chars, reason
    # whatever space remains after the fixed-width prefix (~150 chars
    # on a 200-column display).
    short_title = theory_title if len(theory_title) <= 90 else theory_title[:87] + "..."
    short_reason = ""
    if reason:
        max_reason = min(console.width, MAX_DISPLAY_WIDTH) - 52
        if max_reason < 20:
            max_reason = 20
        short_reason = reason if len(reason) <= max_reason else reason[:max_reason - 3] + "..."

    line = (
        Text("    ")
        + marker
        + Text(" ")
        + Text(theory_id[:8], style=S_DIM)
        + Text(" ")
        + Text(verdict.upper().ljust(9), style=verdict_color)
        + Text(f" {confidence:.0%}".rjust(5), style=S_DIM)
        + Text(" ")
        + Text(timing.ljust(14), style=S_DIM)
        + Text(f" {short_title}", style=S_DIM)
    )
    console.print(line)
    if short_reason:
        console.print(
            Text("        ")
            + Text(f"└─ {short_reason}", style=S_DIM)
        )


def print_redteam_summary(
    survivors: int,
    total: int,
    rejected: int,
    concerned: int = 0,
    errors: int = 0,
) -> None:
    """Print the red-team filter summary — how many theories survived,
    distinguishing clean passes, survived-with-concern, rejections, and
    errors. CONCERNED theories still dispatch under current policy but
    must NOT be reported as "passed" — that is the bug this signature
    was widened to fix.
    """
    passed_clean = survivors - concerned - errors
    if passed_clean < 0:
        # Defensive — caller is expected to pass consistent counts
        passed_clean = 0

    if rejected == 0 and concerned == 0 and errors == 0:
        color = "green"
        phrase = "all passed cleanly"
    elif survivors == 0:
        color = "red"
        phrase = f"all rejected ({rejected})"
    else:
        color = "yellow"
        parts: list[str] = []
        if passed_clean:
            parts.append(f"{passed_clean} pass")
        if concerned:
            parts.append(f"{concerned} concerned")
        if errors:
            parts.append(f"{errors} error")
        if rejected:
            parts.append(f"{rejected} rejected")
        phrase = ", ".join(parts)

    console.print(
        Text("    ")
        + Text(f"{survivors}/{total}", style=f"bold {color}")
        + Text(f" theories survived red-team ({phrase})", style=S_DIM)
    )
    if concerned:
        console.print(
            Text("    ")
            + Text(
                f"  {concerned} dispatching with unresolved red-team "
                "concern — see verdict lines above",
                style=S_WARN,
            )
        )
    console.print()


# ---------------------------------------------------------------------------
# Dispatch — Progress bar + worker telemetry
# ---------------------------------------------------------------------------

_dispatch_progress: Optional[Progress] = None
_dispatch_task_id: Any = None
_dispatch_total: int = 0
_dispatch_done: int = 0


def print_dispatch_header(count: int) -> None:
    """Start the dispatch stage with a progress bar."""
    global _dispatch_progress, _dispatch_task_id, _dispatch_total, _dispatch_done

    _stop_theorist_status()
    _stage_label("DISPATCH")
    _dispatch_total = count
    _dispatch_done = 0

    word = "theory" if count == 1 else "theories"

    _dispatch_progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[dim]{task.description}[/]"),
        BarColumn(bar_width=60, style="dim", complete_style="cyan", finished_style="green"),
        MofNCompleteColumn(),
        TextColumn("[dim]│[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    _dispatch_progress.start()
    _dispatch_task_id = _dispatch_progress.add_task(
        f"Dispatching {count} {word}", total=count,
    )


def print_worker_event(hypothesis_id: str, event: str, detail: str) -> None:
    """Print a live worker telemetry event. Updates progress bar on 'done'."""
    global _dispatch_done

    hid = hypothesis_id[:8]
    ts = _ts()

    if event == "start":
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("▶ ", style=S_INFO)
            + Text(f"{hid}  ", style=S_BOLD)
            + Text(detail[:150], style=S_DIM)
        )
    elif event == "persona":
        # Day 4: worker persona attribution line. Shows which Pantheon
        # persona is handling this worker call. One line per worker,
        # emitted just after the ▶ start event.
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("☰ ", style="magenta")
            + Text(f"{hid}  ", style=S_DIM)
            + Text("persona: ", style=S_DIM)
            + Text(detail, style="magenta")
        )
    elif event == "heartbeat":
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("♡ ", style=S_DIM)
            + Text(f"{hid}  ", style=S_DIM)
            + Text(detail, style=S_DIM)
        )
    elif event == "tool_use":
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("⚙ ", style=S_DIM)
            + Text(f"{hid}  ", style=S_DIM)
            + Text("tool: ", style=S_DIM)
            + Text(detail, style=S_WARN)
        )
    elif event in ("turn", "result"):
        # Widened 2026-04-13 for 4K display. Previous 88-char cap
        # truncated worker reasoning snippets mid-sentence.
        snippet = detail[:180]
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("· ", style=S_DIM)
            + Text(f"{hid}  ", style=S_DIM)
            + Text(snippet, style=S_DIM)
        )
    elif event == "done":
        if "disproved" in detail or "error" in detail:
            icon_style = S_FAIL
        elif "success" in detail:
            icon_style = S_SUCCESS
        else:
            icon_style = S_DIM
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("■ ", style=icon_style)
            + Text(f"{hid}  ", style=S_BOLD)
            + Text(detail)
        )
        # Advance the progress bar
        _dispatch_done += 1
        if _dispatch_progress and _dispatch_task_id is not None:
            _dispatch_progress.update(_dispatch_task_id, completed=_dispatch_done)
    elif event == "error":
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text("! ", style=S_FAIL)
            + Text(f"{hid}  ", style=S_BOLD)
            + Text(detail[:180], style=S_FAIL)
        )
    else:
        console.print(
            Text(f"    {ts} ", style=S_DIM)
            + Text(f"  {hid}  [{event}] {detail[:180]}", style=S_DIM)
        )


def print_dispatch_footer() -> None:
    """Stop the dispatch progress bar."""
    global _dispatch_progress, _dispatch_task_id
    if _dispatch_progress:
        _dispatch_progress.stop()
        _dispatch_progress = None
        _dispatch_task_id = None


# ---------------------------------------------------------------------------
# Outcome summary
# ---------------------------------------------------------------------------

def print_outcome_summary(outcomes: list) -> None:
    """Print a compact outcome summary after dispatch."""
    _stage_label("OUTCOME")

    by_status: dict[str, int] = {}
    for oc in outcomes:
        s = oc.status.value
        by_status[s] = by_status.get(s, 0) + 1

    line = Text("    ")
    first = True
    for s, n in sorted(by_status.items()):
        if not first:
            line.append("  ", style=S_DIM)
        style_map = {"success": S_SUCCESS, "disproved": S_FAIL, "error": S_FAIL}
        st = style_map.get(s, S_DIM)
        line.append(f"{n} {s}", style=st)
        first = False

    console.print(line)
    console.print()


# ---------------------------------------------------------------------------
# Day 5: Statistical-auditor post-execution review display
# ---------------------------------------------------------------------------

def print_stat_audit_start(agent_name: str, model: str, count: int) -> None:
    """Print the stat-audit stage label and attribution line."""
    _stage_label("STAT-AUDIT")
    word = "contract" if count == 1 else "contracts"
    console.print(
        Text("    ")
        + Text(f"{agent_name}", style="bold magenta")
        + Text(f" ({model})", style=S_DIM)
        + Text(f" auditing {count} signal {word}", style=S_DIM)
    )
    console.print()


def print_stat_audit_skipped(reason: str) -> None:
    """Print a one-line skip notice when stat-audit is bypassed."""
    console.print(
        Text("    ")
        + Text("STAT-AUDIT skipped", style=S_DIM)
        + Text(f" — {reason}", style=S_DIM)
    )
    console.print()


def print_stat_audit_verdict(
    theory_id: str,
    theory_title: str,
    verdict: str,
    confidence: float,
    wall_time_sec: float,
    turn_count: int,
    tool_count: int,
    concern: str = "",
) -> None:
    """
    Print a single stat-audit verdict line. One call per audited contract.
    Verdict markers: ✓ confirmed, ~ concerned, ✗ rejected, ? error.
    """
    marker_map = {
        "confirmed": (Text("✓", style=S_SUCCESS), "bold green"),
        "concerned": (Text("~", style=S_WARN), "bold yellow"),
        "rejected": (Text("✗", style=S_FAIL), "bold red"),
        "error": (Text("?", style=S_DIM), "dim"),
    }
    marker, verdict_color = marker_map.get(verdict, (Text("?", style=S_DIM), "dim"))

    timing = f"{wall_time_sec:.0f}s·{turn_count}t·{tool_count}tools"

    short_title = theory_title if len(theory_title) <= 90 else theory_title[:87] + "..."
    short_concern = ""
    if concern:
        max_concern = min(console.width, MAX_DISPLAY_WIDTH) - 52
        if max_concern < 20:
            max_concern = 20
        short_concern = (
            concern if len(concern) <= max_concern
            else concern[:max_concern - 3] + "..."
        )

    line = (
        Text("    ")
        + marker
        + Text(" ")
        + Text(theory_id[:8], style=S_DIM)
        + Text(" ")
        + Text(verdict.upper().ljust(10), style=verdict_color)
        + Text(f" {confidence:.0%}".rjust(5), style=S_DIM)
        + Text(" ")
        + Text(timing.ljust(14), style=S_DIM)
        + Text(f" {short_title}", style=S_DIM)
    )
    console.print(line)
    if short_concern:
        console.print(
            Text("        ")
            + Text(f"└─ {short_concern}", style=S_DIM)
        )


def print_stat_audit_summary(
    confirmed: int, concerned: int, rejected: int, total: int,
) -> None:
    """Print the stat-audit verdict summary at end of phase."""
    parts: list[Text] = []
    if confirmed:
        parts.append(Text(f"{confirmed} confirmed", style="bold green"))
    if concerned:
        parts.append(Text(f"{concerned} concerned", style="bold yellow"))
    if rejected:
        parts.append(Text(f"{rejected} rejected", style="bold red"))

    if not parts:
        # Fallback shouldn't normally happen because the controller skips
        # the print entirely if no candidates met the threshold.
        parts.append(Text(f"0 of {total}", style=S_DIM))

    line = Text("    ")
    for i, p in enumerate(parts):
        if i:
            line += Text(", ", style=S_DIM)
        line += p
    line += Text(f" of {total} signal contract", style=S_DIM)
    line += Text("s" if total != 1 else "", style=S_DIM)
    console.print(line)
    console.print()


# ---------------------------------------------------------------------------
# Day 5: End-of-cycle synthesis display
# ---------------------------------------------------------------------------

def print_synthesis_start(agent_name: str, model: str) -> None:
    """Print the synthesis stage label and attribution line."""
    _stage_label("SYNTHESIS")
    console.print(
        Text("    ")
        + Text(f"{agent_name}", style="bold magenta")
        + Text(f" ({model})", style=S_DIM)
        + Text(" producing end-of-cycle synthesis", style=S_DIM)
    )
    console.print()


def print_synthesis_skipped(reason: str) -> None:
    """Print a one-line skip notice when synthesis is bypassed."""
    console.print(
        Text("    ")
        + Text("SYNTHESIS skipped", style=S_DIM)
        + Text(f" — {reason}", style=S_DIM)
    )
    console.print()


def print_synthesis_result(synthesis) -> None:
    """
    Print a structured CycleSynthesis result. Compact form: headline
    line + counts line + up to 3 family movements + recommended focus.
    """
    if synthesis.error:
        console.print(
            Text("    ")
            + Text("⚠ synthesis degraded", style=S_WARN)
            + Text(f" ({synthesis.error})", style=S_DIM)
        )
        console.print()
        return

    if synthesis.headline:
        console.print(
            Text("    ")
            + Text("▸ ", style=S_DIM)
            + Text(synthesis.headline[:140], style="bold")
        )
    counts = (
        f"{synthesis.dispatched_count} dispatched · "
        f"{synthesis.disproved_count} disproved · "
        f"{synthesis.signal_count} signal"
    )
    console.print(Text("      ") + Text(counts, style=S_DIM))
    # Priority 5: per-category risk breakdown. Suppress zero buckets
    # and "none" (it's never actionable). Render on its own dim line
    # when any risky bucket is non-empty.
    risk_breakdown = getattr(synthesis, "risk_breakdown", None) or {}
    risky = {
        k: v for k, v in risk_breakdown.items()
        if k != "none" and v > 0
    }
    if risky:
        parts = " ".join(f"{k}={v}" for k, v in sorted(risky.items()))
        console.print(Text("      risk: ", style=S_DIM) + Text(parts, style=S_DIM))
    for fm in synthesis.family_movements[:3]:
        console.print(Text("      • ") + Text(fm[:140], style=S_DIM))
    if synthesis.recommended_next_focus:
        console.print(
            Text("      ↪ ")
            + Text(
                f"next focus: {synthesis.recommended_next_focus[:120]}",
                style="italic",
            )
        )
    console.print()


# ---------------------------------------------------------------------------
# Day 6: Lead-pursuit display helpers
# ---------------------------------------------------------------------------


def print_pursuit_start(agent_name: str, model: str, count: int) -> None:
    """Print the lead-pursuit stage label and attribution line."""
    _stage_label("LEAD PURSUIT")
    word = "result" if count == 1 else "results"
    console.print(
        Text("    ")
        + Text(f"{agent_name}", style="bold magenta")
        + Text(f" ({model})", style=S_DIM)
        + Text(f" evaluating {count} sub-signal {word}", style=S_DIM)
    )
    console.print()


def print_pursuit_skipped(reason: str) -> None:
    """Print a one-line skip notice when lead pursuit is bypassed."""
    console.print(
        Text("    ")
        + Text("LEAD PURSUIT skipped", style=S_DIM)
        + Text(f" — {reason}", style=S_DIM)
    )
    console.print()


def print_pursuit_verdict(
    theory_id: str,
    theory_title: str,
    verdict: str,
    confidence: float,
    wall_time_sec: float,
    turn_count: int,
    tool_count: int,
    rationale: str = "",
    suggested_variants: Optional[list[str]] = None,
) -> None:
    """Print a single pursuit-evaluator verdict line."""
    marker_map = {
        "pursue": (Text("↪", style=S_SUCCESS), "bold green"),
        "skip":   (Text("·", style=S_DIM), "dim"),
        "error":  (Text("?", style=S_WARN), "yellow"),
    }
    marker, verdict_color = marker_map.get(verdict, (Text("?", style=S_DIM), "dim"))

    timing = f"{wall_time_sec:.0f}s·{turn_count}t·{tool_count}tools"
    short_title = theory_title if len(theory_title) <= 90 else theory_title[:87] + "..."

    line = (
        Text("    ")
        + marker
        + Text(" ")
        + Text(theory_id[:8], style=S_DIM)
        + Text(" ")
        + Text(verdict.upper().ljust(8), style=verdict_color)
        + Text(f" {confidence:.0%}".rjust(5), style=S_DIM)
        + Text(" ")
        + Text(timing.ljust(14), style=S_DIM)
        + Text(f" {short_title}", style=S_DIM)
    )
    console.print(line)
    if rationale:
        max_r = min(console.width, MAX_DISPLAY_WIDTH) - 52
        if max_r < 20:
            max_r = 20
        short_r = rationale if len(rationale) <= max_r else rationale[:max_r - 3] + "..."
        console.print(
            Text("        ")
            + Text(f"└─ {short_r}", style=S_DIM)
        )
    if suggested_variants:
        for v in suggested_variants[:3]:
            console.print(
                Text("          ")
                + Text(f"• {v[:120]}", style=S_DIM)
            )


def print_pursuit_summary(
    pursue: int, skip: int, error: int, total: int,
) -> None:
    """Print the lead-pursuit verdict summary."""
    parts: list[Text] = []
    if pursue:
        parts.append(Text(f"{pursue} pursue", style="bold green"))
    if skip:
        parts.append(Text(f"{skip} skip", style=S_DIM))
    if error:
        parts.append(Text(f"{error} error", style="yellow"))
    if not parts:
        parts.append(Text(f"0 of {total}", style=S_DIM))

    line = Text("    ")
    for i, p in enumerate(parts):
        if i:
            line += Text(", ", style=S_DIM)
        line += p
    line += Text(f" of {total} sub-signal ", style=S_DIM)
    line += Text("result" if total == 1 else "results", style=S_DIM)
    console.print(line)
    console.print()


# ---------------------------------------------------------------------------
# Dry run / no candidates notices
# ---------------------------------------------------------------------------

def print_dry_run_skip() -> None:
    """Print the dry-run skip notice."""
    console.print(
        Text("    ◆ DRY RUN", style="bold yellow")
        + Text(" — skipping dispatch", style=S_DIM)
    )
    console.print()


def print_no_candidates() -> None:
    """Print notice that no candidates were generated."""
    console.print(Text("    No candidates generated", style=S_WARN))
    console.print()


def print_run_halt(reason: str) -> None:
    """Print a concise halt notice for fatal infrastructure failures."""
    console.print(
        Text("    HALTING remaining cycles", style=S_FAIL)
        + Text(f" — {reason[:220]}", style=S_DIM)
    )
    console.print()


# ---------------------------------------------------------------------------
# Error presentation
# ---------------------------------------------------------------------------

def print_cycle_error(cycle: int, exc: Exception) -> None:
    """Print a cycle error with appropriate urgency."""
    # Stop any active live displays
    global _dispatch_progress
    _stop_theorist_status()
    if _dispatch_progress:
        _dispatch_progress.stop()
        _dispatch_progress = None

    error_panel = Panel(
        Text(f"{type(exc).__name__}: {exc}", style=S_FAIL),
        title=f"[bold red]ERROR in cycle {cycle}[/]",
        subtitle="[dim]state persisted — safe to retry[/]",
        border_style="red",
        box=rich_box.HEAVY,
        padding=(0, 2),
        width=min(console.width, MAX_DISPLAY_WIDTH),
    )
    console.print()
    console.print(error_panel)
    console.print()


# ---------------------------------------------------------------------------
# Completion banner — Panel
# ---------------------------------------------------------------------------

def print_completion(state: dict[str, Any]) -> None:
    """Print the final completion summary as a rich Panel."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=S_DIM, min_width=18)
    grid.add_column()

    cycles = state.get("cycle_number", 0)
    proposed = state.get("theories_proposed", 0)
    tested = state.get("theories_tested", 0)
    eliminated = state.get("theories_eliminated", 0)
    promising = state.get("theories_promising", 0)

    grid.add_row("Cycles completed", Text(str(cycles), style=S_BOLD))
    grid.add_row("Proposed", Text(str(proposed), style=S_BOLD))
    grid.add_row("Tested", Text(str(tested), style=S_BOLD))
    grid.add_row("Eliminated", Text(str(eliminated), style=S_FAIL))
    grid.add_row("Promising", Text(str(promising), style=S_SUCCESS))

    # Choose border color based on outcome
    if promising > 0:
        border = "green"
    elif eliminated > 0:
        border = "yellow"
    else:
        border = "dim"

    panel = Panel(
        grid,
        title="[bold bright_white]RUN COMPLETE[/]",
        border_style=border,
        box=rich_box.HEAVY,
        padding=(1, 2),
        width=min(console.width, 60),
    )
    console.print()
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Status display (--status mode) — Panel
# ---------------------------------------------------------------------------

def print_status(status: dict[str, Any]) -> None:
    """Print controller status as a rich Panel."""
    ctrl = status.get("controller", {})
    ledger = status.get("ledger", {})

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=S_DIM, min_width=16)
    grid.add_column()

    grid.add_row("Cycle", Text(str(ctrl.get("cycle_number", 0)), style=S_BOLD))
    last_run = ctrl.get("last_cycle_at", "never")
    if last_run and last_run != "never":
        last_run = last_run[:19]
    grid.add_row("Last run", Text(str(last_run) if last_run else "never", style=S_DIM))
    grid.add_row("Proposed", Text(str(ctrl.get("theories_proposed", 0)), style=S_BOLD))
    grid.add_row("Tested", Text(str(ctrl.get("theories_tested", 0)), style=S_BOLD))
    grid.add_row("Eliminated", Text(str(ctrl.get("theories_eliminated", 0)), style=S_FAIL))
    grid.add_row("Promising", Text(str(ctrl.get("theories_promising", 0)), style=S_SUCCESS))
    grid.add_row("Timeout", Text(f"{ctrl.get('worker_timeout_minutes', 30)}m per worker", style=S_DIM))

    parts: list[Any] = [grid]

    underexplored = ctrl.get("underexplored_families", [])
    if underexplored:
        lines = Text("\nUnderexplored families:\n", style=S_DIM)
        for fam in underexplored[:8]:
            lines.append(f"  › {fam}\n", style=S_WARN)
        parts.append(lines)

    open_anom = ctrl.get("open_anomalies", [])
    if open_anom:
        lines = Text("\nPrompt anomalies:\n", style=S_DIM)
        for a in open_anom[:5]:
            lines.append(f"  ? {a}\n", style=S_INFO)
        parts.append(lines)

    panel = Panel(
        Group(*parts),
        title="[bold bright_white]CONTROLLER STATUS[/]",
        border_style="bright_blue",
        box=rich_box.HEAVY,
        padding=(1, 2),
        width=min(console.width, MAX_DISPLAY_WIDTH),
    )
    console.print()
    console.print(panel)

    if ledger:
        console.print()
        print_summary(ledger)


# ---------------------------------------------------------------------------
# Summary display (--summary mode) — Panel with status bar chart
# ---------------------------------------------------------------------------

def print_summary(summary: dict[str, Any]) -> None:
    """Print ledger summary as a rich Panel with proportional status bars."""
    by_status = summary.get("theories_by_status", {})
    top = summary.get("top_scoring", [])

    # Top-level counts
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=S_DIM, min_width=14)
    grid.add_column()
    grid.add_row("Theories", Text(str(summary.get("total_theories", 0)), style=S_BOLD))
    grid.add_row("Experiments", Text(str(summary.get("total_experiments", 0)), style=S_BOLD))
    grid.add_row("Families", Text(str(summary.get("tracked_families", 0)), style=S_BOLD))
    grid.add_row("Anomalies", Text(str(summary.get("open_anomalies", 0)), style=S_BOLD) + Text(" open", style=S_DIM))

    parts: list[Any] = [grid]

    # Status breakdown with proportional bars
    if by_status:
        max_count = max(by_status.values()) if by_status else 1
        bar_table = Table.grid(padding=(0, 1))
        bar_table.add_column(min_width=14, style=S_DIM)
        bar_table.add_column(min_width=25)
        bar_table.add_column(justify="right", min_width=4)

        style_map = {
            "eliminated": "red",
            "promising": "green",
            "proposed": "cyan",
            "approved": "yellow",
            "completed": "dim",
            "criticized": "dim red",
            "running": "magenta",
        }
        for status_name, count in sorted(by_status.items()):
            color = style_map.get(status_name, "dim")
            # Proportional bar width (max 25 chars)
            bar_width = max(1, int(25 * count / max_count)) if max_count > 0 else 1
            bar_text = Text("█" * bar_width, style=color)
            bar_table.add_row(status_name, bar_text, Text(str(count), style=S_DIM))

        parts.append(Text("\nStatus breakdown:", style=S_DIM))
        parts.append(bar_table)

    # Top scoring theories
    if top:
        score_table = Table(
            show_header=True,
            header_style="bold dim",
            box=rich_box.SIMPLE,
            padding=(0, 1),
            show_edge=False,
        )
        score_table.add_column("Score", width=6, justify="right")
        score_table.add_column("Theory", max_width=90, no_wrap=True, overflow="ellipsis")
        score_table.add_column("Family", max_width=24, style=S_DIM, no_wrap=True, overflow="ellipsis")
        score_table.add_column("Status", max_width=14, no_wrap=True)

        status_style_map = {
            "eliminated": S_FAIL,
            "promising": S_SUCCESS,
            "completed": S_DIM,
            "approved": S_WARN,
        }
        for t in top[:5]:
            score = t.get("best_score", 0)
            title = t.get("title", t.get("hypothesis_id", "?"))
            fam = t.get("family", "?")
            st = t.get("status", "?")
            st_style = status_style_map.get(st, S_DIM)
            score_table.add_row(
                Text(f"{score:.1f}", style=S_BOLD),
                Text(title),
                Text(fam),
                Text(st, style=st_style),
            )

        parts.append(Text("\nTop scoring:", style=S_DIM))
        parts.append(score_table)

    ts = summary.get("generated_at", "?")[:19]
    parts.append(Text(f"\nGenerated: {ts}", style=S_DIM))

    panel = Panel(
        Group(*parts),
        title="[bold bright_white]LEDGER SUMMARY[/]",
        border_style="bright_blue",
        box=rich_box.HEAVY,
        padding=(1, 2),
        width=min(console.width, MAX_DISPLAY_WIDTH),
    )
    console.print()
    console.print(panel)
    console.print()
