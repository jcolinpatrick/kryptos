"""Contradiction-detector alerting for the KryptosBot research controller.

PHILOSOPHY:
This module is NOT a victory bell. It is a contradiction detector for the
elimination ledger. If a worker reports a score that should be impossible
under the current eliminations, that is far more likely a hole in the
eliminations than a real K4 solution. Either way, you want to know
immediately.

DESIGN:
- Fail-closed: any failure in the alert path is logged but never blocks
  the controller's main loop. Alerting is best-effort.
- No external dependencies: uses urllib for ntfy POST.
- Thresholds are read from kernel constants, NOT hardcoded here.
- Every alert is also persisted to results/breakthroughs/ as a JSON file
  so even if a notification is missed, the audit trail survives.
- The terminal alert is loud and unmissable. The ntfy push is optional
  and silently degrades if NTFY_TOPIC is not configured.

USAGE:
    from kryptosbot.alerts import AlertLevel, process_alerts

    # In the controller's run loop, after _absorb_outcomes:
    alerts = process_alerts(
        outcomes=outcomes,
        threshold=AlertLevel.SIGNAL,
        results_dir=Path("results/breakthroughs"),
    )
    if alerts:
        # alerts already printed to terminal + persisted + pushed to ntfy
        # the controller can decide whether to halt or continue
        pass
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from .models import WorkerContract, WorkerStatus

logger = logging.getLogger("kryptosbot.alerts")


class AlertLevel(str, Enum):
    """Alert severity levels.

    NONE: do not alert on anything
    SIGNAL: alert if crib_score >= 18 (project SIGNAL_THRESHOLD)
    BREAKTHROUGH: alert only if crib_score >= 24 AND bean_passed
    """
    NONE = "none"
    SIGNAL = "signal"
    BREAKTHROUGH = "breakthrough"


@dataclass
class AlertEvent:
    """A structured alert event for persistence and notification."""
    triggered_at: str
    hypothesis_id: str
    level: str                       # AlertLevel value
    crib_score: int
    bean_passed: bool
    score: float
    worker_status: str
    best_plaintext: str
    narrative_summary: str
    contradiction_note: str          # what eliminations this potentially contradicts
    cycle_number: int
    theory_title: str = ""
    theory_family: str = ""
    theory_mechanism: str = ""
    # Campaign-A hardening (2026-04-22): which p-value null was consulted
    # when this alert fired. Empty string for pre-hardening callers that
    # never plumbed the status through. Values mirror alerts._p_value_gate_passes:
    #   "ok_gated"              — random_text null consulted, p <= gate
    #   "ok_ungated"            — random_text null consulted, p > gate
    #   "ok_matched_family"     — matched-family null consulted, p <= gate
    #   "matched_family_ungated"— matched-family null consulted, p > gate
    #   "matched_null_miss"     — matched family requested, cache missed,
    #                             fell back to random_text
    #   "cache_miss"            — no null cache at all
    #
    # Per R3 §5 halt condition 1, a BREAKTHROUGH alert with status
    # matched_null_miss or cache_miss halts the controller so calibration
    # can be rebuilt before the alert is treated as signal.
    p_value_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Threshold checking ────────────────────────────────────────────────

def _load_thresholds() -> dict[str, int]:
    """Load score thresholds from kernel constants.

    Falls back to canonical values if the import fails (e.g. test env).
    """
    try:
        from kryptosbot.constants import (
            SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
        )
        return {
            "signal": int(SIGNAL_THRESHOLD),
            "breakthrough": int(BREAKTHROUGH_THRESHOLD),
        }
    except Exception:
        logger.warning("Could not load kernel thresholds; using fallback")
        return {"signal": 18, "breakthrough": 24}


# Priority 3: ngram floor for BREAKTHROUGH classification.
#
# Natural English per-char quadgram log-probability sits around -2.5 to
# -3.5 for well-formed prose. Concatenated-word cipher plaintexts (no
# spaces, occasional proper nouns, K-section-style compression) float
# around -4.0 to -5.0. Random 26-letter text sits near -6.0 to -6.5.
# A "crib-paste fabrication" — the 23 crib chars in place with the
# remaining 74 positions random — produces a crib_score of 24 with a
# per-char ngram score around -5.8 to -6.1 (weighted mix of crib-region
# English and random filler).
#
# -5.5 is the floor: comfortably above random, comfortably above any
# plausible crib-paste fabrication, and still below where even an
# awkwardly-spaced cipher plaintext should land. Failing the floor
# DOWNGRADES the alert from BREAKTHROUGH to SIGNAL — it does not
# silently discard the result, so a real signal with surprisingly low
# ngram still surfaces in the audit trail.
BREAKTHROUGH_NGRAM_FLOOR: float = -5.5

# Phase 6: p-value gate for SIGNAL / BREAKTHROUGH alerts.
# The brief mandates firing on p_value_vs_null <= 1e-6 AND crib_score >= 18.
# For crib_score >= 18 under the random_text null the analytic
# (Binomial(24, 1/26)) p-value is ~3.7e-21, comfortably below the gate.
# The gate is primarily there to suppress FALSE SIGNAL alerts at lower
# crib_scores where the empirical null tail matters.
ALERT_P_VALUE_GATE: float = 1e-6


def _ngram_per_char_safe(plaintext: str) -> Optional[float]:
    """Return per-char quadgram log-prob for plaintext, or None on error.

    Never raises. If the scorer or plaintext are unavailable we return
    None and the caller downgrades BREAKTHROUGH to SIGNAL. Alerting is
    still best-effort, but missing scorer data must not promote a
    crib-paste-shaped artifact to the highest severity.
    """
    if not plaintext or len(plaintext) < 4:
        return None
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer
        scorer = get_default_scorer()
        return scorer.score_per_char(plaintext)
    except Exception as exc:
        logger.warning("ngram floor check unavailable: %s", exc)
        return None


def _matched_null_family_from_contract(contract: WorkerContract) -> str:
    """Derive the matched-null family tag from a WorkerContract.

    R3-2 (2026-04-21): DSL-dispatched contracts carry
    ``raw_artifacts["dsl_pipeline_kinds"]`` — a list of CipherLayer kinds
    in pipeline order. This function maps that list to a R2-4
    matched-family null key when possible, else returns "" (caller
    falls back to random_text).

    Matching rules (per DSL_CUTOVER_CONTRACT §7.2):
      - Single-layer columnar              → "columnar_single"
      - Two columnar layers in sequence   → "columnar_double"
      - Single-layer {vigenere, beaufort,
        variant_beaufort, atbash}          → the kind itself
      - Anything else (multi-layer,
        grille, polybius, procedural)      → "" (random_text fallback)
    """
    kinds = (contract.raw_artifacts or {}).get("dsl_pipeline_kinds") or []
    if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
        return ""
    if len(kinds) == 1:
        k = kinds[0]
        if k == "columnar":
            return "columnar_single"
        if k in ("beaufort", "variant_beaufort", "vigenere"):
            return k
        return ""
    if len(kinds) == 2 and kinds[0] == "columnar" and kinds[1] == "columnar":
        return "columnar_double"
    return ""


def _p_value_gate_passes(
    plaintext: str,
    crib_score_value: int,
    hypothesis_id: str = "",
    family: str = "",
) -> tuple[bool, str]:
    """Phase 6 p-value gate.

    Returns (passes_gate, status) where status is:
      "ok_gated"            — null cache available, p-value <= ALERT_P_VALUE_GATE
      "ok_ungated"          — null cache available, p-value > gate (alert suppressed)
      "ok_matched_family"   — R3-2: matched-family null consulted, p <= gate
      "matched_family_ungated" — R3-2: matched-family null, p > gate (suppressed)
      "matched_null_miss"   — R3-2: caller gave family but matched cache
                              missing; fell back to random_text null
      "cache_miss"          — null cache unavailable; passes_gate=True (legacy fallback)
                              with a logged warning that the alert is uncalibrated
      "error"               — unexpected failure; passes_gate=True (fail-open, legacy)

    R3-2 (2026-04-21): ``family`` argument routes through the R2-4
    matched-family null cache when present. When absent, falls back to
    random_text and records matched_null_miss so the alert path can log
    the degradation. Empty family preserves Phase 6 behaviour.

    The fallback is explicit: an uncalibrated alert is still emitted
    (legacy behaviour) but flagged as uncalibrated in logs and in the
    AlertEvent.contradiction_note. Once the null cache exists
    (scripts/_infra/calibrate_null_baselines.py has been run on this
    kernel commit), the gate becomes enforcing.
    """
    try:
        from .null_baselines import p_value_for_alert
        p, status = p_value_for_alert(plaintext, crib_score_value, family=family)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "p_value gate failed for %s: %s; falling back to legacy gating",
            hypothesis_id, exc,
        )
        return (True, "error")

    if status == "cache_miss":
        logger.warning(
            "Alert is UNCALIBRATED: null baseline cache missing for "
            "hypothesis %s. Run scripts/_infra/calibrate_null_baselines.py "
            "to enable p-value gating.",
            hypothesis_id,
        )
        return (True, "cache_miss")
    if status == "matched_null_miss":
        # Got a p-value from random_text fallback; keep enforcing the
        # gate but mark the alert's status so downstream records the
        # degradation.
        logger.warning(
            "Alert using random_text fallback p-value for hypothesis %s "
            "(matched-family null for %r was missing)",
            hypothesis_id, family,
        )
        if p is None:
            return (True, "cache_miss")
        passes = p <= ALERT_P_VALUE_GATE
        return (passes, "matched_null_miss")
    if status == "ok_matched_family":
        if p is None:
            return (True, "error")
        passes = p <= ALERT_P_VALUE_GATE
        if not passes:
            logger.info(
                "Alert SUPPRESSED by matched-family p-value gate: "
                "p=%.3g > %.1e (family=%r, hypothesis %s)",
                p, ALERT_P_VALUE_GATE, family, hypothesis_id,
            )
        return (passes, "ok_matched_family" if passes else "matched_family_ungated")
    if status != "ok" or p is None:
        return (True, status or "error")

    passes = p <= ALERT_P_VALUE_GATE
    if not passes:
        logger.info(
            "Alert SUPPRESSED by p-value gate: p=%.3g > %.1e (hypothesis %s)",
            p, ALERT_P_VALUE_GATE, hypothesis_id,
        )
    return (passes, "ok_gated" if passes else "ok_ungated")


def classify_outcome(
    contract: WorkerContract,
    threshold: AlertLevel,
) -> tuple[Optional[AlertLevel], str]:
    """Determine whether a worker outcome triggers an alert.

    Returns ``(level, p_value_status)`` where:
      - ``level`` is the highest matching AlertLevel, or None if no
        alert fires.
      - ``p_value_status`` is the status string from
        ``_p_value_gate_passes`` ("ok_gated" / "ok_matched_family" /
        "matched_null_miss" / "cache_miss" / etc.) so the caller can
        distinguish an alert that was calibrated against a matched-
        family null (R2-4, the R3-target alert quality) from one that
        fell back to random_text or fired with no null cache at all.
        Empty string when no p-value gate was consulted (e.g. level is
        None because the contract is below threshold).

    Campaign-A hardening (2026-04-22): prior version returned only the
    AlertLevel, throwing away the p_value_status. R3 §5 halt condition
    1 requires the controller to halt on BREAKTHROUGH with
    matched_null_miss / cache_miss, so the status must flow through.

    Priority 3: BREAKTHROUGH classification requires the worker's
    best_plaintext to pass an ngram-per-char floor. A crib-paste
    fabrication satisfies crib_score=24 and bean_passed but has a
    plaintext that is ~95% gibberish, which shows up in the per-char
    quadgram score. Failing the floor downgrades BREAKTHROUGH to SIGNAL
    — the result is still worth investigation, but not a full-volume
    alert — and the downgrade is logged so the audit trail records it.

    Phase 6: both SIGNAL and BREAKTHROUGH additionally gate on
    p_value <= ALERT_P_VALUE_GATE (1e-6) against the cached null
    distribution. When the null cache is unavailable, the gate fails
    open to the legacy behaviour with a WARNING logged — so the
    framework never becomes silent on a high score just because
    calibration hasn't run yet.
    """
    if threshold == AlertLevel.NONE:
        return (None, "")

    # Only consider workers that actually completed with a structured result.
    # Errors and timeouts cannot trigger alerts.
    if contract.status not in (WorkerStatus.SUCCESS, WorkerStatus.DISPROVED,
                                WorkerStatus.INCONCLUSIVE):
        return (None, "")

    thresholds = _load_thresholds()
    crib = int(contract.crib_score or 0)
    # R3-2: derive matched-family tag from the contract's DSL metadata.
    # Empty string for legacy contracts → p_value_for_alert falls back
    # to random_text (the Phase 6 behaviour).
    matched_family = _matched_null_family_from_contract(contract)

    # Breakthrough: full crib score AND bean pass AND ngram floor AND
    # p-value gate. If any gate fails, fall through to the SIGNAL branch.
    if crib >= thresholds["breakthrough"] and contract.bean_passed:
        ngram_pc = _ngram_per_char_safe(contract.best_plaintext)
        ngram_ok = ngram_pc is not None and ngram_pc >= BREAKTHROUGH_NGRAM_FLOOR
        p_value_ok, p_status = _p_value_gate_passes(
            contract.best_plaintext, crib, contract.hypothesis_id,
            family=matched_family,
        )
        if ngram_ok and p_value_ok:
            return (AlertLevel.BREAKTHROUGH, p_status)
        if ngram_pc is None:
            logger.warning(
                "BREAKTHROUGH downgraded to SIGNAL: ngram floor unavailable "
                "(hypothesis_id=%s)",
                contract.hypothesis_id,
            )
        elif not ngram_ok:
            # Fabrication-shaped result: crib+bean hit but the plaintext is
            # gibberish. Log the downgrade and fall through to the SIGNAL
            # branch so the result still surfaces, but not at BREAKTHROUGH
            # volume.
            logger.warning(
                "BREAKTHROUGH downgraded to SIGNAL: ngram_per_char=%.3f < "
                "floor=%.3f (fabrication-shaped result from hypothesis_id=%s)",
                ngram_pc, BREAKTHROUGH_NGRAM_FLOOR, contract.hypothesis_id,
            )
        elif not p_value_ok:
            logger.warning(
                "BREAKTHROUGH downgraded to SIGNAL: p-value gate not satisfied "
                "(hypothesis_id=%s)",
                contract.hypothesis_id,
            )

    # Signal: above SIGNAL threshold AND p-value gate.
    if threshold in (AlertLevel.SIGNAL, AlertLevel.BREAKTHROUGH):
        if crib >= thresholds["signal"]:
            p_value_ok, p_status = _p_value_gate_passes(
                contract.best_plaintext, crib, contract.hypothesis_id,
                family=matched_family,
            )
            if p_value_ok:
                return (AlertLevel.SIGNAL, p_status)
            logger.info(
                "SIGNAL suppressed by p-value gate (hypothesis_id=%s, crib=%d)",
                contract.hypothesis_id, crib,
            )

    return (None, "")


def _build_contradiction_note(contract: WorkerContract) -> str:
    """Build the contradiction-detector message for an alert.

    The message frames the alert as a CONTRADICTION with current
    eliminations rather than a victory. This is the project's epistemic
    posture: a high score is more likely a hole in the eliminations
    than a real solve.
    """
    crib = int(contract.crib_score or 0)
    bean = contract.bean_passed
    notes = []

    if crib >= 24 and bean:
        notes.append(
            "Worker reports BREAKTHROUGH (crib_score=24, bean_passed). "
            "Under current eliminations this is structurally implausible. "
            "Most likely: (a) the worker miscomputed crib alignment, "
            "(b) the worker fabricated the score, (c) one of the project's "
            "eliminations has a hole. Verify INDEPENDENTLY before celebrating."
        )
    elif crib >= 18:
        notes.append(
            f"Worker reports SIGNAL crib_score={crib}. Under current "
            f"eliminations (Bean impossibility, periodic-poly impossibility, "
            f"composition-framework null), a score this high should be rare. "
            f"This is more likely a contradiction in the elimination ledger "
            f"than a real positive signal. Audit the worker's actual computation."
        )

    if not bean and crib >= 18:
        notes.append(
            "NOTE: bean_passed=False. The worker found cribs but the keystream "
            "violates Bean constraints. This is consistent with a hole in the "
            "Bean derivation OR with a worker that bypassed Bean validation."
        )

    return " ".join(notes) if notes else "(no contradiction note)"


# ── Persistence ───────────────────────────────────────────────────────

def write_breakthrough_file(
    event: AlertEvent,
    results_dir: Path,
) -> Path:
    """Persist an alert event to results/breakthroughs/ as JSON.

    Returns the path written. Best-effort: failures are logged but raised
    so the caller can decide.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = event.triggered_at.replace(":", "").replace("-", "").replace(".", "_")[:15]
    fname = f"alert_{timestamp}_{event.hypothesis_id[:12]}_{event.level}.json"
    path = results_dir / fname
    path.write_text(json.dumps(event.to_dict(), indent=2))
    return path


# ── Notification channels ─────────────────────────────────────────────

def emit_terminal_alert(event: AlertEvent) -> None:
    """Print a loud, unmissable terminal alert.

    Uses no rich/color so it works under -q mode and in non-TTY contexts.
    """
    border = "!" * 78
    print()
    print(border)
    print(f"!! {event.level.upper()} ALERT — {event.triggered_at[:19]}")
    print(f"!! Hypothesis: {event.hypothesis_id}")
    if event.theory_title:
        print(f"!! Title: {event.theory_title[:70]}")
    if event.theory_family:
        print(f"!! Family: {event.theory_family}")
    print(f"!! crib_score = {event.crib_score} | bean_passed = {event.bean_passed} | score = {event.score:.2f}")
    print(f"!!")
    print(f"!! CONTRADICTION-DETECTOR NOTE:")
    # Wrap the contradiction note at 74 cols for terminal readability
    note = event.contradiction_note
    while note:
        print(f"!! {note[:74]}")
        note = note[74:]
    print(f"!!")
    if event.best_plaintext:
        pt_preview = event.best_plaintext[:70]
        print(f"!! best_plaintext: {pt_preview}")
    print(f"!!")
    print(f"!! This is NOT a victory bell. Verify INDEPENDENTLY before acting.")
    print(border)
    print()


def emit_ntfy_alert(event: AlertEvent) -> bool:
    """POST the alert to the project's ntfy topic if configured.

    Reads NTFY_TOPIC from environment. Returns True on success, False
    otherwise. Never raises — alerting must never block the main loop.

    SAFETY: If KRYPTOSBOT_DISABLE_NTFY=1 is set OR if pytest is detected
    in sys.modules, the .env file fallback is skipped. This prevents
    test runs from accidentally pushing real ntfy notifications when the
    test forgets to mock urlopen.
    """
    topic = os.environ.get("NTFY_TOPIC", "").strip()

    # Hard-disable env switch
    if os.environ.get("KRYPTOSBOT_DISABLE_NTFY", "").strip() in ("1", "true", "yes"):
        logger.debug("KRYPTOSBOT_DISABLE_NTFY set; skipping push notification")
        return False

    # Test environment guard: if pytest is in sys.modules, never read .env.
    # The test must explicitly opt in to ntfy by setting NTFY_TOPIC in the
    # environment via monkeypatch, AND must mock urlopen.
    in_test = "pytest" in sys.modules

    if not topic and not in_test:
        # Try the .env file at repo root as fallback (production only)
        try:
            env_path = Path(__file__).resolve().parent.parent / ".env"
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("NTFY_TOPIC="):
                        topic = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        except Exception as exc:
            logger.debug("Could not read .env for NTFY_TOPIC: %s", exc)

    if not topic:
        logger.debug("No NTFY_TOPIC configured; skipping push notification")
        return False

    title = f"K4 {event.level.upper()} alert: {event.hypothesis_id[:12]}"
    body_parts = [
        f"crib_score={event.crib_score} bean={event.bean_passed} score={event.score:.2f}",
    ]
    if event.theory_title:
        body_parts.append(event.theory_title[:120])
    body_parts.append("")
    body_parts.append("CONTRADICTION-DETECTOR — verify independently before acting.")
    body = "\n".join(body_parts)

    url = f"https://ntfy.sh/{topic}"
    try:
        priority = "5" if event.level == "breakthrough" else "4"
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Title": title,
                "Priority": priority,
                "Tags": "warning,bell,kryptos",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if 200 <= resp.status < 300:
                logger.info("ntfy push delivered to topic '%s'", topic)
                return True
            logger.warning("ntfy push returned status %s", resp.status)
            return False
    except urllib.error.URLError as exc:
        logger.warning("ntfy push failed (network): %s", exc)
        return False
    except Exception as exc:
        logger.warning("ntfy push failed (unexpected): %s", exc)
        return False


# ── Top-level orchestrator ────────────────────────────────────────────

def process_alerts(
    outcomes: list[WorkerContract],
    threshold: AlertLevel,
    cycle_number: int,
    results_dir: Path = Path("results/breakthroughs"),
    theory_lookup: Optional[dict[str, dict[str, str]]] = None,
) -> list[AlertEvent]:
    """Scan worker outcomes for alert-triggering results.

    For each triggering outcome:
    1. Build an AlertEvent
    2. Persist to results/breakthroughs/
    3. Emit terminal alert
    4. POST to ntfy if configured

    Returns the list of alert events that fired (empty if none).

    All channels are best-effort; failures in one do not block the others.
    The controller's main loop continues regardless of alert outcomes.

    Args:
        outcomes: worker contracts from the cycle
        threshold: minimum AlertLevel to trigger
        cycle_number: current controller cycle (for the event record)
        results_dir: where to persist alert JSON files
        theory_lookup: optional {hypothesis_id: {title, family, mechanism}}
            for richer alert context
    """
    if threshold == AlertLevel.NONE:
        return []

    triggered = []
    for contract in outcomes:
        try:
            level, p_value_status = classify_outcome(contract, threshold)
            if level is None:
                continue

            theory_info = (theory_lookup or {}).get(contract.hypothesis_id, {})

            event = AlertEvent(
                triggered_at=datetime.now(timezone.utc).isoformat(),
                hypothesis_id=contract.hypothesis_id,
                level=level.value,
                crib_score=int(contract.crib_score or 0),
                bean_passed=bool(contract.bean_passed),
                score=float(contract.score or 0.0),
                worker_status=contract.status.value,
                best_plaintext=contract.best_plaintext or "",
                narrative_summary=contract.narrative_summary or "",
                contradiction_note=_build_contradiction_note(contract),
                cycle_number=cycle_number,
                theory_title=theory_info.get("title", ""),
                theory_family=theory_info.get("family", ""),
                theory_mechanism=theory_info.get("mechanism", ""),
                p_value_status=p_value_status,
            )

            # Persist first — survives even if notification channels fail
            try:
                path = write_breakthrough_file(event, results_dir)
                logger.info("Alert persisted to %s", path)
            except Exception as exc:
                logger.error("Failed to persist alert: %s", exc)

            # Terminal alert (best-effort, but the print is important)
            try:
                emit_terminal_alert(event)
            except Exception as exc:
                logger.error("Failed to emit terminal alert: %s", exc)

            # ntfy push (best-effort, often disabled in dev)
            try:
                emit_ntfy_alert(event)
            except Exception as exc:
                logger.error("Failed to emit ntfy alert: %s", exc)

            triggered.append(event)
        except Exception as exc:
            # An unexpected exception in the alert path must not break the run
            logger.exception("Alert processing failed for outcome: %s", exc)
            continue

    return triggered
