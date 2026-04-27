"""
Persistent theory ledger for the KryptosBot research controller.

Single source of truth for all hypothesis state. Replaces journal-style
memory with structured, queryable records. SQLite with WAL mode for
concurrent access from controller + workers.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from .models import (
    TheoryRecord, TheoryStatus, CriticVerdict, CriticDecision,
    ExperimentRecord, WorkerContract, WorkerStatus,
    AnomalyRecord, AnomalyStatus,
    FamilyRecord, FamilyStatus,
    EvidenceLink, EvidenceType,
    ControllerState,
    PursuitLead, PursuitLeadStatus,
    PURSUIT_SOURCE_PURSUE, PURSUIT_SOURCE_VALUES,
)
from .provenance import (
    ProvenanceClaim, EpistemicClass, VerificationStatus,
    ReproducibilityStatus, AllowedUse, ScopeConditions,
)

logger = logging.getLogger("kryptosbot.theory_ledger")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_pursuit_source_verdict(value: Any) -> str:
    """Fail closed to the historical hard-lead semantics."""
    if value in PURSUIT_SOURCE_VALUES:
        return str(value)
    return PURSUIT_SOURCE_PURSUE


class SyntheticModeError(RuntimeError):
    """Raised when a controller launches against a ledger pinned to the
    other mode.

    A ledger is committed to "real" or "synthetic" on its first
    controller run (see ``TheoryLedger.verify_and_pin_synthetic_mode``).
    Subsequent runs in the other mode are refused before any controller
    write happens. This prevents synthetic-CT calibration runs from
    silently mutating the real K4 ledger and vice versa.

    The error message names the existing mode and the attempted mode so
    the operator can either point at the correct ledger or, if the
    pinning is genuinely wrong, manually clear the metadata row.
    """

    def __init__(self, existing: str, attempted: str, db_path: Path) -> None:
        super().__init__(
            f"Ledger {db_path} is pinned to synthetic_mode={existing!r} "
            f"but the current process is launching with synthetic_mode="
            f"{attempted!r}. Real and synthetic runs cannot share a "
            f"ledger. Use a fresh ledger path for the new mode, or "
            f"delete the row from ledger_metadata if the pinning is "
            f"incorrect (rare; verify before clearing)."
        )
        self.existing = existing
        self.attempted = attempted
        self.db_path = db_path


class TheoryLedger:
    """
    SQLite-backed theory ledger with full lifecycle tracking.

    Supports:
    - Theory CRUD with rich metadata
    - Experiment tracking linked to theories
    - Anomaly and family registries
    - Evidence links between theories and results
    - Controller state persistence
    - Deduplication via content-addressed hypothesis_id
    - Search and filtering across all dimensions
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path = "db/theory_ledger.sqlite") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Synthetic-mode pinning
    # ------------------------------------------------------------------

    def verify_and_pin_synthetic_mode(self, synthetic: bool) -> None:
        """Pin the ledger to real or synthetic mode, or refuse mismatch.

        Called by ``ResearchController`` BEFORE bootstrap so any
        mismatch fails before the loop mutates the ledger.

        Behavior:
          - Empty ``ledger_metadata`` (fresh ledger): write the current
            mode and proceed.
          - Existing mode matches current mode: no-op.
          - Existing mode differs: raise ``SyntheticModeError``.

        Empty / unpinned ledgers are accepted in either mode. Once the
        first controller run pins the mode, subsequent runs in the
        other mode are refused. The pinning is persistent across
        process restarts, since it is stored in the ledger itself.

        This is the enforcement layer for ``KRYPTOS_CT_OVERRIDE``.
        Without it, a synthetic-mode controller could append rows to a
        real-K4 ledger (or vice versa) and silently corrupt analysis.
        """
        attempted_mode = "synthetic" if synthetic else "real"

        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM ledger_metadata WHERE key='synthetic_mode'"
            ).fetchone()

            if row is None:
                # First-touch pinning. The ledger commits to whatever
                # mode launched first.
                conn.execute(
                    "INSERT INTO ledger_metadata (key, value, updated_at) "
                    "VALUES ('synthetic_mode', ?, ?)",
                    (attempted_mode, _now_iso()),
                )
                logger.info(
                    "Pinned ledger %s to synthetic_mode=%s",
                    self.db_path, attempted_mode,
                )
                return

            existing_mode = row[0]
            if existing_mode == attempted_mode:
                # Mode matches — proceed without touching metadata.
                return

            # Mismatch. Refuse before bootstrap.
            raise SyntheticModeError(
                existing=existing_mode,
                attempted=attempted_mode,
                db_path=self.db_path,
            )

    def get_pinned_synthetic_mode(self) -> Optional[str]:
        """Return 'real', 'synthetic', or None if unpinned. Read-only.

        Useful for tests and operator inspection. Does not pin or
        modify the ledger.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM ledger_metadata WHERE key='synthetic_mode'"
            ).fetchone()
            return row[0] if row is not None else None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );

                -- Core theory table
                CREATE TABLE IF NOT EXISTS theories (
                    hypothesis_id   TEXT PRIMARY KEY,
                    title           TEXT NOT NULL DEFAULT '',
                    core_claim      TEXT NOT NULL DEFAULT '',
                    mechanism       TEXT NOT NULL DEFAULT '',
                    family          TEXT NOT NULL DEFAULT '',
                    subfamily       TEXT NOT NULL DEFAULT '',
                    tags            TEXT NOT NULL DEFAULT '[]',
                    clue_anchors_used TEXT NOT NULL DEFAULT '[]',
                    anomalies_exploited TEXT NOT NULL DEFAULT '[]',
                    novelty_basis   TEXT NOT NULL DEFAULT '',
                    prior_related   TEXT NOT NULL DEFAULT '[]',
                    minimal_test_spec TEXT NOT NULL DEFAULT '{}',
                    kill_criteria   TEXT NOT NULL DEFAULT '[]',
                    expected_signal TEXT NOT NULL DEFAULT '',
                    compute_cost_estimate TEXT NOT NULL DEFAULT '',
                    estimated_compute_minutes INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'proposed',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    critic_verdict  TEXT NOT NULL DEFAULT '{}',
                    experiment_ids  TEXT NOT NULL DEFAULT '[]',
                    outcome_summary TEXT NOT NULL DEFAULT '',
                    failure_reason  TEXT NOT NULL DEFAULT '',
                    best_score      REAL NOT NULL DEFAULT 0.0,
                    best_plaintext  TEXT NOT NULL DEFAULT '',
                    generalization_strength TEXT NOT NULL DEFAULT '',
                    notes           TEXT NOT NULL DEFAULT '',
                    override_justification TEXT NOT NULL DEFAULT '',
                    -- R3-2 (2026-04-21): DSL spec attached by the theorist
                    -- for Category-A (cipher-family) theories. JSON-encoded
                    -- dict matching HypothesisSpec.to_dict() shape. Empty
                    -- "{}" means no spec — appropriate for Category-B
                    -- methodological theories that route via the legacy
                    -- worker path. See DSL_CUTOVER_CONTRACT §5.
                    dsl_spec        TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_theories_status ON theories(status);
                CREATE INDEX IF NOT EXISTS idx_theories_family ON theories(family);
                CREATE INDEX IF NOT EXISTS idx_theories_score ON theories(best_score DESC);

                -- Experiments table
                CREATE TABLE IF NOT EXISTS experiments (
                    experiment_id   TEXT PRIMARY KEY,
                    hypothesis_id   TEXT NOT NULL REFERENCES theories(hypothesis_id),
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT NOT NULL DEFAULT '',
                    worker_role     TEXT NOT NULL DEFAULT '',
                    config          TEXT NOT NULL DEFAULT '{}',
                    result          TEXT NOT NULL DEFAULT '{}',
                    script_id       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_experiments_hyp ON experiments(hypothesis_id);

                -- Anomalies table
                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id      TEXT PRIMARY KEY,
                    title           TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    source          TEXT NOT NULL DEFAULT '',
                    theories_exploring TEXT NOT NULL DEFAULT '[]',
                    evidence_for    TEXT NOT NULL DEFAULT '[]',
                    evidence_against TEXT NOT NULL DEFAULT '[]',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_anomalies_status ON anomalies(status);

                -- Family registry
                CREATE TABLE IF NOT EXISTS families (
                    family_id       TEXT PRIMARY KEY,
                    name            TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'active',
                    subfamilies     TEXT NOT NULL DEFAULT '[]',
                    total_theories  INTEGER NOT NULL DEFAULT 0,
                    eliminated_theories INTEGER NOT NULL DEFAULT 0,
                    best_score      REAL NOT NULL DEFAULT 0.0,
                    elimination_tier INTEGER NOT NULL DEFAULT 0,
                    elimination_evidence TEXT NOT NULL DEFAULT '',
                    notes           TEXT NOT NULL DEFAULT '',
                    updated_at      TEXT NOT NULL
                );

                -- Evidence links
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id     TEXT PRIMARY KEY,
                    hypothesis_id   TEXT NOT NULL REFERENCES theories(hypothesis_id),
                    evidence_type   TEXT NOT NULL DEFAULT 'experiment_result',
                    content         TEXT NOT NULL DEFAULT '',
                    experiment_id   TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_hyp ON evidence(hypothesis_id);

                -- Controller state (singleton row)
                CREATE TABLE IF NOT EXISTS controller_state (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    state           TEXT NOT NULL DEFAULT '{}'
                );

                -- Provenance claims (epistemic-status layer)
                CREATE TABLE IF NOT EXISTS claims (
                    claim_id TEXT PRIMARY KEY,
                    claim_text TEXT NOT NULL DEFAULT '',
                    epistemic_class TEXT NOT NULL DEFAULT 'hypothesis',
                    scope_conditions TEXT NOT NULL DEFAULT '{}',
                    source_basis TEXT NOT NULL DEFAULT '',
                    verification_status TEXT NOT NULL DEFAULT 'pending_verification',
                    reproducibility_status TEXT NOT NULL DEFAULT 'not_applicable',
                    dependency_chain TEXT NOT NULL DEFAULT '[]',
                    caveats TEXT NOT NULL DEFAULT '[]',
                    allowed_downstream_uses TEXT NOT NULL DEFAULT '[]',
                    last_verified_at TEXT NOT NULL DEFAULT '',
                    last_verified_by TEXT NOT NULL DEFAULT '',
                    evidence_links TEXT NOT NULL DEFAULT '[]',
                    related_anomaly_id TEXT NOT NULL DEFAULT '',
                    related_family_id TEXT NOT NULL DEFAULT '',
                    tags TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_claims_class ON claims(epistemic_class);
                CREATE INDEX IF NOT EXISTS idx_claims_verification ON claims(verification_status);

                -- Day 6: lead-pursuit leads (6-17 crib_score "interesting" band).
                -- A lead is "the question a sub-signal result raises" — distinct
                -- from a theory which is "the question itself". The separation
                -- keeps the ledger auditable when a single source theory can
                -- spawn multiple variant leads.
                CREATE TABLE IF NOT EXISTS pursuit_leads (
                    lead_id             TEXT PRIMARY KEY,
                    source_theory_id    TEXT NOT NULL,
                    source_cycle        INTEGER NOT NULL,
                    crib_score          INTEGER NOT NULL,
                    rationale           TEXT NOT NULL DEFAULT '',
                    suggested_variants  TEXT NOT NULL DEFAULT '[]',
                    status              TEXT NOT NULL DEFAULT 'open',
                    source_verdict      TEXT NOT NULL DEFAULT 'pursue',
                    opened_at           TEXT NOT NULL,
                    closed_at           TEXT NOT NULL DEFAULT '',
                    closed_cycle        INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_pursuit_leads_status
                    ON pursuit_leads(status);
                CREATE INDEX IF NOT EXISTS idx_pursuit_leads_source
                    ON pursuit_leads(source_theory_id);

                INSERT OR IGNORE INTO schema_version VALUES (1);
                INSERT OR IGNORE INTO controller_state (id, state) VALUES (1, '{}');

                -- Synthetic-mode enforcement (2026-04-26): a single-row
                -- key/value table that records whether this ledger has
                -- been touched by a real-K4 run or a synthetic-CT
                -- calibration run. ResearchController calls
                -- verify_and_pin_synthetic_mode before bootstrap so a
                -- mismatch (real launch against a synthetic-tainted
                -- ledger, or vice versa) fails before any controller
                -- mutation. See feedback_synthetic_mode_propagation
                -- for the rationale.
                CREATE TABLE IF NOT EXISTS ledger_metadata (
                    key        TEXT PRIMARY KEY,
                    value      TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Day 5 additive migration: estimated_compute_minutes on theories.
            # Use PRAGMA table_info to check whether the column already exists
            # (existing DBs created before Day 5 won't have it, fresh DBs will
            # because the CREATE TABLE above includes it). ALTER TABLE ADD
            # COLUMN with a DEFAULT is safe and atomic in SQLite.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(theories)")}
            if "estimated_compute_minutes" not in cols:
                conn.execute(
                    "ALTER TABLE theories ADD COLUMN "
                    "estimated_compute_minutes INTEGER NOT NULL DEFAULT 0"
                )
            if "override_justification" not in cols:
                # R2-3 (2026-04-21): additive migration for the
                # exhaustion-override justification field.
                conn.execute(
                    "ALTER TABLE theories ADD COLUMN "
                    "override_justification TEXT NOT NULL DEFAULT ''"
                )
            if "dsl_spec" not in cols:
                # R3-2 (2026-04-21): additive migration for the DSL
                # spec field. Pre-R3-2 rows default to "{}" — correct,
                # since those theories were dispatched via the legacy
                # SDK path and never carried a dsl_spec.
                conn.execute(
                    "ALTER TABLE theories ADD COLUMN "
                    "dsl_spec TEXT NOT NULL DEFAULT '{}'"
                )

            pl_cols = {row[1] for row in conn.execute("PRAGMA table_info(pursuit_leads)")}
            if "source_verdict" not in pl_cols:
                conn.execute(
                    "ALTER TABLE pursuit_leads ADD COLUMN "
                    "source_verdict TEXT NOT NULL DEFAULT 'pursue'"
                )

    # ------------------------------------------------------------------
    # Theory CRUD
    # ------------------------------------------------------------------

    def upsert_theory(self, theory: TheoryRecord) -> None:
        """Insert or update a theory. Deduplicates on hypothesis_id."""
        outcome_statuses = {
            TheoryStatus.COMPLETED,
            TheoryStatus.ELIMINATED,
            TheoryStatus.PROMISING,
        }
        if theory.status in outcome_statuses:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM experiments WHERE hypothesis_id = ? LIMIT 1",
                    (theory.hypothesis_id,),
                ).fetchone()
            has_experiment_trail = bool(theory.experiment_ids) or row is not None
            if not has_experiment_trail:
                audit_note = (
                    "[AUDIT] Outcome-state direct upsert without experiment trail."
                )
                if audit_note not in theory.notes:
                    theory.notes = (
                        f"{audit_note} {theory.notes}".strip()
                        if theory.notes else audit_note
                    )
                logger.warning(
                    "Theory %s upserted directly to outcome state '%s' without "
                    "experiment trail; annotated for audit",
                    theory.hypothesis_id, theory.status.value,
                )
        theory.touch()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO theories (
                    hypothesis_id, title, core_claim, mechanism,
                    family, subfamily, tags, clue_anchors_used,
                    anomalies_exploited, novelty_basis, prior_related,
                    minimal_test_spec, kill_criteria, expected_signal,
                    compute_cost_estimate, estimated_compute_minutes,
                    status, created_at, updated_at,
                    critic_verdict, experiment_ids, outcome_summary,
                    failure_reason, best_score, best_plaintext,
                    generalization_strength, notes, override_justification,
                    dsl_spec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hypothesis_id) DO UPDATE SET
                    title=excluded.title, core_claim=excluded.core_claim,
                    mechanism=excluded.mechanism, family=excluded.family,
                    subfamily=excluded.subfamily, tags=excluded.tags,
                    clue_anchors_used=excluded.clue_anchors_used,
                    anomalies_exploited=excluded.anomalies_exploited,
                    novelty_basis=excluded.novelty_basis,
                    prior_related=excluded.prior_related,
                    minimal_test_spec=excluded.minimal_test_spec,
                    kill_criteria=excluded.kill_criteria,
                    expected_signal=excluded.expected_signal,
                    compute_cost_estimate=excluded.compute_cost_estimate,
                    estimated_compute_minutes=excluded.estimated_compute_minutes,
                    status=excluded.status, updated_at=excluded.updated_at,
                    critic_verdict=excluded.critic_verdict,
                    experiment_ids=excluded.experiment_ids,
                    outcome_summary=excluded.outcome_summary,
                    failure_reason=excluded.failure_reason,
                    best_score=excluded.best_score,
                    best_plaintext=excluded.best_plaintext,
                    generalization_strength=excluded.generalization_strength,
                    notes=excluded.notes,
                    override_justification=excluded.override_justification,
                    dsl_spec=excluded.dsl_spec
            """, self._theory_to_row(theory))

    def get_theory(self, hypothesis_id: str) -> Optional[TheoryRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM theories WHERE hypothesis_id = ?",
                (hypothesis_id,)
            ).fetchone()
            return self._row_to_theory(row) if row else None

    def get_theories_by_status(self, status: TheoryStatus) -> list[TheoryRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM theories WHERE status = ? ORDER BY updated_at DESC",
                (status.value,)
            ).fetchall()
            return [self._row_to_theory(r) for r in rows]

    def get_theories_by_family(self, family: str) -> list[TheoryRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM theories WHERE family = ? ORDER BY best_score DESC",
                (family,)
            ).fetchall()
            return [self._row_to_theory(r) for r in rows]

    def search_theories(
        self,
        query: str = "",
        family: str = "",
        status: str = "",
        min_score: float = 0.0,
        limit: int = 50,
    ) -> list[TheoryRecord]:
        """Search theories with optional filters."""
        conditions = []
        params: list[Any] = []

        if query:
            conditions.append(
                "(title LIKE ? OR core_claim LIKE ? OR mechanism LIKE ? OR notes LIKE ?)"
            )
            q = f"%{query}%"
            params.extend([q, q, q, q])
        if family:
            conditions.append("family = ?")
            params.append(family)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if min_score > 0:
            conditions.append("best_score >= ?")
            params.append(min_score)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM theories {where} ORDER BY best_score DESC, updated_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [self._row_to_theory(r) for r in rows]

    def update_theory_status(
        self,
        hypothesis_id: str,
        status: TheoryStatus,
        **extra_fields: Any,
    ) -> None:
        """Update theory status and optional extra fields atomically."""
        outcome_statuses = {
            TheoryStatus.COMPLETED,
            TheoryStatus.ELIMINATED,
            TheoryStatus.PROMISING,
        }
        if status in outcome_statuses:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT 1 FROM experiments WHERE hypothesis_id = ? LIMIT 1",
                    (hypothesis_id,),
                ).fetchone()
            if row is None:
                raise ValueError(
                    f"Refusing to set {status.value} for {hypothesis_id} without "
                    "a recorded experiment trail"
                )
        fields = {"status": status.value, "updated_at": _now_iso()}
        fields.update(extra_fields)
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [hypothesis_id]
        with self._connect() as conn:
            conn.execute(
                f"UPDATE theories SET {set_clause} WHERE hypothesis_id = ?",
                values,
            )

    def exists(self, hypothesis_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM theories WHERE hypothesis_id = ?",
                (hypothesis_id,)
            ).fetchone()
            return row is not None

    def count_by_status(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as n FROM theories GROUP BY status"
            ).fetchall()
            return {r["status"]: r["n"] for r in rows}

    def count_by_family(self) -> dict[str, dict[str, int]]:
        """Return {family: {total: N, eliminated: N, promising: N}}."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT family,
                       COUNT(*) as total,
                       SUM(CASE WHEN status = 'eliminated' THEN 1 ELSE 0 END) as eliminated,
                       SUM(CASE WHEN status = 'promising' THEN 1 ELSE 0 END) as promising
                FROM theories
                GROUP BY family
            """).fetchall()
            return {
                r["family"]: {
                    "total": r["total"],
                    "eliminated": r["eliminated"],
                    "promising": r["promising"],
                }
                for r in rows
            }

    def recent_outcomes(self, limit: int = 20) -> list[TheoryRecord]:
        """Get recently completed/eliminated theories for learning."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM theories WHERE status IN ('completed', 'eliminated', 'promising') "
                "ORDER BY updated_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [self._row_to_theory(r) for r in rows]

    # ------------------------------------------------------------------
    # Experiment CRUD
    # ------------------------------------------------------------------

    def record_experiment(self, exp: ExperimentRecord) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO experiments
                (experiment_id, hypothesis_id, started_at, completed_at,
                 worker_role, config, result, script_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                exp.experiment_id, exp.hypothesis_id, exp.started_at,
                exp.completed_at, exp.worker_role,
                json.dumps(exp.config),
                json.dumps(exp.result.to_dict() if exp.result else {}),
                exp.script_id,
            ))

    def get_experiments_for_theory(self, hypothesis_id: str) -> list[ExperimentRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM experiments WHERE hypothesis_id = ? ORDER BY started_at DESC",
                (hypothesis_id,)
            ).fetchall()
            return [self._row_to_experiment(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomaly CRUD
    # ------------------------------------------------------------------

    def upsert_anomaly(self, anomaly: AnomalyRecord) -> None:
        anomaly.updated_at = _now_iso()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO anomalies
                (anomaly_id, title, description, status, source,
                 theories_exploring, evidence_for, evidence_against,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(anomaly_id) DO UPDATE SET
                    title=excluded.title, description=excluded.description,
                    status=excluded.status, source=excluded.source,
                    theories_exploring=excluded.theories_exploring,
                    evidence_for=excluded.evidence_for,
                    evidence_against=excluded.evidence_against,
                    updated_at=excluded.updated_at
            """, (
                anomaly.anomaly_id, anomaly.title, anomaly.description,
                anomaly.status.value, anomaly.source,
                json.dumps(anomaly.theories_exploring),
                json.dumps(anomaly.evidence_for),
                json.dumps(anomaly.evidence_against),
                anomaly.created_at, anomaly.updated_at,
            ))

    def get_open_anomalies(self) -> list[AnomalyRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM anomalies WHERE status IN ('open', 'disputed') ORDER BY created_at"
            ).fetchall()
            return [self._row_to_anomaly(r) for r in rows]

    def get_anomaly(self, anomaly_id: str) -> Optional[AnomalyRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM anomalies WHERE anomaly_id = ?", (anomaly_id,)
            ).fetchone()
            return self._row_to_anomaly(row) if row else None

    # ------------------------------------------------------------------
    # Family registry
    # ------------------------------------------------------------------

    def upsert_family(self, family: FamilyRecord) -> None:
        family.updated_at = _now_iso()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO families
                (family_id, name, description, status, subfamilies,
                 total_theories, eliminated_theories, best_score,
                 elimination_tier, elimination_evidence, notes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(family_id) DO UPDATE SET
                    name=excluded.name, description=excluded.description,
                    status=excluded.status, subfamilies=excluded.subfamilies,
                    total_theories=excluded.total_theories,
                    eliminated_theories=excluded.eliminated_theories,
                    best_score=excluded.best_score,
                    elimination_tier=excluded.elimination_tier,
                    elimination_evidence=excluded.elimination_evidence,
                    notes=excluded.notes, updated_at=excluded.updated_at
            """, (
                family.family_id, family.name, family.description,
                family.status.value, json.dumps(family.subfamilies),
                family.total_theories, family.eliminated_theories,
                family.best_score, family.elimination_tier,
                family.elimination_evidence, family.notes,
                family.updated_at,
            ))

    def get_family(self, family_id: str) -> Optional[FamilyRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM families WHERE family_id = ?", (family_id,)
            ).fetchone()
            return self._row_to_family(row) if row else None

    def get_all_families(self) -> list[FamilyRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM families ORDER BY status, name"
            ).fetchall()
            return [self._row_to_family(r) for r in rows]

    def get_active_families(self) -> list[FamilyRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM families WHERE status IN ('active', 'partially_explored') ORDER BY name"
            ).fetchall()
            return [self._row_to_family(r) for r in rows]

    def refresh_family_stats(self) -> None:
        """Recompute family statistics from the theories table."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT family,
                       COUNT(*) as total,
                       SUM(CASE WHEN status = 'eliminated' THEN 1 ELSE 0 END) as eliminated,
                       MAX(best_score) as best
                FROM theories
                GROUP BY family
            """).fetchall()
            for r in rows:
                conn.execute("""
                    UPDATE families SET
                        total_theories = ?, eliminated_theories = ?,
                        best_score = ?, updated_at = ?
                    WHERE family_id = ?
                """, (r["total"], r["eliminated"], r["best"] or 0.0,
                      _now_iso(), r["family"]))

    # ------------------------------------------------------------------
    # Evidence links
    # ------------------------------------------------------------------

    def add_evidence(self, link: EvidenceLink) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO evidence
                (evidence_id, hypothesis_id, evidence_type, content,
                 experiment_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                link.evidence_id, link.hypothesis_id,
                link.evidence_type.value, link.content,
                link.experiment_id, link.created_at,
            ))

    def get_evidence_for_theory(self, hypothesis_id: str) -> list[EvidenceLink]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE hypothesis_id = ? ORDER BY created_at",
                (hypothesis_id,)
            ).fetchall()
            return [self._row_to_evidence(r) for r in rows]

    # ------------------------------------------------------------------
    # Controller state
    # ------------------------------------------------------------------

    def save_controller_state(self, state: ControllerState) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE controller_state SET state = ? WHERE id = 1",
                (json.dumps(state.to_dict()),)
            )

    def load_controller_state(self) -> ControllerState:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM controller_state WHERE id = 1"
            ).fetchone()
            if row and row["state"]:
                return ControllerState.from_dict(json.loads(row["state"]))
            return ControllerState()

    # ------------------------------------------------------------------
    # Summary / reporting
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """High-level dashboard of ledger contents."""
        with self._connect() as conn:
            theory_count = conn.execute("SELECT COUNT(*) as n FROM theories").fetchone()["n"]
            exp_count = conn.execute("SELECT COUNT(*) as n FROM experiments").fetchone()["n"]
            anomaly_count = conn.execute(
                "SELECT COUNT(*) as n FROM anomalies WHERE status IN ('open', 'disputed')"
            ).fetchone()["n"]
            family_count = conn.execute("SELECT COUNT(*) as n FROM families").fetchone()["n"]

            by_status = {}
            for row in conn.execute(
                "SELECT status, COUNT(*) as n FROM theories GROUP BY status"
            ):
                by_status[row["status"]] = row["n"]

            top = conn.execute(
                "SELECT hypothesis_id, title, family, best_score, status "
                "FROM theories WHERE best_score > 0 ORDER BY best_score DESC LIMIT 10"
            ).fetchall()

        return {
            "total_theories": theory_count,
            "total_experiments": exp_count,
            "open_anomalies": anomaly_count,
            "tracked_families": family_count,
            "theories_by_status": by_status,
            "top_scoring": [dict(r) for r in top],
            "generated_at": _now_iso(),
        }

    # ------------------------------------------------------------------
    # Row conversion helpers
    # ------------------------------------------------------------------

    def _theory_to_row(self, t: TheoryRecord) -> tuple:
        return (
            t.hypothesis_id, t.title, t.core_claim, t.mechanism,
            t.family, t.subfamily,
            json.dumps(t.tags), json.dumps(t.clue_anchors_used),
            json.dumps(t.anomalies_exploited), t.novelty_basis,
            json.dumps(t.prior_related_hypotheses),
            json.dumps(t.minimal_test_spec), json.dumps(t.kill_criteria),
            t.expected_signal, t.compute_cost_estimate,
            int(t.estimated_compute_minutes or 0),
            t.status.value, t.created_at, t.updated_at,
            json.dumps(t.critic_verdict.to_dict() if t.critic_verdict else {}),
            json.dumps(t.experiment_ids),
            t.outcome_summary, t.failure_reason,
            t.best_score, t.best_plaintext,
            t.generalization_strength, t.notes,
            t.override_justification or "",
            json.dumps(t.dsl_spec or {}),
        )

    def _row_to_theory(self, row: sqlite3.Row) -> TheoryRecord:
        cv_data = json.loads(row["critic_verdict"]) if row["critic_verdict"] else {}
        cv = CriticVerdict.from_dict(cv_data) if cv_data else None

        return TheoryRecord(
            hypothesis_id=row["hypothesis_id"],
            title=row["title"],
            core_claim=row["core_claim"],
            mechanism=row["mechanism"],
            family=row["family"],
            subfamily=row["subfamily"],
            tags=json.loads(row["tags"]),
            clue_anchors_used=json.loads(row["clue_anchors_used"]),
            anomalies_exploited=json.loads(row["anomalies_exploited"]),
            novelty_basis=row["novelty_basis"],
            prior_related_hypotheses=json.loads(row["prior_related"]),
            minimal_test_spec=json.loads(row["minimal_test_spec"]),
            kill_criteria=json.loads(row["kill_criteria"]),
            expected_signal=row["expected_signal"],
            compute_cost_estimate=row["compute_cost_estimate"],
            estimated_compute_minutes=int(row["estimated_compute_minutes"] or 0),
            status=TheoryStatus(row["status"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            critic_verdict=cv,
            experiment_ids=json.loads(row["experiment_ids"]),
            outcome_summary=row["outcome_summary"],
            failure_reason=row["failure_reason"],
            best_score=row["best_score"],
            best_plaintext=row["best_plaintext"],
            generalization_strength=row["generalization_strength"],
            notes=row["notes"],
            override_justification=(
                row["override_justification"]
                if "override_justification" in row.keys() else ""
            ),
            dsl_spec=(
                json.loads(row["dsl_spec"])
                if "dsl_spec" in row.keys() and row["dsl_spec"]
                else {}
            ),
        )

    def _row_to_experiment(self, row: sqlite3.Row) -> ExperimentRecord:
        result_data = json.loads(row["result"]) if row["result"] else {}
        result = WorkerContract.from_dict(result_data) if result_data else None
        return ExperimentRecord(
            experiment_id=row["experiment_id"],
            hypothesis_id=row["hypothesis_id"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            worker_role=row["worker_role"],
            config=json.loads(row["config"]),
            result=result,
            script_id=row["script_id"],
        )

    def _row_to_anomaly(self, row: sqlite3.Row) -> AnomalyRecord:
        return AnomalyRecord(
            anomaly_id=row["anomaly_id"],
            title=row["title"],
            description=row["description"],
            status=AnomalyStatus(row["status"]),
            source=row["source"],
            theories_exploring=json.loads(row["theories_exploring"]),
            evidence_for=json.loads(row["evidence_for"]),
            evidence_against=json.loads(row["evidence_against"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _row_to_family(self, row: sqlite3.Row) -> FamilyRecord:
        return FamilyRecord(
            family_id=row["family_id"],
            name=row["name"],
            description=row["description"],
            status=FamilyStatus(row["status"]),
            subfamilies=json.loads(row["subfamilies"]),
            total_theories=row["total_theories"],
            eliminated_theories=row["eliminated_theories"],
            best_score=row["best_score"],
            elimination_tier=row["elimination_tier"],
            elimination_evidence=row["elimination_evidence"],
            notes=row["notes"],
            updated_at=row["updated_at"],
        )

    def _row_to_evidence(self, row: sqlite3.Row) -> EvidenceLink:
        return EvidenceLink(
            evidence_id=row["evidence_id"],
            hypothesis_id=row["hypothesis_id"],
            evidence_type=EvidenceType(row["evidence_type"]),
            content=row["content"],
            experiment_id=row["experiment_id"],
            created_at=row["created_at"],
        )

    # ------------------------------------------------------------------
    # Provenance claims CRUD
    # ------------------------------------------------------------------

    def upsert_claim(self, claim: ProvenanceClaim) -> None:
        claim.updated_at = _now_iso()
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO claims
                (claim_id, claim_text, epistemic_class, scope_conditions,
                 source_basis, verification_status, reproducibility_status,
                 dependency_chain, caveats, allowed_downstream_uses,
                 last_verified_at, last_verified_by, evidence_links,
                 related_anomaly_id, related_family_id, tags,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(claim_id) DO UPDATE SET
                    claim_text=excluded.claim_text,
                    epistemic_class=excluded.epistemic_class,
                    scope_conditions=excluded.scope_conditions,
                    source_basis=excluded.source_basis,
                    verification_status=excluded.verification_status,
                    reproducibility_status=excluded.reproducibility_status,
                    dependency_chain=excluded.dependency_chain,
                    caveats=excluded.caveats,
                    allowed_downstream_uses=excluded.allowed_downstream_uses,
                    last_verified_at=excluded.last_verified_at,
                    last_verified_by=excluded.last_verified_by,
                    evidence_links=excluded.evidence_links,
                    related_anomaly_id=excluded.related_anomaly_id,
                    related_family_id=excluded.related_family_id,
                    tags=excluded.tags,
                    updated_at=excluded.updated_at
            """, (
                claim.claim_id, claim.claim_text,
                claim.epistemic_class.value,
                json.dumps(claim.scope_conditions.to_dict()),
                claim.source_basis,
                claim.verification_status.value,
                claim.reproducibility_status.value,
                json.dumps(claim.dependency_chain),
                json.dumps(claim.caveats),
                json.dumps([u.value for u in claim.allowed_downstream_uses]),
                claim.last_verified_at, claim.last_verified_by,
                json.dumps(claim.evidence_links),
                claim.related_anomaly_id, claim.related_family_id,
                json.dumps(claim.tags),
                claim.created_at, claim.updated_at,
            ))

    def get_claim(self, claim_id: str) -> Optional[ProvenanceClaim]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM claims WHERE claim_id = ?", (claim_id,)
            ).fetchone()
            return self._row_to_claim(row) if row else None

    def get_all_claims(self) -> list[ProvenanceClaim]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM claims ORDER BY epistemic_class, claim_id"
            ).fetchall()
            return [self._row_to_claim(r) for r in rows]

    def get_claims_by_class(
        self, epistemic_class: EpistemicClass
    ) -> list[ProvenanceClaim]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM claims WHERE epistemic_class = ? ORDER BY claim_id",
                (epistemic_class.value,)
            ).fetchall()
            return [self._row_to_claim(r) for r in rows]

    def delete_claim(self, claim_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM claims WHERE claim_id = ?", (claim_id,))

    def _row_to_claim(self, row: sqlite3.Row) -> ProvenanceClaim:
        return ProvenanceClaim(
            claim_id=row["claim_id"],
            claim_text=row["claim_text"],
            epistemic_class=EpistemicClass(row["epistemic_class"]),
            scope_conditions=ScopeConditions.from_dict(
                json.loads(row["scope_conditions"]) if row["scope_conditions"] else {}
            ),
            source_basis=row["source_basis"],
            verification_status=VerificationStatus(row["verification_status"]),
            reproducibility_status=ReproducibilityStatus(row["reproducibility_status"]),
            dependency_chain=json.loads(row["dependency_chain"]),
            caveats=json.loads(row["caveats"]),
            allowed_downstream_uses=[
                AllowedUse(u) for u in json.loads(row["allowed_downstream_uses"])
            ],
            last_verified_at=row["last_verified_at"],
            last_verified_by=row["last_verified_by"],
            evidence_links=json.loads(row["evidence_links"]),
            related_anomaly_id=row["related_anomaly_id"],
            related_family_id=row["related_family_id"],
            tags=json.loads(row["tags"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ------------------------------------------------------------------
    # Startup reconciliation
    # ------------------------------------------------------------------

    def reconcile_orphaned_running(self) -> list[str]:
        """Transition theories stuck in RUNNING to COMPLETED.

        Called at startup to recover from interrupted sessions. Any theory
        in RUNNING status has no running worker (since the process restarted),
        so it must be marked as completed with a failure reason.

        Returns list of hypothesis_ids that were reconciled.
        """
        reconciled = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT hypothesis_id FROM theories WHERE status = 'running'"
            ).fetchall()
            for row in rows:
                hid = row["hypothesis_id"]
                conn.execute(
                    "UPDATE theories SET status = ?, failure_reason = ?, updated_at = ? "
                    "WHERE hypothesis_id = ?",
                    (
                        TheoryStatus.COMPLETED.value,
                        "Orphaned: found in RUNNING at startup after process restart",
                        _now_iso(),
                        hid,
                    ),
                )
                reconciled.append(hid)
        return reconciled

    # ------------------------------------------------------------------
    # Day 6: Pursuit-lead CRUD
    # ------------------------------------------------------------------

    def insert_pursuit_lead(self, lead: PursuitLead) -> None:
        """Insert a new pursuit lead. Caller must supply a unique lead_id."""
        source_verdict = _normalize_pursuit_source_verdict(lead.source_verdict)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO pursuit_leads (
                    lead_id, source_theory_id, source_cycle, crib_score,
                    rationale, suggested_variants, status, source_verdict,
                    opened_at, closed_at, closed_cycle
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lead.lead_id,
                    lead.source_theory_id,
                    int(lead.source_cycle),
                    int(lead.crib_score),
                    lead.rationale or "",
                    json.dumps(lead.suggested_variants or []),
                    lead.status.value,
                    source_verdict,
                    lead.opened_at or _now_iso(),
                    lead.closed_at or "",
                    lead.closed_cycle,
                ),
            )

    def _row_to_pursuit_lead(self, row: sqlite3.Row) -> PursuitLead:
        try:
            variants = json.loads(row["suggested_variants"] or "[]")
        except (json.JSONDecodeError, TypeError):
            variants = []
        if not isinstance(variants, list):
            variants = []
        try:
            status = PursuitLeadStatus(row["status"])
        except (ValueError, KeyError):
            status = PursuitLeadStatus.OPEN
        # source_verdict column is post-migration; rows written before the
        # migration ran will have a missing key when accessed positionally.
        # sqlite3.Row raises IndexError / the underlying access raises. Fall
        # back to "pursue" so pre-existing rows (all of which were hard
        # leads under the old gate) are interpreted correctly.
        try:
            source_verdict = _normalize_pursuit_source_verdict(
                row["source_verdict"]
            )
        except (IndexError, KeyError):
            source_verdict = PURSUIT_SOURCE_PURSUE
        return PursuitLead(
            lead_id=row["lead_id"],
            source_theory_id=row["source_theory_id"],
            source_cycle=int(row["source_cycle"] or 0),
            crib_score=int(row["crib_score"] or 0),
            rationale=row["rationale"] or "",
            suggested_variants=[str(v) for v in variants],
            status=status,
            source_verdict=source_verdict,
            opened_at=row["opened_at"] or "",
            closed_at=row["closed_at"] or "",
            closed_cycle=row["closed_cycle"],
        )

    def get_open_pursuit_leads(
        self,
        limit: int = 20,
        *,
        source_verdict: Optional[str] = None,
    ) -> list[PursuitLead]:
        """Return the currently open pursuit leads, newest first.

        If `source_verdict` is given, filter to rows matching that
        provenance tag (e.g. "pursue" for hard leads, "skip_variants"
        for soft leads). If None, return all open leads regardless.
        """
        with self._connect() as conn:
            if source_verdict is None:
                rows = conn.execute(
                    """
                    SELECT * FROM pursuit_leads
                     WHERE status = ?
                     ORDER BY source_cycle DESC, opened_at DESC
                     LIMIT ?
                    """,
                    (PursuitLeadStatus.OPEN.value, int(limit)),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM pursuit_leads
                     WHERE status = ? AND source_verdict = ?
                     ORDER BY source_cycle DESC, opened_at DESC
                     LIMIT ?
                    """,
                    (
                        PursuitLeadStatus.OPEN.value,
                        str(source_verdict),
                        int(limit),
                    ),
                ).fetchall()
        return [self._row_to_pursuit_lead(r) for r in rows]

    def get_pursuit_lead(self, lead_id: str) -> Optional[PursuitLead]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pursuit_leads WHERE lead_id = ?",
                (lead_id,),
            ).fetchone()
        return self._row_to_pursuit_lead(row) if row else None

    def close_pursuit_lead(
        self,
        lead_id: str,
        *,
        status: PursuitLeadStatus,
        closed_cycle: int,
    ) -> None:
        """Close a pursuit lead by marking it pursued or stale."""
        if status == PursuitLeadStatus.OPEN:
            raise ValueError("close_pursuit_lead requires a terminal status")
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE pursuit_leads
                   SET status = ?, closed_at = ?, closed_cycle = ?
                 WHERE lead_id = ?
                """,
                (status.value, _now_iso(), int(closed_cycle), lead_id),
            )

    def auto_close_stale_pursuit_leads(
        self,
        *,
        current_cycle: int,
        stale_after_cycles: int,
    ) -> list[str]:
        """Close open leads that have been open for >= stale_after_cycles.

        Returns the list of closed lead_ids so the caller can log the action.
        stale_after_cycles=0 disables auto-close.
        """
        if stale_after_cycles <= 0:
            return []
        cutoff = current_cycle - stale_after_cycles
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT lead_id FROM pursuit_leads
                 WHERE status = ? AND source_cycle <= ?
                """,
                (PursuitLeadStatus.OPEN.value, int(cutoff)),
            ).fetchall()
            closed_ids = [r["lead_id"] for r in rows]
            for lid in closed_ids:
                conn.execute(
                    """
                    UPDATE pursuit_leads
                       SET status = ?, closed_at = ?, closed_cycle = ?
                     WHERE lead_id = ?
                    """,
                    (
                        PursuitLeadStatus.STALE.value,
                        _now_iso(),
                        int(current_cycle),
                        lid,
                    ),
                )
        return closed_ids

    def count_pursuit_leads_by_status(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM pursuit_leads GROUP BY status"
            ).fetchall()
        return {r["status"]: int(r["n"]) for r in rows}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        pass  # connections are per-operation, nothing to close

    def __enter__(self) -> TheoryLedger:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
