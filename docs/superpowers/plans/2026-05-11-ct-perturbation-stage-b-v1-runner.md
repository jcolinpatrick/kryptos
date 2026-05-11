# CT-Perturbation Stage B v1 Sweep Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 full sweep runner for the Stage B CT-perturbation campaign so `--execute-full` actually enumerates all H2 variants in the operator-supplied ambiguous-positions manifest, evaluates them against the inherited Stage A scoring pipeline (3 families × 2 alphabets × keywords), and writes the inherited JSONL artifact schema with checkpointing.

**Architecture:** Inherit Stage A's `SweepConfig`/`SweepResults`/`evaluate_one_variant`/`run_sweep` patterns verbatim, adapting only the variant type (`CTVariantH2` instead of `CTVariant`) and the variant enumerator. `ScorerContext.build` is duck-type compatible — both variant types expose `.ct`, `.ct_sha256`, `.distance`, `.variant_id`. Scoring per (variant, family, alphabet, keyword) cell is unchanged. Multiprocessing pool follows Stage A's `spawn` context + per-future timeout pattern (per `feedback_pool_worker_no_per_task_timeout.md`).

**Tech Stack:**
- Python 3.11+ stdlib only (no new deps)
- `kryptosbot.ct_perturbation` — framework primitives (already implemented)
- `kryptosbot.null_baselines` — ngram null distribution cache (already wired)
- `kryptos.kernel.scoring` — quadgram scorer (already wired)
- Existing Stage A symbols imported by name from `scripts.campaigns.ct_perturbation_stage_a`

---

## File Structure

| File | Responsibility | Modify or Create |
|---|---|---|
| `scripts/campaigns/ct_perturbation_stage_b.py` | Add `SweepConfig`, `SweepResults`, `VariantEvalResult`, `evaluate_one_h2_variant`, `run_h2_sweep`, `_worker_evaluate_h2`, `_h2_candidate_row`, `_h2_summary_only`, `_h2_checkpoint`, `_build_h2_summary`. Wire `--execute-full` to call `run_h2_sweep`. | Modify (extend stub) |
| `tests/test_ct_perturbation_stage_b.py` | Add `TestSweepConfig`, `TestSweepResults`, `TestH2CandidateRow`, `TestEvaluateOneH2Variant`, `TestWorkerEvaluateH2`, `TestH2Checkpoint`, `TestRunH2Sweep`, `TestExecuteFullCli` | Modify (extend existing tests) |
| `results/ct_perturbation_stage_b/<run_id>/` | Runtime artifact dir, created per run | Run-time (not in plan) |

No new top-level modules. All v1 work is inside the existing Stage B runner file plus the existing test file.

---

## Task 1: Inherit Stage A symbols and verify baseline

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py` (top of file, after existing imports)

- [ ] **Step 1: Confirm existing tests green before modifying**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py -q`
Expected: PASS for all 32 collected tests.

- [ ] **Step 2: Add Stage A symbol imports**

In `scripts/campaigns/ct_perturbation_stage_b.py`, after the existing `from kryptosbot.ct_perturbation import (...)` block, add:

```python
from scripts.campaigns.ct_perturbation_stage_a import (
    KeywordSource,
    atomic_write_json,
    load_keywords,
    _git_commit,
    _module_sha,
)
```

- [ ] **Step 3: Run existing tests again to confirm import didn't break anything**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py -q`
Expected: PASS (32 tests).

- [ ] **Step 4: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py
git commit -m "stage_b: inherit Stage A keyword/IO helpers for v1 sweep runner"
```

---

## Task 2: Add Stage B SweepConfig dataclass

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py` (new section after Stage A imports)
- Test: `tests/test_ct_perturbation_stage_b.py` (new `TestSweepConfig` class)

- [ ] **Step 1: Write the failing test**

In `tests/test_ct_perturbation_stage_b.py`, append:

```python
class TestSweepConfig:
    def test_sweep_config_defaults(self):
        from scripts.campaigns.ct_perturbation_stage_b import SweepConfig
        from kryptosbot.ct_perturbation import SUPPORTED_FAMILIES, SUPPORTED_ALPHABET_KINDS

        cfg = SweepConfig(ct="A" * 97, keywords=["TEST"], manifest=None)
        assert cfg.families == SUPPORTED_FAMILIES
        assert cfg.alphabet_kinds == SUPPORTED_ALPHABET_KINDS
        assert cfg.universe_size == 1
        assert cfg.include_h0 is False
        assert cfg.max_h2_variants is None
        assert cfg.max_configs is None
        assert cfg.keyword_limit is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestSweepConfig -v`
Expected: FAIL — `SweepConfig` not yet defined.

- [ ] **Step 3: Add SweepConfig to Stage B runner**

```python
@dataclass
class SweepConfig:
    """Internal config bundle for the Stage B H2 sweep driver.

    Mirrors Stage A's SweepConfig but typed against ``AmbiguousPositionsManifest``
    and uses ``max_h2_variants`` rather than the H1 ``max_ct_variants`` cap.
    """
    ct: str
    keywords: list[str]
    manifest: AmbiguousPositionsManifest | None
    families: tuple[CipherVariant, ...] = SUPPORTED_FAMILIES
    alphabet_kinds: tuple[str, ...] = SUPPORTED_ALPHABET_KINDS
    universe_size: int = 1
    policy: AlertPolicy = field(default_factory=AlertPolicy)
    include_h0: bool = False
    max_h2_variants: int | None = None
    max_configs: int | None = None
    keyword_limit: int | None = None
    crib_dict: dict[int, str] = field(default_factory=lambda: dict(CANONICAL_CRIB_DICT))
    run_id_for_logging: str = ""
```

Ensure `from dataclasses import dataclass, field` is at the top.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestSweepConfig -v`
Expected: PASS.

- [ ] **Step 5: Run full Stage B test suite to confirm no regressions**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add SweepConfig dataclass for H2 sweep driver"
```

---

## Task 3: Add SweepResults and VariantEvalResult dataclasses

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestSweepResults:
    def test_sweep_results_defaults(self):
        from scripts.campaigns.ct_perturbation_stage_b import SweepResults
        r = SweepResults()
        assert r.candidates_evaluated == 0
        assert r.alerts == []
        assert r.watchlist == []
        assert r.bean_pass_count == 0
        assert r.variants_completed == 0
        assert r.last_completed_variant_id is None
        assert r.errors == []

    def test_variant_eval_result_shape(self):
        from scripts.campaigns.ct_perturbation_stage_b import VariantEvalResult
        v = VariantEvalResult(
            variant_id="H2_test", n_evaluated=4, alerts=[], watchlist=[],
            top_candidates=[], bean_pass_count=0, rejection_reason_counts={},
            trace_rows=[],
        )
        assert v.variant_id == "H2_test"
        assert v.n_evaluated == 4
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestSweepResults -v`
Expected: FAIL.

- [ ] **Step 3: Add both dataclasses**

```python
@dataclass
class SweepResults:
    """Accumulator for H2 sweep state."""
    candidates_evaluated: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)
    watchlist: list[dict[str, Any]] = field(default_factory=list)
    top_n: TopNHeap = field(default_factory=lambda: TopNHeap(capacity=100))
    bean_pass_count: int = 0
    by_family_alert_count: dict[str, int] = field(default_factory=dict)
    by_alphabet_alert_count: dict[str, int] = field(default_factory=dict)
    rejection_reason_counts: dict[str, int] = field(default_factory=dict)
    variants_completed: int = 0
    last_completed_variant_id: str | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class VariantEvalResult:
    """Per-H2-variant result emitted by evaluate_one_h2_variant."""
    variant_id: str
    n_evaluated: int
    alerts: list[dict[str, Any]]
    watchlist: list[dict[str, Any]]
    top_candidates: list[tuple[float, dict[str, Any]]]
    bean_pass_count: int
    rejection_reason_counts: dict[str, int]
    trace_rows: list[dict[str, Any]]
```

- [ ] **Step 4: Verify the test passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestSweepResults -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add SweepResults and VariantEvalResult dataclasses"
```

---

## Task 4: Add H2 candidate row builder and helper utilities

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestH2CandidateRow:
    def test_h2_candidate_row_schema(self):
        from scripts.campaigns.ct_perturbation_stage_b import _h2_candidate_row
        from kryptosbot.ct_perturbation import CTVariantH2, CandidateScore, _ct_sha256
        from kryptos.kernel.constants import CT
        from kryptos.kernel.transforms.vigenere import CipherVariant

        new_ct = "A" + CT[1:21] + "Z" + CT[22:]
        v = CTVariantH2(
            variant_id="H2_p00_F->A_p21_F->Z", distance=2,
            pos1=0, old1=CT[0], new1="A", pos2=21, old2=CT[21], new2="Z",
            ct=new_ct, ct_sha256=_ct_sha256(new_ct),
        )
        score = CandidateScore(
            crib_score=18, crib_total=24, bean_passed=True, bean_variant="vigenere",
            ngram_score=-3.4, crib_p_raw=1e-10, ngram_p_raw=1e-3,
            ngram_null_available=True, p_combined_raw=1e-13, p_adjusted=1e-7,
            alert_class="watchlist", rejection_reason="",
        )
        row = _h2_candidate_row(
            run_id="test_run", variant=v, family=CipherVariant.VIGENERE,
            alphabet_kind="AZ", keyword="PALIMPSEST", score=score, pt="X" * 97,
        )
        assert row["run_id"] == "test_run"
        assert row["distance"] == 2
        assert row["pos_pair"] == [0, 21]
        # pos 21 is a crib position; pos 0 is not — crib_overlapping == 1
        assert row["crib_overlapping"] == 1
        assert row["family"] == "vigenere"
        assert row["score"]["crib_score"] == 18
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestH2CandidateRow -v`
Expected: FAIL.

- [ ] **Step 3: Implement `_h2_candidate_row`, `_h2_summary_only`, `_rejection_reason_bucket`**

```python
_CRIB_POSITIONS_SET: frozenset[int] = frozenset(CANONICAL_CRIB_DICT.keys())


def _rejection_reason_bucket(reason: str | None) -> str:
    if not reason:
        return "kept"
    if "crib" in reason:
        return "crib_floor"
    if "bean" in reason:
        return "bean_fail"
    if "ngram" in reason:
        return "ngram_floor"
    if "null" in reason:
        return "null_unavailable"
    return "other"


def _h2_candidate_row(
    run_id: str,
    variant: CTVariantH2,
    family: CipherVariant,
    alphabet_kind: str,
    keyword: str,
    score: CandidateScore,
    pt: str,
) -> dict[str, Any]:
    crib_overlapping = sum(
        1 for p in (variant.pos1, variant.pos2) if p in _CRIB_POSITIONS_SET
    )
    return {
        "run_id": run_id,
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "variant_id": variant.variant_id,
        "distance": variant.distance,
        "pos_pair": [variant.pos1, variant.pos2],
        "chars_pair": [variant.old1, variant.new1, variant.old2, variant.new2],
        "crib_overlapping": crib_overlapping,
        "ct_sha256": variant.ct_sha256,
        "family": family.value,
        "alphabet": alphabet_kind,
        "keyword": keyword,
        "effective_keyword_period": len(keyword),
        "pt": pt,
        "score": {
            "crib_score": score.crib_score,
            "crib_total": score.crib_total,
            "bean_passed": score.bean_passed,
            "bean_variant": score.bean_variant,
            "ngram_score": score.ngram_score,
            "crib_p_raw": score.crib_p_raw,
            "ngram_p_raw": score.ngram_p_raw,
            "ngram_null_available": score.ngram_null_available,
            "p_combined_raw": score.p_combined_raw,
            "p_adjusted": score.p_adjusted,
            "alert_class": score.alert_class,
            "rejection_reason": score.rejection_reason,
        },
    }


def _h2_summary_only(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "variant_id": row["variant_id"],
        "pos_pair": row["pos_pair"],
        "chars_pair": row["chars_pair"],
        "crib_overlapping": row["crib_overlapping"],
        "family": row["family"],
        "alphabet": row["alphabet"],
        "keyword": row["keyword"],
        "crib_score": row["score"]["crib_score"],
        "bean_passed": row["score"]["bean_passed"],
        "ngram_score": row["score"]["ngram_score"],
        "p_adjusted": row["score"]["p_adjusted"],
        "alert_class": row["score"]["alert_class"],
    }
```

- [ ] **Step 4: Verify test passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestH2CandidateRow -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add H2 candidate row builder with pos_pair and crib_overlapping fields"
```

---

## Task 5: Add `evaluate_one_h2_variant`

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestEvaluateOneH2Variant:
    def test_evaluate_one_h2_variant_under_canonical_ct(self):
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepConfig, evaluate_one_h2_variant,
        )
        from kryptosbot.ct_perturbation import CTVariantH2, _ct_sha256
        from kryptos.kernel.constants import CT

        new_ct = CT[:5] + "A" + CT[6:90] + "B" + CT[91:]
        v = CTVariantH2(
            variant_id="H2_p05_X->A_p90_X->B", distance=2,
            pos1=5, old1=CT[5], new1="A", pos2=90, old2=CT[90], new2="B",
            ct=new_ct, ct_sha256=_ct_sha256(new_ct),
        )
        cfg = SweepConfig(
            ct=CT, keywords=["PALIMPSEST", "ABSCISSA"],
            manifest=None, universe_size=4_500,
        )
        result = evaluate_one_h2_variant(
            v, cfg, ngram_scorer=None, ngram_dist_az=None, ngram_dist_ka=None,
        )
        # 3 families × 2 alphabets × 2 keywords = 12 configs
        assert result.n_evaluated == 12
        assert result.alerts == []

    def test_evaluate_one_h2_variant_respects_max_configs(self):
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepConfig, evaluate_one_h2_variant,
        )
        from kryptosbot.ct_perturbation import CTVariantH2, _ct_sha256
        from kryptos.kernel.constants import CT

        new_ct = CT[:5] + "A" + CT[6:90] + "B" + CT[91:]
        v = CTVariantH2(
            variant_id="H2_test_cap", distance=2,
            pos1=5, old1=CT[5], new1="A", pos2=90, old2=CT[90], new2="B",
            ct=new_ct, ct_sha256=_ct_sha256(new_ct),
        )
        cfg = SweepConfig(
            ct=CT, keywords=["A", "B", "C", "D"],
            manifest=None, universe_size=24, max_configs=3,
        )
        result = evaluate_one_h2_variant(
            v, cfg, ngram_scorer=None, ngram_dist_az=None, ngram_dist_ka=None,
        )
        assert result.n_evaluated == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestEvaluateOneH2Variant -v`
Expected: FAIL.

- [ ] **Step 3: Implement `evaluate_one_h2_variant`**

```python
def evaluate_one_h2_variant(
    variant: CTVariantH2,
    cfg: SweepConfig,
    *,
    ngram_scorer: Any,
    ngram_dist_az: Any,
    ngram_dist_ka: Any,
    trace_first_configs: int = 0,
) -> VariantEvalResult:
    """Score every (family × alphabet × keyword) cell for one H2 variant.

    ScorerContext.build is duck-type compatible: CTVariantH2 exposes
    .ct, .ct_sha256, .distance, .variant_id — same fields ScorerContext
    reads from a CTVariant.
    """
    keywords = (
        cfg.keywords if cfg.keyword_limit is None
        else cfg.keywords[: cfg.keyword_limit]
    )
    alerts: list[dict[str, Any]] = []
    watch: list[dict[str, Any]] = []
    heap_items: list[tuple[float, dict[str, Any]]] = []
    bean_pass = 0
    n_eval = 0
    rejection_counts: dict[str, int] = {}
    trace_rows: list[dict[str, Any]] = []

    ctx_by_kind = {
        "AZ": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_az, alphabet_kind="AZ",  # type: ignore[arg-type]
        ),
        "KA": ScorerContext.build(
            variant, cfg.crib_dict, ngram_dist=ngram_dist_ka, alphabet_kind="KA",  # type: ignore[arg-type]
        ),
    }

    for family in cfg.families:
        for kind in cfg.alphabet_kinds:
            ctx = ctx_by_kind[kind]
            for keyword in keywords:
                if cfg.max_configs is not None and n_eval >= cfg.max_configs:
                    return VariantEvalResult(
                        variant_id=variant.variant_id, n_evaluated=n_eval,
                        alerts=alerts, watchlist=watch,
                        top_candidates=heap_items, bean_pass_count=bean_pass,
                        rejection_reason_counts=rejection_counts,
                        trace_rows=trace_rows,
                    )
                score, pt = score_candidate_ct_parametric(
                    ctx, keyword=keyword, family=family,
                    alphabet_kind=kind, universe_size=cfg.universe_size,
                    policy=cfg.policy, ngram_scorer=ngram_scorer,
                )
                n_eval += 1
                reason = _rejection_reason_bucket(score.rejection_reason)
                rejection_counts[reason] = rejection_counts.get(reason, 0) + 1
                if score.bean_passed:
                    bean_pass += 1
                if len(trace_rows) < trace_first_configs:
                    trace_rows.append({
                        "variant_id": variant.variant_id,
                        "variant_distance": variant.distance,
                        "pos_pair": [variant.pos1, variant.pos2],
                        "family": family.value,
                        "alphabet": kind,
                        "keyword": keyword,
                        "effective_keyword_period": len(keyword),
                        "rejection_reason": score.rejection_reason,
                        "alert_class": score.alert_class,
                    })
                if score.alert_class in ("alert", "watchlist", "watchlist_null_unavailable"):
                    payload = _h2_candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    if score.alert_class == "alert":
                        alerts.append(payload)
                    else:
                        watch.append(payload)
                key = float(score.crib_score) * 1000.0 + float(
                    score.ngram_score if score.ngram_score is not None else -10.0
                )
                if score.crib_score >= 10:
                    payload = _h2_candidate_row(
                        cfg.run_id_for_logging, variant, family, kind,
                        keyword, score, pt,
                    )
                    heap_items.append((key, payload))

    return VariantEvalResult(
        variant_id=variant.variant_id, n_evaluated=n_eval,
        alerts=alerts, watchlist=watch, top_candidates=heap_items,
        bean_pass_count=bean_pass, rejection_reason_counts=rejection_counts,
        trace_rows=trace_rows,
    )
```

- [ ] **Step 4: Verify tests pass**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestEvaluateOneH2Variant -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add evaluate_one_h2_variant per-variant evaluator"
```

---

## Task 6: Add `_worker_evaluate_h2` multiprocessing entry

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestWorkerEvaluateH2:
    def test_worker_eval_matches_inprocess(self):
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepConfig, evaluate_one_h2_variant, _worker_evaluate_h2,
        )
        from kryptosbot.ct_perturbation import CTVariantH2, _ct_sha256
        from kryptos.kernel.constants import CT

        new_ct = CT[:5] + "A" + CT[6:90] + "B" + CT[91:]
        v = CTVariantH2(
            variant_id="H2_mp_smoke", distance=2,
            pos1=5, old1=CT[5], new1="A", pos2=90, old2=CT[90], new2="B",
            ct=new_ct, ct_sha256=_ct_sha256(new_ct),
        )
        cfg = SweepConfig(
            ct=CT, keywords=["PALIMPSEST"], manifest=None, universe_size=6,
        )
        inproc = evaluate_one_h2_variant(
            v, cfg, ngram_scorer=None, ngram_dist_az=None, ngram_dist_ka=None,
        )
        worker = _worker_evaluate_h2((v, cfg))
        assert inproc.variant_id == worker.variant_id
        assert inproc.n_evaluated == worker.n_evaluated
        assert inproc.bean_pass_count == worker.bean_pass_count
        assert len(inproc.alerts) == len(worker.alerts)
        assert len(inproc.watchlist) == len(worker.watchlist)
```

- [ ] **Step 2: Verify test fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestWorkerEvaluateH2 -v`
Expected: FAIL.

- [ ] **Step 3: Implement `_worker_evaluate_h2` (mirror Stage A's `_worker_evaluate`)**

Add the function `_worker_evaluate_h2((variant, cfg))` that lazily reconstructs `ngram_scorer` via `get_default_scorer()` and the AZ/KA null distributions via `kryptosbot.null_baselines.get_cached`, then calls `evaluate_one_h2_variant`. Pattern is identical to Stage A's `_worker_evaluate` — copy from `scripts/campaigns/ct_perturbation_stage_a.py:1073`.

Ensure `from kryptos.kernel.scoring import get_default_scorer` is at the top of the file.

- [ ] **Step 4: Verify test passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestWorkerEvaluateH2 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add _worker_evaluate_h2 multiprocessing entry"
```

---

## Task 7: Add `_h2_checkpoint` and `_build_h2_summary`

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestH2Checkpoint:
    def test_h2_checkpoint_payload(self, tmp_path):
        import json
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepResults, _h2_checkpoint,
        )
        results = SweepResults()
        results.candidates_evaluated = 100
        results.variants_completed = 4
        results.last_completed_variant_id = "H2_test"
        results.bean_pass_count = 2
        path = tmp_path / "progress.json"
        _h2_checkpoint(
            path, results, started_at=0.0, started_at_iso="2026-01-01T00:00:00Z",
            variants_total=10, expected_total=10000, workers=4, status="running",
        )
        payload = json.loads(path.read_text())
        assert payload["status"] == "running"
        assert payload["variants_completed"] == 4
        assert payload["variants_total"] == 10
        assert payload["candidates_evaluated"] == 100
        assert payload["expected_total_config_cardinality"] == 10000
        assert payload["bean_pass_count"] == 2
        assert payload["last_completed_variant_id"] == "H2_test"

    def test_build_h2_summary_minimum_fields(self):
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepResults, _build_h2_summary,
        )
        results = SweepResults()
        results.candidates_evaluated = 75
        results.variants_completed = 3
        results.bean_pass_count = 1
        summary = _build_h2_summary(
            run_id="run_smoke", results=results, started_at=0.0,
            status="completed", workers=2, expected_total=75,
            run_metadata={
                "canonical_ct_sha256": "deadbeef", "k": 3,
                "h2_variants_executed": 3,
                "ambiguous_positions_sha256": "cafebabe",
                "keyword_count": 1, "keyword_hash": "empty",
            },
        )
        assert summary["run_id"] == "run_smoke"
        assert summary["status"] == "completed"
        assert summary["candidates_evaluated"] == 75
        assert summary["expected_total_config_cardinality"] == 75
        assert summary["ambiguous_positions_sha256"] == "cafebabe"
        assert summary["k"] == 3
```

- [ ] **Step 2: Verify tests fail**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestH2Checkpoint -v`
Expected: FAIL.

- [ ] **Step 3: Implement `_h2_checkpoint`**

```python
def _h2_checkpoint(
    path: Path,
    results: SweepResults,
    started_at: float,
    started_at_iso: str,
    *,
    variants_total: int,
    expected_total: int,
    workers: int,
    status: str,
) -> None:
    updated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "started_at": started_at_iso,
        "updated_at": updated_at,
        "status": status,
        "variants_completed": results.variants_completed,
        "variants_processed": results.variants_completed,
        "variants_total": variants_total,
        "candidates_evaluated": results.candidates_evaluated,
        "expected_total_config_cardinality": expected_total,
        "bean_pass_count": results.bean_pass_count,
        "alerts_count": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "elapsed_seconds": time.time() - started_at,
        "workers": workers,
        "last_completed_variant_id": results.last_completed_variant_id,
        "errors": results.errors,
    }
    atomic_write_json(path, payload)
```

- [ ] **Step 4: Implement `_build_h2_summary`**

```python
def _build_h2_summary(
    *,
    run_id: str,
    results: SweepResults,
    started_at: float,
    status: str,
    workers: int,
    expected_total: int,
    run_metadata: dict[str, Any],
) -> dict[str, Any]:
    wall_time = time.time() - started_at
    configs_per_sec = (
        results.candidates_evaluated / wall_time if wall_time > 0 else 0.0
    )
    summary: dict[str, Any] = {
        "run_id": run_id,
        "campaign_id": CAMPAIGN_ID_STAGE_B,
        "status": status,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "canonical_ct_sha256": run_metadata.get("canonical_ct_sha256"),
        "ambiguous_positions_sha256": run_metadata.get("ambiguous_positions_sha256"),
        "k": run_metadata.get("k", 0),
        "h2_variants_executed": run_metadata.get(
            "h2_variants_executed", results.variants_completed,
        ),
        "families": [f.value for f in SUPPORTED_FAMILIES],
        "alphabets": list(SUPPORTED_ALPHABET_KINDS),
        "keyword_count": run_metadata.get("keyword_count", 0),
        "keyword_hash": run_metadata.get("keyword_hash", "empty"),
        "period_policy": "keyword_length",
        "expected_total_config_cardinality": expected_total,
        "candidates_evaluated": results.candidates_evaluated,
        "bean_pass_total": results.bean_pass_count,
        "bean_pass_count": results.bean_pass_count,
        "watchlist_total": len(results.watchlist),
        "alerts_total": len(results.alerts),
        "watchlist_count": len(results.watchlist),
        "alerts_count": len(results.alerts),
        "by_family_alert_count": dict(results.by_family_alert_count),
        "by_alphabet_alert_count": dict(results.by_alphabet_alert_count),
        "rejection_reason_counts": dict(results.rejection_reason_counts),
        "wall_time_seconds": wall_time,
        "configs_per_sec": configs_per_sec,
        "workers": workers,
        "errors": results.errors,
        "alerts": [_h2_summary_only(row) for row in results.alerts],
        "watchlist_preview": [
            _h2_summary_only(row) for row in results.watchlist[:25]
        ],
        "top_candidates_preview": [
            _h2_summary_only(payload)
            for payload in results.top_n.sorted_payloads()[:25]
        ],
    }
    summary.update({
        k: v for k, v in run_metadata.items() if k not in summary
    })
    return summary
```

Ensure `import datetime as _dt`, `import time`, `from pathlib import Path` are at the top.

- [ ] **Step 5: Verify tests pass**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestH2Checkpoint -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add _h2_checkpoint and _build_h2_summary writers"
```

---

## Task 8: Add `run_h2_sweep` orchestrator

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Write the failing test**

```python
class TestRunH2Sweep:
    @staticmethod
    def _make_manifest(tmp_path):
        import json
        from kryptosbot.ct_perturbation import (
            AMBIGUOUS_POSITIONS_SCHEMA_VERSION, _sha256_of_positions,
            load_ambiguous_positions,
        )
        positions = [3, 50, 95]
        payload = {
            "schema_version": AMBIGUOUS_POSITIONS_SCHEMA_VERSION,
            "archive_provenance": {
                "primary_source": "test fixture, not real archive",
                "evaluator": "unit test",
                "evaluation_date": "2026-05-11",
                "method": "synthetic",
            },
            "positions": positions,
            "rationale_per_position": {
                str(p): "synthetic" for p in positions
            },
            "checksum": {
                "sha256_of_positions_sorted": _sha256_of_positions(positions),
            },
        }
        path = tmp_path / "amb.json"
        path.write_text(json.dumps(payload))
        return load_ambiguous_positions(str(path))

    def test_run_h2_sweep_smoke(self, tmp_path):
        import json
        from scripts.campaigns.ct_perturbation_stage_b import (
            SweepConfig, run_h2_sweep,
        )
        from kryptos.kernel.constants import CT

        manifest = self._make_manifest(tmp_path)
        cfg = SweepConfig(
            ct=CT, keywords=["PALIMPSEST"], manifest=manifest,
            universe_size=18, max_h2_variants=3,
        )
        artifact_dir = tmp_path / "run"
        results = run_h2_sweep(
            cfg, artifact_dir=artifact_dir, run_id="test_smoke", workers=1,
            run_metadata={
                "canonical_ct_sha256": "test",
                "ambiguous_positions_sha256": manifest.checksum_sha256,
                "k": manifest.k,
                "h2_variants_executed": 3,
                "expected_total_config_cardinality": 18,
            },
        )
        # 3 variants × 3 families × 2 alphabets × 1 keyword = 18
        assert results.candidates_evaluated == 18
        assert results.variants_completed == 3
        assert (artifact_dir / "alerts.jsonl").exists()
        assert (artifact_dir / "watchlist.jsonl").exists()
        assert (artifact_dir / "top_candidates.jsonl").exists()
        assert (artifact_dir / "progress.json").exists()
        assert (artifact_dir / "summary.json").exists()
        summary = json.loads((artifact_dir / "summary.json").read_text())
        assert summary["candidates_evaluated"] == 18
        assert summary["k"] == 3
```

- [ ] **Step 2: Verify test fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestRunH2Sweep -v`
Expected: FAIL.

- [ ] **Step 3: Implement `_iter_h2_variants`**

```python
def _iter_h2_variants(cfg: SweepConfig):
    if cfg.manifest is None:
        return
    seen = 0
    for v in enumerate_hamming2_variants_constrained(cfg.ct, cfg.manifest):
        yield v
        seen += 1
        if cfg.max_h2_variants is not None and seen >= cfg.max_h2_variants:
            return
```

- [ ] **Step 4: Implement `run_h2_sweep` — mirror Stage A's `run_sweep`**

Implementation pattern mirrors `scripts/campaigns/ct_perturbation_stage_a.py:820` `run_sweep` exactly. Differences:
- Iterates `_iter_h2_variants(cfg)` instead of `_iter_variants(cfg)`
- Uses `_h2_checkpoint`, `_build_h2_summary`, `_h2_summary_only`, `_h2_candidate_row`
- Calls `evaluate_one_h2_variant` instead of `evaluate_one_variant`
- MP entry is `_worker_evaluate_h2`

For the multiprocessing branch (when `workers > 1`), follow the Stage A pattern at lines 944–958 but use `apply_async` with per-future `.get(timeout=per_task_timeout_sec)` to honor `feedback_pool_worker_no_per_task_timeout.md`. The pool context is `mp.get_context("spawn").Pool(workers)`. On `TimeoutError`, append a `per_task_timeout` row to `results.errors` and continue.

Function signature:
```python
def run_h2_sweep(
    cfg: SweepConfig,
    *,
    artifact_dir: Path,
    run_id: str,
    workers: int,
    progress_every_n_variants: int = 25,
    run_metadata: dict[str, Any] | None = None,
    trace_first_configs: int = 0,
    per_task_timeout_sec: float | None = None,
) -> SweepResults:
```

Ensure `import multiprocessing as mp` and `import json` are at the top.

- [ ] **Step 5: Verify test passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestRunH2Sweep -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: add run_h2_sweep orchestrator with per-task timeout"
```

---

## Task 9: Wire `--execute-full` to call `run_h2_sweep`

**Files:**
- Modify: `scripts/campaigns/ct_perturbation_stage_b.py`
- Test: `tests/test_ct_perturbation_stage_b.py`

- [ ] **Step 1: Add required CLI flags**

In `_build_argparser`, add (if missing):

```python
parser.add_argument(
    "--keyword-limit", type=int, default=None,
    help="Cap effective keyword count after loading (smoke).",
)
parser.add_argument(
    "--max-h2-variants", type=int, default=None,
    help="Cap H2 variant enumeration (smoke). Default: full universe.",
)
parser.add_argument(
    "--workers", type=int, default=1,
    help="Multiprocessing pool size for H2 variant evaluation.",
)
parser.add_argument(
    "--run-id", type=str, default=None,
    help="Run identifier (default: UTC timestamp).",
)
parser.add_argument(
    "--artifact-root", type=Path,
    default=Path("results/ct_perturbation_stage_b"),
    help="Root directory for per-run artifact directories.",
)
parser.add_argument(
    "--keywords", type=Path, default=None,
    help="Path to keyword list (one per line, uppercase A-Z).",
)
parser.add_argument(
    "--per-task-timeout-sec", type=float, default=None,
    help="Per-H2-variant timeout (seconds) in MP mode.",
)
```

- [ ] **Step 2: Write the failing test**

```python
class TestExecuteFullCli:
    def test_execute_full_runs_sweep(self, tmp_path):
        import json, subprocess, sys
        from kryptosbot.ct_perturbation import (
            AMBIGUOUS_POSITIONS_SCHEMA_VERSION, _sha256_of_positions,
        )
        positions = [3, 50, 95]
        payload = {
            "schema_version": AMBIGUOUS_POSITIONS_SCHEMA_VERSION,
            "archive_provenance": {
                "primary_source": "test fixture",
                "evaluator": "cli integration test",
                "evaluation_date": "2026-05-11",
                "method": "synthetic",
            },
            "positions": positions,
            "rationale_per_position": {str(p): "test" for p in positions},
            "checksum": {
                "sha256_of_positions_sorted": _sha256_of_positions(positions),
            },
        }
        manifest_path = tmp_path / "amb.json"
        manifest_path.write_text(json.dumps(payload))
        artifact_root = tmp_path / "artifacts"

        result = subprocess.run(
            [
                sys.executable, "scripts/campaigns/ct_perturbation_stage_b.py",
                "--ambiguous-positions", str(manifest_path),
                "--execute-full",
                "--max-h2-variants", "3",
                "--keyword-count", "1",
                "--keyword-limit", "1",
                "--artifact-root", str(artifact_root),
                "--run-id", "cli_test",
                "--workers", "1",
            ],
            capture_output=True, text=True,
            env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
            cwd="/home/cpatrick/kryptos",
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        summary = json.loads(
            (artifact_root / "cli_test" / "summary.json").read_text()
        )
        assert summary["status"] in ("completed", "incomplete")
        assert summary["candidates_evaluated"] > 0
```

- [ ] **Step 3: Verify test fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestExecuteFullCli -v`
Expected: FAIL with `returncode == 3` (current stub rejects `--execute-full`).

- [ ] **Step 4: Replace the `--execute-full` rejection block with a real sweep call**

In `main()`, find the block that returns exit code 3 ("Full sweep runner not yet implemented") and replace with:

```python
if args.execute_full:
    if manifest is None:
        logger.error(
            "--execute-full requires --ambiguous-positions <manifest>"
        )
        return 2
    keywords_src = load_keywords(
        args.keywords if args.keywords is not None
        else Path("data/keywords_curated_v1.txt"),
        cap=args.keyword_count,
    )
    run_id = args.run_id or _dt.datetime.now(_dt.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ_full"
    )
    artifact_dir = args.artifact_root / run_id
    universe = stage_b_universe_size(manifest, n_keywords=len(keywords_src.words))
    effective_keywords = (
        args.keyword_limit if args.keyword_limit is not None
        else len(keywords_src.words)
    )
    effective_variants = (
        args.max_h2_variants if args.max_h2_variants is not None
        else universe["h2_variants"]
    )
    expected_total = (
        effective_variants
        * len(SUPPORTED_FAMILIES)
        * len(SUPPORTED_ALPHABET_KINDS)
        * effective_keywords
    )
    cfg = SweepConfig(
        ct=CT, keywords=list(keywords_src.words), manifest=manifest,
        universe_size=universe["total_configs"],
        max_h2_variants=args.max_h2_variants,
        keyword_limit=args.keyword_limit,
    )
    run_metadata = {
        "canonical_ct_sha256": _ct_sha256(CT),
        "ambiguous_positions_sha256": manifest.checksum_sha256,
        "k": manifest.k,
        "h2_variants_executed": effective_variants,
        "expected_total_config_cardinality": expected_total,
        "keyword_count": effective_keywords,
        "keyword_hash": keywords_src.sha256,
    }
    run_h2_sweep(
        cfg, artifact_dir=artifact_dir, run_id=run_id,
        workers=args.workers, run_metadata=run_metadata,
        per_task_timeout_sec=args.per_task_timeout_sec,
    )
    return 0
```

Add `from kryptos.kernel.constants import CT` and `from kryptosbot.ct_perturbation import _ct_sha256, stage_b_universe_size` at top of file if missing.

- [ ] **Step 5: Verify test passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py::TestExecuteFullCli -v`
Expected: PASS.

- [ ] **Step 6: Run the full Stage B test suite for regression check**

Run: `PYTHONPATH=src python3 -m pytest tests/test_ct_perturbation_stage_b.py -q`
Expected: PASS — all existing + new tests.

- [ ] **Step 7: Commit**

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py tests/test_ct_perturbation_stage_b.py
git commit -m "stage_b: wire --execute-full to run_h2_sweep, drop deferred-stub exit"
```

---

## Task 10: Verify against Stage A regression and prereg compliance

**Files:**
- Modify: none (verification only) — except optional doc cleanup in Step 5

- [ ] **Step 1: Run the full project test suite to catch any regression**

Run: `PYTHONPATH=src python3 -m pytest tests/ -q --tb=short`
Expected: all tests pass; counts roughly match the project baseline +10–15 new Stage B tests.

- [ ] **Step 2: Verify the synthetic-recovery test still passes**

Run: `PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py --synthetic-recovery-test`
Expected: exit 0, both selective and structural probes pass.

- [ ] **Step 3: Smoke-run `--execute-full` against an ephemeral k=3 manifest**

```bash
python3 - <<'PY'
import json
from kryptosbot.ct_perturbation import (
    AMBIGUOUS_POSITIONS_SCHEMA_VERSION, _sha256_of_positions,
)
positions = [3, 50, 95]
payload = {
    "schema_version": AMBIGUOUS_POSITIONS_SCHEMA_VERSION,
    "archive_provenance": {
        "primary_source": "smoke test, not archive evidence",
        "evaluator": "operator smoke",
        "evaluation_date": "2026-05-11",
        "method": "synthetic",
    },
    "positions": positions,
    "rationale_per_position": {str(p): "smoke" for p in positions},
    "checksum": {"sha256_of_positions_sorted": _sha256_of_positions(positions)},
}
with open("/tmp/amb_smoke.json", "w") as fh:
    json.dump(payload, fh)
print("manifest written")
PY

PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
  --ambiguous-positions /tmp/amb_smoke.json \
  --execute-full --max-h2-variants 5 --keyword-count 3 --keyword-limit 3 \
  --artifact-root /tmp/stage_b_smoke --run-id v1_smoke
```

Expected: exit 0. Then verify artifacts:

```bash
ls /tmp/stage_b_smoke/v1_smoke/
# alerts.jsonl  checkpoints/  progress.json  summary.json  top_candidates.jsonl  watchlist.jsonl
```

- [ ] **Step 4: Confirm no `--execute-full` exit-3 path remains**

Run: `grep -n "not yet implemented" scripts/campaigns/ct_perturbation_stage_b.py`
Expected: no match.

- [ ] **Step 5: Update the runner's module docstring**

Replace the "What this module does NOT do" entry about the v1 sweep loop with a positive description that the full sweep is now wired up. Then:

```bash
git add scripts/campaigns/ct_perturbation_stage_b.py
git commit -m "stage_b: drop deferred-stub language from module docstring"
```

---

## Self-Review

**Spec coverage check:**
- Prereg §3.3 cardinality binding — `stage_b_universe_size` used in `main()` run_metadata
- Prereg §4 CT-parametric scoring — inherited via `score_candidate_ct_parametric`
- Prereg §5 Bonferroni against H2 universe — passed into scorer via `cfg.universe_size`
- Prereg §6 alert/watchlist policy — inherited via `AlertPolicy` default
- Prereg §8 artifact schema with `pos_pair`, `chars_pair`, `crib_overlapping` — `_h2_candidate_row`
- Prereg §9 CLI — all required flags added
- `feedback_pool_worker_no_per_task_timeout.md` — per-future timeout in MP branch

**Placeholder scan:** None — every step has runnable commands or complete code.

**Type consistency check:**
- `SweepConfig.manifest: AmbiguousPositionsManifest | None` — used in `_iter_h2_variants`, None-checked in `main()`
- `evaluate_one_h2_variant` returns `VariantEvalResult` — consumed by `_merge_variant_result` (inline closure inside `run_h2_sweep`, Task 8 Step 4)
- `_h2_candidate_row` signature matches usage sites in `evaluate_one_h2_variant`

**Gaps noted:**
- The plan does not implement universe_manifest.json or coverage_report.json — those are stage A artifacts that are nice-to-have but not required by prereg §8 for v1 (which mandates `ambiguous_positions_manifest.json` already written by existing stub, plus the JSONL row schema and summary.json — all covered). Wire-in is straightforward in a follow-up via existing Stage A helpers.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-11-ct-perturbation-stage-b-v1-runner.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
