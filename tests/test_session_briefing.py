"""Tests for scripts/_infra/session_briefing.py.

Focus: the epistemic-hygiene contract — verdict classification must not read
prose as closure, Bin-C closure must require a terminal signal (not mere
entry/file existence), recursive scanning must include nested artifacts,
falsy-but-valid values must survive, and missing required sources must warn.
"""

import importlib.util
import json
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SB_PATH = os.path.join(_ROOT, "scripts", "_infra", "session_briefing.py")


def _load_module():
    spec = importlib.util.spec_from_file_location("session_briefing_under_test", _SB_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec: dataclasses with `from __future__ import annotations`
    # resolve field annotations via sys.modules[cls.__module__].
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sb = _load_module()
VC = sb.VerdictClass


# ── Verdict classification ────────────────────────────────────────────────────

@pytest.mark.parametrize("verdict,expected", [
    ("ELIMINATED", VC.CLOSED),
    ("DISPROVED", VC.CLOSED),
    ("STRUCTURALLY IMPOSSIBLE", VC.CLOSED),
    ("EXHAUSTED", VC.CLOSED),
    ("CERTIFIED", VC.CLOSED),
    ("EMPTY", VC.CLOSED),
    ("INVALID", VC.CLOSED),
    ("NOISE", VC.NOISE),
    ("NOT SIGNIFICANT", VC.NOISE),
    ("RETIRED", VC.RETIRED),
    ("SUPERSEDED", VC.RETIRED),
    ("INTERESTING", VC.OPEN),
    ("SIGNAL", VC.OPEN),
    ("PROMISING", VC.OPEN),
    ("INVESTIGATE", VC.OPEN),
    ("NEAR_MISS", VC.OPEN),
    ("ASSUMPTION_UNMET", VC.BLOCKED),
    ("BLOCKED", VC.BLOCKED),
])
def test_classify_known_verdicts(verdict, expected):
    assert sb.classify_verdict(verdict) == expected


def test_failed_to_eliminate_is_not_closed():
    assert sb.classify_verdict("FAILED_TO_ELIMINATE") != VC.CLOSED


def test_not_eliminated_is_not_closed():
    assert sb.classify_verdict("NOT ELIMINATED") != VC.CLOSED


def test_unclear_is_not_closed():
    assert sb.classify_verdict("UNCLEAR") in (VC.UNKNOWN, VC.OPEN)
    assert sb.classify_verdict("UNCLEAR") != VC.CLOSED


@pytest.mark.parametrize("verdict", ["", None, "ANALYSIS_COMPLETE", "TBD", "FOO_BAR_BAZ"])
def test_unrecognized_or_empty_is_unknown(verdict):
    assert sb.classify_verdict(verdict) == VC.UNKNOWN


def test_eliminated_with_signal_prose_is_closed():
    """The headline verdict wins; 'NO SIGNAL' / 'SIGNAL' in the tail must not flip it."""
    v = "ELIMINATED (audit 2026-04-08): self-reports NO SIGNAL; below SIGNAL under mult"
    assert sb.classify_verdict(v) == VC.CLOSED


def test_eliminated_with_investigate_prose_is_closed():
    v = "ELIMINATED (audit): DO NOT TEST; would otherwise INVESTIGATE later"
    assert sb.classify_verdict(v) == VC.CLOSED


def test_marginal_likely_noise_is_noise():
    assert sb.classify_verdict("MARGINAL -- LIKELY NOISE") == VC.NOISE


def test_noise_with_score_suffix_is_noise():
    assert sb.classify_verdict("NOISE -- 6/24") == VC.NOISE


def test_dict_verdict_is_handled():
    assert sb.classify_verdict({"summary": "ELIMINATED", "detail": "x"}) == VC.CLOSED


def test_is_terminal_only_for_closed_noise_retired():
    assert sb.is_terminal(VC.CLOSED)
    assert sb.is_terminal(VC.NOISE)
    assert sb.is_terminal(VC.RETIRED)
    assert not sb.is_terminal(VC.OPEN)
    assert not sb.is_terminal(VC.BLOCKED)
    assert not sb.is_terminal(VC.UNKNOWN)


# ── first_present ─────────────────────────────────────────────────────────────

def test_first_present_preserves_zero():
    assert sb.first_present({"best_score": 0, "alt": 5}, ("best_score", "alt")) == 0


def test_first_present_skips_none():
    assert sb.first_present({"a": None, "b": 7}, ("a", "b")) == 7


def test_first_present_missing_returns_none():
    assert sb.first_present({"a": 1}, ("x", "y")) is None


def test_first_present_preserves_empty_list():
    assert sb.first_present({"escalated": []}, ("escalated",)) == []


# ── Timestamp parsing ─────────────────────────────────────────────────────────

def test_parse_timestamp_iso():
    assert sb.parse_timestamp("2026-04-08T14:18:44") is not None


def test_parse_timestamp_date_only():
    assert sb.parse_timestamp("2026-04-08") is not None


def test_parse_timestamp_garbage_is_none():
    assert sb.parse_timestamp("not-a-date") is None
    assert sb.parse_timestamp(None) is None


def test_parsed_timestamps_are_comparable():
    """Mixed tz-aware/naive inputs must sort without raising."""
    a = sb.parse_timestamp("2026-04-08T14:18:44+00:00")
    b = sb.parse_timestamp("2026-04-09 10:00:00")
    assert sorted([a, b]) is not None  # no TypeError


# ── IC and self-encrypting helpers ────────────────────────────────────────────

def test_compute_ic_all_same_is_one():
    assert sb.compute_ic("AAAA") == 1.0


def test_compute_ic_stable_known_string():
    # "ABCD" has all-distinct letters -> IC 0.
    assert sb.compute_ic("ABCD") == 0.0


@pytest.mark.skipif(not sb._KERNEL_OK, reason="kernel constants unavailable")
def test_compute_ic_of_ct_matches_constant():
    from kryptos.kernel.constants import CT, IC_K4
    assert abs(sb.compute_ic(CT) - IC_K4) < 0.001


@pytest.mark.skipif(not sb._KERNEL_OK, reason="kernel constants unavailable")
def test_self_encrypting_positions():
    assert set(sb.self_encrypting_positions()) == {32, 73}


# ── Recursive result scanning + counting ──────────────────────────────────────

def test_scan_includes_nested_summary_and_result(tmp_path, monkeypatch):
    results = tmp_path / "results"
    (results).mkdir()
    # top-level
    (results / "top.json").write_text(json.dumps({"verdict": "ELIMINATED"}))
    # nested summary.json
    d1 = results / "campaign_a"
    d1.mkdir()
    (d1 / "summary.json").write_text(json.dumps({"verdict": "NOISE"}))
    # nested result.json (separate dir)
    d2 = results / "campaign_b"
    d2.mkdir()
    (d2 / "result.json").write_text(json.dumps({"verdict": "INTERESTING"}))
    # deep per-job file that must NOT be parsed by the scoped scanner
    deep = results / "dsl_jobs" / "JOB1"
    deep.mkdir(parents=True)
    (deep / "result.json").write_text(json.dumps({"verdict": "SIGNAL"}))

    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    diag = sb.Diagnostics()
    entries = sb.scan_result_files(diag)
    names = {e.name for e in entries}
    assert "top" in names
    assert "campaign_a" in names      # nested summary.json picked up
    assert "campaign_b" in names      # nested result.json picked up
    assert "JOB1" not in names        # deep per-job file NOT parsed


def test_scan_dedupes_summary_over_result(tmp_path, monkeypatch):
    results = tmp_path / "results"
    d = results / "campaign_c"
    d.mkdir(parents=True)
    (d / "summary.json").write_text(json.dumps({"verdict": "ELIMINATED"}))
    (d / "result.json").write_text(json.dumps({"verdict": "INTERESTING"}))
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    diag = sb.Diagnostics()
    entries = [e for e in sb.scan_result_files(diag) if e.name == "campaign_c"]
    assert len(entries) == 1
    assert entries[0].verdict_class == VC.CLOSED  # summary.json wins


def test_malformed_result_warns(tmp_path, monkeypatch):
    results = tmp_path / "results"
    results.mkdir()
    (results / "broken.json").write_text("{ not valid json ")
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    diag = sb.Diagnostics()
    sb.scan_result_files(diag)
    assert any("broken.json" in w for w in diag.warnings)


def test_count_result_files_counts_deep(tmp_path, monkeypatch):
    results = tmp_path / "results"
    (results / "dsl_jobs" / "J1").mkdir(parents=True)
    (results / "dsl_jobs" / "J2").mkdir(parents=True)
    (results / "top.json").write_text("{}")
    (results / "dsl_jobs" / "J1" / "result.json").write_text("{}")
    (results / "dsl_jobs" / "J2" / "result.json").write_text("{}")
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    counts = sb.count_result_files()
    assert counts["total"] == 3
    assert counts["top_level"] == 1
    assert counts["nested"] == 2
    assert counts["result_json"] == 2


def test_best_score_zero_preserved_in_entry(tmp_path, monkeypatch):
    results = tmp_path / "results"
    results.mkdir()
    (results / "z.json").write_text(json.dumps({"verdict": "NOISE", "best_score": 0}))
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    diag = sb.Diagnostics()
    entry = [e for e in sb.scan_result_files(diag) if e.name == "z"][0]
    assert entry.best_score == 0  # not None, not dropped


# ── Bin-C closure ─────────────────────────────────────────────────────────────

def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


def test_bin_c_not_closed_on_open_verdict(tmp_path, monkeypatch):
    """A campaign entry with an OPEN verdict must NOT be marked CLOSED."""
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    _write(os.path.join(str(tmp_path), "results", "f_final_checklist_c1_c2.json"),
           {"campaigns": [{"source_id": "carter_tomb_vol1", "verdict": "ESCALATE",
                           "escalated_candidates": [], "orderings_tested": 10}]})
    diag = sb.Diagnostics()
    st = sb._bin_c_status("C1", diag)
    assert st["status"] != "CLOSED"
    assert st["status"] == "OPEN"


def test_bin_c_not_closed_on_missing_verdict_and_no_metrics(tmp_path, monkeypatch):
    """No verdict + no completion metrics => UNKNOWN, never CLOSED."""
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    _write(os.path.join(str(tmp_path), "results", "f_final_checklist_c1_c2.json"),
           {"campaigns": [{"source_id": "carter_tomb_vol1"}]})
    diag = sb.Diagnostics()
    st = sb._bin_c_status("C1", diag)
    assert st["status"] == "UNKNOWN"


def test_bin_c_closed_on_terminal_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    _write(os.path.join(str(tmp_path), "results", "f_final_checklist_c1_c2.json"),
           {"campaigns": [{"source_id": "carter_tomb_vol1", "verdict": "EMPTY",
                           "escalated_candidates": [], "orderings_tested": 403920,
                           "max_crib_score": 0}]})
    diag = sb.Diagnostics()
    st = sb._bin_c_status("C1", diag)
    assert st["status"] == "CLOSED"


def test_bin_c_c7_requires_unclear_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    # unclear > 0 => not closed
    _write(os.path.join(str(tmp_path), "results", "admissibility_elimination_v1",
                        "running_key_policy.json"),
           {"accepted": 5, "rejected": 3, "unclear": 2, "n_scripts": 10})
    diag = sb.Diagnostics()
    st = sb._bin_c_status("C7", diag)
    assert st["status"] == "OPEN"
    # unclear == 0 => closed
    _write(os.path.join(str(tmp_path), "results", "admissibility_elimination_v1",
                        "running_key_policy.json"),
           {"accepted": 11, "rejected": 9, "unclear": 0, "n_scripts": 20})
    st2 = sb._bin_c_status("C7", sb.Diagnostics())
    assert st2["status"] == "CLOSED"


def test_bin_c_md_existence_alone_not_closed(tmp_path, monkeypatch):
    """A markdown artifact with no closure language must NOT close the campaign."""
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    # C7's only artifact is the cert md; give it non-closure content.
    md = os.path.join(str(tmp_path), "docs", "exhaustion_certificate_2026_04_08.md")
    os.makedirs(os.path.dirname(md), exist_ok=True)
    with open(md, "w") as f:
        f.write("# Notes\nSome unrelated text without closure language.\n")
    diag = sb.Diagnostics()
    st = sb._bin_c_status("C7", diag)
    assert st["status"] != "CLOSED"


def test_bin_c_md_with_closure_language_closes(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    md = os.path.join(str(tmp_path), "docs", "exhaustion_certificate_2026_04_08.md")
    os.makedirs(os.path.dirname(md), exist_ok=True)
    with open(md, "w") as f:
        f.write("# Certificate\nThis formally closes the bin-C work. No candidates escalated.\n")
    st = sb._bin_c_status("C7", sb.Diagnostics())
    assert st["status"] == "CLOSED"


def test_bin_c_deferred(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    for cid in ("C3", "C4", "C5", "C8"):
        assert sb._bin_c_status(cid, sb.Diagnostics())["status"] == "DEFERRED"


def test_bin_c_testable_when_no_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    # No artifact files exist under tmp_path => TESTABLE (not silently closed).
    assert sb._bin_c_status("C6", sb.Diagnostics())["status"] == "TESTABLE"


# ── Source-failure warnings ───────────────────────────────────────────────────

def test_missing_required_json_is_error(tmp_path):
    diag = sb.Diagnostics()
    sb.load_json(os.path.join(str(tmp_path), "nope.json"), diag, required=True)
    assert diag.errors
    assert diag.degraded


def test_missing_optional_json_is_warning(tmp_path):
    diag = sb.Diagnostics()
    sb.load_json(os.path.join(str(tmp_path), "nope.json"), diag, required=False)
    assert diag.warnings
    assert not diag.degraded


def test_missing_section_registry_uses_fallback_and_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))  # no docs/ here
    diag = sb.Diagnostics()
    sections, used_fallback = sb.load_section_claims(diag)
    assert used_fallback
    assert diag.errors  # required source missing => error => degraded
    assert "proofs" in sections  # fallback still provides content


def test_malformed_section_registry_uses_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "session_briefing_claims.json").write_text("{ broken")
    diag = sb.Diagnostics()
    sections, used_fallback = sb.load_section_claims(diag)
    assert used_fallback
    assert diag.degraded


# ── Status buckets ────────────────────────────────────────────────────────────

def test_status_bucketing():
    assert sb._bucket_status("exhausted") == "exhausted"
    assert sb._bucket_status("active") == "active"
    assert sb._bucket_status("retired") == "retired"
    assert sb._bucket_status("assumption_unmet") == "blocked"
    assert sb._bucket_status("weird_unknown_status") == "unknown"


# ── End-to-end smoke ──────────────────────────────────────────────────────────

@pytest.mark.skipif(not sb._KERNEL_OK, reason="kernel constants unavailable")
def test_main_runs_clean_on_real_repo():
    assert sb.main([]) == 0


def test_self_test_passes():
    assert sb.run_self_test() == 0


# ── Assumption boundaries (alignment / plaintext-length models) ────────────────
#
# Contract: eliminations proven under direct CT[i]->PT[i] mapping must NOT be
# rendered as closing null-bearing / variable-length / non-direct-alignment
# space. The briefing must enumerate the alignment-model taxonomy, declare each
# elimination's model, surface the mandated scoped-exhaustion statement, and
# warn (with a cautionary line) when an assumption-boundary source is missing.

EXPECTED_ALIGNMENT_KEYS = {
    "direct_ct_pt", "fixed_len_97", "ct73_null_extracted",
    "arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism",
}


def test_alignment_models_taxonomy_complete():
    keys = {k for k, _desc in sb.ALIGNMENT_MODELS}
    assert keys == EXPECTED_ALIGNMENT_KEYS
    ordered = [k for k, _ in sb.ALIGNMENT_MODELS]
    assert ordered[0] == "direct_ct_pt"          # narrowest first
    assert ordered[-1] == "joint_mask_mechanism"  # broadest last


def test_boundary_summary_direct_proof_does_not_close_broad_models():
    """A direct-mapping proof must not surface as a closure of broader models."""
    sections = {"proofs": [
        {"evidence_class": "mathematical_proof",
         "statement": "periodic sub p1-26 eliminated",
         "alignment_model": "direct_ct_pt", "scope": "raw 97 direct"},
    ]}
    summary = {row["key"]: row for row in sb.assumption_boundary_summary(sections)}
    assert summary["direct_ct_pt"]["has_closure"] is True
    for broad in ("arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism"):
        assert summary[broad]["has_closure"] is False
        assert summary[broad]["closure_claims"] == []


def test_boundary_summary_groups_claim_under_its_model():
    """A narrow CT73-null closure must not read as closing the general mask space."""
    sections = {"do_not_test": [
        {"evidence_class": "mathematical_proof",
         "statement": "periodic sub on null-extracted CT73 p1-23",
         "alignment_model": "ct73_null_extracted"},
    ]}
    summary = {row["key"]: row for row in sb.assumption_boundary_summary(sections)}
    assert summary["ct73_null_extracted"]["has_closure"] is True
    assert len(summary["ct73_null_extracted"]["closure_claims"]) == 1
    assert summary["arbitrary_null_mask"]["has_closure"] is False
    assert summary["joint_mask_mechanism"]["has_closure"] is False


def test_section_assumption_boundaries_lists_all_models_and_statement(capsys):
    sections = {"proofs": [
        {"evidence_class": "mathematical_proof", "statement": "x",
         "alignment_model": "direct_ct_pt"}]}
    sb.section_assumption_boundaries(sections, sb.Diagnostics())
    out = capsys.readouterr().out
    for key, _desc in sb.ALIGNMENT_MODELS:
        assert key in out, f"model {key} not rendered"
    # Mandated scoped-exhaustion acceptance statement.
    assert "outside the closure certificate" in out
    assert "Null-bearing" in out
    # Broad models with no closure must render NOT CLOSED.
    assert "NOT CLOSED" in out


def test_claim_missing_alignment_model_is_flagged():
    sections = {"proofs": [
        {"evidence_class": "mathematical_proof", "statement": "no model here"}]}
    assert len(sb.claims_missing_alignment_model(sections)) == 1


def test_real_proof_and_dnt_claims_declare_alignment_model():
    """Every real proofs / do_not_test claim must declare a valid alignment model."""
    path = os.path.join(_ROOT, "docs", "session_briefing_claims.json")
    with open(path) as f:
        data = json.load(f)
    valid = {k for k, _ in sb.ALIGNMENT_MODELS}
    offenders = [(c.get("claim_id"), c.get("alignment_model"))
                 for c in data["claims"]
                 if c.get("section") in ("proofs", "do_not_test")
                 and c.get("alignment_model") not in valid]
    assert offenders == [], f"claims without a valid alignment_model: {offenders}"


def test_assumption_boundary_sources_present_when_all_exist(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "REAL_K4_CURRENT_POSITION.md").write_text("x")
    (tmp_path / "docs" / "methodological_audits.md").write_text("x")
    mem = tmp_path / "mem"
    mem.mkdir()
    (mem / "feedback_pt_length_open_question.md").write_text("x")
    (mem / "project_stego_mechanism_family_cleanup_2026_05_15.md").write_text("x")
    resolved = sb.resolve_assumption_boundary_sources(str(tmp_path), mem_dirs=[str(mem)])
    assert resolved, "expected at least one source row"
    assert all(found for _label, found in resolved)


def test_assumption_boundary_sources_missing_warns(tmp_path):
    diag = sb.Diagnostics()
    missing = sb.check_assumption_boundary_sources(diag, root=str(tmp_path))
    assert missing  # nothing exists under an empty root
    assert any("assumption-boundary source unavailable" in w for w in diag.warnings)


def test_do_not_test_renders_alignment_model_inline(capsys):
    sections = {"do_not_test": [
        {"evidence_class": "mathematical_proof",
         "statement": "periodic sub on null-extracted CT73",
         "alignment_model": "ct73_null_extracted"}]}
    sb.section_do_not_test(sections)
    out = capsys.readouterr().out
    assert "ct73_null_extracted" in out


def test_section_prints_cautionary_line_when_source_missing(tmp_path, monkeypatch, capsys):
    """Missing assumption-boundary source => the mandated WARNING line renders."""
    monkeypatch.setattr(sb, "_ROOT", str(tmp_path))  # empty root: nothing resolves
    sb.section_assumption_boundaries({"proofs": []}, sb.Diagnostics())
    out = capsys.readouterr().out
    assert "assumption-boundary source unavailable" in out
    assert "do not treat" in out


def test_proofs_render_alignment_model_inline(capsys):
    sections = {"proofs": [
        {"evidence_class": "mathematical_proof",
         "statement": "periodic sub p1-26",
         "alignment_model": "direct_ct_pt", "scope": "raw 97 direct"}]}
    sb.section_proofs(sections)
    out = capsys.readouterr().out
    assert "direct_ct_pt" in out
