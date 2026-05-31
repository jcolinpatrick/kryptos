"""Structured-output (output_format / --json-schema) wiring for sibling verdicts.

The Claude Agent SDK 0.1.61 forwards ``ClaudeAgentOptions.output_format`` of
shape ``{"type": "json_schema", "schema": {...}}`` to the CLI as
``--json-schema`` (subprocess_cli.py:330), and the installed CLI (>=2.0.0)
enforces it on the model's final output. Wiring it into the sibling review
calls (red-team / stat-audit / pursuit) guarantees a JSON object that the
``_normalize_*`` parsers can read, removing the regex-extraction failure mode.

The schemas are intentionally PERMISSIVE: the normalizers use ``.get()`` with
safe defaults for every field, so the schema must only steer the model toward
an object with the expected keys (required: just ``verdict``); it must not
constrain values (no enum) or forbid extra keys (no additionalProperties:false),
both of which could reject otherwise-valid output.
"""

import ast
import dataclasses
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# A. Schema constants are well-formed and cover the parser's keys
# --------------------------------------------------------------------------

# (constant name, required key, the keys the matching _normalize_* reads)
_SCHEMA_CASES = [
    ("REDTEAM_OUTPUT_FORMAT", ["verdict", "confidence", "reasons", "next_test", "search_space_risk"]),
    ("STAT_AUDIT_OUTPUT_FORMAT", ["verdict", "confidence", "methodology_concerns", "recommended_action"]),
    ("PURSUIT_OUTPUT_FORMAT", ["verdict", "confidence", "rationale", "suggested_variants"]),
]


@pytest.mark.parametrize("const_name,expected_keys", _SCHEMA_CASES)
def test_schema_constant_is_wellformed_json_schema(const_name, expected_keys):
    import kryptosbot.pantheon_siblings as ps

    fmt = getattr(ps, const_name)
    assert fmt["type"] == "json_schema"
    schema = fmt["schema"]
    assert schema["type"] == "object"
    # verdict is the one field the normalizer maps from; require it so the model
    # always emits at least a verdict.
    assert "verdict" in schema.get("required", [])
    props = schema["properties"]
    for key in expected_keys:
        assert key in props, f"{const_name} schema missing property {key!r}"
    # Permissive: must NOT forbid extra keys (normalizers tolerate them).
    assert schema.get("additionalProperties", True) is not False


# --------------------------------------------------------------------------
# B. Each sibling function declares output_format and forwards it to options
# --------------------------------------------------------------------------

_SIBLING_FUNCS = ["run_red_team_precheck", "run_stat_audit", "run_pursuit_evaluator"]


def _func_def(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def test_synthesis_is_deliberately_excluded_from_output_format():
    # Negative drift guard: synthesis must NOT be wired for output_format. The
    # theorist/synthesis path differs from the flat sibling verdicts (the
    # theorist emits a top-level JSON array embedding nested DSL), so a future
    # dev must not "sync" synthesis to the others without a contract-matched
    # schema. Pin the exclusion in three places.
    import kryptosbot.pantheon_siblings as ps

    assert not hasattr(ps, "SYNTHESIS_OUTPUT_FORMAT")

    src = (_ROOT / "pantheon_siblings.py").read_text()
    tree = ast.parse(src)
    fn = _func_def(tree, "run_results_synthesis")
    assert fn is not None
    arg_names = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    assert "output_format" not in arg_names, "synthesis must not accept output_format yet"

    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fnc = node.func
            cname = getattr(fnc, "id", None) or getattr(fnc, "attr", None)
            if cname == "ClaudeAgentOptions":
                kws = {kw.arg for kw in node.keywords if kw.arg is not None}
                assert "output_format" not in kws, "synthesis options must not pass output_format"


@pytest.mark.parametrize("fname", _SIBLING_FUNCS)
def test_sibling_function_accepts_and_forwards_output_format(fname):
    src = (_ROOT / "pantheon_siblings.py").read_text()
    tree = ast.parse(src)
    fn = _func_def(tree, fname)
    assert fn is not None, f"{fname} not found"

    arg_names = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    assert "output_format" in arg_names, f"{fname} must accept output_format param"

    # Find the ClaudeAgentOptions(...) call inside the function and assert it
    # forwards output_format.
    forwarded = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            fnc = node.func
            cname = getattr(fnc, "id", None) or getattr(fnc, "attr", None)
            if cname == "ClaudeAgentOptions":
                kws = {kw.arg for kw in node.keywords if kw.arg is not None}
                if "output_format" in kws:
                    forwarded = True
    assert forwarded, f"{fname}: ClaudeAgentOptions call must pass output_format="


# --------------------------------------------------------------------------
# C. Config gates default OFF (opt-in; validate on a bench cycle before live)
# --------------------------------------------------------------------------

def test_controller_config_has_output_format_flags_default_false():
    from kryptosbot.controller import ControllerConfig

    fields = {f.name: f for f in dataclasses.fields(ControllerConfig)}
    assert "sibling_output_format" in fields
    assert fields["sibling_output_format"].default is False
    # theorist structured output is deliberately NOT a shipped flag yet (the
    # theorist is the halt-critical path; top-level-array --json-schema is
    # unverified). No dead/no-op flag should be exposed.
    assert "theorist_output_format" not in fields


# --------------------------------------------------------------------------
# D. Controller wires the schemas into the sibling calls, gated by the flag
# --------------------------------------------------------------------------

def test_controller_passes_output_format_to_siblings():
    src = (_ROOT / "controller.py").read_text()
    assert "sibling_output_format" in src
    assert "output_format=" in src
    # references at least one of the schema constants
    assert any(
        c in src for c in ("REDTEAM_OUTPUT_FORMAT", "STAT_AUDIT_OUTPUT_FORMAT", "PURSUIT_OUTPUT_FORMAT")
    )


# --------------------------------------------------------------------------
# E. Installed SDK accepts output_format (drift guard on the field name)
# --------------------------------------------------------------------------

def test_sdk_accepts_output_format_field():
    from claude_agent_sdk import ClaudeAgentOptions

    fmt = {"type": "json_schema", "schema": {"type": "object", "properties": {}}}
    opts = ClaudeAgentOptions(output_format=fmt)
    assert opts.output_format == fmt
