"""CLI flags to toggle the opt-in SDK features without hand-editing config.

`--sibling-output-format` -> ControllerConfig.sibling_output_format
`--enable-mcp-tools`      -> ControllerConfig.enable_mcp_tools

Both default OFF so existing invocations are unchanged; the flags let a bench
validation exercise the new code paths with a one-liner.
"""

import ast
import pathlib
import sys

from kryptosbot.run_controller import parse_args

_RUN_CONTROLLER = pathlib.Path(__file__).resolve().parents[1] / "run_controller.py"


def test_new_sdk_flags_default_false(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["run_controller.py"])
    ns = parse_args()
    assert ns.sibling_output_format is False
    assert ns.enable_mcp_tools is False


def test_new_sdk_flags_parse_true(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["run_controller.py", "--sibling-output-format", "--enable-mcp-tools"],
    )
    ns = parse_args()
    assert ns.sibling_output_format is True
    assert ns.enable_mcp_tools is True


def test_solve_flag_parses(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["run_controller.py"])
    assert parse_args().solve is False
    monkeypatch.setattr(sys, "argv", ["run_controller.py", "--solve"])
    assert parse_args().solve is True


def test_solve_assault_knobs_parse(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["run_controller.py"])
    ns = parse_args()
    assert ns.solve_keywords is None
    assert ns.solve_rounds == 2  # default
    monkeypatch.setattr(
        sys, "argv",
        ["run_controller.py", "--solve", "--solve-keywords", "KRYPTOS,BERLIN", "--solve-rounds", "4"],
    )
    ns = parse_args()
    assert ns.solve_keywords == "KRYPTOS,BERLIN"
    assert ns.solve_rounds == 4


def test_config_construction_threads_new_flags():
    # Pin that the parsed flags actually reach ControllerConfig (the whole point
    # of the flags). AST: the ControllerConfig(...) call must pass each flag
    # sourced from args.<flag>.
    src = _RUN_CONTROLLER.read_text()
    tree = ast.parse(src)

    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name == "ControllerConfig":
                for kw in node.keywords:
                    if kw.arg in ("sibling_output_format", "enable_mcp_tools"):
                        # value must be args.<same-name>
                        v = kw.value
                        ok = (
                            isinstance(v, ast.Attribute)
                            and v.attr == kw.arg
                            and isinstance(v.value, ast.Name)
                            and v.value.id == "args"
                        )
                        found[kw.arg] = ok

    assert found.get("sibling_output_format") is True, "config must set sibling_output_format=args.sibling_output_format"
    assert found.get("enable_mcp_tools") is True, "config must set enable_mcp_tools=args.enable_mcp_tools"
