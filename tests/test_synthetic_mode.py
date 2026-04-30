"""Tests for the synthetic-CT override path in kryptos.kernel.constants.

Backs the synthetic-signal calibration spec (`docs/maturation/round3/
SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md`). Verifies:

1. Without override: real K4 CT loads, all K4 invariants hold.
2. With override: synthetic CT loads, Bean derivation runs against the
   override, K4-specific assertions are correctly skipped, structural
   assertions still fire.
3. Override validation rejects malformed inputs (wrong length, lowercase,
   non-alpha) before the module finishes loading.

Most tests use subprocess to spawn a fresh Python interpreter — module
state is set at import time, so `importlib.reload` would not honestly
exercise the load path the synthetic launcher actually uses.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

import pytest


PYTHON = sys.executable
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")


def _run_with_env(code: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run a Python snippet in a fresh interpreter with an extended env."""
    env = os.environ.copy()
    env["PYTHONPATH"] = SRC + (os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else "")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [PYTHON, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


# ── Default mode (no override): real K4 invariants ───────────────────────


class TestDefaultMode:
    """Fresh interpreter, no override env var. K4 invariants must hold."""

    def test_default_ct_is_real_k4(self):
        code = textwrap.dedent("""
            from kryptos.kernel.constants import CT, _SYNTHETIC_MODE
            assert _SYNTHETIC_MODE is False
            assert CT.startswith("OBKRUOXOG")
            assert CT.endswith("EKCAR")
            print("OK")
        """)
        # Ensure no override is leaking from the test runner's env
        env = os.environ.copy()
        env.pop("KRYPTOS_CT_OVERRIDE", None)
        env["PYTHONPATH"] = SRC
        result = subprocess.run(
            [PYTHON, "-c", code],
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "OK" in result.stdout

    def test_default_bean_counts(self):
        code = textwrap.dedent("""
            from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, BEAN_LINEAR
            assert BEAN_EQ == ((27, 65),), BEAN_EQ
            assert len(BEAN_INEQ) == 242, len(BEAN_INEQ)
            assert len(BEAN_LINEAR) == 101, len(BEAN_LINEAR)
            print("OK")
        """)
        env = os.environ.copy()
        env.pop("KRYPTOS_CT_OVERRIDE", None)
        env["PYTHONPATH"] = SRC
        result = subprocess.run(
            [PYTHON, "-c", code],
            capture_output=True, text=True, env=env, timeout=30,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"


# ── Synthetic mode (override set): synthetic CT, gated assertions ────────


# A simple synthetic CT we control: 97 chars, all alpha uppercase, with
# a known structure so we can verify the override loaded it. Any valid
# 97-char A-Z string works; we use a recognizable pattern.
SYNTHETIC_CT_FIXTURE = "Q" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 3 + "ABCDEFGHIJKLMNOPQ" + "Z"
assert len(SYNTHETIC_CT_FIXTURE) == 97, len(SYNTHETIC_CT_FIXTURE)  # safety check


class TestSyntheticMode:
    """Override env var set: synthetic CT loaded, K4 assertions skipped."""

    def test_override_replaces_ct(self):
        code = textwrap.dedent(f"""
            from kryptos.kernel.constants import CT, _SYNTHETIC_MODE
            assert _SYNTHETIC_MODE is True
            assert CT == {SYNTHETIC_CT_FIXTURE!r}, CT
            print("OK")
        """)
        result = _run_with_env(code, {"KRYPTOS_CT_OVERRIDE": SYNTHETIC_CT_FIXTURE})
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_override_warning_on_stderr(self):
        code = textwrap.dedent("""
            from kryptos.kernel.constants import CT  # noqa: F401
            print("OK")
        """)
        result = _run_with_env(code, {"KRYPTOS_CT_OVERRIDE": SYNTHETIC_CT_FIXTURE})
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "KRYPTOS_CT_OVERRIDE active" in result.stderr
        assert "synthetic" in result.stderr.lower()

    def test_override_bean_derivation_runs(self):
        """Bean derivation must run cleanly against the synthetic CT.

        Counts will differ from K4's 242 / 101, but BEAN_INEQ and
        BEAN_LINEAR must be tuples of valid position pairs / 4-tuples.
        """
        code = textwrap.dedent("""
            from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, BEAN_LINEAR, CRIB_DICT
            crib_set = set(CRIB_DICT.keys())
            for a, b in BEAN_EQ:
                assert a in crib_set and b in crib_set
            for a, b in BEAN_INEQ:
                assert a in crib_set and b in crib_set
                assert a != b
            for a, b, c, d in BEAN_LINEAR:
                assert {a, b, c, d}.issubset(crib_set)
            import json, sys
            sys.stdout.write(json.dumps({
                "bean_eq": len(BEAN_EQ),
                "bean_ineq": len(BEAN_INEQ),
                "bean_linear": len(BEAN_LINEAR),
            }))
        """)
        result = _run_with_env(code, {"KRYPTOS_CT_OVERRIDE": SYNTHETIC_CT_FIXTURE})
        assert result.returncode == 0, f"stderr: {result.stderr}"
        counts = json.loads(result.stdout)
        # Synthetic counts won't match K4's; just verify they're sane
        # integers >= 0. (For most non-degenerate synthetic CTs they
        # are non-trivially > 0; we don't pin a specific value because
        # different synthetic CTs produce different counts.)
        assert isinstance(counts["bean_eq"], int) and counts["bean_eq"] >= 0
        assert isinstance(counts["bean_ineq"], int) and counts["bean_ineq"] >= 0
        assert isinstance(counts["bean_linear"], int) and counts["bean_linear"] >= 0

    def test_synthetic_does_not_assert_k4_self_encrypt(self):
        """Synthetic CT[32] / CT[73] generally won't match crib chars.

        This test uses a synthetic CT whose chars at 32 and 73 are NOT
        'S' and 'K'. Under default mode, the kernel would assert-fail.
        Under synthetic mode, the assertions are gated, so import succeeds.
        """
        # Build a CT where pos 32 and 73 are deliberately not S/K
        ct = list("A" * 97)
        ct[32] = "Q"  # not S
        ct[73] = "Q"  # not K
        ct[0] = "Z"   # not O
        ct[-1] = "Z"  # not R
        synth = "".join(ct)
        assert len(synth) == 97

        code = textwrap.dedent("""
            from kryptos.kernel.constants import CT
            assert CT[32] == "Q"
            assert CT[73] == "Q"
            assert CT[0] == "Z" and CT[-1] == "Z"
            print("OK")
        """)
        result = _run_with_env(code, {"KRYPTOS_CT_OVERRIDE": synth})
        assert result.returncode == 0, f"K4 self-encrypt assertion leaked into synthetic mode. stderr: {result.stderr}"


# ── Override validation: malformed inputs rejected at import time ────────


class TestOverrideValidation:
    """Malformed override values must raise ValueError before module loads."""

    def test_override_wrong_length_rejected(self):
        result = _run_with_env(
            "import kryptos.kernel.constants",
            {"KRYPTOS_CT_OVERRIDE": "A" * 96},  # 96, not 97
        )
        assert result.returncode != 0
        assert "must be exactly 97 chars" in result.stderr

    def test_override_lowercase_rejected(self):
        result = _run_with_env(
            "import kryptos.kernel.constants",
            {"KRYPTOS_CT_OVERRIDE": "a" * 97},
        )
        assert result.returncode != 0
        assert "uppercase A-Z only" in result.stderr

    def test_override_non_alpha_rejected(self):
        result = _run_with_env(
            "import kryptos.kernel.constants",
            {"KRYPTOS_CT_OVERRIDE": "A" * 96 + "1"},
        )
        assert result.returncode != 0
        assert "uppercase A-Z only" in result.stderr

    def test_crib_override_duplicate_normalized_position_rejected(self):
        result = _run_with_env(
            "import kryptos.kernel.constants",
            {
                "KRYPTOS_CT_OVERRIDE": SYNTHETIC_CT_FIXTURE,
                "KRYPTOS_CRIB_DICT_OVERRIDE": json.dumps({
                    "1": "A",
                    "01": "B",
                }),
            },
        )
        assert result.returncode != 0
        assert "duplicate position 1" in result.stderr


# ── Round-trip: synthetic CT correctly preserved through Bean ────────────


class TestRoundTrip:
    """End-to-end: feed a known synthetic CT, verify Bean derivation
    matches what we'd compute by hand on (synthetic_CT, real_cribs)."""

    def test_synthetic_bean_eq_matches_manual_derivation(self):
        """Manually compute BEAN_EQ for a chosen synthetic CT, compare."""
        # Choose a synthetic CT where we can pre-compute the expected
        # BEAN_EQ. Construct it so that two crib positions deliberately
        # share a (CT, PT) pair under all three variants — this gives a
        # known non-empty BEAN_EQ. Use a synthetic where CT[27]=CT[65]
        # (two distinct crib positions where both crib chars are 'R').
        ct = list("A" * 97)
        ct[27] = "X"  # arbitrary
        ct[65] = "X"  # same as ct[27]
        synth = "".join(ct)

        # Now under any cipher variant, k[27] and k[65] are derived from
        # the same (CT, PT) pair (both X, both R), so they're equal.
        code = textwrap.dedent("""
            from kryptos.kernel.constants import BEAN_EQ
            import sys, json
            sys.stdout.write(json.dumps([list(p) for p in BEAN_EQ]))
        """)
        result = _run_with_env(code, {"KRYPTOS_CT_OVERRIDE": synth})
        assert result.returncode == 0, f"stderr: {result.stderr}"
        bean_eq = json.loads(result.stdout)
        # (27, 65) must appear in BEAN_EQ because we constructed it that way
        bean_eq_set = {tuple(p) for p in bean_eq}
        assert (27, 65) in bean_eq_set, f"Expected (27,65) in BEAN_EQ, got {bean_eq_set}"
