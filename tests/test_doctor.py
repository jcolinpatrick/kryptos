"""Smoke test for `python3 -m kryptos doctor`.

Pins the expected behaviour that on a clean repo the doctor reports zero
failures. Specifically guards against regressions of the
bean_count / bean_ineq_count / bean_linear_count pins (CLAUDE.md §Key
Gotchas — the prior threshold of 21 was stale and silently failed for
months).

Added in framework internal phase 1; see
<internal>.
"""

from __future__ import annotations

from kryptos.cli.doctor import run_doctor


def test_doctor_reports_zero_failures():
    """All doctor checks should pass on a clean repo.

    If this fails, either a real environmental regression has landed, or
    the Bean constraint tuples have changed size and the canonical pins in
    src/kryptos/cli/doctor.py need to be updated.
    """
    all_pass = run_doctor(verbose=False)
    assert all_pass, (
        "kryptos doctor reported failures on a clean repo. "
        "Run `PYTHONPATH=src python3 -m kryptos doctor` to see which checks "
        "failed. The most common cause is drift in BEAN_EQ/BEAN_INEQ/"
        "BEAN_LINEAR tuple sizes; update the canonical pins in "
        "src/kryptos/cli/doctor.py if a legitimate expansion has landed."
    )
