"""DEPRECATED: moved to kryptosbot/_archive/worker.py on 2026-04-20.

Reason: superseded by the controller's integrated worker dispatch path (see
`kryptosbot/controller.py` and `kryptosbot/agent_runner.py`). Its imports
are broken — `kryptosbot.framework_strategies` does not exist in the
current tree.

This stub exists to surface a clear error instead of a silent
ModuleNotFoundError.

Quarantined in framework maturation Phase 1; see
`docs/maturation/phase_01_report.md`.
"""

raise ImportError(
    "kryptosbot.worker is deprecated and its dependency "
    "kryptosbot.framework_strategies no longer exists. "
    "Worker dispatch now lives in kryptosbot.controller and "
    "kryptosbot.agent_runner. "
    "The original source lives at kryptosbot/_archive/worker.py for "
    "historical reference only."
)
