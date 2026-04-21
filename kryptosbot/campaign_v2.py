"""DEPRECATED: moved to kryptosbot/_archive/campaign_v2.py on 2026-04-20.

Reason: superseded by `kryptosbot/run_controller.py` (see
`kryptosbot/ARCHITECTURE.md` §Migration from campaign_v2). Its imports are
broken — `kryptosbot.analyst_prompts` does not exist in the current tree.

This stub exists to surface a clear error instead of a silent
ModuleNotFoundError when an automation script or a stale CLAUDE.md snippet
still references `kryptosbot/campaign_v2.py`.

Quarantined in framework maturation Phase 1; see
`docs/maturation/phase_01_report.md`.
"""

raise ImportError(
    "kryptosbot.campaign_v2 is deprecated and its dependency "
    "kryptosbot.analyst_prompts no longer exists. "
    "Use kryptosbot.run_controller instead. "
    "The original source lives at kryptosbot/_archive/campaign_v2.py for "
    "historical reference only."
)
