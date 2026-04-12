"""Local provenance dataclasses for the two-layer campaign.

Self-contained. Does NOT import from kryptosbot/ — the core kryptos
package must stay stdlib-only and independent of the agent subproject.
"""
from __future__ import annotations

from enum import Enum


class ResultProvenance(str, Enum):
    """Epistemic provenance tag for a finding.

    STRUCTURAL      — holds independent of assumptions
    H1_CONDITIONAL  — only valid under direct positional alignment CT[i]->PT[i]
    PROJECT_RERUN   — measured by this project's reproducible pipeline
    BEAN_REPORTED   — cited from Bean 2021 / external, NOT project-rerun
    EXPLORATORY     — candidate for future verification, not load-bearing
    """

    STRUCTURAL = "structural"
    H1_CONDITIONAL = "h1_conditional"
    PROJECT_RERUN = "project_rerun"
    BEAN_REPORTED = "bean_reported"
    EXPLORATORY = "exploratory"
