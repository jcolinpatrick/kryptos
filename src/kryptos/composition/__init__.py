"""Multi-layer composition search framework for K4 cryptanalysis.

Provides disciplined enumeration and testing of ordered cipher layer
combinations, with constraint propagation, early pruning, and durable
campaign tracking.

Architecture:
    models.py      — Core dataclasses (LayerDef, LayerInstance, CompositionStack)
    registry.py    — Layer family registry with initial families
    constraints.py — Constraint propagation and pruning engine
    ledger.py      — SQLite campaign/coverage ledger
    orchestrator.py — Campaign execution and parallel dispatch
    scoring_bridge.py — Bridge to canonical scoring pipeline
"""
