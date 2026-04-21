from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "ops" / "tools" / "self_heal.py"
SPEC = importlib.util.spec_from_file_location("self_heal", MODULE_PATH)
self_heal = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
sys.modules[SPEC.name] = self_heal
SPEC.loader.exec_module(self_heal)


def test_restarts_api_on_local_failure():
    state = self_heal.State(local_down_streak=1, public_down_streak=0, oom_event_count=0)
    obs = self_heal.Observation(
        now_ts=1_000_000,
        api_healthy=False,
        public_healthy=False,
        dns_matches_wan=True,
        oom_events=0,
    )
    state.last_remediation_ts = 0
    assert self_heal.decide_action(state, obs) == "restart_api"


def test_restarts_public_stack_on_sustained_public_only_failure():
    state = self_heal.State(public_down_streak=3, local_down_streak=0, oom_event_count=0)
    obs = self_heal.Observation(
        now_ts=1_000_000,
        api_healthy=True,
        public_healthy=False,
        dns_matches_wan=True,
        oom_events=0,
    )
    assert self_heal.decide_action(state, obs) == "restart_public_stack"


def test_reboots_after_repeated_fresh_ooms():
    state = self_heal.State(public_down_streak=0, local_down_streak=0, oom_event_count=3)
    obs = self_heal.Observation(
        now_ts=1_000_000,
        api_healthy=True,
        public_healthy=True,
        dns_matches_wan=True,
        oom_events=3,
    )
    assert self_heal.decide_action(state, obs) == "reboot_host"


def test_cooldown_blocks_repeat_remediation():
    state = self_heal.State(public_down_streak=10, local_down_streak=0, oom_event_count=0)
    state.last_remediation_ts = 1_000_000 - self_heal.REMEDIATION_COOLDOWN_SECONDS + 30
    obs = self_heal.Observation(
        now_ts=1_000_000,
        api_healthy=True,
        public_healthy=False,
        dns_matches_wan=True,
        oom_events=0,
    )
    assert self_heal.decide_action(state, obs) == "none"
