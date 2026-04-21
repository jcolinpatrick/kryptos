#!/usr/bin/env python3
"""Self-heal watchdog for the public site and local API.

Run this from a root-owned systemd timer. The script is intentionally narrow:
it only heals the public serving stack (`nginx` + `internal-api`) and only
reboots after repeated fresh OOM kills or repeated failed service restarts.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


STATE_PATH = Path("/var/lib/<internal>/self_heal_state.json")
LOG_PATH = Path("/home/cpatrick/kryptos/logs/self_heal.log")
ENV_PATH = Path("/home/cpatrick/kryptos/.env")
DOMAIN = "internal.com"
API_URL = "http://127.0.0.1:8321/"
PUBLIC_URL = f"https://{DOMAIN}/"
NTFY_TOPIC_KEY = "NTFY_TOPIC"
WAN_IP_SERVICES = (
    "https://api.ipify.org",
    "https://ifconfig.me",
    "https://icanhazip.com",
)
OOM_WINDOW_SECONDS = 15 * 60
REMEDIATION_COOLDOWN_SECONDS = 10 * 60
PUBLIC_RESTART_THRESHOLD = 3
PUBLIC_REBOOT_THRESHOLD = 9
OOM_REBOOT_THRESHOLD = 3


@dataclass
class State:
    public_down_streak: int = 0
    local_down_streak: int = 0
    oom_event_count: int = 0
    last_oom_cursor: str = ""
    last_remediation_ts: int = 0
    last_action: str = "none"


@dataclass
class Observation:
    now_ts: int
    api_healthy: bool
    public_healthy: bool
    dns_matches_wan: bool | None
    oom_events: int


def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"[{ts()}] {message}\n")


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if not ENV_PATH.exists():
        return env
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def notify(env: dict[str, str], title: str, message: str, priority: str = "high", tags: str = "warning") -> None:
    topic = env.get(NTFY_TOPIC_KEY, "").strip()
    if not topic:
        return
    try:
        request = urllib.request.Request(
            f"https://ntfy.sh/{topic}",
            data=message.encode("utf-8"),
            headers={
                "Title": title,
                "Priority": priority,
                "Tags": tags,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10):
            pass
    except Exception as exc:  # pragma: no cover - best-effort only
        log(f"WARN: ntfy notification failed: {exc}")


def load_state() -> State:
    if not STATE_PATH.exists():
        return State()
    try:
        payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return State(**payload)
    except Exception:
        return State()


def save_state(state: State) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(asdict(state), indent=2, sort_keys=True), encoding="utf-8")


def http_ok(url: str, timeout: int = 10) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 400
    except Exception:
        return False


def resolve_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def get_wan_ip() -> str | None:
    for url in WAN_IP_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                ip = response.read().decode("utf-8").strip()
                if ip and ip.count(".") == 3:
                    return ip
        except Exception:
            continue
    return None


def get_fresh_oom_events(last_cursor: str) -> tuple[str, int]:
    command = [
        "journalctl",
        "-k",
        "--since",
        f"-{OOM_WINDOW_SECONDS}s",
        "--output",
        "json",
        "--no-pager",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, check=True)
    except Exception as exc:  # pragma: no cover - environment-dependent
        log(f"WARN: unable to read kernel journal for OOM events: {exc}")
        return last_cursor, 0

    max_cursor = last_cursor
    count = 0
    for raw_line in proc.stdout.splitlines():
        if not raw_line.strip():
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        cursor = event.get("__CURSOR__", "")
        if cursor and last_cursor and cursor <= last_cursor:
            continue
        message = event.get("MESSAGE", "")
        if "Out of memory: Killed process" not in message:
            if cursor and cursor > max_cursor:
                max_cursor = cursor
            continue
        if not any(name in message for name in ("python3", "uvicorn", "dbus-daemon")):
            if cursor and cursor > max_cursor:
                max_cursor = cursor
            continue
        count += 1
        if cursor and cursor > max_cursor:
            max_cursor = cursor
    return max_cursor, count


def collect_observation(state: State) -> Observation:
    now_ts = int(time.time())
    api_healthy = http_ok(API_URL, timeout=5)
    public_healthy = http_ok(PUBLIC_URL, timeout=10)
    dns_ip = resolve_domain(DOMAIN)
    wan_ip = get_wan_ip()
    dns_matches_wan = None if not dns_ip or not wan_ip else dns_ip == wan_ip
    last_oom_cursor, oom_events = get_fresh_oom_events(state.last_oom_cursor)
    state.last_oom_cursor = last_oom_cursor
    return Observation(
        now_ts=now_ts,
        api_healthy=api_healthy,
        public_healthy=public_healthy,
        dns_matches_wan=dns_matches_wan,
        oom_events=oom_events,
    )


def update_state(state: State, obs: Observation) -> None:
    state.local_down_streak = 0 if obs.api_healthy else state.local_down_streak + 1
    state.public_down_streak = 0 if obs.public_healthy else state.public_down_streak + 1
    state.oom_event_count = 0 if obs.oom_events == 0 else state.oom_event_count + obs.oom_events


def decide_action(state: State, obs: Observation) -> str:
    cooling_down = (obs.now_ts - state.last_remediation_ts) < REMEDIATION_COOLDOWN_SECONDS
    if cooling_down:
        return "none"

    if state.oom_event_count >= OOM_REBOOT_THRESHOLD:
        return "reboot_host"

    if state.local_down_streak >= 1:
        return "restart_api"

    if (
        state.public_down_streak >= PUBLIC_REBOOT_THRESHOLD
        and obs.api_healthy
        and obs.dns_matches_wan is True
    ):
        return "reboot_host"

    if (
        state.public_down_streak >= PUBLIC_RESTART_THRESHOLD
        and obs.api_healthy
        and obs.dns_matches_wan is True
    ):
        return "restart_public_stack"

    return "none"


def run_systemctl(*args: str) -> None:
    subprocess.run(["systemctl", *args], check=True)


def execute_action(action: str, env: dict[str, str], state: State, obs: Observation) -> None:
    if action == "none":
        return

    detail = (
        f"api_healthy={obs.api_healthy} public_healthy={obs.public_healthy} "
        f"dns_matches_wan={obs.dns_matches_wan} public_down_streak={state.public_down_streak} "
        f"local_down_streak={state.local_down_streak} oom_event_count={state.oom_event_count}"
    )

    if action == "restart_api":
        log(f"SELF-HEAL: restarting internal-api ({detail})")
        run_systemctl("restart", "internal-api.service")
        notify(env, "internalself-heal", f"Restarted internal-api. {detail}")
    elif action == "restart_public_stack":
        log(f"SELF-HEAL: restarting nginx + internal-api ({detail})")
        run_systemctl("restart", "nginx.service")
        run_systemctl("restart", "internal-api.service")
        notify(env, "internalself-heal", f"Restarted nginx + internal-api. {detail}")
    elif action == "reboot_host":
        log(f"SELF-HEAL: rebooting host ({detail})")
        notify(
            env,
            "internalemergency reboot",
            f"Rebooting host after repeated OOMs or sustained public outage. {detail}",
            priority="urgent",
            tags="rotating_light",
        )
        run_systemctl("reboot")
    else:  # pragma: no cover - guarded by decide_action
        raise ValueError(f"Unknown action: {action}")

    state.last_action = action
    state.last_remediation_ts = obs.now_ts
    if action == "reboot_host":
        state.oom_event_count = 0


def main() -> int:
    env = load_env()
    state = load_state()
    obs = collect_observation(state)
    update_state(state, obs)
    action = decide_action(state, obs)
    execute_action(action, env, state, obs)
    save_state(state)
    if action == "none":
        log(
            "OK: "
            f"api_healthy={obs.api_healthy} public_healthy={obs.public_healthy} "
            f"dns_matches_wan={obs.dns_matches_wan} public_down_streak={state.public_down_streak} "
            f"local_down_streak={state.local_down_streak} oom_event_count={state.oom_event_count}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
