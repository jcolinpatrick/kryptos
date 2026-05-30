"""API cost accounting for real-API self-test runs.

Round 2 Phase R2-5 (2026-04-21). The brief's §6.1 requires a hard USD
ceiling on real-API self-test runs so the experiment can't silently
run away with API spend. This module tracks per-message token
consumption, converts to USD via a configured pricing dict, and
halts the caller when the budget is exhausted.

Design notes:

  * Pricing is loaded from ``kryptosbot.config`` if present (see
    ``config.PRICING_USD_PER_MTOKENS``), else from an environment
    variable, else a conservative fallback.
  * ``charge()`` is thread-safe via a simple lock.
  * ``exceeded()`` is checked by the controller after each message;
    the caller halts the run and emits an explicit status.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Dict

logger = logging.getLogger("kryptosbot.token_accountant")


# Default pricing (USD per 1M tokens). Source: Anthropic public pricing
# page at the time of R2-5 authorship. These numbers are load-bearing
# ONLY for the USD ceiling — if they drift, the ceiling becomes looser
# or tighter, but the machinery stays correct. Override via the
# ``pricing`` kwarg on TokenAccountant or via the
# ``KRYPTOSBOT_PRICING_JSON`` environment variable.
_DEFAULT_PRICING: Dict[str, Dict[str, float]] = {
    # Claude 4.x series (opus-4-8 is the current routing default; opus-4-7/4-6
    # retained so any historical / in-flight charge still prices correctly).
    "claude-opus-4-8":   {"input": 15.00, "output": 75.00},
    "claude-opus-4-7":   {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6": {"input":  3.00, "output": 15.00},
    "claude-haiku-4-5":  {"input":  1.00, "output":  5.00},
    # Conservative unknown-model fallback (priced as Opus to fail safe).
    "unknown":           {"input": 15.00, "output": 75.00},
}


def _normalize_model_name(model: str) -> str:
    """Strip variant suffixes to match the pricing table.

    Claude model IDs sometimes carry suffixes like '[1m]' (context size)
    or date stamps. The pricing is per family, not per variant.
    """
    m = (model or "").strip().lower()
    for prefix in ("claude-opus-4-8", "claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5"):
        if m.startswith(prefix):
            return prefix
    return "unknown"


@dataclass
class TokenCharge:
    """One accounted-for billing event."""
    model: str
    input_tokens: int
    output_tokens: int
    usd: float


@dataclass
class TokenAccountant:
    """Per-run token + USD ledger with a hard spending ceiling.

    Thread-safe via a lock. Typical usage from the controller:

        acc = TokenAccountant(max_usd=5.00)
        ...
        acc.charge("claude-opus-4-8", resp.usage.input_tokens,
                   resp.usage.output_tokens)
        if acc.exceeded():
            raise RuntimeError(
                f"budget exhausted: ${acc.total_usd():.2f} / ${acc.max_usd:.2f}"
            )
    """
    max_usd: float
    pricing: Dict[str, Dict[str, float]] = field(
        default_factory=lambda: dict(_DEFAULT_PRICING)
    )
    _charges: list[TokenCharge] = field(default_factory=list)
    _total_usd: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _warned_50: bool = False
    _warned_80: bool = False

    def charge(
        self, model: str, input_tokens: int, output_tokens: int,
    ) -> TokenCharge:
        """Record a billing event for one model message.

        Returns the TokenCharge object recorded. Does NOT raise if
        the budget is exceeded; the caller must check ``exceeded()``
        after the charge.
        """
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError(
                f"token counts must be non-negative; got "
                f"input={input_tokens}, output={output_tokens}"
            )
        family = _normalize_model_name(model)
        rates = self.pricing.get(family) or self.pricing.get("unknown") or {
            "input": 15.00, "output": 75.00,
        }
        usd = (
            input_tokens * rates["input"] / 1_000_000
            + output_tokens * rates["output"] / 1_000_000
        )
        with self._lock:
            charge = TokenCharge(
                model=family,
                input_tokens=int(input_tokens),
                output_tokens=int(output_tokens),
                usd=usd,
            )
            self._charges.append(charge)
            self._total_usd += usd
            # Proactive warnings at 50% and 80% consumption.
            if not self._warned_50 and self._total_usd >= 0.5 * self.max_usd:
                logger.warning(
                    "TokenAccountant: 50%% of USD budget consumed "
                    "($%.2f / $%.2f)",
                    self._total_usd, self.max_usd,
                )
                self._warned_50 = True
            if not self._warned_80 and self._total_usd >= 0.8 * self.max_usd:
                logger.warning(
                    "TokenAccountant: 80%% of USD budget consumed "
                    "($%.2f / $%.2f)",
                    self._total_usd, self.max_usd,
                )
                self._warned_80 = True
        return charge

    def total_usd(self) -> float:
        with self._lock:
            return self._total_usd

    def remaining_usd(self) -> float:
        with self._lock:
            return max(0.0, self.max_usd - self._total_usd)

    def exceeded(self) -> bool:
        with self._lock:
            return self._total_usd >= self.max_usd

    def charge_count(self) -> int:
        with self._lock:
            return len(self._charges)

    def total_input_tokens(self) -> int:
        with self._lock:
            return sum(c.input_tokens for c in self._charges)

    def total_output_tokens(self) -> int:
        with self._lock:
            return sum(c.output_tokens for c in self._charges)

    def summary(self) -> dict:
        """Human- and machine-readable final summary."""
        with self._lock:
            by_model: Dict[str, Dict[str, int | float]] = {}
            for c in self._charges:
                m = by_model.setdefault(
                    c.model, {"input_tokens": 0, "output_tokens": 0, "usd": 0.0},
                )
                m["input_tokens"] += c.input_tokens
                m["output_tokens"] += c.output_tokens
                m["usd"] += c.usd
            return {
                "max_usd": self.max_usd,
                "total_usd": round(self._total_usd, 4),
                "remaining_usd": round(max(0.0, self.max_usd - self._total_usd), 4),
                "exceeded": self._total_usd >= self.max_usd,
                "charge_count": len(self._charges),
                "by_model": by_model,
            }


def default_pricing() -> Dict[str, Dict[str, float]]:
    """Return the effective default pricing table.

    Honors a ``KRYPTOSBOT_PRICING_JSON`` environment variable when set
    (useful for tests and for operators who want to lock a specific
    snapshot of pricing).
    """
    env = os.environ.get("KRYPTOSBOT_PRICING_JSON")
    if env:
        import json
        try:
            return json.loads(env)
        except json.JSONDecodeError as exc:
            logger.warning(
                "KRYPTOSBOT_PRICING_JSON unparseable; using defaults: %s",
                exc,
            )
    return dict(_DEFAULT_PRICING)
