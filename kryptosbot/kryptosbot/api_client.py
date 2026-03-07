"""
Direct Anthropic API client with prompt caching, token tracking,
conversation mode, and batch API support.

Replaces the Agent SDK's opaque Claude Code subprocess spawning with
direct, measurable API calls. Key advantages:
  - Prompt caching (5x effective throughput for repeated K4 context)
  - Exact token tracking (no more 0/0 mystery)
  - Model selection (Sonnet for generation, Haiku for scoring)
  - Extended thinking support
  - Conversation mode (multi-turn reasoning with memory)
  - Batch API for large-scale hypothesis evaluation (50% discount)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anthropic

logger = logging.getLogger("kryptosbot.api_client")

# ---------------------------------------------------------------------------
# Pricing (as of 2026-03)
# ---------------------------------------------------------------------------

PRICING = {
    "claude-sonnet-4-6":  {"input": 3.0, "output": 15.0, "cache_read": 0.30, "cache_write": 3.75},
    "claude-haiku-4-5":   {"input": 0.80, "output": 4.0, "cache_read": 0.08, "cache_write": 1.0},
    "claude-opus-4-6":    {"input": 15.0, "output": 75.0, "cache_read": 1.50, "cache_write": 18.75},
}

# Batch API = 50% off all prices
BATCH_DISCOUNT = 0.5


@dataclass
class TokenUsage:
    """Cumulative token usage tracker with cost estimation."""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    requests: int = 0
    batch_requests: int = 0
    model: str = "claude-sonnet-4-6"

    def add(self, response: anthropic.types.Message) -> None:
        usage = response.usage
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0)
        self.cache_creation_tokens += getattr(usage, "cache_creation_input_tokens", 0)
        self.requests += 1

    def add_batch(self, input_tokens: int, output_tokens: int, count: int = 1) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.batch_requests += count

    @property
    def cost_usd(self) -> float:
        p = PRICING.get(self.model, PRICING["claude-sonnet-4-6"])
        return (
            self.input_tokens * p["input"] / 1_000_000
            + self.output_tokens * p["output"] / 1_000_000
            + self.cache_read_tokens * p["cache_read"] / 1_000_000
            + self.cache_creation_tokens * p["cache_write"] / 1_000_000
        )

    def summary(self) -> str:
        batch_str = f" + {self.batch_requests} batch" if self.batch_requests else ""
        return (
            f"{self.requests} requests{batch_str} | "
            f"{self.input_tokens:,} in + {self.output_tokens:,} out + "
            f"{self.cache_read_tokens:,} cached = ${self.cost_usd:.2f}"
        )


# ---------------------------------------------------------------------------
# K4 system prompt (cacheable)
# ---------------------------------------------------------------------------

K4_SYSTEM_PROMPT = """You are a cryptanalyst working on Kryptos K4, the last unsolved section of the CIA sculpture.

## The Problem

K4 CARVED TEXT (97 chars):
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

Known cribs (0-indexed positions):
  - Positions 21-33: EASTNORTHEAST
  - Positions 63-73: BERLINCLOCK

Self-encrypting positions: CT[32]=PT[32]=S, CT[73]=PT[73]=K

## Bean 2021 Statistical Analysis (CRITICAL)

Richard Bean's 2021 paper provides strong statistical evidence about K4's structure:

1. **Minor differences** (p≈1/5520): When PT letters are from {K,R,Y,P,T,O,S}, the CT letters are very close in the alphabet (mean distance 2.1). This strongly suggests the cipher alphabet is near-standard, perhaps keyword-based.

2. **Repeated-PT-letter distances** (p≈1/240): CT letters for the same PT letter are close to each other (mean 3.6, 10/13 < 5). This implies one-to-one substitution for MOST positions.

3. **Width-21 bigram repeats** (p≈1/6750): 11 repeated vertical bigrams at width 21. Consistent with Gromark-like period-21 key structure.

4. **Reversed-KA mod-5 pattern** (p≈1/1470): Under reversed Kryptos alphabet numbering, 13/24 key values are multiples of 5. Possibly significant.

5. **Sanborn quote**: "BERLINCLOCK in plain matches directly with NYPVTTMZFPK. It is a one-to-one match with plain B taken, has the encipherment done to it, and out pops a cipher N."

Bean argues NO TRANSPOSITION is involved. However, all direct substitution attempts (including exhaustive Gromark search) have FAILED.

## The Working Hypothesis: PARTIAL Transposition

Bean's evidence suggests MOST positions have direct one-to-one substitution correspondence. But pure substitution has been exhaustively tested and failed. The middle ground: K4 uses substitution with only a SMALL NUMBER of positions transposed (perhaps 2-10 character swaps).

This dramatically reduces the search space:
  - 1 swap: C(97,2) = 4,656 candidates per keyword combo
  - 2 swaps: ~10M (tractable with hot-position targeting)
  - 3+ swaps: hill-climbable from near-identity starting point

## Bean Constraints

Equality: k[27] = k[65] (both positions encrypt R→P, so key values must match)
Inequalities: 21 pairs where key values must DIFFER (derived from same PT letter → different CT letter, or different PT letter → same CT letter)

These constraints are ALREADY SATISFIED under identity (no transposition) — they don't help find wrong positions, but they constrain the substitution key structure.

## Key Constants

KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ (keyword "KRYPTOS" first, all 26 letters)
Standard: ABCDEFGHIJKLMNOPQRSTUVWXYZ

## Bean-Viable Keyword Lengths

Bean constraints make most keyword lengths IMPOSSIBLE:
- IMPOSSIBLE lengths: 1-7, 9, 10, 11, 12, 14, 15, 17, 18, 21, 22, 25
- VIABLE lengths: 8, 13, 16, 19, 20, 23, 24, 26+
- Length 8 dominates (3,688 of 5,204 viable words from dictionary)

Known keywords KRYPTOS (7), PALIMPSEST (10), ABSCISSA (8) ALL FAIL Bean constraints.
Only COLOPHON and PARALLAX (both length 8) pass from the known series.
DO NOT generate hypotheses using Bean-impossible keywords as periodic keys.

Top Sanborn-aesthetic Bean-passing keywords (length 8):
MONOLITH, PEDESTAL, CALATHOS, APOPHYGE, LARARIUM, LOGOGRAM, COLOPHON, PARALLAX,
CIVISION, PARADIGM, HOROLOGY, TOPOLOGY, NIHILIST, CAVALIER, YAMAGANE

## Gromark Status

Exhaustively tested 3.2B primers (bases 21-26, primer lengths 2-6, AZ+KA alphabets).
ZERO crib matches. Standard Gromark is effectively eliminated.

## The Cardan Grille (for full-scramble hypotheses)

28×31 grid overlaying cipher panel. Three Kryptos-only elements (absent from Antipodes):
1. Key column (AZ order), 2. Header/footer rows, 3. Extra L on row N

Corrected grille extract (100 chars): HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD

## What Has Been Eliminated

ALL single-layer classical ciphers (600+ experiments). ALL standard transpositions (16M+ configs).
Exhaustive Gromark base-10/len-5 (39 primers). VERDIGRIS (174 configs, 362K perms).
Affine mod 97 (9,312). K3-style rotation. Single-step 97-cycles (96).

## Your Task

Generate hypotheses focused on TWO complementary tracks:

**Track A — Partial Transposition**: Which specific positions might be transposed? Consider:
  - Positions where quadgram score is worst under direct decryption
  - Positions involved in the width-21 bigram pattern (could be structural artifacts of transposition)
  - DIAWINFBN (positions 55-63) has a constant-difference property (Δ4=5 mod 26) — could this segment be preserved or disrupted?
  - The reversed-KA mod-5 pattern might identify which positions are "correct" vs "swapped"

**Track B — Non-Periodic Key**: Bean's Gromark didn't work, but the key IS non-periodic. Consider:
  - Generalized Fibonacci with non-standard bases (5, 8, 12, 26)
  - Berlin Clock arithmetic (base 5 hours, base 12 minutes)
  - Autokey variants (PT or CT feeds back into key)
  - Running key from a thematic source text

Output format: JSON array of hypothesis objects."""

# Hypothesis format instructions (appended to user messages)
HYPOTHESIS_FORMAT = """
Generate 5-15 hypotheses as a JSON array. Each hypothesis must have:
- "name": short identifier
- "description": what this tests and why
- "type": one of "permutation" | "generator" | "reading_order" | "hillclimb" | "partial_swap"
- "data": depends on type:
  - For "permutation": {"perm": [list of 97 integers 0-96]}
  - For "generator": {"python_code": "def generate(ct):\\n  ...\\n  return [(perm, label), ...]"}
  - For "reading_order": {"order": "description", "grid_width": N, "grid_height": M}
  - For "hillclimb": {"seed_perm": [97 ints], "cipher": "vig", "keyword": "KRYPTOS", "alphabet": "AZ", "iterations": N, "fixed_positions": [list of position indices to keep fixed]}
  - For "partial_swap": {"swap_positions": [[i,j], [k,l], ...], "cipher": "vig"|"beau", "keyword": "KRYPTOS", "alphabet": "AZ"|"KA"}
    Tests specific position swaps in the CT before decryption. Use this when you believe
    only a few specific positions are transposed.

Prioritize hypotheses that:
1. **PARTIAL TRANSPOSITION** — Identify specific positions likely to be transposed
   (Bean's evidence says MOST positions are correct one-to-one)
2. **NON-PERIODIC KEY MODELS** — Gromark variants, autokey, Berlin Clock arithmetic
3. Use the Cardan grille structure for full-scramble hypotheses
4. Use "generator" type for systematic enumeration of related candidates
5. Use "hillclimb" type to refine promising permutations from prior rounds

KEY INSIGHT: Bean's statistics show the cipher alphabet is near-standard and most positions
have direct CT↔PT correspondence. Focus on finding the FEW exceptions, not the many.

IMPORTANT for generator code:
- Use ONLY Python stdlib (no numpy, sympy, scipy, etc.)
- The function signature must be: def generate(ct: str) -> list[tuple[list[int], str]]
- Each returned tuple is (permutation, label) where permutation is a list of 97 ints 0-96

Return ONLY the JSON array, no other text."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class KryptosAPIClient:
    """Direct Anthropic API client for K4 hypothesis generation.

    Supports conversation mode: when enabled, maintains message history
    across rounds so Claude remembers its own reasoning and prior results.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-6",
        budget_usd: float | None = None,
        conversation_mode: bool = False,
    ):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.usage = TokenUsage(model=model)
        self.budget_usd = budget_usd
        self.conversation_mode = conversation_mode
        self._conversation_history: list[dict] = []
        self._system_blocks = [
            {
                "type": "text",
                "text": K4_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def is_over_budget(self) -> bool:
        if self.budget_usd is None:
            return False
        return self.usage.cost_usd >= self.budget_usd

    def _make_api_call(
        self,
        messages: list[dict],
        *,
        max_tokens: int = 8192,
        thinking_budget: int | None = None,
    ) -> anthropic.types.Message | None:
        """Shared API call logic with error handling and token tracking."""
        if self.is_over_budget():
            logger.warning("Budget exceeded ($%.2f / $%.2f)", self.usage.cost_usd, self.budget_usd)
            return None

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": self._system_blocks,
            "messages": messages,
        }

        if thinking_budget and ("sonnet" in self.model or "opus" in self.model):
            kwargs["thinking"] = {"type": "enabled", "budget_tokens": thinking_budget}
            kwargs["max_tokens"] = max(max_tokens, thinking_budget + 4096)

        try:
            response = self.client.messages.create(**kwargs, timeout=180.0)
        except Exception as e:
            logger.error("API call failed: %s", e)
            return None

        self.usage.add(response)
        logger.info(
            "API call: %d in + %d out + %d cached = $%.3f (cumulative: %s)",
            response.usage.input_tokens,
            response.usage.output_tokens,
            getattr(response.usage, "cache_read_input_tokens", 0),
            self.usage.cost_usd,
            self.usage.summary(),
        )
        return response

    def _extract_text(self, response: anthropic.types.Message) -> str:
        """Extract text content from response, skipping thinking blocks."""
        for block in response.content:
            if block.type == "text":
                return block.text
        return ""

    def _parse_json_from_text(self, text: str) -> list[dict] | None:
        """Parse JSON array from text, handling markdown wrapping."""
        import re

        # Strategy 1: Try markdown code block extraction
        for pattern in [r"```json\s*\n(.*?)```", r"```\s*\n(.*?)```"]:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    result = json.loads(match.group(1).strip())
                    if isinstance(result, list):
                        return result
                except (json.JSONDecodeError, ValueError):
                    pass

        # Strategy 2: Find the outermost JSON array directly
        start = text.find("[")
        if start >= 0:
            # Find matching closing bracket (handle nesting)
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "[":
                    depth += 1
                elif text[i] == "]":
                    depth -= 1
                    if depth == 0:
                        try:
                            result = json.loads(text[start:i + 1])
                            if isinstance(result, list):
                                return result
                        except (json.JSONDecodeError, ValueError):
                            pass
                        break

        # Strategy 3: Raw parse
        try:
            result = json.loads(text.strip())
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, ValueError):
            pass

        logger.warning("Failed to parse JSON from response (%d chars). First 200: %s",
                       len(text), text[:200])
        return None

    def _append_to_conversation(self, role: str, content: str) -> None:
        """Add a message to the conversation history."""
        if self.conversation_mode:
            # Truncate individual messages to prevent context bloat
            truncated = content[:2000] if len(content) > 2000 else content
            self._conversation_history.append({"role": role, "content": truncated})
            # Keep conversation tight — last 8 messages (~4 rounds)
            if len(self._conversation_history) > 8:
                self._conversation_history = self._conversation_history[-8:]

    def _get_messages(self, user_msg: str) -> list[dict]:
        """Build messages list: conversation history + new user message."""
        if self.conversation_mode and self._conversation_history:
            msgs = list(self._conversation_history)
            msgs.append({"role": "user", "content": user_msg})
            return msgs
        return [{"role": "user", "content": user_msg}]

    def generate_hypotheses(
        self,
        context: str,
        *,
        max_tokens: int = 8192,
        thinking_budget: int | None = 10000,
    ) -> list[dict]:
        """Generate structured hypothesis objects from Claude."""
        user_msg = f"""{context}

{HYPOTHESIS_FORMAT}"""

        messages = self._get_messages(user_msg)
        response = self._make_api_call(
            messages, max_tokens=max_tokens, thinking_budget=thinking_budget
        )
        if not response:
            return []

        text = self._extract_text(response)

        # Update conversation history
        self._append_to_conversation("user", user_msg)
        self._append_to_conversation("assistant", text)

        hypotheses = self._parse_json_from_text(text)
        if hypotheses:
            logger.info("Generated %d hypotheses", len(hypotheses))
            return hypotheses
        return []

    def analyze_results(
        self,
        results: list[dict],
        context: str = "",
        *,
        max_tokens: int = 4096,
    ) -> str:
        """Send test results back to Claude for analysis and next-step recommendations."""
        user_msg = f"""Here are the results from testing the last batch of hypotheses:

{json.dumps(results, indent=2)[:6000]}

{context}

Analyze these results:
1. Which hypotheses showed the most promise (highest quadgram scores, any crib proximity)?
2. What patterns do you see in the better-scoring results?
3. What refined hypotheses should we try next?

Be specific and concise."""

        messages = self._get_messages(user_msg)
        response = self._make_api_call(messages, max_tokens=max_tokens)
        if not response:
            return "API call failed."

        text = self._extract_text(response)

        # Update conversation history
        self._append_to_conversation("user", user_msg)
        self._append_to_conversation("assistant", text)

        return text

    def generate_test_script(
        self,
        hypothesis: dict,
        *,
        max_tokens: int = 8192,
        thinking_budget: int | None = 8000,
    ) -> str:
        """Ask Claude to generate a Python script that tests a specific hypothesis."""
        if self.is_over_budget():
            return ""

        user_msg = f"""Generate a standalone Python script that tests this hypothesis against K4:

{json.dumps(hypothesis, indent=2)}

Requirements:
- Use ONLY Python stdlib (no numpy, sympy, scipy, etc.)
- Script must use multiprocessing with all available CPU cores
- Import from the harness: `sys.path.insert(0, 'scripts/_infra'); from kbot_harness import test_perm, score_text, K4_CARVED, KEYWORDS`
- For each candidate permutation, call `test_perm(perm)` which returns a dict with 'score', 'crib_hits', 'best_plaintext', 'method'
- Print progress every 1000 candidates
- At the end, print JSON summary: {{"hypothesis": name, "tested": N, "best_score": X, "best_plaintext": "...", "best_method": "...", "crib_hits": N}}
- Script must be self-contained and runnable with: PYTHONPATH=src python3 -u <script>
- Keep it under 200 lines
- Use ProcessPoolExecutor for parallelism

Return ONLY the Python code, no explanation."""

        # Don't add script generation to conversation (too verbose)
        response = self._make_api_call(
            [{"role": "user", "content": user_msg}],
            max_tokens=max_tokens,
            thinking_budget=thinking_budget,
        )
        if not response:
            return ""

        text = self._extract_text(response)

        # Extract code from markdown
        if "```python" in text:
            text = text.split("```python")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        return text.strip()

    # ------------------------------------------------------------------
    # Batch API
    # ------------------------------------------------------------------

    def create_batch_evaluation(
        self,
        candidates: list[dict],
        *,
        eval_model: str | None = None,
        max_tokens: int = 1024,
    ) -> str | None:
        """Submit candidate decryptions for batch evaluation via Message Batches API.

        Each candidate dict should have: plaintext, method, score, perm_label.

        Returns batch_id for polling, or None on failure.
        Batch API runs at 50% discount and doesn't count against real-time rate limits.
        """
        model = eval_model or "claude-haiku-4-5"

        requests = []
        for i, cand in enumerate(candidates[:100000]):  # API limit
            requests.append({
                "custom_id": f"eval_{i}_{cand.get('perm_label', 'unknown')}",
                "params": {
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [
                        {
                            "role": "user",
                            "content": (
                                f"You are evaluating a candidate decryption of Kryptos K4.\n\n"
                                f"Candidate plaintext: {cand.get('plaintext', '')}\n"
                                f"Decryption method: {cand.get('method', '')}\n"
                                f"Quadgram score: {cand.get('score', 'unknown')}\n\n"
                                f"Evaluate this candidate:\n"
                                f"1. Does it contain recognizable English words or phrases?\n"
                                f"2. Does it read like a coherent message?\n"
                                f"3. Are EASTNORTHEAST and BERLINCLOCK present at positions 21 and 63?\n"
                                f"4. Rate confidence 0-100 that this is the correct decryption.\n\n"
                                f"Respond with ONLY a JSON object: "
                                f'{{"english_words": [...], "coherent": true/false, '
                                f'"cribs_present": true/false, "confidence": N, "notes": "..."}}'
                            ),
                        }
                    ],
                },
            })

        if not requests:
            return None

        try:
            batch = self.client.messages.batches.create(requests=requests)
            logger.info("Created batch %s with %d requests (model: %s)", batch.id, len(requests), model)
            return batch.id
        except Exception as e:
            logger.error("Batch creation failed: %s", e)
            return None

    def poll_batch(self, batch_id: str, timeout: float = 3600) -> list[dict] | None:
        """Poll a batch until complete, return parsed results.

        Returns list of dicts with evaluation results, or None on timeout/error.
        """
        start = time.monotonic()
        poll_interval = 10.0

        while time.monotonic() - start < timeout:
            try:
                batch = self.client.messages.batches.retrieve(batch_id)
            except Exception as e:
                logger.error("Batch poll failed: %s", e)
                return None

            status = batch.processing_status
            counts = batch.request_counts

            logger.info(
                "Batch %s: %s (succeeded=%d, errored=%d, expired=%d, processing=%d)",
                batch_id, status,
                counts.succeeded, counts.errored, counts.expired, counts.processing,
            )

            if status == "ended":
                break

            time.sleep(poll_interval)
            poll_interval = min(poll_interval * 1.5, 60.0)
        else:
            logger.error("Batch %s timed out after %.0fs", batch_id, timeout)
            return None

        # Collect results
        results = []
        total_in = 0
        total_out = 0
        try:
            for result in self.client.messages.batches.results(batch_id):
                custom_id = result.custom_id
                if result.result.type == "succeeded":
                    msg = result.result.message
                    total_in += msg.usage.input_tokens
                    total_out += msg.usage.output_tokens
                    text = ""
                    for block in msg.content:
                        if block.type == "text":
                            text = block.text
                            break
                    try:
                        parsed = json.loads(text)
                        parsed["custom_id"] = custom_id
                        results.append(parsed)
                    except json.JSONDecodeError:
                        results.append({"custom_id": custom_id, "raw": text[:200], "parse_error": True})
                else:
                    results.append({"custom_id": custom_id, "error": str(result.result.type)})
        except Exception as e:
            logger.error("Failed to collect batch results: %s", e)

        # Track batch token usage (at 50% discount effectively)
        self.usage.add_batch(total_in, total_out, len(results))
        logger.info("Batch complete: %d results, %d in + %d out tokens", len(results), total_in, total_out)

        return results

    def evaluate_candidates_batch(
        self,
        candidates: list[dict],
        *,
        eval_model: str | None = None,
        timeout: float = 3600,
    ) -> list[dict]:
        """Submit + poll a batch evaluation. Blocking convenience method.

        Returns evaluated results sorted by confidence.
        """
        batch_id = self.create_batch_evaluation(candidates, eval_model=eval_model)
        if not batch_id:
            return []

        results = self.poll_batch(batch_id, timeout=timeout)
        if not results:
            return []

        # Sort by confidence
        results.sort(key=lambda r: r.get("confidence", 0), reverse=True)
        return results
