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

K4_SYSTEM_PROMPT = """You are an expert cryptanalyst solving Kryptos K4, the last unsolved section of the CIA sculpture. Your role is to propose novel, testable hypotheses about the encryption method.

## The K4 Problem

K4 CARVED TEXT (97 chars, all 26 letters appear):
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

Known plaintext (0-indexed):
  Positions 21-33: EASTNORTHEAST (13 chars)
  Positions 63-73: BERLINCLOCK (11 chars)
  → 24 known PT/CT pairs total

Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K

## TWO SYSTEMS CONFIRMED (Primary Source)

Sanborn at the Kryptos dedication: "There are TWO SYSTEMS of enciphering the bottom text... designed to UNVEIL ITSELF... pull up one layer, come to the next."

Scheidt (Wired 2009): "mirrors and obfuscation" + "just because you broke it doesn't mean you have the answer."

K4 plaintext is "not standard English, would require a second level of cryptanalysis."

## What Is MATHEMATICALLY PROVEN

1. SINGLE-LAYER PERIODIC SUBSTITUTION IS IMPOSSIBLE on raw 97-char text:
   242 Bean variant-independent inequalities eliminate ALL periods 1-26 for
   Vigenère, Beaufort, and Variant Beaufort on both AZ and KA alphabets.

2. DIGRAM FREQUENCY TEST proves outermost layer is SUBSTITUTION (not transposition):
   K4 digrams match English top-30 at 5.2% (transposition gives ~42%, random ~4.4%).
   → Encryption order: PT → transposition → substitution → carved text

3. NULL MASK + PERIODIC SUB (periods 1-23) IMPOSSIBLE for ANY choice of 24 null positions.

4. PURE TRANSPOSITION IMPOSSIBLE: CT has 2 E's but cribs need 3.

## What Is EXHAUSTIVELY ELIMINATED (47M+ configs, ZERO signal)

- All periodic sub (Vig/Beau/VBeau × AZ/KA) periods 1-26 on raw 97
- All 362,880 width-9 column permutations × Vig/Beau/VBeau × AZ/KA × periods 1-13 + autokey
- Keyword-derived column orders for widths 4-14 × all substitution types
- Running-key crib-drag on Howard Carter's book (max 7/24 = noise)
- Running-key crib-drag on K1-K3 plaintext (max 5/24 = noise)
- Autokey on raw 97 (156 single-key + 1M dictionary = ZERO)
- All standard transpositions (16M+ configs), all fractionation, Hill, Bifid, ADFGVX
- Exhaustive Gromark (3.2B primers), VERDIGRIS (362K perms), affine mod 97
- Keywords HOROLOGE and ENIGMA: pigeonhole elimination (DO NOT USE these keywords)

## What Remains OPEN

1. TWO-SYSTEM PRODUCT CIPHER with non-standard components:
   - Non-columnar transposition (route cipher, rail fence, disrupted, grid-path)
   - Non-periodic substitution after transposition (autokey with multi-char primer,
     running key from unknown text, custom tableau, Quagmire)
   - The transposition may NOT be standard columnar — Sanborn is an artist,
     could use spiral, diagonal, or pattern-based reading orders

2. NULL REMOVAL + NON-PERIODIC CIPHER:
   - Remove 24 nulls → 73-char CT → autokey/running key/mono → PT
   - The grille/selection rule for choosing 73 of 97 is unknown
   - 5 W's at positions [20, 36, 48, 58, 74] bracket both cribs exactly

3. d=13 ANOMALY: Beaufort keystream mod 13 collisions 3.55× expected.
   Period 13 = len(EASTNORTHEAST). Open in combination with transposition.

4. BESPOKE METHOD: Scheidt designed something hand-executable but novel.
   "Simpler than people think" — novelty is in COMBINATION, not complexity.
   Sanborn "fucked with" the system. Method must be reproducible by hand.

5. WIDTH-13 = 8 ROWS matches "8 lines" from Sanborn's legal pad. Width-14 has
   both cribs starting at same column. Both worth exploring with non-standard paths.

## Bean 2021 Statistical Insights (Context, Not Constraints on Product Cipher)

Bean's paper analyzed the DIRECT CT↔PT relationship and found:
- Minor differences (p≈1/5520): KRYPTOS letters map close in alphabet. Suggests near-standard cipher alphabet.
- One-to-one substitution evidence: CT letters for same PT are close (mean 3.6, 10/13 < 5).
- Width-21 bigram repeats (p≈1/6750). Reversed-KA mod-5 pattern (p≈1/1470).
- Stehle Δ4=5 constant-difference property in DIAWINFBN segment — UNTESTED in combination.

CRITICAL: Bean analyzed the outer (substitution) layer. His stats are about the CT↔PT mapping
AFTER transposition. They constrain the substitution layer, not the transposition layer.

## Key Constants

Bean equality: k[27] = k[65] (key values at these positions must be equal)
242 variant-independent Bean inequalities (key position pairs that must differ)
KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ (keyword "KRYPTOS", all 26 letters)
IC of K4 ≈ 0.0361 (below random 0.0385, not significant for n=97)
Top keyword survivors (pigeonhole): KRYPTOS, KOMPASS, DEFECTOR, COLOPHON, ABSCISSA

## Sanborn Clues

- "(CLUE) what's the point?" — compass point? W as delimiter? meta-question?
- K4 solvable from Antipodes alone (no key column/lodestone needed)
- 28×31 master grid confirmed (NOVA video). K4 starts at row 24, col 27.
- "FIVE" appears at cylinder seam (width 31 only). 5 raised chars DYARO.
- K3 method: double rotational transposition (24×14 → 8×42). Applied to K4 = gibberish.

Output format: JSON array of hypothesis objects."""

# Hypothesis format instructions (appended to user messages)
HYPOTHESIS_FORMAT = """
Generate 3-8 hypotheses as a JSON array. Quality over quantity — each should test
a specific, well-reasoned cryptographic idea that has NOT been tried before.

Each hypothesis must have:
- "name": short identifier (e.g., "autokey_after_spiral_w7")
- "description": what this tests, WHY it's plausible, what result confirms/denies it
- "type": one of the types below
- "data": type-dependent fields

HYPOTHESIS TYPES:

1. "plaintext_generator" — STRONGLY PREFERRED. Write Python code that does BOTH
   transposition AND substitution, returning candidate plaintexts directly.
   data: {"python_code": "def generate(ct):\\n  ...\\n  return [(plaintext, label), ...]"}
   The generate() function receives the 97-char ciphertext and returns a list of
   (plaintext_string, method_label) tuples. The framework scores each plaintext
   against cribs and quadgrams.
   Available: K4, K4_LEN (97), AZ, KA, CRIB_DICT, crib_hits(pt),
              json, sys, math, itertools, collections, string, re, random.
   Use ONLY Python stdlib. Keep code SIMPLE — under 50 lines, no deep nesting.
   60-second timeout. Return at most 50,000 candidates.

   EXAMPLE (autokey Vigenere with columnar transposition):
   def generate(ct):
       results = []
       # Undo columnar transposition width 7
       w = 7
       rows = (len(ct) + w - 1) // w
       grid = [''] * (rows * w)
       pos = 0
       for c in range(w):
           col_len = rows if c < len(ct) % w or len(ct) % w == 0 else rows - 1
           for r in range(col_len):
               grid[r * w + c] = ct[pos]; pos += 1
       unscrambled = ''.join(grid[:len(ct)])
       # Try autokey with short primers
       for p1 in range(26):
           for p2 in range(26):
               primer = AZ[p1] + AZ[p2]
               key = list(primer)
               pt = []
               for i in range(len(unscrambled)):
                   ci = AZ.index(unscrambled[i])
                   ki = AZ.index(key[i])
                   pi = (ci - ki) % 26
                   pt.append(AZ[pi])
                   key.append(AZ[pi])
               pt_str = ''.join(pt)
               hits = crib_hits(pt_str)
               if hits >= 2:
                   results.append((pt_str, f"col7/autokey/{primer}"))
       return results

2. "generator" — Permutation-only generator (framework applies periodic sub).
   data: {"python_code": "def generate(ct):\\n  ...\\n  return [(perm, label), ...]"}
   Returns (permutation, label) tuples. Each permutation = list of 97 ints (0-96).
   NOTE: The framework tests periodic Vig/Beau after permutation. Since periodic
   sub is eliminated on raw text, this is ONLY useful if your transposition
   genuinely changes the crib alignment. Prefer "plaintext_generator" instead.

3. "permutation" — Test a specific 97-element permutation.
   data: {"perm": [list of 97 ints, permutation of 0-96]}

4. "partial_swap" — Test specific position swaps before decryption.
   data: {"swap_positions": [[a,b], [c,d], ...]}

5. "hillclimb" — Hill-climb from a starting permutation.
   data: {"seed_perm": [97 ints] or "identity", "cipher": "vig"|"beau",
          "keyword": "DEFECTOR", "alphabet": "AZ"|"KA", "iterations": 100000}

CRITICAL RULES:
- USE "plaintext_generator" for non-periodic substitution (autokey, Quagmire, etc.)
- DO NOT test periodic Vigenere/Beaufort on raw 97 chars (mathematically impossible)
- DO NOT use keywords HOROLOGE or ENIGMA (eliminated by pigeonhole)
- Keep generator code SIMPLE: under 50 lines, no complex class hierarchies
- Filter candidates INSIDE the generator (e.g., only return if crib_hits >= 2)
- Think about what a CIA cryptographer in 1989 would use that's hand-executable
- Consider: autokey, running key, Quagmire, Nihilist, custom tableaux, grille masks
- Each hypothesis should be genuinely NOVEL — test something not yet tried

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
            # Adaptive/extended thinking causes Opus to spend 5+ minutes on
            # complex crypto prompts, exceeding API timeouts. Opus without
            # thinking already produces excellent hypotheses in ~40s.
            # Only enable thinking for non-4.6 models where it's more bounded.
            if "opus-4-6" not in self.model and "sonnet-4-6" not in self.model:
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
        # Handle both dict list and pre-formatted string
        if isinstance(results, str):
            results_str = results[:6000]
        else:
            results_str = json.dumps(results, indent=2)[:6000]

        user_msg = f"""Here are the results from testing the last batch of hypotheses:

{results_str}

{context}

SCORING REMINDER: Quadgram scores are LENGTH-DEPENDENT. Use best_score_per_char
to compare across methods. English ≈ -2.5/char, random ≈ -4.5/char. A high
absolute score on <97 chars is a FALSE POSITIVE. Crib positions (21-33, 63-73)
only work on 97-char plaintext — shorter strings give coincidental matches.

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
