"""Theory classification against the elimination database using Claude Haiku."""

import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

import anthropic


SYSTEM_PROMPT = """\
You are a classifier for the Kryptos K4 elimination database. You will be given:
1. A context string containing all tested elimination entries (each with an ID, title, and verdict)
2. A user-submitted theory about how K4 might be encrypted

Your job has THREE parts:

PART 1 — MATCH CHECK: Determine whether the theory matches any elimination entry.
PART 2 — FEASIBILITY CHECK: If the theory is novel, assess whether it is computationally feasible and well-defined enough to test.
PART 3 — RESPOND with the appropriate status.

MATCHING RULES:
- If the theory matches one or more tested eliminations, return the BEST match.
- Only return elimination IDs that appear VERBATIM in the context. NEVER invent or guess IDs.
- A "match" means the theory describes substantially the same cipher method, key approach, or structural hypothesis.
- If multiple entries partially match, pick the closest one.

FEASIBILITY RULES (for novel theories only):
Assess the theory against these criteria:
- Is it specific enough to implement? Vague theories like "maybe it's something with numbers" are UNTESTABLE.
- Is it computationally feasible? K4 is 97 characters. Consider:
  * Brute-forcing all 97! (~10^152) permutations is IMPOSSIBLE.
  * Brute-forcing all 26^97 substitution keys is IMPOSSIBLE.
  * Trying all possible running keys from all possible texts is IMPOSSIBLE.
  * Methods requiring >10^12 configurations are INFEASIBLE (would take months).
  * Methods requiring <10^10 configurations are FEASIBLE (hours to days).
  * If the theory has a natural parameter space, estimate its size.
- Does it violate known constraints?
  * All 26 letters appear in K4 ciphertext — any cipher requiring a 25-letter alphabet (I/J merge) is IMPOSSIBLE (Bifid, Trifid, Playfair, etc.).
  * The key is provably non-periodic (derived from crib positions).
  * Bean constraints: k[27] must equal k[65]; 21 specific inequality pairs.
- Is it falsifiable? Can we define what "success" looks like (24/24 crib match)?

RESPONSE FORMAT — respond with ONLY valid JSON, no markdown fences:

For a match:
{"status": "matched", "elimination_id": "<exact ID from context>", "title": "<exact title from context>", "verdict": "<ELIMINATED or other verdict from context>", "summary": "<1 sentence explaining why this theory was already tested and the result>"}

For a novel AND feasible theory:
{"status": "novel", "feasibility": "feasible", "summary": "<1-2 sentences on what makes this worth testing and rough complexity estimate>"}

For a novel but INFEASIBLE theory:
{"status": "novel", "feasibility": "infeasible", "reason": "<1-2 sentences explaining why this cannot be practically tested>"}

For a novel but UNTESTABLE (too vague) theory:
{"status": "novel", "feasibility": "untestable", "reason": "<1 sentence explaining what additional specificity is needed>"}

For a novel but IMPOSSIBLE (violates known constraints) theory:
{"status": "novel", "feasibility": "impossible", "reason": "<1 sentence explaining which constraint it violates>"}
"""


@dataclass
class ClassifyResult:
    status: str  # "matched", "novel", "infeasible", "untestable", "impossible"
    elimination_id: Optional[str] = None
    title: Optional[str] = None
    verdict: Optional[str] = None
    url: Optional[str] = None
    summary: Optional[str] = None
    message: Optional[str] = None
    queue_position: Optional[int] = None
    feasibility: Optional[str] = None  # "feasible", "infeasible", "untestable", "impossible"
    reason: Optional[str] = None

    def to_dict(self) -> dict:
        """Return dict with None values removed."""
        return {k: v for k, v in asdict(self).items() if v is not None}


def load_elimination_index(path: str) -> str:
    """Read search-index.json and build a compact context string for the classifier.

    Returns a text block listing each elimination with its ID, title, and verdict.
    The JSON format is: {"ref": "id", "fields": [...], "documents": [...]}.
    """
    with open(path, "r") as f:
        data = json.load(f)

    # Handle both flat list and nested {"documents": [...]} formats
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("documents", [])
    else:
        entries = []

    lines = []
    for entry in entries:
        eid = entry.get("id", entry.get("experiment_id", ""))
        title = entry.get("title", "")
        verdict = entry.get("verdict", "ELIMINATED")
        description = entry.get("description", "")
        line = f"[{eid}] {title} | {verdict}"
        if description:
            line += f" | {description}"
        lines.append(line)

    return "\n".join(lines)


async def classify_theory(theory: str, index_context: str) -> ClassifyResult:
    """Call Claude Haiku to classify a theory against the elimination database.

    Returns a ClassifyResult indicating whether the theory matches an existing
    elimination, is novel and feasible, or is novel but impractical.
    """
    api_key = os.environ.get("KBOT_CLASSIFY_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    client = anthropic.AsyncAnthropic(api_key=api_key)

    user_message = (
        f"ELIMINATION DATABASE:\n{index_context}\n\n"
        f"USER THEORY:\n{theory}"
    )

    try:
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        text = response.content[0].text.strip()
        result = json.loads(text)

        if result.get("status") == "matched":
            eid = result.get("elimination_id", "")
            return ClassifyResult(
                status="matched",
                elimination_id=eid,
                title=result.get("title", ""),
                verdict=result.get("verdict", "ELIMINATED"),
                url=f"/elimination/{eid}/",
                summary=result.get("summary", ""),
            )
        elif result.get("status") == "novel":
            feasibility = result.get("feasibility", "feasible")
            if feasibility == "feasible":
                return ClassifyResult(
                    status="novel",
                    feasibility="feasible",
                    summary=result.get("summary", ""),
                )
            else:
                # infeasible, untestable, or impossible
                return ClassifyResult(
                    status="rejected",
                    feasibility=feasibility,
                    reason=result.get("reason", ""),
                )
        else:
            return ClassifyResult(status="novel", feasibility="feasible")

    except (json.JSONDecodeError, KeyError, IndexError):
        # If Haiku returns unparseable output, treat as novel to be safe
        return ClassifyResult(status="novel", feasibility="feasible")
    except anthropic.APIError:
        raise
