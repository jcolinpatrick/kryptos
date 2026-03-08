"""Theory classification against the elimination database using Claude Haiku."""

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

import anthropic


SYSTEM_PROMPT = """\
You are a classifier for the Kryptos K4 elimination database at kryptosbot.com. You will be given:
1. A comprehensive context containing all tested elimination entries, known constraints, anomalies, and research questions
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
- Be AGGRESSIVE about matching. If someone says "Vigenere with keyword X", that matches the polyalphabetic sweeps that tested hundreds of keywords. If someone says "columnar transposition", that matches the columnar elimination entries.

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
  * All 26 letters appear in K4 ciphertext — any cipher requiring a 25-letter alphabet (I/J merge) is IMPOSSIBLE (Bifid, Trifid, Playfair, ADFGVX, ADFGX, etc.).
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

# Comprehensive summary of what has been eliminated, keyed to index IDs
COMMON_ELIMINATIONS = """\
EXHAUSTIVE ELIMINATIONS (always match these — do NOT classify as novel):
- ALL single-layer Vigenere ciphers with ANY keyword (KRYPTOS, PALIMPSEST, ABSCISSA, HOROLOGE, DEFECTOR, PARALLAX, COLOPHON, SHADOW, LUCID, MEMORY, BERLIN, CLOCK, ENIGMA, and 293+ thematic keywords, both AZ and KA alphabets) → ELIMINATED. Match to [e-poly-01] or [e-poly-02].
- ALL single-layer Beaufort ciphers with ANY keyword (same keyword set, AZ and KA) → ELIMINATED. Match to [e-poly-01] or [e-poly-02].
- ALL single-layer Variant Beaufort ciphers → ELIMINATED. Match to [e-poly-01].
- ALL Caesar/ROT shifts (0-25) → ELIMINATED. Match to [e-disproof-01].
- ALL Atbash substitutions → ELIMINATED.
- ALL affine ciphers mod 97 (9,312 configs) → ELIMINATED.
- ALL Playfair ciphers → IMPOSSIBLE (K4 has all 26 letters; Playfair requires 25-letter I/J merge).
- ALL Bifid ciphers (5x5) → IMPOSSIBLE (same 26-letter reason).
- ALL Trifid ciphers → IMPOSSIBLE.
- ALL ADFGVX / ADFGX ciphers → IMPOSSIBLE (same reason).
- ALL Four-Square ciphers → IMPOSSIBLE.
- ALL columnar transpositions (widths 2-48, 293+ keywords, Myszkowski) → ELIMINATED. Match to [e-rerun-03-expanded-keyword-columnar-myszkowski-s].
- ALL rail fence ciphers (all rails) → ELIMINATED.
- ALL double columnar transpositions (widths 2-14) → ELIMINATED.
- ALL route ciphers on standard grids → ELIMINATED.
- ALL single-step 97-cycle transpositions → ELIMINATED.
- ALL Hill ciphers (2x2, 3x3 matrices) → ELIMINATED.
- ALL homophonic substitutions (partitioned) → ELIMINATED.
- ALL fractionation methods (Bifid/Trifid/ADFGVX/Polybius) → ELIMINATED or IMPOSSIBLE.
- Running keys from Carter's "Tomb of Tutankhamun," Bible (KJV), Shakespeare, and 100+ other texts → ELIMINATED.
- ALL Gromark ciphers (3.2 billion primers tested) → nearly ELIMINATED.
- K3-style double rotational transposition applied to K4 → ELIMINATED.
- Simulated annealing on pure transposition → ceiling at -3.73/char, no English.
- 668 billion+ total configurations tested across 600+ experiment scripts.

KEY FACTS ABOUT K4:
- Ciphertext: OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
- Length: 97 (prime), all 26 letters present, IC = 0.0361
- Known plaintext (cribs): positions 21-33 = EASTNORTHEAST, positions 63-73 = BERLINCLOCK
- Self-encrypting positions: CT[32]=PT[32]=S, CT[73]=PT[73]=K
- Bean equality constraint: k[27] = k[65]; 21 inequality constraints
- Kryptos Alphabet (KA): KRYPTOSABCDEFGHIJLMNQUVWXZ (all 26 letters, keyword-ordered)
- K1-K3 used Vigenere on a KA tableau. Sanborn confirmed K4 uses a DIFFERENT, harder method.
- Sanborn: "There are TWO SYSTEMS of enciphering the bottom text... a major clue in itself"
- Scheidt: method is bespoke but hand-executable. "Mirrors and obfuscation."
- The carved text may be SCRAMBLED ciphertext (transposition of real CT), not direct CT.

PHYSICAL ANOMALIES:
- Deliberate misspellings: K1 IQLUSION (L→Q), K2 UNDERGRUUND (O→U), K3 DESPARATLY (E→A)
- Morse code (K0): VIRTUALLY INVISIBLE, DIGETAL INTERPRETATIU, SHADOW FORCES, LUCID MEMORY, T IS YOUR POSITION, SOS, RQ
- 25-26 extra E characters in Morse code (E = single dit, shortest Morse character)
- Lodestone deflects compass toward ENE (~67.5°) = EASTNORTHEAST crib
- 5 raised characters on sculpture: D, Y, A, R, O
- K2 coordinates: 38°57'6.5"N, 77°8'44"W (near CIA but exact target debated)

OPEN RESEARCH QUESTIONS:
- RQ-1: What is the substitution cipher used on K4? (Not standard Vigenere/Beaufort)
- RQ-2: Is there a transposition layer? What permutation?
- RQ-3: What is the keyword/key for the substitution?
- RQ-4: Does the Cardan grille define an unscrambling permutation?
- RQ-5: Are there null characters inserted in K4?
- RQ-6: What role does the Morse code (K0) play?
- RQ-7: What do the misspellings encode?
- RQ-8: Is the 28x31 master grid structurally significant?
"""


@dataclass
class ClassifyResult:
    status: str  # "matched", "novel", "rejected"
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

    Also loads anomaly registry, research questions, and elimination tiers
    if available, to give the classifier comprehensive knowledge.
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
        cipher_type = entry.get("cipher_type", "")
        tags = entry.get("tags", "")
        keywords = entry.get("keywords_tested", "")
        key_model = entry.get("key_model", "")
        configs = entry.get("configs_tested", "")

        line = f"[{eid}] {title} | {verdict}"
        if cipher_type:
            line += f" | cipher: {cipher_type}"
        if tags:
            line += f" | tags: {tags}"
        if keywords:
            line += f" | keywords tested: {keywords}"
        if key_model:
            line += f" | key: {key_model}"
        if configs:
            line += f" | configs: {configs}"
        if description:
            line += f" | {description[:200]}"
        lines.append(line)

    context = "\n".join(lines)

    # Try to load additional context files
    project_root = str(Path(path).parent.parent)

    # Anomaly registry
    anomaly_path = os.path.join(project_root, "anomaly_registry.md")
    if os.path.exists(anomaly_path):
        try:
            with open(anomaly_path) as f:
                anomaly_text = f.read()
            # Truncate to keep context manageable
            if len(anomaly_text) > 4000:
                anomaly_text = anomaly_text[:4000] + "\n[... truncated]"
            context += f"\n\nANOMALY REGISTRY:\n{anomaly_text}"
        except Exception:
            pass

    # Research questions
    rq_path = os.path.join(project_root, "docs", "research_questions.md")
    if os.path.exists(rq_path):
        try:
            with open(rq_path) as f:
                rq_text = f.read()
            if len(rq_text) > 3000:
                rq_text = rq_text[:3000] + "\n[... truncated]"
            context += f"\n\nRESEARCH QUESTIONS:\n{rq_text}"
        except Exception:
            pass

    # Elimination tiers
    tiers_path = os.path.join(project_root, "docs", "elimination_tiers.md")
    if os.path.exists(tiers_path):
        try:
            with open(tiers_path) as f:
                tiers_text = f.read()
            if len(tiers_text) > 4000:
                tiers_text = tiers_text[:4000] + "\n[... truncated]"
            context += f"\n\nELIMINATION TIERS:\n{tiers_text}"
        except Exception:
            pass

    return context


async def classify_theory(theory: str, index_context: str) -> ClassifyResult:
    """Call Claude Haiku to classify a theory against the elimination database.

    Returns a ClassifyResult indicating whether the theory matches an existing
    elimination, is novel and feasible, or is novel but impractical.
    """
    api_key = os.environ.get("KBOT_CLASSIFY_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    client = anthropic.AsyncAnthropic(api_key=api_key)

    user_message = (
        f"ELIMINATION DATABASE:\n{index_context}\n\n"
        f"{COMMON_ELIMINATIONS}\n"
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
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
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
