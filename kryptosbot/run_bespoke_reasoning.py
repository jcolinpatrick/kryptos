#!/usr/bin/env python3
"""
KryptosBot Bespoke Reasoning Campaign

Deploys 4 Claude agents focused on creative reasoning about what
kind of bespoke cipher K4 uses, informed by the full elimination
landscape from 395+ experiments.

Questions:
  1. What bespoke cipher would a CIA crypto chief design for a sculptor?
  2. How do Scheidt's CKM/key-split patents translate to hand-executable crypto?
  3. What interpretation of "two separate systems" hasn't been tested?
  4. How does "receiver identity protection" manifest in 97 characters?

Usage:
  cd kryptosbot && python run_bespoke_reasoning.py

Requires: ANTHROPIC_API_KEY in environment (or .env file).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kryptosbot.bespoke")

# ── Shared context for all agents ─────────────────────────────────────

ELIMINATION_CONTEXT = """
ELIMINATION LANDSCAPE (as of 2026-03-01, 395+ experiments, ~700B+ configs):

TIER 1 — ALGEBRAICALLY PROVEN IMPOSSIBLE:
- ALL periodic substitution (Vigenère/Beaufort/VarBeau) at ALL periods 2-26
- Key is provably NON-PERIODIC under additive key model + exact cribs
- Null insertion + periodic key: IMPOSSIBLE at all periods (within-crib spacing invariant)
- Keystream transposition of periodic key: 9.8M configs, ZERO consistent (p2-13, w3-12)
- Encrypt-then-transpose + periodic key: periods 2-7 IMPOSSIBLE for ANY transposition
  (not just columnar — ALL 97! permutations eliminated by pigeonhole + Bean INEQ)
  Surviving periods {8,11,12,13,16,18,19,20,22,23,24,26} — ALL UNDERDETERMINED
- Multiple Vig/Beau layers = single layer (mod-26 additive identity)
- Monoalphabetic/affine/polyalphabetic mask + periodic sub → reduces to periodic
- Bean impossibility: only periods {8,13,16,19,20,23,24,26} survive Bean constraints

TIER 2 — EXHAUSTIVELY SEARCHED (single-layer):
- ALL structured transpositions: columnar w5-12, double w7-9 (667B configs), keyword,
  Myszkowski, AMSCO, rail fence — ALL NOISE
- Grid route cipher (spiral, diagonal, zigzag, boustrophedon): 52K configs, 0/24
- Homophonic substitution (direct): 9/14 CT contradictions → IMPOSSIBLE
- Pure nomenclator: ELIMINATED
- Autokey (CT-feedback, PT-feedback, accumulated state): ZERO above noise
- Feedback/digraphic/tableau-walk: 7,488 configs, ZERO above noise
- Beaufort focus: 25M configs, max 8/24, ALL NOISE
- Key-split combiner (CKM): 51K configs, ALL NOISE
- Running key from 130.7M+ chars (identity trans): ALL NOISE
- Running key + columnar w5-11 (1.19B configs): ELIMINATED
- Quagmire I/II/III with KA alphabet: ZERO periodic consistency

WHAT REMAINS OPEN:
1. Running key from UNKNOWN text + transposition (UNDERDETERMINED — need the text)
2. Bespoke physical/procedural cipher ("never in cryptographic literature" per Gillogly)
3. VIC/chart-based cipher (UNDERDETERMINED — enormous parameter space)
4. Physical S-curve / Antipodes inspection (untestable without access)
5. External information: K5 CT, Smithsonian archive (sealed 2075), auction buyer's materials

KEY STRUCTURAL FINDINGS:
- Beaufort keystream at crib positions is 1,200x more structured than Vigenère
  - Cluster {6,10,14} = {G,K,O} appears 12/24 times (50%, 4.3x enrichment)
  - Halved: {3,5,7} = consecutive odd primes
  - Value 10 (='K') is the most frequent (5 of 24)
- K4 IC ≈ 0.0361 (NOT significant for n=97, cannot discriminate)
- Scheidt: "I masked the English language" → IC/frequency analysis is MUTE
- K4 ciphertext is statistically consistent with RANDOM text

KRYPTOS FACTS:
- CT: OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
- 97 chars (prime), all 26 letters present
- Known PT (0-indexed): pos 21-33 = EASTNORTHEAST, pos 63-73 = BERLINCLOCK
- Bean EQ: k[27]=k[65] (CT[27]=CT[65]=P, PT[27]=PT[65]=R). 21 inequalities.
- Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K
- K1: Vigenère with PALIMPSEST. K2: Vigenère with ABSCISSA. K3: Transposition + Vigenère with KRYPTOS.
- KA alphabet on sculpture: KRYPTOSABCDEFGHIJLMNQUVWXZ (all 26 letters, keyed)
- Sanborn's yellow pad: "8 Lines 73" (K4 area), "11 Lines 342" (K2/K3 area)
- Sanborn: "two separate systems... a major clue in itself"
- Sanborn: "Who says it is even a math solution?"
- Gillogly: "K4 employs an invention by Scheidt that has never appeared in cryptographic literature"
- Scheidt: CIA Crypto Center chairman 1963-1989. TecSec co-founder. 36 CKM patents.
- Scheidt taught Sanborn: "substitution, shifting matrices, transposition, matrix codes, systems not dependent on mathematics"
- Scheidt designed the METHOD, Sanborn chose the PARAMETERS
- NSA tried many layered systems → ALL FAILED
- 24-letter anomaly pool forms EQUINOX from 4 independent anomaly sources
- Fold theory: OFLNUXZ emerges from direct overlay fold of sculpture copper sheet
"""

# ── Agent prompts ─────────────────────────────────────────────────────

AGENT_PROMPTS = {
    "bespoke_cipher_design": {
        "title": "What bespoke cipher would a CIA crypto chief design for a sculptor?",
        "prompt": f"""You are a world-class cryptanalyst and historian of cryptographic methods.

{ELIMINATION_CONTEXT}

YOUR TASK: Reason deeply about what kind of cipher Ed Scheidt would have designed for K4.

CONSTRAINTS ON THE METHOD:
- Scheidt was CIA's top cryptographer (1963-1989), then founded TecSec
- He taught Sanborn: "substitution, shifting matrices, transposition, matrix codes, systems not dependent on mathematics"
- The method has "never appeared in cryptographic literature" (Gillogly)
- It must be executable by hand (Sanborn encoded it physically in 1989-1990)
- It uses "two separate systems" (Sanborn)
- It involves masking English before encryption (Scheidt)
- It was designed to last decades without being solved
- The NSA tried many layered systems and FAILED
- 395+ experiments with 700B+ configs have all produced NOISE

SCHEIDT'S EXPERTISE:
- Key management specialist (CKM = Constructive Key Management)
- 36 patents on key-split combiners — splitting one key across multiple components
- "Receiver identity protection" — hiding who the message is for
- Medieval guild crypto (ACA 2013 talk) — pre-mathematical, procedural methods
- "Systems not dependent on mathematics" — physical/procedural, not algebraic

CRITICAL QUESTION: All algebraic approaches (anything expressible as modular arithmetic
on letter positions) have been eliminated at discriminating periods. What PROCEDURAL
methods — methods that cannot be reduced to simple algebra — remain?

Think about:
1. What procedural (non-algebraic) cipher operations would Scheidt know from CIA training?
2. How does one create a cipher that resists modern frequency analysis AND algebraic attack?
3. What does "systems not dependent on mathematics" actually mean in practice?
4. Could the cipher use the PHYSICAL PROPERTIES of the sculpture (S-curve, fold, position)?
5. What is the simplest non-algebraic operation that defeats our entire elimination framework?

IMPORTANT: Do NOT just list possibilities. For each candidate method:
- Describe it CONCRETELY (step by step, what does the encryptor do?)
- Explain WHY it survives our eliminations
- Describe how it could be TESTED against K4
- Rate its plausibility (1-10) given everything we know about Scheidt

Write your analysis to kryptosbot/kbot_results/bespoke_cipher_design.md

```verdict
{{"verdict_status": "inconclusive", "score": 0, "summary": "your one-line summary", "evidence": "key reasoning", "best_plaintext": ""}}
```""",
    },

    "ckm_hand_cipher": {
        "title": "How do Scheidt's CKM/key-split patents translate to hand-executable crypto?",
        "prompt": f"""You are an expert in both modern key management systems and classical hand ciphers.

{ELIMINATION_CONTEXT}

YOUR TASK: Analyze Ed Scheidt's 36 CKM (Constructive Key Management) patents and
determine how key-split combiner concepts could be adapted into a hand-executable
cipher for Kryptos K4.

SCHEIDT'S CKM CONCEPT:
- Multiple independent key sources are COMBINED to produce a working key
- No single source reveals the key — you need ALL components
- This is the mathematical foundation of TecSec's products
- Patent examples: key = f(source_1, source_2, ..., source_n) where each source
  is independent and insufficient alone

FOR KRYPTOS K4, the key sources could be:
1. A keyword (KRYPTOS, or another word)
2. The KA alphabet/tableau on the sculpture
3. Position-dependent values (row, column on the physical sculpture)
4. Text from elsewhere on the sculpture (K1-K3 solutions, K5?)
5. LOOMIS coordinates or other external reference
6. The plaintext itself (autokey variant)

WHAT WE'VE ALREADY TESTED:
- Simple key combinations: key1 + key2 mod 26 (ALL NOISE for 51K configs)
- Two-keyword interleaving, multiplication, XOR, abs_diff
- All of these reduce to algebraically equivalent forms → ELIMINATED

THE QUESTION: How can key-splitting produce a cipher that is NOT algebraically
reducible to a single periodic key or a simple combination of periodic keys?

Think about:
1. Non-linear combination functions (beyond modular addition)
2. State-dependent key selection (current output determines next key source)
3. Position-dependent switching between key sources
4. Key sources that are themselves position-dependent (not just repeating keywords)
5. Physical key derivation (e.g., distance along the S-curve determines the key)

For each plausible CKM-to-hand-cipher translation:
- Describe the key derivation procedure step by step
- Show that it cannot be reduced to an already-eliminated form
- Estimate the parameter space and whether it's searchable
- Rate plausibility (1-10)

Write your analysis to kryptosbot/kbot_results/ckm_hand_cipher.md

```verdict
{{"verdict_status": "inconclusive", "score": 0, "summary": "your one-line summary", "evidence": "key reasoning", "best_plaintext": ""}}
```""",
    },

    "two_systems": {
        "title": "What interpretation of 'two separate systems' hasn't been tested?",
        "prompt": f"""You are a creative cryptanalyst specializing in multi-layer cipher systems.

{ELIMINATION_CONTEXT}

YOUR TASK: Exhaustively analyze Sanborn's statement "two separate systems...
a major clue in itself" and identify interpretations that have NOT been tested.

SANBORN'S EXACT WORDS:
- "Two separate systems were used to produce the ciphertext"
- "This is a major clue in itself"
- The fact that there are TWO systems should help narrow the search

TESTED INTERPRETATIONS (ALL ELIMINATED):
1. Transposition + Vigenère (K3-style): exhaustively tested, ALL NOISE
2. Vigenère + Transposition (reverse order): exhaustively tested, ALL NOISE
3. Double substitution (Vig+Vig, Vig+Beau, Beau+Beau): algebraically = single layer
4. Mask + encryption: all algebraic masks reduce to already-eliminated forms
5. Null insertion + periodic key: algebraically impossible
6. Two-keyword combination: 51K configs, ALL NOISE
7. Beaufort + transposition at all tested periods: ALL NOISE or UNDERDETERMINED

UN-TESTED INTERPRETATIONS TO CONSIDER:
- "Two systems" = the cipher AND a separate encoding of the key
- "Two systems" = one for the first half, one for the second half of K4
- "Two systems" = masking (system 1) and encryption (system 2) where the masking
  is something we haven't tried
- "Two systems" = the tableau encipherment AND the physical arrangement on the S-curve
- "Two systems" = substitution applied WITHIN a transposition grid (not before/after)
- "Two systems" = one for generating the key, one for applying the key
- "Two systems" = encoding and steganography (some characters carry the message,
  others are structural)
- "Two systems" = K4 ciphertext encodes TWO messages simultaneously

For each UNTESTED interpretation:
1. Define it precisely
2. Explain why our current tests don't cover it
3. Propose a specific test with expected results
4. Rate plausibility (1-10) given Sanborn's and Scheidt's known methods

Write your analysis to kryptosbot/kbot_results/two_systems_analysis.md

```verdict
{{"verdict_status": "inconclusive", "score": 0, "summary": "your one-line summary", "evidence": "key reasoning", "best_plaintext": ""}}
```""",
    },

    "receiver_identity": {
        "title": "How does 'receiver identity protection' manifest in 97 characters?",
        "prompt": f"""You are an expert in intelligence tradecraft and cryptographic protocols.

{ELIMINATION_CONTEXT}

YOUR TASK: Analyze Scheidt's concept of "receiver identity protection" and
determine how it could manifest in a 97-character cipher.

CONTEXT:
- At ACA 2013, Scheidt discussed "receiver identity protection" — hiding
  not just the message content but WHO the message is for
- This is a concept from intelligence operations where knowing the RECIPIENT
  reveals information even if you can't read the message
- Scheidt's medieval guild crypto discussion: guild members could verify
  membership and decode messages without revealing the guild's identity
- "IDBYROWS may not be a mistake" — Scheidt, possibly hinting at a grid method

IN CLASSICAL CRYPTOGRAPHY, receiver identity protection can mean:
1. The decryption key encodes the receiver's identity
2. Only the intended receiver knows which parts of the ciphertext to read
3. Multiple valid decryptions exist — only the real receiver knows which is correct
4. The key derivation depends on something only the receiver knows (location, identity)

FOR KRYPTOS SPECIFICALLY:
- The "receiver" might be the solver — the method of solution reveals something
  about you (your knowledge, your access, your location)
- "Receiver identity" could relate to the CIA employees who walk past Kryptos daily
- The LOOMIS geodetic marker "remains important to solving K4" — geographic knowledge?
- K5 is confirmed (97 chars) and "connects to K2" — maybe K5 is the receiver's key?

CRITICAL INSIGHT: If K4 has MULTIPLE valid decryptions (only one being correct),
our crib-matching approach would find the wrong one. The "correct" decryption
depends on knowing something external — the receiver's identity/knowledge.

Think about:
1. Could K4 be a "deniable encryption" scheme with multiple valid plaintexts?
2. How does one build a 97-char cipher where the decryption key IS the receiver's identity?
3. What physical knowledge (location at CIA, view of sculpture, LOOMIS coordinates)
   could serve as part of the key?
4. Does "IDBYROWS" suggest a grid method where the row/column selection IS the identity?
5. Could the Kryptos tableau serve as a lookup table where your "row" is your identity?

For each proposed mechanism:
- Describe it concretely (step by step)
- Explain how it interacts with the known cribs
- Estimate testability
- Rate plausibility (1-10)

Write your analysis to kryptosbot/kbot_results/receiver_identity.md

```verdict
{{"verdict_status": "inconclusive", "score": 0, "summary": "your one-line summary", "evidence": "key reasoning", "best_plaintext": ""}}
```""",
    },
}


async def run_agent(name: str, config: dict, project_root: Path) -> dict:
    """Run a single reasoning agent and return results."""
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    logger.info("Launching agent: %s", config["title"])

    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        cwd=str(project_root),
        max_buffer_size=10_485_760,
        env={"CLAUDECODE": ""},
    )

    output_chunks: list[str] = []
    start = datetime.now(timezone.utc)

    try:
        async for message in safe_query(prompt=config["prompt"], options=options):
            if hasattr(message, "result"):
                chunk = str(message.result)
                output_chunks.append(chunk)
                # Print first 200 chars of each chunk for progress
                preview = chunk[:200].replace("\n", " ")
                if preview.strip():
                    logger.info("[%s] %s...", name, preview[:80])
            elif hasattr(message, "content"):
                content = str(message.content)
                if content.strip():
                    output_chunks.append(content)
    except Exception as e:
        logger.error("Agent %s failed: %s", name, e)
        output_chunks.append(f"\n\nERROR: {e}")

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    raw_output = "\n".join(output_chunks)

    # Extract verdict if present
    import re
    verdict = None
    verdict_match = re.search(r"```verdict\s*\n(.+?)\n\s*```", raw_output, re.DOTALL)
    if verdict_match:
        try:
            verdict = json.loads(verdict_match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    result = {
        "agent": name,
        "title": config["title"],
        "elapsed_seconds": elapsed,
        "output_length": len(raw_output),
        "verdict": verdict,
        "raw_output_file": f"kbot_results/{name}_raw.txt",
    }

    # Save raw output
    raw_path = project_root / "kryptosbot" / "kbot_results" / f"{name}_raw.txt"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(raw_output)

    logger.info(
        "Agent %s completed in %.0fs (%d chars output)",
        name, elapsed, len(raw_output),
    )
    return result


async def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY required", file=sys.stderr)
        print("Set it in your environment or in a .env file", file=sys.stderr)
        sys.exit(1)

    project_root = Path(__file__).parent.parent.resolve()

    logger.info("=" * 70)
    logger.info("KryptosBot Bespoke Reasoning Campaign")
    logger.info("=" * 70)
    logger.info("Project root: %s", project_root)
    logger.info("Launching %d reasoning agents...", len(AGENT_PROMPTS))

    # Run all 4 agents concurrently
    tasks = [
        run_agent(name, config, project_root)
        for name, config in AGENT_PROMPTS.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    successful = []
    failed = []
    for r in results:
        if isinstance(r, Exception):
            failed.append(str(r))
        else:
            successful.append(r)

    # Summary
    logger.info("=" * 70)
    logger.info("CAMPAIGN COMPLETE")
    logger.info("=" * 70)
    logger.info("Successful: %d, Failed: %d", len(successful), len(failed))

    for r in successful:
        verdict_summary = r["verdict"]["summary"] if r["verdict"] else "No verdict"
        logger.info("  %s: %s (%.0fs)", r["agent"], verdict_summary, r["elapsed_seconds"])

    for f in failed:
        logger.error("  FAILED: %s", f)

    # Save campaign summary
    summary_path = project_root / "kryptosbot" / "kbot_results" / "bespoke_campaign_summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "campaign": "bespoke_reasoning",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agents_launched": len(AGENT_PROMPTS),
            "successful": len(successful),
            "failed": len(failed),
            "results": successful,
            "errors": failed,
        }, f, indent=2)

    logger.info("Campaign summary saved to %s", summary_path)


if __name__ == "__main__":
    asyncio.run(main())
