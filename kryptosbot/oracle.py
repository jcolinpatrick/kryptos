"""
Oracle: Local compute dispatcher for Campaign V3.

Routes structured hypotheses from the Analyst (Opus) to existing scripts
and scoring infrastructure. All computation is local — no API calls.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("kryptosbot.oracle")

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX,
    BEAN_EQ, BEAN_INEQ, N_CRIBS, KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet, Alphabet


# ---------------------------------------------------------------------------
# Plaintext fragment testing
# ---------------------------------------------------------------------------

def test_plaintext_fragment(
    text: str,
    start_position: int,
) -> dict:
    """Test a candidate plaintext fragment at a given position.

    Checks how many crib positions the fragment covers and whether
    those positions match the known cribs.
    """
    text = text.upper().replace(" ", "")
    end_position = start_position + len(text)

    # Check overlap with cribs
    matches = 0
    mismatches = 0
    mismatch_details = []
    for pos in range(start_position, min(end_position, CT_LEN)):
        if pos in CRIB_DICT:
            pt_char = text[pos - start_position]
            expected = CRIB_DICT[pos]
            if pt_char == expected:
                matches += 1
            else:
                mismatches += 1
                mismatch_details.append(
                    {"pos": pos, "expected": expected, "got": pt_char}
                )

    # Derive keystream at covered crib positions
    keystream_vig = []
    keystream_beau = []
    for pos in range(start_position, min(end_position, CT_LEN)):
        if pos in CRIB_DICT or pos < end_position:
            pt_idx = ALPH_IDX.get(text[pos - start_position], 0)
            ct_idx = ALPH_IDX.get(CT[pos], 0)
            keystream_vig.append((ct_idx - pt_idx) % 26)
            keystream_beau.append((ct_idx + pt_idx) % 26)

    # Check Bean equality if both positions 27 and 65 are covered
    bean_eq_check = None
    if start_position <= 27 < end_position and start_position <= 65 < end_position:
        k27_v = keystream_vig[27 - start_position]
        k65_v = keystream_vig[65 - start_position]
        k27_b = keystream_beau[27 - start_position]
        k65_b = keystream_beau[65 - start_position]
        bean_eq_check = {
            "vigenere": k27_v == k65_v,
            "beaufort": k27_b == k65_b,
        }

    return {
        "type": "plaintext_fragment",
        "text": text,
        "start_position": start_position,
        "length": len(text),
        "crib_matches": matches,
        "crib_mismatches": mismatches,
        "mismatch_details": mismatch_details,
        "bean_eq_check": bean_eq_check,
        "verdict": "MATCH" if mismatches == 0 and matches > 0 else
                   "PARTIAL" if matches > mismatches else "NOISE",
    }


def test_full_plaintext(text: str) -> dict:
    """Score a complete 97-char plaintext candidate."""
    text = text.upper().replace(" ", "")
    if len(text) != CT_LEN:
        return {"type": "full_plaintext", "error": f"Length {len(text)}, need {CT_LEN}"}

    result = score_candidate(text)
    return {
        "type": "full_plaintext",
        "text": text,
        "crib_score": result.crib_score,
        "ene_score": result.ene_score,
        "bc_score": result.bc_score,
        "bean_passed": result.bean_passed,
        "ic_value": round(result.ic_value, 4),
        "classification": result.crib_classification,
        "is_breakthrough": result.is_breakthrough,
        "verdict": "BREAKTHROUGH" if result.is_breakthrough else
                   "SIGNAL" if result.crib_score >= SIGNAL_THRESHOLD else
                   "INTERESTING" if result.crib_score >= STORE_THRESHOLD else "NOISE",
    }


# ---------------------------------------------------------------------------
# Cipher archetype testing
# ---------------------------------------------------------------------------

def test_cipher_archetype(archetype: dict) -> dict:
    """Test a cipher archetype by running existing scripts or direct computation.

    The archetype dict should contain:
    - encryption_steps: list of step descriptions
    - key_parameters: dict of parameter names → values/ranges
    - test_command: optional shell command using existing scripts
    """
    test_cmd = archetype.get("test_command", "")
    if test_cmd and test_cmd.startswith("PYTHONPATH=src"):
        return _run_script_command(test_cmd, archetype.get("name", "unknown"))

    # Direct computation for simple archetypes
    key_params = archetype.get("key_parameters", {})
    keywords = key_params.get("keywords", [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW",
    ])
    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    best = {"crib_score": 0, "method": ""}
    tested = 0

    for keyword in keywords:
        if not keyword or not keyword.isalpha():
            continue
        kw_upper = keyword.upper()
        kw_len = len(kw_upper)
        key = [ALPH_IDX.get(kw_upper[i % kw_len], 0) for i in range(CT_LEN)]

        for variant in variants:
            pt = decrypt_text(CT, key, variant=variant)
            result = score_candidate(pt)
            tested += 1
            if result.crib_score > best["crib_score"]:
                best = {
                    "crib_score": result.crib_score,
                    "bean_passed": result.bean_passed,
                    "method": f"{kw_upper}/{variant.name}",
                    "plaintext_preview": pt[:60],
                    "classification": result.crib_classification,
                }

    return {
        "type": "cipher_archetype",
        "name": archetype.get("name", "unknown"),
        "configs_tested": tested,
        **best,
        "verdict": "SIGNAL" if best["crib_score"] >= SIGNAL_THRESHOLD else
                   "INTERESTING" if best["crib_score"] >= STORE_THRESHOLD else "NOISE",
    }


# ---------------------------------------------------------------------------
# Stego placement rule testing
# ---------------------------------------------------------------------------

def test_stego_placement_rule(rule: dict) -> dict:
    """Quarantined null-placement scorer.

    This tool previously compared proposed placements against
    CONSENSUS_NULL_POSITIONS and NULL_PALETTE as if they were an answer key.
    Those constants are retired (claim_id: null_palette_retired), so the
    oracle must not emit precision/recall/F1 evidence against them.
    """
    return {
        "type": "stego_placement_rule",
        "name": rule.get("name", "unknown"),
        "predicted_count": len(set(rule.get("predicted_positions", []))),
        "verdict": "RETIRED_UNTESTABLE",
        "retired_claim_id": "null_palette_retired",
        "note": (
            "Null placement rules are no longer scored against "
            "CONSENSUS_NULL_POSITIONS or NULL_PALETTE. Those were retired "
            "on 2026-04-14 after matched controls disproved the palette's "
            "specificity. Provide an explicit non-retired null model and "
            "independent evaluation harness instead."
        ),
    }


# ---------------------------------------------------------------------------
# Key source testing
# ---------------------------------------------------------------------------

_KNOWN_SOURCES: dict[str, str] = {}

def _init_known_sources():
    """Lazily populate known running-key source texts."""
    if _KNOWN_SOURCES:
        return
    _KNOWN_SOURCES["K1"] = (
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    )
    _KNOWN_SOURCES["K2"] = (
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
        "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
        "DOESLANGLEYKNOWABOUTTHISSTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREX"
        "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGEX"
        "THIRTYEIGHTDEGRESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
        "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
    )
    _KNOWN_SOURCES["K3"] = (
        "SLOWLYDESPARATLYSLOWLYTHEREMAINS"
        "OFPASSAGEDEBRISTHATENCUMBEREDTHELOWERPARTOFTHEDOORWAY"
        "WASREMOVEDWITHTREMBLING"
        "HANDSIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHEN"
        "WIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDIN"
        "THEHOTAIRESCAPINGFROMTHECHAMBER"
        "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOM"
        "WITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    )
    _KNOWN_SOURCES["K1K2K3"] = _KNOWN_SOURCES["K1"] + _KNOWN_SOURCES["K2"] + _KNOWN_SOURCES["K3"]
    _KNOWN_SOURCES["K1+K2+K3"] = _KNOWN_SOURCES["K1K2K3"]
    _KNOWN_SOURCES["K3K2K1"] = _KNOWN_SOURCES["K3"] + _KNOWN_SOURCES["K2"] + _KNOWN_SOURCES["K1"]


def _resolve_key_source(source: dict) -> list[int]:
    """Try to resolve a key source to numeric key values.

    First checks for explicit key_values. Then checks if the source name
    matches a known text. Then checks for a 'text' field with raw key text.
    """
    _init_known_sources()

    # Explicit values provided
    key_values = source.get("key_values", [])
    if key_values and len(key_values) >= CT_LEN:
        return key_values

    # Try to match by name against known sources
    name = source.get("name", "").upper()
    for tag, text in _KNOWN_SOURCES.items():
        if tag in name or tag.replace("+", "") in name.replace(" ", ""):
            if len(text) >= CT_LEN:
                return [ALPH_IDX.get(c, 0) for c in text[:CT_LEN]]

    # Check for keywords that suggest K1-K3 combinations
    name_lower = source.get("name", "").lower()
    for hint, tag in [
        ("k1+k2+k3", "K1K2K3"), ("k1k2k3", "K1K2K3"),
        ("k1-k3", "K1K2K3"), ("k3k2k1", "K3K2K1"),
        ("sculpture", "K1K2K3"), ("self-key", "K1K2K3"),
        ("self-ref", "K1K2K3"), ("plaintext concat", "K1K2K3"),
    ]:
        if hint in name_lower and tag in _KNOWN_SOURCES:
            text = _KNOWN_SOURCES[tag]
            if len(text) >= CT_LEN:
                return [ALPH_IDX.get(c, 0) for c in text[:CT_LEN]]

    # Raw text field
    raw = source.get("text", "").upper()
    raw = "".join(c for c in raw if c.isalpha())
    if len(raw) >= CT_LEN:
        return [ALPH_IDX.get(c, 0) for c in raw[:CT_LEN]]

    return []


def test_key_source(source: dict) -> dict:
    """Test a proposed key source against known keystream values at cribs."""
    key_values = _resolve_key_source(source)
    if not key_values or len(key_values) < CT_LEN:
        return {"type": "key_source",
                "name": source.get("name", "unknown"),
                "error": "Could not resolve key source to values. "
                         "Provide key_values list, text field, or reference a known source (K1, K2, K3, K1K2K3).",
                "verdict": "ERROR"}

    # Test against known Vigenere keystream at crib positions
    vig_matches = 0
    beau_matches = 0
    vig_mismatches = []
    beau_mismatches = []

    # ENE crib (positions 21-33)
    for i, pos in enumerate(range(21, 34)):
        kv = key_values[pos] % 26
        if kv == VIGENERE_KEY_ENE[i]:
            vig_matches += 1
        else:
            vig_mismatches.append({"pos": pos, "expected": VIGENERE_KEY_ENE[i], "got": kv})
        if kv == BEAUFORT_KEY_ENE[i]:
            beau_matches += 1
        else:
            beau_mismatches.append({"pos": pos, "expected": BEAUFORT_KEY_ENE[i], "got": kv})

    # BC crib (positions 63-73)
    for i, pos in enumerate(range(63, 74)):
        kv = key_values[pos] % 26
        if kv == VIGENERE_KEY_BC[i]:
            vig_matches += 1
        else:
            vig_mismatches.append({"pos": pos, "expected": VIGENERE_KEY_BC[i], "got": kv})
        if kv == BEAUFORT_KEY_BC[i]:
            beau_matches += 1
        else:
            beau_mismatches.append({"pos": pos, "expected": BEAUFORT_KEY_BC[i], "got": kv})

    best_variant = "vigenere" if vig_matches >= beau_matches else "beaufort"
    best_matches = max(vig_matches, beau_matches)

    return {
        "type": "key_source",
        "name": source.get("name", "unknown"),
        "vigenere_matches": vig_matches,
        "beaufort_matches": beau_matches,
        "best_variant": best_variant,
        "best_matches": best_matches,
        "total_crib_positions": N_CRIBS,
        "mismatches": vig_mismatches[:10] if best_variant == "vigenere" else beau_mismatches[:10],
        "verdict": "SIGNAL" if best_matches >= 18 else
                   "INTERESTING" if best_matches >= 10 else "NOISE",
    }


# ---------------------------------------------------------------------------
# Script execution
# ---------------------------------------------------------------------------

def _run_script_command(cmd: str, name: str, timeout: int = 300) -> dict:
    """Run a shell command and parse results."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=str(_ROOT),
        )
        output = result.stdout[-2000:] if result.stdout else ""
        stderr = result.stderr[-500:] if result.stderr else ""

        # Try to extract score from output
        best_score = 0
        for line in output.splitlines():
            line_lower = line.lower()
            if "best" in line_lower and "score" in line_lower:
                # Try to find a number
                import re
                nums = re.findall(r"(\d+)/24", line)
                if nums:
                    best_score = max(best_score, int(nums[0]))

        return {
            "type": "script_execution",
            "name": name,
            "command": cmd[:200],
            "exit_code": result.returncode,
            "best_score_found": best_score,
            "output_tail": output[-500:],
            "stderr_tail": stderr,
            "verdict": "SIGNAL" if best_score >= SIGNAL_THRESHOLD else
                       "INTERESTING" if best_score >= STORE_THRESHOLD else "NOISE",
        }
    except subprocess.TimeoutExpired:
        return {"type": "script_execution", "name": name, "error": f"Timeout ({timeout}s)",
                "verdict": "TIMEOUT"}
    except Exception as e:
        return {"type": "script_execution", "name": name, "error": str(e),
                "verdict": "ERROR"}


# ---------------------------------------------------------------------------
# Master dispatcher
# ---------------------------------------------------------------------------

def dispatch_hypothesis(h: dict) -> dict:
    """Route a structured hypothesis to the appropriate test function."""
    h_type = h.get("type", "")
    h_name = h.get("name", "unknown")
    start = time.monotonic()

    try:
        if h_type == "plaintext_fragment":
            text = h.get("text", "")
            pos = h.get("start_position", 0)
            if len(text) == CT_LEN:
                result = test_full_plaintext(text)
            else:
                result = test_plaintext_fragment(text, pos)

        elif h_type == "cipher_archetype":
            result = test_cipher_archetype(h)

        elif h_type == "stego_placement_rule":
            result = test_stego_placement_rule(h)

        elif h_type == "key_source":
            result = test_key_source(h)

        elif h_type == "structural_insight":
            # Pure reasoning — no computation, just record it
            result = {
                "type": "structural_insight",
                "name": h_name,
                "claim": h.get("claim", ""),
                "evidence": h.get("evidence", ""),
                "implications": h.get("implications", ""),
                "verdict": "RECORDED",
            }

        elif h_type in ("transposition_rule", "cross_layer_coupling"):
            # These require custom test code — check for test_command
            test_cmd = h.get("test_command", "")
            if test_cmd:
                result = _run_script_command(test_cmd, h_name)
            else:
                result = {
                    "type": h_type, "name": h_name,
                    "verdict": "UNTESTABLE",
                    "note": "No test_command provided. Provide a PYTHONPATH=src command to test.",
                }
        else:
            # Accept any type — treat as structural insight (record without erroring)
            result = {
                "type": h_type, "name": h_name,
                "claim": h.get("claim", h.get("description", "")),
                "evidence": h.get("evidence", ""),
                "implications": h.get("implications", ""),
                "verdict": "RECORDED",
            }

    except Exception as e:
        result = {"type": h_type, "name": h_name, "error": str(e), "verdict": "ERROR"}

    result["elapsed_seconds"] = round(time.monotonic() - start, 2)
    result.setdefault("name", h_name)
    return result


def format_results_for_feedback(results: list[dict]) -> str:
    """Format Oracle results into a human-readable string for Opus feedback."""
    lines = []
    for r in results:
        name = r.get("name", "unknown")
        verdict = r.get("verdict", "?")
        lines.append(f"### {name} [{verdict}]")

        if r.get("error"):
            lines.append(f"  ERROR: {r['error']}")
        elif r.get("type") == "plaintext_fragment":
            lines.append(f"  Crib matches: {r.get('crib_matches', 0)}, "
                         f"mismatches: {r.get('crib_mismatches', 0)}")
            if r.get("mismatch_details"):
                for m in r["mismatch_details"][:5]:
                    lines.append(f"    pos {m['pos']}: expected '{m['expected']}', got '{m['got']}'")
        elif r.get("type") == "cipher_archetype":
            lines.append(f"  Crib score: {r.get('crib_score', 0)}/24 | "
                         f"Bean: {r.get('bean_passed', '?')} | "
                         f"Method: {r.get('method', '?')}")
            lines.append(f"  Configs tested: {r.get('configs_tested', 0)}")
        elif r.get("type") == "key_source":
            lines.append(f"  Vig matches: {r.get('vigenere_matches', 0)}/24, "
                         f"Beau matches: {r.get('beaufort_matches', 0)}/24")
            if r.get("mismatches"):
                for m in r["mismatches"][:5]:
                    lines.append(f"    pos {m['pos']}: expected {m['expected']}, got {m['got']}")
        elif r.get("type") == "stego_placement_rule":
            lines.append(f"  {r.get('note', 'Retired null-placement scorer.')}")
        elif r.get("type") == "structural_insight":
            lines.append(f"  Claim: {r.get('claim', '?')[:200]}")

        lines.append(f"  Time: {r.get('elapsed_seconds', 0):.1f}s")
        lines.append("")

    return "\n".join(lines)
