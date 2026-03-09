"""
Custom MCP tools for K4 analysis via Claude Agent SDK.

Exposes K4 computational functions as @tool-decorated functions that
ClaudeSDKClient agents can call directly during persistent sessions.
This replaces the old generate-then-batch-test workflow with interactive
agent-driven exploration.
"""

from __future__ import annotations

import json
import logging
import random
from typing import Any

from claude_agent_sdk import tool, create_sdk_mcp_server, SdkMcpTool

logger = logging.getLogger("kryptosbot.k4_tools")

# ---------------------------------------------------------------------------
# Constants (self-contained for subprocess isolation)
# ---------------------------------------------------------------------------

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

CRIB_POSITIONS = set()
for _pos, _text in CRIBS:
    for _j in range(len(_text)):
        CRIB_POSITIONS.add(_pos + _j)

# Bean constraints — derived dynamically (variant-independent: 242 pairs)
BEAN_EQ = (27, 65)

_CRIB_DICT_K4: dict[int, str] = {}
for _pos, _text in CRIBS:
    for _j, _ch in enumerate(_text):
        _CRIB_DICT_K4[_pos + _j] = _ch

def _derive_bean_ineq() -> list[tuple[int, int]]:
    positions = sorted(_CRIB_DICT_K4.keys())
    pairs: list[tuple[int, int]] = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ca, pa = ord(K4[a]) - 65, ord(_CRIB_DICT_K4[a]) - 65
            cb, pb = ord(K4[b]) - 65, ord(_CRIB_DICT_K4[b]) - 65
            vig_eq = (ca - pa) % 26 == (cb - pb) % 26
            beau_eq = (ca + pa) % 26 == (cb + pb) % 26
            vbeau_eq = (pa - ca) % 26 == (pb - cb) % 26
            if not vig_eq and not beau_eq and not vbeau_eq:
                pairs.append((a, b))
    return pairs

BEAN_INEQ = _derive_bean_ineq()
assert len(BEAN_INEQ) == 242, f"Expected 242 VI inequalities, got {len(BEAN_INEQ)}"


def _keyword_alphabet(keyword: str, base: str) -> str:
    seen = set()
    result = []
    for c in keyword.upper() + base:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return ''.join(result)


def _decrypt_char(ct_idx: int, key_idx: int, cipher: str) -> int:
    if cipher == "vig":
        return (ct_idx - key_idx) % 26
    elif cipher == "beau":
        return (key_idx - ct_idx) % 26
    elif cipher == "varbeau":
        return (ct_idx + key_idx) % 26
    return (ct_idx - key_idx) % 26


def _recover_key(ct_idx: int, pt_idx: int, cipher: str) -> int:
    if cipher == "vig":
        return (ct_idx - pt_idx) % 26
    elif cipher == "beau":
        return (ct_idx + pt_idx) % 26
    elif cipher == "varbeau":
        return (pt_idx - ct_idx) % 26
    return (ct_idx - pt_idx) % 26


def _apply_perm_and_decrypt(perm: list[int], keyword: str, cipher: str,
                            alphabet: str) -> tuple[str, int, list[int]]:
    """Apply permutation to K4, then decrypt with keyword/cipher/alphabet.

    Returns (plaintext, crib_hits, keystream).
    """
    alpha = KA if alphabet == "KA" else AZ
    cipher_alpha = _keyword_alphabet(keyword, alpha)
    idx = {c: i for i, c in enumerate(cipher_alpha)}

    # Gather: unscrambled[i] = K4[perm[i]]
    unscrambled = ''.join(K4[perm[i]] for i in range(K4_LEN))

    # Decrypt with repeating keyword
    kw_len = len(keyword)
    pt_chars = []
    keystream = []
    for i, c in enumerate(unscrambled):
        ct_i = idx.get(c, ord(c) - ord('A'))
        key_i = idx.get(keyword[i % kw_len], ord(keyword[i % kw_len]) - ord('A'))
        pt_i = _decrypt_char(ct_i, key_i, cipher)
        pt_chars.append(cipher_alpha[pt_i])
        keystream.append(key_i)

    plaintext = ''.join(pt_chars)

    # Score cribs against plaintext
    crib_hits = 0
    for crib_pos, crib_text in CRIBS:
        for j, ch in enumerate(crib_text):
            if crib_pos + j < len(plaintext) and plaintext[crib_pos + j] == ch:
                crib_hits += 1

    return plaintext, crib_hits, keystream


def _check_bean(keystream: list[int]) -> tuple[bool, int]:
    """Check Bean equality and inequality constraints.

    Returns (eq_pass, ineq_pass_count).
    """
    eq_pass = keystream[BEAN_EQ[0]] == keystream[BEAN_EQ[1]]
    ineq_pass = sum(1 for a, b in BEAN_INEQ if keystream[a] != keystream[b])
    return eq_pass, ineq_pass


def _ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = [0] * 26
    for c in text:
        if 'A' <= c <= 'Z':
            freq[ord(c) - ord('A')] += 1
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


# ---------------------------------------------------------------------------
# Shared state for the MCP server (set by campaign before creating server)
# ---------------------------------------------------------------------------

_elite_population: list[dict] = []
_campaign_state: dict[str, Any] = {}


def set_elite(elite: list[dict]) -> None:
    global _elite_population
    _elite_population = elite


def set_campaign_state(state: dict[str, Any]) -> None:
    global _campaign_state
    _campaign_state = state


# ---------------------------------------------------------------------------
# @tool decorated functions
# ---------------------------------------------------------------------------

@tool(
    "test_permutation",
    "Apply a permutation to K4 carved text and decrypt with keyword/cipher/alphabet. "
    "Returns plaintext, crib hits, Bean constraint check, and IC.",
    {
        "perm": list[int],
        "keyword": str,
        "cipher": str,
        "alphabet": str,
    },
)
async def test_permutation_tool(args: dict[str, Any]) -> dict[str, Any]:
    perm = args["perm"]
    keyword = args.get("keyword", "KRYPTOS")
    cipher = args.get("cipher", "vig")
    alphabet = args.get("alphabet", "AZ")

    if len(perm) != K4_LEN:
        return {"content": [{"type": "text",
                "text": f"ERROR: perm must have {K4_LEN} elements, got {len(perm)}"}]}
    if sorted(perm) != list(range(K4_LEN)):
        return {"content": [{"type": "text",
                "text": "ERROR: perm must be a permutation of 0..96"}]}

    pt, crib_hits, ks = _apply_perm_and_decrypt(perm, keyword, cipher, alphabet)
    eq_pass, ineq_pass = _check_bean(ks)
    ic_val = _ic(pt)

    result = {
        "plaintext": pt,
        "crib_hits": crib_hits,
        "bean_eq_pass": eq_pass,
        "bean_ineq_pass": f"{ineq_pass}/{len(BEAN_INEQ)}",
        "ic": round(ic_val, 4),
        "keyword": keyword,
        "cipher": cipher,
        "alphabet": alphabet,
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


@tool(
    "try_keyword_sweep",
    "Try a keyword with all 6 cipher/alphabet combinations (vig/beau/varbeau × AZ/KA) "
    "using identity permutation. Returns best result and all scores.",
    {"keyword": str},
)
async def try_keyword_sweep_tool(args: dict[str, Any]) -> dict[str, Any]:
    keyword = args["keyword"].upper()
    identity = list(range(K4_LEN))
    results = []

    for cipher in ("vig", "beau", "varbeau"):
        for alphabet in ("AZ", "KA"):
            pt, crib_hits, ks = _apply_perm_and_decrypt(
                identity, keyword, cipher, alphabet)
            eq_pass, ineq_pass = _check_bean(ks)
            results.append({
                "cipher": cipher,
                "alphabet": alphabet,
                "crib_hits": crib_hits,
                "bean_eq": eq_pass,
                "bean_ineq": f"{ineq_pass}/21",
                "ic": round(_ic(pt), 4),
                "plaintext_preview": pt[:40],
            })

    results.sort(key=lambda r: (-r["crib_hits"], -r["ic"]))
    best = results[0]

    output = {
        "keyword": keyword,
        "keyword_length": len(keyword),
        "best": best,
        "all_results": results,
    }
    return {"content": [{"type": "text", "text": json.dumps(output, indent=2)}]}


@tool(
    "swap_and_test",
    "Swap specific positions in K4 before decryption. "
    "Takes list of [i,j] swap pairs and keyword/cipher/alphabet.",
    {
        "swaps": list,
        "keyword": str,
        "cipher": str,
        "alphabet": str,
    },
)
async def swap_and_test_tool(args: dict[str, Any]) -> dict[str, Any]:
    swaps = args["swaps"]
    keyword = args.get("keyword", "KRYPTOS")
    cipher = args.get("cipher", "vig")
    alphabet = args.get("alphabet", "AZ")

    perm = list(range(K4_LEN))
    for swap in swaps:
        if len(swap) != 2:
            return {"content": [{"type": "text",
                    "text": f"ERROR: each swap must be [i,j], got {swap}"}]}
        i, j = swap
        if not (0 <= i < K4_LEN and 0 <= j < K4_LEN):
            return {"content": [{"type": "text",
                    "text": f"ERROR: positions must be 0..96, got [{i},{j}]"}]}
        perm[i], perm[j] = perm[j], perm[i]

    pt, crib_hits, ks = _apply_perm_and_decrypt(perm, keyword, cipher, alphabet)
    eq_pass, ineq_pass = _check_bean(ks)

    result = {
        "swaps_applied": swaps,
        "positions_displaced": sum(1 for i in range(K4_LEN) if perm[i] != i),
        "plaintext": pt,
        "crib_hits": crib_hits,
        "bean_eq_pass": eq_pass,
        "bean_ineq_pass": f"{ineq_pass}/{len(BEAN_INEQ)}",
        "ic": round(_ic(pt), 4),
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


@tool(
    "hill_climb",
    "Run a stochastic hill-climb from a seed permutation, optimizing quadgram score "
    "with keyword/cipher/alphabet. Returns the best permutation found.",
    {
        "seed_perm": list[int],
        "keyword": str,
        "cipher": str,
        "alphabet": str,
        "iterations": int,
    },
)
async def hill_climb_tool(args: dict[str, Any]) -> dict[str, Any]:
    seed = args.get("seed_perm", list(range(K4_LEN)))
    keyword = args.get("keyword", "KRYPTOS")
    cipher = args.get("cipher", "vig")
    alphabet = args.get("alphabet", "AZ")
    iterations = min(args.get("iterations", 50000), 200000)

    if len(seed) != K4_LEN or sorted(seed) != list(range(K4_LEN)):
        return {"content": [{"type": "text",
                "text": "ERROR: seed_perm must be a valid permutation of 0..96"}]}

    best_perm = seed[:]
    best_pt, best_cribs, _ = _apply_perm_and_decrypt(best_perm, keyword, cipher, alphabet)
    best_ic = _ic(best_pt)

    for it in range(iterations):
        i, j = random.sample(range(K4_LEN), 2)
        trial = best_perm[:]
        trial[i], trial[j] = trial[j], trial[i]
        pt, cribs, _ = _apply_perm_and_decrypt(trial, keyword, cipher, alphabet)
        ic_val = _ic(pt)

        # Accept if better crib hits, or same cribs + better IC
        if cribs > best_cribs or (cribs == best_cribs and ic_val > best_ic):
            best_perm = trial
            best_pt = pt
            best_cribs = cribs
            best_ic = ic_val

    _, _, ks = _apply_perm_and_decrypt(best_perm, keyword, cipher, alphabet)
    eq_pass, ineq_pass = _check_bean(ks)

    result = {
        "iterations": iterations,
        "best_perm": best_perm,
        "plaintext": best_pt,
        "crib_hits": best_cribs,
        "ic": round(best_ic, 4),
        "bean_eq_pass": eq_pass,
        "bean_ineq_pass": f"{ineq_pass}/{len(BEAN_INEQ)}",
        "positions_displaced": sum(1 for i in range(K4_LEN) if best_perm[i] != i),
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


@tool(
    "get_elite_population",
    "Get the top N members of the current elite population from the campaign. "
    "Each member has: score, crib_hits, method, source, plaintext preview.",
    {"n": int},
)
async def get_elite_tool(args: dict[str, Any]) -> dict[str, Any]:
    n = min(args.get("n", 10), 50)
    elite = _elite_population[:n]
    results = []
    for e in elite:
        results.append({
            "score": e.get("score", 0),
            "crib_hits": e.get("crib_hits", 0),
            "method": e.get("method", "?"),
            "source": e.get("source", "?"),
            "plaintext": e.get("plaintext", "")[:50],
            "perm_hash": e.get("perm_hash", ""),
        })

    output = {
        "elite_count": len(_elite_population),
        "showing": len(results),
        "members": results,
        "campaign_rounds": _campaign_state.get("rounds_completed", 0),
        "best_ever_score": _campaign_state.get("best_ever_score", -9999),
    }
    return {"content": [{"type": "text", "text": json.dumps(output, indent=2)}]}


@tool(
    "score_plaintext",
    "Score a plaintext candidate against K4 cribs and compute IC. "
    "Checks both anchored cribs (at fixed positions) and free cribs (anywhere).",
    {"plaintext": str},
)
async def score_plaintext_tool(args: dict[str, Any]) -> dict[str, Any]:
    pt = args["plaintext"].upper()
    if len(pt) != K4_LEN:
        return {"content": [{"type": "text",
                "text": f"ERROR: plaintext must be {K4_LEN} chars, got {len(pt)}"}]}

    # Anchored crib check
    anchored_hits = 0
    for crib_pos, crib_text in CRIBS:
        for j, ch in enumerate(crib_text):
            if crib_pos + j < len(pt) and pt[crib_pos + j] == ch:
                anchored_hits += 1

    # Free crib check (cribs anywhere)
    free_hits = 0
    for _, crib_text in CRIBS:
        if crib_text in pt:
            free_hits += len(crib_text)

    result = {
        "anchored_crib_hits": anchored_hits,
        "free_crib_found": free_hits > 0,
        "free_crib_hits": free_hits,
        "ic": round(_ic(pt), 4),
        "length": len(pt),
        "plaintext": pt,
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


@tool(
    "get_campaign_status",
    "Get current campaign status: rounds completed, budget, elite size, "
    "Bean analysis status, best results.",
    {},
)
async def get_campaign_status_tool(args: dict[str, Any]) -> dict[str, Any]:
    status = {
        "rounds_completed": _campaign_state.get("rounds_completed", 0),
        "budget_spent": _campaign_state.get("budget_spent", 0),
        "budget_total": _campaign_state.get("budget_total", 250),
        "elite_count": len(_elite_population),
        "best_ever_score": _campaign_state.get("best_ever_score", -9999),
        "best_ever_crib_hits": _campaign_state.get("best_ever_crib_hits", 0),
        "best_ever_method": _campaign_state.get("best_ever_method", ""),
        "bean_baseline_done": _campaign_state.get("bean_baseline_done", False),
        "bean_single_swap_done": _campaign_state.get("bean_single_swap_done", False),
        "priority_keyword_done": _campaign_state.get("priority_keyword_done", False),
        "total_hypotheses_tested": _campaign_state.get("total_hypotheses_tested", 0),
        "total_candidates_tested": _campaign_state.get("total_candidates_tested", 0),
    }
    return {"content": [{"type": "text", "text": json.dumps(status, indent=2)}]}


# ---------------------------------------------------------------------------
# All tools list + MCP server factory
# ---------------------------------------------------------------------------

ALL_TOOLS: list[SdkMcpTool] = [
    test_permutation_tool,
    try_keyword_sweep_tool,
    swap_and_test_tool,
    hill_climb_tool,
    get_elite_tool,
    score_plaintext_tool,
    get_campaign_status_tool,
]


def create_k4_mcp_server() -> dict:
    """Create an MCP server config with all K4 tools.

    Returns a McpSdkServerConfig suitable for ClaudeAgentOptions.mcp_servers.
    """
    return create_sdk_mcp_server(
        name="k4_tools",
        version="1.0.0",
        tools=ALL_TOOLS,
    )
