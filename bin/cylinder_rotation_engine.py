#!/usr/bin/env python3
"""Cylinder Rotation Engine — angular alignment model for Antipodes decipherment.

Tests the hypothesis that K4 was encrypted by aligning ciphertext on the
Antipodes cylinder with a tableau at a specific rotation. Variable row widths
(32-36 chars) produce non-uniform angular fractions, yielding a non-periodic
key — matching K4's provably non-periodic key.

Phase 1: No twist — sweep fraction models × scales × offsets × row modes
Phase 2: Helical twist — best model from Phase 1 + per-row angular offset

Usage:
    PYTHONPATH=src python3 -u bin/cylinder_rotation_engine.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN, KEY_RECOVERY,
)

# ── Paths ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = ROOT / "results" / "cylinder_rotation.jsonl"
SUMMARY_FILE = ROOT / "reports" / "cylinder_rotation.summary.json"

# ── Antipodes Grid (47 rows, letters only) ───────────────────────────────────
# Source: bin/antipodes_device_engine.py (human-verified 2026-02-25)

ANTIPODES_ROWS = [
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH",
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG",
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE",
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH",
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE",
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT",
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER",
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD",
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF",
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK",
    "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW",
    "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF",
    "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL",
    "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV",
    "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE",
    "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ",
    "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA",
    "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL",
    "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK",
    "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC",
    "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA",
    "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ",
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM",
    "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE",
    "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH",
    "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL",
    "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE",
    "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN",
    "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ",
    "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG",
    "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT",
    "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL",
    "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP",
    "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS",
    "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ",
    "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ",
    "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ",
    "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY",
    "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ",
    "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF",
    "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG",
    "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH",
    "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH",
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD",
    "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ",
]

KA = KRYPTOS_ALPHABET
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KA)}

# ── K4 grid positions ────────────────────────────────────────────────────────


@dataclass(slots=True)
class K4Pos:
    idx: int      # 0..96 in CT
    row: int      # grid row
    col: int      # grid column
    char: str     # == CT[idx]
    width: int    # len(row)


def locate_k4() -> Tuple[List[K4Pos], List[K4Pos]]:
    """Find (row, col, width) for each K4 char in both Antipodes passes."""
    flat: List[Tuple[int, int, str, int]] = []
    for r, text in enumerate(ANTIPODES_ROWS):
        w = len(text)
        for c, ch in enumerate(text):
            flat.append((r, c, ch, w))
    flat_text = "".join(t[2] for t in flat)

    result: List[List[K4Pos]] = []
    start = 0
    for pn in range(2):
        idx = flat_text.find(CT, start)
        assert idx >= 0, f"K4 not found (pass {pn + 1})"
        positions = []
        for i in range(CT_LEN):
            r, c, ch, w = flat[idx + i]
            assert ch == CT[i], f"Grid mismatch at K4[{i}]"
            positions.append(K4Pos(idx=i, row=r, col=c, char=ch, width=w))
        result.append(positions)
        start = idx + 1
    return result[0], result[1]


PASS1, PASS2 = locate_k4()

# Grid integrity
for _i in range(CT_LEN):
    assert PASS1[_i].char == CT[_i]
    assert PASS2[_i].char == CT[_i]

# ── Crib expectations ────────────────────────────────────────────────────────
# Precompute expected key values at each crib position for every
# (variant, alphabet_space) combination. The fast path checks only these
# 24 positions instead of decrypting all 97 characters.

CRIB_SORTED = sorted(CRIB_DICT.items())
CPOS = [p for p, _ in CRIB_SORTED]   # crib CT positions, sorted
NC = len(CRIB_SORTED)

EXPECTED: Dict[Tuple[str, str], List[int]] = {}
for _v in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
    _rec = KEY_RECOVERY[_v]
    EXPECTED[(_v.value, "az")] = [
        _rec(ord(CT[p]) - 65, ord(c) - 65) for p, c in CRIB_SORTED
    ]
    EXPECTED[(_v.value, "ka")] = [
        _rec(KA_IDX[CT[p]], KA_IDX[c]) for p, c in CRIB_SORTED
    ]

# Self-encrypting verification: CT[32]=PT[32]='S' → Vigenere key[32]=0
_j32 = CPOS.index(32)
assert EXPECTED[("vigenere", "az")][_j32] == 0
assert EXPECTED[("var_beaufort", "az")][_j32] == 0

# ── Configuration ────────────────────────────────────────────────────────────

FRAC_MODELS = ["col_over_W", "col_over_Wm1", "col_center_over_W", "col_over_36", "direct"]
SCALES = [33, 26]
ROW_MODES = ["absolute", "relative", "sequential", "constant"]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHS = ["az", "ka"]
H_MAX = 33
V_MAX = 32
TWIST_MAX = 32

# ── Precomputation ───────────────────────────────────────────────────────────


def base_tab_cols(positions: List[K4Pos], model: str, scale: int) -> List[int]:
    """floor(angular_fraction * scale) for each position. Pure integer arithmetic."""
    out = [0] * CT_LEN
    for i, p in enumerate(positions):
        if model == "col_over_W":
            out[i] = (p.col * scale) // p.width
        elif model == "col_over_Wm1":
            out[i] = (p.col * scale) // max(p.width - 1, 1)
        elif model == "col_center_over_W":
            out[i] = ((2 * p.col + 1) * scale) // (2 * p.width)
        elif model == "col_over_36":
            out[i] = (p.col * scale) // 36
        else:  # direct
            out[i] = p.col
    return out


def row_vals(positions: List[K4Pos], mode: str, k4_start: int) -> List[int]:
    """Row function value for each K4 position."""
    out = [0] * CT_LEN
    for i, p in enumerate(positions):
        if mode == "absolute":
            out[i] = p.row
        elif mode == "relative":
            out[i] = p.row - k4_start
        elif mode == "sequential":
            out[i] = i
        # else constant: all zeros
    return out


# ── Decrypt helpers ──────────────────────────────────────────────────────────


def decrypt_az(key: List[int], variant: CipherVariant) -> str:
    fn = DECRYPT_FN[variant]
    return "".join(chr(fn(ord(CT[i]) - 65, key[i]) + 65) for i in range(CT_LEN))


def decrypt_ka(key: List[int], variant: CipherVariant) -> str:
    fn = DECRYPT_FN[variant]
    return "".join(KA[fn(KA_IDX[CT[i]], key[i])] for i in range(CT_LEN))


# ── Output ───────────────────────────────────────────────────────────────────


def log_hit(config: dict, pt: str, sbd, bean) -> None:
    record = {"config": config, "plaintext": pt,
              "score": sbd.to_dict(), "bean": bean.summary}
    with open(RESULTS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def full_eval(key, variant, alph, config):
    """Full decrypt + score + Bean check. Returns (stored: bool)."""
    pt = decrypt_ka(key, variant) if alph == "ka" else decrypt_az(key, variant)
    bean = verify_bean(key)
    sbd = score_candidate(pt, bean_result=bean)
    if sbd.crib_score >= STORE_THRESHOLD:
        log_hit(config, pt, sbd, bean)
        return True
    return False


# ── Phase 1: No twist ───────────────────────────────────────────────────────


def run_phase1() -> Dict[str, Any]:
    total = (len(FRAC_MODELS) * len(SCALES) * len(ROW_MODES)
             * V_MAX * H_MAX * len(VARIANTS) * len(ALPHS) * 2)
    print(f"Phase 1: {total:,} configs")
    t0 = time.time()
    st: Dict[str, Any] = {"tested": 0, "stored": 0, "best": 0, "best_cfg": None}

    for plabel, pos in [("pass1", PASS1), ("pass2", PASS2)]:
        k4s = pos[0].row
        for fm in FRAC_MODELS:
            for sc in SCALES:
                btc = base_tab_cols(pos, fm, sc)
                cbtc = [btc[p] for p in CPOS]

                for rm in ROW_MODES:
                    rv = row_vals(pos, rm, k4s)
                    crv = [rv[p] for p in CPOS]

                    for vo in range(V_MAX):
                        crc = [(vo + crv[j]) % 26 for j in range(NC)]

                        for ho in range(H_MAX):
                            ck = [(crc[j] + (cbtc[j] + ho) % sc) % MOD
                                  for j in range(NC)]

                            for var in VARIANTS:
                                for al in ALPHS:
                                    st["tested"] += 1
                                    exp = EXPECTED[(var.value, al)]
                                    cs = sum(ck[j] == exp[j] for j in range(NC))

                                    if cs > st["best"]:
                                        st["best"] = cs
                                        st["best_cfg"] = {
                                            "phase": 1, "frac": fm, "scale": sc,
                                            "h": ho, "v": vo, "row_mode": rm,
                                            "variant": var.value, "alph": al,
                                            "pass": plabel, "crib_score": cs,
                                        }

                                    if cs > NOISE_FLOOR:
                                        rc = [(vo + rv[i]) % 26 for i in range(CT_LEN)]
                                        key = [(rc[i] + (btc[i] + ho) % sc) % MOD
                                               for i in range(CT_LEN)]
                                        cfg = {
                                            "phase": 1, "frac": fm, "scale": sc,
                                            "h": ho, "v": vo, "row_mode": rm,
                                            "variant": var.value, "alph": al,
                                            "pass": plabel,
                                        }
                                        if full_eval(key, var, al, cfg):
                                            st["stored"] += 1

                # Progress per frac×scale combo
                dt = time.time() - t0
                rate = st["tested"] / max(dt, 0.001)
                print(f"  {plabel} {fm:>20s}/s{sc:>2d} | "
                      f"{st['tested']:>8,} | best={st['best']}/24 | {rate:,.0f}/s")

    st["time"] = round(time.time() - t0, 1)
    return st


# ── Phase 2: Helical twist ──────────────────────────────────────────────────


def run_phase2(p1: Dict[str, Any]) -> Dict[str, Any]:
    cfg = p1.get("best_cfg")
    if not cfg:
        print("Phase 2: skipped (no Phase 1 config)")
        return {"tested": 0, "stored": 0, "best": 0, "best_cfg": None, "time": 0}

    fm, sc, rm = cfg["frac"], cfg["scale"], cfg["row_mode"]
    total = H_MAX * V_MAX * TWIST_MAX * len(VARIANTS) * len(ALPHS) * 2
    print(f"Phase 2: {total:,} configs (frac={fm}, scale={sc}, row={rm})")
    t0 = time.time()
    st: Dict[str, Any] = {"tested": 0, "stored": 0, "best": 0, "best_cfg": None}

    for plabel, pos in [("pass1", PASS1), ("pass2", PASS2)]:
        k4s = pos[0].row
        btc = base_tab_cols(pos, fm, sc)
        rv = row_vals(pos, rm, k4s)
        rd = [p.row - k4s for p in pos]
        cbtc = [btc[p] for p in CPOS]
        crv = [rv[p] for p in CPOS]
        crd = [rd[p] for p in CPOS]

        for vo in range(V_MAX):
            crc = [(vo + crv[j]) % 26 for j in range(NC)]

            for ho in range(H_MAX):
                for tw in range(TWIST_MAX):
                    ck = [(crc[j] + (cbtc[j] + ho + tw * crd[j]) % sc) % MOD
                          for j in range(NC)]

                    for var in VARIANTS:
                        for al in ALPHS:
                            st["tested"] += 1
                            exp = EXPECTED[(var.value, al)]
                            cs = sum(ck[j] == exp[j] for j in range(NC))

                            if cs > st["best"]:
                                st["best"] = cs
                                st["best_cfg"] = {
                                    "phase": 2, "frac": fm, "scale": sc,
                                    "h": ho, "v": vo, "row_mode": rm,
                                    "twist": tw, "variant": var.value,
                                    "alph": al, "pass": plabel,
                                    "crib_score": cs,
                                }

                            if cs > NOISE_FLOOR:
                                rc = [(vo + rv[i]) % 26 for i in range(CT_LEN)]
                                key = [(rc[i] + (btc[i] + ho + tw * rd[i]) % sc) % MOD
                                       for i in range(CT_LEN)]
                                c = {
                                    "phase": 2, "frac": fm, "scale": sc,
                                    "h": ho, "v": vo, "row_mode": rm,
                                    "twist": tw, "variant": var.value,
                                    "alph": al, "pass": plabel,
                                }
                                if full_eval(key, var, al, c):
                                    st["stored"] += 1

        dt = time.time() - t0
        rate = st["tested"] / max(dt, 0.001)
        print(f"  {plabel} done | {st['tested']:>8,} | "
              f"best={st['best']}/24 | {rate:,.0f}/s")

    st["time"] = round(time.time() - t0, 1)
    return st


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    print("=== Cylinder Rotation Engine ===")
    print(f"Pass 1: rows {PASS1[0].row}-{PASS1[-1].row}, "
          f"widths {sorted(set(p.width for p in PASS1))}")
    print(f"Pass 2: rows {PASS2[0].row}-{PASS2[-1].row}, "
          f"widths {sorted(set(p.width for p in PASS2))}")
    print(f"Cribs: {NC} positions, self-encrypt key[32]=0 verified")
    print()

    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if RESULTS_FILE.exists():
        RESULTS_FILE.unlink()

    t0 = time.time()

    print("--- Phase 1: No twist ---")
    p1 = run_phase1()
    print(f"Phase 1 done: {p1['tested']:,} in {p1['time']}s, best={p1['best']}/24")
    if p1["best_cfg"]:
        print(f"  Best: {p1['best_cfg']}")
    print()

    print("--- Phase 2: Helical twist ---")
    p2 = run_phase2(p1)
    print(f"Phase 2 done: {p2['tested']:,} in {p2.get('time', 0)}s, best={p2['best']}/24")
    if p2.get("best_cfg"):
        print(f"  Best: {p2['best_cfg']}")
    print()

    total_t = round(time.time() - t0, 1)
    total_n = p1["tested"] + p2["tested"]
    best = max(p1["best"], p2["best"])
    best_cfg = p1["best_cfg"] if p1["best"] >= p2["best"] else p2.get("best_cfg")

    summary = {
        "experiment": "cylinder_rotation",
        "total_configs": total_n,
        "phase1": {
            "configs": p1["tested"], "best_score": p1["best"],
            "best_config": p1["best_cfg"], "time_s": p1["time"],
            "hits": p1["stored"],
        },
        "phase2": {
            "configs": p2["tested"], "best_score": p2["best"],
            "best_config": p2.get("best_cfg"), "time_s": p2.get("time", 0),
            "hits": p2["stored"],
        },
        "best_score": best,
        "best_config": best_cfg,
        "total_hits": p1["stored"] + p2["stored"],
        "total_time_s": total_t,
        "noise_floor": NOISE_FLOOR,
        "store_threshold": STORE_THRESHOLD,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print("=== SUMMARY ===")
    print(f"Configs: {total_n:,} in {total_t}s")
    print(f"Best: {best}/24 (noise={NOISE_FLOOR})")
    if best_cfg:
        print(f"Config: {best_cfg}")
    print(f"Hits: {summary['total_hits']} (threshold={STORE_THRESHOLD})")
    print(f"Output: {RESULTS_FILE}")
    print(f"Summary: {SUMMARY_FILE}")

    if best < STORE_THRESHOLD:
        print(f"\nVerdict: ALL NOISE (best {best}/24 vs noise={NOISE_FLOOR}) "
              f"— cylinder rotation does not produce signal.")


if __name__ == "__main__":
    main()
