#!/usr/bin/env python3
"""
Cipher: pad-letter removal from the full cipher panel + Cardan-style overlay (key generation)
Family: grille
Status: active
Keyspace: see PREREG (7 grid models x 8 letter-removal sets x 2 question-mark modes, deduped to layouts; x 4 overlay targets x 4 hole rules x ADV/SKIP x all phases x 7 tableau cells; plus a full-offset running-key sweep of 4 sculpture streams x 7 cells)
Last run:
Best score:

E-PADGRILLE-01: if "buffer" letters (Q, X, plaintext pad letters, the ? marks) are deleted from
the whole K1-K4 cipher panel and the reflowed panel is laid over the tableau (or over itself),
does the overlay yield K4's key?

Four hole rules turn one overlay into a key:
  FOOT     running key = target letters under K4's own (shifted) cells
  REMOVED  holes = original cells of the deleted letters; key = target letters seen through them
  SLID     holes = original cells of the deleted letters; key = panel letters that slid into them
  MATCH    holes = K1-K3 cells where shifted panel letter == target letter; key = those letters
REMOVED / SLID / MATCH give a short sequence, used as a periodic key at every phase.
SWEEP covers any uniform shift at once: every offset of four sculpture streams as a running key.

Scoring: crib matches (0-24) under 7 tableau cells (AZ/KA vig/beau/varb + the sculpture tableau).
Pre-registration: docs/campaigns/pad_removal_grille_overlay_prereg_2026_10_04.md
PROMOTED means "hand to red-team", never "solved".

Usage:
  PYTHONPATH=src python3 -u scripts/grille/e_padgrille_01_pad_removal_overlay.py --mode selftest
  PYTHONPATH=src python3 -u scripts/grille/e_padgrille_01_pad_removal_overlay.py --mode calibrate --workers 14
  PYTHONPATH=src python3 -u scripts/grille/e_padgrille_01_pad_removal_overlay.py --mode real --workers 14
  PYTHONPATH=src python3 -u scripts/grille/e_padgrille_01_pad_removal_overlay.py --benchmark --workers 14
"""
from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import multiprocessing as mp
import os
import platform
import pstats
import random
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    if os.path.dirname(_ROOT) == _ROOT:  # reached / without finding src/: fall back to cwd
        _ROOT = os.getcwd()
        break
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "kryptosbot"))

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
import panel_cribs as pc  # noqa: E402  (verified K1-K3 texts; data only)

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CELLS = ("AZ-vig", "AZ-beau", "AZ-varb", "KA-vig", "KA-beau", "KA-varb", "sculpt")
CRIB_POS = tuple(sorted(CRIB_DICT))
MAX_WORKERS = 22  # operator cap (2026-10-04): the 28 vCPUs are shared across projects

# ── FROZEN PRE-REGISTRATION CONSTANTS (changing any needs a new campaign id) ──────────
PREREG = {
    "campaign": "E-PADGRILLE-01",
    "grids": ["NYT31-Q4", "NYT31-Q0", "NYT31-SQ1", "NYT31-SQ2", "NYT31-SQ3", "NYT31-SQ4", "COPPER"],
    "letter_removals": ["none", "Q_pre", "Q_all", "X_pre", "X_all", "QX_pre", "QX_all", "PTPAD"],
    "qmark_modes": ["keep", "drop"],
    "targets": ["TAB", "TAB_FOLD", "TAB_LFLOW", "PANEL"],
    "rules": ["FOOT", "REMOVED", "SLID", "MATCH"],
    "index_modes": ["ADV", "SKIP"],
    "sweep_streams": ["TAB", "TAB_LETTERS", "PANEL", "PANEL_LETTERS"],
    "cells": list(CELLS),
    "promote_at": 18,
    "nominate_familywise_p": 0.01,
    "null_seeds": [0, 999],
    "power_seed0": 500000,
    "power_n": 500,
    "plantable_removals": ["none", "Q_pre", "X_pre", "QX_pre", "PTPAD"],
}

# Copper line layout of the cipher panel (28 carved lines, ? included). Letters and ? positions are
# verified in selftest against panel_cribs + constants.CT; line breaks of lines 1-8 match the
# measured 32/31/31/30/31/32/31/31; K3-region line breaks are transcription-derived (unverified
# against a photograph), so COPPER is a secondary grid model.
COPPER_ROWS = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ", "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE", "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA", "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI", "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX", "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ", "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP", "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE", "WMTWNDITEENRAHCTENEUDRETNHAEOE",
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", "EIFTBRSPAMHHEWENATAMATEGYEERLB",
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT", "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR", "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP", "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
)
GRID_QMARKS = {  # which ? marks (ordinal 0-3) occupy a cell under each grid model
    "NYT31-Q4": {0, 1, 2, 3}, "NYT31-Q0": set(), "NYT31-SQ1": {1, 2, 3},
    "NYT31-SQ2": {0, 2, 3}, "NYT31-SQ3": {0, 1, 3}, "NYT31-SQ4": {0, 1, 2}, "COPPER": {0, 1, 2, 3},
}


# ── cipher arithmetic (key index forced by c and p; mod 26) ─────────────────────────────
def required_key(c: str, p: str, cell: str) -> str:
    """Key letter that maps plaintext p to ciphertext c in this tableau cell."""
    if cell == "sculpt":
        return AZ[(KA.index(c) - AZ.index(p)) % 26]
    a = AZ if cell.startswith("AZ") else KA
    kind = cell.split("-")[1]
    if kind == "vig":
        return a[(a.index(c) - a.index(p)) % 26]
    if kind == "beau":
        return a[(a.index(c) + a.index(p)) % 26]
    return a[(a.index(p) - a.index(c)) % 26]


def encrypt(p: str, k: str, cell: str) -> str:
    if cell == "sculpt":
        return KA[(AZ.index(p) + AZ.index(k)) % 26]
    a = AZ if cell.startswith("AZ") else KA
    kind = cell.split("-")[1]
    if kind == "vig":
        return a[(a.index(p) + a.index(k)) % 26]
    if kind == "beau":
        return a[(a.index(k) - a.index(p)) % 26]
    return a[(a.index(p) - a.index(k)) % 26]


def decrypt(c: str, k: str, cell: str) -> str:
    if cell == "sculpt":
        return AZ[(KA.index(c) - AZ.index(k)) % 26]
    a = AZ if cell.startswith("AZ") else KA
    kind = cell.split("-")[1]
    if kind == "vig":
        return a[(a.index(c) - a.index(k)) % 26]
    if kind == "beau":
        return a[(a.index(k) - a.index(c)) % 26]
    return a[(a.index(c) + a.index(k)) % 26]


# ── panel, removal sets, layouts ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class Tok:
    ch: str   # letter, or "?"
    sec: str  # K1..K4, or QM for a question mark
    idx: int  # index within the section's letters (question marks: ordinal 0-3)


def k2_qmark_indices() -> tuple[int, ...]:
    """K2 letter indices that a carved ? immediately precedes (anchors from the copper)."""
    out = []
    for anchor in ("GGWHKK", "HHDDDUVH", "FLGGTEZ"):
        if pc._K2_CT.count(anchor) != 1:
            raise ValueError(f"K2 ? anchor {anchor} not unique")
        out.append(pc._K2_CT.index(anchor) + len(anchor))
    return tuple(out)


def build_panel(k4: str) -> list[Tok]:
    toks = [Tok(c, "K1", i) for i, c in enumerate(pc._K1_CT)]
    qi, q = k2_qmark_indices(), 0
    for i, c in enumerate(pc._K2_CT):
        if i in qi:
            toks.append(Tok("?", "QM", q))
            q += 1
        toks.append(Tok(c, "K2", i))
    toks += [Tok(c, "K3", i) for i, c in enumerate(pc._K3_CT)]
    toks.append(Tok("?", "QM", 3))
    toks += [Tok(c, "K4", i) for i, c in enumerate(k4)]
    return toks


def k3_ct_index_of_pt(i: int) -> int:
    """K3 is an unkeyed double rotation: PT[i] = CT[(191 + 192 i) mod 337]."""
    return (191 + 192 * i) % 337


def ptpad_tokens(panel: list[Tok]) -> set[int]:
    """Stream indices of CT letters that encrypt a plaintext pad: K2 X separators, K3 X and final Q."""
    k2 = {i for i, ch in enumerate(pc._K2_PT) if ch == "X"}
    k3 = {k3_ct_index_of_pt(i) for i, ch in enumerate(pc._K3_PT) if ch in "XQ"}
    return {t for t, tok in enumerate(panel)
            if (tok.sec == "K2" and tok.idx in k2) or (tok.sec == "K3" and tok.idx in k3)}


def letter_removal(panel: list[Tok], name: str) -> set[int]:
    if name == "none":
        return set()
    if name == "PTPAD":
        return ptpad_tokens(panel)
    letters, scope = name.split("_")
    secs = ("K1", "K2", "K3") if scope == "pre" else ("K1", "K2", "K3", "K4")
    return {t for t, tok in enumerate(panel) if tok.sec in secs and tok.ch in letters}


def copper_rows_of(panel: list[Tok]) -> list[int]:
    rows = []
    for r, line in enumerate(COPPER_ROWS):
        rows += [r] * len(line)
    if len(rows) != len(panel):
        raise ValueError("copper layout length != panel length")
    return rows


def layout(grid: str, kept: list[int], crow: list[int]) -> dict[int, tuple[int, int]]:
    """Cell of each kept token. NYT31: strict 31-cell rows (the NYT chart grid), continuous reflow.
    COPPER: carved lines; a deletion shifts the rest of its own line left, other lines unchanged."""
    if grid.startswith("NYT31"):
        return {t: divmod(n, 31) for n, t in enumerate(kept)}
    out, col = {}, Counter()
    for t in kept:
        r = crow[t]
        out[t] = (r, col[r])
        col[r] += 1
    return out


# ── overlay targets ───────────────────────────────────────────────────────────────────
def tableau_rows(body: str = KA) -> list[list[str | None]]:
    """Sculpture tableau: header/footer ' A..Z A..D', 26 rows label + 30 body letters, extra L on row N."""
    hdr = [None] + [AZ[(c - 1) % 26] for c in range(1, 31)]
    rows = [hdr]
    for r in range(26):
        row = [AZ[r]] + [body[(c - 1 + r) % 26] for c in range(1, 31)]
        if AZ[r] == "N":
            row.append("L")
        rows.append(row)
    rows.append(list(hdr))
    return rows


def grid_from_rows(rows: list[list[str | None]]) -> dict[tuple[int, int], str]:
    return {(r, c): ch for r, row in enumerate(rows) for c, ch in enumerate(row) if ch}


def build_targets(tab_rows: list[list[str | None]], panel_letters: list[Tok],
                  base: dict[int, tuple[int, int]]) -> dict[str, dict[tuple[int, int], str]]:
    tab = grid_from_rows(tab_rows)
    fold = {(r, 30 - c): ch for (r, c), ch in tab.items() if c <= 30}
    stream = [ch for row in tab_rows for ch in row]
    lflow = {divmod(n, 31): ch for n, ch in enumerate(stream) if ch}
    panel_t = {cell: panel_letters[t].ch for t, cell in base.items() if panel_letters[t].ch != "?"}
    return {"TAB": tab, "TAB_FOLD": fold, "TAB_LFLOW": lflow, "PANEL": panel_t}


def sweep_streams(tab_rows: list[list[str | None]], panel_letters: list[Tok]) -> dict[str, list[str | None]]:
    tab = [ch for row in tab_rows for ch in row]
    pan = [None if tok.ch == "?" else tok.ch for tok in panel_letters]
    return {"TAB": tab, "TAB_LETTERS": [c for c in tab if c],
            "PANEL": pan, "PANEL_LETTERS": [c for c in pan if c]}


# ── scoring ───────────────────────────────────────────────────────────────────────────
def required_table(k4: str) -> dict[str, list[tuple[int, str]]]:
    return {cell: [(i, required_key(k4[i], CRIB_DICT[i], cell)) for i in CRIB_POS] for cell in CELLS}


def periodic_counts(seq: list[str], t_of: dict[int, int], req: list[tuple[int, str]]) -> Counter:
    """count[phase] = crib matches when key[i] = seq[(t_of[i] + phase) % L]."""
    n = len(seq)
    where: dict[str, list[int]] = {}
    for j, ch in enumerate(seq):
        where.setdefault(ch, []).append(j)
    cnt: Counter = Counter()
    for i, k in req:
        t = t_of.get(i)
        if t is None:
            continue
        for j in where.get(k, ()):
            cnt[(j - t) % n] += 1
    return cnt


@dataclass
class World:
    k4: str
    panel_ct: list[Tok]       # panel whose letters are laid over the target (carries K4)
    panel_target: list[Tok]   # panel copy used as an overlay target / sweep stream
    tab_rows: list[list[str | None]]


def real_world(k4: str = CT) -> World:
    p = build_panel(k4)
    return World(k4, p, list(p), tableau_rows(KA))


def null_world(seed: int) -> World:
    """Matched null: random keyed tableau, shuffled panel target copy, shuffled K1-K3 letters on the
    laid-over panel (Q, X, ? and K4 kept in place, so every removal set and K4 itself are unchanged)."""
    rng = random.Random(seed)
    alpha = list(AZ)
    rng.shuffle(alpha)
    base = build_panel(CT)
    slots = [t for t, tok in enumerate(base) if tok.sec in ("K1", "K2", "K3") and tok.ch not in "QX"]
    letters = [base[t].ch for t in slots]
    rng.shuffle(letters)
    laid = list(base)
    for t, ch in zip(slots, letters):
        laid[t] = Tok(ch, base[t].sec, base[t].idx)
    lt = [t for t, tok in enumerate(base) if tok.ch != "?"]
    tl = [base[t].ch for t in lt]
    rng.shuffle(tl)
    tgt = list(base)
    for t, ch in zip(lt, tl):
        tgt[t] = Tok(ch, base[t].sec, base[t].idx)
    return World(CT, laid, tgt, tableau_rows("".join(alpha)))


def enumerate_layouts(panel: list[Tok]) -> list[dict]:
    """Distinct (grid, deletion) layouts in frozen order; aliases recorded, duplicates skipped."""
    crow = copper_rows_of(panel)
    qm = {tok.idx: t for t, tok in enumerate(panel) if tok.sec == "QM"}
    seen: dict[tuple, dict] = {}
    out = []
    for grid in PREREG["grids"]:
        present = [t for t, tok in enumerate(panel) if tok.sec != "QM" or tok.idx in GRID_QMARKS[grid]]
        pset = set(present)
        for lrem in PREREG["letter_removals"]:
            lset = letter_removal(panel, lrem)
            for qmode in PREREG["qmark_modes"]:
                drop = {qm[i] for i in GRID_QMARKS[grid]} if qmode == "drop" else set()
                removed = sorted((lset | drop) & pset)
                sig = (grid.split("-")[0], frozenset(pset), frozenset(removed))
                name = f"{grid}|{lrem}|{qmode}"
                if sig in seen:
                    seen[sig]["aliases"].append(name)
                    continue
                kept = [t for t in present if t not in set(removed)]
                lay = {"name": name, "grid": grid, "lrem": lrem, "qmode": qmode, "aliases": [],
                       "base": layout(grid, present, crow), "new": layout(grid, kept, crow),
                       "removed": removed, "kept": kept}
                seen[sig] = lay
                out.append(lay)
    return out


def k4_index_maps(panel: list[Tok], lay: dict) -> dict[str, dict[int, int]]:
    """t_of[i] for each index mode; K4 letters deleted by the layout have no key (None)."""
    gone = {panel[t].idx for t in lay["removed"] if panel[t].sec == "K4"}
    adv = {i: i for i in range(97) if i not in gone}
    skip, n = {}, 0
    for i in range(97):
        if i not in gone:
            skip[i] = n
            n += 1
    maps = {"ADV": adv}
    if gone:
        maps["SKIP"] = skip
    return maps


def sequences(world: World, lay: dict, targets: dict) -> dict[tuple[str, str], list[str]]:
    """(rule, target) -> key sequence for REMOVED / SLID / MATCH."""
    panel = world.panel_ct
    base, new = lay["base"], lay["new"]
    seqs = {}
    inv = {cell: t for t, cell in new.items()}
    slid = []
    for t in lay["removed"]:
        u = inv.get(base[t])
        if u is not None and panel[u].ch != "?":
            slid.append(panel[u].ch)
    if slid:
        seqs[("SLID", "-")] = slid
    for tname, tgt in targets.items():
        rem = [tgt[base[t]] for t in lay["removed"] if base[t] in tgt]
        if rem:
            seqs[("REMOVED", tname)] = rem
        match = [panel[t].ch for t in lay["kept"]
                 if panel[t].sec in ("K1", "K2", "K3") and tgt.get(new[t]) == panel[t].ch]
        if match:
            seqs[("MATCH", tname)] = match
    return seqs


def user_hole_rule(panel: list[Tok], lay: dict,
                   targets: dict[str, dict[tuple[int, int], str]]) -> list[str] | None:
    """Extension point, OUTSIDE the frozen E-PADGRILLE-01 universe (returns None, so it adds nothing).

    Gets one layout (`lay`: "base"/"new" map stream index -> (row, col) before/after deletion,
    "removed"/"kept" stream indices, "grid", "lrem", "qmode") and the overlay targets
    (target name -> {(row, col): letter}). Return a key sequence in reading order to have it
    scored as a periodic key at every phase under family USER, or None to skip this layout.
    Any non-None implementation is a new campaign (E-PADGRILLE-02) and needs its own prereg.
    """
    # TODO(Colin): your hole rule (see docs/campaigns/pad_removal_grille_overlay_prereg_2026_10_04.md §10).
    return None


def evaluate(world: World, floor: int = 99, track: set[str] | None = None) -> dict:
    """Score every config. Returns family maxima, a score histogram, configs >= floor, and the
    scores of any config ids listed in `track` (planted controls)."""
    req = required_table(world.k4)
    fam_max: Counter = Counter()
    hist: Counter = Counter()
    hits: list[tuple[int, str]] = []
    tracked: dict[str, int] = {}
    n_cfg = 0

    def note(fam: str, cid: str, s: int) -> None:
        nonlocal n_cfg
        n_cfg += 1
        hist[s] += 1
        if s > fam_max[fam]:
            fam_max[fam] = s
        if s >= floor:
            hits.append((s, cid))
        if track is not None and cid in track:
            tracked[cid] = s

    for lay in enumerate_layouts(world.panel_ct):
        targets = build_targets(world.tab_rows, world.panel_target, lay["base"])
        k4cells = {world.panel_ct[t].idx: cell for t, cell in lay["new"].items()
                   if world.panel_ct[t].sec == "K4"}
        for tname, tgt in targets.items():
            key = {i: tgt.get(cell) for i, cell in k4cells.items()}
            for cell in CELLS:
                s = sum(1 for i, k in req[cell] if key.get(i) == k)
                note("FOOT", f"FOOT|{lay['name']}|{tname}|-|-|{cell}", s)
        maps = k4_index_maps(world.panel_ct, lay)
        seqs = sequences(world, lay, targets)
        user = user_hole_rule(world.panel_ct, lay, targets)
        if user:
            seqs[("USER", "-")] = user
        for (rule, tname), seq in seqs.items():
            for mode, t_of in maps.items():
                for cell in CELLS:
                    cnt = periodic_counts(seq, t_of, req[cell])
                    for ph in range(len(seq)):
                        note(rule, f"{rule}|{lay['name']}|{tname}|{mode}|{ph}|{cell}", cnt.get(ph, 0))
    for sname, stream in sweep_streams(world.tab_rows, world.panel_target).items():
        t_of = {i: i for i in range(97)}
        seq = [c if c else "-" for c in stream]
        for cell in CELLS:
            cnt = periodic_counts(seq, t_of, req[cell])
            for off in range(len(seq)):
                note("SWEEP", f"SWEEP|{sname}|{off}|{cell}", cnt.get(off, 0))
    fam_max["ALL"] = max(fam_max.values())
    return {"fam_max": dict(fam_max), "hist": dict(sorted(hist.items())), "n_configs": n_cfg,
            "hits": sorted(hits, reverse=True), "tracked": tracked}


# ── full key for one config (for reporting and planting) ───────────────────────────────
def full_key(world: World, cid: str) -> list[str | None]:
    parts = cid.split("|")
    key: list[str | None] = [None] * 97
    if parts[0] == "SWEEP":
        stream = sweep_streams(world.tab_rows, world.panel_target)[parts[1]]
        off = int(parts[2])
        for i in range(97):
            key[i] = stream[(off + i) % len(stream)]
        return key
    rule, lname, tname, mode, ph = parts[0], "|".join(parts[1:4]), parts[4], parts[5], parts[6]
    lay = next(x for x in enumerate_layouts(world.panel_ct) if x["name"] == lname)
    targets = build_targets(world.tab_rows, world.panel_target, lay["base"])
    if rule == "FOOT":
        for t, cell in lay["new"].items():
            if world.panel_ct[t].sec == "K4":
                key[world.panel_ct[t].idx] = targets[tname].get(cell)
        return key
    seq = sequences(world, lay, targets)[(rule, tname)]
    for i, t in k4_index_maps(world.panel_ct, lay)[mode].items():
        key[i] = seq[(t + int(ph)) % len(seq)]
    return key


def decrypt_config(world: World, cid: str) -> str:
    cell = cid.split("|")[-1]
    key = full_key(world, cid)
    return "".join(decrypt(c, k, cell) if k else "." for c, k in zip(world.k4, key))


# ── workers ───────────────────────────────────────────────────────────────────────────
_PIN = None


def _init(counter, cpus: list[int] | None) -> None:
    if cpus:
        with counter.get_lock():
            n = counter.value
            counter.value += 1
        os.sched_setaffinity(0, {cpus[n % len(cpus)]})


def null_task(seeds: list[int]) -> list[dict]:
    return [{"seed": s, "fam_max": evaluate(null_world(s))["fam_max"]} for s in seeds]


def plantable(world: World, rng: random.Random) -> str:
    """Random config id whose key does not depend on K4's own letters."""
    lays = [x for x in enumerate_layouts(world.panel_ct)
            if x["lrem"] in PREREG["plantable_removals"]]
    while True:
        fam = rng.choice(["FOOT", "REMOVED", "SLID", "MATCH", "SWEEP"])
        cell = rng.choice(CELLS)
        if fam == "SWEEP":
            sname = rng.choice(PREREG["sweep_streams"])
            n = len(sweep_streams(world.tab_rows, world.panel_target)[sname])
            return f"SWEEP|{sname}|{rng.randrange(n)}|{cell}"
        lay = rng.choice(lays)
        tname = rng.choice(PREREG["targets"])
        if fam == "FOOT":
            return f"FOOT|{lay['name']}|{tname}|-|-|{cell}"
        targets = build_targets(world.tab_rows, world.panel_target, lay["base"])
        seqs = sequences(world, lay, targets)
        key = (fam, "-" if fam == "SLID" else tname)
        if key not in seqs:
            continue
        tname = key[1]
        return f"{fam}|{lay['name']}|{tname}|ADV|{rng.randrange(len(seqs[key]))}|{cell}"


def plant(seed: int) -> dict:
    """Encrypt a random crib-bearing PT with a random plantable config's key; harness must find 24."""
    rng = random.Random(seed)
    base = real_world(CT)
    for _ in range(1000):  # redraw configs lacking crib keys or whose key reads K4's own letters
        cid = plantable(base, rng)
        key = full_key(base, cid)
        if not all(key[i] for i in CRIB_POS):
            continue
        cell = cid.split("|")[-1]
        pt = [CRIB_DICT.get(i) or rng.choice(AZ) for i in range(97)]
        k4 = "".join(encrypt(p, k, cell) if k else rng.choice(AZ) for p, k in zip(pt, key))
        world = real_world(k4)
        stable = full_key(world, cid) == key
        if stable:
            break
    res = evaluate(world, track={cid})
    return {"seed": seed, "cid": cid, "stable": stable, "planted_score": res["tracked"].get(cid),
            "family_max": res["fam_max"]["ALL"],
            "detected": res["tracked"].get(cid) == 24 and res["fam_max"]["ALL"] == 24}


def power_task(seeds: list[int]) -> list[dict]:
    return [plant(s) for s in seeds]


def run_pool(fn, seeds: list[int], workers: int, batch: int, affinity: str) -> list[dict]:
    chunks = [seeds[i:i + batch] for i in range(0, len(seeds), batch)]
    cpus = sorted(os.sched_getaffinity(0)) if affinity == "pin" and hasattr(os, "sched_getaffinity") else None
    if cpus:
        print(f"  affinity pin: workers round-robin over CPUs {cpus[:workers]}", flush=True)
    counter = mp.Value("i", 0)
    out: list[dict] = []
    with ProcessPoolExecutor(max_workers=workers, initializer=_init, initargs=(counter, cpus)) as ex:
        for res in ex.map(fn, chunks):
            out += res
    return out


# ── selftest (oracles) ────────────────────────────────────────────────────────────────
def selftest() -> bool:
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        ok &= bool(cond)
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}", flush=True)

    rng = random.Random(1)
    check("cipher round trips (all 7 cells, 2000 random letters each)", all(
        decrypt(encrypt(p, k, c), k, c) == p and required_key(encrypt(p, k, c), p, c) == k
        for c in CELLS for p, k in ((rng.choice(AZ), rng.choice(AZ)) for _ in range(2000))))
    k1 = "".join(required_key(c, p, "KA-vig") for c, p in zip(pc._K1_CT, pc._K1_PT))
    check("K1 keystream under KA-vig is PALIMPSEST repeated", k1 == ("PALIMPSEST" * 7)[:63])
    k2 = "".join(required_key(c, p, "KA-vig") for c, p in zip(pc._K2_CT, pc._K2_PT))
    check("K2 keystream under KA-vig is ABSCISSA repeated", k2 == ("ABSCISSA" * 47)[:369])
    check("K3 PT[i] == CT[(191+192i) mod 337] for all 336",
          all(pc._K3_PT[i] == pc._K3_CT[k3_ct_index_of_pt(i)] for i in range(336)))
    panel = build_panel(CT)
    stream = "".join(t.ch for t in panel)
    check("panel = 869 tokens, letters == K1+K2+K3+K4 (verified sources)",
          len(panel) == 869 and stream.replace("?", "") == pc._K1_CT + pc._K2_CT + pc._K3_CT + CT)
    check("? at stream indices 100, 226, 288, 771", [i for i, c in enumerate(stream) if c == "?"] == [100, 226, 288, 771])
    check("copper rows concatenate to the panel stream", "".join(COPPER_ROWS) == stream)
    rows = ["".join(ch or " " for ch in r) for r in tableau_rows()]
    check("tableau header, row A, row N (extra L), row Z, footer", rows[0] == " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
          and rows[1] == "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP" and rows[14] == "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL"
          and rows[26] == "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY" and rows[27] == rows[0] and len(rows) == 28)
    pads = ptpad_tokens(panel)
    k3pads = sorted(panel[t].ch for t in pads if panel[t].sec == "K3")
    check("PTPAD = 6 K2 X-separator cells + K3 'X','Q' (transposition keeps letters)",
          len(pads) == 8 and k3pads == ["Q", "X"])
    check("Q in K4 at crib CT positions 25, 26 (EASTNORTHEAST clue uses both)",
          CT[25] == CT[26] == "Q" and 25 in CRIB_DICT and 26 in CRIB_DICT)
    lays = enumerate_layouts(panel)
    plain = next(x for x in lays if x["name"] == "NYT31-Q4|none|keep")
    check("NYT31-Q4 plain overlay: K4 'O' at row 24 col 28", plain["new"][772] == (24, 28) and panel[772].ch == "O")
    cop = next(x for x in lays if x["name"] == "COPPER|none|keep")
    check("COPPER plain overlay: K4 'O' at row 24 col 27", cop["new"][772] == (24, 27))
    qpre = next(x for x in lays if x["name"] == "NYT31-Q4|Q_pre|keep")
    check("Q_pre deletes 30 letters and shifts K4 30 cells", len(qpre["removed"]) == 30 and qpre["new"][772] == divmod(772 - 30, 31))
    for s in (11, 12, 13, 14, 15):
        r = plant(s)
        check(f"planted control seed {s}: {r['cid']} scores {r['planted_score']}/24 (stable={r['stable']})", r["detected"])
    return ok


# ── main ──────────────────────────────────────────────────────────────────────────────
def env_report(workers: int, affinity: str) -> dict:
    model = ""
    try:
        with open("/proc/cpuinfo") as fh:
            model = next((ln.split(":", 1)[1].strip() for ln in fh if ln.startswith("model name")), "")
    except OSError as exc:
        model = f"unavailable ({exc})"
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    return {"python": sys.version.split()[0], "platform": platform.platform(), "cpu_model": model,
            "usable_logical_cpus": cpus, "workers": workers, "affinity": affinity,
            "native_libs": "none (stdlib only; no BLAS/OpenMP threads to control)"}


def universe_hash() -> str:
    lays = enumerate_layouts(build_panel(CT))
    desc = json.dumps({"prereg": PREREG, "layouts": [x["name"] for x in lays]}, sort_keys=True)
    return hashlib.sha256(desc.encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="E-PADGRILLE-01 pad-letter removal + overlay key test")
    ap.add_argument("--mode", choices=["selftest", "calibrate", "real"], default="selftest")
    ap.add_argument("--workers", type=int, default=14, help=f"process workers (capped at {MAX_WORKERS})")
    ap.add_argument("--batch-size", type=int, default=10, help="null/power worlds per task")
    ap.add_argument("--affinity", choices=["auto", "none", "pin"], default="none",
                    help="auto == none here (no SMT on this VM; pinning not shown to help)")
    ap.add_argument("--benchmark", action="store_true", help="time 56 null worlds and exit")
    ap.add_argument("--profile", action="store_true", help="cProfile one null world and exit")
    ap.add_argument("--run-id", default=time.strftime("run_%Y%m%d_%H%M%S"))
    ap.add_argument("--out", default=os.path.join(_ROOT, "results", "e_padgrille_01"))
    args = ap.parse_args()
    affinity = "none" if args.affinity == "auto" else args.affinity
    if args.workers > MAX_WORKERS:
        print(f"  --workers {args.workers} capped to {MAX_WORKERS} (shared box; operator cap)", flush=True)
        args.workers = MAX_WORKERS

    if args.profile:
        pr = cProfile.Profile()
        pr.runcall(evaluate, null_world(0))
        pstats.Stats(pr).sort_stats("cumulative").print_stats(12)
        return 0
    if args.benchmark:
        t0 = time.perf_counter()
        run_pool(null_task, list(range(56)), args.workers, 2, affinity)
        dt = time.perf_counter() - t0
        print(json.dumps({**env_report(args.workers, affinity), "worlds": 56, "seconds": round(dt, 2),
                          "worlds_per_s": round(56 / dt, 2)}, indent=1))
        return 0

    print(f"E-PADGRILLE-01 mode={args.mode} universe={universe_hash()[:16]}", flush=True)
    if not selftest():
        print("SELFTEST FAILED: refusing to run", flush=True)
        return 1
    if args.mode == "selftest":
        return 0
    out = os.path.join(args.out, args.run_id)
    os.makedirs(out, exist_ok=True)
    meta = {"campaign": PREREG["campaign"], "universe": universe_hash(), "env": env_report(args.workers, affinity)}

    if args.mode == "calibrate":
        t0 = time.perf_counter()
        lo, hi = PREREG["null_seeds"]
        null = run_pool(null_task, list(range(lo, hi + 1)), args.workers, args.batch_size, affinity)
        t1 = time.perf_counter()
        p0 = PREREG["power_seed0"]
        power = run_pool(power_task, list(range(p0, p0 + PREREG["power_n"])), args.workers, args.batch_size, affinity)
        t2 = time.perf_counter()
        fams = sorted(null[0]["fam_max"])
        dist = {f: dict(sorted(Counter(r["fam_max"].get(f, 0) for r in null).items())) for f in fams}
        det = sum(r["detected"] for r in power)
        by_fam = Counter(r["cid"].split("|")[0] for r in power)
        det_fam = Counter(r["cid"].split("|")[0] for r in power if r["detected"])
        summary = {**meta, "null_worlds": len(null), "null_family_max_distribution": dist,
                   "power": det / len(power), "power_by_family": {f: f"{det_fam[f]}/{by_fam[f]}" for f in by_fam},
                   "power_unstable_plants": sum(not r["stable"] for r in power),
                   "seconds_null": round(t1 - t0, 1), "seconds_power": round(t2 - t1, 1),
                   "throughput_worlds_per_s": round(len(null) / (t1 - t0), 2)}
        with open(os.path.join(out, "calibration.json"), "w") as fh:
            json.dump({**summary, "null": null, "power_runs": power}, fh, indent=1)
        print(json.dumps(summary, indent=1), flush=True)
        return 0

    t0 = time.perf_counter()
    res = evaluate(real_world(CT), floor=8)
    world = real_world(CT)
    top = [{"score": s, "cid": c, "pt": decrypt_config(world, c)} for s, c in res["hits"][:25]]
    promoted = [h for h in top if h["score"] >= PREREG["promote_at"]]
    summary = {**meta, "seconds": round(time.perf_counter() - t0, 2), "n_configs": res["n_configs"],
               "family_max": res["fam_max"], "histogram": res["hist"], "promoted": promoted, "top": top}
    with open(os.path.join(out, "real.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    print(json.dumps({k: v for k, v in summary.items() if k != "top"}, indent=1), flush=True)
    for h in top[:10]:
        print(f"  {h['score']:2d}/24  {h['cid']}\n         {h['pt']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
