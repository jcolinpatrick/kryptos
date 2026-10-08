""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal, cast

import numpy as np

from cryptolab.tools.alphabets import keyed_alphabet
from cryptolab.tools.fitness import quadgram_score
from cryptolab.tools.transforms import apply_transform

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = keyed_alphabet("KRYPTOS")
ALPHABETS: dict[str, str] = {"AZ": AZ, "KA": KA}
CELL_NAMES: tuple[str, ...] = tuple(f"{pa}/{ca}/{sign}" for pa in ("AZ", "KA") for ca in ("AZ", "KA") for sign in "+-")
LAYER_ORDERS: tuple[str, ...] = ("substitution_first", "transposition_first")


KEYWORD_CELL_KINDS: tuple[str, ...] = ("X/AZ", "AZ/X", "X/X", "X/KA", "KA/X")


def alphabet_keyword(token: str) -> str:
    ""

    if token == "AZ":
        return ""
    if token == "KA":
        return "KRYPTOS"
    if token.startswith("K-") and len(token) > 2 and token[2:].isalpha() and token[2:].isupper() and token[2:].isascii():
        return token[2:]
    raise ValueError(f"unknown alphabet {token!r}: use AZ, KA or K-<WORD> (A-Z letters)")


@lru_cache(maxsize=65536)
def alphabet_for(token: str) -> str:
    keyword = alphabet_keyword(token)
    return keyed_alphabet(keyword) if keyword else AZ


@dataclass(frozen=True)
class Cell:
    name: str
    pa: str
    ca: str
    sign: int

    @property
    def pa_alpha(self) -> str:
        return alphabet_for(self.pa)

    @property
    def ca_alpha(self) -> str:
        return alphabet_for(self.ca)


@lru_cache(maxsize=65536)
def cell(name: str) -> Cell:
    ""

    parts = name.split("/")
    if len(parts) != 3 or parts[2] not in {"+", "-"}:
        raise ValueError(f"unknown cell {name!r}: use pa/ca/sign, e.g. {', '.join(CELL_NAMES[:2])} or K-BERLIN/AZ/+")
    pa, ca, sign = parts
    alphabet_keyword(pa), alphabet_keyword(ca)
    return Cell(name=name, pa=pa, ca=ca, sign=1 if sign == "+" else -1)


def is_cell(name: str) -> bool:
    try:
        cell(name)
    except ValueError:
        return False
    return True


def keyword_cells(keywords: Sequence[str], kinds: Sequence[str]) -> list[str]:
    ""

    out: list[str] = []
    for word in keywords:
        token = f"K-{word}"
        for kind in KEYWORD_CELL_KINDS:
            if kind in kinds:
                pa, ca = (token if part == "X" else part for part in kind.split("/"))
                out += [f"{pa}/{ca}/+", f"{pa}/{ca}/-"]
    return out


KEYWORD_SOURCES: dict[str, str] = {"english_words": "english_words.txt"}


@lru_cache(maxsize=4)
def _read_source(source: str) -> tuple[tuple[str, ...], str]:
    ""

    import hashlib
    from pathlib import Path

    raw = (Path(__file__).resolve().parents[1] / "data" / KEYWORD_SOURCES[source]).read_bytes()
    return tuple(raw.decode("utf-8").splitlines()), hashlib.sha256(raw).hexdigest()


@lru_cache(maxsize=8)
def source_keywords(source: str, min_length: int) -> tuple[str, ...]:
    ""

    words = (line.strip().upper() for line in _read_source(source)[0])
    return tuple(w for w in words if len(w) >= min_length and w.isascii() and w.isalpha())


def source_digest(source: str) -> str:
    ""

    return _read_source(source)[1]


def block_keywords(block: Any) -> list[str]:
    ""

    words = list(getattr(block, "keywords", []))
    source = getattr(block, "keyword_source", None)
    if source:
        words += source_keywords(source, int(getattr(block, "keyword_min_length", 4)))
    return words


@lru_cache(maxsize=16)
def _expand(cells: tuple[str, ...], words: tuple[str, ...], kinds: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[tuple[str, str, int]] = set()
    out: list[str] = []
    for name in [*cells, *keyword_cells(words, kinds)]:
        pa, ca, sign = name.split("/")
        key = (alphabet_for(pa), alphabet_for(ca), 1 if sign == "+" else -1)
        if key not in seen:
            cell(name)
            seen.add(key)
            out.append(name)
    return tuple(out)


def effective_cells(block: Any) -> list[str]:
    ""

    return list(_expand(tuple(block.cells), tuple(block_keywords(block)), tuple(getattr(block, "keyword_cells", []))))





def column_lengths(length: int, width: int) -> list[int]:
    return [(length - column + width - 1) // width for column in range(width)]


def position_map(length: int, width: int, order: Sequence[int]) -> list[int]:
    ""

    lengths = column_lengths(length, width)
    offsets = [0] * width
    offset = 0
    for column in order:
        offsets[column] = offset
        offset += lengths[column]
    return [offsets[index % width] + index // width for index in range(length)]





def numba_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("numba") is not None


_COMPILED: dict[Callable[..., Any], Callable[..., Any]] = {}


def compiled(kernel: Callable[..., Any]) -> Callable[..., Any]:
    ""

    if kernel not in _COMPILED:
        try:
            from numba import njit
        except ImportError as exc:
            raise RuntimeError("method crib_exact needs numba: pip install 'cryptolab[research]'") from exc
        _COMPILED[kernel] = cast(Callable[..., Any], njit(cache=True)(kernel))
    return _COMPILED[kernel]


def _bnb(
    width: int,
    col_len: np.ndarray,
    col_start: np.ndarray,
    crib_pos: np.ndarray,
    crib_row: np.ndarray,
    crib_term: np.ndarray,
    ct_ca: np.ndarray,
    period: int,
    key_by_ct: bool,
    first_col: int,
    max_out: int,
    node_cap: int,
    out: np.ndarray,
) -> tuple[int, int, bool]:
    ""

    key = np.full(period, -1, np.int64)
    used = np.zeros(width, np.bool_)
    order = np.zeros(width, np.int64)
    ptr = np.zeros(width + 1, np.int64)
    offs = np.zeros(width + 1, np.int64)
    maxu = 0
    for column in range(width):
        maxu = max(maxu, col_start[column + 1] - col_start[column])
    maxu = max(maxu, 1)
    undo = np.zeros(width * maxu, np.int64)
    undo_n = np.zeros(width, np.int64)
    count = 0
    nodes = 0
    depth = 0
    ptr[0] = first_col if first_col >= 0 else 0
    while depth >= 0:
        limit = width
        if depth == 0 and first_col >= 0:
            limit = first_col + 1
        if ptr[depth] >= limit:
            depth -= 1
            if depth >= 0:
                column = order[depth]
                used[column] = False
                for u in range(undo_n[depth]):
                    key[undo[depth * maxu + u]] = -1
                ptr[depth] += 1
            continue
        column = ptr[depth]
        if used[column]:
            ptr[depth] += 1
            continue
        nodes += 1
        if nodes > node_cap:
            return count, nodes, False
        offset = offs[depth]
        assigned = 0
        consistent = True
        for t in range(col_start[column], col_start[column + 1]):
            j = offset + crib_row[t]
            value = (ct_ca[j] - crib_term[t]) % 26
            residue = (j % period) if key_by_ct else (crib_pos[t] % period)
            if key[residue] < 0:
                key[residue] = value
                undo[depth * maxu + assigned] = residue
                assigned += 1
            elif key[residue] != value:
                consistent = False
                break
        if not consistent:
            for u in range(assigned):
                key[undo[depth * maxu + u]] = -1
            ptr[depth] += 1
            continue
        undo_n[depth] = assigned
        order[depth] = column
        used[column] = True
        offs[depth + 1] = offset + col_len[column]
        if depth + 1 == width:
            if count < max_out:
                for slot in range(width):
                    out[count, slot] = order[slot]
            count += 1
            used[column] = False
            for u in range(assigned):
                key[undo[depth * maxu + u]] = -1
            ptr[depth] += 1
            if count >= max_out:
                return count, nodes, False
        else:
            depth += 1
            ptr[depth] = 0
    return count, nodes, True


@dataclass(frozen=True)
class Task:
    cell: str
    period: int
    width: int
    layer_order: str
    first_col: int


@dataclass
class TaskResult:
    task: Task
    orders: list[tuple[int, ...]]
    nodes: int
    complete: bool
    overflow: bool


def solve_task(
    ciphertext: str,
    cribs: Mapping[int, str],
    task: Task,
    *,
    max_out: int = 2000,
    node_cap: int = 2_000_000_000,
) -> TaskResult:
    ""

    c = cell(task.cell)
    n, w = len(ciphertext), task.width
    by_column: list[list[int]] = [[] for _ in range(w)]
    for position in sorted(cribs):
        by_column[position % w].append(position)
    col_start = np.zeros(w + 1, np.int64)
    flat: list[int] = []
    for column in range(w):
        col_start[column] = len(flat)
        flat.extend(by_column[column])
    col_start[w] = len(flat)
    crib_pos = np.array(flat, np.int64)
    crib_row = np.array([position // w for position in flat], np.int64)
    pa = c.pa_alpha
    crib_term = np.array([(c.sign * pa.index(cribs[position])) % 26 for position in flat], np.int64)
    ct_ca = np.array([c.ca_alpha.index(letter) for letter in ciphertext], np.int64)
    col_len = np.array(column_lengths(n, w), np.int64)
    out = np.zeros((max_out, w), np.int64)
    count, nodes, complete = compiled(_bnb)(
        w, col_len, col_start, crib_pos, crib_row, crib_term, ct_ca, task.period,
        task.layer_order == "transposition_first", task.first_col, max_out, node_cap, out,
    )
    kept = min(count, max_out)
    orders = [tuple(int(x) for x in out[i]) for i in range(kept)]
    return TaskResult(task=task, orders=orders, nodes=int(nodes), complete=bool(complete), overflow=count >= max_out)


def brute_force_orders(ciphertext: str, cribs: Mapping[int, str], cell_name: str, period: int, width: int,
                       layer_order: str) -> list[tuple[int, ...]]:
    ""

    from itertools import permutations

    c = cell(cell_name)
    out: list[tuple[int, ...]] = []
    for order in permutations(range(width)):
        pos = position_map(len(ciphertext), width, order)
        key: dict[int, int] = {}
        ok = True
        for i, letter in cribs.items():
            j = pos[i]
            value = (c.ca_alpha.index(ciphertext[j]) - c.sign * c.pa_alpha.index(letter)) % 26
            residue = (j if layer_order == "transposition_first" else i) % period
            if key.setdefault(residue, value) != value:
                ok = False
                break
        if ok:
            out.append(tuple(order))
    return out





def derive_key(ciphertext: str, cribs: Mapping[int, str], cell_name: str, period: int, width: int,
               order: Sequence[int], layer_order: str) -> list[int | None]:
    ""

    c = cell(cell_name)
    pos = position_map(len(ciphertext), width, order)
    key: list[int | None] = [None] * period
    for i, letter in cribs.items():
        j = pos[i]
        value = (c.ca_alpha.index(ciphertext[j]) - c.sign * c.pa_alpha.index(letter)) % 26
        residue = (j if layer_order == "transposition_first" else i) % period
        if key[residue] is not None and key[residue] != value:
            raise ValueError("inconsistent order: the cribs disagree on a residue")
        key[residue] = value
    return key


def substitution_stages(cell_name: str, key: Sequence[int]) -> list[dict[str, Any]]:
    ""

    c = cell(cell_name)
    pa_keyword, ca_keyword = alphabet_keyword(c.pa), alphabet_keyword(c.ca)
    if c.sign == 1:
        shifts = [k % 26 for k in key]
        if c.pa == c.ca == "AZ":
            return [{"name": "vigenere", "params": {"key": "".join(AZ[k] for k in shifts)}}]
        return [{"name": "quagmire", "params": {
            "period_keyword": "".join(c.ca_alpha[k] for k in shifts), "indicator": c.pa_alpha[0],
            "alphabet_keyword": "KRYPTOS", "pt_alphabet_keyword": pa_keyword, "ct_alphabet_keyword": ca_keyword}}]
    if c.pa == c.ca == "AZ":
        return [{"name": "beaufort", "params": {"key": "".join(AZ[k % 26] for k in key)}}]

    atbash: dict[str, Any] = {"name": "atbash", "params": {"alphabet_keyword": pa_keyword} if pa_keyword else {}}
    return [atbash, {"name": "quagmire", "params": {
        "period_keyword": "".join(c.ca_alpha[(k - 25) % 26] for k in key), "indicator": c.pa_alpha[0],
        "alphabet_keyword": "KRYPTOS", "pt_alphabet_keyword": pa_keyword, "ct_alphabet_keyword": ca_keyword}}]


def recipe(cell_name: str, key: Sequence[int], width: int, order: Sequence[int], layer_order: str) -> list[dict[str, Any]]:
    columnar = {"name": "columnar", "params": {"width": width, "read_order": [int(x) for x in order]}}
    substitution = substitution_stages(cell_name, key)
    return [*substitution, columnar] if layer_order == "substitution_first" else [columnar, *substitution]


def run_stages(stages: Sequence[Mapping[str, Any]], text: str, mode: Literal["encode", "decode"]) -> str:
    sequence = list(stages) if mode == "encode" else list(reversed(stages))
    for stage in sequence:
        text = apply_transform(str(stage["name"]), mode, text, parameters=dict(stage["params"])).output_text
    return text


def _decode_direct(ciphertext: str, cell_name: str, key: Sequence[int], width: int, order: Sequence[int],
                   layer_order: str, pos: Sequence[int] | None = None) -> str:
    ""

    c = cell(cell_name)
    n, p = len(ciphertext), len(key)
    if pos is None:
        pos = position_map(n, width, order)
    letters = ["?"] * n
    for i in range(n):
        j = pos[i]
        residue = (j if layer_order == "transposition_first" else i) % p
        value = (c.ca_alpha.index(ciphertext[j]) - key[residue]) % 26
        letters[i] = c.pa_alpha[(c.sign * value) % 26]
    return "".join(letters)


_QUAD: np.ndarray | None = None


def _quad_table() -> np.ndarray:
    ""

    global _QUAD
    if _QUAD is None:
        from cryptolab.tools import fitness

        table = fitness._load_quadgrams()
        floor = fitness._quadgram_floor
        quad = np.full((26, 26, 26, 26), floor, dtype=np.float64)
        for gram, value in table.items():
            if len(gram) == 4 and gram.isalpha() and gram.isupper():
                a, b, c, d = (ord(ch) - 65 for ch in gram)
                quad[a, b, c, d] = value
        _QUAD = quad
    return _QUAD


def _letter_tables(ciphertext: str, cell_name: str, width: int, order: Sequence[int], layer_order: str,
                   period: int, pos: Sequence[int] | None = None) -> tuple[list[int], np.ndarray]:
    ""

    c = cell(cell_name)
    n = len(ciphertext)
    if pos is None:
        pos = position_map(n, width, order)
    residues = [(pos[i] if layer_order == "transposition_first" else i) % period for i in range(n)]
    pa_to_az = np.array([AZ.index(ch) for ch in c.pa_alpha], dtype=np.int64)
    ct = np.array([c.ca_alpha.index(ciphertext[pos[i]]) for i in range(n)], dtype=np.int64)
    values = np.arange(26, dtype=np.int64)
    letters = pa_to_az[(c.sign * (ct[:, None] - values[None, :])) % 26]
    return residues, letters


def _fill_chain(residues: list[int], letters: np.ndarray, key: list[int | None], period: int) -> list[int] | None:
    ""

    quad = _quad_table()
    known = [value is not None for value in key]
    cut = next((r for r in range(period) if all(known[(r + d) % period] for d in range(-3, 4))), None)
    if cut is None:
        return None
    seq = [(cut + 1 + j) % period for j in range(period - 1)]
    domain = [np.array([key[r]]) if key[r] is not None else np.arange(26) for r in seq]
    n = len(residues)
    windows: dict[int, list[int]] = {}
    for t in range(n - 3):
        windows.setdefault(residues[t], []).append(t)

    def factor(j: int) -> np.ndarray:
        ""

        r0 = seq[j - 3]
        dims = [domain[j - 3], domain[j - 2], domain[j - 1], domain[j]]
        out = np.zeros(tuple(len(d) for d in dims))
        for t in windows.get(r0, []):
            if any(residues[t + k] != seq[j - 3 + k] for k in range(4)):
                continue
            idx = np.ix_(*(letters[t + k][dims[k]] for k in range(4)))
            out += quad[idx]
        return out


    state = np.zeros((len(domain[0]), len(domain[1]), len(domain[2])))
    back: list[np.ndarray] = []
    for j in range(3, len(seq)):
        total = state[:, :, :, None] + factor(j)
        back.append(np.argmax(total, axis=0))
        state = np.max(total, axis=0)
    flat = np.unravel_index(int(np.argmax(state)), state.shape)
    choice = [0] * len(seq)
    choice[-3], choice[-2], choice[-1] = (int(x) for x in flat)
    for j in range(len(seq) - 1, 2, -1):
        choice[j - 3] = int(back[j - 3][choice[j - 2], choice[j - 1], choice[j]])
    full = [int(v) if v is not None else 0 for v in key]
    for j, r in enumerate(seq):
        full[r] = int(domain[j][choice[j]])
    return full


def _fill_tensor(residues: list[int], letters: np.ndarray, key: list[int | None], unknown: list[int]) -> list[int]:
    ""

    quad = _quad_table()
    u = len(unknown)
    slot = {r: k for k, r in enumerate(unknown)}
    grid = np.indices((26,) * u)
    total = np.zeros((26,) * u)
    for t in range(len(residues) - 3):
        indices = []
        for k in range(4):
            r = residues[t + k]
            if r in slot:
                indices.append(letters[t + k][grid[slot[r]]])
            else:
                known = key[r]
                assert known is not None
                indices.append(np.full((26,) * u, letters[t + k][known], dtype=np.int64))
        total = total + quad[indices[0], indices[1], indices[2], indices[3]]
    best = np.unravel_index(int(np.argmax(total)), total.shape)
    full = [int(v) if v is not None else 0 for v in key]
    for r, value in zip(unknown, best, strict=True):
        full[r] = int(value)
    return full


def fill_key(ciphertext: str, partial: Sequence[int | None], cell_name: str, width: int, order: Sequence[int],
             layer_order: str, passes: int = 2, pos: Sequence[int] | None = None) -> tuple[list[int], list[int], str]:
    ""

    filled = [r for r, value in enumerate(partial) if value is None]
    if not filled:
        return [int(v) for v in partial if v is not None], filled, "none"
    period = len(partial)
    residues, letters = _letter_tables(ciphertext, cell_name, width, order, layer_order, period, pos)
    if layer_order == "substitution_first":
        chained = _fill_chain(residues, letters, list(partial), period)
        if chained is not None:
            return chained, filled, "exact_chain"
    if len(filled) <= 4:
        return _fill_tensor(residues, letters, list(partial), filled), filled, "exact_tensor"
    best_key: list[int] = []
    best_score = -math.inf
    for restart in range(4):
        rng = random.Random(restart)
        key = [int(v) if v is not None else (0 if restart == 0 else rng.randrange(26)) for v in partial]
        for _ in range(max(passes, 3)):
            for residue in filled:
                top, top_score = key[residue], -math.inf
                for value in range(26):
                    key[residue] = value
                    trial = quadgram_score(_decode_direct(ciphertext, cell_name, key, width, order, layer_order, pos))
                    if trial > top_score:
                        top, top_score = value, trial
                key[residue] = top
        score_now = quadgram_score(_decode_direct(ciphertext, cell_name, key, width, order, layer_order, pos))
        if score_now > best_score:
            best_key, best_score = list(key), score_now
    return best_key, filled, "heuristic"





def task_list(cells: Sequence[str], periods: Sequence[int], widths: Sequence[int], layer_order: str) -> list[Task]:
    ""

    return [Task(cell=c, period=p, width=w, layer_order=layer_order, first_col=first)
            for w in widths for p in periods for c in cells for first in range(w)]


def sample_plant(plaintext: str, cribs_at: Sequence[int], *, cells: Sequence[str], periods: Sequence[int],
                 widths: Sequence[int], layer_order: str, rng: random.Random) -> dict[str, Any]:
    ""

    cell_name = rng.choice(list(cells))
    period = rng.choice(list(periods))
    width = rng.choice(list(widths))
    order = list(range(width))
    rng.shuffle(order)
    key = [rng.randrange(26) for _ in range(period)]
    stages = recipe(cell_name, key, width, order, layer_order)
    ciphertext = run_stages(stages, plaintext, "encode")
    return {
        "ciphertext": ciphertext,
        "cribs": {int(i): plaintext[i] for i in cribs_at if i < len(plaintext)},
        "truth": {"cell": cell_name, "period": period, "width": width, "order": order, "key": key},
        "encode_stages": stages,
    }


ProgressFn = Callable[[int, int], None]
RunStatus = Literal["completed", "timeout", "cancelled"]
_POLL_SECONDS = 0.2


def run_bounded(function: Callable[..., Any], pieces: Sequence[tuple[Any, ...]], *, workers: int,
                deadline: float, cancel_check: Callable[[], bool] | None,
                on_done: Callable[[int], None] | None = None) -> tuple[list[Any], RunStatus, str]:
    ""

    import multiprocessing
    import os
    import time

    done: dict[int, Any] = {}
    status: RunStatus = "completed"
    reason = ""

    def stop() -> bool:
        nonlocal status, reason
        if cancel_check is not None and cancel_check():
            status, reason = "cancelled", "cancel requested"
        elif time.monotonic() > deadline:
            status, reason = "timeout", "wall_time_seconds reached (workers terminated)"
        return status != "completed"

    if not pieces:
        return [], status, reason
    if os.environ.get("CRYPTOLAB_IN_SOLVER_WORKER") == "1":
        for index, piece in enumerate(pieces):
            if stop():
                break
            done[index] = function(*piece)
            if on_done is not None:
                on_done(index)
        return [done[i] for i in sorted(done)], status, reason
    pool = multiprocessing.get_context("forkserver").Pool(processes=max(1, workers))
    try:
        pending = {index: pool.apply_async(function, piece) for index, piece in enumerate(pieces)}
        while pending and not stop():
            pending[min(pending)].wait(min(_POLL_SECONDS, max(0.0, deadline - time.monotonic())))
            for index in [i for i, result in pending.items() if result.ready()]:
                done[index] = pending.pop(index).get()
                if on_done is not None:
                    on_done(index)
    finally:
        if status == "completed":
            pool.close()
        else:
            pool.terminate()
        pool.join()
    return [done[i] for i in sorted(done)], status, reason





def _solve_chunk(ciphertext: str, cribs: list[tuple[int, str]], tasks: list[tuple[str, int, int, str, int]],
                 max_out: int, node_cap: int) -> list[dict[str, Any]]:
    ""

    crib_map = dict(cribs)
    out: list[dict[str, Any]] = []
    for name, period, width, layer_order, first in tasks:
        result = solve_task(ciphertext, crib_map, Task(name, period, width, layer_order, first),
                            max_out=max_out, node_cap=node_cap)
        out.append({"task": [name, period, width, layer_order, first], "orders": [list(o) for o in result.orders],
                    "nodes": result.nodes, "complete": result.complete, "overflow": result.overflow})
    return out


def materialize(ciphertext: str, cribs: Mapping[int, str], task: Task, order: Sequence[int], fill_passes: int,
                spec: Any, index: int) -> Any:
    ""

    from cryptolab.research_bridge.search import (
        CandidateRecipe,
        crib_check,
        decode_text,
        objective_key,
    )
    from cryptolab.tools.classical import index_of_coincidence

    partial = derive_key(ciphertext, cribs, task.cell, task.period, task.width, order, task.layer_order)
    key, filled, fill_method = fill_key(ciphertext, partial, task.cell, task.width, order, task.layer_order, passes=fill_passes)
    encode = recipe(task.cell, key, task.width, order, task.layer_order)
    decode = [{"name": stage["name"], "params": dict(stage["params"])} for stage in reversed(encode)]
    plaintext = decode_text(decode, ciphertext)
    matched, total = crib_check(plaintext, cribs)
    assignment = (task.cell, task.period, task.width, task.layer_order, "-".join(str(c) for c in order),
                  ",".join(str(k) for k in key), (",".join(str(r) for r in filled) or "none") + f" [{fill_method}]")
    return CandidateRecipe(
        index=index, assignment=assignment, plaintext=plaintext, encode_stages=encode, decode_stages=decode,
        objective=objective_key(plaintext, spec.scoring.objective, positional_cribs=cribs, languages=spec.scoring.languages),
        quadgram=quadgram_score(plaintext.upper()), ioc=index_of_coincidence(plaintext),
        crib_matched=matched, crib_total=total,
    )


def _materialize_chunk(spec_json: str, ciphertext: str, cribs: list[tuple[int, str]],
                       items: list[tuple[int, tuple[str, int, int, str, int], list[int]]]) -> list[Any]:
    ""

    from cryptolab.research_bridge.spec import ExperimentSpec

    spec = ExperimentSpec.model_validate_json(spec_json)
    block = spec.search.crib_exact
    passes = block.fill_passes if block is not None else 2
    crib_map = dict(cribs)
    return [materialize(ciphertext, crib_map, Task(*task), order, passes, spec, index) for index, task, order in items]


def run_crib_exact(spec: Any, ciphertext: str, *, positional_cribs: Mapping[int, str], truth_plaintext: str | None,
                   deadline: float | None, cancel_check: Callable[[], bool] | None,
                   progress: Callable[[int, int], None] | None) -> Any:
    ""

    import json as _json
    import time

    from cryptolab.research_bridge.search import SearchOutcome, SearchStatus

    block = spec.search.crib_exact
    if block.family == "autokey_permutation":
        from cryptolab.research_bridge.cribsolve_autokey import run_crib_exact_autokey

        return run_crib_exact_autokey(spec, ciphertext, positional_cribs=positional_cribs, truth_plaintext=truth_plaintext,
                                      deadline=deadline, cancel_check=cancel_check, progress=progress)
    if block.family == "periodic_permutation":
        from cryptolab.research_bridge.cribsolve_perm import run_crib_exact_perm

        return run_crib_exact_perm(spec, ciphertext, positional_cribs=positional_cribs, truth_plaintext=truth_plaintext,
                                   deadline=deadline, cancel_check=cancel_check, progress=progress)
    if block.family == "running_key_columnar":
        from cryptolab.research_bridge.cribsolve_rk import run_crib_exact_rk

        return run_crib_exact_rk(spec, ciphertext, positional_cribs=positional_cribs, truth_plaintext=truth_plaintext,
                                 deadline=deadline, cancel_check=cancel_check, progress=progress)
    started = time.monotonic()
    if deadline is None:
        deadline = started + spec.limits.wall_time_seconds
    cribs = {int(k): str(v).upper() for k, v in positional_cribs.items()}
    tasks = task_list(effective_cells(block), block.periods, block.widths, block.layer_order)
    total = len(tasks)
    raw: list[dict[str, Any]] = []
    status: SearchStatus = "completed"
    stop_reason = ""
    if not cribs:
        status, stop_reason = "completed", "no positional cribs: the method needs cribs and evaluated nothing"
        tasks = []
    task_tuples = [(t.cell, t.period, t.width, t.layer_order, t.first_col) for t in tasks]
    workers = max(1, min(spec.limits.workers, len(task_tuples) or 1))
    chunk = max(1, math.ceil(len(task_tuples) / (workers * 16))) if task_tuples else 1
    chunks = [task_tuples[i:i + chunk] for i in range(0, len(task_tuples), chunk)]
    crib_items = sorted(cribs.items())
    done = 0

    def tick(index: int) -> None:
        nonlocal done
        done += len(chunks[index])
        if progress is not None:
            progress(done, total)

    pieces = [(ciphertext, crib_items, piece, block.max_survivors_per_task, block.node_cap_per_task) for piece in chunks]
    results, run_status, run_reason = run_bounded(_solve_chunk, pieces, workers=workers, deadline=deadline,
                                                  cancel_check=cancel_check, on_done=tick)
    for result in results:
        raw.extend(result)
    if run_status != "completed":
        status, stop_reason = run_status, run_reason

    nodes = sum(int(r["nodes"]) for r in raw)
    incomplete = [r["task"] for r in raw if not r["complete"]]
    by_cell_period_width: dict[str, dict[str, int]] = {}
    survivors: list[tuple[Task, tuple[int, ...]]] = []
    for r in raw:
        name, period, width, layer_order, first = r["task"]
        key = f"{name}|p{period}|w{width}"
        entry = by_cell_period_width.setdefault(key, {"survivors": 0, "nodes": 0, "incomplete_tasks": 0})
        entry["survivors"] += len(r["orders"])
        entry["nodes"] += int(r["nodes"])
        entry["incomplete_tasks"] += int(not r["complete"])
        survivors.extend((Task(name, period, width, layer_order, first), tuple(o)) for o in r["orders"])
    if status == "completed" and len(raw) < total:
        status, stop_reason = "truncated", f"{total - len(raw)} tasks not run"
    if status == "completed" and incomplete:
        status, stop_reason = "truncated", f"{len(incomplete)} tasks hit the node or survivor cap"
    cap = spec.limits.max_pipelines
    materialized = survivors[:cap]
    if status == "completed" and len(survivors) > cap:
        status, stop_reason = "truncated", f"{len(survivors)} survivors, max_pipelines {cap} materialized"
    items = [(i, (t.cell, t.period, t.width, t.layer_order, t.first_col), list(order))
             for i, (t, order) in enumerate(materialized)]
    candidates: list[Any] = []
    spec_json = _json.dumps(spec.model_dump(mode="json"))
    size = max(8, math.ceil(len(items) / (workers * 8))) if items else 1
    item_pieces = [(spec_json, ciphertext, crib_items, items[i:i + size]) for i in range(0, len(items), size)]
    made, made_status, made_reason = run_bounded(_materialize_chunk, item_pieces, workers=workers if len(items) >= 64 else 1,
                                                 deadline=deadline, cancel_check=cancel_check)
    for chunk_candidates in made:
        candidates.extend(chunk_candidates)
    if made_status != "completed" and status in ("completed", "truncated"):
        status, stop_reason = made_status, f"{made_reason} during candidate materialization ({len(candidates)} of {len(items)} survivors materialized)"
    candidates.sort(key=lambda c: (tuple(c.objective), -c.index), reverse=True)
    top = candidates[: spec.search.top_k]
    truth_generated = truth_rank = None
    if truth_plaintext is not None:
        ranks = [i for i, c in enumerate(candidates, start=1) if c.plaintext == truth_plaintext]
        truth_generated = bool(ranks)
        truth_rank = ranks[0] if ranks else None
    details = {
        "method": "crib_exact",
        "family": block.family,
        "layer_order": block.layer_order,
        "tasks_total": total,
        "tasks_run": len(raw),
        "tasks_incomplete": incomplete[:50],
        "nodes": nodes,
        "survivors_total": len(survivors),
        "survivors_materialized": len(materialized),
        "by_cell_period_width": by_cell_period_width,
        "crib_letters": len(cribs),
    }
    outcome = SearchOutcome(
        status=status, evaluated=nodes, pruned=max(0, nodes - len(survivors)), decode_failures=0,
        space_size=total, cap=cap, top=top, wall_seconds=time.monotonic() - started, partitions=len(chunks),
        objective=spec.scoring.objective, truth_generated=truth_generated,
        truth_survived_prune=truth_generated, truth_rank=truth_rank,
        truth_objective=None, progress_events=done, stop_reason=stop_reason,
    )
    outcome.details = _json.loads(_json.dumps(details))
    return outcome


def fitted_residue_equivalent(found: Sequence[Any], truth: Sequence[Any], found_plaintext: str, truth_plaintext: str) -> bool:
    ""

    if len(found) < 7 or len(truth) < 6 or list(found[:5]) != list(truth[:5]):
        return False
    if len(found_plaintext) != len(truth_plaintext):
        return False
    filled_text = str(found[6]).split(" [")[0]
    filled = set() if filled_text == "none" else {int(x) for x in filled_text.split(",") if x}
    found_key = [int(x) for x in str(found[5]).split(",")]
    truth_key = [int(x) for x in str(truth[5]).split(",")]
    if len(found_key) != len(truth_key) or any(found_key[r] != truth_key[r] for r in range(len(truth_key)) if r not in filled):
        return False
    period, layer = int(truth[1]), str(truth[3])
    if truth[2] == "perm":
        from cryptolab.research_bridge.cribsolve_perm import position_for_label

        pos = position_for_label(str(truth[4]), len(truth_plaintext))
    else:
        pos = position_map(len(truth_plaintext), int(truth[2]), [int(x) for x in str(truth[4]).split("-")])
    for i, (a, b) in enumerate(zip(found_plaintext, truth_plaintext, strict=True)):
        residue = (pos[i] if layer == "transposition_first" else i) % period
        if a != b and residue not in filled:
            return False
    return True
