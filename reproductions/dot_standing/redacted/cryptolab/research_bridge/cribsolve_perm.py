""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from functools import lru_cache
from typing import Any

import numpy as np

from cryptolab.research_bridge.cribsolve import (
    cell,
    compiled,
    effective_cells,
    fill_key,
    run_bounded,
    run_stages,
    source_digest,
    substitution_stages,
)
from cryptolab.tools.transposition import _columnar_position_map, _rail_order, _route_order



CELL_BLOCK = 2048

PERMUTATION_SETS: tuple[str, ...] = (
    "reversal", "rotate_single", "rotate_double", "spiral", "diagonal", "boustrophedon", "rail_fence", "skip",
    "columnar_keyless",
    "identity",
)





def _gather_pos(order: Sequence[int]) -> np.ndarray:
    ""

    pos = np.empty(len(order), dtype=np.int64)
    pos[np.asarray(order, dtype=np.int64)] = np.arange(len(order), dtype=np.int64)
    return pos


def _stage_pos(stage: Mapping[str, Any], n: int) -> np.ndarray:
    name, params = stage["name"], stage["params"]
    if name == "block_reversal":
        if params["block"] != n:
            raise ValueError("only whole-text reversal is part of this family")
        return np.arange(n - 1, -1, -1, dtype=np.int64)
    if name == "rail_fence":
        return _gather_pos(_rail_order(n, int(params["rails"])))
    if name == "columnar":
        return np.asarray(_columnar_position_map(n, int(params["width"]), tuple(params["read_order"])), dtype=np.int64)
    if name == "route":
        kwargs = {k: v for k, v in params.items() if k != "route_type"}
        return _gather_pos(_route_order(n, route_type=str(params["route_type"]), width=kwargs.get("width"),
                                        start=int(kwargs.get("start", 0)), step=int(kwargs.get("step", 1))))
    raise ValueError(f"stage {name!r} is not a transposition of this family")


def stages_pos(stages: Sequence[Mapping[str, Any]], n: int) -> np.ndarray:
    ""

    pos = np.arange(n, dtype=np.int64)
    for stage in stages:
        pos = _stage_pos(stage, n)[pos]
    return pos


def _rot(width: int, ccw: bool, n: int) -> list[dict[str, Any]]:
    stages: list[dict[str, Any]] = [{"name": "route", "params": {"route_type": "rotate", "width": width}}]
    if ccw:
        stages.append({"name": "block_reversal", "params": {"block": n}})
    return stages


def _turn(text: str) -> tuple[int, bool]:
    ""

    match = re.fullmatch(r"(cw|ccw)(\d+)", text)
    if match is None:
        raise ValueError(f"bad rotation {text!r}")
    return int(match.group(2)), match.group(1) == "ccw"


def stages_for_label(label: str, n: int) -> list[dict[str, Any]]:
    ""

    kind, _, body = label.partition(":")
    reverse = body.endswith(",rev")
    if reverse:
        body = body[: -len(",rev")]
    rev = [{"name": "block_reversal", "params": {"block": n}}] if reverse else []
    if kind == "id":
        return []
    if kind == "rev":
        return [{"name": "block_reversal", "params": {"block": n}}]
    if kind == "rot":
        return _rot(*_turn(body), n)
    if kind == "rot2":
        first, second = body.split("+")
        return [*_rot(*_turn(first), n), *_rot(*_turn(second), n)]
    if kind in {"spiral", "diagonal", "diagonal_alt"}:
        width, start = body[1:].split("s")
        return [{"name": "route", "params": {"route_type": kind, "width": int(width), "start": int(start)}}, *rev]
    if kind in {"boustrophedon_rows", "boustrophedon_cols"}:
        return [{"name": "route", "params": {"route_type": kind, "width": int(body[1:])}}, *rev]
    if kind == "rail":
        return [{"name": "rail_fence", "params": {"rails": int(body)}}, *rev]
    if kind == "col":
        width, order = body[1:].split("o")
        columns = list(range(int(width)))
        read_order = columns if order == "id" else columns[::-1]
        return [{"name": "columnar", "params": {"width": int(width), "read_order": read_order}}, *rev]
    if kind == "skip":
        step, start = body[1:].split("o")
        return [{"name": "route", "params": {"route_type": "skip", "start": int(start), "step": int(step)}}]
    raise ValueError(f"unknown permutation label {label!r}")


def _labels(sets: Sequence[str], widths: Sequence[int], n: int) -> list[tuple[str, str]]:
    ""

    out: list[tuple[str, str]] = []
    ws = sorted(set(int(w) for w in widths))
    for name in PERMUTATION_SETS:
        if name not in sets:
            continue
        labels: list[str] = []
        if name == "reversal":
            labels = ["rev:"]
        elif name == "rotate_single":
            labels = [f"rot:{d}{a}" for a in ws for d in ("cw", "ccw")]
        elif name == "rotate_double":
            labels = [f"rot2:{x}{a}+{y}{b}" for a in ws for b in ws for x in ("cw", "ccw") for y in ("cw", "ccw")]
        elif name == "spiral":
            labels = [f"spiral:w{w}s{s}{r}" for w in ws for s in range(4) for r in ("", ",rev")]
        elif name == "diagonal":
            labels = [f"{k}:w{w}s{s}{r}" for k in ("diagonal", "diagonal_alt") for w in ws for s in range(2) for r in ("", ",rev")]
        elif name == "boustrophedon":
            labels = [f"{k}:w{w}{r}" for k in ("boustrophedon_rows", "boustrophedon_cols") for w in ws for r in ("", ",rev")]
        elif name == "rail_fence":
            labels = [f"rail:{w}{r}" for w in ws for r in ("", ",rev")]
        elif name == "skip":
            labels = [f"skip:s{w}o{o}" for w in ws if math.gcd(w, n) == 1 for o in range(n)]
        elif name == "identity":
            labels = ["id:"]
        elif name == "columnar_keyless":
            labels = [f"col:w{w}o{o}{r}" for w in ws for o in ("id", "desc") for r in ("", ",rev")]
        out += [(name, label) for label in labels]
    return out


@lru_cache(maxsize=8)
def _build(sets: tuple[str, ...], widths: tuple[int, ...], n: int) -> tuple[tuple[str, ...], np.ndarray, int, tuple[str, ...]]:
    labels: list[str] = []
    origin: list[str] = []
    rows: list[np.ndarray] = []
    seen: set[bytes] = set()
    aliases = 0
    identity = np.arange(n, dtype=np.int64).tobytes()
    for set_name, label in _labels(sets, widths, n):
        pos = stages_pos(stages_for_label(label, n), n)
        key = pos.tobytes()
        if key in seen:
            aliases += 1
            continue
        seen.add(key)
        labels.append("id:" if key == identity else label)
        origin.append(set_name)
        rows.append(pos)
    matrix = np.stack(rows) if rows else np.zeros((0, n), dtype=np.int64)
    return tuple(labels), matrix, aliases, tuple(origin)


def family(sets: tuple[str, ...], widths: tuple[int, ...], n: int) -> tuple[tuple[str, ...], np.ndarray, int]:
    ""

    labels, matrix, aliases, _origin = _build(sets, widths, n)
    return labels, matrix, aliases


def family_sets(sets: tuple[str, ...], widths: tuple[int, ...], n: int) -> tuple[str, ...]:
    ""

    return _build(sets, widths, n)[3]


def crib_classes(matrix: np.ndarray, crib_positions: Sequence[int]) -> np.ndarray:
    ""

    if matrix.shape[0] == 0:
        return np.zeros(0, dtype=np.int64)
    signature = np.ascontiguousarray(matrix[:, list(crib_positions)])
    _unique, first, inverse = np.unique(signature, axis=0, return_index=True, return_inverse=True)
    return first[inverse.reshape(-1)].astype(np.int64)


def crib_class_recovered(found: Sequence[Any], survivors: Sequence[Sequence[Any]], truth: Sequence[Any], n: int,
                         crib_positions: Sequence[int]) -> bool:
    ""

    cell_name, period, label = str(truth[0]), int(truth[1]), str(truth[4])
    truth_pos = position_for_label(label, n)
    listed = any(str(row[1]) == cell_name and int(row[2]) == period and position_for_label(str(row[0]), n) == truth_pos
                 for row in survivors)
    if not listed or len(found) < 5 or int(found[1]) % period != 0:
        return False
    return crib_class_equivalent(found, truth, n, crib_positions)


def crib_class_equivalent(found: Sequence[Any], truth: Sequence[Any], n: int, crib_positions: Sequence[int]) -> bool:
    ""

    if len(found) < 5 or len(truth) < 5 or found[2] != "perm" or truth[2] != "perm":
        return False
    if found[0] != truth[0] or found[3] != truth[3]:
        return False
    a, b = position_for_label(str(found[4]), n), position_for_label(str(truth[4]), n)
    return all(a[i] == b[i] for i in crib_positions)


def position_for_label(label: str, n: int) -> list[int]:
    return [int(x) for x in stages_pos(stages_for_label(label, n), n)]


def recipe_perm(cell_name: str, key: Sequence[int], label: str, n: int, layer_order: str) -> list[dict[str, Any]]:
    transposition = stages_for_label(label, n)
    substitution = substitution_stages(cell_name, key)
    return [*substitution, *transposition] if layer_order == "substitution_first" else [*transposition, *substitution]





def _perm_kernel(pos_all: np.ndarray, crib_pos: np.ndarray, crib_term: np.ndarray, ct_ca: np.ndarray,
                 transposition_first: bool, periods: np.ndarray, out: np.ndarray) -> int:
    ""

    hits = 0
    seen = np.empty(128, np.int64)
    m = crib_pos.shape[0]
    for q in range(pos_all.shape[0]):
        for c in range(ct_ca.shape[0]):
            for k in range(periods.shape[0]):
                p = periods[k]
                for r in range(p):
                    seen[r] = -1
                ok = 1
                for x in range(m):
                    i = crib_pos[x]
                    j = pos_all[q, i]
                    value = (ct_ca[c, j] - crib_term[c, x]) % 26
                    t = j if transposition_first else i
                    r = t % p
                    if seen[r] == -1:
                        seen[r] = value
                    elif seen[r] != value:
                        ok = 0
                        break
                out[q, c, k] = ok
                hits += ok
    return hits


def solve_block(ciphertext: str, cribs: Mapping[int, str], cells: Sequence[str], periods: Sequence[int],
                pos_block: np.ndarray, layer_order: str) -> list[tuple[int, str, int]]:
    ""

    items = sorted(cribs.items())
    crib_pos = np.array([i for i, _ in items], np.int64)
    crib_term = np.array([[(cell(name).sign * cell(name).pa_alpha.index(letter)) % 26 for _, letter in items]
                          for name in cells], np.int64)
    ct_ca = np.array([[cell(name).ca_alpha.index(ch) for ch in ciphertext] for name in cells], np.int64)
    period_array = np.array(list(periods), np.int64)
    out = np.zeros((pos_block.shape[0], len(cells), len(period_array)), np.uint8)
    compiled(_perm_kernel)(np.ascontiguousarray(pos_block, dtype=np.int64), crib_pos, crib_term, ct_ca,
                           layer_order == "transposition_first", period_array, out)
    return [(int(q), cells[int(c)], int(period_array[k])) for q, c, k in zip(*np.nonzero(out), strict=True)]


def brute_force(ciphertext: str, cribs: Mapping[int, str], cell_name: str, period: int, pos: Sequence[int],
                layer_order: str) -> bool:
    ""

    c = cell(cell_name)
    key: dict[int, int] = {}
    for i, letter in cribs.items():
        j = pos[i]
        value = (c.ca_alpha.index(ciphertext[j]) - c.sign * c.pa_alpha.index(letter)) % 26
        residue = (j if layer_order == "transposition_first" else i) % period
        if key.setdefault(residue, value) != value:
            return False
    return True





def plant_perm(plaintext: str, cribs_at: Sequence[int], *, sets: Sequence[str], widths: Sequence[int],
               cells: Sequence[str], periods: Sequence[int], layer_order: str, rng: Any,
               plant_index: int | None = None) -> dict[str, Any]:
    ""

    n = len(plaintext)
    key_sets, key_widths = tuple(sorted(sets)), tuple(sorted(widths))
    labels, _matrix, _aliases = family(key_sets, key_widths, n)
    if plant_index is None:
        label = rng.choice(list(labels))
    else:
        origin = family_sets(key_sets, key_widths, n)
        strata = [name for name in PERMUTATION_SETS if name in origin]
        stratum = strata[plant_index % len(strata)]
        label = rng.choice([lab for lab, org in zip(labels, origin, strict=True) if org == stratum])
    cell_name, period = rng.choice(list(cells)), rng.choice(list(periods))
    key = [rng.randrange(26) for _ in range(period)]
    stages = recipe_perm(cell_name, key, label, n, layer_order)
    return {"ciphertext": run_stages(stages, plaintext, "encode"),
            "cribs": {int(i): plaintext[i] for i in cribs_at if i < n},
            "truth": {"cell": cell_name, "period": period, "label": label, "key": key},
            "encode_stages": stages}


def derive_key_pos(ciphertext: str, cribs: Mapping[int, str], cell_name: str, period: int, pos: Sequence[int],
                   layer_order: str) -> list[int | None]:
    c = cell(cell_name)
    key: list[int | None] = [None] * period
    for i, letter in cribs.items():
        j = pos[i]
        value = (c.ca_alpha.index(ciphertext[j]) - c.sign * c.pa_alpha.index(letter)) % 26
        residue = (j if layer_order == "transposition_first" else i) % period
        if key[residue] is not None and key[residue] != value:
            raise ValueError("inconsistent permutation: the cribs disagree on a residue")
        key[residue] = value
    return key


def materialize_perm(spec_json: str, ciphertext: str, cribs: list[tuple[int, str]],
                     items: list[tuple[int, str, str, int]]) -> list[Any]:
    ""

    from cryptolab.research_bridge.search import (
        CandidateRecipe,
        crib_check,
        decode_text,
        objective_key,
    )
    from cryptolab.research_bridge.spec import ExperimentSpec
    from cryptolab.tools.classical import index_of_coincidence
    from cryptolab.tools.fitness import quadgram_score

    spec = ExperimentSpec.model_validate_json(spec_json)
    block = spec.search.crib_exact
    assert block is not None
    crib_map = dict(cribs)
    n = len(ciphertext)
    out: list[Any] = []
    for index, label, cell_name, period in items:
        pos = position_for_label(label, n)
        partial = derive_key_pos(ciphertext, crib_map, cell_name, period, pos, block.layer_order)
        key, filled, method = fill_key(ciphertext, partial, cell_name, 0, [], block.layer_order,
                                       passes=block.fill_passes, pos=pos)
        encode = recipe_perm(cell_name, key, label, n, block.layer_order)
        decode = [{"name": stage["name"], "params": dict(stage["params"])} for stage in reversed(encode)]
        plaintext = decode_text(decode, ciphertext)
        matched, total = crib_check(plaintext, crib_map)
        assignment = (cell_name, period, "perm", block.layer_order, label, ",".join(str(k) for k in key),
                      (",".join(str(r) for r in filled) or "none") + f" [{method}]")
        out.append(CandidateRecipe(
            index=index, assignment=assignment, plaintext=plaintext, encode_stages=encode, decode_stages=decode,
            objective=objective_key(plaintext, spec.scoring.objective, positional_cribs=crib_map,
                                    languages=spec.scoring.languages),
            quadgram=quadgram_score(plaintext.upper()), ioc=index_of_coincidence(plaintext),
            crib_matched=matched, crib_total=total))
    return out


def _perm_chunk(ciphertext: str, cribs: list[tuple[int, str]], cells: list[str], periods: list[int],
                pos_block: np.ndarray, offset: int, layer_order: str) -> list[tuple[int, str, int]]:
    ""

    return [(offset + q, c, p) for q, c, p in solve_block(ciphertext, dict(cribs), cells, periods, pos_block, layer_order)]


def run_crib_exact_perm(spec: Any, ciphertext: str, *, positional_cribs: Mapping[int, str], truth_plaintext: str | None,
                        deadline: float | None, cancel_check: Callable[[], bool] | None,
                        progress: Callable[[int, int], None] | None) -> Any:
    ""

    import json as _json

    from cryptolab.research_bridge.search import SearchOutcome, SearchStatus

    block = spec.search.crib_exact
    started = time.monotonic()
    if deadline is None:
        deadline = started + spec.limits.wall_time_seconds
    n = len(ciphertext)
    cribs = {int(k): str(v).upper() for k, v in positional_cribs.items()}
    labels, matrix, aliases = family(tuple(sorted(block.permutation_sets)), tuple(sorted(block.widths)), n)
    total = len(labels) if cribs else 0
    cells = effective_cells(block)
    cell_blocks = math.ceil(len(cells) / CELL_BLOCK) if cells else 1


    workers = max(1, min(spec.limits.workers, max(total // 2000, cell_blocks if cell_blocks > 1 else 1)))
    size = max(1, math.ceil(total / (workers * 8))) if total else 1
    crib_items = sorted(cribs.items())

    cell_size = min(len(cells), CELL_BLOCK) or 1
    pieces = [(ciphertext, crib_items, cells[j:j + cell_size], list(block.periods), matrix[i:i + size], i,
               block.layer_order) for i in range(0, total, size) for j in range(0, len(cells), cell_size)]
    done = 0
    pairs_done = 0

    def tick(index: int) -> None:
        nonlocal done, pairs_done
        pairs_done += len(pieces[index][4]) * len(pieces[index][2])
        done = pairs_done // max(1, len(cells))
        if progress is not None:
            progress(done, total)

    status: SearchStatus = "completed"
    stop_reason = "" if cribs else "no positional cribs: the method needs cribs and evaluated nothing"
    results, run_status, run_reason = run_bounded(_perm_chunk, pieces, workers=workers, deadline=deadline,
                                                  cancel_check=cancel_check, on_done=tick)
    if run_status != "completed":
        status, stop_reason = run_status, run_reason
    survivors = sorted(hit for chunk in results for hit in chunk)
    by_set: dict[str, int] = {}
    for q, cell_name, period in survivors:
        key = f"{labels[q].split(':')[0]}|{cell_name}|p{period}"
        by_set[key] = by_set.get(key, 0) + 1
    if status == "completed" and pairs_done < total * len(cells):
        status, stop_reason = "truncated", f"{total * len(cells) - pairs_done} permutation x cell pairs not run"
    cap = spec.limits.max_pipelines
    kept = survivors[:cap]
    if status == "completed" and len(survivors) > cap:
        status, stop_reason = "truncated", f"{len(survivors)} survivors, max_pipelines {cap} materialized"
    items = [(index, labels[q], cell_name, period) for index, (q, cell_name, period) in enumerate(kept)]
    spec_json = _json.dumps(spec.model_dump(mode="json"))
    item_size = max(8, math.ceil(len(items) / (workers * 8))) if items else 1
    item_pieces = [(spec_json, ciphertext, crib_items, items[i:i + item_size]) for i in range(0, len(items), item_size)]
    made, made_status, made_reason = run_bounded(materialize_perm, item_pieces, workers=workers if len(items) >= 64 else 1,
                                                 deadline=deadline, cancel_check=cancel_check)
    candidates: list[Any] = [c for chunk in made for c in chunk]
    if made_status != "completed" and status in ("completed", "truncated"):
        status, stop_reason = made_status, (f"{made_reason} during candidate materialization "
                                            f"({len(candidates)} of {len(items)} survivors materialized)")
    candidates.sort(key=lambda c: (tuple(c.objective), -c.index), reverse=True)
    top = candidates[: spec.search.top_k]
    truth_generated = truth_rank = None
    if truth_plaintext is not None:
        ranks = [i for i, c in enumerate(candidates, start=1) if c.plaintext == truth_plaintext]
        truth_generated, truth_rank = bool(ranks), (ranks[0] if ranks else None)
    by_period: dict[str, int] = {}
    for _q, _cell, period in survivors:
        by_period[str(period)] = by_period.get(str(period), 0) + 1
    classes = crib_classes(matrix, sorted(cribs)) if cribs else np.zeros(0, dtype=np.int64)
    class_size = np.bincount(classes, minlength=len(labels)) if len(classes) else np.zeros(0, dtype=np.int64)
    grouped: dict[int, list[list[Any]]] = {}
    for q, cell_name, period in survivors:
        grouped.setdefault(int(classes[q]), []).append([labels[q], cell_name, period])
    survivor_classes = [{"class": labels[rep], "family_members": int(class_size[rep]),
                         "survivors": len(members), "examples": members[:20]}
                        for rep, members in sorted(grouped.items(), key=lambda item: -len(item[1]))]
    details = {"method": "crib_exact", "family": "periodic_permutation", "layer_order": block.layer_order,
               "permutation_sets": sorted(block.permutation_sets), "permutations_total": total,
               "permutations_run": done, "aliases_dropped": aliases, "configurations_checked": pairs_done * len(block.periods),
               "cells_total": len(cells),
               "keyword_source": ({"name": block.keyword_source, "sha256": source_digest(block.keyword_source),
                                   "min_length": block.keyword_min_length} if block.keyword_source else None),
               "survivors_total": len(survivors), "survivors_materialized": len(candidates),
               "survivors_by_period": by_period, "by_set_cell_period": by_set, "crib_letters": len(cribs),
               "crib_classes_in_family": len(set(classes.tolist())) if len(classes) else 0,
               "survivor_classes": survivor_classes[:200],
               "survivors": [[labels[q], c, p, labels[int(classes[q])]] for q, c, p in survivors[:5000]],
               "survivors_listed_complete": len(survivors) <= 5000}
    outcome = SearchOutcome(status=status, evaluated=pairs_done * len(block.periods),
                            pruned=max(0, pairs_done * len(block.periods) - len(survivors)),
                            decode_failures=0, space_size=total, cap=cap, top=top,
                            wall_seconds=time.monotonic() - started, partitions=len(pieces),
                            objective=spec.scoring.objective, truth_generated=truth_generated,
                            truth_survived_prune=truth_generated, truth_rank=truth_rank, truth_objective=None,
                            progress_events=done, stop_reason=stop_reason)
    outcome.details = _json.loads(_json.dumps(details))
    return outcome
