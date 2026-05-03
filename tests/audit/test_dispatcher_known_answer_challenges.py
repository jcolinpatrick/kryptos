from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import execute


ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {ch: i for i, ch in enumerate(ALPH)}
PT97 = (
    "THEQUICKBROWNFOXIUMPSOVERTHELAZYDOG"
    "ATTACKATDAWNTHEPACKAGEISSAFE"
    "MEETATTHEOLDSTONEBRIDGEATNOON"
    "ALPHA"
)[:97]
assert len(PT97) == 97

PT35 = "THEQUICKBROWNFOXIUMPSOVERTHELAZYDOG"
assert len(PT35) == 35


def _crib_all(text: str) -> dict[int, str]:
    return {i: ch for i, ch in enumerate(text)}


def _spec(kind: str, params: dict[str, object] | None = None, *, recipe_id: str | None = None) -> HypothesisSpec:
    ranges = [
        ParamRange(name=name, values=[value])
        for name, value in (params or {}).items()
    ]
    return HypothesisSpec(
        hypothesis_id=f"audit-known-answer-{kind}",
        pipeline=[CipherLayer(kind=kind, params=ranges, recipe_id=recipe_id)],
        compute_budget_cpu_minutes=1,
        assumption_bundle=["audit_known_answer"],
    )


def _spec_pipeline(layers: list[dict[str, object]], *, hypothesis_id: str = "audit-known-answer-composite") -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id=hypothesis_id,
        pipeline=[
            CipherLayer(
                kind=str(layer["kind"]),
                params=[
                    ParamRange(name=name, values=[value])
                    for name, value in dict(layer.get("params", {})).items()
                ],
            )
            for layer in layers
        ],
        compute_budget_cpu_minutes=1,
        assumption_bundle=["audit_known_answer"],
    )


def _run_fixture(kind: str, ciphertext: str, params: dict[str, object] | None = None, *, recipe_id: str | None = None):
    _run_fixture_text(PT97, kind, ciphertext, params, recipe_id=recipe_id)


def _run_fixture_text(
    plaintext: str,
    kind: str,
    ciphertext: str,
    params: dict[str, object] | None = None,
    *,
    recipe_id: str | None = None,
):
    spec = _spec(kind, params, recipe_id=recipe_id)
    assert spec.expected_cardinality() == 1
    result = execute(
        spec,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=ciphertext,
        challenge_crib_dict=_crib_all(plaintext),
    )
    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.total_tested == 1
    assert result.universe_hash
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] == plaintext
    assert result.best_candidate["crib_score"] == len(plaintext)
    assert result.best_candidate["classification"] == "challenge_known_answer"
    return result


def _run_pipeline_fixture(plaintext: str, ciphertext: str, layers: list[dict[str, object]]):
    spec = _spec_pipeline(layers)
    assert spec.expected_cardinality() == 1
    result = execute(
        spec,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=ciphertext,
        challenge_crib_dict=_crib_all(plaintext),
    )
    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.total_tested == 1
    assert result.universe_hash
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] == plaintext
    assert result.best_candidate["crib_score"] == len(plaintext)
    assert result.best_candidate["classification"] == "challenge_known_answer"
    return result


def _shift(text: str, shift: int) -> str:
    return "".join(ALPH[(IDX[ch] + shift) % 26] for ch in text)


def _vig(text: str, keyword: str, sign: int) -> str:
    key = [IDX[ch] for ch in keyword]
    return "".join(
        ALPH[(IDX[ch] + sign * key[i % len(key)]) % 26]
        for i, ch in enumerate(text)
    )


def _beaufort(text: str, keyword: str) -> str:
    key = [IDX[ch] for ch in keyword]
    return "".join(
        ALPH[(key[i % len(key)] - IDX[ch]) % 26]
        for i, ch in enumerate(text)
    )


def _keyword_mixed(keyword: str) -> str:
    out = []
    seen = set()
    for ch in (keyword + ALPH).upper():
        if ch in IDX and ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


def _quagmire_encrypt(
    text: str,
    period_keyword: str,
    *,
    indicator: str,
    ct_alphabet_keyword: str,
    pt_alphabet_keyword: str,
) -> str:
    ct_alpha = _keyword_mixed(ct_alphabet_keyword)
    pt_alpha = _keyword_mixed(pt_alphabet_keyword)
    ct_idx = {ch: i for i, ch in enumerate(ct_alpha)}
    pt_idx = {ch: i for i, ch in enumerate(pt_alpha)}
    indicator_pos = ct_idx[indicator]
    key = period_keyword.upper()
    out = []
    for i, ch in enumerate(text):
        shift = (ct_idx[key[i % len(key)]] - indicator_pos) % 26
        out.append(ct_alpha[(pt_idx[ch] + shift) % 26])
    return "".join(out)


def _apply_perm(text: str, perm: list[int]) -> str:
    return "".join(text[p] for p in perm)


def _columnar_perm(width: int, col_order: list[int], length: int = 97) -> list[int]:
    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(length):
        cols[pos % width].append(pos)
    perm = []
    for rank in range(width):
        perm.extend(cols[col_order.index(rank)])
    return perm


def _rail_perm(length: int, depth: int) -> list[int]:
    rails = [[] for _ in range(depth)]
    rail, direction = 0, 1
    for i in range(length):
        rails[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == depth - 1:
            direction = -1
        rail += direction
    return [pos for row in rails for pos in row]


def _serpentine_perm(rows: int, cols: int, length: int = 97, *, vertical: bool = False) -> list[int]:
    perm = []
    if vertical:
        for c in range(cols):
            row_range = range(rows) if c % 2 == 0 else range(rows - 1, -1, -1)
            for r in row_range:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    else:
        for r in range(rows):
            col_range = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            for c in col_range:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    return perm


def _myszkowski_perm(keyword: str, length: int = 97) -> list[int]:
    ranks = {ch: i for i, ch in enumerate(sorted(set(keyword)))}
    col_ranks = [ranks[ch] for ch in keyword]
    rank_to_cols: dict[int, list[int]] = defaultdict(list)
    for col, rank in enumerate(col_ranks):
        rank_to_cols[rank].append(col)
    rows = (length + len(keyword) - 1) // len(keyword)
    perm = []
    for rank in sorted(rank_to_cols):
        cols = rank_to_cols[rank]
        if len(cols) == 1:
            for pos in range(cols[0], length, len(keyword)):
                perm.append(pos)
        else:
            for row in range(rows):
                for col in cols:
                    pos = row * len(keyword) + col
                    if pos < length:
                        perm.append(pos)
    return perm


def _reverse_blocks(text: str, block_size: int) -> str:
    return "".join(text[i : i + block_size][::-1] for i in range(0, len(text), block_size))


def _row_reverse(text: str, width: int, parity: str, start_row: int) -> str:
    chars = list(text)
    for row, start in enumerate(range(0, len(text), width)):
        end = min(start + width, len(text))
        effective = row - start_row
        reverse = parity == "both" or (parity == "odd" and effective % 2 == 1) or (parity == "even" and effective % 2 == 0)
        if reverse:
            chars[start:end] = reversed(chars[start:end])
    return "".join(chars)


def _skip_route_ciphertext(plaintext: str, step: int, offset: int) -> str:
    out = ["?"] * len(plaintext)
    for i, ch in enumerate(plaintext):
        out[(offset + i * step) % len(plaintext)] = ch
    return "".join(out)


def _bifid_grid(keyword: str, merge: str = "IJ") -> list[str]:
    omitted = merge[1]
    seen = set()
    grid = []
    for ch in (keyword + ALPH).upper():
        ch = merge[0] if ch == omitted else ch
        if ch in IDX and ch != omitted and ch not in seen:
            seen.add(ch)
            grid.append(ch)
    assert len(grid) == 25
    return grid


def _bifid_encrypt(text: str, keyword: str, period: int = 0) -> str:
    grid = _bifid_grid(keyword)
    pos = {ch: divmod(i, 5) for i, ch in enumerate(grid)}
    lookup = {(r, c): grid[r * 5 + c] for r in range(5) for c in range(5)}
    coords = [pos[ch] for ch in text]
    period = period or len(coords)
    out = []
    for start in range(0, len(coords), period):
        block = coords[start : start + period]
        combined = [r for r, _ in block] + [c for _, c in block]
        out.extend(lookup[(combined[2 * i], combined[2 * i + 1])] for i in range(len(block)))
    return "".join(out)


def _grille_ciphertext(plaintext: str, mask: list[int]) -> str:
    out = ["?"] * len(plaintext)
    for i, pos in enumerate(mask):
        out[pos] = plaintext[i]
    return "".join(out)


@pytest.mark.parametrize(
    ("kind", "ciphertext", "params"),
    [
        ("identity", PT97, {}),
        ("caesar", _shift(PT97, 8), {"shift": 8}),
        ("vigenere", _vig(PT97, "ORBIT", +1), {"keyword": "ORBIT"}),
        ("beaufort", _beaufort(PT97, "ORBIT"), {"keyword": "ORBIT"}),
        ("variant_beaufort", _vig(PT97, "ORBIT", -1), {"keyword": "ORBIT"}),
        ("atbash", "".join(ALPH[25 - IDX[ch]] for ch in PT97), {}),
        ("columnar", _apply_perm(PT97, _columnar_perm(7, [2, 0, 5, 1, 6, 3, 4])), {"width": 7, "col_order": [2, 0, 5, 1, 6, 3, 4]}),
        ("rail_fence", _apply_perm(PT97, _rail_perm(97, 4)), {"depth": 4}),
        ("route", _apply_perm(PT97, _serpentine_perm(11, 9)), {"variant": "serpentine", "rows": 11, "cols": 9, "vertical": False}),
        ("myszkowski", _apply_perm(PT97, _myszkowski_perm("BALLOON")), {"keyword": "BALLOON"}),
        ("polybius", _bifid_encrypt(PT97, "CIPHER", period=7), {"square_keyword": "CIPHER", "variant": "bifid", "merge": "IJ", "period": 7, "direction": "decrypt"}),
        ("quagmire", _quagmire_encrypt(PT97, "ORBIT", indicator="K", ct_alphabet_keyword="KRYPTOS", pt_alphabet_keyword="KRYPTOS"), {"period_keyword": "ORBIT", "indicator": "K", "ct_alphabet_keyword": "KRYPTOS", "pt_alphabet_keyword": "KRYPTOS", "variant": "quagmire_iii"}),
        ("grille", _grille_ciphertext(PT97, list(reversed(range(97)))), {"hole_mask": list(reversed(range(97)))}),
        ("reverse_blocks", _reverse_blocks(PT97, 6), {"block_size": 6, "block_mode": "reverse_partial"}),
        ("skip_route", _skip_route_ciphertext(PT97, 5, 7), {"step": 5, "offset": 7}),
        ("route_boustrophedon", _apply_perm(PT97, _serpentine_perm(13, 8)), {"width": 8, "vertical": False}),
        ("row_reverse", _row_reverse(PT97, 9, "odd", 0), {"width": 9, "parity": "odd", "start_row": 0}),
    ],
)
def test_dispatcher_solves_independent_97_char_known_answer_challenges(kind, ciphertext, params):
    _run_fixture(kind, ciphertext, params)


@pytest.mark.parametrize(
    ("kind", "ciphertext", "params"),
    [
        ("identity", PT35, {}),
        ("caesar", _shift(PT35, 8), {"shift": 8}),
        ("vigenere", _vig(PT35, "ORBIT", +1), {"keyword": "ORBIT"}),
        ("beaufort", _beaufort(PT35, "ORBIT"), {"keyword": "ORBIT"}),
        ("variant_beaufort", _vig(PT35, "ORBIT", -1), {"keyword": "ORBIT"}),
        ("atbash", "".join(ALPH[25 - IDX[ch]] for ch in PT35), {}),
        ("columnar", _apply_perm(PT35, _columnar_perm(6, [2, 0, 5, 1, 3, 4], len(PT35))), {"width": 6, "col_order": [2, 0, 5, 1, 3, 4]}),
        ("rail_fence", _apply_perm(PT35, _rail_perm(len(PT35), 3)), {"depth": 3}),
        ("route", _apply_perm(PT35, _serpentine_perm(5, 7, len(PT35))), {"variant": "serpentine", "rows": 5, "cols": 7, "vertical": False}),
        ("myszkowski", _apply_perm(PT35, _myszkowski_perm("BALLOON", len(PT35))), {"keyword": "BALLOON"}),
        ("polybius", _bifid_encrypt(PT35, "CIPHER", period=5), {"square_keyword": "CIPHER", "variant": "bifid", "merge": "IJ", "period": 5, "direction": "decrypt"}),
        ("quagmire", _quagmire_encrypt(PT35, "ORBIT", indicator="K", ct_alphabet_keyword="KRYPTOS", pt_alphabet_keyword="KRYPTOS"), {"period_keyword": "ORBIT", "indicator": "K", "ct_alphabet_keyword": "KRYPTOS", "pt_alphabet_keyword": "KRYPTOS", "variant": "quagmire_iii"}),
        ("grille", _grille_ciphertext(PT35, list(reversed(range(len(PT35))))), {"hole_mask": list(reversed(range(len(PT35))))}),
        ("reverse_blocks", _reverse_blocks(PT35, 6), {"block_size": 6, "block_mode": "reverse_partial"}),
        ("skip_route", _skip_route_ciphertext(PT35, 6, 4), {"step": 6, "offset": 4}),
        ("route_boustrophedon", _apply_perm(PT35, _serpentine_perm(6, 6, len(PT35))), {"width": 6, "vertical": False}),
        ("row_reverse", _row_reverse(PT35, 8, "odd", 0), {"width": 8, "parity": "odd", "start_row": 0}),
    ],
)
def test_dispatcher_solves_non_97_known_answer_challenges(kind, ciphertext, params):
    _run_fixture_text(PT35, kind, ciphertext, params)


def test_non_97_challenge_universe_hash_depends_on_challenge_context():
    spec = _spec("identity", {})
    r35 = execute(
        spec,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT35,
        challenge_crib_dict=_crib_all(PT35),
    )
    r97 = execute(
        spec,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT97,
        challenge_crib_dict=_crib_all(PT97),
    )

    assert r35.admissibility_verdict == "ok"
    assert r97.admissibility_verdict == "ok"
    assert r35.universe_hash != r97.universe_hash


def test_challenge_scoring_uses_explicit_cribs_not_real_k4_constants():
    wrong_cribs = _crib_all(PT35)
    wrong_cribs[0] = "A" if PT35[0] != "A" else "B"

    result = execute(
        _spec("identity", {}),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT35,
        challenge_crib_dict=wrong_cribs,
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] == PT35
    assert result.best_candidate["crib_score"] == len(PT35) - 1
    assert result.best_candidate["classification"] != "challenge_known_answer"


def test_challenge_mode_rejects_non_az_ciphertext_before_dispatch():
    result = execute(
        _spec("identity", {}),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext="ATTACKATDAWN1",
        challenge_crib_dict=_crib_all("ATTACKATDAWNA"),
    )

    assert result.admissibility_verdict == "rejected"
    assert "uppercase A-Z letters only" in result.admissibility_reasons[0]


def test_non_97_grille_rejects_mask_with_wrong_length():
    result = execute(
        _spec("grille", {"hole_mask": list(range(97))}),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT35,
        challenge_crib_dict=_crib_all(PT35),
    )

    assert result.admissibility_verdict == "rejected"
    assert "grille hole_mask invalid" in result.admissibility_reasons[0]


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("known_answer_corpus.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_dispatcher_solves_static_known_answer_corpus(fixture):
    _run_fixture_text(
        fixture["plaintext"],
        fixture["family"],
        fixture["ciphertext"],
        fixture["params"],
    )


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("external_known_answer_corpus.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_dispatcher_solves_external_known_answer_corpus(fixture):
    _run_fixture_text(
        fixture["plaintext"],
        fixture["family"],
        fixture["ciphertext"],
        fixture["params"],
    )


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("known_answer_composites.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_dispatcher_solves_static_composite_known_answer_corpus(fixture):
    _run_pipeline_fixture(
        fixture["plaintext"],
        fixture["ciphertext"],
        fixture["pipeline"],
    )


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("external_known_answer_composites.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_dispatcher_solves_external_composite_known_answer_corpus(fixture):
    _run_pipeline_fixture(
        fixture["plaintext"],
        fixture["ciphertext"],
        fixture["pipeline"],
    )


def test_composite_layer_order_is_cryptanalytic_semantics_not_cosmetic():
    fixture = json.loads((Path(__file__).with_name("known_answer_composites.json")).read_text())[1]
    reversed_layers = list(reversed(fixture["pipeline"]))
    result = execute(
        _spec_pipeline(reversed_layers, hypothesis_id="audit-composite-wrong-order"),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=fixture["ciphertext"],
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])


def test_external_composite_layer_order_is_cryptanalytic_semantics_not_cosmetic():
    fixture = json.loads((Path(__file__).with_name("external_known_answer_composites.json")).read_text())[0]
    reversed_layers = list(reversed(fixture["pipeline"]))
    result = execute(
        _spec_pipeline(reversed_layers, hypothesis_id="audit-external-composite-wrong-order"),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=fixture["ciphertext"],
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])


def _wrong_params_for_fixture(fixture: dict[str, object]) -> dict[str, object] | None:
    family = str(fixture["family"])
    plaintext = str(fixture["plaintext"])
    if family == "caesar":
        return {"shift": (int(fixture["params"]["shift"]) + 1) % 26}
    if family in {"vigenere", "beaufort", "variant_beaufort"}:
        return {"keyword": "WRONG"}
    if family == "columnar":
        return {"width": 6, "col_order": [0, 1, 2, 3, 4, 5]}
    if family == "rail_fence":
        return {"depth": 4}
    if family == "route":
        return {"variant": "serpentine", "rows": 5, "cols": 7, "vertical": True}
    if family == "myszkowski":
        return {"keyword": "ORANGE"}
    if family == "polybius":
        return {"square_keyword": "KRYPTOS", "variant": "bifid", "merge": "IJ", "period": 5, "direction": "decrypt"}
    if family == "quagmire":
        return {"period_keyword": "LEMON", "indicator": "K", "ct_alphabet_keyword": "KRYPTOS", "pt_alphabet_keyword": "KRYPTOS", "variant": "quagmire_iii"}
    if family == "grille":
        return {"hole_mask": list(range(len(plaintext)))}
    if family == "reverse_blocks":
        return {"block_size": 5, "block_mode": "reverse_partial"}
    if family == "skip_route":
        return {"step": 6, "offset": 5}
    if family == "route_boustrophedon":
        return {"width": 7, "vertical": False}
    if family == "row_reverse":
        return {"width": 8, "parity": "even", "start_row": 0}
    return None


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("known_answer_corpus.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_static_known_answer_corpus_rejects_randomized_ciphertext_negative_control(fixture):
    bad_ciphertext = _shift(fixture["ciphertext"], 13)
    result = execute(
        _spec(fixture["family"], fixture["params"]),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=bad_ciphertext,
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])
    assert result.best_candidate["classification"] != "challenge_known_answer"


@pytest.mark.parametrize(
    "fixture",
    json.loads((Path(__file__).with_name("external_known_answer_corpus.json")).read_text()),
    ids=lambda fixture: fixture["id"],
)
def test_external_known_answer_corpus_rejects_randomized_ciphertext_negative_control(fixture):
    bad_ciphertext = _shift(fixture["ciphertext"], 13)
    result = execute(
        _spec(fixture["family"], fixture["params"]),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=bad_ciphertext,
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])
    assert result.best_candidate["classification"] != "challenge_known_answer"


@pytest.mark.parametrize(
    "fixture",
    [
        fixture
        for fixture in json.loads((Path(__file__).with_name("known_answer_corpus.json")).read_text())
        if _wrong_params_for_fixture(fixture) is not None
    ],
    ids=lambda fixture: fixture["id"],
)
def test_static_known_answer_corpus_rejects_wrong_parameters(fixture):
    result = execute(
        _spec(fixture["family"], _wrong_params_for_fixture(fixture)),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=fixture["ciphertext"],
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])


@pytest.mark.parametrize(
    "fixture",
    [
        fixture
        for fixture in json.loads((Path(__file__).with_name("external_known_answer_corpus.json")).read_text())
        if _wrong_params_for_fixture(fixture) is not None
    ],
    ids=lambda fixture: fixture["id"],
)
def test_external_known_answer_corpus_rejects_wrong_parameters(fixture):
    result = execute(
        _spec(fixture["family"], _wrong_params_for_fixture(fixture)),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=fixture["ciphertext"],
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])


def test_route_spiral_start_corner_is_cryptanalytic_semantics_not_cosmetic():
    fixture = next(
        item
        for item in json.loads((Path(__file__).with_name("external_known_answer_corpus.json")).read_text())
        if item["id"] == "route_cryptoit_brighton_spiral_top_right"
    )
    wrong_params = dict(fixture["params"])
    wrong_params["start_corner"] = "top_left"

    result = execute(
        _spec("route", wrong_params),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=fixture["ciphertext"],
        challenge_crib_dict=_crib_all(fixture["plaintext"]),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != fixture["plaintext"]
    assert result.best_candidate["crib_score"] < len(fixture["plaintext"])


def test_route_spiral_rejects_unknown_start_corner():
    result = execute(
        _spec(
            "route",
            {
                "variant": "spiral",
                "rows": 5,
                "cols": 3,
                "clockwise": True,
                "start_corner": "center",
            },
        ),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext="ITAHEVONOGBRHND",
        challenge_crib_dict=_crib_all("BRIGHTONANDHOVE"),
    )

    assert result.admissibility_verdict == "rejected"
    assert any("start_corner" in reason for reason in result.admissibility_reasons)


def test_enumerated_challenge_search_reports_exact_cardinality_and_family_width():
    ciphertext = _shift(_vig(PT35, "ORBIT", +1), 5)
    spec = HypothesisSpec(
        hypothesis_id="audit-enumerated-composite",
        pipeline=[
            CipherLayer(kind="caesar", params=[ParamRange(name="shift", values=[3, 5, 7])]),
            CipherLayer(kind="vigenere", params=[ParamRange(name="keyword", values=["ORBIT", "LEMON"])]),
        ],
        compute_budget_cpu_minutes=1,
        assumption_bundle=["audit_known_answer"],
    )

    result = execute(
        spec,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=ciphertext,
        challenge_crib_dict=_crib_all(PT35),
    )

    assert spec.expected_cardinality() == 6
    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.total_tested == 6
    assert result.universe_hash
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] == PT35
    assert result.best_candidate["crib_score"] == len(PT35)


def test_dispatcher_runs_procedural_identity_recipe_against_challenge_ct():
    result = execute(
        HypothesisSpec(
            hypothesis_id="audit-known-answer-procedural-identity",
            pipeline=[CipherLayer(kind="procedural", recipe_id="P-BASELINE-1")],
            compute_budget_cpu_minutes=1,
            assumption_bundle=["audit_known_answer"],
        ),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT97,
        challenge_crib_dict=_crib_all(PT97),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] == PT97
    assert result.best_candidate["crib_score"] == 97


def test_known_answer_challenge_rejects_wrong_variant():
    ciphertext = _vig(PT97, "ORBIT", +1)
    result = execute(
        _spec("beaufort", {"keyword": "ORBIT"}),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=ciphertext,
        challenge_crib_dict=_crib_all(PT97),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != PT97
    assert result.best_candidate["crib_score"] < 97


def test_static_columnar_fixture_rejects_wrong_column_order():
    wrong_params = {"width": 6, "col_order": [0, 1, 2, 3, 4, 5]}
    ciphertext = "HKFPTYQRXOEOTCNMRZUOIVLGIWUEAEBOSHD"

    result = execute(
        _spec("columnar", wrong_params),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=ciphertext,
        challenge_crib_dict=_crib_all(PT35),
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    assert result.best_candidate["candidate_pt"] != PT35
    assert result.best_candidate["crib_score"] < len(PT35)


def test_key_tape_dispatcher_translation_is_now_live():
    # 2026-05-03 (key_tape DSL build Task 12): key_tape gained its dispatcher
    # translation in Task 9. The previous test asserted it was deferred;
    # this replacement test verifies that the admissibility gate no longer
    # rejects key_tape on "no dispatcher translation" grounds.
    #
    # An invalid tape (non-int values) is used so the spec fails fast on
    # param validation rather than running a full 97-char sweep, but the
    # rejection reason must be param validation, NOT "no dispatcher translation".
    result = execute(
        _spec("key_tape", {"tape": [1, 2, 3], "variant": "vigenere", "alphabet": "AZ"}),
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=PT97,
        challenge_crib_dict=_crib_all(PT97),
    )

    # The dispatcher now translates key_tape so admissibility passes.
    # (The spec may be rejected for other reasons once it reaches validation,
    # but NOT for "no dispatcher translation".)
    assert not any(
        "no dispatcher translation" in reason
        for reason in result.admissibility_reasons
    ), (
        "key_tape should no longer be rejected as having no dispatcher "
        f"translation; got: {result.admissibility_reasons}"
    )


def test_real_k4_dispatcher_artifact_carries_family_wise_p_value_annotation(tmp_path):
    result = execute(
        _spec("identity", {}),
        parallel=False,
        exhaustion_log={},
        artifact_root=tmp_path,
    )

    assert result.admissibility_verdict == "ok", result.admissibility_reasons
    assert result.best_candidate is not None
    correction = result.best_candidate["family_wise_p_value_vs_null"]
    assert correction["n_tests"] == 1
    assert correction["universe_hash"] == result.universe_hash
    assert result.best_p_value_vs_null == correction["bonferroni_p_value"]
