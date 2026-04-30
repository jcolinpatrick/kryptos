"""K4Bench offline evaluator.

Reads a K4Bench attempts artifact (``k4bench.attempts.v1``) and a
sealed answers file, then scores the controller's submission against
the answers. Designed to run on a separate machine from the VM that
emitted the attempts: the VM only emits attempts, the evaluator
does the comparison.

Contract for the inputs:

    --attempts PATH    Path to ``k4bench.attempts.v1`` artifact JSON.
                       Multiple bench_ids in one file are supported;
                       the evaluator groups by bench_id and picks the
                       best attempt per bench_id (by crib_score desc,
                       confidence desc).

    --answers PATH     Sealed answers JSON. Tolerant of three shapes:
                         {"answers": [<answer>, ...]}
                         {"K4B-001": <answer>, ...}
                         [<answer>, <answer>, ...]
                         <answer>    (single bench_id)
                       Each <answer> must contain at minimum:
                         {"bench_id": str,
                          "ciphertext": str (97 A-Z),
                          "plaintext": str (97 A-Z)}

    --out PATH         Optional. JSON output path. When omitted, the
                       report is printed to stdout.

Per-bench output fields:

    bench_id              The bench identifier.
    n_attempts_seen       How many attempts the artifact carried for this id.
    chosen_attempt_index  Position (0-indexed) of the picked attempt in
                          the attempts list, before sort.
    claimed_crib_score    The crib_score reported on the picked attempt.
    plaintext_exact       True iff submitted plaintext == answer plaintext.
    method_functional     True iff replaying the submitted layers against
                          the challenge ciphertext produces the submitted
                          plaintext. False iff replay was attempted and
                          failed. Null iff layers are absent or contain
                          any layer kind unsupported by the dispatcher.
    strict_pass           plaintext_exact AND (method_functional is True).
                          Note: method_functional == None never satisfies
                          strict_pass, even if plaintext_exact is True.

Top-level fields:

    summary               Counts (n_bench_ids, n_pass, n_fail) and the
                          overall verdict (PASS / FAIL).
    schema_version        ``k4bench.evaluation.v1``
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

# Add the kryptos source root to sys.path so we can import the
# dispatcher's translation helpers and the kernel pipeline builder
# without installing the project. Mirrors the standalone-bootstrap
# pattern used elsewhere in scripts/.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT))


_SCHEMA_VERSION = "k4bench.evaluation.v1"


# --- Answer-file ingestion ---------------------------------------------------


class EvaluatorError(ValueError):
    """Raised on unrecoverable structural problems with input files."""


def _load_answers(path: Path) -> dict[str, dict[str, Any]]:
    """Load and normalize a sealed answers file into a dict by bench_id.

    Accepts the four input shapes documented at the top of this module.
    Validates that each answer carries a bench_id and a 97-char A-Z
    ciphertext + plaintext. Raises EvaluatorError on shape problems
    rather than producing silent partial output.
    """
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise EvaluatorError(f"answers file {path} is not valid JSON: {exc}")

    candidates: list[dict[str, Any]]
    if isinstance(raw, list):
        candidates = list(raw)
    elif isinstance(raw, dict):
        if "answers" in raw and isinstance(raw["answers"], list):
            candidates = list(raw["answers"])
        elif "bench_id" in raw:
            candidates = [raw]
        else:
            # Treat as {bench_id: answer_dict}
            candidates = []
            for k, v in raw.items():
                if not isinstance(v, dict):
                    continue
                # Inject bench_id from the key when not present in the value
                merged = dict(v)
                merged.setdefault("bench_id", k)
                candidates.append(merged)
    else:
        raise EvaluatorError(
            f"answers file {path} top-level must be list or dict; "
            f"got {type(raw).__name__}"
        )

    out: dict[str, dict[str, Any]] = {}
    for i, ans in enumerate(candidates):
        if not isinstance(ans, dict):
            raise EvaluatorError(
                f"answers[{i}] in {path} is not a dict; got {type(ans).__name__}"
            )
        bench_id = ans.get("bench_id")
        if not isinstance(bench_id, str) or not bench_id:
            raise EvaluatorError(
                f"answers[{i}] in {path} missing or empty bench_id"
            )
        ct = ans.get("ciphertext")
        pt = ans.get("plaintext")
        for label, val in (("ciphertext", ct), ("plaintext", pt)):
            if not isinstance(val, str):
                raise EvaluatorError(
                    f"answers[{bench_id}] in {path}: {label} must be str"
                )
            if len(val) != 97 or not val.isalpha() or not val.isupper():
                raise EvaluatorError(
                    f"answers[{bench_id}] in {path}: {label} must be 97 "
                    f"uppercase A-Z chars; got len={len(val)}"
                )
        if bench_id in out:
            raise EvaluatorError(
                f"answers file {path} contains duplicate bench_id {bench_id!r}"
            )
        out[bench_id] = ans
    return out


# --- Attempts-file ingestion -------------------------------------------------


def _load_attempts(path: Path) -> dict[str, Any]:
    """Load the attempts artifact verbatim. Validates only the schema
    version and the presence of an ``attempts`` list. Per-attempt
    validation happens lazily during evaluation so a single malformed
    entry does not block scoring of valid parallels.
    """
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise EvaluatorError(f"attempts file {path} is not valid JSON: {exc}")
    if not isinstance(raw, dict):
        raise EvaluatorError(
            f"attempts file {path} top-level must be dict; "
            f"got {type(raw).__name__}"
        )
    schema = raw.get("schema_version")
    if schema != "k4bench.attempts.v1":
        raise EvaluatorError(
            f"attempts file {path}: unexpected schema_version {schema!r}; "
            f"expected 'k4bench.attempts.v1'"
        )
    attempts = raw.get("attempts")
    if not isinstance(attempts, list):
        raise EvaluatorError(
            f"attempts file {path}: 'attempts' field must be a list; "
            f"got {type(attempts).__name__}"
        )
    return raw


def _group_by_bench(attempts: Iterable[dict[str, Any]]) -> dict[str, list[tuple[int, dict[str, Any]]]]:
    """Group attempts by bench_id, preserving original index for traceback.

    Skips attempts without a bench_id (logged via the caller's report
    path). The original index is preserved so the per-bench output can
    point at exactly which attempt was chosen.
    """
    groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for i, att in enumerate(attempts):
        if not isinstance(att, dict):
            continue
        bench_id = att.get("bench_id")
        if not isinstance(bench_id, str) or not bench_id:
            continue
        groups.setdefault(bench_id, []).append((i, att))
    return groups


def _pick_best(group: list[tuple[int, dict[str, Any]]]) -> tuple[int, dict[str, Any]]:
    """Return the (original_index, attempt) with highest crib_score,
    breaking ties by confidence then by original index.

    Sorting reverse=True on the (crib_score, confidence) key makes
    higher numbers win; ties on both fall back to lowest original
    index (stable sort + ascending tie-breaker).
    """
    def _key(item: tuple[int, dict[str, Any]]) -> tuple[float, float, int]:
        idx, att = item
        crib = att.get("crib_score", 0)
        conf = att.get("confidence", 0.0)
        try:
            crib_f = float(crib)
        except (TypeError, ValueError):
            crib_f = 0.0
        try:
            conf_f = float(conf)
        except (TypeError, ValueError):
            conf_f = 0.0
        # Negate idx so the natural reverse-sort below produces
        # ascending tie-break on idx (lower idx wins ties).
        return (crib_f, conf_f, -idx)

    return sorted(group, key=_key, reverse=True)[0]


# --- Replay machinery --------------------------------------------------------


def _bindings_per_layer(
    attempt: dict[str, Any],
    n_layers: int,
) -> dict[int, dict[str, Any]]:
    """Resolve which value to use for each layer's params during replay.

    Order of operations:
      1. Seed each layer with the first value of every ParamRange on
         that layer (first ``values[0]`` if explicit; otherwise
         ``start`` for an integer range). Multi-value sweeps collapse
         to their first element.
      2. Override with ``best_config_bindings`` (when present): the
         binding tuple the dispatcher itself picked for the best
         candidate. This wins over the first-value fallback so
         multi-config dispatches replay using the actually-best config.

    Returns a dict ``{layer_idx: {param_name: value}}``. Layers with
    no params produce an empty inner dict.
    """
    out: dict[int, dict[str, Any]] = {i: {} for i in range(n_layers)}

    # Seed with first value of every ParamRange on every layer.
    layers_raw = attempt.get("layers") or []
    for layer_idx, layer_dict in enumerate(layers_raw):
        if layer_idx >= n_layers or not isinstance(layer_dict, dict):
            continue
        params = layer_dict.get("params") or []
        if not isinstance(params, list):
            continue
        for p in params:
            if not isinstance(p, dict):
                continue
            name = p.get("name")
            if not isinstance(name, str) or not name:
                continue
            # Prefer explicit values list; otherwise take start of an
            # integer range. ParamRange.validate() guarantees exactly
            # one mode is set, but we're tolerant here so a malformed
            # entry doesn't crash the whole replay.
            values = p.get("values")
            if isinstance(values, list) and len(values) > 0:
                out[layer_idx][name] = values[0]
                continue
            start = p.get("start")
            if isinstance(start, int):
                out[layer_idx][name] = start

    # Override with explicit best_config_bindings when supplied.
    bindings_raw = attempt.get("best_config_bindings") or []
    if isinstance(bindings_raw, list) and bindings_raw:
        for entry in bindings_raw:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                continue
            flat_key, value = entry
            if not isinstance(flat_key, str) or "." not in flat_key:
                continue
            layer_idx_str, param_name = flat_key.split(".", 1)
            if not layer_idx_str.startswith("layer"):
                continue
            try:
                layer_idx = int(layer_idx_str[len("layer"):])
            except ValueError:
                continue
            if 0 <= layer_idx < n_layers:
                out[layer_idx][param_name] = value
    return out


def _replay_layers(
    layers: list[dict[str, Any]],
    ciphertext: str,
    bindings_by_layer: dict[int, dict[str, Any]],
) -> tuple[Optional[str], Optional[str]]:
    """Replay a layer pipeline against ``ciphertext``.

    Returns ``(plaintext, error)``:
      - ``(plaintext, None)`` on success.
      - ``(None, "unsupported: <kind>")`` when any layer's ``kind``
        is outside the dispatcher's supported set. The caller maps
        this to ``method_functional = None``.
      - ``(None, "<error message>")`` on any other replay failure.
        The caller maps this to ``method_functional = False``.

    The function reuses the dispatcher's per-layer translator and the
    kernel's pipeline builder so the replay is bit-for-bit equivalent
    to what the controller's worker did.
    """
    from internal.internal_dsl import CipherLayer
    from internal.dispatcher import (
        _SUPPORTED_KINDS,
        _translate_layer,
        DispatcherError,
    )

    # Pre-flight: every layer kind must be dispatchable. Anything
    # outside _SUPPORTED_KINDS maps to method_functional=None because
    # we cannot fairly judge a layer the dispatcher itself cannot run.
    for i, layer_dict in enumerate(layers):
        if not isinstance(layer_dict, dict):
            return None, f"layer[{i}] is not a dict"
        kind = layer_dict.get("kind")
        if not isinstance(kind, str) or kind not in _SUPPORTED_KINDS:
            return None, f"unsupported: layer[{i}].kind={kind!r}"
        # Procedural layers carry a recipe_id and would normally be
        # expanded by the dispatcher before reaching translation.
        # We do not perform that expansion in the offline replay
        # path; surfacing it as unsupported is the honest answer.
        if kind == "procedural":
            return None, f"unsupported: layer[{i}].kind='procedural' (replay does not expand recipes)"

    # Translate each layer using the current bindings.
    try:
        cipher_layers = [CipherLayer.from_dict(layer_dict) for layer_dict in layers]
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        return None, f"layer parse failure: {type(exc).__name__}: {exc}"

    try:
        steps_dict: list[dict[str, Any]] = []
        for i, layer in enumerate(cipher_layers):
            binding = bindings_by_layer.get(i, {})
            steps_dict.append(_translate_layer(layer, binding))
    except DispatcherError as exc:
        return None, f"translation: {exc}"
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        return None, f"translation raised: {type(exc).__name__}: {exc}"

    # Build the kernel pipeline and apply it to the challenge CT.
    try:
        from kryptos.kernel.transforms.compose import (
            PipelineConfig,
            TransformConfig,
            TransformType,
            build_pipeline,
        )
    except ImportError as exc:
        return None, f"kernel import failure: {exc}"

    try:
        pipeline_steps = tuple(
            TransformConfig(
                transform_type=TransformType(s["type"]),
                params=dict(s.get("params", {})),
                description=s.get("description", ""),
            )
            for s in steps_dict
        )
        pipeline = PipelineConfig(
            name="evaluator_replay",
            steps=pipeline_steps,
            direction="decrypt",
        )
        fn = build_pipeline(pipeline)
        candidate_pt = fn(ciphertext)
    except Exception as exc:  # noqa: BLE001 — defensive boundary
        return None, f"pipeline run failed: {type(exc).__name__}: {exc}"

    if not isinstance(candidate_pt, str) or len(candidate_pt) != len(ciphertext):
        return None, (
            f"replay output length {len(candidate_pt) if isinstance(candidate_pt, str) else 'n/a'} "
            f"!= CT length {len(ciphertext)}"
        )
    return candidate_pt, None


def _evaluate_attempt(
    attempt: dict[str, Any],
    answer: dict[str, Any],
) -> dict[str, Any]:
    """Score one attempt against one answer.

    Always returns a dict with the same keys regardless of which
    field happened to be available; missing inputs map to None
    rather than producing a heterogeneous dict shape.
    """
    submitted_pt = attempt.get("plaintext")
    answer_pt = answer.get("plaintext", "")
    answer_ct = answer.get("ciphertext", "")
    layers = attempt.get("layers") or []

    plaintext_exact: bool = (
        isinstance(submitted_pt, str)
        and isinstance(answer_pt, str)
        and submitted_pt == answer_pt
    )

    # method_functional: replay layers against challenge CT, compare to
    # the SUBMITTED plaintext (not the answer). The point of this check
    # is whether the controller's claim "these layers produced this
    # plaintext" is internally consistent — independent of correctness.
    method_functional: Optional[bool]
    replay_pt: Optional[str] = None
    replay_error: Optional[str] = None

    if not isinstance(layers, list) or len(layers) == 0:
        method_functional = None
        replay_error = "layers absent"
    elif not isinstance(submitted_pt, str) or len(submitted_pt) != 97:
        method_functional = None
        replay_error = "submitted plaintext absent or wrong length"
    elif not isinstance(answer_ct, str) or len(answer_ct) != 97:
        method_functional = None
        replay_error = "answer ciphertext absent or wrong length"
    else:
        bindings = _bindings_per_layer(attempt, n_layers=len(layers))
        replay_pt, replay_error = _replay_layers(layers, answer_ct, bindings)
        if replay_pt is None and replay_error and replay_error.startswith("unsupported"):
            method_functional = None
        elif replay_pt is None:
            method_functional = False
        else:
            method_functional = (replay_pt == submitted_pt)

    strict_pass = bool(plaintext_exact) and (method_functional is True)

    return {
        "plaintext_exact": plaintext_exact,
        "method_functional": method_functional,
        "strict_pass": strict_pass,
        "replay_error": replay_error,
        "replay_plaintext_matches_submitted": (
            None if replay_pt is None else (replay_pt == submitted_pt)
        ),
    }


# --- Top-level orchestration -------------------------------------------------


def evaluate(
    answers: dict[str, dict[str, Any]],
    attempts_artifact: dict[str, Any],
) -> dict[str, Any]:
    """Score every attempt in the artifact against the loaded answers.

    Pure function so tests can construct inputs in memory rather than
    round-tripping through disk.
    """
    attempts_list = attempts_artifact.get("attempts") or []
    groups = _group_by_bench(attempts_list)

    per_bench: list[dict[str, Any]] = []
    n_pass = 0
    n_fail = 0

    for bench_id in sorted(groups.keys()):
        group = groups[bench_id]
        idx, best = _pick_best(group)
        answer = answers.get(bench_id)
        if answer is None:
            per_bench.append({
                "bench_id": bench_id,
                "n_attempts_seen": len(group),
                "chosen_attempt_index": idx,
                "claimed_crib_score": best.get("crib_score"),
                "plaintext_exact": None,
                "method_functional": None,
                "strict_pass": False,
                "error": (
                    f"no answer for bench_id {bench_id!r}; "
                    f"cannot score plaintext or method_functional"
                ),
            })
            n_fail += 1
            continue
        score = _evaluate_attempt(best, answer)
        per_bench.append({
            "bench_id": bench_id,
            "n_attempts_seen": len(group),
            "chosen_attempt_index": idx,
            "claimed_crib_score": best.get("crib_score"),
            "claimed_confidence": best.get("confidence"),
            "claimed_plaintext_preview": (best.get("plaintext") or "")[:32],
            **score,
        })
        if score["strict_pass"]:
            n_pass += 1
        else:
            n_fail += 1

    return {
        "schema_version": _SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "n_bench_ids": len(per_bench),
            "n_pass": n_pass,
            "n_fail": n_fail,
            "verdict": "PASS" if n_pass > 0 and n_fail == 0 else "FAIL",
        },
        "per_bench": per_bench,
    }


# --- CLI ---------------------------------------------------------------------


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Score a K4Bench attempts artifact against a sealed answers "
            "file. Reads only the two files; never reads the controller "
            "ledger."
        ),
    )
    p.add_argument(
        "--attempts", required=True, type=Path,
        help="Path to k4bench.attempts.v1 artifact JSON.",
    )
    p.add_argument(
        "--answers", required=True, type=Path,
        help="Path to sealed answers JSON.",
    )
    p.add_argument(
        "--out", required=False, type=Path, default=None,
        help="Optional output path. When omitted, writes the report to stdout.",
    )
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        answers = _load_answers(args.answers)
        attempts = _load_attempts(args.attempts)
    except EvaluatorError as exc:
        print(f"evaluator: {exc}", file=sys.stderr)
        return 2

    report = evaluate(answers, attempts)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    else:
        print(payload)
    # Exit 0 on overall PASS, exit 1 on any failure. The exit code lets
    # CI gates trip without parsing the JSON.
    return 0 if report["summary"]["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
