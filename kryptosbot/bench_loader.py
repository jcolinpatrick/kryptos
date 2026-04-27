"""K4Bench public-challenge loader.

Pure data adapter for the K4Bench blind synthetic benchmark suite. This
module is deliberately small: it loads, validates, and structures one
public challenge JSON for the existing controller. It is NOT a separate
controller, it does NOT execute ciphers, and it MUST refuse any file
that contains sealed answer material.

Design constraints:

- The challenge JSON is public input. The companion answer JSON is
  sealed and must not be read here, by any controller path, or by any
  prompt-visible code. ``load_k4bench_challenge`` rejects any file that
  carries answer-like keys, so a misplaced sealed file fails loud.
- The structural contract (97-char A-Z CT, 24 crib positions in spans
  21-33 and 63-73) mirrors real K4 so the existing scoring machinery
  applies without per-challenge variation. Crib content varies per
  challenge — that is what ``KRYPTOS_CRIB_DICT_OVERRIDE`` carries.
- The loader produces controller-safe "canonical facts" for the bench
  context. These replace, but parallel, the real-K4 facts that
  ``ResearchController._load_canonical_facts`` writes when bench mode
  is inactive.

Usage from ``run_controller.py``::

    challenge = load_k4bench_challenge(args.bench_challenge)
    challenge.install_kernel_overrides()       # before any kryptos.kernel import
    facts = challenge.canonical_facts()
    prompt_block = challenge.prompt_block()

The K4Bench harness lives at ``bench/k4bench/`` (challenges, manifest,
attempts), and the ``--bench-challenge`` flag on
``kryptosbot/run_controller.py`` is the user-facing entrypoint.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


# Keys whose presence in a challenge JSON indicates sealed-answer
# material. The loader refuses any input file containing any of these;
# they belong in the sealed answer file, never on the public side.
_FORBIDDEN_KEYS: frozenset[str] = frozenset({
    "plaintext",
    "answer",
    "answers",
    "encryption_layers_in_order",
    "decryption_layers_in_order",
    "sealed",
    "answer_count",
    "key_material",
    "decryption_key",
    "encryption_key",
    "solution",
    "solution_layers",
})

# Required positions: K4-shaped 24-crib layout (0-indexed). Every
# K4Bench challenge uses these exact positions; only the letters at
# those positions vary.
_REQUIRED_CRIB_POSITIONS: frozenset[int] = frozenset(
    list(range(21, 34)) + list(range(63, 74))
)
_EXPECTED_CT_LEN: int = 97
_EXPECTED_ALPHABET: str = "AZ"
_SCHEMA_VERSION: str = "k4bench.challenge.v1"


class BenchLoaderError(ValueError):
    """Raised when a K4Bench challenge file fails validation.

    The existing controller surfaces this as a startup error rather
    than letting an invalid challenge silently launch a run.
    """


@dataclass(frozen=True)
class K4BenchChallenge:
    """One validated K4Bench public challenge.

    Frozen so the loader cannot accidentally mutate it after handing
    it to the controller. The CT/cribs/clue text are exactly what the
    challenge JSON declares; the loader does not transform them.
    """

    bench_id: str
    suite_id: str
    title: str
    ciphertext: str
    ciphertext_alphabet: str
    crib_dict: Mapping[int, str]
    crib_spans: tuple[tuple[int, int, str, str], ...]  # (start, end_inclusive, text, label)
    clue_text: str
    constraint_summary: tuple[str, ...]
    solver_required_fields: tuple[str, ...]
    strict_pass_rule: str
    known_crib_score_target: int
    challenge_path: Path

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def ciphertext_length(self) -> int:
        return len(self.ciphertext)

    @property
    def n_cribs(self) -> int:
        return len(self.crib_dict)

    @property
    def crib_positions(self) -> tuple[int, ...]:
        return tuple(sorted(self.crib_dict.keys()))

    def ciphertext_sha256(self) -> str:
        return hashlib.sha256(self.ciphertext.encode("ascii")).hexdigest()

    # ------------------------------------------------------------------
    # Kernel override installation
    # ------------------------------------------------------------------

    def install_kernel_overrides(self) -> None:
        """Set ``KRYPTOS_CT_OVERRIDE`` and ``KRYPTOS_CRIB_DICT_OVERRIDE``
        in ``os.environ`` so the kernel constants module loads the
        challenge CT/cribs at first import.

        MUST be called before any ``kryptos.kernel.*`` import in the
        process. The kernel module reads the env vars exactly once at
        import time; later changes do not propagate. The K4Bench loader
        is structured so the entrypoint can call this between argparse
        and any controller import.

        Multiprocessing inheritance: on Linux the Pool default start
        method is ``fork``, so worker processes inherit both the parent
        ``os.environ`` and the parent's already-loaded kernel module
        memory. Either path keeps the override in effect.
        """
        os.environ["KRYPTOS_CT_OVERRIDE"] = self.ciphertext
        os.environ["KRYPTOS_CRIB_DICT_OVERRIDE"] = json.dumps(
            {str(pos): ch for pos, ch in self.crib_dict.items()},
            separators=(",", ":"),
        )
        # Also set a sentinel that downstream observability can pick up
        # without re-reading the challenge JSON.
        os.environ["KRYPTOS_BENCH_ID"] = self.bench_id
        os.environ["KRYPTOS_BENCH_SUITE"] = self.suite_id

    # ------------------------------------------------------------------
    # Controller surfaces
    # ------------------------------------------------------------------

    def canonical_facts(self) -> dict[str, Any]:
        """Return the bench-mode replacement for the real-K4 canonical
        facts dict that ``ResearchController._load_canonical_facts``
        installs on the controller.

        Field names match the real-K4 facts shape so any downstream
        consumer that reads ``facts["ciphertext"]`` / ``facts["cribs"]``
        keeps working under bench mode without a special case.
        """
        return {
            "ciphertext": self.ciphertext,
            "ct_length": self.ciphertext_length,
            "cribs": [
                (start, text)
                for (start, _end, text, _label) in self.crib_spans
            ],
            "n_crib_chars": self.n_cribs,
            "bench_mode": True,
            "bench_id": self.bench_id,
            "suite_id": self.suite_id,
            "title": self.title,
            "clue_text": self.clue_text,
            "constraint_summary": list(self.constraint_summary),
            "solver_required_fields": list(self.solver_required_fields),
            "strict_pass_rule": self.strict_pass_rule,
            "known_crib_score_target": self.known_crib_score_target,
        }

    def prompt_block(self) -> str:
        """Return a self-contained prompt block describing the bench
        challenge.

        Plugged into the theorist and worker prompts in place of the
        real-K4 anchor blocks (Oranchak corpora, serpentine anchor,
        archive seeds) so the model sees ONLY the synthetic challenge.
        Crib spans, clue text, constraint summary, and the solver
        output contract are all printed verbatim.

        The block deliberately does NOT contain the real K4 ciphertext
        or any K4-specific archive material. The
        ``test_bench_prompt_does_not_contain_real_k4_ct`` regression
        pins this property so a future edit cannot leak K4 anchors into
        bench-mode prompts.
        """
        spans_lines = []
        for (start, end, text, label) in self.crib_spans:
            spans_lines.append(
                f"  - {label} @ positions {start}-{end} (inclusive, "
                f"0-indexed): {text!r} ({len(text)} chars)"
            )
        constraint_lines = [f"  - {c}" for c in self.constraint_summary]
        required_fields = ", ".join(self.solver_required_fields)
        return f"""K4BENCH SYNTHETIC CHALLENGE — bench_id={self.bench_id}
suite_id={self.suite_id} | title={self.title!r}

THIS IS NOT REAL K4. This is one challenge from the K4Bench blind
synthetic calibration suite. The ciphertext and cribs below are the
SOLE source of truth. Do not import, recall, or apply any real-K4
ciphertext, real-K4 cribs, real-K4 archive evidence, or real-K4
anomaly registry content as if they applied here — they do not.

CIPHERTEXT ({self.ciphertext_length} chars, alphabet {self.ciphertext_alphabet}):
{self.ciphertext}

KNOWN PLAINTEXT SPANS (24 positions, 0-indexed):
{chr(10).join(spans_lines)}

CONSTRAINT SUMMARY (from challenge clue pack):
{chr(10).join(constraint_lines)}

PUBLIC CLUE TEXT:
{self.clue_text}

SOLVER OUTPUT CONTRACT:
  - Required JSON fields: {required_fields}
  - Strict pass rule: {self.strict_pass_rule}
  - Known crib_score target: {self.known_crib_score_target} (matching
    all 24 declared positions; this alone is NOT a strict pass —
    method/layer order must also be reproducible).
  - Avoid overfitting only the 24 crib positions: a plaintext that
    matches the cribs but reads as noise outside them is a crib-
    overfit and should be reported as such, not as a solve.

PROCEDURAL POLICY:
  - The construction uses hand-executable classical/procedural layers
    only (Vigenere, Beaufort, columnar, route, rail-fence, Atbash,
    affine, Polybius, etc.). No modern cryptographic primitives.
  - All key material needed for the intended solution is derivable
    from the clue pack above.
  - Layer count is between 2 and 3 unless a clue explicitly collapses
    a layer into a simple reversal or mirror.
"""

    # ------------------------------------------------------------------
    # Serialization for diagnostics / attempt artifacts
    # ------------------------------------------------------------------

    def to_summary_dict(self) -> dict[str, Any]:
        """Compact, audit-friendly summary. Safe to log or attach to an
        attempt artifact; contains no answer-derived material."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "bench_id": self.bench_id,
            "suite_id": self.suite_id,
            "title": self.title,
            "ciphertext_length": self.ciphertext_length,
            "ciphertext_sha256": self.ciphertext_sha256(),
            "n_cribs": self.n_cribs,
            "crib_positions": list(self.crib_positions),
            "challenge_path": str(self.challenge_path),
        }


def _ensure_no_forbidden_keys(payload: Mapping[str, Any], path: Path) -> None:
    """Refuse files containing answer-like fields.

    A clean public challenge file must not carry the sealed answer or
    its derivatives. Anything in ``_FORBIDDEN_KEYS`` indicates the
    operator is pointing at the wrong file.
    """
    found: list[str] = []

    def _walk(node: Any, prefix: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                key_lc = str(k).lower()
                if key_lc in _FORBIDDEN_KEYS:
                    found.append(f"{prefix}{k}")
                _walk(v, prefix=f"{prefix}{k}.")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                _walk(item, prefix=f"{prefix}[{i}].")

    _walk(payload)
    if found:
        raise BenchLoaderError(
            f"Challenge file {path} contains forbidden answer-like keys: "
            f"{', '.join(found)}. The K4Bench public challenge must not "
            f"include sealed-answer material. Verify you are pointing at "
            f"the public challenge JSON, not the sealed answer file."
        )


def _validate_payload(payload: Mapping[str, Any], path: Path) -> None:
    """Validate a parsed K4Bench challenge JSON.

    Raises ``BenchLoaderError`` on any structural problem. The checks
    cover schema version, CT length and alphabet, exactly the K4-shape
    crib positions, and consistency between ``known_plaintext_spans``
    and ``known_plaintext_positions``.
    """
    schema = payload.get("schema_version")
    if schema != _SCHEMA_VERSION:
        raise BenchLoaderError(
            f"Unexpected schema_version {schema!r} in {path}; expected "
            f"{_SCHEMA_VERSION!r}"
        )

    bench_id = payload.get("bench_id")
    if not isinstance(bench_id, str) or not bench_id:
        raise BenchLoaderError(f"Missing or empty bench_id in {path}")

    suite_id = payload.get("suite_id")
    if not isinstance(suite_id, str) or not suite_id:
        raise BenchLoaderError(f"Missing or empty suite_id in {path}")

    ct = payload.get("ciphertext")
    if not isinstance(ct, str):
        raise BenchLoaderError(f"ciphertext in {path} is not a string")
    if len(ct) != _EXPECTED_CT_LEN:
        raise BenchLoaderError(
            f"ciphertext in {path} has length {len(ct)}; expected "
            f"{_EXPECTED_CT_LEN}"
        )
    if not ct.isalpha() or not ct.isupper():
        raise BenchLoaderError(
            f"ciphertext in {path} must be uppercase A-Z only; got {ct!r}"
        )

    declared_len = payload.get("ciphertext_length")
    if declared_len is not None and declared_len != len(ct):
        raise BenchLoaderError(
            f"ciphertext_length {declared_len} disagrees with actual "
            f"length {len(ct)} in {path}"
        )

    alphabet = payload.get("ciphertext_alphabet")
    if alphabet != _EXPECTED_ALPHABET:
        raise BenchLoaderError(
            f"ciphertext_alphabet in {path} is {alphabet!r}; expected "
            f"{_EXPECTED_ALPHABET!r}"
        )

    positions = payload.get("known_plaintext_positions")
    if not isinstance(positions, dict) or not positions:
        raise BenchLoaderError(
            f"known_plaintext_positions in {path} is missing or empty"
        )

    parsed_positions: dict[int, str] = {}
    for k, v in positions.items():
        try:
            pos = int(k)
        except (TypeError, ValueError) as exc:
            raise BenchLoaderError(
                f"known_plaintext_positions key {k!r} in {path} is not "
                f"an integer"
            ) from exc
        if not isinstance(v, str) or len(v) != 1 or not v.isupper() or not v.isalpha():
            raise BenchLoaderError(
                f"known_plaintext_positions[{k}] in {path} must be a "
                f"single uppercase A-Z letter; got {v!r}"
            )
        if pos in parsed_positions:
            raise BenchLoaderError(
                f"Duplicate position {pos} in known_plaintext_positions "
                f"of {path}"
            )
        parsed_positions[pos] = v

    if frozenset(parsed_positions.keys()) != _REQUIRED_CRIB_POSITIONS:
        missing = sorted(_REQUIRED_CRIB_POSITIONS - set(parsed_positions.keys()))
        extra = sorted(set(parsed_positions.keys()) - _REQUIRED_CRIB_POSITIONS)
        raise BenchLoaderError(
            f"known_plaintext_positions in {path} must cover exactly the "
            f"K4-shaped 24 positions (21-33, 63-73). Missing={missing}, "
            f"Extra={extra}"
        )

    spans = payload.get("known_plaintext_spans")
    if not isinstance(spans, list) or not spans:
        raise BenchLoaderError(
            f"known_plaintext_spans in {path} is missing or empty"
        )
    for span in spans:
        if not isinstance(span, dict):
            raise BenchLoaderError(
                f"known_plaintext_spans entry {span!r} in {path} is not "
                f"an object"
            )
        for required in ("start", "end_inclusive", "length", "text", "label"):
            if required not in span:
                raise BenchLoaderError(
                    f"known_plaintext_spans entry {span!r} in {path} is "
                    f"missing field {required!r}"
                )
        start = int(span["start"])
        end_inc = int(span["end_inclusive"])
        text = span["text"]
        if not isinstance(text, str) or not text.isalpha() or not text.isupper():
            raise BenchLoaderError(
                f"Span {span!r} in {path}: text must be uppercase A-Z"
            )
        if end_inc - start + 1 != int(span["length"]) or len(text) != int(span["length"]):
            raise BenchLoaderError(
                f"Span {span!r} in {path}: length / start / end_inclusive "
                f"are inconsistent"
            )
        for offset, ch in enumerate(text):
            pos = start + offset
            if pos not in parsed_positions:
                raise BenchLoaderError(
                    f"Span {span!r} in {path} covers position {pos} not "
                    f"present in known_plaintext_positions"
                )
            if parsed_positions[pos] != ch:
                raise BenchLoaderError(
                    f"Span {span!r} in {path}: text[{offset}]={ch!r} "
                    f"disagrees with known_plaintext_positions[{pos}]="
                    f"{parsed_positions[pos]!r}"
                )

    clue_pack = payload.get("public_clue_pack")
    if not isinstance(clue_pack, dict):
        raise BenchLoaderError(
            f"public_clue_pack in {path} is missing or not an object"
        )
    if not isinstance(clue_pack.get("clue_text"), str):
        raise BenchLoaderError(
            f"public_clue_pack.clue_text in {path} is not a string"
        )

    contract = payload.get("solver_output_contract")
    if not isinstance(contract, dict):
        raise BenchLoaderError(
            f"solver_output_contract in {path} is missing or not an object"
        )
    required_fields = contract.get("required_json_fields")
    if not isinstance(required_fields, list) or not required_fields:
        raise BenchLoaderError(
            f"solver_output_contract.required_json_fields in {path} is "
            f"missing or empty"
        )


def load_k4bench_challenge(path: str | Path) -> K4BenchChallenge:
    """Load and validate one K4Bench public challenge JSON.

    Raises ``BenchLoaderError`` on any validation failure. The error
    message names the offending field so the operator can fix the
    file (or, more commonly, point at the right path).

    The loader is intentionally strict: the K4Bench harness exists
    precisely to test the controller against blind, schema-validated
    inputs, so a silent acceptance of a malformed file would defeat
    its purpose.
    """
    challenge_path = Path(path).resolve()
    if not challenge_path.exists():
        raise BenchLoaderError(f"Challenge file does not exist: {challenge_path}")
    if not challenge_path.is_file():
        raise BenchLoaderError(f"Challenge path is not a file: {challenge_path}")

    try:
        payload = json.loads(challenge_path.read_text())
    except json.JSONDecodeError as exc:
        raise BenchLoaderError(
            f"Challenge file {challenge_path} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise BenchLoaderError(
            f"Challenge file {challenge_path} root must be a JSON object"
        )

    _ensure_no_forbidden_keys(payload, challenge_path)
    _validate_payload(payload, challenge_path)

    crib_dict: dict[int, str] = {
        int(k): v for k, v in payload["known_plaintext_positions"].items()
    }
    crib_spans = tuple(
        (
            int(s["start"]),
            int(s["end_inclusive"]),
            str(s["text"]),
            str(s["label"]),
        )
        for s in payload["known_plaintext_spans"]
    )

    contract = payload["solver_output_contract"]
    return K4BenchChallenge(
        bench_id=payload["bench_id"],
        suite_id=payload["suite_id"],
        title=payload.get("title", ""),
        ciphertext=payload["ciphertext"],
        ciphertext_alphabet=payload["ciphertext_alphabet"],
        crib_dict=crib_dict,
        crib_spans=crib_spans,
        clue_text=payload["public_clue_pack"]["clue_text"],
        constraint_summary=tuple(
            payload["public_clue_pack"].get("constraint_summary", [])
        ),
        solver_required_fields=tuple(contract["required_json_fields"]),
        strict_pass_rule=contract.get("strict_pass_rule", ""),
        known_crib_score_target=int(contract.get("known_crib_score_target", 24)),
        challenge_path=challenge_path,
    )


def derive_synthetic_ledger_path(
    bench_id: str,
    *,
    project_root: Path,
    requested: Path | None = None,
) -> Path:
    """Pick a safe synthetic-ledger path for a bench run.

    Refuses any path that points at the real-K4 ledger. The default is
    ``<project_root>/db/k4bench/<bench_id>.sqlite``. An explicitly
    requested path is accepted only if it lives under ``db/k4bench/``
    or carries a ``bench`` / ``synthetic`` segment, so a stray
    ``--db db/theory_ledger.sqlite`` cannot stomp the real ledger.
    """
    real_default = (project_root / "db" / "theory_ledger.sqlite").resolve()
    bench_default = (project_root / "db" / "k4bench" / f"{bench_id}.sqlite").resolve()

    if requested is None:
        return bench_default

    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = (project_root / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if candidate == real_default:
        raise BenchLoaderError(
            f"Refusing to use the real K4 ledger {candidate} for a "
            f"synthetic K4Bench run. Pass --db <path under db/k4bench/> "
            f"or omit --db to default to {bench_default}."
        )

    parts = {p.lower() for p in candidate.parts}
    if not (parts & {"k4bench", "bench", "synthetic"}):
        raise BenchLoaderError(
            f"Refusing to use ledger path {candidate} for a synthetic "
            f"K4Bench run: the path must live under db/k4bench/ or "
            f"contain a 'bench'/'synthetic' segment so it cannot be "
            f"confused with the real-K4 ledger."
        )
    return candidate
