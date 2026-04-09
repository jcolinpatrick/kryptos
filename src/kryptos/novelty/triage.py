"""Triage layer — cheap tests to prioritize hypotheses.

Runs fast, lightweight tests on hypotheses before committing to
expensive full sweeps. Promotes top candidates and records all results.
"""
from __future__ import annotations

from typing import List, Optional

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, NOISE_FLOOR
from kryptos.kernel.text import sanitize, text_to_nums
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, remove_additive_mask,
)
from kryptos.kernel.constraints.crib import crib_score
from kryptos.kernel.scoring.ic import ic
from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
from kryptos.admissibility.certificate import (
    EliminationCertificate,
    EliminationReason,
    certificate_to_json,
)
from kryptos.admissibility.corpus_policy import (
    _path_to_source_id,
    check_corpus_source,
    resolve_license_path,
)
from kryptos.admissibility.procedure_policy import check_cipher_procedure


def _gate_bespoke_procedure(hyp: Hypothesis) -> Optional[Hypothesis]:
    """Procedure-policy gate for bespoke hypotheses.

    If `hyp.bespoke` is False this is a no-op and returns None (the caller
    should proceed with normal triage). If `hyp.bespoke` is True, the
    hypothesis is rejected unless `hyp.procedure_id` names a procedure on
    the allowlist.

    Returns:
        None if the hypothesis is not bespoke (proceed normally), or if
        the bespoke hypothesis passes the gate.

        A modified `Hypothesis` with status=ELIMINATED and a JSON
        certificate in `elimination_reason` if the bespoke hypothesis is
        rejected.
    """
    if not hyp.bespoke:
        return None

    if not hyp.procedure_id:
        cert = EliminationCertificate(
            family="bespoke_cipher",
            reason=EliminationReason.PROCEDURE_POLICY_VIOLATION,
            summary=(
                "Bespoke cipher hypothesis declared bespoke=True but did "
                "not provide a procedure_id. Every bespoke hypothesis "
                "must name a licensed procedure on the allowlist."
            ),
            assumptions=[
                "Bespoke cipher hypotheses require an admissible procedure",
                "procedure_id must be set when bespoke=True",
            ],
            evidence={
                "hypothesis_id": hyp.hypothesis_id,
                "description": hyp.description[:200],
                "bespoke": True,
                "procedure_id": None,
            },
            solver="manual",
            is_exact=False,
        )
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = cert.summary
        hyp.elimination_reason = certificate_to_json(cert)
        return hyp

    ok, cert = check_cipher_procedure(
        hyp.procedure_id, family="bespoke_cipher"
    )
    if not ok and cert is not None:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = cert.summary
        hyp.elimination_reason = certificate_to_json(cert)
        return hyp

    return None


def triage_running_key(hyp: Hypothesis) -> Hypothesis:
    """Triage a running-key hypothesis by sampling offsets.

    Tests a sample of offsets and checks crib scores.
    """
    from pathlib import Path
    import random

    params = hyp.transform_stack[0].get("params", {})
    caller_source_path = params.get("source_path", "")
    source_id = params.get("source_id", "")
    variant_name = hyp.transform_stack[0].get("type", "vigenere")

    # ── Corpus admissibility gate (admissibility-first) ─────────────────
    # Step 1: determine a canonical source_id.  If the caller passed one
    # we use it directly; otherwise we heuristically map the supplied
    # path to a known source_id.  Either way, the caller's source_path
    # is only a *hint* for mapping — it is never used to read bytes.
    if source_id:
        ok, cert = check_corpus_source(
            source_id, family="running_key", is_source_id=True,
        )
        resolved_source_id: Optional[str] = source_id if ok else None
    else:
        ok, cert = check_corpus_source(
            caller_source_path, family="running_key", is_source_id=False,
        )
        resolved_source_id = (
            _path_to_source_id(caller_source_path) if ok else None
        )

    if not ok and cert is not None:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = cert.summary
        hyp.elimination_reason = certificate_to_json(cert)
        return hyp

    # Step 2: resolve the bytes from the *license*, never from the
    # caller-supplied path.  This closes the source_id/source_path
    # bypass where a valid source_id could be paired with an arbitrary
    # source_path to smuggle unlicensed bytes through the gate.
    license_path = (
        resolve_license_path(resolved_source_id)
        if resolved_source_id else None
    )
    if license_path is None:
        miss_cert = EliminationCertificate(
            family="running_key",
            reason=EliminationReason.ASSUMPTION_UNMET,
            summary=(
                f"Source id {resolved_source_id!r} is allowlisted but its "
                f"provenance URI cannot be resolved to a concrete readable "
                f"file — licensed sources must be file-backed for the "
                f"admissibility gate to attest the bytes consumed."
            ),
            assumptions=[
                "Licensed sources must have a resolvable provenance_uri",
                "Caller-supplied source_path is a mapping hint, not a data source",
            ],
            evidence={
                "resolved_source_id": resolved_source_id,
                "caller_source_path": caller_source_path,
            },
            solver="manual",
            is_exact=False,
        )
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = miss_cert.summary
        hyp.elimination_reason = certificate_to_json(miss_cert)
        return hyp

    try:
        raw = license_path.read_text(errors="replace")
    except (FileNotFoundError, OSError):
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = f"Licensed source unreadable: {license_path}"
        return hyp

    clean = sanitize(raw)
    if len(clean) < CT_LEN:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "Source text too short"
        return hyp

    n_offsets = len(clean) - CT_LEN + 1
    sample_size = min(200, n_offsets)

    rng = random.Random(42)  # Deterministic seed
    offsets = rng.sample(range(n_offsets), sample_size)

    best_score = 0
    best_offset = 0
    scores: list[int] = []

    for offset in offsets:
        key = text_to_nums(clean[offset:offset + CT_LEN])
        pt = decrypt_text(CT, key, CipherVariant(variant_name))
        sc = crib_score(pt)
        scores.append(sc)
        if sc > best_score:
            best_score = sc
            best_offset = offset

    avg_score = sum(scores) / len(scores) if scores else 0
    above_noise = sum(1 for s in scores if s > NOISE_FLOOR)

    # Score: ratio of best to theoretical max, boosted by above-noise count
    triage = min(1.0, best_score / 24.0 + above_noise / sample_size * 0.1)

    hyp.triage_score = triage
    hyp.triage_detail = (
        f"Sampled {sample_size}/{n_offsets} offsets. "
        f"Best: {best_score}/24 at offset {best_offset}. "
        f"Avg: {avg_score:.1f}. Above noise: {above_noise}/{sample_size}."
    )

    if best_score >= 10:
        hyp.status = HypothesisStatus.PROMOTED
    elif best_score > NOISE_FLOOR:
        hyp.status = HypothesisStatus.TRIAGED
    else:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.elimination_reason = f"Best score {best_score} at noise floor"

    return hyp


def triage_simple_key(hyp: Hypothesis) -> Hypothesis:
    """Triage a hypothesis with a fixed key (date-derived, etc.)."""
    params = hyp.transform_stack[0].get("params", {})
    key = params.get("key", [])
    variant_name = hyp.transform_stack[0].get("type", "vigenere")

    if not key:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "No key provided"
        return hyp

    pt = decrypt_text(CT, key, CipherVariant(variant_name))
    sc = crib_score(pt)
    text_ic = ic(pt)

    hyp.triage_score = sc / 24.0
    hyp.triage_detail = f"Score: {sc}/24, IC: {text_ic:.4f}"

    if sc >= 10:
        hyp.status = HypothesisStatus.PROMOTED
    elif sc > NOISE_FLOOR:
        hyp.status = HypothesisStatus.TRIAGED
    else:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.elimination_reason = f"Score {sc} at noise floor"

    return hyp


def triage_hypothesis(hyp: Hypothesis) -> Hypothesis:
    """Route a hypothesis to the appropriate triage function."""
    # Procedure-policy gate for bespoke-cipher hypotheses. Runs BEFORE
    # any other check so an unlicensed bespoke hypothesis is eliminated
    # cleanly with a PROCEDURE_POLICY_VIOLATION certificate even if its
    # transform_stack is malformed or empty.
    gated = _gate_bespoke_procedure(hyp)
    if gated is not None:
        return gated

    if not hyp.transform_stack:
        hyp.status = HypothesisStatus.ELIMINATED
        hyp.triage_score = 0.0
        hyp.triage_detail = "No transform stack defined"
        return hyp

    first_type = hyp.transform_stack[0].get("type", "")
    params = hyp.transform_stack[0].get("params", {})

    if params.get("key_source") == "running_key":
        return triage_running_key(hyp)
    elif params.get("key"):
        return triage_simple_key(hyp)
    else:
        # Default: mark as triaged with neutral score
        hyp.status = HypothesisStatus.TRIAGED
        hyp.triage_score = 0.5
        hyp.triage_detail = "No specific triage available; needs manual review"
        return hyp


def triage_batch(hypotheses: List[Hypothesis]) -> List[Hypothesis]:
    """Triage a batch of hypotheses and return sorted by priority."""
    results = [triage_hypothesis(h) for h in hypotheses]
    # Sort by priority score (highest first)
    results.sort(key=lambda h: h.priority_score, reverse=True)
    return results
