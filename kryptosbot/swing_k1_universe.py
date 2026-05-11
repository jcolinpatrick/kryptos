"""Swing K-1 config-tuple enumerator with universe hash."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Literal, Optional, Tuple

from kryptosbot.swing_k1_masks import Mask, build_mask_catalog

ModelVariant = Literal["M1", "M2", "M3", "M4", "M5"]
Variant = Literal["vigenere", "beaufort", "var_beaufort"]
Alphabet = Literal["AZ", "KA"]
NullRule = Literal["skip", "consume"]

M4_TAPE_LENGTHS: Tuple[int, ...] = (24, 30, 36, 49, 60, 73)
M5_SEGMENTATIONS: Tuple[Tuple[int, ...], ...] = (
    (21,), (34,), (63,),
    (21, 34), (21, 63), (34, 63),
    (21, 34, 63),
)


@dataclass(frozen=True)
class Config:
    spec_hash: str
    model_variant: ModelVariant
    variant: Variant
    alphabet: Alphabet
    mask_id: str
    null_positions: FrozenSet[int]
    null_consumption_mode: NullRule
    tape_length: Optional[int]
    segment_boundaries: Optional[Tuple[int, ...]]
    control_arm: bool


def _compute_spec_hash(canonical: dict) -> str:
    serial = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serial.encode("utf-8")).hexdigest()


def _canonical(c_dict: dict) -> dict:
    # Convert FrozenSets and tuples to sorted lists for hashing
    out = {}
    for k, v in c_dict.items():
        if isinstance(v, frozenset):
            out[k] = sorted(v)
        elif isinstance(v, tuple):
            out[k] = list(v)
        else:
            out[k] = v
    return out


def _make_config(
    model_variant: ModelVariant,
    variant: Variant,
    alphabet: Alphabet,
    mask: Mask,
    null_consumption_mode: NullRule,
    tape_length: Optional[int],
    segment_boundaries: Optional[Tuple[int, ...]],
    control_arm: bool,
) -> Config:
    canonical = _canonical({
        "model_variant": model_variant,
        "variant": variant,
        "alphabet": alphabet,
        "mask_id": mask.mask_id,
        "null_positions": mask.positions,
        "null_consumption_mode": null_consumption_mode,
        "tape_length": tape_length,
        "segment_boundaries": segment_boundaries,
        "control_arm": control_arm,
    })
    spec_hash = _compute_spec_hash(canonical)
    return Config(
        spec_hash=spec_hash,
        model_variant=model_variant,
        variant=variant,
        alphabet=alphabet,
        mask_id=mask.mask_id,
        null_positions=mask.positions,
        null_consumption_mode=null_consumption_mode,
        tape_length=tape_length,
        segment_boundaries=segment_boundaries,
        control_arm=control_arm,
    )


# A synthetic "empty mask" sentinel for M1 control-arm configs.
_EMPTY_MASK = Mask(
    mask_id="EMPTY_MASK",
    class_label="sentinel",  # sentinel class for M1 control arm; never a real mask
    positions=frozenset(),
    params=(("special", "control_arm_empty"),),
)


def enumerate_universe() -> Iterable[Config]:
    """Yield every (model, variant, alphabet, mask, rule, ...) config in the universe.

    The order is deterministic so the universe hash is stable.
    """
    catalog = build_mask_catalog()
    variants: tuple[Variant, ...] = ("beaufort", "var_beaufort", "vigenere")
    alphabets: tuple[Alphabet, ...] = ("AZ", "KA")
    for v in variants:
        for a in alphabets:
            # M1 control arm: empty mask, no nulls.
            yield _make_config(
                model_variant="M1",
                variant=v,
                alphabet=a,
                mask=_EMPTY_MASK,
                null_consumption_mode="skip",
                tape_length=None,
                segment_boundaries=None,
                control_arm=True,
            )
            for m in catalog:
                # M2: consume.
                yield _make_config("M2", v, a, m, "consume", None, None, False)
                # M3: skip.
                yield _make_config("M3", v, a, m, "skip", None, None, False)
                # M4: 6 tape lengths.
                for L in M4_TAPE_LENGTHS:
                    yield _make_config("M4", v, a, m, "skip", L, None, False)
                # M5: 7 segmentation sets.
                for seg in M5_SEGMENTATIONS:
                    yield _make_config("M5", v, a, m, "skip", None, seg, False)


def compute_universe_hash(target_null_counts: Tuple[int, ...] = (17, 20, 24, 28)) -> str:
    """SHA-256 over the sorted, canonical serialization of every spec_hash in the universe."""
    from kryptosbot.swing_k1_masks import build_mask_catalog
    catalog = build_mask_catalog(target_null_counts=target_null_counts)
    spec_hashes: list[str] = []
    variants: tuple[Variant, ...] = ("beaufort", "var_beaufort", "vigenere")
    alphabets: tuple[Alphabet, ...] = ("AZ", "KA")
    for v in variants:
        for a in alphabets:
            spec_hashes.append(
                _make_config("M1", v, a, _EMPTY_MASK, "skip", None, None, True).spec_hash
            )
            for m in catalog:
                spec_hashes.append(_make_config("M2", v, a, m, "consume", None, None, False).spec_hash)
                spec_hashes.append(_make_config("M3", v, a, m, "skip", None, None, False).spec_hash)
                for L in M4_TAPE_LENGTHS:
                    spec_hashes.append(_make_config("M4", v, a, m, "skip", L, None, False).spec_hash)
                for seg in M5_SEGMENTATIONS:
                    spec_hashes.append(_make_config("M5", v, a, m, "skip", None, seg, False).spec_hash)
    spec_hashes.sort()
    return hashlib.sha256("\n".join(spec_hashes).encode("utf-8")).hexdigest()


def universe_summary() -> dict:
    per_model = {"M1": 0, "M2": 0, "M3": 0, "M4": 0, "M5": 0}
    total = 0
    for c in enumerate_universe():
        per_model[c.model_variant] += 1
        total += 1
    return {
        "total_config_count": total,
        "per_model": per_model,
        "universe_hash": compute_universe_hash(),
    }
