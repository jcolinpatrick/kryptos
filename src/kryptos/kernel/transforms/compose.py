"""Composable transform pipelines.

Allows chaining arbitrary transforms with typed configs. Each transform
is a function text -> text with an associated config for reproducibility.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class TransformType(str, Enum):
    """Types of transforms in a pipeline."""
    TRANSPOSITION_FULL = "transposition_full"
    TRANSPOSITION_BLOCK = "transposition_block"
    ADDITIVE_MASK = "additive_mask"
    VIGENERE = "vigenere"
    BEAUFORT = "beaufort"
    VAR_BEAUFORT = "var_beaufort"
    BIFID = "bifid"
    TRIFID = "trifid"
    # R3-0.5-2: Cardano-grille gather under the permutation-only
    # interpretation. Shape-identical to TRANSPOSITION_FULL with
    # direction="apply" but kept as its own enum value so step dicts
    # record the grille semantics explicitly. Dispatches to
    # kryptos.kernel.transforms.grille.apply_grille_permutation.
    GRILLE = "grille"
    # B-DSL-expanded (2026-04-22): Quagmire III routed as a first-class
    # kernel transform. Dispatches to
    # kryptos.kernel.transforms.quagmire.quagmire_{encrypt,decrypt}. The
    # K1/K2 convention (both ct_alphabet_keyword AND pt_alphabet_keyword
    # set to the same keyword + indicator = first letter of that keyword)
    # is enforced by the dispatcher translator, not by this transform —
    # the transform just calls the kernel function with the params it
    # receives.
    QUAGMIRE = "quagmire"
    # B-DSL-expanded (2026-05-03): finite-tape additive cipher with optional
    # null insertion. Dispatches to
    # kryptos.kernel.transforms.key_tape.apply_key_tape.
    KEY_TAPE = "key_tape"
    IDENTITY = "identity"
    CUSTOM = "custom"


@dataclass(frozen=True)
class TransformConfig:
    """Configuration for a single transform step.

    Immutable and serializable for reproducibility.
    """
    transform_type: TransformType
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    @property
    def config_hash(self) -> str:
        """Deterministic hash for deduplication."""
        payload = json.dumps(
            {"type": self.transform_type.value, "params": self.params},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.transform_type.value,
            "params": self.params,
            "description": self.description,
        }


@dataclass(frozen=True)
class PipelineConfig:
    """Configuration for a sequence of transform steps.

    Defines a complete encryption/decryption pipeline.
    """
    name: str
    steps: Tuple[TransformConfig, ...]
    direction: str = "decrypt"  # "encrypt" or "decrypt"

    @property
    def pipeline_hash(self) -> str:
        """Deterministic hash of the full pipeline."""
        payload = json.dumps(
            {
                "name": self.name,
                "direction": self.direction,
                "steps": [s.to_dict() for s in self.steps],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "direction": self.direction,
            "steps": [s.to_dict() for s in self.steps],
            "hash": self.pipeline_hash,
        }


# ── Transform function type ──────────────────────────────────────────────

TransformFn = Callable[[str], str]


def identity(text: str) -> str:
    """Identity transform — returns text unchanged."""
    return text


def compose(transforms: List[TransformFn]) -> TransformFn:
    """Compose a list of transforms into a single function.

    Applies transforms left-to-right: compose([f, g, h])(x) = h(g(f(x))).
    """
    def composed(text: str) -> str:
        result = text
        for fn in transforms:
            result = fn(result)
        return result
    return composed


def build_transform(config: TransformConfig) -> TransformFn:
    """Build a transform function from a config.

    This is the canonical way to instantiate transforms from configs.
    Returns a callable that transforms text.
    """
    from kryptos.kernel.transforms.vigenere import (
        decrypt_text, encrypt_text, remove_additive_mask, apply_additive_mask,
        CipherVariant,
    )
    from kryptos.kernel.transforms.transposition import (
        apply_perm, invert_perm, unmask_block_transposition,
    )

    t = config.transform_type
    p = config.params

    if t == TransformType.IDENTITY:
        return identity

    elif t == TransformType.ADDITIVE_MASK:
        keyword = p.get("keyword", "NONE")
        direction = p.get("direction", "remove")
        if direction == "remove":
            return lambda text, kw=keyword: remove_additive_mask(text, kw)
        else:
            return lambda text, kw=keyword: apply_additive_mask(text, kw)

    elif t == TransformType.TRANSPOSITION_FULL:
        perm = p["perm"]
        direction = p.get("direction", "undo")
        if direction == "undo":
            inv = invert_perm(perm)
            return lambda text, ip=inv: apply_perm(text, ip)
        else:
            return lambda text, pm=perm: apply_perm(text, pm)

    elif t == TransformType.TRANSPOSITION_BLOCK:
        perm = p["perm"]
        boustro = p.get("cycle_boustro", False)
        return lambda text, pm=perm, b=boustro: unmask_block_transposition(text, pm, b)

    elif t in (TransformType.VIGENERE, TransformType.BEAUFORT, TransformType.VAR_BEAUFORT):
        key = p["key"]
        variant_map = {
            TransformType.VIGENERE: CipherVariant.VIGENERE,
            TransformType.BEAUFORT: CipherVariant.BEAUFORT,
            TransformType.VAR_BEAUFORT: CipherVariant.VAR_BEAUFORT,
        }
        variant = variant_map[t]
        direction = p.get("direction", "decrypt")
        # R2-2 (2026-04-21): optional alphabet_sequence param routes through
        # keyword-mixed / KA tableaux. When absent the AZ fast path is used
        # (zero behavior change for Phase 4 callers).
        alph_seq = p.get("alphabet_sequence")
        if alph_seq is not None:
            from kryptos.kernel.alphabet import Alphabet
            alph_obj = Alphabet(p.get("alphabet_label", "custom"), alph_seq)
        else:
            alph_obj = None
        if direction == "decrypt":
            return lambda text, k=key, v=variant, a=alph_obj: decrypt_text(text, k, v, a)
        else:
            return lambda text, k=key, v=variant, a=alph_obj: encrypt_text(text, k, v, a)

    elif t == TransformType.BIFID:
        from kryptos.kernel.transforms.polybius import bifid_decrypt, bifid_encrypt, make_polybius_5x5
        grid = make_polybius_5x5(p.get("keyword", ""), p.get("merge", "IJ"))
        period = p.get("period", 0)
        direction = p.get("direction", "decrypt")
        if direction == "decrypt":
            return lambda text, g=grid, per=period: bifid_decrypt(text, g, per)
        else:
            return lambda text, g=grid, per=period: bifid_encrypt(text, g, per)

    elif t == TransformType.GRILLE:
        # R3-0.5-2: Cardano-grille gather. Mask order is a permutation
        # of range(CT_LEN); output[i] = input[mask_order[i]]. Validated
        # by the dispatcher translator; reaching this point means the
        # mask is well-formed.
        from kryptos.kernel.transforms.grille import apply_grille_permutation
        mask_order = p["mask_order"]
        return lambda text, m=mask_order: apply_grille_permutation(text, m)

    elif t == TransformType.QUAGMIRE:
        # B-DSL-expanded (2026-04-22): Quagmire III / IV routed via the
        # kernel's quagmire_encrypt / quagmire_decrypt functions. The
        # K1/K2 calling convention (pt_alphabet_keyword AND
        # ct_alphabet_keyword both set to the same mixed-alphabet
        # keyword, indicator = first letter of that keyword) is the
        # caller's responsibility — the dispatcher translator enforces
        # it. This transform just forwards params.
        from kryptos.kernel.transforms.quagmire import (
            quagmire_decrypt, quagmire_encrypt,
        )
        period_keyword = p["period_keyword"]
        indicator = p.get("indicator", "A")
        ct_alphabet_keyword = p.get("ct_alphabet_keyword", "")
        pt_alphabet_keyword = p.get("pt_alphabet_keyword", "")
        direction = p.get("direction", "decrypt")
        if direction == "decrypt":
            return (
                lambda text, pk=period_keyword, ind=indicator,
                       cak=ct_alphabet_keyword, pak=pt_alphabet_keyword:
                quagmire_decrypt(text, pk, ind, cak, pak)
            )
        else:
            return (
                lambda text, pk=period_keyword, ind=indicator,
                       cak=ct_alphabet_keyword, pak=pt_alphabet_keyword:
                quagmire_encrypt(text, pk, ind, cak, pak)
            )

    elif t == TransformType.KEY_TAPE:
        # B-DSL-expanded (2026-05-03): finite-tape additive cipher with
        # optional null insertion. Dispatches to apply_key_tape in the
        # kernel. Variant string is passed as a CipherVariant enum value
        # (str, Enum — construction from string works directly).
        from kryptos.kernel.transforms.key_tape import apply_key_tape
        from kryptos.kernel.transforms.vigenere import CipherVariant
        from kryptos.kernel.alphabet import AZ, KA
        tape = tuple(p["tape"])
        variant_str = p["variant"]
        variant = CipherVariant(variant_str)
        direction = p.get("direction", "decrypt")
        null_positions = frozenset(p.get("null_positions", frozenset()))
        null_rule = p.get("null_rule")
        if null_rule is None:
            if null_positions:
                raise ValueError(
                    "key_tape: null_rule required when null_positions is non-empty"
                )
            null_rule = "skip"
        alphabet_str = p.get("alphabet", "AZ")
        if alphabet_str == "AZ":
            alpha = AZ
        elif alphabet_str == "KA":
            alpha = KA
        else:
            raise ValueError(
                f"key_tape: unsupported alphabet {alphabet_str!r}; "
                "expected 'AZ' or 'KA'"
            )
        return (
            lambda text, tp=tape, v=variant, d=direction,
                   np=null_positions, nr=null_rule, a=alpha:
            apply_key_tape(text, tp, variant=v, direction=d,
                           null_positions=np, null_rule=nr, alphabet=a)
        )

    elif t == TransformType.CUSTOM:
        raise ValueError("Custom transforms must be provided as functions, not configs")

    else:
        raise ValueError(f"Unknown transform type: {t}")


def build_pipeline(config: PipelineConfig) -> TransformFn:
    """Build a complete transform pipeline from a PipelineConfig."""
    transforms = [build_transform(step) for step in config.steps]
    return compose(transforms)
