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
        if direction == "decrypt":
            return lambda text, k=key, v=variant: decrypt_text(text, k, v)
        else:
            return lambda text, k=key, v=variant: encrypt_text(text, k, v)

    elif t == TransformType.BIFID:
        from kryptos.kernel.transforms.polybius import bifid_decrypt, bifid_encrypt, make_polybius_5x5
        grid = make_polybius_5x5(p.get("keyword", ""), p.get("merge", "IJ"))
        period = p.get("period", 0)
        direction = p.get("direction", "decrypt")
        if direction == "decrypt":
            return lambda text, g=grid, per=period: bifid_decrypt(text, g, per)
        else:
            return lambda text, g=grid, per=period: bifid_encrypt(text, g, per)

    elif t == TransformType.CUSTOM:
        raise ValueError("Custom transforms must be provided as functions, not configs")

    else:
        raise ValueError(f"Unknown transform type: {t}")


def build_pipeline(config: PipelineConfig) -> TransformFn:
    """Build a complete transform pipeline from a PipelineConfig."""
    transforms = [build_transform(step) for step in config.steps]
    return compose(transforms)
