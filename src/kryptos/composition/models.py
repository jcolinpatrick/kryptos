"""Core data models for the composition search framework.

Defines the typed representations for cipher layers, their instances,
ordered composition stacks, and peel-order semantics.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple


# ── Enums ───────────────────────────────────────────────────────────────

class LayerFamily(str, Enum):
    """Supported layer families."""
    IDENTITY = "identity"
    ADDITIVE_MASK = "additive_mask"
    VIGENERE = "vigenere"
    BEAUFORT = "beaufort"
    VAR_BEAUFORT = "var_beaufort"
    TRANSPOSITION_COLUMNAR = "transposition_columnar"
    TRANSPOSITION_MYSZKOWSKI = "transposition_myszkowski"
    TRANSPOSITION_RAIL_FENCE = "transposition_rail_fence"
    TRANSPOSITION_ROUTE = "transposition_route"
    BLOCK_TRANSPOSITION = "block_transposition"
    # Nonstandard / stateful / architecture-specific families (v3)
    BAND_OFFSET = "band_offset"
    POLARITY_SWITCH = "polarity_switch"
    PROGRESSIVE_KEY = "progressive_key"
    STATE_ALPHABET = "state_alphabet"
    BAND_POLARITY = "band_polarity"
    COMPASS_OFFSET = "compass_offset"


class PeelOrder(str, Enum):
    """Which layer to invert first during decryption.

    If encryption was inner(outer(PT)):
      OUTER_FIRST means decrypt outer, then decrypt inner.
      INNER_FIRST means decrypt inner, then decrypt outer.

    For composition A(B(CT)) where A is outer and B is inner:
      OUTER_FIRST: PT = B_inv(A_inv(CT))
      INNER_FIRST: PT = A_inv(B_inv(CT))
    """
    OUTER_FIRST = "outer_first"
    INNER_FIRST = "inner_first"


class PruneType(str, Enum):
    """Classification of a pruning decision."""
    EXACT = "exact"           # Mathematically proven incompatible
    HEURISTIC = "heuristic"   # Statistically unlikely, not proven
    NOT_MODELED = "not_modeled"  # Cannot determine compatibility


class BranchStatus(str, Enum):
    """Status of a composition branch in the ledger."""
    OPEN = "open"
    TESTED = "tested"
    PRUNED = "pruned"
    PARTIAL = "partial"


# ── Layer semantic properties ───────────────────────────────────────────

@dataclass(frozen=True)
class LayerSemantics:
    """Describes how a layer transforms text and which constraints survive.

    These properties enable the constraint propagation engine to prune
    branches without executing them.
    """
    preserves_positions: bool = True
    """If True, output[i] corresponds to input[i] — no reordering."""

    preserves_unigram_frequencies: bool = True
    """If True, letter frequency distribution is unchanged."""

    preserves_length: bool = True
    """If True, len(output) == len(input)."""

    preserves_crib_locality: bool = True
    """If True, adjacent crib characters remain adjacent."""

    changes_effective_key: bool = False
    """If True, the layer modifies effective keystream values (additive)."""

    is_involution: bool = False
    """If True, applying the transform twice returns the original text."""

    position_dependent: bool = False
    """If True, the transform varies by position (e.g., periodic mask)."""

    def to_dict(self) -> Dict[str, bool]:
        return {
            "preserves_positions": self.preserves_positions,
            "preserves_unigram_frequencies": self.preserves_unigram_frequencies,
            "preserves_length": self.preserves_length,
            "preserves_crib_locality": self.preserves_crib_locality,
            "changes_effective_key": self.changes_effective_key,
            "is_involution": self.is_involution,
            "position_dependent": self.position_dependent,
        }


# ── Layer definition (family-level) ────────────────────────────────────

TransformFn = Callable[[str], str]


@dataclass(frozen=True)
class LayerDef:
    """Definition of a layer family.

    This is the family-level metadata. Individual parameterizations
    are represented as LayerInstance.
    """
    family: LayerFamily
    description: str
    semantics: LayerSemantics
    reversible: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family.value,
            "description": self.description,
            "semantics": self.semantics.to_dict(),
            "reversible": self.reversible,
        }


# ── Layer instance (specific parameterization) ─────────────────────────

@dataclass(frozen=True)
class LayerInstance:
    """A specific parameterized instance of a layer family.

    Contains both the configuration needed for reproducibility and
    the callable transforms for execution.
    """
    layer_def: LayerDef
    params: Dict[str, Any] = field(default_factory=dict)
    label: str = ""

    @property
    def family(self) -> LayerFamily:
        return self.layer_def.family

    @property
    def semantics(self) -> LayerSemantics:
        return self.layer_def.semantics

    @property
    def instance_hash(self) -> str:
        """Deterministic hash for dedup and ledger keys."""
        payload = json.dumps(
            {"family": self.family.value, "params": self.params},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @property
    def display_label(self) -> str:
        if self.label:
            return self.label
        parts = [self.family.value]
        for k, v in sorted(self.params.items()):
            if isinstance(v, list) and len(v) > 6:
                parts.append(f"{k}=[{len(v)} items]")
            else:
                parts.append(f"{k}={v}")
        return "/".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family.value,
            "params": self.params,
            "label": self.label,
            "hash": self.instance_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], registry: Any = None) -> "LayerInstance":
        """Reconstruct from serialized dict. Requires registry for layer_def."""
        if registry is None:
            from kryptos.composition.registry import get_layer_def
            layer_def = get_layer_def(LayerFamily(data["family"]))
        else:
            layer_def = registry.get_layer_def(LayerFamily(data["family"]))
        return cls(
            layer_def=layer_def,
            params=data.get("params", {}),
            label=data.get("label", ""),
        )


# ── Composition stack ──────────────────────────────────────────────────

@dataclass(frozen=True)
class CompositionStack:
    """An ordered composition of layers.

    Represents the encryption model: layers[0](layers[1](...(PT)...)).
    layers[0] is the outermost layer; layers[-1] is the innermost.

    Decryption peels from outside in by default (OUTER_FIRST).
    """
    layers: Tuple[LayerInstance, ...]
    peel_order: PeelOrder = PeelOrder.OUTER_FIRST
    description: str = ""

    @property
    def depth(self) -> int:
        return len(self.layers)

    @property
    def outer(self) -> LayerInstance:
        """The outermost layer (applied last during encryption)."""
        return self.layers[0]

    @property
    def inner(self) -> LayerInstance:
        """The innermost layer (applied first during encryption)."""
        return self.layers[-1]

    @property
    def stack_hash(self) -> str:
        """Deterministic hash for the full composition."""
        payload = json.dumps(
            {
                "layers": [l.to_dict() for l in self.layers],
                "peel_order": self.peel_order.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    @property
    def campaign_key(self) -> str:
        """Human-readable key for campaign grouping."""
        families = "+".join(l.family.value for l in self.layers)
        return f"{families}/{self.peel_order.value}"

    @property
    def preserves_positions(self) -> bool:
        """True only if ALL layers preserve positions."""
        return all(l.semantics.preserves_positions for l in self.layers)

    @property
    def preserves_frequencies(self) -> bool:
        """True only if ALL layers preserve unigram frequencies."""
        return all(l.semantics.preserves_unigram_frequencies for l in self.layers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layers": [l.to_dict() for l in self.layers],
            "peel_order": self.peel_order.value,
            "description": self.description,
            "stack_hash": self.stack_hash,
            "campaign_key": self.campaign_key,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CompositionStack":
        layers = tuple(LayerInstance.from_dict(d) for d in data["layers"])
        return cls(
            layers=layers,
            peel_order=PeelOrder(data.get("peel_order", "outer_first")),
            description=data.get("description", ""),
        )


# ── Pruning result ─────────────────────────────────────────────────────

@dataclass
class PruneResult:
    """Result of a pruning check on a composition branch."""
    pruned: bool
    prune_type: PruneType = PruneType.NOT_MODELED
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def pass_() -> "PruneResult":
        return PruneResult(pruned=False)

    @staticmethod
    def exact(reason: str, **details: Any) -> "PruneResult":
        return PruneResult(
            pruned=True,
            prune_type=PruneType.EXACT,
            reason=reason,
            details=details,
        )

    @staticmethod
    def heuristic(reason: str, **details: Any) -> "PruneResult":
        return PruneResult(
            pruned=True,
            prune_type=PruneType.HEURISTIC,
            reason=reason,
            details=details,
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "pruned": self.pruned,
            "prune_type": self.prune_type.value,
        }
        if self.pruned:
            d["reason"] = self.reason
            if self.details:
                d["details"] = self.details
        return d


# ── Composition result ─────────────────────────────────────────────────

@dataclass
class CompositionResult:
    """Result of evaluating a single composition stack."""
    stack: CompositionStack
    intermediate_text: str = ""
    plaintext: str = ""
    crib_score: int = 0
    bean_pass: bool = False
    ic_value: float = 0.0
    ngram_score: Optional[float] = None
    score_breakdown: Optional[Dict[str, Any]] = None
    pruned: bool = False
    prune_result: Optional[PruneResult] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_storable(self) -> bool:
        from kryptos.kernel.constants import STORE_THRESHOLD
        return self.crib_score >= STORE_THRESHOLD

    @property
    def is_signal(self) -> bool:
        from kryptos.kernel.constants import SIGNAL_THRESHOLD
        return self.crib_score >= SIGNAL_THRESHOLD

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "stack": self.stack.to_dict(),
            "crib_score": self.crib_score,
            "bean_pass": self.bean_pass,
            "ic_value": self.ic_value,
            "pruned": self.pruned,
        }
        if self.plaintext:
            d["plaintext"] = self.plaintext
        if self.intermediate_text:
            d["intermediate_text"] = self.intermediate_text
        if self.ngram_score is not None:
            d["ngram_score"] = self.ngram_score
        if self.score_breakdown:
            d["score_breakdown"] = self.score_breakdown
        if self.prune_result:
            d["prune_result"] = self.prune_result.to_dict()
        if self.metadata:
            d["metadata"] = self.metadata
        return d
