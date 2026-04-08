"""Layer family registry.

Maps LayerFamily enums to LayerDef metadata and provides factories
that produce executable (forward, inverse) transform pairs from params.

All actual cipher operations delegate to kernel/transforms/ — this module
only adds semantic metadata and a uniform interface.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from kryptos.composition.models import (
    LayerDef,
    LayerFamily,
    LayerInstance,
    LayerSemantics,
    TransformFn,
)


# ── Transform factory type ─────────────────────────────────────────────

# Given params dict, returns (forward_fn, inverse_fn).
# forward = encryption direction; inverse = decryption direction.
TransformFactory = Callable[[Dict[str, Any]], Tuple[TransformFn, TransformFn]]


# ── Registry storage ───────────────────────────────────────────────────

_LAYER_DEFS: Dict[LayerFamily, LayerDef] = {}
_FACTORIES: Dict[LayerFamily, TransformFactory] = {}
_PARAM_GENERATORS: Dict[LayerFamily, Callable[..., List[Dict[str, Any]]]] = {}


def register_layer(
    family: LayerFamily,
    layer_def: LayerDef,
    factory: TransformFactory,
    param_generator: Optional[Callable[..., List[Dict[str, Any]]]] = None,
) -> None:
    """Register a layer family with its definition and factory."""
    _LAYER_DEFS[family] = layer_def
    _FACTORIES[family] = factory
    if param_generator is not None:
        _PARAM_GENERATORS[family] = param_generator


def get_layer_def(family: LayerFamily) -> LayerDef:
    """Get the LayerDef for a registered family."""
    if family not in _LAYER_DEFS:
        raise KeyError(f"Layer family {family.value!r} not registered")
    return _LAYER_DEFS[family]


def get_factory(family: LayerFamily) -> TransformFactory:
    """Get the transform factory for a registered family."""
    if family not in _FACTORIES:
        raise KeyError(f"Layer family {family.value!r} not registered")
    return _FACTORIES[family]


def build_transforms(instance: LayerInstance) -> Tuple[TransformFn, TransformFn]:
    """Build (forward, inverse) transforms for a layer instance."""
    factory = get_factory(instance.family)
    return factory(instance.params)


def make_instance(
    family: LayerFamily,
    params: Optional[Dict[str, Any]] = None,
    label: str = "",
) -> LayerInstance:
    """Convenience: create a LayerInstance from family + params."""
    layer_def = get_layer_def(family)
    return LayerInstance(
        layer_def=layer_def,
        params=params or {},
        label=label,
    )


def generate_params(
    family: LayerFamily,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Generate parameter combinations for a family.

    Each family can register a parameter generator that produces
    a list of param dicts to sweep.
    """
    if family not in _PARAM_GENERATORS:
        return [{}]
    return _PARAM_GENERATORS[family](**kwargs)


def registered_families() -> List[LayerFamily]:
    """List all registered layer families."""
    return list(_LAYER_DEFS.keys())


# ══════════════════════════════════════════════════════════════════════════
# Built-in layer family registrations
# ══════════════════════════════════════════════════════════════════════════


def _register_identity() -> None:
    """Identity (no-op) layer — used for control experiments."""
    layer_def = LayerDef(
        family=LayerFamily.IDENTITY,
        description="Identity (no-op) — returns text unchanged",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=False,
            is_involution=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        def ident(text: str) -> str:
            return text
        return ident, ident

    register_layer(LayerFamily.IDENTITY, layer_def, factory)


def _register_additive_mask() -> None:
    """Additive mask layer — shifts each position by keyword values mod 26."""
    from kryptos.kernel.transforms.vigenere import apply_additive_mask, remove_additive_mask

    layer_def = LayerDef(
        family=LayerFamily.ADDITIVE_MASK,
        description="Additive (Vigenere-style) mask: shifts positions by keyword",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,  # shifts change distribution
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        def forward(text: str, kw: str = keyword) -> str:
            return apply_additive_mask(text, kw)
        def inverse(text: str, kw: str = keyword) -> str:
            return remove_additive_mask(text, kw)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.ADDITIVE_MASK, layer_def, factory, param_gen)


def _register_columnar() -> None:
    """Columnar transposition layer."""
    from kryptos.kernel.transforms.transposition import (
        apply_perm, invert_perm, columnar_perm, keyword_to_order,
    )
    from kryptos.kernel.constants import CT_LEN

    layer_def = LayerDef(
        family=LayerFamily.TRANSPOSITION_COLUMNAR,
        description="Columnar transposition: fill rows, read by keyword-ordered columns",
        semantics=LayerSemantics(
            preserves_positions=False,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=False,
            changes_effective_key=False,
            is_involution=False,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        length = params.get("length", CT_LEN)
        if "perm" in params:
            perm = params["perm"]
        else:
            keyword = params["keyword"]
            width = params.get("width", len(keyword))
            order = keyword_to_order(keyword, width)
            if order is None:
                raise ValueError(f"Keyword {keyword!r} too short for width {width}")
            perm = columnar_perm(width, order, length)
        inv = invert_perm(perm)

        def forward(text: str, p: list = perm) -> str:
            return apply_perm(text, p)

        def inverse(text: str, ip: list = inv) -> str:
            return apply_perm(text, ip)

        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        widths: Optional[List[int]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        results: list[Dict[str, Any]] = []
        for kw in keywords:
            if widths:
                for w in widths:
                    if len(kw) >= w:
                        results.append({"keyword": kw, "width": w})
            else:
                results.append({"keyword": kw, "width": len(kw)})
        return results

    register_layer(LayerFamily.TRANSPOSITION_COLUMNAR, layer_def, factory, param_gen)


def _register_myszkowski() -> None:
    """Myszkowski transposition layer."""
    from kryptos.kernel.transforms.transposition import (
        apply_perm, invert_perm, myszkowski_perm,
    )
    from kryptos.kernel.constants import CT_LEN

    layer_def = LayerDef(
        family=LayerFamily.TRANSPOSITION_MYSZKOWSKI,
        description="Myszkowski transposition: tied columns read row-by-row",
        semantics=LayerSemantics(
            preserves_positions=False,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=False,
            changes_effective_key=False,
            is_involution=False,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params["keyword"]
        length = params.get("length", CT_LEN)
        perm = myszkowski_perm(keyword, length)
        inv = invert_perm(perm)

        def forward(text: str, p: list = perm) -> str:
            return apply_perm(text, p)

        def inverse(text: str, ip: list = inv) -> str:
            return apply_perm(text, ip)

        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.TRANSPOSITION_MYSZKOWSKI, layer_def, factory, param_gen)


def _register_rail_fence() -> None:
    """Rail fence transposition layer."""
    from kryptos.kernel.transforms.transposition import (
        apply_perm, invert_perm, rail_fence_perm,
    )
    from kryptos.kernel.constants import CT_LEN

    layer_def = LayerDef(
        family=LayerFamily.TRANSPOSITION_RAIL_FENCE,
        description="Rail fence (zigzag) transposition",
        semantics=LayerSemantics(
            preserves_positions=False,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=False,
            changes_effective_key=False,
            is_involution=False,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        depth = params["depth"]
        length = params.get("length", CT_LEN)
        perm = rail_fence_perm(length, depth)
        inv = invert_perm(perm)

        def forward(text: str, p: list = perm) -> str:
            return apply_perm(text, p)

        def inverse(text: str, ip: list = inv) -> str:
            return apply_perm(text, ip)

        return forward, inverse

    def param_gen(
        depths: Optional[List[int]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if depths is None:
            depths = list(range(2, 13))
        return [{"depth": d} for d in depths]

    register_layer(LayerFamily.TRANSPOSITION_RAIL_FENCE, layer_def, factory, param_gen)


def _register_route() -> None:
    """Route transposition layer — supports spiral, serpentine, strip."""
    from kryptos.kernel.transforms.transposition import (
        apply_perm, invert_perm, spiral_perm, serpentine_perm,
    )
    from kryptos.kernel.constants import CT_LEN

    layer_def = LayerDef(
        family=LayerFamily.TRANSPOSITION_ROUTE,
        description="Route transposition: spiral, serpentine, or custom reading order",
        semantics=LayerSemantics(
            preserves_positions=False,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=False,
            changes_effective_key=False,
            is_involution=False,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        length = params.get("length", CT_LEN)

        if "perm" in params:
            perm = params["perm"]
        else:
            route_type = params.get("route_type", "spiral")
            rows = params["rows"]
            cols = params["cols"]
            if route_type == "spiral":
                clockwise = params.get("clockwise", True)
                perm = spiral_perm(rows, cols, length, clockwise)
            elif route_type == "serpentine":
                vertical = params.get("vertical", False)
                perm = serpentine_perm(rows, cols, length, vertical)
            else:
                raise ValueError(f"Unknown route_type: {route_type!r}")

        inv = invert_perm(perm)

        def forward(text: str, p: list = perm) -> str:
            return apply_perm(text, p)

        def inverse(text: str, ip: list = inv) -> str:
            return apply_perm(text, ip)

        return forward, inverse

    def param_gen(
        grid_sizes: Optional[List[Tuple[int, int]]] = None,
        route_types: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        from kryptos.kernel.constants import CT_LEN
        if grid_sizes is None:
            # Grids that fit 97 chars (rows*cols >= 97)
            grid_sizes = [
                (7, 14), (14, 7), (8, 13), (13, 8),
                (10, 10), (11, 9), (9, 11),
            ]
        if route_types is None:
            route_types = ["spiral", "serpentine"]

        results: list[Dict[str, Any]] = []
        for rows, cols in grid_sizes:
            for rt in route_types:
                if rt == "spiral":
                    for cw in [True, False]:
                        results.append({
                            "rows": rows, "cols": cols,
                            "route_type": "spiral", "clockwise": cw,
                        })
                elif rt == "serpentine":
                    for vert in [True, False]:
                        results.append({
                            "rows": rows, "cols": cols,
                            "route_type": "serpentine", "vertical": vert,
                        })
        return results

    register_layer(LayerFamily.TRANSPOSITION_ROUTE, layer_def, factory, param_gen)


def _register_block_transposition() -> None:
    """Block transposition layer — 24-char blocks (Berlin clock style)."""
    from kryptos.kernel.transforms.transposition import (
        unmask_block_transposition, apply_perm, invert_perm,
        make_mengen_route, apply_rotation, apply_reflection, BLOCK_SIZE,
    )

    layer_def = LayerDef(
        family=LayerFamily.BLOCK_TRANSPOSITION,
        description="Block transposition: 24-char blocks with clock-face permutations",
        semantics=LayerSemantics(
            preserves_positions=False,
            preserves_unigram_frequencies=True,
            preserves_length=True,
            preserves_crib_locality=False,
            changes_effective_key=False,
            is_involution=False,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        perm = params["perm"]
        boustro = params.get("cycle_boustro", False)

        def forward(text: str, p: list = perm, b: bool = boustro) -> str:
            # Forward = apply the block transposition (encryption direction)
            bs = BLOCK_SIZE
            out = list(text)
            inv = invert_perm(p)
            inv_rev = invert_perm(list(reversed(p)))
            blocks = len(text) // bs
            for block in range(blocks):
                base = block * bs
                use_p = list(reversed(p)) if (b and block % 2 == 1) else p
                for j in range(bs):
                    src = base + use_p[j]
                    if src < len(text):
                        out[base + j] = text[src]
            return "".join(out)

        def inverse(text: str, p: list = perm, b: bool = boustro) -> str:
            return unmask_block_transposition(text, p, b)

        return forward, inverse

    def param_gen(**kwargs: Any) -> List[Dict[str, Any]]:
        results: list[Dict[str, Any]] = []
        for route_name in ["identity", "band_boustro", "all_forward", "all_reversed", "reverse_bands"]:
            base_route = make_mengen_route(route_name)
            for rot in range(24):
                perm = apply_rotation(base_route, rot)
                results.append({
                    "perm": perm,
                    "cycle_boustro": False,
                    "route_name": route_name,
                    "rotation": rot,
                })
                results.append({
                    "perm": perm,
                    "cycle_boustro": True,
                    "route_name": route_name,
                    "rotation": rot,
                })
            # Reflected variants
            reflected = apply_reflection(base_route)
            for rot in range(24):
                perm = apply_rotation(reflected, rot)
                results.append({
                    "perm": perm,
                    "cycle_boustro": False,
                    "route_name": f"{route_name}_reflected",
                    "rotation": rot,
                })
        return results

    register_layer(LayerFamily.BLOCK_TRANSPOSITION, layer_def, factory, param_gen)


# ── Vigenere / Beaufort / Variant Beaufort cipher layers ──────────────

def _register_vigenere() -> None:
    """Vigenere cipher layer: C = (P + K) mod 26, periodic keyword."""
    from kryptos.kernel.transforms.vigenere import (
        CipherVariant, decrypt_text, encrypt_text,
    )
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.VIGENERE,
        description="Vigenere cipher: periodic keyword, C = (P + K) mod 26",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        key = [ALPH_IDX[c] for c in keyword.upper()]

        def forward(text: str, k: list = key) -> str:
            return encrypt_text(text, k, CipherVariant.VIGENERE)

        def inverse(text: str, k: list = key) -> str:
            return decrypt_text(text, k, CipherVariant.VIGENERE)

        return forward, inverse

    def param_gen(keywords: Optional[List[str]] = None, **kwargs: Any) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.VIGENERE, layer_def, factory, param_gen)


def _register_beaufort() -> None:
    """Beaufort cipher layer: C = (K - P) mod 26, periodic keyword. Reciprocal."""
    from kryptos.kernel.transforms.vigenere import (
        CipherVariant, decrypt_text, encrypt_text,
    )
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.BEAUFORT,
        description="Beaufort cipher: periodic keyword, C = (K - P) mod 26, reciprocal",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=True,  # Beaufort is reciprocal
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        key = [ALPH_IDX[c] for c in keyword.upper()]

        def forward(text: str, k: list = key) -> str:
            return encrypt_text(text, k, CipherVariant.BEAUFORT)

        def inverse(text: str, k: list = key) -> str:
            return decrypt_text(text, k, CipherVariant.BEAUFORT)

        return forward, inverse

    def param_gen(keywords: Optional[List[str]] = None, **kwargs: Any) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.BEAUFORT, layer_def, factory, param_gen)


def _register_var_beaufort() -> None:
    """Variant Beaufort cipher: C = (P - K) mod 26, periodic keyword."""
    from kryptos.kernel.transforms.vigenere import (
        CipherVariant, decrypt_text, encrypt_text,
    )
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.VAR_BEAUFORT,
        description="Variant Beaufort cipher: periodic keyword, C = (P - K) mod 26",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        key = [ALPH_IDX[c] for c in keyword.upper()]

        def forward(text: str, k: list = key) -> str:
            return encrypt_text(text, k, CipherVariant.VAR_BEAUFORT)

        def inverse(text: str, k: list = key) -> str:
            return decrypt_text(text, k, CipherVariant.VAR_BEAUFORT)

        return forward, inverse

    def param_gen(keywords: Optional[List[str]] = None, **kwargs: Any) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.VAR_BEAUFORT, layer_def, factory, param_gen)


# ══════════════════════════════════════════════════════════════════════════
# Nonstandard / stateful / architecture-specific layer families (v3)
# ══════════════════════════════════════════════════════════════════════════

def _register_band_offset() -> None:
    """Band-scheduled offset mask: Berlin clock bands select shift values."""
    from kryptos.kernel.transforms.stateful import band_offset_encrypt, band_offset_decrypt
    from itertools import product

    layer_def = LayerDef(
        family=LayerFamily.BAND_OFFSET,
        description="Berlin clock band-scheduled additive offsets (5 bands, 1-4-4-11-4)",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        offsets = params["band_offsets"]
        def forward(text: str, o: list = offsets) -> str:
            return band_offset_encrypt(text, o)
        def inverse(text: str, o: list = offsets) -> str:
            return band_offset_decrypt(text, o)
        return forward, inverse

    def param_gen(
        offset_values: Optional[List[int]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if offset_values is None:
            offset_values = [0, 1, 3, 5, 7, 9, 11, 13, 17, 19, 23, 25]
        # Enumerate: band A is often 0 (indicator), vary B-E
        results: list[Dict[str, Any]] = []
        for a in [0]:  # Fix band A at 0
            for b in offset_values:
                for c in offset_values:
                    for d in offset_values:
                        for e in offset_values:
                            results.append({"band_offsets": [a, b, c, d, e]})
        return results

    register_layer(LayerFamily.BAND_OFFSET, layer_def, factory, param_gen)


def _register_polarity_switch() -> None:
    """Polarity-switching schedule: Vig/Beau/VarBeau selected per position class."""
    from kryptos.kernel.transforms.stateful import polarity_switch_encrypt, polarity_switch_decrypt
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.POLARITY_SWITCH,
        description="Polarity-switching: schedule selects Vig/Beau/VarBeau per position",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        key = [ALPH_IDX[c] for c in keyword.upper()]
        schedule = params["schedule"]
        def forward(text: str, k: list = key, s: list = schedule) -> str:
            return polarity_switch_encrypt(text, k, s)
        def inverse(text: str, k: list = key, s: list = schedule) -> str:
            return polarity_switch_decrypt(text, k, s)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        schedules: Optional[List[List[int]]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        if schedules is None:
            schedules = _polarity_schedules()
        results: list[Dict[str, Any]] = []
        for kw in keywords:
            for sched in schedules:
                results.append({"keyword": kw, "schedule": sched})
        return results

    register_layer(LayerFamily.POLARITY_SWITCH, layer_def, factory, param_gen)


def _register_progressive_key() -> None:
    """Progressive key (Fibonacci-like recurrence from seed)."""
    from kryptos.kernel.transforms.stateful import progressive_key_encrypt, progressive_key_decrypt
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.PROGRESSIVE_KEY,
        description="Progressive key: Fibonacci-like key stream from keyword seed",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        seed = [ALPH_IDX[c] for c in keyword.upper()]
        def forward(text: str, s: list = seed) -> str:
            return progressive_key_encrypt(text, s)
        def inverse(text: str, s: list = seed) -> str:
            return progressive_key_decrypt(text, s)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        return [{"keyword": kw} for kw in keywords]

    register_layer(LayerFamily.PROGRESSIVE_KEY, layer_def, factory, param_gen)


def _register_state_alphabet() -> None:
    """State-selected alphabet: state schedule modifies effective key values."""
    from kryptos.kernel.transforms.stateful import state_alphabet_encrypt, state_alphabet_decrypt
    from kryptos.kernel.constants import ALPH_IDX

    layer_def = LayerDef(
        family=LayerFamily.STATE_ALPHABET,
        description="State-scheduled key modification: state offsets shift effective key",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        base_key = [ALPH_IDX[c] for c in keyword.upper()]
        state_offsets = params["state_offsets"]
        state_schedule = params["state_schedule"]
        def forward(text: str, k: list = base_key, so: list = state_offsets, ss: list = state_schedule) -> str:
            return state_alphabet_encrypt(text, k, so, ss)
        def inverse(text: str, k: list = base_key, so: list = state_offsets, ss: list = state_schedule) -> str:
            return state_alphabet_decrypt(text, k, so, ss)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        state_configs: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()[:8]
        if state_configs is None:
            state_configs = _state_alphabet_configs()
        results: list[Dict[str, Any]] = []
        for kw in keywords:
            for cfg in state_configs:
                results.append({
                    "keyword": kw,
                    "state_offsets": cfg["offsets"],
                    "state_schedule": cfg["schedule"],
                })
        return results

    register_layer(LayerFamily.STATE_ALPHABET, layer_def, factory, param_gen)


def _register_band_polarity() -> None:
    """Band-polarity: Berlin clock band selects Vig/Beau/VarBeau."""
    from kryptos.kernel.transforms.stateful import band_polarity_encrypt, band_polarity_decrypt
    from kryptos.kernel.constants import ALPH_IDX
    from itertools import product

    layer_def = LayerDef(
        family=LayerFamily.BAND_POLARITY,
        description="Berlin clock band-scheduled cipher polarity (Vig/Beau/VarBeau per band)",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params.get("keyword", "A")
        key = [ALPH_IDX[c] for c in keyword.upper()]
        band_variants = params["band_variants"]
        def forward(text: str, k: list = key, bv: list = band_variants) -> str:
            return band_polarity_encrypt(text, k, bv)
        def inverse(text: str, k: list = key, bv: list = band_variants) -> str:
            return band_polarity_decrypt(text, k, bv)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = _default_keywords()
        results: list[Dict[str, Any]] = []
        # All 3^5 = 243 band variant combinations
        for bv in product(range(3), repeat=5):
            # Skip all-same (reduces to standard Vig/Beau/VarBeau)
            if len(set(bv)) == 1:
                continue
            for kw in keywords:
                results.append({"keyword": kw, "band_variants": list(bv)})
        return results

    register_layer(LayerFamily.BAND_POLARITY, layer_def, factory, param_gen)


def _register_compass_offset() -> None:
    """Compass-bearing-scheduled offsets."""
    from kryptos.kernel.transforms.stateful import compass_offset_encrypt, compass_offset_decrypt

    layer_def = LayerDef(
        family=LayerFamily.COMPASS_OFFSET,
        description="Compass-bearing-scheduled additive offsets (keyword selects 8 bearings)",
        semantics=LayerSemantics(
            preserves_positions=True,
            preserves_unigram_frequencies=False,
            preserves_length=True,
            preserves_crib_locality=True,
            changes_effective_key=True,
            is_involution=False,
            position_dependent=True,
        ),
        reversible=True,
    )

    def factory(params: Dict[str, Any]) -> Tuple[TransformFn, TransformFn]:
        keyword = params["keyword"]
        bearing_offsets = params["bearing_offsets"]
        def forward(text: str, kw: str = keyword, bo: list = bearing_offsets) -> str:
            return compass_offset_encrypt(text, kw, bo)
        def inverse(text: str, kw: str = keyword, bo: list = bearing_offsets) -> str:
            return compass_offset_decrypt(text, kw, bo)
        return forward, inverse

    def param_gen(
        keywords: Optional[List[str]] = None,
        offset_sets: Optional[List[List[int]]] = None,
        **kwargs: Any,
    ) -> List[Dict[str, Any]]:
        if keywords is None:
            keywords = ["EASTNORTHEAST", "KRYPTOS", "BERLINCLOCK", "SANBORN", "KOMPASS"]
        if offset_sets is None:
            offset_sets = _compass_offset_sets()
        results: list[Dict[str, Any]] = []
        for kw in keywords:
            for bo in offset_sets:
                results.append({"keyword": kw, "bearing_offsets": bo})
        return results

    register_layer(LayerFamily.COMPASS_OFFSET, layer_def, factory, param_gen)


# ── Default parameter sets for stateful families ──────────────────────

def _polarity_schedules() -> List[List[int]]:
    """Generate hand-executable polarity schedules."""
    schedules: list[list[int]] = []
    # Period-2: alternating
    schedules.append([0, 1])       # Vig, Beau
    schedules.append([1, 0])       # Beau, Vig
    schedules.append([0, 2])       # Vig, VarBeau
    schedules.append([1, 2])       # Beau, VarBeau
    # Period-3
    schedules.append([0, 1, 2])    # Vig, Beau, VarBeau cycle
    schedules.append([0, 0, 1])    # VVB
    schedules.append([1, 1, 0])    # BBV
    # Period-4 (compass-like)
    schedules.append([0, 1, 0, 1])
    schedules.append([0, 0, 1, 1])
    schedules.append([0, 1, 2, 1])
    # Period-5 (band-like: 1-4-4-11-4 simplified)
    schedules.append([0, 1, 1, 0, 1])
    schedules.append([1, 0, 0, 1, 0])
    schedules.append([0, 1, 2, 0, 1])
    # Period-7 (KRYPTOS length)
    schedules.append([0, 1, 0, 0, 1, 1, 0])
    schedules.append([0, 0, 1, 0, 1, 0, 1])
    # Period-24 Berlin-clock-derived
    bcl_sched = [0]*1 + [1]*4 + [0]*4 + [1]*11 + [0]*4
    schedules.append(bcl_sched)
    bcl_sched2 = [0]*1 + [0]*4 + [1]*4 + [0]*11 + [1]*4
    schedules.append(bcl_sched2)
    bcl_sched3 = [2]*1 + [0]*4 + [1]*4 + [0]*11 + [2]*4
    schedules.append(bcl_sched3)
    return schedules


def _state_alphabet_configs() -> List[Dict[str, Any]]:
    """Generate state alphabet configurations."""
    configs: list[Dict[str, Any]] = []
    # 2-state systems
    for off in [1, 3, 5, 7, 13]:
        configs.append({"offsets": [0, off], "schedule": [0, 1]})
        configs.append({"offsets": [0, off], "schedule": [0, 0, 1]})
        configs.append({"offsets": [0, off], "schedule": [0, 0, 1, 1]})
    # 3-state
    for off1, off2 in [(1, 5), (3, 7), (5, 13), (7, 17)]:
        configs.append({"offsets": [0, off1, off2], "schedule": [0, 1, 2]})
    # 5-state (band-derived)
    configs.append({"offsets": [0, 3, 7, 13, 19], "schedule": list(range(5))})
    configs.append({"offsets": [0, 1, 5, 11, 23], "schedule": list(range(5))})
    # 24-state Berlin clock schedule
    bcl_states = [0]*1 + [1]*4 + [2]*4 + [3]*11 + [4]*4
    for off_set in [(0, 3, 7, 13, 19), (0, 1, 5, 11, 23), (0, 7, 13, 17, 25)]:
        configs.append({"offsets": list(off_set), "schedule": bcl_states})
    return configs


def _compass_offset_sets() -> List[List[int]]:
    """Generate compass bearing offset sets."""
    sets: list[list[int]] = []
    # Cardinal vs ordinal differentiation
    sets.append([0, 3, 0, 3, 0, 3, 0, 3])   # N,NE,E,SE,S,SW,W,NW
    sets.append([0, 7, 0, 7, 0, 7, 0, 7])
    sets.append([0, 13, 0, 13, 0, 13, 0, 13])
    # Progressive bearing
    sets.append([0, 1, 3, 5, 7, 11, 13, 17])
    sets.append([0, 3, 7, 11, 13, 17, 19, 23])
    # ENE-themed (bearing 1.5 rounds to 1 or 2)
    sets.append([0, 0, 7, 0, 0, 0, 7, 0])  # Only NE and W shifted
    sets.append([0, 5, 0, 5, 13, 5, 0, 5])
    # Symmetric
    sets.append([0, 5, 10, 15, 20, 15, 10, 5])
    sets.append([0, 3, 6, 9, 12, 9, 6, 3])
    return sets


# ── Default keyword set ────────────────────────────────────────────────

def _default_keywords() -> List[str]:
    """Thematic keywords for K4 search."""
    return [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW",
        "BERLINCLOCK", "EASTNORTHEAST", "SANBORN", "SCHEIDT",
        "KOMPASS", "DEFECTOR", "CLOCK", "BERLIN",
        "WEBSTER", "EQUINOX", "VERDIGRIS",
    ]


# ── Auto-register all built-in families ────────────────────────────────

def _init_registry() -> None:
    """Register all built-in layer families."""
    _register_identity()
    _register_additive_mask()
    _register_vigenere()
    _register_beaufort()
    _register_var_beaufort()
    _register_columnar()
    _register_myszkowski()
    _register_rail_fence()
    _register_route()
    _register_block_transposition()
    # v3: stateful / architecture-specific
    _register_band_offset()
    _register_polarity_switch()
    _register_progressive_key()
    _register_state_alphabet()
    _register_band_polarity()
    _register_compass_offset()


_init_registry()
