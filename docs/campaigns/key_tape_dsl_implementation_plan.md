# `key_tape` DSL Kind — Implementation Plan

**Status:** LANDED — workstream complete 2026-05-03
**Landed:** 2026-05-03 — closure criteria §11 all green. Implementation final commit: `d998264` (kryptosbot tests aligned to nested-params + binding model). 39 new tests added; key_tape suite + K1/K2 self-test + audit dossier all green. See `MEMORY.md` → `project_key_tape_dsl_landed_2026_05_03.md` for the full outcome record.
**Author:** Colin Patrick + Claude (KryptosBot)
**Date authored:** 2026-05-02 · **Promoted to active:** 2026-05-03
**Closes:** the explicit deferred DSL gap identified in
`docs/audits/dsl_dispatcher_semantics.md`
(Codex audit 2026-05-02: "DSL-valid kinds: 19, Dispatcher-supported
kinds: 18; Valid without translation: ['key_tape']")

---

## 0. Scope decision (locked 2026-05-03)

**Scope (c): capability-only.** This project delivers the kernel
transform, DSL validation, dispatcher translator, known-answer
fixture, and synthetic recovery. It does **NOT** implement an
enumeration runner or simulated-annealing search over tapes — those
are separate projects layered on top, each requiring their own
brainstorm (neighbor function, restart strategy, parallelism plumbing,
null-position generation).

**Rationale:** the DSL/dispatcher gap is a capability ceiling
(Codex-flagged); closing it unblocks the keystream-forensics line and
lets theorists propose tape-based attacks. Search design is a
follow-up that composes cleanly on top of (c).

**Out-of-scope confirmation:** §10 below already excludes infinite
tapes, autokey, CT-feedback, and stateful tapes. Adding to that:
**no automated keyspace search** (enumeration or SA) is delivered by
this project.

---

## 1. What `key_tape` is

A finite-tape additive cipher with optional null insertion — the
kernel-level model the keystream-forensics agent ships its M1–M5
hypothesis classes on top of (`.claude/agents/keystream-forensics.md`,
`memory/keystream_forensics_v2.md`).

Mathematically:

> Given a CT of length N, a key tape T of length L (where L ≤ N),
> a null-position set `S ⊂ {0..N-1}`, and a null-consumption rule R,
> compute the implied plaintext PT.

The tape consumption walks CT positions in order:
- If position `i` is in `S` (a null), apply rule R:
  - **SKIP:** tape index does not advance; `PT[i]` is undefined / "?"
  - **CONSUME:** tape index advances; `PT[i]` is undefined / "?"
- Otherwise, apply the additive variant rule (Vigenère / Beaufort / VarBeau)
  with the current tape value, and advance the tape index.

The tape may be shorter than the count of non-null CT positions (then the
operation fails: insufficient tape) or longer (then trailing tape is
unused).

## 2. Why it's not just "Vigenère with a short keyword"

A periodic Vigenère with key length L is a tape of length L that **repeats**
to fill 97. `key_tape` is **non-repeating**: positions beyond L are
undefined unless reached via a null-rule consumption pattern that lands
within L. The semantic difference:

- Periodic Vigenère: `K[i] = key[i mod L]` for all i.
- key_tape: `K[i] = tape[j]` where j is the running tape-consumption
  counter, NOT `i mod L`. Without nulls, j = i (so the tape just runs
  out at L). With nulls, j evolves under R.

This is the OTP-like / fixed-tape model — the cipher class Sanborn might
plausibly hand-execute against a printed strip of letters.

## 3. DSL parameter schema

Add to `kryptosbot/hypothesis_dsl.py` `_VALID_CIPHER_KINDS` (already
present) plus new validation constants:

```python
NullRule = Literal["skip", "consume"]
_VALID_NULL_RULES: frozenset[str] = frozenset({"skip", "consume"})

# Supported additive variants for key_tape (matches Stage A/B exclusion
# list — no autokey, no Quagmire, no running-key).
_VALID_KEY_TAPE_VARIANTS: frozenset[str] = frozenset({
    "vigenere", "beaufort", "var_beaufort",
})

# Variant strings match ``CipherVariant`` enum values verbatim (no DSL→kernel mapping layer needed).
```

Required parameters per layer instance:

| Param | Type | Domain | Required |
|---|---|---|---|
| `tape` | tuple[int, ...] | each in [0, 25], len in [1, CT_LEN] | yes |
| `variant` | str | one of `_VALID_KEY_TAPE_VARIANTS` | yes |
| `null_positions` | frozenset[int] | each in [0, CT_LEN) | optional, default empty |
| `null_rule` | str | one of `_VALID_NULL_RULES` | required if `null_positions` non-empty; ignored otherwise |
| `alphabet` | str | "AZ" or "KA" | yes (delegate to existing alphabet plumbing) |

Validation rules enforced in `validate_layer_for_kind("key_tape", ...)`:

- `len(tape) >= 1`
- `len(tape) <= CT_LEN` (no infinite tapes; the DSL is for finite tapes)
- All `tape[i]` in `[0, 25]`
- All `null_positions` in `[0, CT_LEN)` and unique
- If `null_positions` is non-empty, `null_rule` must be present
- `len(tape) >= count_non_null_positions(null_positions)` for the
  campaign's CT length under SKIP rule (consume rule may require less,
  see §4.4)

## 4. Kernel transform

Add to `src/kryptos/kernel/transforms/`:

### 4.1 New module: `src/kryptos/kernel/transforms/key_tape.py`

```python
"""Finite-tape additive cipher with optional null insertion.

Models the M1-M5 hypothesis class from the keystream-forensics agent
(see memory/keystream_forensics_v2.md). The tape is finite; nulls
either skip the tape (M4 default) or consume it without contributing
to plaintext (alternative).
"""

from typing import FrozenSet, Literal, Tuple
from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.transforms.vigenere import CipherVariant

NullRule = Literal["skip", "consume"]
Direction = Literal["encrypt", "decrypt"]


def apply_key_tape(
    text: str,
    tape: Tuple[int, ...],
    *,
    variant: CipherVariant,
    direction: Direction = "decrypt",
    null_positions: FrozenSet[int] = frozenset(),
    null_rule: NullRule = "skip",
    alphabet: Alphabet = AZ,
) -> str:
    """Apply finite-tape additive cipher with null insertion.

    With ``direction="decrypt"``, ``text`` is CT and the return value
    is PT (with '?' at null positions). With ``direction="encrypt"``,
    ``text`` is PT and the return value is CT (the inverse operation
    under the same tape and variant).

    The kernel default null_rule of "skip" matches M4-default semantics
    (`memory/keystream_forensics_v2.md`); the DSL layer (§3) requires
    callers to declare null_rule explicitly when null_positions is
    non-empty so campaign manifests are unambiguous.

    Raises ValueError on:
        - tape contents out of [0, 25]
        - null_positions out of [0, len(text))
        - tape exhaustion (insufficient tape under chosen rule)
    """
    # Implementation:
    # 1. Validate inputs.
    # 2. Walk text positions. Maintain tape_index.
    # 3. If pos in null_positions:
    #    - SKIP: out[pos] = '?'; tape_index unchanged
    #    - CONSUME: out[pos] = '?'; tape_index += 1 (raise if past end)
    # 4. Otherwise:
    #    - tape_value = tape[tape_index] (raise if past end)
    #    - out[pos] = apply_one(text[pos], tape_value, variant,
    #                            direction, alphabet)
    #    - tape_index += 1
    # 5. Return ''.join(out).
```

Both directions live in one function (single source of validation
logic). Synthetic recovery (§7) uses encrypt-then-decrypt with the
same parameters. The encrypt path internally inverts variant rules
that are not self-reciprocal: Vigenère's `K = (CT - PT) mod 26`
inverts to `CT = (PT + K) mod 26`; Beaufort is self-reciprocal;
Variant Beaufort's `K = (PT - CT) mod 26` inverts to `CT = (PT - K) mod 26`,
and the inverse decrypt direction is `PT = (CT + K) mod 26`. The
authoritative reference for these formulas is
`src/kryptos/kernel/transforms/vigenere.py` (DECRYPT_FN/ENCRYPT_FN
dicts) — re-derive only if those change.

### 4.2 Compose integration

Add to `src/kryptos/kernel/transforms/compose.py`:

```python
class TransformType(Enum):
    ...
    KEY_TAPE = "key_tape"  # finite tape + null insertion
```

And the dispatch arm in `build_pipeline()` that calls `apply_key_tape`.

## 5. Dispatcher translator

Add to `kryptosbot/job_dispatcher.py`:

```python
def _translate_key_tape(
    layer: CipherLayer,
    binding: dict[str, Any],
) -> dict[str, Any]:
    """Translate a key_tape DSL layer into a kernel TransformConfig.

    Produces a TransformConfig with type=KEY_TAPE carrying tape,
    variant, null_positions, null_rule, and alphabet.
    """
    tape = tuple(layer.params.get("tape", ()))
    variant_name = layer.params.get("variant")
    null_positions = frozenset(layer.params.get("null_positions", ()))
    null_rule = layer.params.get("null_rule", "skip" if not null_positions else None)
    alphabet_kind = layer.params.get("alphabet", "AZ")

    # Validation enforced earlier; re-assert here for safety.
    if not tape:
        raise ValueError("key_tape requires non-empty tape")
    if variant_name not in _VALID_KEY_TAPE_VARIANTS:
        raise ValueError(f"key_tape: unsupported variant {variant_name!r}")
    if null_positions and null_rule is None:
        raise ValueError("key_tape: null_rule required when null_positions non-empty")

    return {
        "type": "key_tape",
        "tape": tape,
        "variant": variant_name,
        "null_positions": null_positions,
        "null_rule": null_rule,
        "alphabet": alphabet_kind,
    }
```

Add `"key_tape"` to `_SUPPORTED_KINDS` (the dispatcher's
`frozenset[str]` of supported kinds) and to the `_translate_layer()`
dispatch arm. Translator return type is `dict[str, Any]` to match
existing translators (the dispatcher emits dicts so configs travel
across multiprocessing worker boundaries via the standard
serialization that the worker pool uses for arguments).

`kryptosbot/critic.py` does not maintain a separate `_DEFERRED_KINDS`
constant; it gates kind admission via `_SUPPORTED_KINDS` imported from
`job_dispatcher`. Once `key_tape` is added to `_SUPPORTED_KINDS`, the
critic accepts it automatically. Verify in the dispatcher tests
(§6.3) by asserting `_kind_has_translation("key_tape") is True`.

`CT_LEN` is imported from `kryptos.kernel.constants` (matches the
existing translators). For text-length validation the translator uses
`_translation_text_length(text_length)` like the other translators.

## 6. Tests

### 6.1 Unit tests (`tests/test_key_tape_kernel.py`)

- Roundtrip: encrypt with known tape + variant, decrypt with same
  parameters, recover original PT.
- Tape length matches non-null count under SKIP: PT has `?` exactly at
  null positions, real letters elsewhere.
- Tape exhaustion: shorter tape than required raises `ValueError`.
- Null-position out of range: raises `ValueError`.
- Tape entry out of [0, 25]: raises `ValueError`.
- Empty `null_positions` with `null_rule=None` is allowed.
- Variant correctness: Vig / Beau / VarBeau roundtrip independently.
- Alphabet correctness: AZ and KA give different PT for same tape.

### 6.2 DSL tests (`kryptosbot/tests/test_dsl_key_tape.py`)

- Valid layer accepted by `validate_layer_for_kind("key_tape", ...)`.
- Negative cases: missing variant, malformed tape, null_positions out
  of range, missing null_rule with null_positions.

### 6.3 Dispatcher tests (`kryptosbot/tests/test_dispatcher_key_tape.py`)

- Translator emits valid TransformConfig.
- Single-tape known-answer fixture (e.g., synthetic 20-char CT,
  hand-computed expected PT).
- Composed key_tape + columnar challenge.
- The audit script `scripts/audit/audit_dsl_dispatcher_semantics.py`
  must report `Valid without translation: []` after this lands.

### 6.4 Known-answer fixture (`tests/audit/known_answer_corpus.json`)

Add at least one external known-answer fixture. Candidates:

- A historical "OTP with selected nulls" example from a cryptographic
  textbook (preferred — independent of this codebase's conventions).
- A synthetic K1-style mini-cipher with explicit tape and null
  positions.

## 7. Synthetic recovery test (mandatory before declaring complete)

Mirroring Stage A/B's synthetic recovery pattern. The fixture is sized
so tape length equals non-null count under SKIP (otherwise the kernel
raises tape-exhaustion per §1).

1. Build synthetic 16-char PT: `KRYPTOSEXAMPLEAB` (length 16).
2. Encrypt under key_tape with `variant=vigenere`, `direction=encrypt`,
   `tape=(7,3,1,2,5,8,11,4,9,0)` (length 10),
   `null_positions={2, 5, 8, 11, 14, 15}` (6 positions ⇒ 10 non-null),
   `null_rule=skip`, `alphabet=AZ`.
3. Verify the dispatcher correctly recovers PT from CT given the same
   parameters with `direction=decrypt`. Round-trip equality is exact
   on non-null positions; null positions are `?` in PT.
4. Repeat (1)–(3) for `variant=beaufort` and `variant=var_beaufort`
   to confirm both reciprocal and non-reciprocal variants round-trip
   correctly.

The CONSUME null rule is exercised in `tests/test_key_tape_kernel.py`
(§6.1) with a separate fixture sized appropriately (tape length ≥
full text length, since CONSUME advances on every position).

## 8. Estimated cost

| Phase | Time |
|---|---|
| 8.1 Kernel transform + tests | 0.5 d |
| 8.2 DSL params + validation + tests | 0.25 d |
| 8.3 Dispatcher translator + tests | 0.25 d |
| 8.4 Known-answer fixture | 0.25 d |
| 8.5 Synthetic recovery test + audit script update | 0.25 d |
| 8.6 Documentation (CLAUDE.md, ARCHITECTURE.md, audit dossier update) | 0.25 d |
| **Total** | **~1.75 d** |

## 9. Why this is worth doing now (after the hardening pass)

1. **Codex's audit explicitly identifies it as the only DSL gap.** Closing
   it brings the DSL/dispatcher to 100% coverage of the declared
   cipher-kind set.

2. **The keystream-forensics research line depends on it.** The agent's
   M1-M5 hypothesis classes are paper-only without a kernel implementation.
   The hardening pass produced trustworthy alert/dispatcher infrastructure;
   key_tape lets the keystream-forensics line use it.

3. **Stage A/B explicitly excludes running-key but does not exclude
   finite-tape additive.** A finite tape is not a running key
   (no external source-text prior; the tape is the parameter). key_tape
   is the natural extension into "non-periodic but bounded" key models
   that Stage A/B don't reach.

4. **Bounded keyspace.** Tape of length L over {0..25} is 26^L. For
   small L (say L ≤ 12), the keyspace is enumerable. For larger L, a
   simulated annealing search is feasible. This is qualitatively
   different from autokey (proven impossible per Tier 1) because there
   is no PT-feedback in the consumption rule — it's PT-independent.

## 10. Out of scope (explicitly)

- **Infinite tapes (running-key).** Excluded per Stage A/B doctrine.
- **PT-feedback consumption rules (autokey).** Eliminated by Tier 1.
- **CT-feedback consumption rules.** Same as autokey under variant
  algebra; excluded.
- **Stateful tapes that mutate during decryption** (e.g.,
  Chaocipher-class). Forbidden by `stateful_attack_requirements.md`
  unless 8 conditions met; out of scope here.

---

## 11. Closure criteria

The gap closes when:

- [x] `scripts/audit/audit_dsl_dispatcher_semantics.py` reports
      `Valid without translation: []`. — closed Task 10 (fd02a6b)
- [x] All tests in §6 pass. — closed across Tasks 1-9 (kernel + DSL + dispatcher tests)
- [x] Synthetic recovery test in §7 passes. — closed Task 11 (066d4a2)
- [x] `_kind_has_translation("key_tape") is True` (dispatcher exposes
      it; critic admits it automatically via `_SUPPORTED_KINDS`). — closed Task 9 (419d90d)
- [x] CLAUDE.md and `kryptosbot/ARCHITECTURE.md` are updated. — closing in this Task 13
- [x] `docs/audits/dsl_dispatcher_semantics.md` is regenerated and
      shows DSL-valid kinds equal to dispatcher-supported kinds. — closed Task 10

---

*Last updated 2026-05-03 (scope locked). The plan is concrete enough
that any contributor can pick it up. The keystream-forensics agent's
conventions (memory/keystream_forensics_v2.md) are the authoritative
reference for the M4 SKIP / CONSUME semantics this implements. Spec
ambiguities resolved 2026-05-03: `KEY_RECOVERY` import dropped (does
not exist; only `CipherVariant` is imported), `apply_key_tape` now
explicitly accepts a `direction` argument so synthetic recovery (§7)
can encrypt and decrypt in one function, `_DEFERRED_KINDS` reference
removed (critic gates via `_SUPPORTED_KINDS`), `CT_LEN` source named.*
