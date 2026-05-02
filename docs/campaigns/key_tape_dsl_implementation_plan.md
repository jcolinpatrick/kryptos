# `key_tape` DSL Kind — Implementation Plan

**Status:** PLAN — implementation not started
**Author:** Colin Patrick + Claude (KryptosBot)
**Date authored:** 2026-05-02
**Closes:** the explicit deferred DSL gap identified in
`docs/audits/dsl_dispatcher_semantics.md`
(Codex audit 2026-05-02: "DSL-valid kinds: 19, Dispatcher-supported
kinds: 18; Valid without translation: ['key_tape']")

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
    "vigenere", "beaufort", "variant_beaufort",
})
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

from typing import FrozenSet, Tuple, Literal
from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY,
)

NullRule = Literal["skip", "consume"]


def apply_key_tape(
    ct: str,
    tape: Tuple[int, ...],
    *,
    variant: CipherVariant,
    null_positions: FrozenSet[int] = frozenset(),
    null_rule: NullRule = "skip",
    alphabet: Alphabet = AZ,
) -> str:
    """Apply finite-tape additive cipher with null insertion to CT.

    Returns plaintext where null positions are filled with '?' and
    non-null positions are decrypted under the chosen variant using
    the running tape index.

    Raises ValueError on:
        - tape contents out of [0, 25]
        - null_positions out of range
        - tape exhaustion (insufficient tape under chosen rule)
    """
    # Implementation:
    # 1. Validate inputs.
    # 2. Walk CT positions. Maintain tape_index.
    # 3. If pos in null_positions:
    #    - SKIP: PT[pos] = '?'; tape_index unchanged
    #    - CONSUME: PT[pos] = '?'; tape_index += 1 (raise if past end)
    # 4. Otherwise:
    #    - tape_value = tape[tape_index] (raise if past end)
    #    - PT[pos] = decrypt_one(ct[pos], tape_value, variant, alphabet)
    #    - tape_index += 1
    # 5. Return ''.join(PT).
```

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

Add `"key_tape"` to `_SUPPORTED_KINDS` and the `_translate_layer()`
dispatch.

Remove from `kryptosbot/critic.py` `_DEFERRED_KINDS`.

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

Mirroring Stage A/B's synthetic recovery pattern:

1. Build synthetic 30-char PT: `KRYPTOSEXAMPLEPLAINTEXTNULLABCD`.
2. Encrypt under key_tape with `variant=vigenere`, `tape=(7,3,1,2,5,8,11,4,9,0)`,
   `null_positions={4, 9, 14, 19, 24, 29}`, `null_rule=skip`,
   `alphabet=AZ`.
3. Verify the dispatcher correctly recovers PT from CT given the same
   parameters.
4. Verify that with `null_rule=consume`, a *shorter* tape produces a
   different valid recovery (different non-null positions decoded).

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

- [ ] `scripts/audit/audit_dsl_dispatcher_semantics.py` reports
      `Valid without translation: []`.
- [ ] All tests in §6 pass.
- [ ] Synthetic recovery test in §7 passes.
- [ ] `kryptosbot/critic.py` `_DEFERRED_KINDS` no longer includes
      `key_tape`.
- [ ] CLAUDE.md and `kryptosbot/ARCHITECTURE.md` are updated.
- [ ] `docs/audits/dsl_dispatcher_semantics.md` is regenerated and
      shows DSL-valid kinds equal to dispatcher-supported kinds.

---

*Last updated 2026-05-02. Implementation plan only; no code written.
The plan is concrete enough that any contributor can pick it up. The
keystream-forensics agent's conventions (memory/keystream_forensics_v2.md)
are the authoritative reference for the M4 SKIP / CONSUME semantics
this implements.*
