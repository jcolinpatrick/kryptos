# key_tape DSL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `key_tape` DSL kind to the Kryptos framework — a finite-tape additive cipher (Vig / Beau / VarBeau) with optional null insertion under SKIP or CONSUME consumption rules — closing the named DSL/dispatcher gap from the 2026-05-02 Codex audit.

**Architecture:** New kernel transform `apply_key_tape(text, tape, variant, direction, null_positions, null_rule, alphabet) -> str` handles both encrypt and decrypt in one function (single source of validation). DSL gains validation for the new kind. Dispatcher gains `_translate_key_tape` and `key_tape` joins `_SUPPORTED_KINDS`. No automated search delivered — this is capability-only per spec §0.

**Tech Stack:** Python 3.11+ stdlib only (kernel), pytest for tests. Follows existing patterns in `src/kryptos/kernel/transforms/vigenere.py` (variant arithmetic), `src/kryptos/kernel/transforms/compose.py` (TransformType enum), `kryptosbot/job_dispatcher.py` (translator return type `dict[str, Any]`).

**Spec:** `docs/campaigns/key_tape_dsl_implementation_plan.md` (status ACTIVE, scope (c) capability-only, locked 2026-05-03).

**Reconciliation note (one-line spec patch needed during execution):** Spec §3 lists `"variant_beaufort"` in `_VALID_KEY_TAPE_VARIANTS`. The kernel enum is `CipherVariant.VAR_BEAUFORT = "var_beaufort"`. Use `"var_beaufort"` in the DSL constant — matches the enum value verbatim, no mapping layer needed. (Task 7 below applies this; the spec is updated in the same task.)

**Test baseline at start:** 3956 collected (`PYTHONPATH=src pytest tests/ kryptosbot/tests/ --collect-only -q | tail -1`). Final test count must be ≥ 3956 + new tests; no existing test may regress.

---

## Pre-flight

- [ ] **P.1: Confirm we are on `main`, working tree clean (apart from untracked dirs):**

  Run: `git status --short`
  Expected: only `??` lines (analysis_runs/, copy/, scratch/), no `M` lines.

- [ ] **P.2: Capture baseline test count:**

  Run: `PYTHONPATH=src python3 -m pytest tests/ kryptosbot/tests/ --collect-only -q 2>/dev/null | tail -1`
  Expected output: `NNNN tests collected in <time>` where NNNN ≥ 3956. Record the number; final task verifies the new total is consistent with new tests added (~25–30) and zero regressions.

- [ ] **P.3: K1/K2 self-test fitness check (CLAUDE.md pre-flight #10):**

  Run: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run`
  Expected: PASS. K1 and K2 are still recovered. This must pass at start AND end of the build.

- [ ] **P.4: Confirm `apply_key_tape` does not already exist:**

  Run: `grep -rn "apply_key_tape\|class TransformType" src/kryptos/kernel/transforms/`
  Expected: `TransformType` exists in `compose.py`; `apply_key_tape` is absent. (If absent grep is silent for that term.)

---

## Task 1: Kernel transform — module scaffold + first failing decrypt test (Vigenère, no nulls, AZ)

**Files:**
- Create: `src/kryptos/kernel/transforms/key_tape.py`
- Create: `tests/test_key_tape_kernel.py`

- [ ] **Step 1: Write the failing test (Vigenère decrypt, no nulls, AZ)**

  Create `tests/test_key_tape_kernel.py` with:

  ```python
  """Tests for the key_tape finite-tape additive cipher with null insertion."""
  import pytest

  from kryptos.kernel.alphabet import AZ, KA
  from kryptos.kernel.transforms.vigenere import CipherVariant
  from kryptos.kernel.transforms.key_tape import apply_key_tape


  class TestKeyTapeBasic:
      def test_vigenere_decrypt_no_nulls_az(self):
          # Vigenère: K = (CT - PT) mod 26; PT = (CT - K) mod 26.
          # Tape (0,0,0,0,0) is the identity for Vigenère, so PT == CT.
          pt = apply_key_tape(
              "ABCDE",
              tape=(0, 0, 0, 0, 0),
              variant=CipherVariant.VIGENERE,
              direction="decrypt",
              alphabet=AZ,
          )
          assert pt == "ABCDE"

      def test_vigenere_decrypt_known_value(self):
          # CT = "BCDEF", tape = (1,1,1,1,1), Vigenère decrypt -> "ABCDE"
          pt = apply_key_tape(
              "BCDEF",
              tape=(1, 1, 1, 1, 1),
              variant=CipherVariant.VIGENERE,
              direction="decrypt",
              alphabet=AZ,
          )
          assert pt == "ABCDE"
  ```

- [ ] **Step 2: Run test to verify it fails with ModuleNotFoundError**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeBasic -v`
  Expected: collection error or `ModuleNotFoundError: No module named 'kryptos.kernel.transforms.key_tape'`.

- [ ] **Step 3: Create the kernel module with minimal Vigenère decrypt**

  Create `src/kryptos/kernel/transforms/key_tape.py`:

  ```python
  """Finite-tape additive cipher with optional null insertion.

  Implements the M1-M5 hypothesis class from the keystream-forensics
  agent (memory/keystream_forensics_v2.md). The tape is finite; nulls
  either skip the tape (M4 default, "skip" rule) or consume it without
  contributing to plaintext ("consume" rule).

  Spec: docs/campaigns/key_tape_dsl_implementation_plan.md
  """
  from typing import FrozenSet, Literal, Tuple

  from kryptos.kernel.alphabet import AZ, Alphabet
  from kryptos.kernel.transforms.vigenere import CipherVariant

  NullRule = Literal["skip", "consume"]
  Direction = Literal["encrypt", "decrypt"]


  def _apply_one(
      ch: str,
      key_val: int,
      variant: CipherVariant,
      direction: Direction,
      alphabet: Alphabet,
  ) -> str:
      """Apply variant arithmetic to one letter under the given direction.

      Convention (matches kernel/transforms/vigenere.py):
          Vigenère decrypt:    PT = (CT - K) mod 26
          Vigenère encrypt:    CT = (PT + K) mod 26
          Beaufort:            self-reciprocal; out = (K - in) mod 26
          Variant Beaufort decrypt: PT = (K - CT) mod 26
          Variant Beaufort encrypt: CT = (PT - K) mod 26
      """
      idx = alphabet.index(ch)
      if variant == CipherVariant.VIGENERE:
          out = (idx - key_val) % 26 if direction == "decrypt" else (idx + key_val) % 26
      else:
          raise NotImplementedError(f"variant {variant!r} not yet supported")
      return alphabet.letter(out)


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
      ``text`` is PT and the return value is CT.
      """
      out: list[str] = []
      tape_idx = 0
      for pos, ch in enumerate(text):
          if pos in null_positions:
              out.append("?")
              if null_rule == "consume":
                  tape_idx += 1
              continue
          key_val = tape[tape_idx]
          out.append(_apply_one(ch, key_val, variant, direction, alphabet))
          tape_idx += 1
      return "".join(out)
  ```

  Note: this module assumes `Alphabet` exposes `.index(letter) -> int` and `.letter(idx) -> str`. If the existing `Alphabet` class uses different method names (check `src/kryptos/kernel/alphabet.py` first; common alternatives are `.encode()/.decode()` or `.position_of()`), substitute the actual method names in `_apply_one`. **Do not** rewrite letter-index conversion locally — reuse what `vigenere.py` reuses.

- [ ] **Step 4: Run test to verify it passes**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeBasic -v`
  Expected: 2 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py src/kryptos/kernel/transforms/key_tape.py
  git commit -m "key_tape: kernel transform scaffold + Vigenère decrypt path"
  ```

---

## Task 2: Encrypt direction (Vigenère)

**Files:**
- Modify: `tests/test_key_tape_kernel.py` (add encrypt tests)
- (Implementation already in Task 1; this task verifies the encrypt branch with explicit tests + adds a roundtrip property test.)

- [ ] **Step 1: Write failing tests for encrypt + roundtrip**

  Append to `tests/test_key_tape_kernel.py`:

  ```python
  class TestKeyTapeEncrypt:
      def test_vigenere_encrypt_known_value(self):
          # PT = "ABCDE", tape = (1,1,1,1,1), Vigenère encrypt -> "BCDEF"
          ct = apply_key_tape(
              "ABCDE",
              tape=(1, 1, 1, 1, 1),
              variant=CipherVariant.VIGENERE,
              direction="encrypt",
              alphabet=AZ,
          )
          assert ct == "BCDEF"

      def test_vigenere_roundtrip(self):
          pt = "KRYPTOSEXAMPLE"
          tape = (3, 7, 1, 14, 22, 5, 19, 0, 11, 8, 6, 25, 13, 4)
          ct = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="encrypt", alphabet=AZ,
          )
          recovered = apply_key_tape(
              ct, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="decrypt", alphabet=AZ,
          )
          assert recovered == pt
  ```

- [ ] **Step 2: Run tests**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeEncrypt -v`
  Expected: 2 passed (encrypt branch already implemented in Task 1).

- [ ] **Step 3: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py
  git commit -m "key_tape: tests confirm Vigenère encrypt + roundtrip"
  ```

---

## Task 3: Beaufort variant (both directions)

**Files:**
- Modify: `src/kryptos/kernel/transforms/key_tape.py` (extend `_apply_one`)
- Modify: `tests/test_key_tape_kernel.py` (add Beaufort tests)

- [ ] **Step 1: Write failing tests**

  Append to `tests/test_key_tape_kernel.py`:

  ```python
  class TestKeyTapeBeaufort:
      def test_beaufort_self_reciprocal(self):
          # Beaufort: out = (K - in) mod 26. Same formula for encrypt and decrypt.
          pt = "ABCDE"
          tape = (5, 10, 15, 20, 25)
          ct = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.BEAUFORT,
              direction="encrypt", alphabet=AZ,
          )
          recovered = apply_key_tape(
              ct, tape=tape,
              variant=CipherVariant.BEAUFORT,
              direction="decrypt", alphabet=AZ,
          )
          assert recovered == pt

      def test_beaufort_known_value(self):
          # PT='A' (0), K=1 -> Beaufort out = (1-0) mod 26 = 1 -> 'B'
          ct = apply_key_tape(
              "A", tape=(1,),
              variant=CipherVariant.BEAUFORT,
              direction="encrypt", alphabet=AZ,
          )
          assert ct == "B"
  ```

- [ ] **Step 2: Run, verify NotImplementedError**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeBeaufort -v`
  Expected: FAIL with `NotImplementedError: variant <CipherVariant.BEAUFORT: 'beaufort'> not yet supported`.

- [ ] **Step 3: Extend `_apply_one` in `src/kryptos/kernel/transforms/key_tape.py`**

  Replace the `_apply_one` body's `if/else` block with:

  ```python
      if variant == CipherVariant.VIGENERE:
          out = (idx - key_val) % 26 if direction == "decrypt" else (idx + key_val) % 26
      elif variant == CipherVariant.BEAUFORT:
          # Self-reciprocal: out = (K - in) mod 26 in both directions.
          out = (key_val - idx) % 26
      else:
          raise NotImplementedError(f"variant {variant!r} not yet supported")
  ```

- [ ] **Step 4: Run, verify pass**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeBeaufort -v`
  Expected: 2 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py src/kryptos/kernel/transforms/key_tape.py
  git commit -m "key_tape: Beaufort variant (self-reciprocal)"
  ```

---

## Task 4: Variant Beaufort variant (both directions)

**Files:**
- Modify: `src/kryptos/kernel/transforms/key_tape.py`
- Modify: `tests/test_key_tape_kernel.py`

- [ ] **Step 1: Write failing tests**

  Append to `tests/test_key_tape_kernel.py`:

  ```python
  class TestKeyTapeVarBeaufort:
      def test_var_beaufort_decrypt_known_value(self):
          # VarBeau decrypt: PT = (CT + K) mod 26 (per
          # src/kryptos/kernel/transforms/vigenere.py::varbeau_decrypt).
          # CT='B' (1), K=2 -> PT = (1+2) mod 26 = 3 -> 'D'.
          pt = apply_key_tape(
              "B", tape=(2,),
              variant=CipherVariant.VAR_BEAUFORT,
              direction="decrypt", alphabet=AZ,
          )
          assert pt == "D"

      def test_var_beaufort_roundtrip(self):
          pt = "HELLO"
          tape = (3, 1, 4, 1, 5)
          ct = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.VAR_BEAUFORT,
              direction="encrypt", alphabet=AZ,
          )
          recovered = apply_key_tape(
              ct, tape=tape,
              variant=CipherVariant.VAR_BEAUFORT,
              direction="decrypt", alphabet=AZ,
          )
          assert recovered == pt
  ```

- [ ] **Step 2: Run, verify NotImplementedError**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeVarBeaufort -v`
  Expected: FAIL with `NotImplementedError`.

- [ ] **Step 3: Add VAR_BEAUFORT branch to `_apply_one`**

  Replace the `else` arm:

  Note: the implementer's Task 1 commit already covers VAR_BEAUFORT
  via the `_OP_TABLE` dispatch into `vigenere.py::varbeau_{decrypt,encrypt}`,
  so no `_apply_one` extension is needed. If the Task 1 implementation
  was instead the plan's inline-if/elif scaffold (it was not), the
  correct branch would be:

  ```python
      elif variant == CipherVariant.VAR_BEAUFORT:
          # decrypt: PT = (CT + K) mod 26
          # encrypt: CT = (PT - K) mod 26
          if direction == "decrypt":
              out = (idx + key_val) % 26
          else:
              out = (idx - key_val) % 26
      else:
          raise ValueError(f"unsupported variant: {variant!r}")
  ```

- [ ] **Step 4: Run, verify pass**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py -v`
  Expected: all key_tape tests pass.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py src/kryptos/kernel/transforms/key_tape.py
  git commit -m "key_tape: Variant Beaufort variant (asymmetric)"
  ```

---

## Task 5: KA alphabet support

**Files:**
- Modify: `tests/test_key_tape_kernel.py`

- [ ] **Step 1: Write failing test (KA gives different output than AZ for same tape)**

  Append:

  ```python
  class TestKeyTapeAlphabet:
      def test_ka_differs_from_az(self):
          pt = "KRYPTOS"
          tape = (1, 2, 3, 4, 5, 6, 7)
          ct_az = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="encrypt", alphabet=AZ,
          )
          ct_ka = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="encrypt", alphabet=KA,
          )
          # KA reorders the alphabet, so identical tape under same variant
          # produces a different CT under different alphabets.
          assert ct_az != ct_ka

      def test_ka_roundtrip(self):
          pt = "KRYPTOS"
          tape = (1, 2, 3, 4, 5, 6, 7)
          ct = apply_key_tape(
              pt, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="encrypt", alphabet=KA,
          )
          recovered = apply_key_tape(
              ct, tape=tape,
              variant=CipherVariant.VIGENERE,
              direction="decrypt", alphabet=KA,
          )
          assert recovered == pt
  ```

- [ ] **Step 2: Run, expect pass (no implementation change needed; alphabet is already a parameter)**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeAlphabet -v`
  Expected: 2 passed.

  If `test_ka_differs_from_az` fails because the implementation hardcoded `AZ` somewhere, fix `_apply_one` and `apply_key_tape` to pass `alphabet` through correctly.

- [ ] **Step 3: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py
  git commit -m "key_tape: confirm AZ vs KA alphabet plumbing"
  ```

---

## Task 6: Null insertion — SKIP and CONSUME rules + validation

**Files:**
- Modify: `tests/test_key_tape_kernel.py`
- Modify: `src/kryptos/kernel/transforms/key_tape.py` (add validation)

- [ ] **Step 1: Write failing tests for null behavior + validation**

  Append:

  ```python
  class TestKeyTapeNulls:
      def test_skip_null_rule(self):
          # 6-char text, 2 nulls at {1,4}, 4 non-null positions.
          # Tape length = 4 (matches non-null count under SKIP).
          ct = apply_key_tape(
              "ABCDEF",
              tape=(0, 0, 0, 0),
              variant=CipherVariant.VIGENERE,
              direction="decrypt",
              null_positions=frozenset({1, 4}),
              null_rule="skip",
              alphabet=AZ,
          )
          # tape (0,0,0,0) is identity for Vigenère; non-null positions
          # decrypt to themselves; null positions become '?'.
          assert ct == "A?CD?F"

      def test_consume_null_rule(self):
          # CONSUME advances tape on every position (including nulls).
          # 6-char text, 2 nulls at {1,4}, tape length = 6 (full).
          ct = apply_key_tape(
              "ABCDEF",
              tape=(0, 99, 0, 0, 99, 0),  # values at null positions ignored
              variant=CipherVariant.VIGENERE,
              direction="decrypt",
              null_positions=frozenset({1, 4}),
              null_rule="consume",
              alphabet=AZ,
          )
          assert ct == "A?CD?F"

      def test_skip_short_tape_raises(self):
          # 6 non-null positions, tape length 3 -> exhaustion -> ValueError.
          with pytest.raises(ValueError, match="tape exhausted"):
              apply_key_tape(
                  "ABCDEF",
                  tape=(0, 0, 0),
                  variant=CipherVariant.VIGENERE,
                  null_positions=frozenset(),
                  null_rule="skip",
                  alphabet=AZ,
              )

      def test_consume_short_tape_raises(self):
          # 6 positions total under CONSUME, tape length 3 -> exhaustion at pos 3.
          with pytest.raises(ValueError, match="tape exhausted"):
              apply_key_tape(
                  "ABCDEF",
                  tape=(0, 0, 0),
                  variant=CipherVariant.VIGENERE,
                  null_positions=frozenset({1, 4}),
                  null_rule="consume",
                  alphabet=AZ,
              )

      def test_tape_value_out_of_range_raises(self):
          with pytest.raises(ValueError, match=r"tape\[\d+\]"):
              apply_key_tape(
                  "AB", tape=(26,),  # 26 is out of range
                  variant=CipherVariant.VIGENERE, alphabet=AZ,
              )

      def test_null_position_out_of_range_raises(self):
          with pytest.raises(ValueError, match="null_positions"):
              apply_key_tape(
                  "AB", tape=(0, 0),
                  variant=CipherVariant.VIGENERE,
                  null_positions=frozenset({99}),
                  null_rule="skip",
                  alphabet=AZ,
              )

      def test_empty_tape_raises(self):
          with pytest.raises(ValueError, match="tape must be non-empty"):
              apply_key_tape(
                  "AB", tape=(),
                  variant=CipherVariant.VIGENERE, alphabet=AZ,
              )
  ```

- [ ] **Step 2: Run, expect mixed (some pass, validation tests fail)**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeNulls -v`
  Expected: SKIP and CONSUME basic cases pass (already implemented). The 5 validation tests fail (no validation in scaffold).

- [ ] **Step 3: Add validation at top of `apply_key_tape`**

  Insert before the `out: list[str] = []` line in `apply_key_tape`:

  ```python
      # Input validation.
      if not tape:
          raise ValueError("tape must be non-empty")
      for i, v in enumerate(tape):
          if not (0 <= v <= 25):
              raise ValueError(f"tape[{i}] = {v} out of range [0, 25]")
      n = len(text)
      for p in null_positions:
          if not (0 <= p < n):
              raise ValueError(f"null_positions value {p} out of [0, {n})")
  ```

  Then in the main loop, raise on tape exhaustion. Replace the loop body's `key_val = tape[tape_idx]` line with:

  ```python
          if tape_idx >= len(tape):
              raise ValueError(f"tape exhausted at position {pos} (tape length {len(tape)})")
          key_val = tape[tape_idx]
  ```

  And also raise in the CONSUME branch when advancing past the tape end. Replace the CONSUME `tape_idx += 1` with:

  ```python
              if null_rule == "consume":
                  if tape_idx >= len(tape):
                      raise ValueError(f"tape exhausted at null position {pos} under consume rule")
                  tape_idx += 1
  ```

- [ ] **Step 4: Run all key_tape tests**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py -v`
  Expected: all tests pass.

- [ ] **Step 5: Commit**

  ```bash
  git add tests/test_key_tape_kernel.py src/kryptos/kernel/transforms/key_tape.py
  git commit -m "key_tape: SKIP/CONSUME null rules + input validation"
  ```

---

## Task 7: Compose integration — TransformType.KEY_TAPE + dispatch arm + DSL constants

**Files:**
- Modify: `src/kryptos/kernel/transforms/compose.py` (add enum value + dispatch)
- Modify: `kryptosbot/hypothesis_dsl.py` (add validation constants for new kind)
- Modify: `docs/campaigns/key_tape_dsl_implementation_plan.md` (one-line spec patch: `variant_beaufort` → `var_beaufort`)
- Modify: `tests/test_key_tape_kernel.py` (add compose-level test)

- [ ] **Step 1: Patch the spec to use `var_beaufort` (matches the kernel enum value)**

  In `docs/campaigns/key_tape_dsl_implementation_plan.md` §3, edit the `_VALID_KEY_TAPE_VARIANTS` block from:

  ```python
  _VALID_KEY_TAPE_VARIANTS: frozenset[str] = frozenset({
      "vigenere", "beaufort", "variant_beaufort",
  })
  ```

  to:

  ```python
  _VALID_KEY_TAPE_VARIANTS: frozenset[str] = frozenset({
      "vigenere", "beaufort", "var_beaufort",
  })
  ```

  Add a one-line note in the §3 prose: "Variant strings match `CipherVariant` enum values verbatim — no DSL→kernel mapping layer needed."

- [ ] **Step 2: Add KEY_TAPE to TransformType enum**

  In `src/kryptos/kernel/transforms/compose.py`, locate `class TransformType(str, Enum):` and add:

  ```python
      KEY_TAPE = "key_tape"
  ```

  Place alphabetically or at the end of the enum (match the file's convention).

- [ ] **Step 3: Write failing test that compose dispatches KEY_TAPE**

  Append to `tests/test_key_tape_kernel.py`:

  ```python
  class TestKeyTapeCompose:
      def test_transform_type_key_tape_exists(self):
          from kryptos.kernel.transforms.compose import TransformType
          assert TransformType.KEY_TAPE.value == "key_tape"

      def test_compose_pipeline_with_key_tape(self):
          # Build a single-step pipeline that applies key_tape and
          # confirm it produces the same output as direct apply_key_tape.
          from kryptos.kernel.transforms.compose import (
              TransformConfig, TransformType, build_pipeline,
          )
          ct = "BCDEF"
          tape = (1, 1, 1, 1, 1)
          cfg = TransformConfig(
              type=TransformType.KEY_TAPE,
              params={
                  "tape": tape,
                  "variant": "vigenere",
                  "direction": "decrypt",
                  "null_positions": frozenset(),
                  "null_rule": "skip",
                  "alphabet": "AZ",
              },
          )
          pipeline = build_pipeline([cfg])
          assert pipeline(ct) == "ABCDE"
  ```

- [ ] **Step 4: Run, expect failure on the second test (build_pipeline does not know KEY_TAPE)**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py::TestKeyTapeCompose -v`
  Expected: first test passes, second fails (KeyError or ValueError in build_pipeline).

- [ ] **Step 5: Add KEY_TAPE dispatch arm in `build_pipeline()`**

  In `src/kryptos/kernel/transforms/compose.py`, locate `build_pipeline()` and add a dispatch arm matching the existing pattern. The arm:

  1. Reads `tape`, `variant`, `direction`, `null_positions`, `null_rule`, `alphabet` from `cfg.params`.
  2. Resolves `variant` (string) → `CipherVariant(variant_str)`.
  3. Resolves `alphabet` (string "AZ"/"KA") → the corresponding `Alphabet` singleton.
  4. Returns a closure that calls `apply_key_tape(text, tape=tape, variant=v, direction=d, null_positions=np, null_rule=nr, alphabet=alpha)`.

  Use the existing dispatch arms in the same file as the structural template (they all follow the same closure pattern).

- [ ] **Step 6: Add the DSL validation constants**

  In `kryptosbot/hypothesis_dsl.py`, near the existing `_VALID_CIPHER_KINDS` constant, add:

  ```python
  _VALID_NULL_RULES: frozenset[str] = frozenset({"skip", "consume"})
  _VALID_KEY_TAPE_VARIANTS: frozenset[str] = frozenset({
      "vigenere", "beaufort", "var_beaufort",
  })
  ```

  These are imported by the dispatcher translator in Task 9.

- [ ] **Step 7: Run all key_tape tests**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py -v`
  Expected: all pass.

- [ ] **Step 8: Commit**

  ```bash
  git add docs/campaigns/key_tape_dsl_implementation_plan.md \
          src/kryptos/kernel/transforms/compose.py \
          kryptosbot/hypothesis_dsl.py \
          tests/test_key_tape_kernel.py
  git commit -m "key_tape: TransformType + compose dispatch + DSL constants"
  ```

---

## Task 8: DSL validation — `validate_layer_for_kind("key_tape", ...)`

**Files:**
- Modify: `kryptosbot/hypothesis_dsl.py` (extend `validate_layer_for_kind`)
- Create: `kryptosbot/tests/test_dsl_key_tape.py`

- [ ] **Step 1: Locate `validate_layer_for_kind` to confirm structure**

  Run: `grep -n "def validate_layer_for_kind" kryptosbot/hypothesis_dsl.py`
  Read the surrounding context to understand the existing pattern (which kinds are validated, how errors are returned). This is required before editing — preserve the existing error-return convention.

- [ ] **Step 2: Write failing DSL validation tests**

  Create `kryptosbot/tests/test_dsl_key_tape.py`:

  ```python
  """DSL validation tests for the key_tape kind."""
  import pytest

  from kryptosbot.hypothesis_dsl import validate_layer_for_kind


  def _layer(**params):
      """Minimal layer params for key_tape; tests override fields."""
      base = {
          "tape": (1, 2, 3),
          "variant": "vigenere",
          "alphabet": "AZ",
      }
      base.update(params)
      return base


  class TestKeyTapeDslValidation:
      def test_minimal_valid_layer_accepted(self):
          errors = validate_layer_for_kind("key_tape", _layer())
          assert errors == [], errors

      def test_valid_with_nulls(self):
          errors = validate_layer_for_kind("key_tape", _layer(
              null_positions=(0, 2),
              null_rule="skip",
          ))
          assert errors == [], errors

      def test_missing_tape_rejected(self):
          params = _layer()
          del params["tape"]
          errors = validate_layer_for_kind("key_tape", params)
          assert any("tape" in e for e in errors)

      def test_empty_tape_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(tape=()))
          assert any("tape" in e and ("non-empty" in e or "empty" in e) for e in errors)

      def test_unknown_variant_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(variant="quagmire"))
          assert any("variant" in e for e in errors)

      def test_tape_value_out_of_range_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(tape=(0, 99, 5)))
          assert any("tape" in e and "range" in e for e in errors)

      def test_null_positions_out_of_range_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(
              null_positions=(0, 999),
              null_rule="skip",
          ))
          assert any("null_positions" in e for e in errors)

      def test_null_positions_without_rule_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(
              null_positions=(0, 2),
              # null_rule omitted
          ))
          assert any("null_rule" in e for e in errors)

      def test_unknown_alphabet_rejected(self):
          errors = validate_layer_for_kind("key_tape", _layer(alphabet="ZZ"))
          assert any("alphabet" in e for e in errors)
  ```

- [ ] **Step 3: Run, expect all tests fail (kind not yet handled)**

  Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_dsl_key_tape.py -v`
  Expected: all 9 tests fail (or error if `validate_layer_for_kind` raises on unknown kind).

- [ ] **Step 4: Add `key_tape` validation to `validate_layer_for_kind`**

  In `kryptosbot/hypothesis_dsl.py`, extend `validate_layer_for_kind` with a `key_tape` branch. Follow the existing pattern for other kinds. The branch must check:

  ```python
  if kind == "key_tape":
      from kryptos.kernel.constants import CT_LEN
      errors: list[str] = []
      tape = params.get("tape")
      if tape is None:
          errors.append("key_tape: missing required parameter 'tape'")
      elif not tape:
          errors.append("key_tape: 'tape' must be non-empty")
      else:
          for i, v in enumerate(tape):
              if not isinstance(v, int) or not (0 <= v <= 25):
                  errors.append(f"key_tape: tape[{i}] = {v!r} not in range [0, 25]")
                  break
          if len(tape) > CT_LEN:
              errors.append(f"key_tape: tape length {len(tape)} exceeds CT_LEN {CT_LEN}")

      variant = params.get("variant")
      if variant not in _VALID_KEY_TAPE_VARIANTS:
          errors.append(
              f"key_tape: variant {variant!r} not in {sorted(_VALID_KEY_TAPE_VARIANTS)}"
          )

      alphabet = params.get("alphabet")
      if alphabet not in {"AZ", "KA"}:
          errors.append(f"key_tape: alphabet {alphabet!r} must be 'AZ' or 'KA'")

      null_positions = params.get("null_positions", ())
      null_rule = params.get("null_rule")
      if null_positions:
          for p in null_positions:
              if not isinstance(p, int) or not (0 <= p < CT_LEN):
                  errors.append(
                      f"key_tape: null_positions value {p!r} not in [0, {CT_LEN})"
                  )
                  break
          if null_rule is None:
              errors.append(
                  "key_tape: null_rule required when null_positions is non-empty"
              )
          elif null_rule not in _VALID_NULL_RULES:
              errors.append(
                  f"key_tape: null_rule {null_rule!r} not in {sorted(_VALID_NULL_RULES)}"
              )

      return errors
  ```

  Wire this into the existing dispatch (the function probably has an `if kind == "...":` chain or a dict-based dispatch — match the style).

- [ ] **Step 5: Run all DSL tests**

  Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_dsl_key_tape.py -v`
  Expected: 9 passed.

- [ ] **Step 6: Commit**

  ```bash
  git add kryptosbot/hypothesis_dsl.py kryptosbot/tests/test_dsl_key_tape.py
  git commit -m "key_tape: DSL validation for tape/variant/nulls/alphabet"
  ```

---

## Task 9: Dispatcher translator — `_translate_key_tape` + `_SUPPORTED_KINDS`

**Files:**
- Modify: `kryptosbot/job_dispatcher.py`
- Create: `kryptosbot/tests/test_dispatcher_key_tape.py`

- [ ] **Step 1: Locate existing translators for the structural template**

  Run: `grep -n "^def _translate_\|_SUPPORTED_KINDS\|^def _translate_layer" kryptosbot/job_dispatcher.py`
  Read 1–2 existing translators (e.g. `_translate_columnar`) to mirror the return shape. Translators return `dict[str, Any]`.

- [ ] **Step 2: Write failing dispatcher tests**

  Create `kryptosbot/tests/test_dispatcher_key_tape.py`:

  ```python
  """Dispatcher integration tests for the key_tape kind."""
  import pytest

  from kryptosbot.job_dispatcher import (
      _SUPPORTED_KINDS,
      _kind_has_translation,
      _translate_layer,
  )


  class TestKeyTapeDispatcher:
      def test_kind_in_supported_set(self):
          assert "key_tape" in _SUPPORTED_KINDS

      def test_kind_has_translation(self):
          assert _kind_has_translation("key_tape") is True

      def test_translator_emits_dict(self):
          # Mock CipherLayer with the params we care about.
          class _Layer:
              def __init__(self, params):
                  self.kind = "key_tape"
                  self.params = params

          layer = _Layer({
              "tape": (1, 2, 3, 4, 5),
              "variant": "vigenere",
              "direction": "decrypt",
              "null_positions": (),
              "null_rule": "skip",
              "alphabet": "AZ",
          })
          cfg = _translate_layer(layer, binding={}, text_length=97)
          assert isinstance(cfg, dict)
          assert cfg["type"] == "key_tape"
          assert cfg["tape"] == (1, 2, 3, 4, 5)
          assert cfg["variant"] == "vigenere"
          assert cfg["alphabet"] == "AZ"

      def test_translator_rejects_empty_tape(self):
          class _Layer:
              def __init__(self, params):
                  self.kind = "key_tape"
                  self.params = params

          layer = _Layer({"tape": (), "variant": "vigenere", "alphabet": "AZ"})
          with pytest.raises(ValueError):
              _translate_layer(layer, binding={}, text_length=97)
  ```

  Note: if the existing test suite has a real `CipherLayer` factory or fixture, prefer that over the in-test mock class. Run `grep -rn "class CipherLayer" kryptosbot/` to find it; use the real factory if available.

- [ ] **Step 3: Run tests, expect failures (translator does not exist, kind not in `_SUPPORTED_KINDS`)**

  Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_dispatcher_key_tape.py -v`
  Expected: all 4 fail.

- [ ] **Step 4: Implement `_translate_key_tape` and register it**

  In `kryptosbot/job_dispatcher.py`:

  Add `"key_tape"` to the `_SUPPORTED_KINDS` frozenset.

  Add the translator function (place near other `_translate_*` functions):

  ```python
  def _translate_key_tape(
      layer: "CipherLayer",
      binding: dict[str, Any],
      *,
      text_length: int | None = None,
  ) -> dict[str, Any]:
      """Translate a key_tape DSL layer into a kernel TransformConfig dict.

      Spec: docs/campaigns/key_tape_dsl_implementation_plan.md §5.
      """
      from kryptosbot.hypothesis_dsl import (
          _VALID_KEY_TAPE_VARIANTS, _VALID_NULL_RULES,
      )
      tape = tuple(layer.params.get("tape", ()))
      variant = layer.params.get("variant")
      direction = layer.params.get("direction", "decrypt")
      null_positions = frozenset(layer.params.get("null_positions", ()))
      null_rule = layer.params.get("null_rule")
      alphabet_kind = layer.params.get("alphabet", "AZ")

      if not tape:
          raise ValueError("key_tape: tape must be non-empty")
      if variant not in _VALID_KEY_TAPE_VARIANTS:
          raise ValueError(
              f"key_tape: unsupported variant {variant!r}; "
              f"allowed: {sorted(_VALID_KEY_TAPE_VARIANTS)}"
          )
      if null_positions and null_rule is None:
          raise ValueError(
              "key_tape: null_rule required when null_positions is non-empty"
          )
      if null_rule is not None and null_rule not in _VALID_NULL_RULES:
          raise ValueError(
              f"key_tape: null_rule {null_rule!r} not in {sorted(_VALID_NULL_RULES)}"
          )
      if alphabet_kind not in {"AZ", "KA"}:
          raise ValueError(f"key_tape: alphabet {alphabet_kind!r} must be 'AZ' or 'KA'")

      return {
          "type": "key_tape",
          "tape": tape,
          "variant": variant,
          "direction": direction,
          "null_positions": null_positions,
          "null_rule": null_rule if null_rule is not None else "skip",
          "alphabet": alphabet_kind,
      }
  ```

  Add the dispatch arm in `_translate_layer` matching the existing pattern (it has an `if/elif` chain on `layer.kind`):

  ```python
      elif layer.kind == "key_tape":
          return _translate_key_tape(layer, binding, text_length=text_length)
  ```

- [ ] **Step 5: Run all dispatcher + DSL + kernel tests**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_kernel.py kryptosbot/tests/test_dsl_key_tape.py kryptosbot/tests/test_dispatcher_key_tape.py -v`
  Expected: all pass.

- [ ] **Step 6: Commit**

  ```bash
  git add kryptosbot/job_dispatcher.py kryptosbot/tests/test_dispatcher_key_tape.py
  git commit -m "key_tape: dispatcher translator + _SUPPORTED_KINDS entry"
  ```

---

## Task 10: Audit script verification — `Valid without translation: []`

**Files:**
- Run: `scripts/audit/audit_dsl_dispatcher_semantics.py`
- Modify: `docs/audits/dsl_dispatcher_semantics.md` (regenerate)

- [ ] **Step 1: Run the audit script**

  Run: `PYTHONPATH=src python3 -u scripts/audit/audit_dsl_dispatcher_semantics.py`
  Expected output includes: `Valid without translation: []` (was `['key_tape']` before).

- [ ] **Step 2: Regenerate the audit dossier**

  The audit script should write to `docs/audits/dsl_dispatcher_semantics.md`. If it writes to stdout only, capture and update the dossier manually:

  ```bash
  PYTHONPATH=src python3 -u scripts/audit/audit_dsl_dispatcher_semantics.py > docs/audits/dsl_dispatcher_semantics.md
  ```

  Verify by reading the file: `head -30 docs/audits/dsl_dispatcher_semantics.md`. The new content must show "DSL-valid kinds == Dispatcher-supported kinds" and the date should be updated.

- [ ] **Step 3: Commit**

  ```bash
  git add docs/audits/dsl_dispatcher_semantics.md
  git commit -m "key_tape: audit dossier confirms DSL/dispatcher coverage at 100%"
  ```

---

## Task 11: Synthetic recovery test (16-char fixture)

**Files:**
- Create: `tests/test_key_tape_synthetic_recovery.py`

- [ ] **Step 1: Write the synthetic-recovery test**

  Create `tests/test_key_tape_synthetic_recovery.py`:

  ```python
  """Synthetic recovery test for the key_tape kind.

  Mirror of Stage A/B's synthetic recovery pattern. Encrypts a known
  PT through the dispatcher pipeline, then decrypts with the same
  parameters and asserts roundtrip on non-null positions.

  Spec: docs/campaigns/key_tape_dsl_implementation_plan.md §7.
  """
  import pytest

  from kryptos.kernel.alphabet import AZ
  from kryptos.kernel.transforms.key_tape import apply_key_tape
  from kryptos.kernel.transforms.vigenere import CipherVariant


  PT = "KRYPTOSEXAMPLEAB"  # 16 chars
  TAPE = (7, 3, 1, 2, 5, 8, 11, 4, 9, 0)  # 10 elements
  NULLS = frozenset({2, 5, 8, 11, 14, 15})  # 6 nulls -> 10 non-null

  VARIANTS = [
      CipherVariant.VIGENERE,
      CipherVariant.BEAUFORT,
      CipherVariant.VAR_BEAUFORT,
  ]


  @pytest.mark.parametrize("variant", VARIANTS)
  def test_synthetic_recovery_skip(variant):
      ct = apply_key_tape(
          PT, tape=TAPE, variant=variant,
          direction="encrypt",
          null_positions=NULLS, null_rule="skip", alphabet=AZ,
      )
      pt_recovered = apply_key_tape(
          ct, tape=TAPE, variant=variant,
          direction="decrypt",
          null_positions=NULLS, null_rule="skip", alphabet=AZ,
      )
      # Non-null positions roundtrip exactly; null positions become '?'.
      assert len(pt_recovered) == len(PT)
      for i in range(len(PT)):
          if i in NULLS:
              assert pt_recovered[i] == "?", f"null pos {i} should be '?'"
          else:
              assert pt_recovered[i] == PT[i], (
                  f"non-null pos {i} roundtrip failed: "
                  f"expected {PT[i]!r}, got {pt_recovered[i]!r}"
              )

      # Encrypt should change the non-null letters under any non-trivial tape.
      assert ct != PT


  def test_synthetic_recovery_consume_full_tape():
      # CONSUME requires tape length >= total positions (16).
      tape16 = TAPE + (12, 22, 18, 6, 17, 21)  # length 16
      ct = apply_key_tape(
          PT, tape=tape16, variant=CipherVariant.VIGENERE,
          direction="encrypt",
          null_positions=NULLS, null_rule="consume", alphabet=AZ,
      )
      pt_recovered = apply_key_tape(
          ct, tape=tape16, variant=CipherVariant.VIGENERE,
          direction="decrypt",
          null_positions=NULLS, null_rule="consume", alphabet=AZ,
      )
      for i in range(len(PT)):
          if i in NULLS:
              assert pt_recovered[i] == "?"
          else:
              assert pt_recovered[i] == PT[i]
  ```

- [ ] **Step 2: Run synthetic recovery**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_key_tape_synthetic_recovery.py -v`
  Expected: 4 passed (3 parametrized + 1 consume).

- [ ] **Step 3: Commit**

  ```bash
  git add tests/test_key_tape_synthetic_recovery.py
  git commit -m "key_tape: synthetic recovery across all 3 variants + both null rules"
  ```

---

## Task 12: Known-answer fixture in `tests/audit/known_answer_corpus.json`

**Files:**
- Modify: `tests/audit/known_answer_corpus.json` (add at least one key_tape entry)
- Modify: `tests/test_audit_known_answer_battery.py` (or whichever test consumes the corpus) — only if the consuming test does not auto-discover new entries.

- [ ] **Step 1: Inspect the known-answer corpus structure**

  Run: `head -60 tests/audit/known_answer_corpus.json` and `grep -n "known_answer" tests/test_audit*.py kryptosbot/tests/test_audit*.py`.

  Read 1–2 existing entries and the test that consumes the corpus to understand the schema (kind, params, expected ct/pt, etc.).

- [ ] **Step 2: Add a key_tape entry with a hand-computed expected output**

  Append (or insert in the appropriate position) a new entry to `tests/audit/known_answer_corpus.json` matching the corpus's existing shape. The entry must include:

  - `kind: "key_tape"`
  - A small text (e.g., 8 chars).
  - A small tape (e.g., (1, 2, 3, 4, 5, 6, 7, 8)).
  - `variant: "vigenere"`, `alphabet: "AZ"`, `direction: "encrypt"`.
  - Hand-computed `expected_output`. Verify by running this Python snippet:

  ```python
  PYTHONPATH=src python3 -c "
  from kryptos.kernel.alphabet import AZ
  from kryptos.kernel.transforms.key_tape import apply_key_tape
  from kryptos.kernel.transforms.vigenere import CipherVariant
  print(apply_key_tape('ABCDEFGH', tape=(1,2,3,4,5,6,7,8),
      variant=CipherVariant.VIGENERE, direction='encrypt', alphabet=AZ))
  "
  ```

  Use the printed output as the `expected_output` value.

  Use the existing entry shape from the corpus (the JSON keys vary by codebase convention). If the corpus uses different field names, match them exactly.

- [ ] **Step 3: Run the known-answer battery test**

  Run: `PYTHONPATH=src python3 -m pytest tests/test_audit_known_answer_battery.py -v` (or whichever test file consumes the corpus).
  Expected: pass, including the new key_tape entry.

- [ ] **Step 4: Commit**

  ```bash
  git add tests/audit/known_answer_corpus.json
  git commit -m "key_tape: known-answer fixture (Vigenère AZ, 8-char)"
  ```

---

## Task 13: Documentation updates

**Files:**
- Modify: `CLAUDE.md` (add key_tape gotcha + DSL kind count update)
- Modify: `kryptosbot/ARCHITECTURE.md` (DSL table)
- Modify: `docs/maturation/round3/K4_RUN_PROTOCOL_R3.md` if it lists supported kinds (check first)
- Modify: `docs/campaigns/key_tape_dsl_implementation_plan.md` (mark §11 closure criteria checked)

- [ ] **Step 1: Add a CLAUDE.md gotcha**

  In `CLAUDE.md` Key Gotchas section, add one bullet:

  ```markdown
  - **key_tape variant strings match `CipherVariant` enum values verbatim**: DSL strings are `"vigenere"`, `"beaufort"`, `"var_beaufort"` (note: `var_beaufort`, not `variant_beaufort`). Mismatched casing or the `variant_beaufort` form is rejected at validation. See `kryptosbot/hypothesis_dsl.py::_VALID_KEY_TAPE_VARIANTS`.
  ```

- [ ] **Step 2: Update `kryptosbot/ARCHITECTURE.md` DSL table**

  Locate the DSL kinds table (`grep -n "DSL kinds\|_SUPPORTED_KINDS\|key_tape" kryptosbot/ARCHITECTURE.md`). Add a row for `key_tape` matching the table's existing column structure (kind, brief description, params summary, supported direction).

- [ ] **Step 3: Check the related run-protocol doc**

  Run: `grep -n "key_tape\|DSL kind" docs/maturation/round3/K4_RUN_PROTOCOL_R3.md`
  If `key_tape` is referenced as deferred / not-implemented, update those references. If absent, no change needed.

- [ ] **Step 4: Mark spec §11 closure criteria as ✅**

  In `docs/campaigns/key_tape_dsl_implementation_plan.md` §11, replace each `- [ ]` with `- [x]` for items now satisfied. Add a one-line landed banner near the top:

  ```markdown
  **Status:** LANDED 2026-05-NN (commit <SHA>) — closure criteria §11 all green.
  ```

  Where the SHA is `git rev-parse --short HEAD` after the final closure commit.

- [ ] **Step 5: Commit**

  ```bash
  git add CLAUDE.md kryptosbot/ARCHITECTURE.md docs/campaigns/key_tape_dsl_implementation_plan.md
  # only add K4_RUN_PROTOCOL_R3.md if it was edited:
  git add docs/maturation/round3/K4_RUN_PROTOCOL_R3.md 2>/dev/null || true
  git commit -m "key_tape: docs (CLAUDE.md gotcha, ARCHITECTURE.md DSL row, spec closure)"
  ```

---

## Task 14: Final closure — full test suite + K1/K2 self-test + audit dossier sanity

- [ ] **Step 1: Run full test suite**

  Run: `PYTHONPATH=src python3 -m pytest tests/ kryptosbot/tests/ -q 2>&1 | tail -20`
  Expected: all green. Final test count must be `baseline + N`, where N is the number of new tests added (~25–30). No regressions.

- [ ] **Step 2: Run K1/K2 self-test**

  Run: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run`
  Expected: PASS.

- [ ] **Step 3: Re-run the DSL/dispatcher audit and confirm `Valid without translation: []`**

  Run: `PYTHONPATH=src python3 -u scripts/audit/audit_dsl_dispatcher_semantics.py 2>&1 | grep -i "without translation\|key_tape"`
  Expected: line containing `Valid without translation: []`. If `key_tape` appears anywhere as deferred/missing, that's a regression — investigate before declaring done.

- [ ] **Step 4: Run `python3 -m kryptos doctor`**

  Run: `PYTHONPATH=src python3 -m kryptos doctor`
  Expected: all checks PASS. The doctor verifies Bean constants and other invariants — must remain green.

- [ ] **Step 5: Update MEMORY.md project state entry**

  Mark the workstream landed:

  Edit `MEMORY.md` index entry from "key_tape DSL active" to point at a new "key_tape DSL landed" memory file describing the closure SHA. The corresponding memory file in `.claude/projects/-home-cpatrick-kryptos/memory/` should be created with the landed banner and final test count.

- [ ] **Step 6: Final commit**

  ```bash
  git add MEMORY.md
  git commit -m "key_tape: workstream LANDED — DSL coverage at 100%, all closure criteria green"
  ```

  Then: `git log --oneline -15` to verify the commit history reads as a clean TDD progression.

---

## Self-review checklist (run before declaring plan complete)

- [ ] **Spec coverage:** every line item in `docs/campaigns/key_tape_dsl_implementation_plan.md` §3, §4, §5, §6, §7, §11 has a task in this plan. Skim each closure criterion in §11 and point to the task that satisfies it.
- [ ] **No placeholders:** zero `TBD`, `TODO`, `FIXME`, `implement later`, "add error handling" without showing what.
- [ ] **Type / signature consistency:** `apply_key_tape` signature is identical across Tasks 1, 2, 3, 4, 5, 6, 11. `_translate_key_tape` parameters in Task 9 match the dispatcher pattern. `CipherVariant.VAR_BEAUFORT` (not `VARIANT_BEAUFORT`) used everywhere.
- [ ] **Test ordering:** validation tests (Task 6, Task 8) run after the kind exists in the kernel and DSL. No test references a function that hasn't been introduced.
- [ ] **Commit cadence:** every task ends with a commit. No task batches more than one logical change.

---

*Last updated 2026-05-03. Plan derived from `docs/campaigns/key_tape_dsl_implementation_plan.md` (locked spec, status ACTIVE). Total tasks: 14. Pre-flight + 14 tasks ≈ ~14 hours = ~1.75d, matching spec §8. No automated search delivered (out-of-scope per spec §0). Plan should be executed via `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` (inline).*
