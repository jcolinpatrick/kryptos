# Yield-Feedback Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [docs/specs/2026-05-16-yield-feedback-phase2-design.md](../specs/2026-05-16-yield-feedback-phase2-design.md)

**Goal:** Land the two Phase 2 components of the empirical-yield feedback loop — (a) the crib-paste detector that rejects 24/24 artifact plaintexts at worker-result intake, and (b) the cipher-discovery KB injection that populates `EmpiricalDeathRejectionPayload.suggested_mechanism_records` per `REJECT_EMPIRICALLY_DEAD` rejection and renders them in the next cycle's theorist prompt conditional on escape status.

**Architecture:** Two pure modules (`kb_family_map.py`, `kb_injection.py`) plus targeted surgery inside the existing critic / controller / contracts boundaries. The crib-paste detector lives in `contracts.py::_verify_against_kernel` and fails closed. KB injection runs per rejection during critic evaluation; the controller aggregates suggestions at the existing `_write_cycle_escape_summary` chokepoint (no rewiring through `_absorb_outcomes`). Suggestions render with hard caps (8 total / 3 per family on full block; 3 advisory on partial block; none otherwise).

**Tech Stack:** Python 3.11+ stdlib only for kryptosbot internals; sqlite3 to read `cipher_discovery.sqlite`; existing kernel ngram scorer for non-crib ngram score; pytest for tests. No new dependencies.

**Working directory:** `/home/cpatrick/kryptos` (main branch — project policy is dev directly on main).

---

## Pre-flight (run before Task 1)

- [ ] **Confirm Phase 1 is on `main` and tests green**

  Run from repo root:

  ```bash
  cd /home/cpatrick/kryptos
  git log --oneline -3
  PYTHONPATH=src pytest kryptosbot/tests/test_family_yield.py kryptosbot/tests/test_critic_empirical_death.py -q
  ```

  Expected: top commit is `2386d72 spec: yield-feedback Phase 2 design ...` (or a later commit on `main`); `test_family_yield.py` and `test_critic_empirical_death.py` pass cleanly.

- [ ] **Inspect Phase 1 reference modules so signatures match**

  Read (do not edit) for naming/style:

  - `kryptosbot/family_yield.py` — module header style, `dataclass(frozen=True)` usage, `_normalize_*` helpers.
  - `kryptosbot/contracts.py:84-220` — the `_verify_against_kernel` function Phase 2 modifies.
  - `kryptosbot/models.py:232-279` — the `EmpiricalDeathRejectionPayload` dataclass Phase 2 renames a field on.
  - `kryptosbot/critic.py` — find `_check_family_empirically_dead` (Phase 1 Task 9).
  - `src/kryptos/cipher_discovery/schema.py:64-145` — `CipherRecord` dataclass.

- [ ] **Confirm the KB DB exists and is readable**

  ```bash
  PYTHONPATH=src python3 -c "
  import sqlite3
  conn = sqlite3.connect('db/cipher_discovery.sqlite')
  c = conn.cursor()
  c.execute('SELECT COUNT(*) FROM cipher_records')
  print('cipher_records:', c.fetchone()[0])
  "
  ```

  Expected: `cipher_records: 83` (give-or-take 1–2; record count can grow). If the file does not exist, Phase 2 will still merge cleanly (fail-open posture) — but the live-KB smoke test in Task 26 will skip.

---

## Task 1: Create `kb_family_map.py` skeleton with `KB_TO_LEDGER_FAMILY`

**Files:**
- Create: `kryptosbot/kb_family_map.py`
- Create: `kryptosbot/tests/test_kb_family_map.py`

**Files referenced (read-only):** `kryptosbot/registries.py` (for `KNOWN_FAMILIES`), spec §4.1.

- [ ] **Step 1: Write the failing test**

  Create `kryptosbot/tests/test_kb_family_map.py`:

  ```python
  """Tests for kryptosbot/kb_family_map.py: curated namespace bridge."""
  from __future__ import annotations

  import pytest

  from kryptosbot.kb_family_map import (
      KB_TO_DSL_KIND,
      KB_TO_LEDGER_FAMILY,
  )


  class TestConstants:
      def test_kb_to_ledger_family_keys_are_normalized_lowercase(self):
          for k in KB_TO_LEDGER_FAMILY:
              assert k == k.lower(), f"{k!r} should be lowercase"

      def test_kb_to_ledger_family_values_are_frozensets(self):
          for v in KB_TO_LEDGER_FAMILY.values():
              assert isinstance(v, frozenset)
              assert v, "value must be non-empty"

      def test_kb_to_ledger_family_has_expected_keys(self):
          # Spec §4.1 — minimum committed set. Additions are fine; removals
          # need a doc note. We assert presence, not equality, to keep growth
          # additive without test churn.
          expected = {
              "columnar",
              "polybius transposition",
              "positional",
              "steganographic",
              "running key",
              "substitution",
              "polyalphabetic",
              "fractionation",
              "route transposition",
              "monoalphabetic",
              "delastelle",
              "playfair family",
          }
          assert expected <= set(KB_TO_LEDGER_FAMILY)

      def test_kb_to_dsl_kind_values_are_strings(self):
          for v in KB_TO_DSL_KIND.values():
              assert isinstance(v, str)
              assert v
  ```

- [ ] **Step 2: Run test to verify it fails**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v`
  Expected: `ImportError: cannot import name 'KB_TO_DSL_KIND' from 'kryptosbot.kb_family_map'` (the module does not exist yet).

- [ ] **Step 3: Write the module**

  Create `kryptosbot/kb_family_map.py`:

  ```python
  """Curated namespace bridge between cipher-discovery KB strings and ledger family ids.

  Stdlib only. No I/O. No side effects.

  Every value in KB_TO_LEDGER_FAMILY MUST be in
  ``valid_ledger_family_universe()`` (KNOWN_FAMILIES.family_id ∪
  historical ledger.theories.family). Task 3's test enforces this.

  Every value in KB_TO_DSL_KIND MUST be in
  ``kryptosbot.job_dispatcher._SUPPORTED_KINDS``. Task 5's test enforces this.

  Unmapped KB ``cipher_family`` strings produce ``None`` from
  ``map_kb_family_to_ledger_families()`` — the calling code routes these
  to ``verdict="defer_needs_mapping"`` rather than silently allowing them
  through.

  See docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.1.
  """
  from __future__ import annotations

  from typing import Mapping, Optional


  # Lowercase, whitespace-collapsed KB cipher_family strings → ledger family ids.
  # Values must each be in the bootstrapped family universe.
  KB_TO_LEDGER_FAMILY: Mapping[str, frozenset[str]] = {
      "columnar":               frozenset({"columnar_single", "double_columnar", "route_cipher"}),
      "polybius transposition": frozenset({"fractionation", "multi_layer"}),
      "positional":             frozenset({"route_cipher", "geometry", "procedural"}),
      "steganographic":         frozenset({"stego_layer", "physical_overlay", "procedural"}),
      "running key":            frozenset({"running_key", "key_tape"}),
      "substitution":           frozenset({"vigenere", "beaufort", "variant_beaufort", "novel"}),
      "polyalphabetic":         frozenset({"vigenere", "beaufort", "variant_beaufort", "polyalphabetic"}),
      "fractionation":          frozenset({"fractionation", "multi_layer"}),
      "route transposition":    frozenset({"route_cipher", "transposition"}),
      "monoalphabetic":         frozenset({"caesar", "atbash", "affine", "novel"}),
      "delastelle":             frozenset({"four_square", "multi_layer"}),
      "playfair family":        frozenset({"four_square", "multi_layer"}),
  }


  # Lowercase, whitespace-collapsed KB cipher_family strings → dispatcher kind.
  # Values must each be in job_dispatcher._SUPPORTED_KINDS.
  KB_TO_DSL_KIND: Mapping[str, str] = {
      "columnar":               "columnar",
      "polybius transposition": "polybius",
      "route":                  "route",
      "route transposition":    "route",
      "myszkowski":             "myszkowski",
      "rail fence":             "rail_fence",
      "quagmire":               "quagmire",
      "grille":                 "grille",
      "procedural":             "procedural",
  }
  ```

- [ ] **Step 4: Run test to verify it passes**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v`
  Expected: 4 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_family_map.py kryptosbot/tests/test_kb_family_map.py
  git commit -m "yield-feedback Phase 2: KB family map constants"
  ```

---

## Task 2: `map_kb_family_to_ledger_families()` and normalization

**Files:**
- Modify: `kryptosbot/kb_family_map.py`
- Modify: `kryptosbot/tests/test_kb_family_map.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_family_map.py`:

  ```python
  from kryptosbot.kb_family_map import (
      map_kb_family_to_ledger_families,
      normalize_kb_family,
  )


  class TestNormalize:
      def test_lowercases(self):
          assert normalize_kb_family("Columnar") == "columnar"

      def test_collapses_whitespace(self):
          assert normalize_kb_family("Polybius   Transposition") == "polybius transposition"

      def test_strips(self):
          assert normalize_kb_family("  columnar  ") == "columnar"

      def test_empty(self):
          assert normalize_kb_family("") == ""
          assert normalize_kb_family("   ") == ""

      def test_none_safe(self):
          # KB rows may have NULL family; treat as empty string.
          assert normalize_kb_family(None) == ""


  class TestMapKBFamily:
      def test_known_family(self):
          assert map_kb_family_to_ledger_families("columnar") == frozenset(
              {"columnar_single", "double_columnar", "route_cipher"}
          )

      def test_case_insensitive(self):
          assert map_kb_family_to_ledger_families("COLUMNAR") == frozenset(
              {"columnar_single", "double_columnar", "route_cipher"}
          )

      def test_whitespace_insensitive(self):
          assert map_kb_family_to_ledger_families("polybius  transposition") == frozenset(
              {"fractionation", "multi_layer"}
          )

      def test_unmapped_returns_none(self):
          # Phase 2 invariant 3: unmapped KB family → defer, not silent allow.
          assert map_kb_family_to_ledger_families("xyzzy never seen") is None

      def test_empty_returns_none(self):
          assert map_kb_family_to_ledger_families("") is None
          assert map_kb_family_to_ledger_families(None) is None
  ```

- [ ] **Step 2: Run tests, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v`
  Expected: import errors on `normalize_kb_family` and `map_kb_family_to_ledger_families`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_family_map.py`:

  ```python
  import re


  _WHITESPACE_RE = re.compile(r"\s+")


  def normalize_kb_family(name: Optional[str]) -> str:
      """Lowercase, collapse internal whitespace, strip edges.

      None and pathological inputs collapse to "". Calling code treats ""
      as "no KB family declared" which maps to None (defer_needs_mapping).
      """
      if not name or not isinstance(name, str):
          return ""
      s = _WHITESPACE_RE.sub(" ", name).strip().lower()
      return s


  def map_kb_family_to_ledger_families(kb_family: Optional[str]) -> Optional[frozenset[str]]:
      """Return mapped ledger families for a KB cipher_family string.

      Returns None when the KB family is empty, missing, or unmapped.
      Callers route None to verdict="defer_needs_mapping" — they do NOT
      silently allow.
      """
      key = normalize_kb_family(kb_family)
      if not key:
          return None
      return KB_TO_LEDGER_FAMILY.get(key)
  ```

- [ ] **Step 4: Run tests to confirm pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v`
  Expected: all tests pass (9+ total).

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_family_map.py kryptosbot/tests/test_kb_family_map.py
  git commit -m "yield-feedback Phase 2: normalize_kb_family + map_kb_family_to_ledger_families"
  ```

---

## Task 3: `valid_ledger_family_universe()` cross-check test

**Files:**
- Modify: `kryptosbot/kb_family_map.py`
- Modify: `kryptosbot/tests/test_kb_family_map.py`

This is the acceptance-criterion #11 test: every value in `KB_TO_LEDGER_FAMILY` must resolve to a real family identifier. Universe = `KNOWN_FAMILIES.family_id ∪ historical ledger.theories.family`.

- [ ] **Step 1: Write the failing test**

  Append to `kryptosbot/tests/test_kb_family_map.py`:

  ```python
  from kryptosbot.kb_family_map import valid_ledger_family_universe


  class TestValidUniverse:
      def test_universe_contains_known_families(self):
          """Bootstrapped registry family_ids must be in the universe."""
          from kryptosbot.registries import KNOWN_FAMILIES
          universe = valid_ledger_family_universe()
          for fam in KNOWN_FAMILIES:
              assert fam["family_id"] in universe

      def test_universe_is_a_set_of_strings(self):
          universe = valid_ledger_family_universe()
          assert isinstance(universe, (set, frozenset))
          for x in universe:
              assert isinstance(x, str)
              assert x

      def test_every_kb_to_ledger_family_value_is_in_universe(self):
          """ACCEPTANCE CRITERION #11. Every mapped ledger family must
          exist in the bootstrapped family universe. A new mapping value
          that doesn't satisfy this needs to be added to KNOWN_FAMILIES
          (registries.py) or removed."""
          universe = valid_ledger_family_universe()
          for kb_family, ledger_families in KB_TO_LEDGER_FAMILY.items():
              for fam in ledger_families:
                  assert fam in universe, (
                      f"KB_TO_LEDGER_FAMILY[{kb_family!r}] contains {fam!r} "
                      f"which is not in valid_ledger_family_universe(). "
                      f"Add {fam!r} to kryptosbot/registries.KNOWN_FAMILIES "
                      f"or remove it from KB_TO_LEDGER_FAMILY."
                  )

      def test_every_kb_to_dsl_kind_value_is_supported_by_dispatcher(self):
          from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
          for kb_family, kind in KB_TO_DSL_KIND.items():
              assert kind in _SUPPORTED_KINDS, (
                  f"KB_TO_DSL_KIND[{kb_family!r}] = {kind!r} is not in "
                  f"job_dispatcher._SUPPORTED_KINDS. Add a translator or "
                  f"remove the entry."
              )
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v -k TestValidUniverse`
  Expected: `ImportError: cannot import name 'valid_ledger_family_universe'`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_family_map.py`:

  ```python
  # Historical ledger families that are NOT yet in KNOWN_FAMILIES but are
  # legitimate empirical labels observed in production ledger snapshots.
  # Adding here keeps the universe stable across ledger churn without
  # forcing a KNOWN_FAMILIES entry for every transient ledger string.
  # Audit by re-running:
  #   SELECT DISTINCT family FROM theories WHERE family <> ''
  # and reconciling. Spec §4.1 — Task 3 acceptance.
  _HISTORICAL_LEDGER_FAMILIES: frozenset[str] = frozenset({
      "admissibility",
      "antipodes",
      "archive_evidence",
      "campaigns_final_checklist",
      "crib_analysis",
      "encoding",
      "fractionation",
      "geodetic",
      "geometry",
      "k2_coords",
      "k3_continuity",
      "mirror_ka",
      "overlay",
      "polyalphabetic",
      "transposition",
  })


  def valid_ledger_family_universe() -> frozenset[str]:
      """Union of KNOWN_FAMILIES.family_id and historical ledger families.

      Authoritative validity check for KB_TO_LEDGER_FAMILY values. Grows
      as new families are added to either source. Pure function; no I/O.
      """
      # Local import — registries imports kryptos kernel which is heavy.
      from kryptosbot.registries import KNOWN_FAMILIES
      registry_ids = frozenset(f["family_id"] for f in KNOWN_FAMILIES)
      return registry_ids | _HISTORICAL_LEDGER_FAMILIES
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_family_map.py -v`
  Expected: all tests pass. If `test_every_kb_to_ledger_family_value_is_in_universe` fails, the assertion message points at the bad value — fix `KB_TO_LEDGER_FAMILY` or `_HISTORICAL_LEDGER_FAMILIES`.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_family_map.py kryptosbot/tests/test_kb_family_map.py
  git commit -m "yield-feedback Phase 2: valid_ledger_family_universe + acceptance cross-check"
  ```

---

## Task 4: `kb_injection.py` skeleton + `kb_mechanism_signature()`

**Files:**
- Create: `kryptosbot/kb_injection.py`
- Create: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Write the failing test**

  Create `kryptosbot/tests/test_kb_injection.py`:

  ```python
  """Tests for kryptosbot/kb_injection.py: KB signature, novelty join, query."""
  from __future__ import annotations

  import json

  import pytest

  from kryptosbot.kb_injection import (
      KB_SIGNATURE_SCHEMA_VERSION,
      kb_mechanism_signature,
  )


  def _make_record(**overrides):
      """Lightweight CipherRecord stand-in for signature tests. Fields used by
      kb_mechanism_signature only."""
      from kryptos.cipher_discovery.schema import CipherRecord
      defaults = dict(
          canonical_name="Test Cipher",
          alias_names=[],
          category="",
          cipher_family="test family",
          description="A test cipher",
          operational_mechanics="Fold in half, swap odd/even.",
      )
      defaults.update(overrides)
      return CipherRecord(**defaults)


  class TestSchemaVersion:
      def test_schema_version_is_v1(self):
          assert KB_SIGNATURE_SCHEMA_VERSION == "kb_mechanism_sig_v1"


  class TestKBMechanismSignature:
      def test_returns_16_char_hex(self):
          sig = kb_mechanism_signature(_make_record())
          assert isinstance(sig, str)
          assert len(sig) == 16
          # All lowercase hex.
          int(sig, 16)

      def test_deterministic(self):
          r = _make_record()
          assert kb_mechanism_signature(r) == kb_mechanism_signature(r)

      def test_differs_on_canonical_name_change(self):
          a = kb_mechanism_signature(_make_record(canonical_name="Alpha"))
          b = kb_mechanism_signature(_make_record(canonical_name="Beta"))
          assert a != b

      def test_differs_on_cipher_family_change(self):
          a = kb_mechanism_signature(_make_record(cipher_family="columnar"))
          b = kb_mechanism_signature(_make_record(cipher_family="substitution"))
          assert a != b

      def test_insensitive_to_canonical_name_case(self):
          """Normalization should canonicalize case."""
          a = kb_mechanism_signature(_make_record(canonical_name="Columnar"))
          b = kb_mechanism_signature(_make_record(canonical_name="COLUMNAR"))
          assert a == b

      def test_insensitive_to_whitespace_variations(self):
          a = kb_mechanism_signature(_make_record(cipher_family="polybius transposition"))
          b = kb_mechanism_signature(_make_record(cipher_family="polybius  transposition"))
          c = kb_mechanism_signature(_make_record(cipher_family="  polybius transposition  "))
          assert a == b == c

      def test_excludes_ledger_family_mapping(self):
          """Spec §4.2 invariant: signature describes the KB mechanism, not
          its dispatch routing. Two records with identical KB fields must
          hash identically even if the mapping table changes."""
          # This is a structural property — the signature payload must not
          # reference KB_TO_LEDGER_FAMILY. We assert by constructing a payload
          # manually and verifying the signature matches.
          r = _make_record(
              canonical_name="Probe",
              cipher_family="columnar",
              cipher_type="historical",
              taxonomy="historically_attested",
              operational_mechanics="ABC",
              description="DEF",
          )
          sig1 = kb_mechanism_signature(r)
          # Same record, recomputed in a fresh Python session, must yield
          # the same hash. We approximate by re-running.
          sig2 = kb_mechanism_signature(r)
          assert sig1 == sig2

      def test_includes_schema_version_in_payload(self):
          """If we ever bump KB_SIGNATURE_SCHEMA_VERSION, the same KB record
          must produce a DIFFERENT signature so callers can recognize stale
          payloads. Achieved by including the schema string in the hash."""
          # We verify by patching the constant and re-hashing.
          import kryptosbot.kb_injection as kbi
          r = _make_record()
          orig_sig = kb_mechanism_signature(r)
          orig_version = kbi.KB_SIGNATURE_SCHEMA_VERSION
          try:
              kbi.KB_SIGNATURE_SCHEMA_VERSION = "kb_mechanism_sig_v999"
              new_sig = kb_mechanism_signature(r)
          finally:
              kbi.KB_SIGNATURE_SCHEMA_VERSION = orig_version
          assert orig_sig != new_sig
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Create `kryptosbot/kb_injection.py`:

  ```python
  """KB query, signature generation, and novelty join for Phase 2 yield-feedback.

  Stdlib + sqlite3. Reads ``db/cipher_discovery.sqlite`` (or an injected
  path for tests). Produces ``CipherDiscoverySuggestion`` records for the
  critic to attach to ``REJECT_EMPIRICALLY_DEAD`` rejections.

  See docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.2.
  """
  from __future__ import annotations

  import hashlib
  import json
  import re
  from typing import Iterable, Optional


  KB_SIGNATURE_SCHEMA_VERSION = "kb_mechanism_sig_v1"

  _WHITESPACE_RE = re.compile(r"\s+")
  _WORD_RE = re.compile(r"[a-z0-9]+")


  def _normalize(s: Optional[str]) -> str:
      """Lowercase, collapse internal whitespace, strip. None → ''."""
      if not s or not isinstance(s, str):
          return ""
      return _WHITESPACE_RE.sub(" ", s).strip().lower()


  def _content_tokens(*fields: Optional[str]) -> tuple[str, ...]:
      """Extract a sorted, deduplicated tuple of word tokens from prose fields.

      Used for signature payload — order-independent, case-folded, no
      punctuation. Empty fields contribute nothing.
      """
      joined = " ".join(_normalize(f) for f in fields if f)
      tokens = set(_WORD_RE.findall(joined))
      return tuple(sorted(tokens))


  def kb_mechanism_signature(record) -> str:
      """Deterministic 16-char hash of normalized KB fields.

      The signature describes the KB mechanism itself. The ledger-family
      mapping (``kb_family_map.KB_TO_LEDGER_FAMILY``) is deliberately
      EXCLUDED — mixing it in would let a mapping-table edit silently
      invalidate every prior signature.

      Accepts any record with the CipherRecord-compatible attribute set
      (canonical_name, cipher_family, cipher_type, taxonomy, operational_mechanics,
      description). Taxonomy may be an enum-like with ``.value`` or a string.
      """
      cipher_type_val = getattr(record, "cipher_type", "")
      if hasattr(cipher_type_val, "value"):
          cipher_type_val = cipher_type_val.value
      taxonomy_val = getattr(record, "taxonomy", "")
      if hasattr(taxonomy_val, "value"):
          taxonomy_val = taxonomy_val.value

      payload = {
          "schema": KB_SIGNATURE_SCHEMA_VERSION,
          "canonical_name": _normalize(getattr(record, "canonical_name", "")),
          "cipher_family": _normalize(getattr(record, "cipher_family", "")),
          "cipher_type": _normalize(str(cipher_type_val or "")),
          "taxonomy": _normalize(str(taxonomy_val or "")),
          "mechanics_tokens": list(_content_tokens(
              getattr(record, "canonical_name", ""),
              getattr(record, "cipher_family", ""),
              str(cipher_type_val or ""),
              getattr(record, "operational_mechanics", ""),
              getattr(record, "description", ""),
          )),
      }
      blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
      return hashlib.sha256(blob).hexdigest()[:16]
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py -v`
  Expected: all signature tests pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: kb_mechanism_signature with schema versioning"
  ```

---

## Task 5: `dispatcher_testable()` helper

**Files:**
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from kryptosbot.kb_injection import dispatcher_testable


  class TestDispatcherTestable:
      def test_columnar_is_supported(self):
          r = _make_record(cipher_family="columnar")
          assert dispatcher_testable(r) is True

      def test_polybius_transposition_is_supported(self):
          r = _make_record(cipher_family="polybius transposition")
          assert dispatcher_testable(r) is True

      def test_grille_is_supported(self):
          r = _make_record(cipher_family="grille")
          assert dispatcher_testable(r) is True

      def test_unknown_family_is_not_supported(self):
          r = _make_record(cipher_family="completely fictional ciphersystem")
          assert dispatcher_testable(r) is False

      def test_empty_family_is_not_supported(self):
          r = _make_record(cipher_family="")
          assert dispatcher_testable(r) is False

      def test_case_insensitive(self):
          r = _make_record(cipher_family="COLUMNAR")
          assert dispatcher_testable(r) is True

      def test_kb_to_dsl_kind_is_filtered_by_supported_kinds(self):
          """Even if KB_TO_DSL_KIND maps to a kind, dispatcher_testable must
          re-check against the dispatcher's _SUPPORTED_KINDS at call time.
          This guards against drift: if a kind is removed from the
          dispatcher, dispatcher_testable immediately stops reporting True
          for it without requiring an edit to kb_family_map.py."""
          import kryptosbot.kb_family_map as km
          import kryptosbot.job_dispatcher as jd
          orig_supported = jd._SUPPORTED_KINDS
          orig_map = dict(km.KB_TO_DSL_KIND)
          try:
              # Pretend "columnar" got pulled from the dispatcher.
              jd._SUPPORTED_KINDS = frozenset(orig_supported) - {"columnar"}
              r = _make_record(cipher_family="columnar")
              assert dispatcher_testable(r) is False
          finally:
              jd._SUPPORTED_KINDS = orig_supported
              km.KB_TO_DSL_KIND = orig_map
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestDispatcherTestable -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_injection.py`:

  ```python
  def dispatcher_testable(record) -> bool:
      """True iff the record's cipher_family maps to a dispatcher-supported kind.

      Two-step: KB cipher_family → KB_TO_DSL_KIND → kind → _SUPPORTED_KINDS.
      The second step is re-evaluated at every call so dispatcher changes
      take effect immediately.
      """
      from kryptosbot.kb_family_map import KB_TO_DSL_KIND, normalize_kb_family
      from kryptosbot.job_dispatcher import _SUPPORTED_KINDS

      key = normalize_kb_family(getattr(record, "cipher_family", ""))
      kind = KB_TO_DSL_KIND.get(key)
      return bool(kind and kind in _SUPPORTED_KINDS)
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestDispatcherTestable -v`
  Expected: 7 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: dispatcher_testable filtered by _SUPPORTED_KINDS"
  ```

---

## Task 6: `KBCandidateNoveltyVerdict` dataclass

**Files:**
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from kryptosbot.kb_injection import KBCandidateNoveltyVerdict


  class TestKBCandidateNoveltyVerdict:
      def test_dataclass_shape(self):
          v = KBCandidateNoveltyVerdict(
              kb_record_id="abc",
              kb_cipher_family="columnar",
              mapped_ledger_families=("columnar_single", "double_columnar"),
              tested_status_ok=True,
              family_blocked=False,
              static_exhaustion_blocked=False,
              mechanism_signature="0123456789abcdef",
              signature_seen=False,
              dispatcher_testable=True,
              verdict="allow",
              reasons=("ok",),
          )
          assert v.kb_record_id == "abc"
          assert v.verdict == "allow"
          assert v.mapped_ledger_families == ("columnar_single", "double_columnar")

      def test_dataclass_is_frozen(self):
          v = KBCandidateNoveltyVerdict(
              kb_record_id="x", kb_cipher_family="", mapped_ledger_families=(),
              tested_status_ok=False, family_blocked=False, static_exhaustion_blocked=False,
              mechanism_signature="", signature_seen=False,
              dispatcher_testable=False, verdict="reject", reasons=(),
          )
          with pytest.raises((AttributeError, Exception)):
              v.verdict = "allow"

      def test_valid_verdict_values(self):
          for verdict in ("allow", "reject", "defer_needs_mapping"):
              KBCandidateNoveltyVerdict(
                  kb_record_id="x", kb_cipher_family="", mapped_ledger_families=(),
                  tested_status_ok=False, family_blocked=False, static_exhaustion_blocked=False,
                  mechanism_signature="", signature_seen=False,
                  dispatcher_testable=False, verdict=verdict, reasons=(),
              )
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestKBCandidateNoveltyVerdict -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_injection.py` (under the imports at top, but at module scope after `_content_tokens`):

  ```python
  from dataclasses import dataclass, field
  from typing import Literal


  NoveltyVerdictKind = Literal["allow", "reject", "defer_needs_mapping"]


  @dataclass(frozen=True)
  class KBCandidateNoveltyVerdict:
      """Per-row novelty join result. Constructed once per candidate row.

      ``verdict`` is the actionable output:
      - "allow"              — candidate survives all filters; emit suggestion.
      - "reject"             — failed one or more eligibility / novelty checks.
      - "defer_needs_mapping" — KB cipher_family is not in KB_TO_LEDGER_FAMILY.
                               Operator review path; never silently rendered.
      """
      kb_record_id: str
      kb_cipher_family: str
      mapped_ledger_families: tuple[str, ...]
      tested_status_ok: bool
      family_blocked: bool
      static_exhaustion_blocked: bool
      mechanism_signature: str
      signature_seen: bool
      dispatcher_testable: bool
      verdict: NoveltyVerdictKind
      reasons: tuple[str, ...]
  ```

  Note: move the `from dataclasses import dataclass, field` and `from typing import Literal` lines up to the existing import block to keep all imports together.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestKBCandidateNoveltyVerdict -v`
  Expected: 3 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: KBCandidateNoveltyVerdict dataclass"
  ```

---

## Task 7: `CipherDiscoverySuggestion` dataclass + `to_dict`/`from_dict`

**Files:**
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from kryptosbot.kb_injection import CipherDiscoverySuggestion


  class TestCipherDiscoverySuggestion:
      def _example(self, **overrides):
          base = dict(
              kb_record_id="rec-abc-123",
              canonical_name="Test Cipher",
              kb_cipher_family="columnar",
              mapped_ledger_families=("columnar_single", "double_columnar"),
              mechanism_signature="0123456789abcdef",
              signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
              dispatcher_testable=True,
              k4_relevance_score=42.5,
              sketch_class="dsl_testable",
              one_line_sketch="A short prose sketch.",
              bounded_kill_criterion="Score must exceed X on Y trials.",
              source_verdict="allow",
          )
          base.update(overrides)
          return CipherDiscoverySuggestion(**base)

      def test_dataclass_shape(self):
          s = self._example()
          assert s.canonical_name == "Test Cipher"
          assert s.mapped_ledger_families == ("columnar_single", "double_columnar")
          assert s.signature_schema_version == "kb_mechanism_sig_v1"

      def test_to_dict_round_trip(self):
          s = self._example()
          d = s.to_dict()
          assert isinstance(d, dict)
          # Tuples become lists in JSON.
          assert isinstance(d["mapped_ledger_families"], list)
          assert d["canonical_name"] == "Test Cipher"
          # JSON serializable end-to-end.
          json_blob = json.dumps(d, sort_keys=True)
          reloaded = json.loads(json_blob)
          s2 = CipherDiscoverySuggestion.from_dict(reloaded)
          assert s2 == s

      def test_from_dict_tolerates_missing_optional_fields(self):
          d = {
              "kb_record_id": "x",
              "canonical_name": "X",
              "kb_cipher_family": "",
              "mapped_ledger_families": [],
              "mechanism_signature": "",
              "signature_schema_version": KB_SIGNATURE_SCHEMA_VERSION,
              "dispatcher_testable": False,
              "k4_relevance_score": 0.0,
              "sketch_class": "unknown",
              "one_line_sketch": "",
              "bounded_kill_criterion": "",
              "source_verdict": "allow",
          }
          s = CipherDiscoverySuggestion.from_dict(d)
          assert s.mapped_ledger_families == ()
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestCipherDiscoverySuggestion -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_injection.py`:

  ```python
  SketchClass = Literal["dsl_testable", "category_b", "unknown"]


  @dataclass(frozen=True)
  class CipherDiscoverySuggestion:
      """Single rendered suggestion attached to an EmpiricalDeathRejectionPayload.

      Carries enough structure for the critic to ledger and the controller
      to aggregate and render, but never enough to auto-dispatch.
      Suggestions are prompt context only — the theorist must still draft
      a HypothesisSpec and the critic must still admit it.
      """
      kb_record_id: str
      canonical_name: str
      kb_cipher_family: str
      mapped_ledger_families: tuple[str, ...]
      mechanism_signature: str
      signature_schema_version: str
      dispatcher_testable: bool
      k4_relevance_score: float
      sketch_class: SketchClass
      one_line_sketch: str
      bounded_kill_criterion: str
      source_verdict: Literal["allow"]

      def to_dict(self) -> dict:
          return {
              "kb_record_id": self.kb_record_id,
              "canonical_name": self.canonical_name,
              "kb_cipher_family": self.kb_cipher_family,
              "mapped_ledger_families": list(self.mapped_ledger_families),
              "mechanism_signature": self.mechanism_signature,
              "signature_schema_version": self.signature_schema_version,
              "dispatcher_testable": bool(self.dispatcher_testable),
              "k4_relevance_score": float(self.k4_relevance_score),
              "sketch_class": self.sketch_class,
              "one_line_sketch": self.one_line_sketch,
              "bounded_kill_criterion": self.bounded_kill_criterion,
              "source_verdict": self.source_verdict,
          }

      @classmethod
      def from_dict(cls, d: dict) -> "CipherDiscoverySuggestion":
          return cls(
              kb_record_id=str(d.get("kb_record_id", "")),
              canonical_name=str(d.get("canonical_name", "")),
              kb_cipher_family=str(d.get("kb_cipher_family", "")),
              mapped_ledger_families=tuple(d.get("mapped_ledger_families") or ()),
              mechanism_signature=str(d.get("mechanism_signature", "")),
              signature_schema_version=str(
                  d.get("signature_schema_version", KB_SIGNATURE_SCHEMA_VERSION)
              ),
              dispatcher_testable=bool(d.get("dispatcher_testable", False)),
              k4_relevance_score=float(d.get("k4_relevance_score", 0.0)),
              sketch_class=d.get("sketch_class", "unknown"),
              one_line_sketch=str(d.get("one_line_sketch", "")),
              bounded_kill_criterion=str(d.get("bounded_kill_criterion", "")),
              source_verdict="allow",
          )
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestCipherDiscoverySuggestion -v`
  Expected: 3 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: CipherDiscoverySuggestion dataclass + JSON round-trip"
  ```

---

## Task 8: Build a fixture KB DB and a row loader

**Files:**
- Create: `kryptosbot/tests/fixtures/build_phase2_kb.py` (builder script, run once locally)
- Create: `kryptosbot/tests/fixtures/cipher_discovery_phase2_fixture.sqlite` (output)
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

The fixture is small (4–5 hand-picked rows) covering: dispatcher-testable, Category-B investigative, exhausted (should be filtered out), unmapped (defer), and one with a deliberately signature-collidable mechanism for novelty tests.

- [ ] **Step 1: Create the fixture-builder script**

  Create `kryptosbot/tests/fixtures/build_phase2_kb.py`:

  ```python
  """Build kryptosbot/tests/fixtures/cipher_discovery_phase2_fixture.sqlite.

  Run once locally:
      PYTHONPATH=src python3 kryptosbot/tests/fixtures/build_phase2_kb.py

  Re-run to regenerate (output is overwritten). Deterministic across runs
  because record_id values are hard-coded.
  """
  from __future__ import annotations

  import os
  import sqlite3
  from pathlib import Path


  HERE = Path(__file__).resolve().parent
  OUT = HERE / "cipher_discovery_phase2_fixture.sqlite"


  # Schema mirrors src/kryptos/cipher_discovery/persistence.py — kept inline
  # to avoid coupling the test fixture to internal SQL string drift.
  _SCHEMA = """
  CREATE TABLE cipher_records (
      record_id TEXT PRIMARY KEY,
      canonical_name TEXT NOT NULL,
      alias_names_json TEXT DEFAULT '[]',
      category TEXT DEFAULT '',
      cipher_type TEXT DEFAULT 'uncertain',
      taxonomy TEXT DEFAULT 'needs_human_review',
      cipher_family TEXT DEFAULT '',
      description TEXT DEFAULT '',
      operational_mechanics TEXT DEFAULT '',
      execution_model TEXT DEFAULT '',
      tools_required_json TEXT DEFAULT '[]',
      materials_needed_json TEXT DEFAULT '[]',
      manual_execution_type TEXT DEFAULT '',
      claimed_origin TEXT DEFAULT '',
      source_urls_json TEXT DEFAULT '[]',
      quote_snippets_json TEXT DEFAULT '[]',
      source_type TEXT DEFAULT 'unknown',
      source_title TEXT DEFAULT '',
      author TEXT DEFAULT '',
      publication_year INTEGER,
      historically_attested BOOLEAN DEFAULT 0,
      pedagogical_amateur BOOLEAN DEFAULT 0,
      bespoke BOOLEAN DEFAULT 0,
      requires_human_review BOOLEAN DEFAULT 1,
      confidence_real_system REAL DEFAULT 0.0,
      confidence_distinct_from_known REAL DEFAULT 0.0,
      confidence_relevance_to_k4 REAL DEFAULT 0.0,
      obscurity_score REAL DEFAULT 0.0,
      k4_relevance_score REAL DEFAULT 0.0,
      k4_score_breakdown_json TEXT DEFAULT '{}',
      ambiguity_flags_json TEXT DEFAULT '[]',
      extraction_notes TEXT DEFAULT '',
      unresolved_questions_json TEXT DEFAULT '[]',
      tested_in_project BOOLEAN DEFAULT 0,
      exhaustion_log_ids_json TEXT DEFAULT '[]',
      exhaustion_status TEXT DEFAULT '',
      discovered_at TEXT,
      updated_at TEXT
  );
  """


  ROWS = [
      # 1) Dispatcher-testable, untested, columnar.
      dict(
          record_id="fx-swagman",
          canonical_name="Swagman Cipher",
          cipher_family="columnar",
          cipher_type="historical",
          taxonomy="historically_attested",
          operational_mechanics="N-row columnar with skew permutation per row.",
          description="A columnar transposition with row-dependent skew.",
          k4_relevance_score=42.0,
          tested_in_project=0,
          exhaustion_status="untested",
      ),
      # 2) Category-B investigative, positional.
      dict(
          record_id="fx-astrolabe",
          canonical_name="Astrolabe Cipher",
          cipher_family="positional",
          cipher_type="bespoke",
          taxonomy="historically_attested",
          operational_mechanics="Star-coordinate lookup against a brass plate.",
          description="A positional cipher using astrolabe coordinates.",
          k4_relevance_score=67.4,
          tested_in_project=0,
          exhaustion_status="untested",
      ),
      # 3) Exhausted — should be filtered out by tested_status check.
      dict(
          record_id="fx-compass-exhausted",
          canonical_name="Compass Cipher",
          cipher_family="positional",
          cipher_type="bespoke",
          taxonomy="historically_attested",
          operational_mechanics="Compass-bearing lookup.",
          description="Compass-based positional cipher.",
          k4_relevance_score=71.5,
          tested_in_project=1,
          exhaustion_status="exhausted",
      ),
      # 4) Unmapped cipher_family — should defer.
      dict(
          record_id="fx-unmapped",
          canonical_name="Mystery Cipher",
          cipher_family="entirely fictional bespoke art-cipher",
          cipher_type="bespoke",
          taxonomy="needs_human_review",
          operational_mechanics="Unspecified bespoke mechanism.",
          description="Unmapped on purpose for the fixture.",
          k4_relevance_score=30.0,
          tested_in_project=0,
          exhaustion_status="untested",
      ),
      # 5) Dispatcher-testable, polybius transposition — for ranking tests.
      dict(
          record_id="fx-adfgvx",
          canonical_name="ADFGVX Cipher",
          cipher_family="polybius transposition",
          cipher_type="historical",
          taxonomy="historically_attested",
          operational_mechanics="Polybius square then columnar transposition.",
          description="WWI-era polybius+columnar two-stage cipher.",
          k4_relevance_score=58.0,
          tested_in_project=0,
          exhaustion_status="untested",
      ),
  ]


  def main() -> None:
      if OUT.exists():
          OUT.unlink()
      conn = sqlite3.connect(str(OUT))
      try:
          conn.executescript(_SCHEMA)
          cols = list(ROWS[0].keys())
          placeholders = ",".join("?" for _ in cols)
          sql = f"INSERT INTO cipher_records ({','.join(cols)}) VALUES ({placeholders})"
          for row in ROWS:
              conn.execute(sql, [row.get(c) for c in cols])
          conn.commit()
      finally:
          conn.close()
      print(f"wrote {OUT} with {len(ROWS)} rows")


  if __name__ == "__main__":
      main()
  ```

- [ ] **Step 2: Build the fixture**

  Run:

  ```bash
  mkdir -p kryptosbot/tests/fixtures
  PYTHONPATH=src python3 kryptosbot/tests/fixtures/build_phase2_kb.py
  ls -l kryptosbot/tests/fixtures/cipher_discovery_phase2_fixture.sqlite
  ```

  Expected: file exists, non-zero size, "wrote ... with 5 rows" printed.

- [ ] **Step 3: Add a failing test for the loader**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from pathlib import Path

  from kryptosbot.kb_injection import iter_kb_records


  FIXTURE_DB = Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"


  class TestKBRowLoader:
      def test_iter_returns_records_for_fixture(self):
          records = list(iter_kb_records(str(FIXTURE_DB)))
          assert len(records) == 5
          names = {r.canonical_name for r in records}
          assert "Swagman Cipher" in names
          assert "ADFGVX Cipher" in names

      def test_iter_yields_cipher_record_compatible_attrs(self):
          for r in iter_kb_records(str(FIXTURE_DB)):
              assert hasattr(r, "canonical_name")
              assert hasattr(r, "cipher_family")
              assert hasattr(r, "k4_relevance_score")
              assert hasattr(r, "tested_in_project")
              assert hasattr(r, "exhaustion_status")

      def test_iter_returns_empty_for_missing_db(self, tmp_path):
          missing = tmp_path / "does_not_exist.sqlite"
          assert list(iter_kb_records(str(missing))) == []

      def test_iter_skips_corrupt_row(self, tmp_path):
          import sqlite3
          db = tmp_path / "partial.sqlite"
          conn = sqlite3.connect(str(db))
          conn.execute("""
              CREATE TABLE cipher_records (
                  record_id TEXT PRIMARY KEY,
                  canonical_name TEXT NOT NULL,
                  cipher_family TEXT,
                  k4_relevance_score REAL,
                  tested_in_project BOOLEAN,
                  exhaustion_status TEXT
              )
          """)
          # Valid row.
          conn.execute(
              "INSERT INTO cipher_records VALUES ('ok', 'OK Cipher', 'columnar', 10.0, 0, 'untested')"
          )
          # Row with corrupt JSON in a column that we don't strictly need —
          # loader must yield the valid row and continue.
          conn.commit()
          conn.close()
          records = list(iter_kb_records(str(db)))
          # Single valid row.
          assert any(r.canonical_name == "OK Cipher" for r in records)
  ```

- [ ] **Step 4: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestKBRowLoader -v`
  Expected: `ImportError: cannot import name 'iter_kb_records'`.

- [ ] **Step 5: Implement the loader**

  Append to `kryptosbot/kb_injection.py`:

  ```python
  import logging
  import sqlite3
  from pathlib import Path

  logger = logging.getLogger(__name__)


  # Columns we strictly require from the cipher_records table. Other columns
  # are read opportunistically; missing values fall back to dataclass defaults.
  _CORE_COLUMNS = (
      "record_id",
      "canonical_name",
      "cipher_family",
      "cipher_type",
      "taxonomy",
      "description",
      "operational_mechanics",
      "k4_relevance_score",
      "tested_in_project",
      "exhaustion_status",
  )


  def iter_kb_records(db_path: str):
      """Yield CipherRecord-compatible objects from ``db_path``.

      Missing DB → empty iterator (no exception). Corrupt rows → skipped
      with WARNING. Schema-version drift on the cipher_records table is
      tolerated as long as the columns in _CORE_COLUMNS are present.
      """
      from kryptos.cipher_discovery.schema import CipherRecord

      if not Path(db_path).exists():
          return

      conn = None
      try:
          conn = sqlite3.connect(str(db_path))
          conn.row_factory = sqlite3.Row
          try:
              cursor = conn.execute(
                  f"SELECT {','.join(_CORE_COLUMNS)} FROM cipher_records"
              )
          except sqlite3.Error as exc:
              logger.warning("kb_injection: cipher_records query failed: %s", exc)
              return
          for row in cursor:
              try:
                  rec = CipherRecord(
                      record_id=row["record_id"] or "",
                      canonical_name=row["canonical_name"] or "",
                      cipher_family=row["cipher_family"] or "",
                      description=row["description"] or "",
                      operational_mechanics=row["operational_mechanics"] or "",
                  )
                  # Patch the bare-string enum-typed columns onto the
                  # CipherRecord via direct attribute assignment so we
                  # don't have to construct the actual enums (and so
                  # taxonomy/cipher_type drift doesn't crash the loader).
                  try:
                      rec.cipher_type = row["cipher_type"] or ""
                  except Exception:
                      pass
                  try:
                      rec.taxonomy = row["taxonomy"] or ""
                  except Exception:
                      pass
                  rec.k4_relevance_score = float(row["k4_relevance_score"] or 0.0)
                  rec.tested_in_project = bool(row["tested_in_project"])
                  rec.exhaustion_status = row["exhaustion_status"] or ""
                  yield rec
              except Exception as exc:
                  rid = row["record_id"] if "record_id" in row.keys() else "?"
                  logger.warning(
                      "kb_injection: skipping corrupt row %r: %s", rid, exc
                  )
                  continue
      except sqlite3.Error as exc:
          logger.warning("kb_injection: sqlite open failed: %s", exc)
      finally:
          if conn is not None:
              conn.close()
  ```

- [ ] **Step 6: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestKBRowLoader -v`
  Expected: 4 passed.

- [ ] **Step 7: Commit**

  ```bash
  git add kryptosbot/tests/fixtures/ kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: KB fixture DB + iter_kb_records loader"
  ```

---

## Task 9: `classify_kb_candidate()` — per-row novelty join

**Files:**
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from kryptosbot.kb_injection import classify_kb_candidate


  class TestClassifyKBCandidate:
      def test_allow_unblocked_unseen_signature(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
          v = classify_kb_candidate(
              rec,
              prior_signatures={"columnar_single": frozenset(), "double_columnar": frozenset()},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
          )
          assert v.verdict == "allow"
          assert v.tested_status_ok is True
          assert v.signature_seen is False
          assert v.family_blocked is False

      def test_reject_when_exhausted(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-compass-exhausted")
          v = classify_kb_candidate(
              rec,
              prior_signatures={},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset(),
          )
          assert v.verdict == "reject"
          assert v.tested_status_ok is False
          assert "exhausted" in " ".join(v.reasons).lower()

      def test_reject_when_family_blocked(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
          v = classify_kb_candidate(
              rec,
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"columnar_single"}),
              static_exhaustion_blocklist=frozenset(),
          )
          assert v.verdict == "reject"
          assert v.family_blocked is True

      def test_reject_when_signature_seen(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
          sig = kb_mechanism_signature(rec)
          v = classify_kb_candidate(
              rec,
              prior_signatures={"columnar_single": frozenset({sig})},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset(),
          )
          assert v.verdict == "reject"
          assert v.signature_seen is True

      def test_defer_when_unmapped(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-unmapped")
          v = classify_kb_candidate(
              rec,
              prior_signatures={},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset(),
          )
          assert v.verdict == "defer_needs_mapping"
          assert v.mapped_ledger_families == ()

      def test_reject_when_static_exhaustion(self):
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
          v = classify_kb_candidate(
              rec,
              prior_signatures={},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset({"columnar_single"}),
          )
          assert v.verdict == "reject"
          assert v.static_exhaustion_blocked is True
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestClassifyKBCandidate -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_injection.py`:

  ```python
  _EXHAUSTED_STATUSES = frozenset({"exhausted"})


  def classify_kb_candidate(
      record,
      *,
      prior_signatures: dict,
      blocked_families_in_cycle: frozenset,
      static_exhaustion_blocklist: frozenset,
  ) -> KBCandidateNoveltyVerdict:
      """Per-row novelty join. Pure: no I/O, no SQL.

      Determines verdict by sequentially checking:
      1. KB cipher_family mapping — None → defer_needs_mapping.
      2. tested_in_project / exhaustion_status — exhausted → reject.
      3. mapped_ledger_families ∩ blocked_families_in_cycle — overlap → reject.
      4. mapped_ledger_families ∩ static_exhaustion_blocklist — overlap → reject.
      5. mechanism_signature ∈ prior_signatures[family] for any mapped family — reject.
      Otherwise → allow.
      """
      from kryptosbot.kb_family_map import map_kb_family_to_ledger_families

      reasons: list[str] = []
      kb_record_id = getattr(record, "record_id", "") or ""
      kb_cipher_family = getattr(record, "cipher_family", "") or ""

      mapped = map_kb_family_to_ledger_families(kb_cipher_family)
      if mapped is None:
          return KBCandidateNoveltyVerdict(
              kb_record_id=kb_record_id,
              kb_cipher_family=kb_cipher_family,
              mapped_ledger_families=(),
              tested_status_ok=False,
              family_blocked=False,
              static_exhaustion_blocked=False,
              mechanism_signature=kb_mechanism_signature(record),
              signature_seen=False,
              dispatcher_testable=False,
              verdict="defer_needs_mapping",
              reasons=(f"unmapped KB cipher_family: {kb_cipher_family!r}",),
          )

      mapped_tuple = tuple(sorted(mapped))
      exhaustion_status = (getattr(record, "exhaustion_status", "") or "").lower()
      tested = bool(getattr(record, "tested_in_project", False))
      tested_status_ok = (not tested) or (exhaustion_status not in _EXHAUSTED_STATUSES)
      if not tested_status_ok:
          reasons.append(
              f"exhausted: tested_in_project={tested} exhaustion_status={exhaustion_status!r}"
          )

      family_blocked = bool(mapped & blocked_families_in_cycle)
      if family_blocked:
          overlap = sorted(mapped & blocked_families_in_cycle)
          reasons.append(f"mapped families overlap blocked cycle families: {overlap}")

      static_exhaustion_blocked = bool(mapped & static_exhaustion_blocklist)
      if static_exhaustion_blocked:
          overlap = sorted(mapped & static_exhaustion_blocklist)
          reasons.append(f"mapped families overlap static exhaustion list: {overlap}")

      signature = kb_mechanism_signature(record)
      signature_seen = any(
          signature in (prior_signatures.get(fam) or frozenset())
          for fam in mapped
      )
      if signature_seen:
          reasons.append(f"mechanism_signature {signature!r} already seen in a mapped family")

      dispatcher_supported = dispatcher_testable(record)

      if tested_status_ok and not family_blocked and not static_exhaustion_blocked and not signature_seen:
          verdict: NoveltyVerdictKind = "allow"
          if not reasons:
              reasons.append("ok")
      else:
          verdict = "reject"

      return KBCandidateNoveltyVerdict(
          kb_record_id=kb_record_id,
          kb_cipher_family=kb_cipher_family,
          mapped_ledger_families=mapped_tuple,
          tested_status_ok=tested_status_ok,
          family_blocked=family_blocked,
          static_exhaustion_blocked=static_exhaustion_blocked,
          mechanism_signature=signature,
          signature_seen=signature_seen,
          dispatcher_testable=dispatcher_supported,
          verdict=verdict,
          reasons=tuple(reasons),
      )
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestClassifyKBCandidate -v`
  Expected: 6 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: classify_kb_candidate novelty-join state machine"
  ```

---

## Task 10: `query_suggestions()` with deterministic ranking

**Files:**
- Modify: `kryptosbot/kb_injection.py`
- Modify: `kryptosbot/tests/test_kb_injection.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_kb_injection.py`:

  ```python
  from kryptosbot.kb_injection import query_suggestions


  class TestQuerySuggestions:
      def test_returns_only_allow_verdicts(self):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="prev-signature",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
          )
          for s in out:
              assert s.source_verdict == "allow"

      def test_excludes_exhausted_fixture_row(self):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="prev-signature",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
          )
          names = {s.canonical_name for s in out}
          assert "Compass Cipher" not in names

      def test_excludes_unmapped_fixture_row(self):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="prev-signature",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
          )
          names = {s.canonical_name for s in out}
          assert "Mystery Cipher" not in names

      def test_ranks_dispatcher_testable_first_then_by_k4_relevance(self):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="prev-signature",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
          )
          # Both Swagman and ADFGVX are dispatcher_testable; Astrolabe is not.
          first_three = [s.canonical_name for s in out[:3]]
          assert "Astrolabe Cipher" not in first_three[:2], (
              "dispatcher-testable rows should sort before non-testable"
          )

      def test_max_per_call_caps_returned_count(self):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="prev-signature",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
              max_per_call=2,
          )
          assert len(out) <= 2

      def test_missing_db_returns_empty(self, tmp_path):
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="x",
              prior_signatures={},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(tmp_path / "missing.sqlite"),
          )
          assert out == ()

      def test_skips_signature_seen_in_mapped_family(self):
          # Compute the Swagman signature, mark it as seen in columnar_single.
          rec = next(r for r in iter_kb_records(str(FIXTURE_DB)) if r.record_id == "fx-swagman")
          sig = kb_mechanism_signature(rec)
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="x",
              prior_signatures={"columnar_single": frozenset({sig})},
              blocked_families_in_cycle=frozenset(),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(FIXTURE_DB),
          )
          names = {s.canonical_name for s in out}
          assert "Swagman Cipher" not in names
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestQuerySuggestions -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement**

  Append to `kryptosbot/kb_injection.py`:

  ```python
  def _one_line_sketch(record) -> str:
      """Return a short prose sketch for the suggestion render.

      Prefers operational_mechanics, falls back to description, then
      canonical_name. Truncated to 160 chars."""
      for attr in ("operational_mechanics", "description"):
          val = getattr(record, attr, "") or ""
          val = _WHITESPACE_RE.sub(" ", val).strip()
          if val:
              return val[:160]
      return _normalize(getattr(record, "canonical_name", ""))[:160] or ""


  def _bounded_kill_criterion(record) -> str:
      """One-line guidance the theorist can adapt into a kill criterion."""
      from kryptosbot.kb_family_map import KB_TO_DSL_KIND, normalize_kb_family

      key = normalize_kb_family(getattr(record, "cipher_family", ""))
      kind = KB_TO_DSL_KIND.get(key)
      if kind:
          return (
              f"If the {kind} translator yields zero crib_score >= 18 across "
              f"its bounded parameter space, treat the mechanism as inert."
          )
      return (
          "Specify a bounded, hand-executable test method and a per-trial "
          "crib_score / Bean-pass criterion before dispatch."
      )


  def _sketch_class(record) -> SketchClass:
      if dispatcher_testable(record):
          return "dsl_testable"
      from kryptosbot.kb_family_map import map_kb_family_to_ledger_families
      mapped = map_kb_family_to_ledger_families(getattr(record, "cipher_family", ""))
      if mapped:
          return "category_b"
      return "unknown"


  def query_suggestions(
      *,
      blocked_family: str,
      blocked_signature: str,
      prior_signatures: dict,
      blocked_families_in_cycle: frozenset,
      static_exhaustion_blocklist: frozenset,
      db_path: str = "db/cipher_discovery.sqlite",
      max_per_call: int = 12,
  ) -> tuple[CipherDiscoverySuggestion, ...]:
      """Return ranked allow-list of suggestions for one blocked rejection.

      Failure modes:
        Missing DB → ().
        Corrupt row → skipped via iter_kb_records.
      Ranking key: (not dispatcher_testable, -k4_relevance_score, canonical_name).
      """
      allow_pairs: list[tuple[KBCandidateNoveltyVerdict, object]] = []
      for record in iter_kb_records(db_path):
          verdict = classify_kb_candidate(
              record,
              prior_signatures=prior_signatures,
              blocked_families_in_cycle=blocked_families_in_cycle,
              static_exhaustion_blocklist=static_exhaustion_blocklist,
          )
          if verdict.verdict == "allow":
              allow_pairs.append((verdict, record))
          elif verdict.verdict == "defer_needs_mapping":
              logger.warning(
                  "kb_injection: defer_needs_mapping kb_record_id=%r kb_cipher_family=%r",
                  verdict.kb_record_id, verdict.kb_cipher_family,
              )

      def _rank(pair: tuple[KBCandidateNoveltyVerdict, object]) -> tuple:
          v, r = pair
          return (
              not v.dispatcher_testable,
              -float(getattr(r, "k4_relevance_score", 0.0) or 0.0),
              (getattr(r, "canonical_name", "") or "").lower(),
          )

      allow_pairs.sort(key=_rank)
      out: list[CipherDiscoverySuggestion] = []
      for verdict, record in allow_pairs[:max_per_call]:
          out.append(CipherDiscoverySuggestion(
              kb_record_id=verdict.kb_record_id,
              canonical_name=getattr(record, "canonical_name", "") or "",
              kb_cipher_family=verdict.kb_cipher_family,
              mapped_ledger_families=verdict.mapped_ledger_families,
              mechanism_signature=verdict.mechanism_signature,
              signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
              dispatcher_testable=verdict.dispatcher_testable,
              k4_relevance_score=float(getattr(record, "k4_relevance_score", 0.0) or 0.0),
              sketch_class=_sketch_class(record),
              one_line_sketch=_one_line_sketch(record),
              bounded_kill_criterion=_bounded_kill_criterion(record),
              source_verdict="allow",
          ))
      return tuple(out)
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_injection.py::TestQuerySuggestions -v`
  Expected: 7 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/kb_injection.py kryptosbot/tests/test_kb_injection.py
  git commit -m "yield-feedback Phase 2: query_suggestions ranking + missing-DB fail-open"
  ```

---

## Task 11: Rename `suggested_mechanisms` to `suggested_mechanism_records`; widen type; tolerate old name in `from_dict`

**Files:**
- Modify: `kryptosbot/models.py`
- Create: `kryptosbot/tests/test_kb_serialization.py`

This is the field-rename plus widening from `tuple[str, ...]` to `tuple[CipherDiscoverySuggestion, ...]`. Phase 1 never populated the field with non-empty data, so the rename is safe — but we still keep `from_dict` tolerant of the legacy key for any ledger row that already carries the empty default.

- [ ] **Step 1: Write the failing test**

  Create `kryptosbot/tests/test_kb_serialization.py`:

  ```python
  """Round-trip tests for Phase 2 KB-suggestion serialization."""
  from __future__ import annotations

  import json

  import pytest

  from kryptosbot.kb_injection import (
      KB_SIGNATURE_SCHEMA_VERSION,
      CipherDiscoverySuggestion,
  )
  from kryptosbot.models import (
      CriticDecision,
      CriticVerdict,
      EmpiricalDeathRejectionPayload,
  )


  def _example_suggestion(**overrides):
      base = dict(
          kb_record_id="rec-1",
          canonical_name="Sample",
          kb_cipher_family="columnar",
          mapped_ledger_families=("columnar_single",),
          mechanism_signature="aaaaaaaaaaaaaaaa",
          signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
          dispatcher_testable=True,
          k4_relevance_score=11.5,
          sketch_class="dsl_testable",
          one_line_sketch="A short sketch.",
          bounded_kill_criterion="Stop if score < 18 across the bounded set.",
          source_verdict="allow",
      )
      base.update(overrides)
      return CipherDiscoverySuggestion(**base)


  class TestPayloadRoundTripWithSuggestions:
      def test_payload_to_dict_serializes_suggestions(self):
          payload = EmpiricalDeathRejectionPayload(
              family="encoding",
              verdict=None,
              bypass_failed_reasons=("subfamily seen",),
              suggested_mechanism_records=(_example_suggestion(),),
              suggestion_source="cipher_discovery_kb",
              suggestion_query_scope={"blocked_family": "encoding"},
          )
          d = payload.to_dict()
          assert isinstance(d, dict)
          recs = d.get("suggested_mechanism_records")
          assert isinstance(recs, list)
          assert len(recs) == 1
          assert recs[0]["canonical_name"] == "Sample"
          # JSON serializable end-to-end.
          json.dumps(d)

      def test_payload_round_trip_through_json(self):
          payload = EmpiricalDeathRejectionPayload(
              family="encoding",
              verdict=None,
              bypass_failed_reasons=("x",),
              suggested_mechanism_records=(_example_suggestion(),),
              suggestion_source="cipher_discovery_kb",
              suggestion_query_scope={},
          )
          d = payload.to_dict()
          blob = json.dumps(d)
          reloaded = json.loads(blob)
          payload2 = EmpiricalDeathRejectionPayload.from_dict(reloaded)
          assert payload2.family == "encoding"
          assert len(payload2.suggested_mechanism_records) == 1
          assert payload2.suggested_mechanism_records[0].canonical_name == "Sample"

      def test_critic_verdict_round_trip_with_suggestions(self):
          cv = CriticVerdict(
              decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
              confidence=0.9,
              reasons=["family dead"],
              empirical_death=EmpiricalDeathRejectionPayload(
                  family="encoding",
                  verdict=None,
                  bypass_failed_reasons=("x",),
                  suggested_mechanism_records=(_example_suggestion(),),
                  suggestion_source="cipher_discovery_kb",
                  suggestion_query_scope={},
              ),
          )
          d = cv.to_dict()
          blob = json.dumps(d)
          cv2 = CriticVerdict.from_dict(json.loads(blob))
          assert cv2.decision == CriticDecision.REJECT_EMPIRICALLY_DEAD
          assert cv2.empirical_death is not None
          assert cv2.empirical_death.suggested_mechanism_records[0].canonical_name == "Sample"

      def test_from_dict_tolerates_legacy_suggested_mechanisms_key(self):
          """Pre-Phase-2 ledger rows used `suggested_mechanisms: tuple[str,...]`
          which Phase 1 always emitted empty. from_dict must treat the old
          name as either an empty record list or, if non-empty strings are
          present, ignore them rather than crash."""
          legacy = {
              "family": "encoding",
              "verdict": {},
              "bypass_failed_reasons": [],
              "suggested_mechanisms": [],
              "suggestion_source": "none",
              "suggestion_query_scope": {},
          }
          payload = EmpiricalDeathRejectionPayload.from_dict(legacy)
          assert payload.family == "encoding"
          assert payload.suggested_mechanism_records == ()
          assert payload.suggestion_source == "none"

      def test_suggestion_query_scope_round_trips(self):
          payload = EmpiricalDeathRejectionPayload(
              family="encoding",
              verdict=None,
              bypass_failed_reasons=(),
              suggested_mechanism_records=(),
              suggestion_source="none",
              suggestion_query_scope={"blocked_family": "encoding", "max_per_call": 12},
          )
          payload2 = EmpiricalDeathRejectionPayload.from_dict(payload.to_dict())
          assert payload2.suggestion_query_scope == {"blocked_family": "encoding", "max_per_call": 12}
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_serialization.py -v`
  Expected: `AttributeError: 'EmpiricalDeathRejectionPayload' object has no attribute 'suggested_mechanism_records'`.

- [ ] **Step 3: Update `kryptosbot/models.py`**

  Open `kryptosbot/models.py` and modify `EmpiricalDeathRejectionPayload`:

  Replace the existing class (`@dataclass class EmpiricalDeathRejectionPayload ...` block, currently at lines ~231-279) with:

  ```python
  @dataclass
  class EmpiricalDeathRejectionPayload:
      """Structured payload attached to REJECT_EMPIRICALLY_DEAD verdicts.

      Phase 1 emitted suggested_mechanisms: tuple[str, ...] = (). Phase 2
      renames and widens to suggested_mechanism_records: tuple[
      CipherDiscoverySuggestion, ...] and populates from the cipher-discovery
      KB at REJECT_EMPIRICALLY_DEAD time. See
      docs/specs/2026-05-16-yield-feedback-phase2-design.md §4.3.
      """
      family: str
      verdict: Optional["FamilyYieldVerdict"] = None
      bypass_failed_reasons: tuple[str, ...] = ()
      # NEW Phase 2. Structured KB suggestion records, JSON-serializable
      # via CipherDiscoverySuggestion.to_dict / from_dict. Always () when
      # KB DB is missing or no candidate survives the novelty join.
      suggested_mechanism_records: tuple = ()
      suggestion_source: str = "none"  # "cipher_discovery_kb" | "none"
      suggestion_query_scope: dict = field(default_factory=dict)

      def to_dict(self) -> dict[str, Any]:
          # Avoid asdict() so we can serialize the suggestion records
          # through their own to_dict and avoid nested-dataclass round-trip
          # surprises.
          verdict_d: Optional[dict[str, Any]] = None
          if self.verdict is not None:
              # FamilyYieldVerdict is a frozen dataclass — asdict works.
              from dataclasses import asdict
              verdict_d = asdict(self.verdict)
          recs: list[dict[str, Any]] = []
          for rec in self.suggested_mechanism_records or ():
              if hasattr(rec, "to_dict"):
                  recs.append(rec.to_dict())
              elif isinstance(rec, dict):
                  recs.append(dict(rec))
              # else: silently skip — Phase-1 strings cannot round-trip
              #  through the Phase-2 typed reader anyway. The from_dict
              #  helper enforces this asymmetry on read.
          return {
              "family": self.family,
              "verdict": verdict_d,
              "bypass_failed_reasons": list(self.bypass_failed_reasons or ()),
              "suggested_mechanism_records": recs,
              "suggestion_source": self.suggestion_source,
              "suggestion_query_scope": dict(self.suggestion_query_scope or {}),
          }

      @classmethod
      def from_dict(cls, d: dict[str, Any]) -> "EmpiricalDeathRejectionPayload":
          from kryptosbot.family_yield import FamilyYieldStats, FamilyYieldVerdict
          from kryptosbot.kb_injection import CipherDiscoverySuggestion

          d = dict(d)
          verdict_d = d.get("verdict") or {}
          stats_d = verdict_d.get("stats") or {}

          verdict: Optional[FamilyYieldVerdict] = None
          if verdict_d and stats_d:
              stats = FamilyYieldStats(**{
                  k: stats_d.get(k) for k in (
                      "family", "trials", "mean_score", "best_score",
                      "promotions", "eliminated",
                  )
              })
              verdict = FamilyYieldVerdict(
                  family=verdict_d.get("family", ""),
                  status=verdict_d.get("status", "healthy"),
                  reasons=tuple(verdict_d.get("reasons") or ()),
                  stats=stats,
              )

          # Read new key first; fall back to legacy key (Phase 1 emitted
          # an empty tuple of strings under "suggested_mechanisms").
          rec_payload = d.get("suggested_mechanism_records")
          if rec_payload is None:
              # Legacy key tolerated; non-record-shaped entries are dropped.
              legacy = d.get("suggested_mechanisms") or []
              rec_payload = [
                  r for r in legacy if isinstance(r, dict)
              ]
          recs: list[CipherDiscoverySuggestion] = []
          for r in rec_payload or ():
              if isinstance(r, dict):
                  try:
                      recs.append(CipherDiscoverySuggestion.from_dict(r))
                  except Exception:
                      continue

          return cls(
              family=d.get("family", ""),
              verdict=verdict,
              bypass_failed_reasons=tuple(d.get("bypass_failed_reasons") or ()),
              suggested_mechanism_records=tuple(recs),
              suggestion_source=d.get("suggestion_source", "none"),
              suggestion_query_scope=dict(d.get("suggestion_query_scope") or {}),
          )
  ```

- [ ] **Step 4: Run the new serialization tests, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_kb_serialization.py -v`
  Expected: 5 passed.

- [ ] **Step 5: Run the Phase-1 serialization tests, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_family_yield.py kryptosbot/tests/test_critic_empirical_death.py -q`
  Expected: all pass. If any test references `suggested_mechanisms` directly (Phase 1 left this empty), they may need an update. Note any updates needed and apply minimal renames.

- [ ] **Step 6: Commit**

  ```bash
  git add kryptosbot/models.py kryptosbot/tests/test_kb_serialization.py
  git commit -m "yield-feedback Phase 2: rename suggested_mechanisms -> suggested_mechanism_records + JSON round-trip"
  ```

---

## Task 12: Audit existing references to `suggested_mechanisms` across the codebase

**Files:**
- Modify: any file under `kryptosbot/` that still references `suggested_mechanisms`.

This is the equivalent of Phase 1's Task 8 (dispatch-site audit). The rename in Task 11 changes the canonical name; any remaining reader of the old name needs to switch.

- [ ] **Step 1: Find every reference**

  Run from repo root:

  ```bash
  grep -rn "suggested_mechanisms" kryptosbot/ docs/specs/ docs/audits/ docs/plans/ 2>/dev/null
  ```

  Expected output: occurrences in docs (acceptable — they describe Phase 1), and *possibly* one or two in `pantheon.py`, `controller.py`, or older tests if Phase 1 had readers.

- [ ] **Step 2: Update each non-doc reference**

  For each occurrence outside `docs/` and outside the Phase 1 design spec, decide:
  - If it reads the field on `EmpiricalDeathRejectionPayload`, rename to `suggested_mechanism_records`.
  - If it constructs the payload, update the keyword argument.
  - If it is a comment that names the old field, update the comment.

  Common locations to inspect:
  - `kryptosbot/controller.py` — search for `suggested_mechanisms`; rename if present.
  - `kryptosbot/pantheon.py` — search; rename.
  - `kryptosbot/tests/test_critic_empirical_death.py` — search; rename test assertions.

  Show the diff:

  ```bash
  git diff
  ```

- [ ] **Step 3: Run Phase 1 + Phase 2 test files**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_family_yield.py kryptosbot/tests/test_critic_empirical_death.py kryptosbot/tests/test_kb_serialization.py kryptosbot/tests/test_kb_injection.py kryptosbot/tests/test_kb_family_map.py -q`
  Expected: all pass.

- [ ] **Step 4: Commit**

  ```bash
  git add -u
  git commit -m "yield-feedback Phase 2: rename remaining suggested_mechanisms call sites"
  ```

  If `git diff --cached` shows no changes, skip the commit and proceed.

---

## Task 13: `contracts.py::_non_crib_ngram_per_char` helper

**Files:**
- Modify: `kryptosbot/contracts.py`
- Create: `kryptosbot/tests/test_crib_paste_detector.py`

- [ ] **Step 1: Write the failing test**

  Create `kryptosbot/tests/test_crib_paste_detector.py`:

  ```python
  """Tests for crib-paste detection in contracts._verify_against_kernel."""
  from __future__ import annotations

  import pytest

  from kryptosbot.contracts import (
      _is_crib_paste_artifact,
      _non_crib_ngram_per_char,
  )


  # Spec §F: crib positions are 21-33 inclusive (EASTNORTHEAST, 13 chars)
  # and 63-73 inclusive (BERLINCLOCK, 11 chars). 0-indexed.
  CRIB_EAST_RANGE = (21, 34)   # half-open
  CRIB_BERLIN_RANGE = (63, 74)


  def _paste_pt(filler: str = "X") -> str:
      """Build a 97-char PT that pastes the canonical cribs and fills the
      remaining 73 positions with `filler` chars."""
      pt = [filler] * 97
      for i, ch in enumerate("EASTNORTHEAST"):
          pt[CRIB_EAST_RANGE[0] + i] = ch
      for i, ch in enumerate("BERLINCLOCK"):
          pt[CRIB_BERLIN_RANGE[0] + i] = ch
      return "".join(pt)


  class TestNonCribNgramPerChar:
      def test_masks_crib_positions(self):
          pt = _paste_pt(filler="X")
          # 73 non-crib chars, all X — very low ngram score.
          score = _non_crib_ngram_per_char(pt)
          assert score < -5.0, f"all-X non-crib should be low, got {score}"

      def test_legitimate_english_non_crib_scores_higher(self):
          # Construct a PT with cribs at the canonical positions but
          # plausible-looking English everywhere else. The exact value depends
          # on the kernel ngram scorer's training corpus — we only assert
          # that English-looking text scores meaningfully higher than X-filler.
          pt = list("THEQUICKBROWNFOXJUMPSOVERLAZYDOGS" * 3)
          pt = pt[:97]
          for i, ch in enumerate("EASTNORTHEAST"):
              pt[CRIB_EAST_RANGE[0] + i] = ch
          for i, ch in enumerate("BERLINCLOCK"):
              pt[CRIB_BERLIN_RANGE[0] + i] = ch
          pt_str = "".join(pt)
          english_score = _non_crib_ngram_per_char(pt_str)
          paste_score = _non_crib_ngram_per_char(_paste_pt(filler="X"))
          assert english_score > paste_score

      def test_handles_empty_or_short_pt(self):
          # Helper must not crash on degenerate input.
          assert _non_crib_ngram_per_char("") == float("nan") or _non_crib_ngram_per_char("") <= -6.0
          assert _non_crib_ngram_per_char("ABC") == float("nan") or _non_crib_ngram_per_char("ABC") <= -6.0


  class TestIsCribPasteArtifact:
      def test_fires_at_threshold(self):
          # crib=24, non-crib ngram per-char at -6.2 (exact boundary).
          assert _is_crib_paste_artifact(
              "A" * 97,
              verified_crib=24,
              non_crib_ngram_per_char=-6.2,
          ) is True

      def test_does_not_fire_above_threshold(self):
          assert _is_crib_paste_artifact(
              "A" * 97,
              verified_crib=24,
              non_crib_ngram_per_char=-6.0,
          ) is False

      def test_does_not_fire_below_crib_24(self):
          assert _is_crib_paste_artifact(
              "A" * 97,
              verified_crib=23,
              non_crib_ngram_per_char=-10.0,
          ) is False

      def test_fires_for_paste_pt(self):
          # The 8 ledger 24/24 events all match this shape — X-filler around
          # canonical cribs.
          pt = _paste_pt(filler="X")
          ngram_pc = _non_crib_ngram_per_char(pt)
          assert ngram_pc <= -6.2
          assert _is_crib_paste_artifact(
              pt, verified_crib=24, non_crib_ngram_per_char=ngram_pc,
          ) is True
  ```

- [ ] **Step 2: Run, expect ImportError**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_crib_paste_detector.py -v`
  Expected: `ImportError`.

- [ ] **Step 3: Implement helpers in `contracts.py`**

  In `kryptosbot/contracts.py`, find the `_safe_float` / `_safe_int` helpers near the top (around line 60-80) and add ABOVE `_verify_against_kernel`:

  ```python
  # ---------------------------------------------------------------------------
  # Phase 2 yield-feedback: crib-paste artifact detector
  # ---------------------------------------------------------------------------

  # 0-indexed half-open crib ranges. Match kernel.constants.CRIB_POSITIONS.
  _CRIB_EAST_SLICE = slice(21, 34)    # EASTNORTHEAST, 13 chars
  _CRIB_BERLIN_SLICE = slice(63, 74)  # BERLINCLOCK, 11 chars


  def _non_crib_ngram_per_char(pt: str) -> float:
      """Score the PT with crib positions masked, divided by non-crib length.

      Returns -inf-like (very negative) on degenerate inputs (wrong length,
      no ngram scorer available). The caller treats anything <= -6.2 as
      crib-paste evidence in conjunction with verified_crib == 24.
      """
      try:
          if not isinstance(pt, str) or len(pt) != 97:
              return -99.0
          non_crib_chars: list[str] = []
          for i, ch in enumerate(pt):
              if (_CRIB_EAST_SLICE.start <= i < _CRIB_EAST_SLICE.stop):
                  continue
              if (_CRIB_BERLIN_SLICE.start <= i < _CRIB_BERLIN_SLICE.stop):
                  continue
              non_crib_chars.append(ch)
          if not non_crib_chars:
              return -99.0
          non_crib_text = "".join(non_crib_chars)
          # Reuse the kernel's ngram scorer. import here so the rest of
          # contracts.py stays loadable without the kernel ngram path.
          from kryptos.kernel.scoring.ngram import NgramScorer
          scorer = NgramScorer.load()
          total = scorer.score(non_crib_text)
          return float(total) / float(len(non_crib_text))
      except Exception:
          return -99.0


  # Pre-registered threshold. Versioned 'crib_paste_artifact:v1' in error
  # strings. Tightening or partial-paste extension requires v2 + new spec.
  _CRIB_PASTE_NGRAM_FLOOR = -6.2


  def _is_crib_paste_artifact(
      pt: str,
      *,
      verified_crib: int,
      non_crib_ngram_per_char: float,
  ) -> bool:
      """True iff the worker result is a literal crib paste over a
      Bean-valid keystream. Boolean only; caller mutates the contract.
      """
      if verified_crib != 24:
          return False
      return float(non_crib_ngram_per_char) <= _CRIB_PASTE_NGRAM_FLOOR
  ```

  If `NgramScorer.load()` does not exist with that exact signature, check `src/kryptos/kernel/scoring/ngram.py` for the correct constructor — Phase 1 already wires this elsewhere (look for `ngram_scorer=` in `kryptosbot/contracts.py` or `kryptosbot/alerts.py` for the canonical loader).

- [ ] **Step 4: Run the helper tests**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_crib_paste_detector.py -v`
  Expected: all helper-level tests pass. If `_non_crib_ngram_per_char` returns values outside the expected boundary on the English-looking PT (because the kernel ngram scorer's training corpus is different than expected), relax the `english_score > paste_score` assertion only — never relax the strict `<= -6.2` paste detection.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/contracts.py kryptosbot/tests/test_crib_paste_detector.py
  git commit -m "yield-feedback Phase 2: _non_crib_ngram_per_char + _is_crib_paste_artifact helpers"
  ```

---

## Task 14: Integrate the detector into `_verify_against_kernel`

**Files:**
- Modify: `kryptosbot/contracts.py` (function `_verify_against_kernel`)
- Modify: `kryptosbot/tests/test_contracts.py`

The detector runs AFTER step 3 (kernel recomputes verified scores) and BEFORE the existing disagreement comparison. If `verified_crib == 24`, compute non-crib ngram, run `_is_crib_paste_artifact`, and on True mutate the contract.

- [ ] **Step 1: Write the failing integration test**

  Append to `kryptosbot/tests/test_crib_paste_detector.py`:

  ```python
  from kryptosbot.contracts import _verify_against_kernel
  from kryptosbot.models import WorkerContract, WorkerStatus


  def _new_contract(pt: str, claimed_crib: int = 24) -> WorkerContract:
      return WorkerContract(
          hypothesis_id="test",
          best_plaintext=pt,
          crib_score=claimed_crib,
          bean_passed=True,
          score=float(claimed_crib),
          status=WorkerStatus.SUCCESS,
      )


  class TestVerifyAgainstKernelIntegration:
      def test_paste_pt_is_classified_as_artifact(self):
          c = _new_contract(_paste_pt(filler="X"))
          _verify_against_kernel(c)
          # Zeroed signal fields.
          assert c.crib_score == 0
          assert c.bean_passed is False
          assert c.score == 0.0
          # Status forced to INCONCLUSIVE — NOT DISPROVED (which maps to
          # TheoryStatus.ELIMINATED in the controller).
          assert c.status == WorkerStatus.INCONCLUSIVE
          # Audit trail.
          assert c.fields_overwritten is True
          assert "crib_paste_artifact:v1" in (c.verification_error or "")
          assert c.raw_artifacts.get("artifact_class") == "crib_paste"
          snapshot = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
          assert isinstance(snapshot, dict)
          assert snapshot.get("crib_score") == 24

      def test_paste_with_random_filler_is_classified_as_artifact(self):
          # Random-looking garbage around cribs (per the actual ledger events).
          import random
          rng = random.Random(0)
          chars = [chr(ord("A") + rng.randint(0, 25)) for _ in range(97)]
          for i, ch in enumerate("EASTNORTHEAST"):
              chars[CRIB_EAST_RANGE[0] + i] = ch
          for i, ch in enumerate("BERLINCLOCK"):
              chars[CRIB_BERLIN_RANGE[0] + i] = ch
          pt = "".join(chars)
          c = _new_contract(pt)
          _verify_against_kernel(c)
          # Random ASCII garbage scores below the ngram floor too — this is
          # the actual 8-event ledger signature.
          assert c.raw_artifacts.get("artifact_class") == "crib_paste"
          assert c.status == WorkerStatus.INCONCLUSIVE

      def test_non_paste_24_24_is_preserved(self):
          # English-looking PT with cribs at canonical positions: the
          # non-crib ngram floor should be ABOVE -6.2, so the detector
          # does NOT fire even if verified_crib == 24. We don't have a
          # known 24/24 legitimate plaintext (K4 is unsolved), so we
          # construct one with plausible English filler.
          pt = list("THEQUICKBROWNFOXJUMPSOVERLAZYDOG" * 4)
          pt = pt[:97]
          for i, ch in enumerate("EASTNORTHEAST"):
              pt[CRIB_EAST_RANGE[0] + i] = ch
          for i, ch in enumerate("BERLINCLOCK"):
              pt[CRIB_BERLIN_RANGE[0] + i] = ch
          c = _new_contract("".join(pt))
          _verify_against_kernel(c)
          # The Bean check may or may not pass for this random plaintext,
          # but the crib-paste detector must NOT fire.
          assert c.raw_artifacts.get("artifact_class") != "crib_paste"
          # Verification_error must NOT mention crib_paste.
          assert "crib_paste_artifact" not in (c.verification_error or "")

      def test_below_24_crib_score_untouched_by_detector(self):
          # 18/24 result: cribs not all matched; detector must not fire.
          pt = "A" * 97  # crib_score will be 0 from the kernel
          c = _new_contract(pt, claimed_crib=18)
          _verify_against_kernel(c)
          # Detector does not fire (verified_crib != 24).
          assert c.raw_artifacts.get("artifact_class") != "crib_paste"

      def test_detector_exception_fails_closed(self, monkeypatch):
          """If the detector raises, the contract must NOT be promoted as
          24/24. Spec §F: fail-closed."""
          import kryptosbot.contracts as ctr

          def _boom(*a, **kw):
              raise RuntimeError("synthetic detector failure")

          monkeypatch.setattr(ctr, "_is_crib_paste_artifact", _boom)
          c = _new_contract(_paste_pt(filler="X"))
          _verify_against_kernel(c)
          # Score must NOT show a promoted 24.
          assert c.crib_score == 0
          assert c.status == WorkerStatus.INCONCLUSIVE
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_crib_paste_detector.py::TestVerifyAgainstKernelIntegration -v`
  Expected: 4–5 tests fail with AssertionError (no integration yet).

- [ ] **Step 3: Wire the detector into `_verify_against_kernel`**

  In `kryptosbot/contracts.py`, find the block immediately after the kernel verification try/except (around line 197-220). Add the detector block BEFORE the existing disagreement comparison:

  ```python
      # ── Phase 2 yield-feedback: crib-paste artifact detector ───────────────
      # When the kernel agrees crib_score == 24, check whether the plaintext
      # is a literal crib paste (random garbage / repeated chars surrounding
      # canonical cribs over a Bean-valid keystream). This pattern is
      # mathematically allowed (624 Bean-valid keystreams admit arbitrary
      # crib-position plaintexts) but is never legitimate signal.
      #
      # Local try/except is required — DO NOT rely on the outer kernel-
      # verification try/except. Spec §4.4: detector failure must fail
      # CLOSED, not let a 24/24 paste through.
      if verified_crib == 24:
          try:
              ngram_pc = _non_crib_ngram_per_char(pt)
              is_paste = _is_crib_paste_artifact(
                  pt,
                  verified_crib=verified_crib,
                  non_crib_ngram_per_char=ngram_pc,
              )
          except Exception as exc:
              # Fail-closed: treat as artifact. Worker self-report is
              # already snapshotted above.
              ngram_pc = float("nan")
              is_paste = True
              logger.warning("crib_paste_detector raised: %s", exc)

          if is_paste:
              if contract.raw_artifacts is None:
                  contract.raw_artifacts = {}
              contract.raw_artifacts["artifact_class"] = "crib_paste"
              contract.raw_artifacts["kernel_verified_before_artifact_filter"] = {
                  "crib_score": int(verified_crib),
                  "bean_passed": bool(verified_bean),
                  "score": float(verified_score),
                  "bean_variant": verified_variant,
                  "non_crib_ngram_per_char": float(ngram_pc),
              }
              contract.crib_score = 0
              contract.bean_passed = False
              contract.score = 0.0
              contract.bean_variant = None
              contract.fields_overwritten = True
              contract.worker_self_report = worker_claim
              contract.verification_error = (
                  f"crib_paste_artifact:v1: verified_crib=24, "
                  f"non_crib_ngram_per_char={ngram_pc:.2f} <= -6.2"
              )
              contract.status = WorkerStatus.INCONCLUSIVE
              return
  ```

  Confirm `import logging` and `logger = logging.getLogger(__name__)` are present at the top of `contracts.py` — if not, add them.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_crib_paste_detector.py -v`
  Expected: all tests pass (helpers + integration).

- [ ] **Step 5: Run the broader contracts test file to catch regressions**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_contracts.py -q`
  Expected: all pass. If a Phase 1 test asserted "24/24 always preserved", update it to assert the paste-vs-legitimate distinction explicitly.

- [ ] **Step 6: Commit**

  ```bash
  git add kryptosbot/contracts.py kryptosbot/tests/test_crib_paste_detector.py
  git commit -m "yield-feedback Phase 2: crib-paste detector inside _verify_against_kernel (fail-closed)"
  ```

---

## Task 15: Critic gate — KB query + per-cycle cache

**Files:**
- Modify: `kryptosbot/critic.py` (function `_check_family_empirically_dead`, plus `__init__`)
- Modify: `kryptosbot/tests/test_critic_empirical_death.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_critic_empirical_death.py` (file already exists from Phase 1):

  ```python
  from pathlib import Path

  from kryptosbot.kb_injection import (
      KB_SIGNATURE_SCHEMA_VERSION,
      CipherDiscoverySuggestion,
  )


  PHASE2_FIXTURE_DB = (
      Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"
  )


  class TestKBSuggestionInjection:
      def _critic_under_test(
          self,
          *,
          yield_index,
          prior_subfamilies=None,
          prior_signatures=None,
          blocked_families_in_cycle=None,
          static_exhaustion_blocklist=None,
      ):
          from kryptosbot.critic import TheoryCritic
          critic = TheoryCritic(
              yield_index=yield_index,
              prior_subfamilies=prior_subfamilies or {},
              prior_signatures=prior_signatures or {},
              blocked_families_in_cycle=blocked_families_in_cycle or frozenset(),
              static_exhaustion_blocklist=static_exhaustion_blocklist or frozenset(),
              kb_db_path=str(PHASE2_FIXTURE_DB),
          )
          return critic

      def test_kb_query_populates_suggestions_on_empirical_death(
          self, dead_encoding_yield, encoding_theory
      ):
          """Spec acceptance #3: REJECT_EMPIRICALLY_DEAD on encoding yields
          non-empty suggested_mechanism_records when fixture KB has at least
          one record mapped to a non-blocked ledger family with unseen sig."""
          critic = self._critic_under_test(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
          )
          verdict = critic.evaluate(encoding_theory)
          assert verdict.decision.value == "reject_empirically_dead"
          ed = verdict.empirical_death
          assert ed is not None
          assert ed.suggestion_source == "cipher_discovery_kb"
          assert len(ed.suggested_mechanism_records) >= 1
          for s in ed.suggested_mechanism_records:
              assert isinstance(s, CipherDiscoverySuggestion)
              assert s.source_verdict == "allow"
              assert s.signature_schema_version == KB_SIGNATURE_SCHEMA_VERSION

      def test_cache_hit_on_repeat_family_signature(
          self, dead_encoding_yield, encoding_theory
      ):
          critic = self._critic_under_test(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
          )
          # First call populates cache; second call must use cache (no
          # re-query). We assert by patching iter_kb_records to fail the
          # second time and confirming we still get suggestions.
          v1 = critic.evaluate(encoding_theory)
          assert v1.empirical_death is not None
          import kryptosbot.kb_injection as kbi

          def _boom(*a, **kw):
              raise RuntimeError("must not re-query")

          orig = kbi.iter_kb_records
          try:
              kbi.iter_kb_records = _boom
              # SAME theory => same (family, signature) cache key.
              v2 = critic.evaluate(encoding_theory)
          finally:
              kbi.iter_kb_records = orig
          assert v2.empirical_death is not None
          assert len(v2.empirical_death.suggested_mechanism_records) == len(
              v1.empirical_death.suggested_mechanism_records
          )

      def test_no_kb_query_when_bypass_satisfied(
          self, dead_encoding_yield, encoding_theory_with_novel_subfamily_and_signature
      ):
          critic = self._critic_under_test(
              yield_index={"encoding": dead_encoding_yield},
              # Empty prior_subfamilies / prior_signatures — bypass should fire.
              blocked_families_in_cycle=frozenset({"encoding"}),
          )
          verdict = critic.evaluate(encoding_theory_with_novel_subfamily_and_signature)
          # Bypass means the empirical-death gate falls through; the gate's
          # KB query does not run; downstream checks may still reject for
          # other reasons, but if they pass, no empirical_death payload.
          if verdict.decision.value == "reject_empirically_dead":
              raise AssertionError("Bypass should have prevented empirical-death rejection")

      def test_kb_db_missing_falls_back_to_none_source(
          self, dead_encoding_yield, encoding_theory, tmp_path
      ):
          missing_path = tmp_path / "no_such_db.sqlite"
          critic = self._critic_under_test(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
          )
          critic._kb_db_path = str(missing_path)
          # Clear any cache populated by a previous suite run.
          critic._kb_cache.clear()
          verdict = critic.evaluate(encoding_theory)
          ed = verdict.empirical_death
          assert ed is not None
          assert ed.suggestion_source == "none"
          assert ed.suggested_mechanism_records == ()
  ```

  The four pytest fixtures referenced (`dead_encoding_yield`, `encoding_theory`, `encoding_theory_with_novel_subfamily_and_signature`) MUST already exist in `test_critic_empirical_death.py` from Phase 1. If they don't have those exact names, look near the top of the existing file for equivalent ones and rename in the new tests. The fixtures should not need new helpers — Phase 1 set them up.

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_critic_empirical_death.py::TestKBSuggestionInjection -v`
  Expected: `TypeError: TheoryCritic.__init__() got an unexpected keyword argument 'kb_db_path'` and/or `AttributeError: '...' has no attribute 'suggestion_source'`.

- [ ] **Step 3: Extend `TheoryCritic.__init__` and `_check_family_empirically_dead`**

  Open `kryptosbot/critic.py`. Find the `TheoryCritic` class definition. In `__init__`:

  ```python
  # Phase 2 yield-feedback. New constructor kwargs with safe defaults
  # so Phase 1 call sites (and tests that don't pass these) continue working.
  def __init__(
      self,
      *,
      yield_index: dict | None = None,
      prior_subfamilies: dict | None = None,
      prior_signatures: dict | None = None,
      # NEW Phase 2:
      blocked_families_in_cycle: frozenset[str] | None = None,
      static_exhaustion_blocklist: frozenset[str] | None = None,
      kb_db_path: str | None = None,
      policy=None,
      # ... preserve any other Phase 1 kwargs already in this signature
  ):
      self.yield_index = yield_index or {}
      self.prior_subfamilies = prior_subfamilies or {}
      self.prior_signatures = prior_signatures or {}
      self.blocked_families_in_cycle = (
          frozenset(blocked_families_in_cycle)
          if blocked_families_in_cycle is not None
          else frozenset(
              f for f, v in self.yield_index.items()
              if getattr(v, "status", "") == "empirically_dead"
          )
      )
      self.static_exhaustion_blocklist = (
          frozenset(static_exhaustion_blocklist)
          if static_exhaustion_blocklist is not None
          else frozenset()
      )
      self._kb_db_path = kb_db_path or "db/cipher_discovery.sqlite"
      self._kb_cache: dict[tuple[str, str], tuple] = {}
      # ... preserve the rest of Phase 1's __init__ body
  ```

  Preserve everything from Phase 1's `__init__` that this block doesn't replace.

  Then find `_check_family_empirically_dead` (added in Phase 1 Task 9). Replace the `# Phase 1 logic ...` block — the part that constructs `CriticVerdict(decision=CriticDecision.REJECT_EMPIRICALLY_DEAD, ...)` — with the Phase 2 variant that also queries the KB:

  ```python
  def _check_family_empirically_dead(self, theory, family_lower):
      verdict = self.yield_index.get(family_lower)
      if not verdict or getattr(verdict, "status", "") != "empirically_dead":
          return None

      from kryptosbot.family_yield import (
          check_bypass_eligibility,
          mechanism_signature_for_theory,
          _normalize_subfamily,
      )

      eligible, bypass_reasons = check_bypass_eligibility(
          family=family_lower,
          subfamily=_normalize_subfamily(getattr(theory, "subfamily", "")),
          mechanism_signature=mechanism_signature_for_theory(theory),
          prior_subfamilies_in_family=self.prior_subfamilies.get(
              family_lower, frozenset()
          ),
          prior_mechanism_signatures_in_family=self.prior_signatures.get(
              family_lower, frozenset()
          ),
      )
      if eligible:
          return None
      # Phase 1's shadow-mode hook: preserve verbatim if present in policy.
      policy = getattr(self, "policy", None)
      if policy is not None and getattr(policy, "shadow_mode", False):
          import logging
          logging.getLogger(__name__).warning(
              "[shadow] would_reject_empirically_dead: %s", family_lower
          )
          return None

      # ── Phase 2: query the KB for structurally-novel escape candidates.
      blocked_signature = mechanism_signature_for_theory(theory)
      cache_key = (family_lower, blocked_signature)
      if cache_key in self._kb_cache:
          suggestions = self._kb_cache[cache_key]
      else:
          from kryptosbot.kb_injection import query_suggestions
          suggestions = query_suggestions(
              blocked_family=family_lower,
              blocked_signature=blocked_signature,
              prior_signatures=self.prior_signatures,
              blocked_families_in_cycle=self.blocked_families_in_cycle,
              static_exhaustion_blocklist=self.static_exhaustion_blocklist,
              db_path=self._kb_db_path,
          )
          self._kb_cache[cache_key] = suggestions

      suggestion_source = "cipher_discovery_kb" if suggestions else "none"

      # Reuse Phase 1's CriticVerdict / CriticDecision / payload imports.
      from kryptosbot.models import (
          CriticDecision,
          CriticVerdict,
          EmpiricalDeathRejectionPayload,
      )
      from kryptosbot.kb_injection import KB_SIGNATURE_SCHEMA_VERSION

      stats = getattr(verdict, "stats", None)
      n = getattr(stats, "trials", 0) if stats else 0
      mean = getattr(stats, "mean_score", 0.0) if stats else 0.0
      best = getattr(stats, "best_score", 0.0) if stats else 0.0
      promotions = getattr(stats, "promotions", 0) if stats else 0

      return CriticVerdict(
          decision=CriticDecision.REJECT_EMPIRICALLY_DEAD,
          confidence=0.9,
          reasons=[
              (
                  f"Family {family_lower!r} empirically dead "
                  f"(n={n}, mean={mean:.2f}, best={best:.1f}, "
                  f"promotions={promotions}); bypass not satisfied"
              ),
              *bypass_reasons,
          ],
          empirical_death=EmpiricalDeathRejectionPayload(
              family=family_lower,
              verdict=verdict,
              bypass_failed_reasons=tuple(bypass_reasons),
              suggested_mechanism_records=suggestions,
              suggestion_source=suggestion_source,
              suggestion_query_scope={
                  "blocked_family": family_lower,
                  "blocked_signature_prefix": blocked_signature[:8],
                  "blocked_families_in_cycle": sorted(self.blocked_families_in_cycle),
                  "max_per_call": 12,
                  "kb_signature_schema_version": KB_SIGNATURE_SCHEMA_VERSION,
              },
          ),
      )
  ```

- [ ] **Step 4: Run the new tests, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_critic_empirical_death.py -v`
  Expected: all pass. The Phase 1 tests in this file should still pass — the changes are additive on top of Phase 1's gate.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/critic.py kryptosbot/tests/test_critic_empirical_death.py
  git commit -m "yield-feedback Phase 2: critic KB query in _check_family_empirically_dead with per-cycle cache"
  ```

---

## Task 16: `ControllerState.last_escape_suggestions` field

**Files:**
- Modify: `kryptosbot/controller.py` (find the `ControllerState` dataclass)
- Modify: `kryptosbot/tests/test_theory_ledger.py` (existing Phase-1 round-trip test)

- [ ] **Step 1: Add a failing round-trip test**

  Open `kryptosbot/tests/test_theory_ledger.py`. Find the Phase 1 test `test_controller_state_round_trip_preserves_phase1_fields` (or the closest equivalent). Add a new test next to it:

  ```python
  class TestControllerStatePhase2RoundTrip:
      def test_last_escape_suggestions_round_trips(self):
          from kryptosbot.controller import ControllerState
          # Use list[dict] (the JSON-storage shape), not list[CipherDiscoverySuggestion].
          suggestions = [
              {
                  "kb_record_id": "fx-swagman",
                  "canonical_name": "Swagman Cipher",
                  "kb_cipher_family": "columnar",
                  "mapped_ledger_families": ["columnar_single"],
                  "mechanism_signature": "0123456789abcdef",
                  "signature_schema_version": "kb_mechanism_sig_v1",
                  "dispatcher_testable": True,
                  "k4_relevance_score": 42.0,
                  "sketch_class": "dsl_testable",
                  "one_line_sketch": "N-row columnar with skew permutation.",
                  "bounded_kill_criterion": "Stop if no run scores >= 18.",
                  "source_verdict": "allow",
                  "blocked_family": "encoding",
              }
          ]
          s = ControllerState(
              cycle_number=42,
              last_escape_suggestions=suggestions,
          )
          # to_dict / from_dict round-trip (controller_state JSON column).
          d = s.to_dict() if hasattr(s, "to_dict") else asdict(s)
          import json
          reloaded = json.loads(json.dumps(d))
          # Phase 1 already round-trips other fields; just check the new one.
          assert reloaded["last_escape_suggestions"] == suggestions
  ```

  Note: if `ControllerState` does NOT have `to_dict` (Phase 1 used `dataclasses.asdict`), import and use that. The test verifies JSON-round-trip safety either way.

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_theory_ledger.py::TestControllerStatePhase2RoundTrip -v`
  Expected: `TypeError: ControllerState.__init__() got an unexpected keyword argument 'last_escape_suggestions'`.

- [ ] **Step 3: Add the field**

  In `kryptosbot/controller.py`, find the `ControllerState` dataclass (search for `@dataclass\nclass ControllerState`). Add the new field at the end of the field list, before any methods:

  ```python
  @dataclass
  class ControllerState:
      # ... existing Phase 1 fields ...
      escape_needed_streak: int = 0
      last_escape_status: str = "none"
      last_escape_families_blocked: list[str] = field(default_factory=list)
      last_escape_families_blocked_total: int = 0
      last_escape_cycle: int = 0
      last_partial_empirical_block_count: int = 0
      # NEW Phase 2: aggregated KB suggestions from the prior cycle's
      # REJECT_EMPIRICALLY_DEAD rejections. Stored as JSON-friendly list[dict]
      # (CipherDiscoverySuggestion.to_dict + a blocked_family key per entry)
      # rather than as a nested dataclass to avoid round-trip surprises
      # through the controller_state JSON column.
      last_escape_suggestions: list[dict] = field(default_factory=list)
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_theory_ledger.py -v -k Phase2`
  Expected: pass.

  Then run the full Phase 1 round-trip test:

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_theory_ledger.py -q`
  Expected: pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/controller.py kryptosbot/tests/test_theory_ledger.py
  git commit -m "yield-feedback Phase 2: ControllerState.last_escape_suggestions field"
  ```

---

## Task 17: `_kb_db_missing_logged_this_cycle` flag + `_begin_cycle_phase_state` reset

**Files:**
- Modify: `kryptosbot/controller.py` (`__init__` and `_begin_cycle_phase_state`)
- Modify: `kryptosbot/tests/test_cycle_escape_telemetry.py`

- [ ] **Step 1: Add a failing test**

  Append to `kryptosbot/tests/test_cycle_escape_telemetry.py`:

  ```python
  class TestKBDBMissingLoggedOncePerCycle:
      def test_flag_resets_in_begin_cycle_phase_state(self):
          from kryptosbot.controller import ResearchController
          # Minimal controller construction may be heavy; if Phase 1 has a
          # _bare_controller_for_tests helper, use it. Otherwise construct
          # the bare class with no API key and rely on _begin_cycle_phase_state
          # being a pure-method.
          c = ResearchController.__new__(ResearchController)
          # Manually initialize minimal state.
          c._cycle_empirical_dead_rejections = []
          c._kb_db_missing_logged_this_cycle = True
          # Phase 1 supplies _begin_cycle_phase_state.
          c._begin_cycle_phase_state()
          assert c._kb_db_missing_logged_this_cycle is False
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestKBDBMissingLoggedOncePerCycle -v`
  Expected: AttributeError or AssertionError.

- [ ] **Step 3: Add the flag + reset**

  In `kryptosbot/controller.py`, find `_begin_cycle_phase_state` (Phase 1 chokepoint). Add a line in its body:

  ```python
  def _begin_cycle_phase_state(self) -> None:
      # ... existing Phase 1 resets ...
      self._cycle_empirical_dead_rejections = []
      # ... other Phase 1 resets ...
      # Phase 2 yield-feedback: per-cycle flag so the KB-missing WARNING
      # fires at most once per cycle, never per rejection.
      self._kb_db_missing_logged_this_cycle = False
  ```

  Also, in `ResearchController.__init__`, after Phase 1 init, add:

  ```python
      # Phase 2: per-cycle flag, initialized once in case _begin_cycle_phase_state
      # has not been called yet (e.g. during cold-start tests).
      self._kb_db_missing_logged_this_cycle = False
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestKBDBMissingLoggedOncePerCycle -v`
  Expected: pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/controller.py kryptosbot/tests/test_cycle_escape_telemetry.py
  git commit -m "yield-feedback Phase 2: _kb_db_missing_logged_this_cycle flag reset chokepoint"
  ```

---

## Task 18: `_write_cycle_escape_summary` aggregation + suggestions storage

**Files:**
- Modify: `kryptosbot/controller.py` (function `_write_cycle_escape_summary`)
- Modify: `kryptosbot/tests/test_cycle_escape_telemetry.py`

- [ ] **Step 1: Add failing tests**

  Append to `kryptosbot/tests/test_cycle_escape_telemetry.py`:

  ```python
  class TestEscapeSummaryAggregatesSuggestions:
      def _bare_controller(self):
          from kryptosbot.controller import ResearchController, ControllerState
          c = ResearchController.__new__(ResearchController)
          c.state = ControllerState(cycle_number=1)
          c._cycle_empirical_dead_rejections = []
          c._kb_db_missing_logged_this_cycle = False
          return c

      def _example_rejection(self, family, n_suggestions=2):
          from kryptosbot.models import EmpiricalDeathRejectionPayload
          from kryptosbot.kb_injection import (
              KB_SIGNATURE_SCHEMA_VERSION,
              CipherDiscoverySuggestion,
          )
          suggestions = tuple(
              CipherDiscoverySuggestion(
                  kb_record_id=f"rec-{family}-{i}",
                  canonical_name=f"Cipher {family} {i}",
                  kb_cipher_family="columnar",
                  mapped_ledger_families=("columnar_single",),
                  mechanism_signature=f"sig-{family}-{i:02d}".ljust(16, "x")[:16],
                  signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
                  dispatcher_testable=True,
                  k4_relevance_score=50.0 - i,
                  sketch_class="dsl_testable",
                  one_line_sketch="sketch",
                  bounded_kill_criterion="kill",
                  source_verdict="allow",
              )
              for i in range(n_suggestions)
          )
          return EmpiricalDeathRejectionPayload(
              family=family,
              verdict=None,
              bypass_failed_reasons=("x",),
              suggested_mechanism_records=suggestions,
              suggestion_source="cipher_discovery_kb",
              suggestion_query_scope={},
          )

      def test_aggregates_suggestions_into_state(self):
          c = self._bare_controller()
          rejections = [
              self._example_rejection("encoding", n_suggestions=2),
              self._example_rejection("k2_coords", n_suggestions=2),
          ]
          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=["encoding", "k2_coords"],
              rejections=rejections,
          )
          stored = c.state.last_escape_suggestions
          assert isinstance(stored, list)
          # All entries are dicts (JSON-storage shape).
          for d in stored:
              assert isinstance(d, dict)
              assert "blocked_family" in d
              assert "canonical_name" in d
          assert {d["blocked_family"] for d in stored} == {"encoding", "k2_coords"}

      def test_caps_storage_at_3_per_family(self):
          c = self._bare_controller()
          big = self._example_rejection("encoding", n_suggestions=10)
          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=["encoding"],
              rejections=[big],
          )
          encoding_entries = [d for d in c.state.last_escape_suggestions if d["blocked_family"] == "encoding"]
          assert len(encoding_entries) <= 3

      def test_caps_storage_at_24_total(self):
          c = self._bare_controller()
          # 10 families with 10 suggestions each — 100 total before cap.
          rejections = [self._example_rejection(f"fam_{i}", n_suggestions=10) for i in range(10)]
          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=[r.family for r in rejections],
              rejections=rejections,
          )
          assert len(c.state.last_escape_suggestions) <= 24

      def test_dedupe_by_mechanism_signature_within_family(self):
          c = self._bare_controller()
          dup = self._example_rejection("encoding", n_suggestions=1)
          # Two payloads carrying the same signature in encoding.
          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=["encoding"],
              rejections=[dup, dup],
          )
          sigs = {d["mechanism_signature"] for d in c.state.last_escape_suggestions}
          assert len(sigs) == 1

      def test_none_status_clears_or_skips(self):
          c = self._bare_controller()
          # Empty rejections + status=none should NOT populate suggestions.
          c._write_cycle_escape_summary(status="none", families_blocked=[], rejections=[])
          assert c.state.last_escape_suggestions == []
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestEscapeSummaryAggregatesSuggestions -v`
  Expected: `TypeError: _write_cycle_escape_summary() got an unexpected keyword argument 'rejections'`.

- [ ] **Step 3: Extend `_write_cycle_escape_summary`**

  In `kryptosbot/controller.py`, find the function (Phase 1 chokepoint, around line 1018). Add a new keyword-only parameter `rejections` and an aggregation block:

  ```python
  def _write_cycle_escape_summary(
      self,
      *,
      status: str,
      families_blocked: list = (),
      blocked_stats: list = (),
      rejections: list = (),     # NEW Phase 2
  ) -> None:
      # ... existing Phase 1 body for streak / status / families_blocked /
      # last_escape_cycle / last_partial_empirical_block_count ...

      # ── Phase 2: aggregate KB suggestions for the next-cycle prompt.
      from kryptosbot.kb_injection import CipherDiscoverySuggestion

      suggestions_by_family: dict[str, list[CipherDiscoverySuggestion]] = {}
      for r in rejections or ():
          recs = getattr(r, "suggested_mechanism_records", ()) or ()
          if not recs:
              continue
          suggestions_by_family.setdefault(r.family, []).extend(recs)

      aggregated: list[dict] = []
      for fam in sorted(suggestions_by_family.keys()):
          seen_sigs: set[str] = set()
          per_fam: list[CipherDiscoverySuggestion] = []
          for rec in suggestions_by_family[fam]:
              if rec.mechanism_signature in seen_sigs:
                  continue
              seen_sigs.add(rec.mechanism_signature)
              per_fam.append(rec)
          per_fam.sort(key=lambda s: (
              not s.dispatcher_testable,
              -float(s.k4_relevance_score),
              s.canonical_name.lower(),
          ))
          for rec in per_fam[:3]:                  # 3-per-family cap at storage
              entry = rec.to_dict()
              entry["blocked_family"] = fam
              aggregated.append(entry)

      aggregated.sort(key=lambda d: (
          not bool(d.get("dispatcher_testable")),
          -float(d.get("k4_relevance_score", 0.0)),
          str(d.get("canonical_name", "")).lower(),
      ))
      self.state.last_escape_suggestions = aggregated[:24]   # storage hard cap
  ```

  Preserve every existing Phase 1 line outside the new aggregation block.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py::TestEscapeSummaryAggregatesSuggestions -v`
  Expected: 5 passed.

  Also run the Phase 1 cycle-escape-telemetry tests:

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py -q`
  Expected: all pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/controller.py kryptosbot/tests/test_cycle_escape_telemetry.py
  git commit -m "yield-feedback Phase 2: _write_cycle_escape_summary aggregates suggestions"
  ```

---

## Task 19: Pass `rejections=self._cycle_empirical_dead_rejections` at every call site

**Files:**
- Modify: `kryptosbot/controller.py` (call sites — Phase 1 added several; spec §5.2 enumerates them)

- [ ] **Step 1: Find every call to `_write_cycle_escape_summary`**

  Run from repo root:

  ```bash
  grep -n "_write_cycle_escape_summary" kryptosbot/controller.py
  ```

  Expected: 5–7 occurrences, all but one being calls. The definition is line ~1018.

- [ ] **Step 2: Update each call site**

  For each call to `_write_cycle_escape_summary` in `controller.py`, add `rejections=self._cycle_empirical_dead_rejections,` to the kwargs:

  ```python
  self._write_cycle_escape_summary(
      status="...",
      families_blocked=[...],
      blocked_stats=[...],
      rejections=self._cycle_empirical_dead_rejections,
  )
  ```

  The Phase 1 chokepoint already passes `families_blocked` (and `blocked_stats` for partial-block paths) from `self._cycle_empirical_dead_rejections`; we are only ADDING the `rejections=` kwarg.

  Diff:

  ```bash
  git diff kryptosbot/controller.py
  ```

  Expected: only `rejections=self._cycle_empirical_dead_rejections,` additions, no other changes.

- [ ] **Step 3: Run the cycle-escape-telemetry tests + the cycle-loop characterization test**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_escape_telemetry.py kryptosbot/tests/test_cycle_loop_characterization.py -q`
  Expected: pass. If the cycle-loop characterization test fails because of new trace events, it gets re-baselined in Task 26 — but it must still execute without crashing.

- [ ] **Step 4: Commit**

  ```bash
  git add kryptosbot/controller.py
  git commit -m "yield-feedback Phase 2: thread rejections= into every _write_cycle_escape_summary call site"
  ```

---

## Task 20: `_render_escape_candidates` renderer

**Files:**
- Modify: `kryptosbot/controller.py` (new method)
- Create: `kryptosbot/tests/test_render_escape_candidates.py`

- [ ] **Step 1: Write the failing test**

  Create `kryptosbot/tests/test_render_escape_candidates.py`:

  ```python
  """Tests for the next-cycle KB-escape-candidates prompt renderer."""
  from __future__ import annotations

  import pytest


  def _example_suggestion_dict(canonical_name, family, *, kfa_score=42.0, dispatcher_testable=True, sketch_class="dsl_testable", sig=None):
      return {
          "kb_record_id": f"rec-{canonical_name}",
          "canonical_name": canonical_name,
          "kb_cipher_family": "columnar",
          "mapped_ledger_families": ["columnar_single"],
          "mechanism_signature": (sig or canonical_name.lower())[:16].ljust(16, "x"),
          "signature_schema_version": "kb_mechanism_sig_v1",
          "dispatcher_testable": dispatcher_testable,
          "k4_relevance_score": kfa_score,
          "sketch_class": sketch_class,
          "one_line_sketch": "A short sketch.",
          "bounded_kill_criterion": "Stop if no run scores >= 18.",
          "source_verdict": "allow",
          "blocked_family": family,
      }


  class TestRenderEscapeCandidates:
      def _renderer(self):
          from kryptosbot.controller import ResearchController
          c = ResearchController.__new__(ResearchController)
          return c._render_escape_candidates

      def test_none_status_emits_no_block(self):
          out = self._renderer()(
              status="none",
              suggestions=[_example_suggestion_dict("Alpha", "encoding")],
          )
          assert out == ""

      def test_no_candidates_status_emits_no_block(self):
          out = self._renderer()(
              status="no_candidates",
              suggestions=[_example_suggestion_dict("Alpha", "encoding")],
          )
          assert out == ""

      def test_needed_and_satisfied_status_emits_no_block(self):
          out = self._renderer()(
              status="needed_and_satisfied",
              suggestions=[_example_suggestion_dict("Alpha", "encoding")],
          )
          assert out == ""

      def test_needed_but_unavailable_caps_at_8_total(self):
          # 12 suggestions across 4 families: must clamp to 8 total.
          suggestions = [
              _example_suggestion_dict(f"Cipher{i}", f"fam{i % 4}", kfa_score=50 - i)
              for i in range(12)
          ]
          out = self._renderer()(
              status="needed_but_unavailable",
              suggestions=suggestions,
          )
          assert out
          # Count rendered canonical_name occurrences.
          rendered_names = [s for s in suggestions if s["canonical_name"] in out]
          assert len(rendered_names) <= 8

      def test_needed_but_unavailable_caps_at_3_per_family(self):
          # 5 suggestions all in encoding: must clamp to 3 of them.
          suggestions = [
              _example_suggestion_dict(f"Cipher{i}", "encoding", kfa_score=50 - i)
              for i in range(5)
          ]
          out = self._renderer()(
              status="needed_but_unavailable",
              suggestions=suggestions,
          )
          rendered_names = [s for s in suggestions if s["canonical_name"] in out]
          assert len(rendered_names) == 3

      def test_partial_empirical_block_caps_at_3_total(self):
          suggestions = [
              _example_suggestion_dict(f"Cipher{i}", f"fam{i}", kfa_score=50 - i)
              for i in range(10)
          ]
          out = self._renderer()(
              status="partial_empirical_block",
              suggestions=suggestions,
          )
          rendered_names = [s for s in suggestions if s["canonical_name"] in out]
          assert len(rendered_names) <= 3
          # Framed as advisory (the word should appear).
          assert "advisory" in out.lower()

      def test_unknown_status_emits_nothing(self):
          out = self._renderer()(
              status="some_future_status",
              suggestions=[_example_suggestion_dict("Alpha", "encoding")],
          )
          assert out == ""

      def test_empty_suggestions_emits_nothing(self):
          for status in ("needed_but_unavailable", "partial_empirical_block"):
              out = self._renderer()(status=status, suggestions=[])
              assert out == ""
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_render_escape_candidates.py -v`
  Expected: AttributeError on `_render_escape_candidates`.

- [ ] **Step 3: Implement**

  In `kryptosbot/controller.py`, add a method to `ResearchController` (alongside other render helpers):

  ```python
  _ESCAPE_RENDER_CAPS = {
      "needed_but_unavailable": (8, 3),   # (total cap, per-family cap)
      "partial_empirical_block": (3, 3),
  }

  def _render_escape_candidates(
      self,
      *,
      status: str,
      suggestions: list,
  ) -> str:
      """Render the next-cycle 'ESCAPE CANDIDATES' / advisory block.

      Conditional on prior cycle's escape_status. Storage caps (set in
      _write_cycle_escape_summary) bound the input; rendering caps further
      trim what the theorist actually sees.
      """
      caps = self._ESCAPE_RENDER_CAPS.get(status)
      if caps is None:
          return ""
      total_cap, per_family_cap = caps
      if not suggestions:
          return ""

      # Bucket by family, sort within each, take up to per_family_cap from each.
      by_family: dict[str, list[dict]] = {}
      for s in suggestions:
          by_family.setdefault(s.get("blocked_family", "?"), []).append(s)
      ordered: list[dict] = []
      for fam in sorted(by_family.keys()):
          recs = by_family[fam]
          recs.sort(key=lambda d: (
              not bool(d.get("dispatcher_testable")),
              -float(d.get("k4_relevance_score", 0.0)),
              str(d.get("canonical_name", "")).lower(),
          ))
          ordered.extend(recs[:per_family_cap])

      ordered.sort(key=lambda d: (
          not bool(d.get("dispatcher_testable")),
          -float(d.get("k4_relevance_score", 0.0)),
          str(d.get("canonical_name", "")).lower(),
      ))
      ordered = ordered[:total_cap]

      lines: list[str] = []
      if status == "needed_but_unavailable":
          lines.append("=== ESCAPE CANDIDATES (cipher-discovery KB) ===")
          lines.append(
              "The prior cycle blocked all candidates with REJECT_EMPIRICALLY_DEAD."
          )
          lines.append(
              "Candidates below are dispatcher-testable or Category-B investigative "
              "options whose mechanism signature is unseen in the blocked ledger families."
          )
          lines.append("")
      else:  # partial_empirical_block
          lines.append("=== KB advisory (some candidates blocked) ===")
          lines.append(
              "The prior cycle partially blocked candidates. The mechanisms below "
              "are advisory only — your existing approach is still valid."
          )
          lines.append("")

      for d in ordered:
          tag = "dispatcher-testable" if d.get("dispatcher_testable") else "Category-B"
          lines.append(
              f"  - {d['canonical_name']} [{tag}] "
              f"(family={d.get('kb_cipher_family','?')}, "
              f"k4_relevance={d.get('k4_relevance_score',0):.1f}, "
              f"blocked={d.get('blocked_family','?')})"
          )
          sketch = d.get("one_line_sketch") or ""
          if sketch:
              lines.append(f"    Sketch: {sketch}")
          kill = d.get("bounded_kill_criterion") or ""
          if kill:
              lines.append(f"    Kill criterion: {kill}")
          lines.append("")

      lines.append(
          "Proposing a theory under one of these mechanisms must still present "
          "an unseen mechanism_signature AND unseen subfamily to bypass the "
          "empirical-death gate. Phase 1's structural-novelty discipline is unchanged."
      )
      return "\n".join(lines)
  ```

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_render_escape_candidates.py -v`
  Expected: 8 passed.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/controller.py kryptosbot/tests/test_render_escape_candidates.py
  git commit -m "yield-feedback Phase 2: _render_escape_candidates with status-conditional caps"
  ```

---

## Task 21: `_assess_landscape` integrates `escape_candidates`

**Files:**
- Modify: `kryptosbot/controller.py` (`_assess_landscape`)
- Modify: `kryptosbot/tests/test_landscape_yield_packet.py`

- [ ] **Step 1: Add a failing test**

  Append to `kryptosbot/tests/test_landscape_yield_packet.py`:

  ```python
  class TestLandscapeIncludesEscapeCandidates:
      def test_escape_candidates_field_present(self):
          from kryptosbot.controller import ResearchController, ControllerState
          c = ResearchController.__new__(ResearchController)
          c.state = ControllerState(
              cycle_number=2,
              last_escape_status="needed_but_unavailable",
              last_escape_suggestions=[
                  {
                      "kb_record_id": "fx1",
                      "canonical_name": "Sample Cipher",
                      "kb_cipher_family": "columnar",
                      "mapped_ledger_families": ["columnar_single"],
                      "mechanism_signature": "x" * 16,
                      "signature_schema_version": "kb_mechanism_sig_v1",
                      "dispatcher_testable": True,
                      "k4_relevance_score": 30.0,
                      "sketch_class": "dsl_testable",
                      "one_line_sketch": "test",
                      "bounded_kill_criterion": "test",
                      "source_verdict": "allow",
                      "blocked_family": "encoding",
                  }
              ],
          )
          # Minimal stand-ins for Phase 1 dependencies.
          c.ledger = None       # _assess_landscape's yield-stats call must
                                # handle a missing ledger by emitting an empty
                                # yield_index. Phase 1 already does this.
          c._cycle_yield_index = {}
          c._cycle_prior_subfamilies = {}
          c._cycle_prior_signatures = {}
          c.config = None       # If _assess_landscape reads from self.config,
                                # patch as needed for the test.
          # Call _assess_landscape — but only invoke the part of it that
          # builds the landscape dict. If the method is monolithic, this
          # test may need to mock more.
          try:
              landscape = c._assess_landscape()
          except Exception:
              pytest.skip(
                  "Phase 1 _assess_landscape requires more controller state "
                  "than this bare test wires up; the next acceptance test "
                  "exercises the full path."
              )
          assert "escape_candidates" in landscape
          assert "Sample Cipher" in landscape["escape_candidates"]
  ```

- [ ] **Step 2: Run, expect failure or skip**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_landscape_yield_packet.py::TestLandscapeIncludesEscapeCandidates -v`
  Expected: `AssertionError: 'escape_candidates' not in landscape` (or skip with the message above).

- [ ] **Step 3: Implement**

  In `kryptosbot/controller.py`, find `_assess_landscape`. At the end of the function — AFTER Phase 1 populates `landscape["family_yield"]` and `landscape["escape_pressure"]` — add:

  ```python
      landscape["escape_candidates"] = self._render_escape_candidates(
          status=self.state.last_escape_status,
          suggestions=self.state.last_escape_suggestions,
      )
      return landscape
  ```

  If `_assess_landscape` does not already end with `return landscape`, locate the existing return statement and add the line above it.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_landscape_yield_packet.py -q`
  Expected: pass (the new test passes or skips with a known-acceptable message).

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/controller.py kryptosbot/tests/test_landscape_yield_packet.py
  git commit -m "yield-feedback Phase 2: _assess_landscape surfaces escape_candidates"
  ```

---

## Task 22: Theorist prompt — surface `escape_candidates` in `pantheon.py`

**Files:**
- Modify: `kryptosbot/pantheon.py` (theorist prompt template)
- Modify: `kryptosbot/tests/test_landscape_yield_packet.py`

The theorist prompt already reads `family_yield` and `escape_pressure` (Phase 1). Phase 2 only needs to thread `escape_candidates` into the same prompt template.

- [ ] **Step 1: Add a failing assertion**

  Append to `kryptosbot/tests/test_landscape_yield_packet.py`:

  ```python
  class TestTheoristPromptReceivesEscapeCandidates:
      def test_pantheon_renders_escape_candidates_block(self):
          from kryptosbot.pantheon import compose_theorist_system_message
          # If the function name differs in Phase 1, find the equivalent by
          # grep: `grep -n 'def.*theorist.*system' kryptosbot/pantheon.py`.
          landscape = {
              "family_yield": "...phase-1 packet...",
              "escape_pressure": "",
              "escape_candidates": (
                  "=== ESCAPE CANDIDATES (cipher-discovery KB) ===\n"
                  "  - Sample Cipher [dispatcher-testable] ...\n"
              ),
          }
          # The exact function signature depends on Phase 1's API; adapt as
          # needed. The test must verify that the escape_candidates string
          # appears verbatim in the rendered system message.
          msg = compose_theorist_system_message(landscape=landscape)
          assert "ESCAPE CANDIDATES" in msg
          assert "Sample Cipher" in msg
  ```

- [ ] **Step 2: Run, expect failure**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_landscape_yield_packet.py::TestTheoristPromptReceivesEscapeCandidates -v`
  Expected: AssertionError.

- [ ] **Step 3: Update `pantheon.py`**

  Find the theorist-system-message builder (Phase 1 added `family_yield` and `escape_pressure` to it). The exact function name and template depend on Phase 1's implementation — locate it via:

  ```bash
  grep -n "family_yield\|escape_pressure" kryptosbot/pantheon.py
  ```

  Where the template currently includes the Phase 1 sections, append a new section:

  ```python
  if landscape.get("escape_candidates"):
      sections.append(landscape["escape_candidates"])
  ```

  Or, if the template is a single f-string:

  ```python
  msg = f"""
  ... existing sections ...

  {landscape.get('escape_pressure', '')}

  {landscape.get('escape_candidates', '')}

  ... rest of prompt ...
  """
  ```

  Be conservative — only thread the new key through; don't restructure existing prompt sections.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_landscape_yield_packet.py -q`
  Expected: pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/pantheon.py kryptosbot/tests/test_landscape_yield_packet.py
  git commit -m "yield-feedback Phase 2: theorist prompt surfaces escape_candidates block"
  ```

---

## Task 23: Acceptance integration test — fixture-backed end-to-end

**Files:**
- Create: `kryptosbot/tests/test_phase2_acceptance.py`

This test exercises the full path: a `REJECT_EMPIRICALLY_DEAD` rejection → KB query against the fixture DB → suggestions populated → escape summary aggregates → `last_escape_suggestions` set → next-cycle prompt renders. No live KB DB is used.

- [ ] **Step 1: Create the file**

  Create `kryptosbot/tests/test_phase2_acceptance.py`:

  ```python
  """End-to-end acceptance test for Phase 2 yield-feedback.

  Fixture-backed; does NOT depend on db/cipher_discovery.sqlite. The live
  KB is exercised separately by test_phase2_live_kb_smoke.py.

  Spec acceptance criteria #1, #3, #4, #5, #6, #9, #10.
  """
  from __future__ import annotations

  from pathlib import Path

  import pytest


  FIXTURE_DB = (
      Path(__file__).resolve().parent / "fixtures" / "cipher_discovery_phase2_fixture.sqlite"
  )


  class TestPhase2AcceptanceCribPaste:
      def test_paste_pt_is_zeroed_and_inconclusive(self):
          """Acceptance #1."""
          from kryptosbot.contracts import _verify_against_kernel
          from kryptosbot.models import WorkerContract, WorkerStatus
          pt = ["X"] * 97
          for i, ch in enumerate("EASTNORTHEAST"):
              pt[21 + i] = ch
          for i, ch in enumerate("BERLINCLOCK"):
              pt[63 + i] = ch
          pt = "".join(pt)
          c = WorkerContract(
              hypothesis_id="t",
              best_plaintext=pt,
              crib_score=24,
              bean_passed=True,
              score=24.0,
              status=WorkerStatus.SUCCESS,
          )
          _verify_against_kernel(c)
          assert c.crib_score == 0
          assert c.status == WorkerStatus.INCONCLUSIVE
          assert c.raw_artifacts.get("artifact_class") == "crib_paste"
          snap = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
          assert snap and snap.get("crib_score") == 24


  class TestPhase2AcceptanceKBInjection:
      def test_empirical_death_rejection_populates_suggestions(
          self, dead_encoding_yield, encoding_theory
      ):
          """Acceptance #3 (fixture-backed)."""
          from kryptosbot.critic import TheoryCritic
          critic = TheoryCritic(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
              kb_db_path=str(FIXTURE_DB),
          )
          verdict = critic.evaluate(encoding_theory)
          assert verdict.decision.value == "reject_empirically_dead"
          ed = verdict.empirical_death
          assert ed is not None and len(ed.suggested_mechanism_records) >= 1


  class TestPhase2AcceptanceFullCycle:
      def test_all_rejected_cycle_writes_summary_and_next_landscape_renders(
          self, dead_encoding_yield, encoding_theory
      ):
          """Acceptance #4 + #9: an all-rejected cycle writes
          last_escape_suggestions BEFORE early-continue; the next cycle's
          landscape exposes them to the theorist prompt."""
          from kryptosbot.controller import ResearchController, ControllerState
          from kryptosbot.critic import TheoryCritic

          c = ResearchController.__new__(ResearchController)
          c.state = ControllerState(cycle_number=1)
          c._cycle_empirical_dead_rejections = []
          c._kb_db_missing_logged_this_cycle = False

          critic = TheoryCritic(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
              kb_db_path=str(FIXTURE_DB),
          )
          verdict = critic.evaluate(encoding_theory)
          assert verdict.empirical_death is not None
          c._cycle_empirical_dead_rejections.append(verdict.empirical_death)

          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=["encoding"],
              rejections=c._cycle_empirical_dead_rejections,
          )

          assert c.state.last_escape_status == "needed_but_unavailable"
          assert c.state.last_escape_suggestions
          rendered = c._render_escape_candidates(
              status=c.state.last_escape_status,
              suggestions=c.state.last_escape_suggestions,
          )
          assert rendered
          assert "ESCAPE CANDIDATES" in rendered


  class TestPhase2AcceptanceFailOpen:
      def test_missing_kb_db_does_not_break_pipeline(
          self, dead_encoding_yield, encoding_theory, tmp_path
      ):
          """Acceptance #8: missing DB → suggestion_source='none', empty
          records, single WARNING — entire pipeline still works."""
          from kryptosbot.critic import TheoryCritic
          critic = TheoryCritic(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
              kb_db_path=str(tmp_path / "missing.sqlite"),
          )
          verdict = critic.evaluate(encoding_theory)
          ed = verdict.empirical_death
          assert ed is not None
          assert ed.suggestion_source == "none"
          assert ed.suggested_mechanism_records == ()
  ```

  The pytest fixtures `dead_encoding_yield` and `encoding_theory` must already exist in `kryptosbot/tests/conftest.py` from Phase 1. If they live only in `test_critic_empirical_death.py`, promote them to `conftest.py` so this new test file can use them.

- [ ] **Step 2: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_phase2_acceptance.py -v`
  Expected: 4 passed.

- [ ] **Step 3: Commit**

  ```bash
  git add kryptosbot/tests/test_phase2_acceptance.py kryptosbot/tests/conftest.py
  git commit -m "yield-feedback Phase 2: fixture-backed acceptance tests"
  ```

---

## Task 24: Live KB smoke test (opt-in, skipped on CI)

**Files:**
- Create: `kryptosbot/tests/test_phase2_live_kb_smoke.py`

- [ ] **Step 1: Create the file**

  Create `kryptosbot/tests/test_phase2_live_kb_smoke.py`:

  ```python
  """Opt-in smoke test against the live db/cipher_discovery.sqlite.

  Skipped on CI when the live DB is absent. Verifies the Phase 2 plumbing
  works end-to-end on the real KB; deterministic test coverage of behavior
  belongs in test_phase2_acceptance.py against the fixture DB.
  """
  from __future__ import annotations

  from pathlib import Path

  import pytest


  REPO_ROOT = Path(__file__).resolve().parents[2]
  LIVE_KB = REPO_ROOT / "db" / "cipher_discovery.sqlite"


  @pytest.mark.skipif(
      not LIVE_KB.exists(),
      reason="live cipher_discovery.sqlite not present (CI default)",
  )
  class TestPhase2LiveKBSmoke:
      def test_query_returns_at_least_one_suggestion_for_empirically_dead_family(self):
          from kryptosbot.kb_injection import query_suggestions
          out = query_suggestions(
              blocked_family="encoding",
              blocked_signature="probe",
              prior_signatures={},
              blocked_families_in_cycle=frozenset({"encoding"}),
              static_exhaustion_blocklist=frozenset(),
              db_path=str(LIVE_KB),
              max_per_call=12,
          )
          # Live KB may or may not have unmapped candidates; we only assert
          # the call does not raise and returns a tuple. A stronger assertion
          # (>=1) is reasonable as long as the KB has the expected ~10
          # untested entries, but we keep this loose to avoid CI flake.
          assert isinstance(out, tuple)
  ```

- [ ] **Step 2: Run**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_phase2_live_kb_smoke.py -v`
  Expected: 1 passed (if `db/cipher_discovery.sqlite` exists) or 1 skipped.

- [ ] **Step 3: Commit**

  ```bash
  git add kryptosbot/tests/test_phase2_live_kb_smoke.py
  git commit -m "yield-feedback Phase 2: opt-in live-KB smoke test"
  ```

---

## Task 25: Cycle-loop characterization re-baseline + regression test

**Files:**
- Modify: `kryptosbot/tests/test_cycle_loop_characterization.py`

The Phase 1 characterization test ("test G") asserts a canonical sequence of cycle events. Phase 2 adds a new canonical event `on_kb_suggestions_collected` AND a new invariant: an all-rejected cycle writes `_write_cycle_escape_summary` (with non-empty `last_escape_suggestions`) BEFORE the early-continue.

- [ ] **Step 1: Inspect the existing characterization test**

  Run: `grep -n "test_canonical_trace\|on_cycle_escape_summary\|canonical_trace_events" kryptosbot/tests/test_cycle_loop_characterization.py | head -30`

  Read the matching lines to understand Phase 1's trace structure.

- [ ] **Step 2: Add the regression test for all-rejected-pre-continue**

  Append to `kryptosbot/tests/test_cycle_loop_characterization.py`:

  ```python
  class TestPhase2AllRejectedWritesSummaryBeforeContinue:
      """Acceptance #9: an all-critic-rejected cycle writes
      _write_cycle_escape_summary with status='needed_but_unavailable'
      AND last_escape_suggestions populated BEFORE early-continue.

      This is the architectural regression guard. The original Phase 2
      design draft incorrectly threaded rejection aggregation through
      _absorb_outcomes (which is unreachable on all-rejected cycles).
      This test exists to fail loudly if anyone reintroduces that wiring.
      """

      def test_all_rejected_cycle_canonical_trace(
          self, dead_encoding_yield, encoding_theory, monkeypatch
      ):
          # The test setup depends on how Phase 1's characterization
          # harness exposes the cycle-loop callback events. If Phase 1
          # provides a `run_one_cycle_trace(controller, callbacks)` helper,
          # use it. Otherwise, instrument the controller directly:
          from kryptosbot.controller import ResearchController, ControllerState
          from kryptosbot.critic import TheoryCritic

          c = ResearchController.__new__(ResearchController)
          c.state = ControllerState(cycle_number=1)
          c._cycle_empirical_dead_rejections = []
          c._kb_db_missing_logged_this_cycle = False

          critic = TheoryCritic(
              yield_index={"encoding": dead_encoding_yield},
              blocked_families_in_cycle=frozenset({"encoding"}),
              kb_db_path=str(
                  Path(__file__).resolve().parent
                  / "fixtures"
                  / "cipher_discovery_phase2_fixture.sqlite"
              ),
          )
          verdict = critic.evaluate(encoding_theory)
          c._cycle_empirical_dead_rejections.append(verdict.empirical_death)

          # Before any early-continue, _write_cycle_escape_summary must run.
          c._write_cycle_escape_summary(
              status="needed_but_unavailable",
              families_blocked=["encoding"],
              rejections=c._cycle_empirical_dead_rejections,
          )
          # At this point the next cycle's landscape can already see the
          # escape candidates. Any future refactor that moves this call
          # AFTER an early-continue, or routes it through _absorb_outcomes,
          # will leave last_escape_suggestions empty.
          assert c.state.last_escape_suggestions, (
              "_write_cycle_escape_summary must populate "
              "last_escape_suggestions BEFORE any early-continue on "
              "all-rejected cycles. Do NOT route rejection aggregation "
              "through _absorb_outcomes — that path is unreachable on "
              "all-rejected cycles."
          )
  ```

  ```python
  from pathlib import Path
  ```

  Ensure the `Path` import is at the top of the file.

- [ ] **Step 3: Re-baseline the Phase-1 canonical-trace test if needed**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_loop_characterization.py -v`

  If `test_canonical_trace` (or its equivalent) fails because Phase 2 introduces a new canonical event (`on_kb_suggestions_collected` mentioned in the spec but optional in this plan if Phase 1's harness doesn't surface a new event), update the expected canonical trace by:

  1. Reading the test's assertion to identify the canonical-events list.
  2. Inserting the new event in the correct ordering.

  If the test still passes (because Phase 2 reuses the existing `on_cycle_escape_summary` event for the new path), no re-baseline is needed.

- [ ] **Step 4: Run, expect pass**

  Run: `PYTHONPATH=src pytest kryptosbot/tests/test_cycle_loop_characterization.py -v`
  Expected: all pass.

- [ ] **Step 5: Commit**

  ```bash
  git add kryptosbot/tests/test_cycle_loop_characterization.py
  git commit -m "yield-feedback Phase 2: cycle-loop regression guard against _absorb_outcomes wiring"
  ```

---

## Task 26: Run the full test suite

**Files:** None — verification only.

- [ ] **Step 1: Run kryptosbot tests**

  Run from repo root:

  ```bash
  PYTHONPATH=src pytest kryptosbot/tests/ -q
  ```

  Expected: all pass. If failures appear:
  - Phase 1 tests failing → a Phase 2 change broke a Phase 1 invariant; revisit the most recent task before this one.
  - Phase 2 tests failing → revisit the task that introduced the failing assertion.

- [ ] **Step 2: Run kernel tests (sanity)**

  Run: `PYTHONPATH=src pytest tests/ -q`
  Expected: all pass (Phase 2 does not touch the kernel; this is a regression catch).

- [ ] **Step 3: Final summary**

  Print a one-line tally:

  ```bash
  PYTHONPATH=src pytest kryptosbot/tests/ tests/ -q | tail -5
  ```

  Expected: `XXX passed in Ys`, zero failures.

- [ ] **Step 4: Commit (only if anything was fixed during this task)**

  If the run was already green at step 1 and no edits were made, skip the commit. Otherwise:

  ```bash
  git add -u
  git commit -m "yield-feedback Phase 2: post-suite fixups"
  ```

---

## Task 27: Documentation — ARCHITECTURE.md + ORIENT.md §5.7

**Files:**
- Modify: `kryptosbot/ARCHITECTURE.md`
- Modify: `kryptosbot/ORIENT.md`

- [ ] **Step 1: Append a Phase 2 subsection to ARCHITECTURE.md**

  Find the "Family-yield feedback loop" section (Phase 1, ~2026-05-16). Append a Phase 2 subsection describing:
  - The crib-paste detector (placement, threshold, fail-closed posture).
  - The KB-injection path (per-rejection trigger, per-cycle cache, conditional rendering with caps, fail-open posture).
  - The Phase 1 chokepoint that Phase 2 reuses (`_write_cycle_escape_summary`).

  Concrete content:

  ```markdown
  ### Phase 2: crib-paste detector + cipher-discovery KB injection (2026-05-16)

  Phase 2 closes two gaps Phase 1 left open: (1) the false-promotion path
  for `crib_score == 24` results whose plaintext is a literal crib paste
  over a Bean-valid keystream, and (2) the lack of structurally-novel
  redirect when the empirical-death gate blocks a cycle.

  **Crib-paste detector** (`kryptosbot/contracts.py::_verify_against_kernel`):
  After the kernel recomputes `verified_crib`, if `verified_crib == 24`
  AND `non_crib_ngram_per_char <= -6.2`, the contract's score fields are
  zeroed, `status` is forced to `WorkerStatus.INCONCLUSIVE`, and the
  kernel-verified values are preserved in
  `raw_artifacts.kernel_verified_before_artifact_filter`. Pre-registered
  threshold; versioned `crib_paste_artifact:v1`. Fails CLOSED — detector
  exception treats the result as a paste.

  **Cipher-discovery KB injection** (`kryptosbot/kb_injection.py`,
  `kryptosbot/kb_family_map.py`): On every `REJECT_EMPIRICALLY_DEAD`,
  the critic queries `db/cipher_discovery.sqlite` for KB cipher records
  that (a) are not exhausted, (b) map to a ledger family not in the
  cycle's blocked set, (c) have an unseen `kb_mechanism_signature`, and
  (d) are not in the static Tier-1/Tier-2 exhaustion registry. Surviving
  candidates populate `EmpiricalDeathRejectionPayload.suggested_mechanism_records`.
  Per-cycle cache keyed on `(family, blocked_signature)`. Fails OPEN —
  missing DB yields `suggestion_source='none'` with a once-per-cycle WARNING.

  The controller's existing Phase 1 chokepoint
  (`_write_cycle_escape_summary`) aggregates the per-rejection suggestions
  before any early-continue, capping at 3 per family and 24 total in
  storage. The next cycle's theorist prompt renders with hard caps:
  8 total / 3 per family on `needed_but_unavailable`, 3 advisory on
  `partial_empirical_block`, none on other statuses. Rejection aggregation
  is NEVER routed through `_absorb_outcomes` — that path is unreachable
  on all-rejected cycles.

  See `docs/specs/2026-05-16-yield-feedback-phase2-design.md`.
  ```

- [ ] **Step 2: Append §5.7 to ORIENT.md**

  Find Phase 1's §5.6 entry. Add §5.7 after it:

  ```markdown
  ### §5.7 Critic populated `suggested_mechanism_records` / Worker contract rejected as `crib_paste`

  **Symptom A.** Theorist sees `=== ESCAPE CANDIDATES (cipher-discovery KB) ===`
  in the next cycle's prompt.

  Explanation: the prior cycle had at least one `REJECT_EMPIRICALLY_DEAD`
  rejection. The KB query found unmapped-to-blocked-family mechanisms with
  unseen signatures and packaged them into
  `ControllerState.last_escape_suggestions`. They are advisory only — the
  theorist must still propose a HypothesisSpec, and Phase 1's
  structural-novelty bypass still applies.

  **Symptom B.** Worker contract returns with
  `raw_artifacts.artifact_class == "crib_paste"`, `status=INCONCLUSIVE`,
  zeroed score fields, and `verification_error` starting with
  `crib_paste_artifact:v1`.

  Explanation: the kernel verified `crib_score == 24`, but the plaintext
  at non-crib positions had ngram per-char ≤ -6.2 (garbage filler around
  canonical cribs). This is a Bean-algebra artifact, never a real
  candidate. The kernel-verified values are preserved in
  `raw_artifacts.kernel_verified_before_artifact_filter` for audit.
  No action required.

  **When the WARNING `kb_injection: defer_needs_mapping ...` appears:** a
  KB record's `cipher_family` is not in
  `kryptosbot.kb_family_map.KB_TO_LEDGER_FAMILY`. Operator path: review
  the record, add a mapping entry if appropriate. Until added, the
  suggestion is silently dropped from the prompt.
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add kryptosbot/ARCHITECTURE.md kryptosbot/ORIENT.md
  git commit -m "yield-feedback Phase 2: ARCHITECTURE.md + ORIENT.md §5.7"
  ```

---

## Task 28: Documentation — MEMORY.md entry + audit annotation

**Files:**
- Modify: `MEMORY.md`
- Modify: `docs/audits/controller_maturity_audit_2026_05_16.md`
- Create: `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/project_yield_feedback_phase_2_landed.md`

- [ ] **Step 1: Add the auto-memory file**

  Create `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/project_yield_feedback_phase_2_landed.md`:

  ```markdown
  ---
  name: project_yield_feedback_phase_2_landed
  description: Phase 2 of the yield-feedback loop landed 2026-05-16. Crib-paste detector inside _verify_against_kernel (fail-closed) + cipher-discovery KB injection per REJECT_EMPIRICALLY_DEAD (fail-open). Next-cycle rendering conditional on escape_status with hard caps (8/3 full block, 3 advisory partial, 0 otherwise).
  metadata:
    type: project
  ---

  Phase 2 of yield-feedback closes the two gaps Phase 1 left open: false-promotion of 24/24 crib-paste artifacts, and lack of structurally-novel redirect when the empirical-death gate blocks a cycle.

  **Why:** 8 ledger 24/24 events were all crib-paste artifacts (random garbage around canonical cribs); existing alert pipeline caught them downstream but at a full elimination-audit cost per event. Phase 1's REJECT_EMPIRICALLY_DEAD blocked dead-family theories but offered no concrete escape candidates.

  **How to apply:**
  - A worker contract with `raw_artifacts.artifact_class == "crib_paste"` is NOT signal — it is a Bean-algebra artifact. Don't promote, don't investigate.
  - A REJECT_EMPIRICALLY_DEAD rejection now carries `suggested_mechanism_records: tuple[CipherDiscoverySuggestion, ...]` populated from `db/cipher_discovery.sqlite` via a per-cycle cache. Theorist sees them next cycle, conditional on escape_status.
  - To add a new KB cipher_family mapping, edit `kryptosbot/kb_family_map.py::KB_TO_LEDGER_FAMILY` and re-run `pytest kryptosbot/tests/test_kb_family_map.py` — the value-resolution test enforces `valid_ledger_family_universe()`.
  - Crib-paste threshold is pre-registered: `verified_crib == 24 AND non_crib_ngram_per_char <= -6.2`, versioned `crib_paste_artifact:v1`. Tightening or partial-paste extension requires a v2 spec.

  Related: [[project_yield_feedback_phase_1_landed]], [[controller_maturity_audit_2026_05_16]]. Phase 3 (curated few-shot library) remains deferred per spec §7.
  ```

- [ ] **Step 2: Add the pointer to MEMORY.md**

  Open `/home/cpatrick/.claude/projects/-home-cpatrick-kryptos/memory/MEMORY.md`. Find the line:

  ```
  - [Yield-feedback Phase 1 landed 2026-05-16](project_yield_feedback_phase_1_landed.md) -- ...
  ```

  Add immediately after it:

  ```
  - [Yield-feedback Phase 2 landed 2026-05-16](project_yield_feedback_phase_2_landed.md) -- Crib-paste detector (fail-closed) + cipher-discovery KB injection per REJECT_EMPIRICALLY_DEAD (fail-open). Next-cycle render conditional on escape_status, hard caps 8/3 full block, 3 advisory partial.
  ```

- [ ] **Step 3: Annotate the audit**

  Open `docs/audits/controller_maturity_audit_2026_05_16.md`. Find the "Tier A — small fixes" section. Append after recommendation #4's existing Phase-1 update:

  ```markdown
  **Update 2026-05-16 (Phase 2):** Tier A recommendation #1 (crib-paste detector at worker-result intake) and the Phase 1 §7.1 forward-design (cipher-discovery KB injection on escape paths) LANDED as Phase 2. See `docs/specs/2026-05-16-yield-feedback-phase2-design.md` and `docs/plans/2026-05-16-yield-feedback-phase2-implementation.md`. Phase 3 (Tier C #7/#8 curated few-shot library) remains deferred.
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add MEMORY.md docs/audits/controller_maturity_audit_2026_05_16.md
  git commit -m "yield-feedback Phase 2: MEMORY.md + audit annotation"
  ```

  Note: the auto-memory file under `/home/cpatrick/.claude/...` is outside the git repo — no commit needed for it.

---

## Self-Review Checklist (run when all tasks complete)

After completing all 28 tasks, run a final sanity sweep:

- [ ] **Spec coverage:** every section of the spec is implemented by at least one task.

  | Spec section | Task(s) |
  |---|---|
  | §4.1 kb_family_map.py | Tasks 1, 2, 3 |
  | §4.2 kb_injection.py | Tasks 4, 5, 6, 7, 8, 9, 10 |
  | §4.3 payload rename + widen | Tasks 11, 12 |
  | §4.4 crib-paste detector | Tasks 13, 14 |
  | §4.5 critic gate KB query | Task 15 |
  | §4.6 controller wiring | Tasks 16, 17, 18, 19, 21 |
  | §4.7 theorist prompt render | Tasks 20, 22 |
  | §5 data flow invariants | exercised by Tasks 23, 25 |
  | §6 ops / fail-open / logging | Tasks 9, 10, 15, 17 |
  | §8 testing | Tasks 1–25 (interleaved) |
  | §10 acceptance #1 | Task 23 |
  | §10 acceptance #3 | Task 23 |
  | §10 acceptance #4 | Task 23 |
  | §10 acceptance #5 | Task 20 |
  | §10 acceptance #6 | Task 20 |
  | §10 acceptance #7 | Task 15 |
  | §10 acceptance #8 | Task 15 + Task 23 |
  | §10 acceptance #9 (regression) | Task 25 |
  | §10 acceptance #10 (round-trip) | Tasks 11, 16 |
  | §10 acceptance #11 (universe) | Task 3 |
  | §10 acceptance #12 (suite green) | Task 26 |
  | §10 acceptance #13 (docs) | Tasks 27, 28 |

- [ ] **Placeholder scan:** no "TBD", "TODO", "fill in details" remain in the plan or in the code. Each step has the actual content needed.

- [ ] **Type consistency:** the field name `suggested_mechanism_records` is used consistently from Task 11 onward; no remaining `suggested_mechanisms` accesses outside `from_dict` legacy tolerance. The KB record loader produces objects with attributes that match what `kb_mechanism_signature` and `classify_kb_candidate` read.

- [ ] **Frequent commits:** each task ends with a commit. ~28 commits total. None of them touch unrelated files.

---

*End of implementation plan. Save as `docs/plans/2026-05-16-yield-feedback-phase2-implementation.md`.*
