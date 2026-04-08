# Admissibility-First Architecture

*Added 2026-04-08.  See `src/kryptos/admissibility/` and
`scripts/campaigns/f_admissibility_elimination_v1.py`.*

## Why

Kryptosbot is an effective elimination engine for Layer 3 (enumerative
search + scoring), but prior to this layer it had two structural leaks:

1. **Running-key was a default sink.** Any script could load any text
   file and declare it a "running-key source".  The implicit allowlist
   (`EGYPT_GUTENBERG_BOOKS` etc.) was curated thematically, not by
   admissibility justification.
2. **Zero-hit results were free-text.** `elimination_reason` was a
   single string column; "0 hits at period 7" and "formal UNSAT at
   period 7" were indistinguishable in the ledger.

The admissibility layer closes both leaks without touching the Layer 3
machinery.  The three layers are now:

| Layer | Question | Where |
|---|---|---|
| 1. Structural legitimacy | Is this family publicly justified? | `corpus_policy.py`, `triage_running_key` gate |
| 2. Exact admissibility | Can ANY parameter satisfy Bean + cribs? | `periodic_admissibility.py` (CP-SAT primary, pure-Python fallback) |
| 3. Enumerative search | Does some parameter actually decrypt K4? | pre-existing pipeline |

## Module layout

```
src/kryptos/admissibility/
    __init__.py                    — flat re-exports
    certificate.py                 — EliminationCertificate, AdmissibilityCertificate, EliminationReason
    corpus_policy.py               — CorpusLicense, allowlist, check_corpus_source
    periodic_admissibility.py      — CP-SAT admissibility for periodic additive families
```

No abstract base classes, no protocol registries, no plugin system.  Two
solver backends (CP-SAT and a pure-Python specialised checker) are
selected by a `use_cp_sat=True` flag; `cross_verify=True` runs both and
enforces agreement.

## Certificates

Every admissibility decision produces a `Certificate` (union of
`EliminationCertificate` and `AdmissibilityCertificate`).  Certificates
are JSON-serialisable and stored in the existing
`Hypothesis.elimination_reason` TEXT column.  Legacy rows (plain strings)
are still valid — `certificate_from_json` returns `None` for them.

**Exact vs empirical is a first-class distinction.**
`EliminationCertificate.is_exact = True` means formal UNSAT under the
stated assumptions.  `is_exact = False` means a bounded-search negative
result.  The two are never conflated.

### Closed reason taxonomy

```
bean_unsat                     — solver proved Bean constraints UNSAT
crib_position_contradiction    — crib positions force incompatible values
insufficient_key_dof           — fewer DOFs than constraints require
empty_parameter_space          — domain empty after propagation
topology_contradiction         — structural/grid contradiction
corpus_policy_violation        — running-key source not on allowlist
assumption_unmet               — required precondition not satisfied
no_hits_full_enum              — empirical, full enumeration, no hits
no_hits_under_budget           — empirical, bounded search, no hits
runtime_exhausted              — timeout or resource ceiling hit
```

Adding a new reason requires a deliberate test update in
`tests/test_admissibility.py::test_reason_enum_is_closed`.  This is
intentional: the closed set is part of the contract.

## Corpus policy

The initial allowlist (`CORPUS_ALLOWLIST` in `corpus_policy.py`) contains
**five** entries:

| source_id | justification | basis |
|---|---|---|
| `k1_plaintext` | CLUE_SURFACE | Published K1 plaintext |
| `k2_plaintext` | CLUE_SURFACE | Published K2 plaintext |
| `k3_plaintext` | CLUE_SURFACE | Published K3 plaintext |
| `carter_tomb_vol1` | ARTIST_STATEMENT | Sanborn's documented Egyptological reference |
| `kahn_codebreakers` | CREATOR_STATEMENT | Ed Scheidt's documented use during design |

Each entry requires a `provenance_uri` and at least one `evidence_refs`
path.  Extending the list requires either a code edit (with test) or a
runtime override at `config/corpus_allowlist.json` that must follow the
same schema.

**Gate enforcement.**  `kryptos.novelty.triage.triage_running_key` calls
`check_corpus_source` before reading any source file.  An unlicensed
source produces an `EliminationCertificate(reason=CORPUS_POLICY_VIOLATION)`
that is stored in `elimination_reason` as JSON and short-circuits the
triage path.

When the gate passes, the bytes consumed are resolved exclusively from
the license's `provenance_uri` via `resolve_license_path(source_id)`.
Caller-supplied `source_path` values are treated as mapping hints only
and are **never** used as a data source.  This closes the
`source_id`/`source_path` decoupling bypass where a valid licensed id
could be paired with an arbitrary path to smuggle unlicensed bytes past
the gate.  If the license's provenance URI is opaque (e.g.
`kryptos://k1_plaintext`), the gate emits an `ASSUMPTION_UNMET`
certificate rather than falling through to any caller-supplied path.

### Known ungated paths

The gate **only** applies to running-key hypotheses routed through
`kryptos.novelty.triage.triage_running_key`.  The following code paths
are intentionally NOT gated by the corpus policy and must be audited
manually:

- **`kryptos.corpus.ingest.TextIngester`.**  A corpus builder used by
  `scripts/_uncategorized/e_egypt_00_corpus_pipeline.py` to load and
  segment Egyptological source texts.  It has no policy hook and
  historical documentation referred to an `enforce_policy` parameter
  that was never implemented in code — that ghost feature has been
  removed from the architecture doc and the `corpus_policy.py`
  docstring.
- **Direct script execution under `scripts/running_key/`.**  Scripts
  that call `decrypt_text`, `beau_decrypt`, or other low-level cipher
  primitives directly without constructing a `Hypothesis` do not pass
  through `triage_running_key` and are therefore ungated.  The
  `f_admissibility_elimination_v1` campaign statically scans these
  scripts and emits `CORPUS_POLICY_VIOLATION` or `ASSUMPTION_UNMET`
  certificates, but the scan is a post-hoc audit, not a runtime gate.
- **`scripts/campaigns/`** scripts that read corpus files directly.
  Same reason as the running-key scripts.
- **Any future code path** that calls `decrypt_text` or equivalent
  with caller-supplied key bytes without routing through
  `triage_running_key`.

### Manual-review backlog

The `f_admissibility_elimination_v1` running-key policy sweep produced
(as of 2026-04-08):
- **2** scripts ACCEPTED under static scan (literal reference to
  allowlisted source)
- **9** scripts REJECTED with `CORPUS_POLICY_VIOLATION` (hint-matched
  to unlicensed themes)
- **16** scripts flagged `ASSUMPTION_UNMET` — they do not expose a
  statically scannable source literal and require manual provenance
  review before they can be run under policy.

The 16 `ASSUMPTION_UNMET` scripts form a backlog.  They are recorded
in `results/admissibility_elimination_v1/running_key_policy.json`.
Until each one is either (a) updated to declare a licensed `source_id`,
(b) paired with a new `CorpusLicense` entry with evidence, or
(c) archived, they should be treated as ineligible to run under
policy.  This backlog is operationally consequential, not decorative.

## Periodic additive admissibility

For variant `V ∈ {vigenere, beaufort, var_beaufort}` and period `p`,
the family `periodic_additive(V, p)` is:

```
k[i] = key[i mod p],  i ∈ [0, 96],  key[j] ∈ [0, 25]
```

Admissibility is the question "does there EXIST a `key` such that
decryption satisfies all 24 crib positions and all 243 Bean constraints
(1 equality + 242 inequalities)?"

The pure-Python checker collapses the CSP to per-residue-class forced
values and a linear scan over Bean pairs; CP-SAT solves the same CSP
directly.  Both return a verdict plus evidence.  The `cross_verify=True`
mode runs both and raises `RuntimeError` on disagreement — a modelling
bug, not a data bug.

### Initial campaign result

`scripts/campaigns/f_admissibility_elimination_v1.py` produces:

- **78/78** (variant, period) pairs for `p ∈ [1, 26]` formally eliminated
  under assumptions A1–A4, every rejection with reason
  `crib_position_contradiction`.  Bean constraints never get to trigger
  because the cribs themselves force incompatible residue-class values
  at every period.
- **9/27** running-key scripts rejected for naming unlicensed sources
  or themes (Gutenberg, ISBN hunt, book cipher, etc.).
- **16/27** running-key scripts flagged as `ASSUMPTION_UNMET` — they do
  not declare a statically scannable source and require manual
  provenance review before they can be run under policy.
- **2/27** running-key scripts accepted (literal reference to Carter
  Vol 1 — an allowlisted `ARTIST_STATEMENT` source).

All certificates are written to
`results/admissibility_elimination_v1/{periodic_additive,running_key_policy}.json`.

## What is deliberately NOT formalised

**Stehle anomaly.**  The constant-difference property at positions
55–63 is a descriptive statistic about the ciphertext, not a predicate
over key variables under a specific family.  Encoding it as a solver
constraint would require a specific family (e.g. "linear-drift additive
with δ=5") for which there is no independent justification.  Attempting
to do so would be pretence.  Stehle remains a valid *evidence reference*
attached to any license entry claiming anomaly-derived provenance, but
it is not a solver constraint.

**KenLM / ML reranking.**  Not the bottleneck.  Would improve Layer 3
scoring at the cost of blurring the admissibility/search distinction.

**pyahocorasick.**  No documented throughput bottleneck in crib scanning.

**New orchestration / dispatch system.**  `run_attack.py` is adequate.
A new dispatch layer would be prestige-tool sprawl.

## Test coverage

`tests/test_admissibility.py` (21 tests) covers:

- Certificate JSON roundtrip for both types
- Legacy plain-string backward compatibility
- Closed reason enum contract
- Corpus policy allowlist structure and entries
- Corpus policy rejection of unknown ids and paths
- Corpus policy acceptance of licensed sources
- Periodic admissibility UNSAT at period 1 for all variants
- Periodic admissibility UNSAT at period 2 from Bean inequality
- Sweep family-name stability
- CP-SAT vs pure-Python agreement
- Triage gate integration: unlicensed source → JSON certificate in
  `elimination_reason`, licensed source → gate bypasses to inner logic

Full suite (1201 tests) passes in ~99s with zero regressions.
