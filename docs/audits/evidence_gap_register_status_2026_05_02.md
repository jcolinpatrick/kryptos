# Evidence Gap Register — Status 2026-05-02

**Predecessor:** `docs/REAL_K4_EVIDENCE_GAP_REGISTER.md` (2026-04-30)

Status of each evidence gap as of post-hardening commit `ffaf5a0`,
informed by the Codex Master Mathematical Audit and the 2026-05-02
review documented in this dossier and `width21_bigram_re-examination.md`.

| gap | original status | new status | what changed |
|---|---|---|---|
| GAP-01 Stehle Δ5 | open | **partially closed** | Codex `audit_stehle_significance.py` + `audit_stehle_mechanisms.py` (2026-05-01) reproduced existence + p≈1/642 Bonferroni calculation, **bounded mechanism audit found no hard predicate** under additive leakage / simple grid / equal-delta scans / single-deletion null / finite-geometry classes. Original closure criterion ("constrained measurement on full 97 chars") still partially open: a pre-registered cipher test tied to the anomaly remains required. |
| GAP-02 Width-21 | open | **rewritten** | The "two contradictory readings" framing is obsolete after palette retirement. "CT73 stego artifact" reading lost its supporting argument (CONSENSUS_NULL_POSITIONS retired). CT97 width-21 anomaly (`p≈1.6e-4`, z=4.48) **stands** as unexplained. See `docs/audits/width21_bigram_re-examination.md`. The gap should be re-cast as *"width-21 on CT97 mechanism attribution: cipher / stego / coincidence — undetermined after retired-palette removal."* |
| GAP-03 BCL Beaufort E0b | open | **partially closed (existence)** | Codex reproduced E0b at p≈0.000186 under K4-multiset permutation null. Claim promoted to `PROJECT_REVERIFIED_STATISTICAL_ANOMALY`. Gap's own criterion was "E0b-specific side-effect operationalization beyond crib match" — that criterion is **still open**; project verification of existence does not by itself supply the side-effect predicate. Reduce priority slightly (existence settled). |
| GAP-04 NDYAHR/YAR | open | unchanged | No new spatial measurement. |
| GAP-05 sculpture geometry | open | unchanged | No new measurement. |
| GAP-06 Sanborn non-crib comments | open — likely permanent | unchanged | No new operational creator statement; doctrine codified in `C-SANBORN-02`. |
| GAP-07 running-key source text | open | unchanged | No new specific source-text identification. Stage A/B explicitly exclude running-key. |
| GAP-08 K2/K3 provenance analogy | open | unchanged | No new design-pattern attestation. |
| GAP-09 null-mask / stego evidence | open | **structurally clarified** | Palette retirement landed; `CONSENSUS_NULL_POSITIONS` moved to `kryptos.kernel.retired`; score-conditioned null audit closed the palette as post-hoc. The gap's closure criterion (a "not derived from score-conditioned search" stego construct) is now codified. No new construct has been proposed that meets it. |
| GAP-10 crib-bound positional mechanism | open | unchanged | No new analysis on the unknown 73 positions. |

## Aggregate

- Closed: 0
- Partially closed: 2 (GAP-01, GAP-03 — both have project-verified
  existence claims now; the structural / mechanism criteria remain
  open)
- Rewritten: 1 (GAP-02 — palette retirement changed the framing)
- Structurally clarified: 1 (GAP-09 — closure criterion codified)
- Unchanged: 6

## Implication for the bridge-campaign pause rule

The evidence gap register's pause rule says:

> No new bridge campaign should be opened against any of the gaps
> below until at least one of them is closed by new admissible
> evidence.

By the register's own criteria, **no gap has reached "closed"
status**. Two have moved to "partially closed" — but that movement is
on the *existence* dimension only; the *operationalization* dimension
that gates new bridge admission is unchanged for both. The pause rule
should remain in effect.

## Recommended next actions on the gaps

Three small probes from the width-21 re-examination (`docs/audits/width21_bigram_re-examination.md`
§"Recommended action") are the only project-internal moves that can
make further progress on a gap (specifically GAP-02) without new
external evidence:

1. Reproduce CT97 width-21 with current kernel under palette-free
   tooling (≤ 1 hour).
2. Cross-test CT97 in a 21-column grid with predeclared row offsets
   (≤ 1 hour).
3. Pre-declare a non-palette null mask candidate set and test
   width-21 under each (≤ 2 hours).

Everything else on the register depends on external evidence acquisition
that is not project-internal (`docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md`).

---

*Last updated 2026-05-02. Score-only; no new compute. The
recommendation table updates the register's `status` column candidates
but does not edit the register itself — operator review required.*
