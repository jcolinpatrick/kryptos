# Codex Master Mathematical Audit

Date: 2026-05-02

## Executive Verdict

**PARTIALLY TRUSTWORTHY**

KryptosBot now has several trustworthy bounded components: CT97 constants import cleanly, Bean H1 crib-position constraints are independently reproducible, stale null caches have been rebuilt for the current kernel commit, worker self-reported score fields are kernel-overruled, dispatcher scoring can be exercised on independent arbitrary-length known-answer challenges including externally sourced fixtures, and prompt surfaces now carry explicit provenance guardrails.

It is still not a production-grade general classical-cryptanalysis instrument. Its strongest results remain conditional on the exact search universe, exact crib model, exact cipher-family semantics, and exact calibration null that were tested.

## Strongest Honest Claim

Under H1 - direct positional crib mapping, canonical 97-character carved transcription, and Vigenere/Beaufort/Variant Beaufort additive semantics - the project independently verifies Bean crib-position algebra, candidate plaintexts against kernel crib scoring, calibrated candidate-local null baselines, and dispatcher semantics for a useful set of arbitrary-length local and external hand-cipher fixtures.

## Strongest Forbidden Claim

The project must not claim that KryptosBot would solve K4 if K4 were a normal hand cipher. The repository does not yet demonstrate broad autonomous solving power across arbitrary-length independent challenge ciphertexts, complete search-breadth corrections, and fully external known-answer corpora for every live family and multi-layer search.

## Audit Conclusions

| Claim | Evidence | Reproduction | Failure Mode If Wrong | Confidence | Recommended Action |
| --- | --- | --- | --- | --- | --- |
| Bean equality k[27] = k[65] | Independently derived from CT+cribs; exact repo match. | `PYTHONPATH=src python3 scripts/audit/audit_bean_constraints.py` | False hard constraints at crib positions. | High | Keep H1-scoped. |
| 242 Bean inequalities | Independently derived by variant-independent key inequality checks. | Same as above | Invalid candidate pruning. | High | Keep H1-scoped; do not globalize. |
| 101 Bean linear constraints | Independently rederived as mod-26 linear identities over crib positions. | Same as above | Wrong 624 count and false eliminations. | High | Treat as algebraic consequence, not independent evidence. |
| 624 valid keystream vectors | Reproduced by solving mod 2 and mod 13, CRT-combining 8788 candidates, then applying inequalities. | Same as above | Overstated exhaustive search or bad pruning. | High | Document that no literal 26^24 enumeration occurred. |
| Bean p~1/5520 minor-difference claim | Independently reproduced in substance under a K4-letter-multiset permutation null: p=0.000186, about 1/5376 with 2,000,000 samples. | `PYTHONPATH=src python3 scripts/audit/audit_bean_reported_statistics.py` | Reported statistic becomes a hard scoring prior or global K4 fact. | Medium-high | Classify as PROJECT_REVERIFIED_STATISTICAL_ANOMALY; ranking/context only. |
| Bean repeated-PT-distance statistic | One explicit summed repeated-PT CT-distance statistic rerun: p=0.004276 under the same permutation null. Bean's unspecified variants remain under-specified. | Same as above | Descriptive clustering becomes a false mechanism. | Medium | Keep exact tested statistic separate from Bean narrative variants. |
| Stehle Δ5 existence | CT[55:64] = `DIAWINFBN`; all five lag-4 deltas equal 5. | `PYTHONPATH=src python3 scripts/audit/audit_stehle_significance.py` | Prompt chases a false local pattern. | High | Keep as verified local anomaly. |
| Stehle p~1/642 | Reproduced only as 712 * 1/26^4 Bonferroni any-delta calculation, not as a pre-registered cipher test. | Same as above | Treats post-hoc descriptive p-value as mechanism evidence. | Medium | Recast as post-hoc significance only. |
| Stehle exploitability | Bounded mechanism audit tested additive leakage, simple grid interpretations, equal-delta scans, single-deletion null hypotheses, and finite geometry-only predicates; no hard predicate found. | `PYTHONPATH=src python3 scripts/audit/audit_stehle_mechanisms.py` | False hard constraint or "fingerprint" language. | High | Use as soft ranking/prompt context only. |
| Random-text crib-score null | Exact Binomial(24, 1/26) tail confirmed. | `PYTHONPATH=src python3 scripts/audit/audit_null_baselines.py` | Misleading tail p-values for crib score. | High | Valid only for independent random candidate plaintext. |
| Matched-family empirical nulls | Manifest now has 13 current-commit distributions and 0 stale entries; extreme p-values remain limited by empirical floors. | Same as above | Alerts calibrated against stale kernels or impossible tail resolution. | High | Keep stale-cache refusal and floor reporting. |
| Alert p-value consumption | Alerts call p-value helper; helper refuses stale cache and returns `stale_cache`; alert artifacts now persist null identity, candidate-local p, family-wise p, sample floor, effective gate, and universe hash. | `PYTHONPATH=src python3 -m pytest tests/audit -q` | Silent calibrated claims from stale distributions or candidate-local p-values mistaken for family evidence. | High | Continue treating p-values as calibrated metadata, not victory conditions. |
| K1/K2/K3 self-test | Dry-run discovers K1/15, K2/17, K3/9345. | `PYTHONPATH=src python3 scripts/audit/audit_known_answer_battery.py` | Scripted replay mistaken for general solving. | Medium | Keep as regression only. |
| Dispatcher known-answer challenges | Arbitrary-length independent fixtures now pass through `job_dispatcher.execute(..., challenge_ciphertext=..., challenge_crib_dict=...)` for many live families plus random/wrong-parameter controls, exact one-candidate checks, externally sourced Caesar/Vigenere/Beaufort/Atbash/rail-fence/columnar/Myszkowski/route/Bifid/Quagmire fixtures, a published double-columnar composite, three local composite fixtures, layer-order controls, and a six-candidate enumerated composite universe. | `PYTHONPATH=src python3 -m pytest tests/audit/test_dispatcher_known_answer_challenges.py -q` | Tests prove known-key semantic translation, not autonomous cryptanalysis. | Medium-high | Expand external grille/procedural corpora and larger preregistered multi-layer fixtures. |
| DSL dispatcher coverage | 19 DSL kinds, 18 dispatcher kinds; `key_tape` is the explicit gap. | `PYTHONPATH=src python3 scripts/audit/audit_dsl_dispatcher_semantics.py` | DSL accepts silent unsupported cipher. | High | Keep gap explicit until implemented and independently tested. |
| Provenance enforcement | Policy gates block retired/statistical/reported claims as hard constraints; Pantheon and API prompts include guardrails; live `.claude` null-palette surfaces were rewritten as retired-context-only. | `PYTHONPATH=src python3 scripts/audit/audit_provenance_leakage.py` | Claims leak through archival docs or generated eval outputs outside gates. | Medium | Continue replacing free prose with rendered policy outputs. |
| Elimination harness accounting | Three finite harnesses were smoke-run, budget-truncated, resumed, and hash-mismatch probed; coverage totals match inventory totals, audit processed counts, and checkpoint semantics. | `PYTHONPATH=src python3 scripts/audit/audit_elimination_harness_accounting.py` | Partial runs could be mislabeled eliminated or resume could double/drop work. | High | Keep as CI smoke for any harness checkpoint changes. |
| Live provenance surface CI guard | Live `.claude` prompt surfaces plus Pantheon/API/registry guards now pass a fail-closed checker with zero violations. | `PYTHONPATH=src python3 scripts/audit/check_provenance_live_surfaces.py` | Retired/statistical claims leak through prompt text despite registry policy. | High | Run in CI or pre-controller startup checks. |

## K4 No-Signal Meaning

Current no-signal results are meaningful only inside each exact tested universe. They support statements such as "no signal under this encoded family, these parameters, these cribs, this scorer, this null, and this family-wise correction." They do not support global claims that K4 is probably flawed, bespoke, or beyond standard hand-cipher methods.

## K4 Plausibility Classes

- Flawed: possible, not established by this repository.
- Bespoke: possible, not established.
- Multi-layer beyond current search: plausible because many searches are narrow or H1-bound.
- Underconstrained by public clues: plausible and consistent with current evidence.
- Not yet meaningfully tested globally: true for broad hand-cipher space.

## Top 10 Mathematical Risks

1. H1-conditional Bean facts being used as global K4 facts.
2. 24 crib-position constraints being described as full 97-position keystream constraints.
3. Algebraic constraints counted as independent evidence.
4. Project-rerun statistics used beyond the exact rerun null and statistic.
5. Additive-cipher assumptions leaking into non-additive mechanisms.
6. 0-based/1-based CT position mistakes in prompt or docs.
7. Reduced 73-space and carved 97-space results being mixed.
8. Self-encrypting positions 32 and 73 over-interpreted beyond H1.
9. Linear-constraint enumeration prose implying literal 26^24 exhaustion.
10. Fixed crib disclosures treated as complete plaintext structure.

## Top 10 Statistical Risks

1. Candidate-local p-values mistaken for search-family p-values.
2. Multiple comparisons not globally accounted for outside the added family-wise wrapper.
3. Post-hoc anomaly discovery under-penalized.
4. Empirical null floors below requested alert gates.
5. Future stale null distributions silently accumulating if the manifest is not checked.
6. Permutation, IID, and matched-family nulls mixed rhetorically.
7. Normal approximation used outside its supported scorer/null context.
8. `p < 1/N` language overstating empirical evidence.
9. "No signal" interpreted without exact universe cardinality.
10. High-looking crib scores evaluated without search breadth.

## Top 10 Cryptanalytic-Engineering Risks

1. General arbitrary-length hand-cipher challenge solving is improved but still not proven as autonomous search.
2. Known-answer coverage now includes local, external, route, and composite fixtures plus negative controls, but grille/procedural and broader multi-layer external corpora remain thin.
3. Some supported families still have thin oracle coverage compared with their parameter space.
4. `key_tape` is DSL-valid but intentionally unsupported.
5. Provenance-safe claims can still be bypassed by archival `.claude` prose or generated skill-eval outputs.
6. Registries can promote anomaly language unless reviewed.
7. Retired or speculative agent memory remains searchable.
8. Controller prompt examples can encode post-hoc key priors.
9. Full search-universe hashes are only as good as the parameter model.
10. Timeout/inconclusive/eliminated distinctions require continuous regression tests.

## Concrete Patches Applied

- `kryptosbot/null_baselines.py`: alert p-value helper now refuses stale null caches, reports `stale_cache`, and exposes family-wise p-value correction metadata.
- `kryptosbot/alerts.py`: alert status documentation and warning path now include `stale_cache`; alert artifacts persist null identity, candidate p-value, family-wise p-value, sample floor, and universe hash.
- `kryptosbot/job_dispatcher.py`: raw dispatcher candidates now infer Bean status from candidate plaintext/CT, support explicit arbitrary-length challenge ciphertexts and cribs, reserve `challenge_known_answer` for full crib agreement, annotate best candidates with candidate-local and family-wise p-values, and accept fail-closed spiral route `start_corner`.
- `src/kryptos/kernel/transforms/transposition.py` and `src/kryptos/composition/registry.py`: spiral route permutations now support top-left/top-right/bottom-right/bottom-left starts while preserving the historical top-left default.
- `kryptosbot/claims_registry.py`: Bean minor-difference claim upgraded to PROJECT_REVERIFIED_STATISTICAL_ANOMALY with explicit H1/post-hoc caveats.
- `kryptosbot/registries.py`: Stehle entry downgraded from "cipher fingerprint/weakness" language to local regularity and soft context.
- `kryptosbot/pantheon.py`: agent prompt bodies are prepended with a provenance guardrail.
- `kryptosbot/api_client.py`: Bean statistics prompt wording now uses rendered soft-context claims, not hard-constraint language.
- `null_baselines/manifest.json`: stale entries rebuilt for commit `acfe266e624cb882d2ce8a870257a055e04990e9`.
- `scripts/audit/*.py`, `docs/audits/*.md`, and `tests/audit/*.py`: independent audit artifacts, external known-answer corpus, external double-columnar composite, composite fixtures, negative controls, elimination-harness accounting checks, live provenance-surface checks, and regression tests added.
- `kryptosbot/tests/test_provenance.py`: stale expectation updated to the new soft project-verified anomaly invariant.
- `.claude/agents/*.md` and `.claude/skills/*/SKILL.md`: live null-palette prompt surfaces rewritten as retired-context-only.

## Next Experiments Ranked By Expected Information Gain

1. Add external grille/procedural fixtures and broader external multi-layer composites; keep local audit fixtures as smoke coverage.
2. Separate K4-specific clues from general solver capabilities in every generated prompt.
3. Re-run Bean repeated-distance variants only after their exact statistic and search family are declared.
4. Build a mutation harness that intentionally corrupts crib indexing, variant direction, and alert metadata serialization.
5. Extend external oracle coverage beyond known-key examples into unknown-key challenge corpora where available.
6. Run a larger bounded multi-layer challenge battery with preregistered search budgets and family-wise correction.
7. Extend Stehle mechanism tests to richer finite hand-procedure families beyond geometry-only and single-deletion predicates.
8. Add randomized wrong-parameter/property tests around each transposition family.
9. Promote elimination-harness and live-provenance checks into project CI or controller startup preflight.
10. Add explicit freshness checks for audit JSON artifacts if they become release-blocking deliverables.

## Kill List

- "Stehle is a cipher fingerprint."
- "Stehle is a weakness to exploit" without a defined cipher family.
- "Bean constraints prove global K4 keystream structure."
- "624 vectors constrain the whole keystream."
- "p~1/642 proves mechanism."
- "p~1/5520 is a hard constraint or global K4 fact."
- "Bean repeated-distance variants are fully project-reproduced."
- "No K4 signal means K4 is flawed."
- "No K4 signal means K4 is bespoke beyond normal hand ciphers."
- "KryptosBot would solve K4 if K4 were normal."
- "K1/K2/K3 dry-run proves general solver strength."

## Promote List

- Bean equality, 242 inequalities, 101 linear constraints, and 624 count are independently reproduced as H1-conditional crib-position derivations.
- Bean minor-difference statistic is independently reproduced in substance as a post-hoc H1 statistical anomaly under a K4-multiset permutation null.
- Stehle Δ5 existence is independently verified as a local CT regularity.
- Exact random-text crib-score Binomial tail is mathematically correct.
- Null baseline manifest currently has zero stale distributions.
- Worker self-reported score fields are kernel-overruled at the contract boundary.
- Dispatcher challenge mode now verifies many live families on independent arbitrary-length known-answer fixtures, exact one-candidate universe checks, random/wrong-parameter controls, local and external corpora, a published double-columnar composite, and three local composite fixtures.
- Finite elimination harness smoke/resume accounting is independently audited for three high-risk harnesses.
- Live prompt/control provenance surfaces currently pass the fail-closed guard with zero violations.
- DSL unsupported gap is explicit: `key_tape`.

## Do Not Use As Hard Constraint

- Stehle Δ5.
- Bean p~1/5520 minor-difference statistic.
- Bean repeated-plaintext-distance statistics.
- Width-21 vertical bigram anomaly.
- Retired null palette.
- Physical observations, unless routed through an explicit cryptographic derivation.
- Any H1 claim outside H1 context.
- Any candidate-local p-value without search-family correction.

## One-Page Operator Summary

Use KryptosBot as a bounded audit and experiment harness, not as proof of K4 impossibility. The kernel-level H1 Bean math is solid and independently reproduced. The Bean minor-difference statistic is now independently rerun in substance, but remains post-hoc, H1-conditional, and unusable as a hard constraint. The statistical layer is more defensible after cache refresh, alert artifact metadata, and family-wise p-value annotation, but p-values remain conditional on exact nulls and search universes. The Stehle pattern exists, but bounded mechanism tests and finite geometry-only predicates did not turn it into a cipher constraint. K1/K2/K3 dry-run success plus arbitrary-length local, external, route, and double-columnar dispatcher challenges are useful regressions, not evidence of autonomous general hand-cipher-solving power. The highest-value next step is preregistered multi-layer challenge batteries with exact search-universe accounting.
