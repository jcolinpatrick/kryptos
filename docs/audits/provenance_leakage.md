# Provenance Leakage Audit

## Verdict

- Total high-risk un-routed hits: 2025
- Registry and policy files contain expected uses of the searched terms.
- Any un-routed `fingerprint`, `hard constraint`, p-value, or retired-claim language should be treated as a prompt/doc hardening target.
- Pantheon prompt guardrail present: True
- API prompt Bean section downgraded: True

## Highest-Risk Hits

- `.claude/agent-memory/escape-room-cryptanalyst/misspelling_null_mask_analysis.md:9` [medium]: The intentional misspellings across K0-K3 are DEMONSTRATIONS of the null-mask technique ("wrong letter covers correct letter") and may PARTIALLY define the null palette, but they do NOT by themselves constitute the complete null mask construction rule.
- `.claude/agent-memory/escape-room-cryptanalyst/misspelling_null_mask_analysis.md:26` [medium]: ## Finding 1: NULL PALETTE CONTAINMENT (100%)
- `.claude/agent-memory/escape-room-cryptanalyst/misspelling_null_mask_analysis.md:28` [medium]: All 17 consensus null positions {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85} contain ONLY letters from the null palette {B,G,I,K,O,W,Z}. This is a p < 7.5e-5 result. The palette is a NECESSARY condition for null status.
- `.claude/agent-memory/escape-room-cryptanalyst/physical_puzzle_master_theory.md:35` [medium]: ### Null Palette {B,G,I,K,O,W,Z} as Photographic Artifact
- `.claude/agent-memory/escape-room-cryptanalyst/testable_hypothesis_h6.md:3` [medium]: description: Immediately testable hypothesis that compass deflection angle (66) via mod 6 selects rows from the KA 5-wide grid to produce exactly the null palette {B,G,I,K,O,W,Z}
- `.claude/agent-memory/escape-room-cryptanalyst/testable_hypothesis_h6.md:9` [medium]: The null palette {B,G,I,K,O,W,Z} (proven at p=7.5e-5) maps to KA-alphabet columns 0 and 3
- `.claude/agent-memory/statistical-auditor/MEMORY.md:4` [medium]: - [LaTeX proof post-A1 retirement audit](audit_latex_proof_post_a1_2026_04_02.md) — RETRACT: 3/5 results invalidated. Only Stehle and autokey (weakened) survive.
- `.claude/agent-memory/statistical-auditor/audit_backward_propagation_2026_03_22.md:13` [medium]: - S4 (Stehle delta4) MC p=0.026 (not 0.0016 claimed), destroyed by null removal, subsumed by stego layer
- `.claude/agent-memory/statistical-auditor/audit_latex_proof_post_a1_2026_04_02.md:3` [medium]: description: Full audit of k4_structural_proof.tex after A1 palette invalidation. Verdict: retract. 3/5 main results invalidated (Thm1 palette, Thm2 BCL enrichment, combined BF=1666). Only Stehle delta-4=5 and autokey impossibility survive (autokey weakened, needs re-verification without invalidated mask).
- `.claude/agent-memory/statistical-auditor/audit_latex_proof_post_a1_2026_04_02.md:21` [medium]: | Stehle delta-4=5 | SURVIVES — independent of palette and null mask, p=1.56e-3 |
- `.claude/agent-memory/statistical-auditor/audit_latex_proof_post_a1_2026_04_02.md:28` [medium]: **How to apply:** Do not cite any palette-based statistics from this document. Autokey impossibility and Stehle are the only salvageable claims, both need fresh standalone proofs.
- `.claude/agent-memory/statistical-auditor/website_findings_verification_2026_03_24.md:19` [medium]: - Stehle Delta4=5 unique, corrected p ~1/625: CORRECT (actual 1/642)
- `.claude/agents/AGENT_TEMPLATE.md:114` [high]: ## Hard Constraints
- `.claude/agents/MIGRATION.md:46` [high]: - Hard constraints and behavioral rules
- `.claude/agents/PANTHEON.md:79` [high]: ### Hard Constraints
- `.claude/agents/archivist-historian.md:123` [medium]: - **Accessibility** — would a non-cryptographer (Sanborn) or a retired CIA officer (Scheidt) have encountered it?
- `.claude/agents/archivist-historian.md:195` [high]: ## Hard Constraints
- `.claude/agents/cryptanalyst.md:133` [high]: ## Hard Constraints
- `.claude/agents/keystream-forensics.md:208` [medium]: - Retired null-palette claim: historical set {B,G,I,K,O,W,Z}. Do not use as
- `.claude/agents/keystream-forensics.md:209` [high]: a hard constraint, must-explain requirement, or mechanism evidence without
- `.claude/agents/red-team-disprover.md:201` [high]: ## Hard Constraints
- `.claude/agents/research-chancellor.md:215` [high]: ## Hard Constraints
- `.claude/agents/results-analyst.md:120` [high]: ## Hard Constraints
- `.claude/agents/script-auditor.md:121` [high]: ## Hard Constraints
- `.claude/agents/statistical-auditor.md:3` [medium]: description: "Use this agent when a candidate finding, pattern, or statistical claim from Kryptos K4 research needs rigorous evaluation before being trusted, published, or used to prioritize further work. This includes p-values, enrichment claims, Monte Carlo or permutation results, null-position hypotheses, crib-conditioned structure, score anomalies, model comparisons, robustness checks, and any argument that a pattern is stronger than chance. Also use this agent when drafting publication-qual
- `.claude/agents/stego-analyst.md:5` [medium]: inference, null palette characterization, placement rule discovery, grid/width
- `.claude/agents/stego-analyst.md:22` [medium]: Context: The user proposes an alternative null palette.
- `.claude/agents/stego-analyst.md:26` [medium]: Testing alternative palettes requires MC baselines, comparison to the retired historical palette claim, and checking whether the alternative has a generative mechanism. The stego-analyst is purpose-built for this.
- `.claude/agents/stego-analyst.md:99` [medium]: You are a dedicated steganalysis agent for Kryptos K4. Your sole purpose is to characterize the steganographic layer — the null mask, the null palette, the placement rule, and the coupling between stego and cipher — independently of full ciphertext decryption.
- `.claude/agents/stego-analyst.md:154` [medium]: - **Retired null-palette claim**: historical set {B,G,I,K,O,W,Z}; do not use
- `.claude/agents/stego-analyst.md:155` [high]: as a hard constraint or must-explain requirement without current provenance
- `.claude/projects/-home-cpatrick-kryptos/memory/null_mask_model_dependence.md:32` [medium]: - **Cannot confidently state** the null palette is a ground truth about K4 — the gap between "anomalous under one model" and "intrinsic to K4" has not been closed
- `.claude/projects/-home-cpatrick-kryptos/memory/nyt_article_null_mask_impact.md:13` [medium]: 3. A demonstration was built: 80 chars of real message + 17 null palette letters = 97 chars that read as "LONG AGO SOMEONE EAST NORTH EAST OF THE BURIED REMAINS BENEATH BERLIN CLOCK AT THE SACRED PASSAGE"
- `.claude/projects/-home-cpatrick-kryptos/memory/nyt_article_null_mask_impact.md:14` [medium]: 4. The null palette {B,G,I,K,O,W,Z} at p~3e-5 is a property of the **ciphertext**, not the plaintext — the NYT article reveals nothing about CT structure
- `.claude/skills/cipher-beaufort/SKILL.md:57` [medium]: **Retired BCL palette-enrichment claim**: prior notes stated that 7/8 letters
- `.claude/skills/cipher-beaufort/SKILL.md:59` [high]: that as retired historical context only; it is not a hard constraint, not a
- `.claude/skills/cipher-running-key-beaufort/SKILL.md:36` [medium]: enrichment at BCL positions; treat that claim as retired historical context
- `.claude/skills/cipher-running-key-beaufort/SKILL.md:37` [high]: only, not as a hard constraint or model-selection reason without current
- `.claude/skills/k4-stego-cracker/SKILL.md:107` [medium]: - Retired null-palette claim: historical set {B,G,I,K,O,W,Z}. Do not use as
- `.claude/skills/k4-stego-cracker/SKILL.md:108` [high]: a hard constraint, must-explain requirement, or mechanism evidence without

## Reproduction

```bash
PYTHONPATH=src python3 scripts/audit/audit_provenance_leakage.py
```
