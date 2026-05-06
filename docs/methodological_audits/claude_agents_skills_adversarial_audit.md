# Claude Agents and Skills Adversarial Audit

## Executive Verdict

Verdict: **PARTIAL**.

The `.claude` layer is useful infrastructure, and the controller wiring is materially better than a freeform multi-agent brainstorming setup: all routed agents load, `setting_sources=["project"]` is used in the controller paths, Task/Agent delegation is blocked, and prompt wrappers override native narrative contracts where the controller needs JSON.

It is **not** sufficient to call the current Claude skill/agent layer K4-solve-capable. The suite is strong at framed hypothesis generation and some epistemic guardrails, but it is weak at enforcing known-answer readiness, DSL/dispatcher discipline from the prompt layer, and preventing narrative or physical-theory prompts from creating a satisfying story without a bounded kernel test. The biggest gap is not breadth; it is operational closure.

## Commands Run

Required first commands:

| Command | Exit | Result |
|---|---:|---|
| `pwd` | 0 | `/home/cpatrick/kryptos` |
| `git status --short` | 0 | Dirty before audit: `M null_baselines/manifest.json`, untracked `analysis_runs/`, `copy/`, `scratch/` |
| `git rev-parse HEAD` | 0 | `4694094611ca1a43519141367f3c7278bd80b120` |

Pre-flight and load tests:

| Command | Exit | Result |
|---|---:|---|
| `PYTHONPATH=src python3 -m kryptos doctor` | 0 | All doctor checks passed |
| `PYTHONPATH=src python3 scripts/_infra/session_briefing.py` | 0 | Generated live elimination/state briefing |
| `PYTHONPATH=src python3 kryptosbot/run_controller.py --summary` | 0 | Ledger: 1359 theories, 807 experiments, 75 families, 22 open anomalies |
| `PYTHONPATH=src python3 kryptosbot/run_controller.py --inventory` | 0 | Provenance inventory emitted with hedged claim classes |
| `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run` | 0 | K1/K2 rediscovered; K3 failed at default 500 cycles |
| `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000` | 0 | K1/K2/K3 rediscovered; K3 at cycle 9345 |
| Runtime roster load script from prompt | 0 | 13 agents loaded; no routed theorists missing |
| `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_routing.py -q` | 0 | 7 passed |
| `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_r2_1_columnar_double.py -q` | 0 | 13 passed |
| `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_job_dispatcher.py -q` | 0 | 57 passed |

Inventory/static analysis:

| Command | Exit | Result |
|---|---:|---|
| `find .claude -maxdepth 5 -type f | sort` | 0 | 118 files |
| `find .claude/agents -maxdepth 2 -type f | sort` | 0 | 17 files |
| `find .claude/skills -maxdepth 4 -type f | sort` | 0 | 55 files including references/workspace files |
| `find .claude/commands -maxdepth 3 -type f | sort 2>/dev/null || true` | 0 | No `.claude/commands` directory |
| `rg -n "load_roster|DEFAULT_AGENTS_DIR|setting_sources|..." kryptosbot .claude docs CLAUDE.md MEMORY.md` | 0 | Found controller, routing, test, and prompt references |
| `PYTHONPATH=src python3 scratch/claude_static_audit.py` | 1 | Failed: repo root absent from Python path, `ModuleNotFoundError: kryptosbot` |
| `PYTHONPATH=.:src python3 scratch/claude_static_audit.py > /tmp/claude_static_audit.json` | 0 | Static analyzer succeeded |

Why the failed static-analyzer run matters: local scripts in this repo often need both the repo root and `src` on `PYTHONPATH` when importing `kryptosbot` plus `src/kryptos`. The failure did not block the audit; the rerun with `PYTHONPATH=.:src` succeeded.

## Pre-flight Results

`kryptos doctor` passed. Kernel constants, crib count, Bean equality/inequality/linear counts, alphabets, Vigenere/perm roundtrips, Bean checks, scoring, database, quadgrams, and novelty engine all reported `[PASS]`.

The session briefing is internally consistent with the current hardening posture: it reports no credible decrypt path, retired null-palette constructs, strict scoping for H1/Bean claims, and a large active/exhausted script landscape.

The required dry-run self-test is the key negative result. With the default command specified in this audit prompt, K1 and K2 pass but K3 fails:

```text
k1 discovered=True cycles=15 peak=20/20
k2 discovered=True cycles=17 peak=20/20
k3 discovered=False peak=4/20 tested=500
```

The harness itself is not broken: with `--cycles 20000`, K3 is discovered at cycle 9345. The problem is the default readiness command. A default 500-cycle all-panel run produces a false readiness failure for K3, while the R3 protocol expects a larger cap.

## .claude Inventory

Counts:

| Surface | Count | Runtime relevance |
|---|---:|---|
| All `.claude` files to maxdepth 5 | 118 | Mixed: agents, skills, memory, references, skill eval output |
| `.claude/agents` files | 17 | 13 loadable agents, 4 documentation/template files |
| Loadable agents | 13 | Loaded by `kryptosbot.pantheon.load_roster()` |
| `.claude/skills/*/SKILL.md` | 39 | Project skills loadable by Claude Code/Agent SDK through `setting_sources=["project"]` |
| Skills referenced in agent frontmatter | 8 | Declarative only; controller does not pass these references to SDK |
| Skills unreferenced by agent frontmatter | 31 | Available globally only if the Skill tool selects them |
| `.claude/commands` | 0 | No command-layer coverage |
| `.claude/agent-memory` files | 34 | Documentation/archival; not loaded by Pantheon |
| `.claude/projects/.../memory` files | 9 | Claude Code memory/doc artifacts, not Pantheon agents |
| `.claude/memory` files | 1 | Documentation/archival |

Loadable agent files:

```text
.claude/agents/archivist-historian.md
.claude/agents/cipher-discovery-builder.md
.claude/agents/cryptanalyst.md
.claude/agents/escape-room-cryptanalyst.md
.claude/agents/forensic-photo-analyst.md
.claude/agents/keystream-forensics.md
.claude/agents/kryptos-corpus-forensics.md
.claude/agents/red-team-disprover.md
.claude/agents/research-chancellor.md
.claude/agents/results-analyst.md
.claude/agents/script-auditor.md
.claude/agents/statistical-auditor.md
.claude/agents/stego-analyst.md
```

Agent documentation/template files:

```text
.claude/agents/AGENT_TEMPLATE.md
.claude/agents/MIGRATION.md
.claude/agents/PANTHEON.md
.claude/agents/USAGE.md
```

Skill files:

```text
.claude/skills/cipher-affine/SKILL.md
.claude/skills/cipher-atbash/SKILL.md
.claude/skills/cipher-autokey-beaufort/SKILL.md
.claude/skills/cipher-autokey-vigenere/SKILL.md
.claude/skills/cipher-beaufort/SKILL.md
.claude/skills/cipher-bifid/SKILL.md
.claude/skills/cipher-caesar/SKILL.md
.claude/skills/cipher-columnar/SKILL.md
.claude/skills/cipher-ct-autokey-beaufort/SKILL.md
.claude/skills/cipher-ct-autokey-vigenere/SKILL.md
.claude/skills/cipher-double-columnar/SKILL.md
.claude/skills/cipher-four-square/SKILL.md
.claude/skills/cipher-gromark/SKILL.md
.claude/skills/cipher-gronsfeld/SKILL.md
.claude/skills/cipher-identification/SKILL.md
.claude/skills/cipher-myszkowski/SKILL.md
.claude/skills/cipher-nihilist/SKILL.md
.claude/skills/cipher-porta/SKILL.md
.claude/skills/cipher-quagmire-ii-autokey/SKILL.md
.claude/skills/cipher-quagmire-ii/SKILL.md
.claude/skills/cipher-rail-fence/SKILL.md
.claude/skills/cipher-rot13/SKILL.md
.claude/skills/cipher-route/SKILL.md
.claude/skills/cipher-running-key-beaufort/SKILL.md
.claude/skills/cipher-running-key-vigenere/SKILL.md
.claude/skills/cipher-serpentine/SKILL.md
.claude/skills/cipher-spiral/SKILL.md
.claude/skills/cipher-variant-beaufort/SKILL.md
.claude/skills/cipher-vigenere/SKILL.md
.claude/skills/disproof-protocol/SKILL.md
.claude/skills/forensic-photo-analysis/SKILL.md
.claude/skills/k4-stego-cracker/SKILL.md
.claude/skills/otp-null-keystream-forensics/SKILL.md
.claude/skills/project-onboarding/SKILL.md
.claude/skills/results-protocol/SKILL.md
.claude/skills/script-discovery/SKILL.md
.claude/skills/statistics/SKILL.md
.claude/skills/sweep-kryptos-photo-corpus/SKILL.md
.claude/skills/sympy-proof-writer/SKILL.md
```

Documentation/reference-only skill files include `k4-stego-cracker/references/*`, `otp-null-keystream-forensics/references/*`, `statistics/references/*`, `statistics/scripts/stat_tests.py`, `sweep-kryptos-photo-corpus/references/output_schema.md`, and the `sympy-proof-writer-workspace` eval artifacts. These are not skills themselves.

## Runtime Wiring Findings

All routed agents are discoverable by `load_roster()`. Runtime roster load reported:

```text
ROSTER_COUNT 13
MISSING_THEORISTS []
redteam: red-team-disprover
stat_auditor: statistical-auditor
```

Routed and present:

```text
archivist-historian
cipher-discovery-builder
cryptanalyst
escape-room-cryptanalyst
keystream-forensics
red-team-disprover
research-chancellor
results-analyst
statistical-auditor
stego-analyst
```

Present but unrouted:

```text
forensic-photo-analyst
kryptos-corpus-forensics
script-auditor
```

Routed missing: none.

The controller does use `setting_sources=["project"]` in the relevant paid-session paths, and explicitly disables Task/Agent tools. This is compatible with sibling orchestration. The controller comments state that project settings make skills and agents available, then block Task/Agent so all inter-agent orchestration happens in Python (`kryptosbot/controller.py:1885`, `kryptosbot/controller.py:2001`, `kryptosbot/controller.py:2009`). Sibling calls use the same `setting_sources=["project"]` plus `disallowed_tools=["Task", "Agent"]`.

Important caveat: agent frontmatter `tools` and `skills` are parsed into `AgentSpec`, but the controller does not use `spec.tools` or `spec.skills` to configure the SDK. Actual SDK options use `ControllerConfig.allowed_tools` for all agents. The declared skill lists are documentation, not enforcement. This is a real integration gap because “skill referenced by an agent” does not mean “skill will be loaded into that agent only” or “skill will be invoked.”

The native agent output contracts generally conflict with controller-required JSON, but `pantheon.AgentSpec` wraps the body per phase:

- `theorist_system_prompt()` forces one JSON array.
- `worker_system_prompt()` forces a fenced `WorkerContract` JSON block.
- `redteam_precheck_system_prompt()`, `stat_audit_system_prompt()`, `synthesis_system_prompt()`, and `pursuit_system_prompt()` force structured JSON objects.

This wrapper layer is essential. Without it, the native `.claude/agents/*.md` prompts are mostly narrative contracts.

## Agent Capability Matrix

Ratings:

- Contract strength: `A` explicit machine output, falsification, anti-overfit, repo/tool discipline; `B` good but missing one major element; `C` useful persona but weak operational contract; `D` narrative-only or likely to break controller expectations; `F` missing/unloadable/actively harmful.
- Cryptanalytic value: `A` materially improves bounded K4 search/validation; `B` useful specialist; `C` mostly advisory; `D` redundant/unfocused; `F` harmful/misleading.

| Agent | File | Loadable? | Routed phase(s) | Model | Tools | Skills | Contract strength | Cryptanalytic value | Main risk | Recommendation |
|---|---|---:|---|---|---|---|---|---|---|---|
| cryptanalyst | `.claude/agents/cryptanalyst.md` | yes | theorist, worker fallback/default for many families | opus | frontmatter R/B/G/W; runtime global | onboarding, script, results, disproof | B | B | Good canonical scoring guidance, but native output is narrative and no native DSL contract | Keep; add explicit HypothesisSpec/dispatcher doctrine |
| escape-room-cryptanalyst | `.claude/agents/escape-room-cryptanalyst.md` | yes | theorist, worker for geometry/grille/procedural | opus | none in frontmatter; runtime global | none | C | C | Strongest story-generation/sycophancy risk; physical claims may outrun testability | Rewrite to require physical fact vs crypto constraint separation and DSL handoff |
| stego-analyst | `.claude/agents/stego-analyst.md` | yes | theorist, worker for null/stego | opus | R/W/B/G | k4-stego, onboarding, stats, disproof, results | B | B | Carries retired/conditional null evidence in compact reference; points to missing memory files | Keep but scrub stale paths/retired constructs; add fail-closed provenance gates |
| archivist-historian | `.claude/agents/archivist-historian.md` | yes | theorist, worker for archive_evidence | opus | R/G/W | onboarding, results | C | B/C | Source analysis useful, but no machine contract and weak direct dispatcher handoff | Keep; add provenance policy checklist and hard “not a constraint” language |
| keystream-forensics | `.claude/agents/keystream-forensics.md` | yes | theorist, worker for key_tape/otp | opus | R/W/B/G | otp-null, onboarding, stats, disproof, results | B | B | Tunnel-vision risk; some model-status statements look stale; hardcoded constants | Keep; update model status from live briefing and route to key_tape DSL examples |
| cipher-discovery-builder | `.claude/agents/cipher-discovery-builder.md` | yes | theorist only | opus | none in frontmatter; runtime global | none | D | C | Prompt is a broad subsystem builder, mentions web search, and examples say use Agent tool; mismatched to controller sibling mode | Split into offline corpus analyst vs implementation builder; remove from theorist rotation until bounded |
| red-team-disprover | `.claude/agents/red-team-disprover.md` | yes | red-team precheck | opus | R/B/G/W | onboarding, disproof, stats, script, results | B | B | Good adversarial method, but controller treats red-team SDK/parse error as pass | Keep; add tests for reject/concerned JSON and reduce bypass paths |
| statistical-auditor | `.claude/agents/statistical-auditor.md` | yes | stat-audit | opus | none in frontmatter; runtime global | none | B | B/A | Strong methodology but weak repo-specific command/tool binding | Keep; add canonical null-baseline command paths and artifact expectations |
| results-analyst | `.claude/agents/results-analyst.md` | yes | synthesis, pursuit | sonnet | R/G/W | onboarding, results | B/C | C | Can summarize narrative too readily; not a validator by itself | Keep; constrain to ledger/kernel fields only |
| research-chancellor | `.claude/agents/research-chancellor.md` | yes | pursuit fallback; present but not main manager in controller | opus | R/W/B/G | onboarding, results, stats | C | C | Native prompt says commission/cross-examine agents, but runtime blocks nested agents | Keep for human/manual use; do not rely on it for actual orchestration |
| script-auditor | `.claude/agents/script-auditor.md` | yes | none | opus | R/G | onboarding, script | B | B | Valuable but not routed; implementation bugs can reach campaigns without this persona | Add routed phase for code/harness audit or keep manual-only intentionally |
| forensic-photo-analyst | `.claude/agents/forensic-photo-analyst.md` | yes | none | opus | R/G/B | forensic-photo, onboarding | C | C | Physical observations can be mistaken for crypto constraints unless gated | Manual-only unless a physical-evidence pipeline is added |
| kryptos-corpus-forensics | `.claude/agents/kryptos-corpus-forensics.md` | yes | none | opus | R/G/B | none | C | C | Useful image/corpus workflow but no runtime route; Phase 4/stale indicators | Manual-only or route through explicit archival acquisition phase |

## Skill Capability Matrix

| Skill | Path | Trigger clarity | Operational specificity | Uses canonical repo tools? | Anti-overfit safeguards | Agent references | Runtime relevance | Risk | Recommendation |
|---|---|---|---|---:|---:|---|---|---|---|
| cipher-affine | `.claude/skills/cipher-affine/SKILL.md` | high | low | yes | partial | none | globally available only | medium | Retire or convert to dispatcher examples |
| cipher-atbash | `.claude/skills/cipher-atbash/SKILL.md` | high | low | yes | partial | none | globally available only | medium | Retire or fold into basic-cipher appendix |
| cipher-autokey-beaufort | `.claude/skills/cipher-autokey-beaufort/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add current elimination scope and stop conditions |
| cipher-autokey-vigenere | `.claude/skills/cipher-autokey-vigenere/SKILL.md` | high | medium | yes | partial | none | globally available only | medium | Same as above |
| cipher-beaufort | `.claude/skills/cipher-beaufort/SKILL.md` | high | medium | yes | partial | none | globally available only | high | Scrub retired BCL/palette context; add dispatcher specs |
| cipher-bifid | `.claude/skills/cipher-bifid/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Mark structural elimination scope prominently |
| cipher-caesar | `.claude/skills/cipher-caesar/SKILL.md` | high | low | yes | partial | none | globally available only | medium | Fold into basic additive skill |
| cipher-columnar | `.claude/skills/cipher-columnar/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add known-answer K3 and dispatcher DSL examples |
| cipher-ct-autokey-beaufort | `.claude/skills/cipher-ct-autokey-beaufort/SKILL.md` | high | medium | partial | weak | none | globally available only | medium | Mark eliminated/direct-scope only |
| cipher-ct-autokey-vigenere | `.claude/skills/cipher-ct-autokey-vigenere/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Same |
| cipher-double-columnar | `.claude/skills/cipher-double-columnar/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add K3/R2-1 exact regression and correct method language |
| cipher-four-square | `.claude/skills/cipher-four-square/SKILL.md` | high | low | yes | weak | none | globally available only | medium | Retire or scope as eliminated/fractionation note |
| cipher-gromark | `.claude/skills/cipher-gromark/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Mark exhaustive elimination scope |
| cipher-gronsfeld | `.claude/skills/cipher-gronsfeld/SKILL.md` | high | medium | yes | partial | none | globally available only | medium | Add DSL examples and score nulls |
| cipher-identification | `.claude/skills/cipher-identification/SKILL.md` | high | medium | no | weak | none | globally available only | medium | Rewrite around dispatcher-supported families |
| cipher-myszkowski | `.claude/skills/cipher-myszkowski/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add assumptions and current eliminations |
| cipher-nihilist | `.claude/skills/cipher-nihilist/SKILL.md` | high | medium | no | partial | none | globally available only | medium | Scope to Polybius/fractionation limitations |
| cipher-porta | `.claude/skills/cipher-porta/SKILL.md` | high | medium | yes | partial | none | globally available only | medium | Add current direct-periodic elimination |
| cipher-quagmire-ii | `.claude/skills/cipher-quagmire-ii/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add Quagmire III/K1/K2 self-test recipe |
| cipher-quagmire-ii-autokey | `.claude/skills/cipher-quagmire-ii-autokey/SKILL.md` | high | low | yes | partial | none | globally available only | medium | Retire or strictly mark eliminated |
| cipher-rail-fence | `.claude/skills/cipher-rail-fence/SKILL.md` | high | medium | yes | partial | none | globally available only | medium | Add DSL kind and null baseline examples |
| cipher-rot13 | `.claude/skills/cipher-rot13/SKILL.md` | high | low | yes | partial | none | globally available only | medium | Fold into Caesar/basic |
| cipher-route | `.claude/skills/cipher-route/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add route/skip/boustrophedon DSL examples |
| cipher-running-key-beaufort | `.claude/skills/cipher-running-key-beaufort/SKILL.md` | high | medium | yes | weak | none | globally available only | high | Scrub retired palette mentions; add corpus license/admissibility |
| cipher-running-key-vigenere | `.claude/skills/cipher-running-key-vigenere/SKILL.md` | high | medium | yes | partial | none | globally available only | medium | Add current public-English elimination scope |
| cipher-serpentine | `.claude/skills/cipher-serpentine/SKILL.md` | high | medium | yes | weak | none | globally available only | low | Keep; add route_boustrophedon mapping |
| cipher-spiral | `.claude/skills/cipher-spiral/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add current DSL support and failure criteria |
| cipher-variant-beaufort | `.claude/skills/cipher-variant-beaufort/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add current Bean conventions and direct eliminations |
| cipher-vigenere | `.claude/skills/cipher-vigenere/SKILL.md` | high | medium | yes | weak | none | globally available only | medium | Add K1/K2/KA and dispatcher examples |
| disproof-protocol | `.claude/skills/disproof-protocol/SKILL.md` | high | low/medium | partial | yes | cryptanalyst, keystream, red-team, stego | referenced | medium | Update commands to `rg`/session briefing and require universe hash |
| forensic-photo-analysis | `.claude/skills/forensic-photo-analysis/SKILL.md` | high | medium | no | yes | forensic-photo | referenced only by unrouted agent | medium | Keep manual-only; require provenance claim class |
| k4-stego-cracker | `.claude/skills/k4-stego-cracker/SKILL.md` | high | high | yes | yes | stego | referenced | high | Fix missing memory paths and retired/conditional compact evidence |
| otp-null-keystream-forensics | `.claude/skills/otp-null-keystream-forensics/SKILL.md` | high | high | yes | yes | keystream | referenced | high | Update model status, remove stale ledger path, add key_tape DSL contract |
| project-onboarding | `.claude/skills/project-onboarding/SKILL.md` | high | low | partial | yes | many | referenced | high | Rewrite; it falsely says CLAUDE contains “current working hypothesis” |
| results-protocol | `.claude/skills/results-protocol/SKILL.md` | high | low | no | weak | many | referenced | medium/high | Replace PROMISING/Hot Leads language with controller status semantics |
| script-discovery | `.claude/skills/script-discovery/SKILL.md` | high | medium | partial | weak | cryptanalyst, red-team, script-auditor | referenced | low/medium | Update from `grep/find` to `run_attack.py`/`rg` and exhaustion log |
| statistics | `.claude/skills/statistics/SKILL.md` | high | high | no | yes | keystream, red-team, chancellor, stego | referenced | medium | Add canonical null-baseline commands and artifact schemas |
| sweep-kryptos-photo-corpus | `.claude/skills/sweep-kryptos-photo-corpus/SKILL.md` | high | low/medium | no | yes | none | globally available only | medium | Reference from corpus/forensic agents or mark manual |
| sympy-proof-writer | `.claude/skills/sympy-proof-writer/SKILL.md` | high | medium | no | yes | none | globally available only | medium | Keep as optional proof tool; not K4 campaign-critical |

## Coverage Map Against K4 Requirements

| Capability needed for credible K4 work | Covered by agent(s)? | Covered by skill(s)? | Wired to controller? | Tested? | Gap severity | Notes |
|---|---:|---:|---:|---:|---|---|
| Known-answer K1/K2/K3 recovery | prose only | no dedicated skill | code harness only | yes, code; default fails K3 | high | Agents/skills rarely mention self-test; no prompt gate forces it |
| Canonical crib scoring | yes | partial | yes via controller/kernel | yes | medium | Cryptanalyst mentions `score_candidate`; many skills do not |
| Bean constraints / scope discipline | yes | partial | yes via contracts/claims | yes | medium | Good code policy; prompt layer still carries compact retired/null references |
| Null-baseline / p-value reasoning | yes | statistics/stego | yes in alerts/dispatcher | yes in tests, not prompt-linted | medium | Strong statistical prose, weak repo command binding |
| Conditional admitted-theory null reasoning | partial | partial | partial | unknown | high | No dedicated conditional-null methodology skill |
| Period/width underdetermination | partial | partial | yes in doctrine | partial | medium | Mentioned in docs/prompts but not enforced across all cipher skills |
| Additive cipher families | yes | many skills | yes via DSL/dispatcher | yes | medium | Skills mostly unreferenced and not agent-specific at runtime |
| Quagmire / Kryptos tableau | partial | yes | yes | yes for K1/K2 paths | medium | Quagmire skills unreferenced; code tests stronger than skill layer |
| Columnar / transposition | yes | yes | yes | yes incl K3 | medium | Default dry-run cap hides K3 success; skill should teach correct cap |
| Route / Myszkowski | yes | yes | yes | yes dispatcher tests | medium | Skills unreferenced and not consistently DSL-specific |
| Grille / Cardano | escape-room/stego | partial | yes via dispatcher for permutation-only | partial | medium/high | Physical grille vs computational grille not sharply separated in prompts |
| Key tape / null insertion | keystream | otp-null | yes via dispatcher as of 2026-05-03 | partial | medium | Good specialist, but stale model-status language |
| Two-layer systems | cryptanalyst/keystream | partial | yes | yes partially | medium/high | Prompt layer lacks concise DSL composition recipes |
| Procedural/sculptural hypotheses | escape-room | weak | partial non-DSL route | weak | high | Highest story risk; needs stricter preregistration |
| Archival source analysis | archivist | weak | partial non-DSL route | weak | medium/high | Useful but must not become constraints |
| Red-team falsification | red-team | disproof/statistics | yes | routing tested | medium | SDK/parse error currently degrades to pass |
| Dispatcher/DSL compatibility | weak in agents | no dedicated skill | yes in code | yes | high | Critical missing skill; agents are not taught exact HypothesisSpec procedures |
| Sycophancy resistance | partial | partial | partial | no prompt lint tests | high | Guardrails exist, but story-driven agents can still satisfy the operator |

Legend: “covered in prose” is not “covered operationally”; only code paths with tests are “covered and tested.”

## Sycophancy-Loop Risk Audit

1. Agents most likely to validate the operator’s preferred frame:
   `escape-room-cryptanalyst`, `cipher-discovery-builder`, `keystream-forensics`, and `stego-analyst`. They each have explicit biases toward physical mechanisms, obscure/bespoke systems, finite-tape models, or stego mechanisms. Bias is useful only if bounded by tests.

2. Actually adversarial agents:
   `red-team-disprover` and `statistical-auditor` are genuinely adversarial in prompt posture. `script-auditor` is potentially adversarial but not routed.

3. Adversarial in name only:
   None are purely cosmetic, but `research-chancellor` is weaker than it looks in controller runtime because it describes commissioning/cross-examination while Task/Agent delegation is blocked. It cannot actually orchestrate agents from inside its session.

4. Skills that encourage “try to solve” without enough falsification:
   Most unreferenced cipher-family skills are attack guides, not campaign contracts. They often describe mechanics and kernel APIs but do not force `HypothesisSpec`, budget, universe hash, matched null, or known-answer validation.

5. Risky language:
   `results-protocol` still says `PROMISING / DISPROVED / INCONCLUSIVE / ERROR` and says to add promising results to “Hot Leads.” That is stale against the controller doctrine where `SUCCESS` is execution completion and `PROMISING` requires kernel-verified signal.

6. Physical/sculptural separation:
   The provenance layer separates physical facts from interpretive physical claims, but `escape-room-cryptanalyst` still contains high-confidence interpretive framings such as “Scheidt confirmed STEGANOGRAPHY” and “Two systems of encipherment are confirmed — one may be physical/steganographic.” These need policy-gated source class labels in the prompt itself.

7. Mechanism forcing “not enough to solve K4”:
   Statistical-auditor and red-team can say it, but no global prompt-contract linter enforces that every agent downgrade advisory/narrative conclusions.

8. Mechanism forcing known-answer validation before K4 search:
   Code exists (`kryptosbot/self_test.py`), but `.claude` skills do not make this a campaign readiness gate. The default all-panel dry-run also fails K3 at 500 cycles.

9. Incentive to produce satisfying story:
   `escape-room-cryptanalyst` has the highest risk: high imagination/narrative sensitivity, low tool discipline, and output contract centered on transform hypotheses. It can be valuable, but only after it is forced into preregistered, measurable predictions.

10. Most likely way the suite fools the operator:
   It looks comprehensive because there are 13 agents and 39 skills, but 31 skills are unreferenced by agent frontmatter, frontmatter skill references are not enforced by the controller, three loadable agents are unrouted, and the skill catalog is not equivalent to bounded dispatcher coverage.

## Known-Answer Fitness Implications

The self-test harness states the correct standard: if the framework cannot rediscover K1/K2/K3 in bounded cycles, it cannot credibly solve K4. The code can rediscover all three with the documented 20K cap. The prompt/skill layer does not make that standard operational.

Implication: the system has a credible known-answer harness, but `.claude` does not yet teach or enforce the harness as a pre-K4 campaign gate. A Claude agent can generate K4 hypotheses without proving that its current skill/tool context can rediscover K3 within the configured cap.

## Underdeveloped Agents

- `cipher-discovery-builder`: too broad and implementation-heavy for a theorist rotation slot. It can launch network-seeking subsystem work rather than bounded K4 hypotheses.
- `escape-room-cryptanalyst`: needs stronger physical-fact vs cryptographic-constraint doctrine and a mandatory path from physical claim to testable prediction.
- `research-chancellor`: useful as a human-facing synthesis prompt, but its native “commission agents” workflow is not executable inside controller sessions.
- `statistical-auditor`: methodologically strong but insufficiently tied to repo null-baseline commands and artifacts.
- `script-auditor`: valuable but not routed.
- `forensic-photo-analyst` and `kryptos-corpus-forensics`: loadable but unrouted; either mark as manual-only or add explicit acquisition routes.

## Underdeveloped Skills

- `project-onboarding`: stale; says `CLAUDE.md` contains the current working hypothesis, directly conflicting with `CLAUDE.md` itself.
- `results-protocol`: stale status vocabulary and memory-update instructions.
- `disproof-protocol`: lacks universe hash, assumption bundle, timeout/inconclusive distinction, and current controller status semantics.
- `script-discovery`: uses `find|grep` examples instead of repo-standard `rg` and `run_attack.py --list --verbose`.
- Cipher-family skills: too many are advisory guides without `HypothesisSpec`, dispatcher support matrix, matched null, failure criteria, or current eliminations.
- `k4-stego-cracker` and `otp-null-keystream-forensics`: operationally specific, but contain stale paths and compact references that can revive retired/conditional constructs.

## Missing Agents / Skills

The suite needs fewer broad personas and more contract-enforcing skills/tests. Highest-value additions are:

- `known-answer-benchmark-auditor`
- `dispatcher-dsl-contract-auditor`
- `conditional-null-methodologist`
- `prompt-contract-linter`
- `crib-constraint-solver`
- `period-width-underdetermination-auditor`
- `anti-sycophancy-reviewer`

### Proposed Agent: known-answer-benchmark-auditor

- Purpose: Own the K1/K2/K3 fitness gate and distinguish “framework can execute a remembered panel” from “framework can derive a new K4 hypothesis.”
- Why existing agents do not cover this: `statistical-auditor` can critique results, but no routed agent owns self-test readiness or blocks K4 campaigns when solved-panel recovery is stale.
- Routed phase: pre-run readiness, not every cycle.
- Model recommendation: sonnet for routine readiness; opus only for failure triage.
- Tools: Read, Bash, Grep/rg, Glob.
- Skills: `known-answer-validation`, `dispatcher-dsl-contract`, `results-protocol`.
- Output contract: one JSON object with `verdict`, `panels_passed`, `failed_panels`, `commands`, `artifacts`, `block_k4_campaign`, and `reason`.
- Falsification criteria: If K1/K2/K3 cannot be rediscovered under the documented cap, or if the command used is inconsistent with current protocol, campaign readiness fails.
- Tests required before use: `test_known_answer_skill_present`, `test_self_test_default_or_protocol_consistency`, `test_known_answer_agent_blocks_on_k3_failure`.

### Proposed Agent: dispatcher-dsl-contract-auditor

- Purpose: Ensure generated hypotheses are expressible as bounded `HypothesisSpec` objects and actually dispatch through `job_dispatcher`.
- Why existing agents do not cover this: `cryptanalyst` and `keystream-forensics` know cipher mechanics, but neither is a dedicated DSL admissibility auditor.
- Routed phase: pre-dispatch audit for high-cost or new-family theories; periodic prompt-contract audit.
- Model recommendation: sonnet.
- Tools: Read, Bash, Grep/rg.
- Skills: `dispatcher-dsl-contract`, `known-answer-validation`, `disproof-protocol`.
- Output contract: JSON object with `dsl_valid`, `dispatcher_supported`, `assumption_bundle`, `universe_hash_expected`, `budget_ok`, `null_baseline`, `blocking_errors`, and `minimal_spec`.
- Falsification criteria: Any hypothesis without a bounded spec, supported translation, budget, kill criteria, and null baseline is not campaign-ready.
- Tests required before use: `test_theorist_prompt_contract_generates_json_array`, `test_dispatcher_dsl_skill_present`, `test_generated_specs_validate`.

### Proposed Agent: anti-sycophancy-reviewer

- Purpose: Audit whether a prompt, result, or synthesis is giving the operator a satisfying story rather than a disconfirmable test.
- Why existing agents do not cover this: `red-team-disprover` attacks claims, but does not explicitly audit operator-frame validation or narrative reward loops.
- Routed phase: promotion review and physical/interpretive hypotheses; optional pre-run audit.
- Model recommendation: opus for promotion reviews; sonnet for prompt linting.
- Tools: Read, Grep/rg.
- Skills: `prompt-contract-lint`, `conditional-null-methodology`, `statistics`.
- Output contract: JSON object with `sycophancy_risk`, `operator_frame_validated`, `unsupported_story_elements`, `required_downgrades`, `forced_not_enough_statement`, and `next_disconfirming_test`.
- Falsification criteria: A claim fails if its “evidence” is thematic fit, creator-intent inference, or physical observation without a measurable cryptographic prediction.
- Tests required before use: `test_sycophancy_guardrails_present`, `test_physical_claims_not_constraints`, `test_no_breakthrough_language_without_kernel_gate`.

### Proposed Agent: agent-roster-integration-auditor

- Purpose: Continuously verify `.claude/agents`, `.claude/skills`, routing, and controller wrapper assumptions.
- Why existing agents do not cover this: `script-auditor` audits code/scripts but not prompt loadability, route drift, skill reachability, and wrapper contracts as a single surface.
- Routed phase: CI/static audit, not K4 cycles.
- Model recommendation: haiku/sonnet; most checks should be deterministic tests.
- Tools: Read, Bash, Grep/rg, Glob.
- Skills: `prompt-contract-lint`, `dispatcher-dsl-contract`.
- Output contract: JSON object with `roster_count`, `routed_missing`, `unrouted_agents`, `missing_skills`, `stale_refs`, `contract_violations`, and `fail_ci`.
- Falsification criteria: Any routed-missing agent, stale skill path, or unwrapped narrative contract fails.
- Tests required before use: all `.claude` linter tests listed in Proposed Tests.

### Proposed Skill: known-answer-validation

- Trigger: Before any K4 campaign, after any prompt/routing/dispatcher change, or when a skill claims cryptanalytic capability.
- Purpose: Make K1/K2/K3 recovery a prompt-layer requirement, not just a code harness.
- Exact procedures it should contain: run doctor, run `self_test.py --panel all --mode dry-run --cycles 20000`, inspect pass/fail by panel, record whether K3 needed extended cap, distinguish dry-run kernel recovery from real-API agent derivation.
- Repo commands it should teach: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000`; targeted K1/K2/K3 pytest files.
- Anti-overfit safeguards: note K1 may be training-data recognition; require no leakage of answer keys into K4 prompt paths.
- Agents that should use it: `cryptanalyst`, `dispatcher-dsl-contract-auditor`, `known-answer-benchmark-auditor`, `script-auditor`.
- Tests required: `test_known_answer_skill_present`, `test_self_test_default_or_protocol_consistency`.

### Proposed Skill: dispatcher-dsl-contract

- Trigger: Whenever an agent proposes, executes, or reviews a computational K4 hypothesis.
- Purpose: Teach exact DSL/dispatcher workflow rather than ad hoc scripts or narrative tests.
- Exact procedures it should contain: construct `HypothesisSpec`, validate, run admissibility, compute expected cardinality, require `assumption_bundle`, select `null_baseline`, run `execute()`, inspect `JobResult`, convert to `WorkerContract`.
- Repo commands it should teach: `PYTHONPATH=src python3 - <<'PY' ... validate_hypothesis_spec ...`; `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_job_dispatcher.py -q`.
- Anti-overfit safeguards: budget must be declared before testing; universe hash and family-wise p-value required for any positive claim.
- Agents that should use it: `cryptanalyst`, `keystream-forensics`, `stego-analyst`, `red-team-disprover`.
- Tests required: `test_dispatcher_dsl_skill_present`, `test_generated_specs_validate`, `test_agents_do_not_reference_deprecated_tools`.

### Proposed Skill: conditional-null-methodology

- Trigger: Any H1-conditional, Bean, null mask, crib-position, or admitted-theory statistical claim.
- Purpose: Prevent H1/crib-conditioned facts from becoming global K4 facts.
- Exact procedures it should contain: state conditioning assumptions, define null family, identify what is fixed/random, report whether claim is local crib-position, CT73, CT97, or post-transform.
- Repo commands it should teach: `run_controller.py --inventory`, null-baseline calibration/query commands, claim policy checks.
- Anti-overfit safeguards: every result must state “does not apply if...” and list break conditions.
- Agents that should use it: `statistical-auditor`, `stego-analyst`, `keystream-forensics`, `anti-sycophancy-reviewer`.
- Tests required: `test_conditional_null_skill_present`, `test_h1_claims_have_scope_language`.

### Proposed Skill: prompt-contract-lint

- Trigger: Any edit to `.claude/agents`, `.claude/skills`, or controller prompt wrappers.
- Purpose: Catch stale paths, retired claims, missing output contracts, and unsafe words before paid runs.
- Exact procedures it should contain: parse frontmatter, compare routing names, scan for missing files, scan for retired constants, scan for `Agent tool` examples in controller-used agents, check output-contract and anti-bias sections.
- Repo commands it should teach: a deterministic `python3` linter under `kryptosbot/tests` or `scripts/audit`.
- Anti-overfit safeguards: test failures should be deterministic, not model-reviewed.
- Agents that should use it: `agent-roster-integration-auditor`, `script-auditor`.
- Tests required: most `.claude` tests listed below.

### Proposed Skill: crib-constraint-solving

- Trigger: Any hypothesis that claims to exploit ENE/BCL, Bean constraints, crib positions, or fixed-point/self-encrypting positions.
- Purpose: Teach agents how to use the kernel crib/Bean APIs rather than recomputing or narrating constraints.
- Exact procedures it should contain: import constants, score anchored/free cribs, derive variant-specific keystreams, verify Bean with current kernel, state 0-indexed positions.
- Repo commands it should teach: small Python snippets using `kryptos.kernel.scoring.crib_score`, `kryptos.kernel.constraints.bean`, and `score_candidate`.
- Anti-overfit safeguards: explicitly distinguish direct positional CT97 from transposed/free alignment.
- Agents that should use it: `cryptanalyst`, `keystream-forensics`, `red-team-disprover`.
- Tests required: `test_crib_constraint_skill_present`, `test_no_hardcoded_crib_constants_in_skills`.

### Proposed Skill: period-width-underdetermination

- Trigger: Any period, width, route, transposition, or high crib-score result at large parameter count.
- Purpose: Prevent high-score false positives from underdetermined residue classes.
- Exact procedures it should contain: compute constraints per residue/column, compare random expected max, require matched nulls, reject high period/width scores without family-wise correction.
- Repo commands it should teach: null-baseline query commands and dispatcher family-wise p-value inspection.
- Anti-overfit safeguards: no “signal” from period/width search unless the whole search procedure is calibrated.
- Agents that should use it: `cryptanalyst`, `statistical-auditor`, `red-team-disprover`, `results-analyst`.
- Tests required: `test_period_width_skill_present`, `test_high_period_language_requires_null_expectation`.

## Deprecated or Dangerous References

- `.claude/skills/k4-stego-cracker/SKILL.md` references missing `memory/elimination_ledger.md` and `memory/confirmed_findings.md`.
- `.claude/agents/stego-analyst.md` has the same missing memory-file update instructions.
- `.claude/skills/otp-null-keystream-forensics/SKILL.md` references missing `memory/elimination_ledger.md`.
- `.claude/skills/project-onboarding/SKILL.md` says `CLAUDE.md` contains “The current working hypothesis,” but `CLAUDE.md` says it does not describe the current favorite theory.
- `.claude/settings.local.json` allows a stale command importing `CONSENSUS_NULL_POSITIONS` from `kryptos.kernel.constants`; that import now fails because the retired constant lives under `kryptos.kernel.retired`.
- Several agent descriptions tell Claude to “launch” or “use the Agent tool” even though controller sessions block Task/Agent and use sibling orchestration.
- `.claude/settings.local.json` allows broad `python3:*`, `PYTHONPATH=src python3:*`, and `sudo apt-get:*`. This may be acceptable for a local Claude Code profile, but it is a high-risk permission surface and not a K4-solving capability.

## Recommendations

### Tier 1 — Must Fix Before More K4 Campaigns

1. Add `.claude` quality tests for roster loadability, routed-name existence, stale references, retired-claim revival, and output-contract wrapper compatibility.
2. Rewrite `project-onboarding`, `results-protocol`, `disproof-protocol`, `k4-stego-cracker`, and `otp-null-keystream-forensics` to match current controller semantics and existing file paths.
3. Add a dedicated `dispatcher-dsl-contract` skill that teaches agents exact `HypothesisSpec` construction, admissibility, universe hashes, assumption bundles, and `job_dispatcher.execute()` artifacts.
4. Add a `known-answer-validation` skill and make campaign readiness require `self_test.py --panel all --mode dry-run --cycles 20000` or a documented equivalent.
5. Remove or quarantine compact null-palette/consensus-null references from live prompts unless every mention is policy-gated as retired/conditional.
6. Decide whether `script-auditor` is manual-only or route it into controller phases before any high-risk harness/script campaign.
7. Remove “use Agent tool / launch agent” examples from agents used by the controller, or explicitly mark them manual-Claude-only.

### Tier 2 — Should Fix Soon

1. Collapse unreferenced basic cipher skills into a smaller set of dispatcher-backed operational skills.
2. Add agent prompt linting for words like “breakthrough,” “promising,” “signal,” “evidence,” and “explains” unless paired with kernel/statistical criteria.
3. Add null-baseline command examples to `statistics` and `statistical-auditor`.
4. Add K1/K2/K3 known-answer examples to Quagmire and columnar skills.
5. Mark `forensic-photo-analyst` and `kryptos-corpus-forensics` as manual-only unless routed.
6. Tighten `escape-room-cryptanalyst` so every physical hypothesis must produce a measurable artifact, a falsification criterion, and a non-cryptographic alternative.

### Tier 3 — Nice to Have

1. Add short per-agent “what I may not claim” checklists.
2. Add agent-specific crib sheets for supported DSL families.
3. Add report templates for rejected theories, not just positive findings.
4. Add line-linked references from `.claude` docs to current controller invariants.

## Proposed Tests

| Test | Purpose | Files inspected | Failure condition | Why it matters for K4 |
|---|---|---|---|---|
| `test_pantheon_all_agents_parse` | Ensure all intended agents load | `.claude/agents/*.md`, `pantheon.py` | Loadable agent parse failure or duplicate name | Prevents silent roster loss |
| `test_routing_references_existing_agents` | Ensure routing names exist | `routing.py`, roster | Any routed name missing | Avoids generic fallback campaigns |
| `test_present_unrouted_agents_are_marked_manual` | Avoid accidental dead agents | `.claude/agents/*.md`, `routing.py` | Loadable but unrouted agent lacks manual-only marker | Prevents false sense of coverage |
| `test_agent_frontmatter_skill_refs_exist` | Validate skill references | agent frontmatter, `.claude/skills/*` | Missing skill dir | Prevents stale skill mentions |
| `test_agent_skill_refs_not_assumed_enforced` | Document current integration | controller, pantheon | Report or docs say frontmatter skills are enforced | Prevents false runtime assumptions |
| `test_all_routed_agents_have_phase_wrapper_contract` | Verify JSON overrides | `pantheon.py`, agents | Routed phase lacks wrapper | Prevents narrative output parse failures |
| `test_agents_do_not_reference_missing_project_files` | Catch stale paths | `.claude/agents`, `.claude/skills` | Mentioned repo path missing | Prevents agent dead ends |
| `test_no_agent_promotes_retired_claims` | Guard retired null palette | `.claude/**/*` | Retired construct appears without retired/policy wording | Prevents claim revival |
| `test_no_agent_uses_breakthrough_without_kernel_verification` | Enforce alert semantics | `.claude/**/*` | “breakthrough” without Bean/kernel/p-value language | Prevents overclaiming |
| `test_results_protocol_status_vocab_matches_controller` | Align status semantics | `results-protocol`, `models.py` | Uses stale status meanings | Prevents SUCCESS/PROMISING drift |
| `test_known_answer_skill_present` | Make K1/K2/K3 a prompt-layer gate | `.claude/skills` | No known-answer validation skill | Prevents K4 runs without fitness check |
| `test_conditional_null_skill_present` | Make H1/null scoping explicit | `.claude/skills` | No conditional-null methodology | Prevents H1-to-global leakage |
| `test_sycophancy_guardrails_present` | Force “not enough” language | routed agents | No anti-sycophancy/falsification section | Prevents satisfying stories |
| `test_settings_local_no_retired_constant_imports` | Catch stale local permissions | `.claude/settings.local.json` | Allows `CONSENSUS_NULL_POSITIONS` import from constants | Prevents retired claim reactivation |
| `test_self_test_default_or_protocol_consistency` | Avoid misleading K3 readiness | `self_test.py`, run protocol docs | Default all-panel command fails but docs call it readiness | Prevents false pass/fail gate |

## Final Sufficiency Judgment

Verdict: **PARTIAL**.

## Why

The suite is operationally credible in the narrow sense that routed agents load and controller wrappers enforce machine-readable outputs. The code layer is much stronger than the prompt layer: contract validation, kernel overrule, DSL dispatcher, null baselines, routing tests, and known-answer harnesses are real.

The `.claude` layer itself is not enough. Most skills are broad guides or unreferenced cipher notes. The agents are often narrative specialists wrapped into JSON by controller code, not native producers of `HypothesisSpec`/`WorkerContract` artifacts. The prompt layer does not force K1/K2/K3 readiness before K4 search.

## What the suite can plausibly do

- Generate diverse K4 hypotheses across cryptanalytic, stego, keystream, archive, and physical frames.
- Reject some bad hypotheses through deterministic critic plus red-team/stat-audit siblings.
- Protect against worker score hallucination through controller/kernel verification.
- Improve epistemic hygiene when the correct wrapper path is used.

## What the suite cannot currently do

- Prove it can derive solved panels through the same agent/skill path used for K4.
- Reliably translate agent ideas into bounded, dispatcher-compatible DSL specs without extra controller or human scaffolding.
- Prevent physical/narrative agents from producing plausible but untestable frames.
- Guarantee that skills used by an agent are the ones declared in its frontmatter.
- Keep all live prompt surfaces free of stale paths, stale status semantics, and retired/conditional claim leakage.

## Highest-risk illusion of capability

The biggest illusion is that a large skill catalog equals operational cryptanalytic coverage. It does not. Thirty-one of thirty-nine skills are unreferenced by agent frontmatter, the controller does not enforce frontmatter skills anyway, and many cipher-family skills do not teach the dispatcher/DSL/null-baseline workflow that actually protects K4 runs from self-deception.

## Minimum changes before calling this K4-solve-capable

1. Prompt/skill linter tests green.
2. Dedicated known-answer validation skill present and used in campaign readiness.
3. Dispatcher/DSL contract skill present and referenced by theorist/worker agents.
4. Stale/missing file references removed.
5. Retired/conditional null material scrubbed or policy-gated in every live prompt.
6. `escape-room`/physical hypotheses forced through measurable preregistered tests.
7. `script-auditor` routed or explicitly manual-only.
8. K3 readiness command aligned with the documented 20K-cycle cap.

## Appendix A — Raw Agent Inventory

| File | Loadable | Name | Model | Skills | Body chars | Output contract | Falsification | Anti-bias | Canonical scoring/dispatcher/kernel | K1/K2/K3/self-test |
|---|---:|---|---|---|---:|---:|---:|---:|---:|---:|
| `.claude/agents/AGENT_TEMPLATE.md` | no | `AGENT_NAME` | opus | project-onboarding, results-protocol | 2507 | yes | yes | yes | yes | no |
| `.claude/agents/MIGRATION.md` | no |  |  |  | 5120 | no | no | yes | no | no |
| `.claude/agents/PANTHEON.md` | no |  |  |  | 13846 | no | yes | yes | no | no |
| `.claude/agents/USAGE.md` | no |  |  |  | 6375 | no | no | no | no | no |
| `.claude/agents/archivist-historian.md` | yes | archivist-historian | opus | project-onboarding, results-protocol | 8218 | yes | weak | yes | no | yes |
| `.claude/agents/cipher-discovery-builder.md` | yes | cipher-discovery-builder | opus | none | 12950 | no | weak | yes | yes | no |
| `.claude/agents/cryptanalyst.md` | yes | cryptanalyst | opus | project-onboarding, script-discovery, results-protocol, disproof-protocol | 5281 | yes | yes | yes | yes | no |
| `.claude/agents/escape-room-cryptanalyst.md` | yes | escape-room-cryptanalyst | opus | none | 10494 | no | yes | yes | no | no |
| `.claude/agents/forensic-photo-analyst.md` | yes | forensic-photo-analyst | opus | forensic-photo-analysis, project-onboarding | 9008 | no | weak | yes | yes | yes |
| `.claude/agents/keystream-forensics.md` | yes | keystream-forensics | opus | otp-null-keystream-forensics, project-onboarding, statistics, disproof-protocol, results-protocol | 7929 | yes | yes | yes | yes | no |
| `.claude/agents/kryptos-corpus-forensics.md` | yes | kryptos-corpus-forensics | opus | none | 10500 | yes | weak | yes | no | yes |
| `.claude/agents/red-team-disprover.md` | yes | red-team-disprover | opus | project-onboarding, disproof-protocol, statistics, script-discovery, results-protocol | 7279 | yes | weak | yes | yes | no |
| `.claude/agents/research-chancellor.md` | yes | research-chancellor | opus | project-onboarding, results-protocol, statistics | 8031 | yes | weak | yes | no | no |
| `.claude/agents/results-analyst.md` | yes | results-analyst | sonnet | project-onboarding, results-protocol | 4529 | yes | yes | yes | no | no |
| `.claude/agents/script-auditor.md` | yes | script-auditor | opus | project-onboarding, script-discovery | 5129 | yes | weak | yes | yes | no |
| `.claude/agents/statistical-auditor.md` | yes | statistical-auditor | opus | none | 17328 | yes | weak | yes | no | no |
| `.claude/agents/stego-analyst.md` | yes | stego-analyst | opus | k4-stego-cracker, project-onboarding, statistics, disproof-protocol, results-protocol | 9364 | yes | yes | yes | yes | no |

## Appendix B — Raw Skill Inventory

Referenced skills: `disproof-protocol`, `forensic-photo-analysis`, `k4-stego-cracker`, `otp-null-keystream-forensics`, `project-onboarding`, `results-protocol`, `script-discovery`, `statistics`.

Unreferenced skills: `cipher-affine`, `cipher-atbash`, `cipher-autokey-beaufort`, `cipher-autokey-vigenere`, `cipher-beaufort`, `cipher-bifid`, `cipher-caesar`, `cipher-columnar`, `cipher-ct-autokey-beaufort`, `cipher-ct-autokey-vigenere`, `cipher-double-columnar`, `cipher-four-square`, `cipher-gromark`, `cipher-gronsfeld`, `cipher-identification`, `cipher-myszkowski`, `cipher-nihilist`, `cipher-porta`, `cipher-quagmire-ii`, `cipher-quagmire-ii-autokey`, `cipher-rail-fence`, `cipher-rot13`, `cipher-route`, `cipher-running-key-beaufort`, `cipher-running-key-vigenere`, `cipher-serpentine`, `cipher-spiral`, `cipher-variant-beaufort`, `cipher-vigenere`, `sweep-kryptos-photo-corpus`, `sympy-proof-writer`.

High-risk skills: `project-onboarding`, `results-protocol`, `k4-stego-cracker`, `otp-null-keystream-forensics`, `cipher-beaufort`, `cipher-running-key-beaufort`.

## Appendix C — Routing Comparison

Theorist rotation:

```text
cryptanalyst
escape-room-cryptanalyst
stego-analyst
archivist-historian
keystream-forensics
cipher-discovery-builder
```

Worker routing targets:

```text
archivist-historian
cryptanalyst
escape-room-cryptanalyst
keystream-forensics
stego-analyst
```

Audit/synthesis/pursuit targets:

```text
red-team-disprover
statistical-auditor
results-analyst
research-chancellor
```

Unrouted loadable agents:

```text
forensic-photo-analyst
kryptos-corpus-forensics
script-auditor
```

## Appendix D — Evidence Quotes

- Controller confirms sibling discipline and skill loading: `setting_sources=["project"]` makes `.claude/skills/` available, and Task/Agent is disabled so orchestration happens at Python-controller level (`kryptosbot/controller.py:1885` to `kryptosbot/controller.py:1891`).
- Theorist prompt wrapper exists because native agent contracts conflict with JSON-array generation; prior failure mode was “16-minute, 75-turn sessions with 0 JSON output” (`kryptosbot/controller.py:1951` to `kryptosbot/controller.py:1959`).
- Provenance guardrail is prepended to loaded agent bodies and blocks retired null-palette revival (`kryptosbot/pantheon.py:653` to `kryptosbot/pantheon.py:664`).
- Self-test harness says failure to rediscover K1/K2/K3 means the framework cannot solve K4 (`kryptosbot/self_test.py:3` to `kryptosbot/self_test.py:8`).
- Project onboarding says `CLAUDE.md` contains “The current working hypothesis,” conflicting with `CLAUDE.md` doctrine (`.claude/skills/project-onboarding/SKILL.md:18` to `.claude/skills/project-onboarding/SKILL.md:24`).
- Stego skill references missing `memory/elimination_ledger.md` and `memory/confirmed_findings.md` (`.claude/skills/k4-stego-cracker/SKILL.md:98` to `.claude/skills/k4-stego-cracker/SKILL.md:104`, `.claude/skills/k4-stego-cracker/SKILL.md:274` to `.claude/skills/k4-stego-cracker/SKILL.md:279`).
- Results protocol still uses stale `PROMISING`/“Hot Leads” language (`.claude/skills/results-protocol/SKILL.md:23` to `.claude/skills/results-protocol/SKILL.md:30`, `.claude/skills/results-protocol/SKILL.md:42` to `.claude/skills/results-protocol/SKILL.md:48`).
- Escape-room prompt encodes strong physical/narrative priors and states “Never default to mathematical analysis first” (`.claude/agents/escape-room-cryptanalyst.md:106` to `.claude/agents/escape-room-cryptanalyst.md:137`).
- `settings.local.json` allows stale import of `CONSENSUS_NULL_POSITIONS` from `kryptos.kernel.constants`, which now fails (`.claude/settings.local.json:20` to `.claude/settings.local.json:25`).
