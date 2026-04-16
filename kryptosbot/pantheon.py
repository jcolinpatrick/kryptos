"""
Pantheon agent loader for kryptosbot.

Reads .claude/agents/*.md files, parses their YAML frontmatter without a
yaml dependency, and returns structured AgentSpec records the controller
can use to configure Claude Agent SDK sessions.

The .claude/agents/ directory holds the project's specialized research
agents (the Pantheon). Each agent is a markdown file with YAML frontmatter
declaring name, description, model, tools, skills, etc., followed by a
markdown body that serves as the agent's system prompt.

This module provides:
  - AgentSpec: a dataclass wrapping a loaded agent's metadata and body
  - load_agent(name): read a single agent by name
  - load_roster(): discover and load all Pantheon agents at once
  - strip_frontmatter(text): utility for body-only extraction

Design notes:
  - No PyYAML dependency. The frontmatter parser is purpose-built for the
    exact shapes used in .claude/agents/ files. If a new agent uses YAML
    constructs this parser doesn't handle, it will raise a clear error
    rather than silently mis-parse.
  - The parser handles: scalar key:value, '>' folded block scalars,
    '"..."' quoted strings with backslash escapes, '[a, b]' inline lists,
    and '- item' block lists.
  - PANTHEON.md, AGENT_TEMPLATE.md, USAGE.md, MIGRATION.md and any other
    non-agent markdown in .claude/agents/ are automatically skipped
    (they lack the 'name:' frontmatter field).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("kryptosbot.pantheon")


# Default location relative to the project root. Override for tests.
DEFAULT_AGENTS_DIR = Path(".claude/agents")


# ---------------------------------------------------------------------------
# Theorist-mode prompt wrapper
# ---------------------------------------------------------------------------
# These constants wrap an agent body when we call the agent in theorist
# generation mode (vs its native audit mode). See AgentSpec.theorist_system_prompt
# for the rationale. The wrapper sandwiches the persona body with explicit
# override directives at both ends — Opus pays the most attention to the
# beginning and end of its system prompt, so the override is most durable
# there.

_THEORIST_MODE_PREFACE = """\
# ===== OPERATIONAL MODE: THEORIST GENERATION =====
#
# You are {agent_name}, a KryptosBot research operator, running in
# THEORIST GENERATION MODE for a single research cycle.
#
# Your task: generate a JSON array of novel, testable K4 hypotheses
# shaped by your agent priors (Identity, Stats, Bias/Anti-bias,
# Analytical Procedure, Rivals) which follow below.
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
# Your persona definition below contains an "Output Contract" section
# that prescribes narrative structured output with headings like
# Observations / Interpretation / Prior / Evidence For / Evidence
# Against / Falsification / Confidence / Next Test. That contract is
# correct when you are running as an audit operator. It DOES NOT
# APPLY to this call. For this specific invocation:
#
#   • Your final output MUST be ONE JSON array of hypothesis objects.
#   • Do NOT emit any of the narrative sections from your Output Contract.
#   • Do NOT emit prose before or after the JSON array.
#   • Do NOT wrap the JSON in markdown code fences (no ```json).
#   • The user prompt below the persona will specify the exact JSON
#     schema — follow it literally.
#
# TOOL USE GUIDANCE:
# You may use Read / Bash / Grep / Glob to briefly consult existing
# infrastructure (exhaustion_log.json, scripts/, memory/, docs/) if
# your persona's Tool Discipline stat or Analytical Procedure says you
# should. Keep investigation short — the goal is hypothesis generation,
# not a full pre-flight audit. Aim for under 5 tool calls before you
# emit the JSON. If you have not emitted the JSON array by 10 tool
# calls, stop investigating and emit based on what you know.
#
# HOW TO USE YOUR PRIORS:
# Use your Identity, Stats, Bias/Anti-bias, Analytical Procedure, and
# Rivals to shape:
#   - WHICH hypotheses you generate (your domain bias)
#   - HOW you frame them (your preferred vocabulary and methodology)
#   - WHAT you would never propose (your anti-bias and rival agents)
#
# Do NOT use these sections to dictate your output format. The output
# format for this call is a JSON array. Period.
#
# ===== AGENT PERSONA (priors — use for reasoning, not output format) ====="""


_THEORIST_MODE_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your output for this call is ONE JSON array of
# hypothesis objects. Nothing before it, nothing after it, no markdown
# fences, no narrative sections from your Output Contract. The user
# prompt specifies the exact schema — follow it literally.
# ==================================================================="""


# Red-team pre-check mode wrapper.
#
# This is for the controller's pre-dispatch adversarial check, NOT a full
# signal-level audit. The controller calls red-team-disprover (or another
# Judge agent) with a single proposed theory and gets back a structured
# JSON verdict deciding whether to dispatch the theory or reject it.
#
# Why we don't use system_prompt() for this: red-team-disprover's audit-mode
# Output Contract prescribes a multi-section narrative response. That's
# correct for promoting findings or auditing signal claims, but it's
# overkill for a proposal-time gate where we just need verdict + brief
# reasons + confidence. The wrapper preserves the agent's adversarial
# priors (bias toward finding noise, methodology) while constraining the
# output to a quick structured verdict.

_REDTEAM_PRECHECK_PREFACE = """\
# ===== OPERATIONAL MODE: PROPOSAL-TIME RED-TEAM PRE-CHECK =====
#
# You are {agent_name}, running in PROPOSAL-TIME PRE-CHECK MODE for the
# KryptosBot research controller.
#
# Your task: a deterministic critic has approved a candidate theory.
# Before the controller commits compute to dispatching a worker for
# this theory, your job is to apply your adversarial priors and decide
# whether the theory is worth testing. You are the last gate before
# expensive compute.
#
# This is NOT a signal-level audit. You are not reviewing a finding
# that scored ≥18. You are not promoting a result to canonical memory.
# You are pre-screening a proposal that has not yet been tested.
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
# Your persona definition below contains an "Output Contract" section
# that prescribes a multi-section narrative response. That contract
# applies to full audit-mode calls. It DOES NOT apply to this call.
# For this specific invocation:
#
#   • Your final output MUST be ONE JSON object.
#   • The JSON object MUST have exactly these five fields:
#       "verdict"           : (string) one of "pass", "concerned", "reject"
#       "confidence"        : (float)  in [0.0, 1.0]
#       "reasons"           : (array of strings) 1-4 short reasons
#       "next_test"         : (string) one sentence — what the strongest
#                             falsification would look like, or empty
#                             string if no specific test comes to mind
#       "search_space_risk" : (string) one of the seven taxonomy values
#                             below. "none" for any PASS verdict. For
#                             CONCERNED and REJECT, pick the MOST
#                             specific category that describes your
#                             primary objection.
#   • Do NOT emit any narrative sections, prose, or markdown fences
#     before or after the JSON object.
#
# VERDICT SEMANTICS:
#   "pass"      — the theory is worth dispatching. Your adversarial
#                 priors do NOT predict it will be noise. Compute will
#                 be spent on a hypothesis with a fair chance of
#                 producing a meaningful result. Emit
#                 search_space_risk="none".
#   "concerned" — the theory has structural issues but is not
#                 obviously dead. Dispatch is allowed, but the
#                 reasons array should explain what to watch for.
#                 Pick the search_space_risk value that best describes
#                 the specific concern.
#   "reject"    — the theory will produce noise with high confidence.
#                 Examples: symmetric hypotheses without a stated
#                 budget; mechanisms already eliminated by an existing
#                 family/anomaly; unfalsifiable claims; restating
#                 known hypotheses in new vocabulary; constructions
#                 ruled out by Bean constraints. Pick the
#                 search_space_risk value that best describes the
#                 reason for rejection.
#
# SEARCH_SPACE_RISK TAXONOMY (seven values — pick exactly one):
#   "none" — no search-space concern. Required for every PASS verdict.
#       May also apply to a CONCERNED verdict when the concern is
#       entirely unrelated to the size or coverage of the search space
#       (but in that case consider "residual_caution" first).
#
#   "unbounded_search" — the proposed test has an unconstrained or
#       quasi-continuous parameter space with NO stated budget. Use
#       ONLY when the proposer has not stated when to stop. Examples:
#       "sweep all offsets", "enumerate rotations until something
#       matches", "explore the space", "free parameter with no bound".
#       Do NOT use this for "exhausted source" or "looks like a
#       duplicate" — those have their own buckets.
#
#   "exhausted_source_material" — the theory mines a source (a
#       specific anomaly, misspelling, coordinate, crib region) that
#       has ALREADY been exhausted by prior scripts with zero signal.
#       The search CAN be bounded, it's just pointless because the
#       space has been swept. Examples: "DESPARATLY misspelling
#       already mined", "e_recurrence_00_linear_order2 EXHAUSTED".
#
#   "underconstrained" — the kill criterion is too loose. The proposer
#       could always claim more search is needed, or "a pattern was
#       found" without a preregistered threshold. This is about the
#       FALSIFICATION condition, not the parameter space size.
#       Examples: "kill criterion is effectively vacuous", "score>15
#       with no Bonferroni correction".
#
#   "duplicate_family" — the theory RESTATES a known-dead cipher
#       family in new vocabulary. The mechanism has been structurally
#       eliminated; re-running under a new name would produce the same
#       result. Examples: "structurally Vigenère with mixed CT
#       alphabet", "guild cipher ring stepping = variable-period
#       polyalphabetic rebranded", "Gronsfeld algebraically eliminated".
#
#   "residual_caution" — CONCERNED verdict where you explicitly
#       checked for a structural problem (duplicate, exhausted,
#       unbounded, loose kill) and found none, but want the check
#       noted in the audit trail. You think it should dispatch; you
#       just want the record to show the diligence. Empirically the
#       most common CONCERNED flavor. Does NOT trigger any prompt
#       injection. Diagnostic only.
#
#   "other" — escape hatch. A concern that doesn't fit the six
#       specific categories above. Should be rare. If you find
#       yourself reaching for "other", first try to fit the concern
#       into one of the six named buckets.
#
# BUDGET FOR YOUR REASONING:
# Be brief. The controller is making a binary dispatch decision, not
# requesting a publication review. Aim for under 5 turns of internal
# reasoning before emitting the JSON. You may use Read/Bash/Grep/Glob
# briefly if your persona's methodology demands it (e.g. checking
# exhaustion_log.json for prior tests of this exact mechanism), but
# keep tool use under 3 calls.
#
# HOW TO USE YOUR PRIORS:
# Use your Identity, Stats, Bias/Anti-bias, and Analytical Procedure
# to shape WHICH objections you raise. The red-team-disprover
# specifically should look for: symmetric failure modes, post-hoc
# explanations, mechanisms that fit any data, ignored prior work,
# unstated budgets on enumeration searches, vague kill criteria,
# attractive numerology without mechanism.
#
# ===== AGENT PERSONA (priors — use for reasoning, not output format) ====="""


_REDTEAM_PRECHECK_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your output for this call is ONE JSON object with
# exactly the FIVE fields specified above:
#   verdict, confidence, reasons, next_test, search_space_risk
# No prose. No narrative sections. No markdown fences. Be brief and
# decisive. The search_space_risk taxonomy has seven possible values —
# pick exactly one per the semantics defined in the preface.
# ==================================================================="""


# ---------------------------------------------------------------------------
# Day 5: Statistical-auditor post-execution review wrapper
# ---------------------------------------------------------------------------
#
# Used after a worker returns a contract with crib_score >= SIGNAL_THRESHOLD
# (18). The statistical-auditor reviews the methodology that produced the
# claimed signal and decides whether to confirm, flag, or reject it. This is
# the post-execution mirror of the proposal-time red-team pre-check: same
# adversarial sibling-call pattern, opposite end of the cycle.
#
# Why this wrapper exists: statistical-auditor's audit-mode Output Contract
# prescribes a multi-section narrative (Observations / Interpretation /
# Prior / Evidence For / Evidence Against / Falsification / Confidence /
# Next Test). That format is correct for promoting findings to canonical
# memory, but it's wasteful for a per-cycle gate where the controller just
# needs a verdict + methodology concerns + recommended action. The wrapper
# preserves the audit priors (multiple-testing burden, null model design,
# look-elsewhere effects, post-hoc threshold setting) while constraining
# output to a structured JSON verdict the controller can absorb.

_STAT_AUDIT_PREFACE = """\
# ===== OPERATIONAL MODE: POST-EXECUTION SIGNAL AUDIT =====
#
# You are {agent_name}, running in POST-EXECUTION SIGNAL AUDIT MODE for
# the KryptosBot research controller.
#
# Your task: a worker has returned a result with a kernel-verified
# crib_score at or above the SIGNAL threshold (18). Before this result
# is allowed to fire a contradiction-detector alert, update the family
# best_score, or propagate into the next cycle's landscape, your job is
# to apply your statistical-rigor priors and decide whether the signal
# is credible or whether it is noise dressed as signal.
#
# Key fact you should rely on: the contract you receive has had its
# crib_score, bean_passed, and score fields independently recomputed
# from best_plaintext against the kernel (see contracts._verify_against_kernel
# added 2026-04-13). Worker self-reports for those fields are NOT
# trustworthy — only the kernel-verified values are, and they are the
# values shown to you in the contract. If `fields_overwritten` is True,
# the worker's original self-report is preserved in `worker_self_report`
# for your audit, and the disagreement itself is diagnostic.
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
# Your persona definition below contains an "Output Contract" section
# that prescribes a multi-section narrative response. That contract
# applies to canonical-memory promotion calls. It DOES NOT apply to
# this call. For this specific invocation:
#
#   • Your final output MUST be ONE JSON object.
#   • The JSON object MUST have exactly these four fields:
#       "verdict"              : (string) one of "confirmed", "concerned", "rejected"
#       "confidence"           : (float)  in [0.0, 1.0]
#       "methodology_concerns" : (array of strings) 1-4 short concerns; empty if none
#       "recommended_action"   : (string) one sentence — what the controller
#                                should do with this result, or empty string
#   • Do NOT emit any narrative sections, prose, or markdown fences
#     before or after the JSON object.
#
# VERDICT SEMANTICS:
#   "confirmed" — the signal survives statistical scrutiny. Multiple-testing
#                 burden has been considered; the null model is well-defined;
#                 the result is not an artifact of search breadth or post-hoc
#                 threshold setting. The controller should propagate the
#                 finding and allow alerts to fire.
#   "concerned" — the signal is real-looking but has methodology concerns
#                 the controller should know about. Allow alerts to fire
#                 but record the concerns. Examples: untested null
#                 assumption, non-independent test multiplicity, post-hoc
#                 cherry-picked statistic.
#   "rejected"  — the signal is methodologically unsound. Suppress the
#                 alert. Record the rejection reasons on the contract for
#                 audit. Examples: worker fabricated the score (should
#                 have been caught upstream but verify); kernel-verified
#                 score appears valid but was produced by an enumeration
#                 with no stated stopping rule; the result requires the
#                 elimination ledger to be wrong without explaining how.
#
# BUDGET FOR YOUR REASONING:
# Be brief. The controller is making a binary alert-gate decision, not
# requesting a publication review. Aim for under 5 turns of internal
# reasoning before emitting the JSON. You may use Read/Bash/Grep/Glob
# briefly if your methodology requires it (e.g. checking exhaustion_log.json
# for whether this exact mechanism was already eliminated, or re-running
# `verify_bean_simple` on the worker's keystream), but keep tool use
# under 3 calls.
#
# HOW TO USE YOUR PRIORS:
# Use your Identity, Stats, Bias/Anti-bias, and Analytical Procedure to
# shape WHICH concerns you raise. The statistical-auditor specifically
# should look for: multiple-testing without correction, null models that
# don't match the search procedure, post-hoc threshold setting, look-
# elsewhere effects, claimed effect sizes that conflict with prior
# eliminations, contracts where `fields_overwritten` is True (the worker
# tried to inflate something).
#
# ===== AGENT PERSONA (priors — use for reasoning, not output format) ====="""


_STAT_AUDIT_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your output for this call is ONE JSON object with
# exactly the four fields specified above (verdict, confidence,
# methodology_concerns, recommended_action). No prose. No narrative
# sections. No markdown fences. Be brief and decisive.
# ==================================================================="""


# ---------------------------------------------------------------------------
# Day 5: Cycle synthesis wrapper
# ---------------------------------------------------------------------------
#
# Used at end-of-cycle, after _absorb_outcomes / _run_alerts / persist.
# The results-analyst takes the cycle's outcomes (worker contracts,
# red-team verdicts, stat-audit verdicts, alerts that fired) and produces
# a structured per-cycle synthesis that feeds the next cycle's landscape
# brief as enriched context.
#
# Why this wrapper exists: results-analyst's audit-mode Output Contract
# prescribes a multi-section narrative. For end-of-cycle synthesis the
# controller needs a structured object it can persist to the ledger and
# render in the next cycle's landscape — a free-text essay would not be
# usable as input to the theorist.

_SYNTHESIS_PREFACE = """\
# ===== OPERATIONAL MODE: END-OF-CYCLE RESULTS SYNTHESIS =====
#
# You are {agent_name}, running in CYCLE-SYNTHESIS MODE for the
# KryptosBot research controller.
#
# Your task: a research cycle just completed. Read the cycle's outcomes
# (worker contracts with kernel-verified scores, red-team pre-check
# verdicts, statistical-auditor post-execution verdicts, any
# contradiction-detector alerts that fired) and produce a structured
# synthesis that the next cycle's theorist will use as context.
#
# This is NOT a publication summary, a memory-promotion proposal, or a
# narrative essay. It is a structured handoff. The controller will
# persist your output and render it in the next cycle's landscape brief.
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
# Your persona definition below contains an "Output Contract" section
# that prescribes a multi-section narrative response. That contract
# applies to publication-style synthesis calls. It DOES NOT apply to
# this call. For this specific invocation:
#
#   • Your final output MUST be ONE JSON object.
#   • The JSON object MUST have exactly these seven fields:
#       "headline"              : (string) one sentence — the most
#                                  important fact about this cycle
#       "family_movements"      : (array of strings) zero or more short
#                                  notes about which families gained or
#                                  lost evidence this cycle
#       "evidence_added"        : (array of strings) zero or more short
#                                  notes about new evidence the next
#                                  cycle should know about
#       "recommended_next_focus": (string) one sentence — what the next
#                                  cycle's theorist should bias toward,
#                                  or empty string if no bias
#       "dispatched_count"      : (integer) how many theories were
#                                  dispatched this cycle
#       "disproved_count"       : (integer) how many were disproved
#       "signal_count"          : (integer) how many returned at or
#                                  above the SIGNAL threshold (18)
#   • Do NOT emit any narrative sections, prose, or markdown fences
#     before or after the JSON object.
#
# BUDGET FOR YOUR REASONING:
# Be brief. The controller is persisting your synthesis for later use,
# not asking for a deep retrospective. Aim for under 4 turns of internal
# reasoning before emitting the JSON. Tool use is allowed but rarely
# needed — the cycle's outcomes are in the user prompt.
#
# HOW TO USE YOUR PRIORS:
# Use your Identity, Stats, Bias/Anti-bias, and Analytical Procedure to
# shape WHAT YOU CONSIDER IMPORTANT. The results-analyst specifically
# should look for: cross-cycle echoes (same mechanism tested twice),
# unexpected family movement (a "dead" family producing a result),
# concentration of red-team rejections in one family (the family is
# becoming exhausted), and statistical-auditor concerns that recur.
#
# ===== AGENT PERSONA (priors — use for reasoning, not output format) ====="""


_SYNTHESIS_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your output for this call is ONE JSON object with
# exactly the seven fields specified above (headline, family_movements,
# evidence_added, recommended_next_focus, dispatched_count,
# disproved_count, signal_count). No prose. No narrative sections.
# No markdown fences. Be brief.
# ==================================================================="""


# Day 6: lead-pursuit evaluator mode wrapper.
#
# This is for the post-absorb pursuit evaluation phase — the controller
# has a single sub-signal contract (6-17 crib_score) and wants a yes/no
# on whether to open a pursuit lead in the ledger. Output must be a
# structured JSON verdict, not narrative.
#
# Shape mirrors _STAT_AUDIT_PREFACE but narrower: one contract in, one
# verdict out. Default agent: results-analyst.

_PURSUIT_PREFACE = """\
# ===== OPERATIONAL MODE: LEAD-PURSUIT EVALUATION =====
#
# You are {agent_name}, running in LEAD-PURSUIT-EVALUATOR MODE for the
# KryptosBot research controller.
#
# Your task: one worker contract has returned in the "interesting but
# sub-signal" band (6 <= crib_score <= 17). Decide whether this result
# is worth opening a structured pursuit lead so the next theorist cycle
# considers it as priority context. Your output drives a single
# ledger write (or no-op).
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
#   • Your final output MUST be ONE JSON object.
#   • The JSON object MUST have exactly these four fields:
#       "verdict"            : (string) "pursue" or "skip"
#       "confidence"         : (float 0.0-1.0)
#       "rationale"          : (string) one to three sentences explaining
#                              the verdict in terms the next theorist can
#                              use as context
#       "suggested_variants" : (array of strings) at most 3 short
#                              variant directions (each <=80 chars).
#                              Each must be a specific narrowing of a
#                              parameter axis, NOT "explore more".
#   • Do NOT emit any narrative sections, prose, or markdown fences
#     before or after the JSON object.
#
# BUDGET FOR YOUR REASONING:
# Be strict. Rotation slots are scarce. If the score is explainable as
# noise given the search size, SKIP. If the variant axis is unbounded
# (would trip the bounded-search policy next cycle), SKIP. If the
# mechanism overlaps a known-eliminated family, SKIP. Aim for under 5
# turns of internal reasoning. Tool use allowed but rarely needed —
# the contract is in the user prompt.
#
# HOW TO USE YOUR PRIORS:
# Use your persona's Identity, Stats, Bias/Anti-bias, and Analytical
# Procedure to shape what counts as "worth pursuing." The results-analyst
# specifically should look for: specific parameter axes where a small
# narrowing could flip the verdict, worker narratives that name a
# concrete next step, crib-position patterns that suggest a mechanism
# rather than random hits.
#
# ===== AGENT PERSONA (priors — use for reasoning, not output format) ====="""


_PURSUIT_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your output for this call is ONE JSON object with
# exactly the four fields specified above (verdict, confidence,
# rationale, suggested_variants). No prose. No markdown fences.
# Be strict — rotation slots are scarce.
# ==================================================================="""


# Worker execution mode wrapper.
#
# This is for the controller's dispatch phase — the worker receives a
# specific hypothesis, executes the test, and reports a WorkerContract
# result. Unlike theorist/redteam/audit modes, the worker's output is
# a FENCED ```json code block, not a raw JSON object, because
# `validate_worker_contract` specifically requires a fenced block.
#
# Why the wrapper exists: same root cause as theorist mode. Every
# Pantheon agent's .md body declares an Output Contract section with
# the narrative spine (Observations / Interpretation / Prior / etc.),
# which is correct for audit-mode calls but WRONG for worker execution
# mode. Day 2's cycle 36 worker 2165214e ran 21 minutes and 166 turns
# with a generic system prompt before emitting output without a ```json
# fence — failed validation. That was a generic worker. With the
# persona-loaded wrapper, cryptanalyst's body brings in the
# `results-protocol` and `disproof-protocol` skills (via
# setting_sources=["project"]), and the wrapper's explicit directive
# reinforces the fence contract.

_WORKER_MODE_PREFACE = """\
# ===== OPERATIONAL MODE: WORKER EXECUTION =====
#
# You are {agent_name}, running in WORKER EXECUTION MODE for a single
# K4 hypothesis test dispatched by the KryptosBot research controller.
#
# Your task: execute the test described in the user prompt, evaluate
# the result against the kill criteria, and report a structured
# WorkerContract JSON result. This is a ONE-SHOT test, not an audit,
# investigation, or signal-level review.
#
# OUTPUT FORMAT OVERRIDE (non-negotiable for this call):
# Your persona definition below contains an "Output Contract" section
# that prescribes a multi-section narrative response (Observations,
# Interpretation, Prior, Evidence For, Evidence Against, Falsification,
# Confidence, Next Test). That contract is correct for audit-mode
# calls. It DOES NOT APPLY to this call. For this specific invocation:
#
#   • Your final response MUST end with ONE fenced JSON code block
#     containing a WorkerContract object matching the schema in the
#     user prompt.
#   • The fence MUST start with the literal characters ```json on its
#     own line, followed by the JSON object, followed by ``` on its
#     own line.
#   • You MAY emit intermediate prose while reasoning — that is
#     expected and useful for worker debugging. The ```json block
#     goes at the END of your response.
#   • Do NOT emit any of the narrative sections from your persona's
#     Output Contract. Those sections are for audit calls, not worker
#     execution.
#
# WORKER BEHAVIOR:
# This is execution mode. You are expected to actually run the test:
#
#   • Use Read, Bash, Grep, Glob, Write, Edit freely to examine the
#     repository, consult existing scripts, and execute tests.
#   • If your persona's Tool Discipline stat is 8-10, check
#     exhaustion_log.json and run_attack.py --list BEFORE writing any
#     new test code. Prefer existing infrastructure.
#   • If your persona's Analytical Procedure section describes a
#     specific methodology for testing hypotheses in this family,
#     follow it.
#   • If the hypothesis turns out to be a refinement of an
#     already-eliminated family, report that finding in your JSON
#     result rather than spending compute on confirmed-dead work.
#   • Write scratch files only to the directory specified in the user
#     prompt. NEVER to scripts/, tests/, or src/.
#
# ESCALATION NOTE:
# You are NOT the controller. You execute one test and report one
# structured result. Do not propose follow-up hypotheses, do not
# suggest variant tests, do not recommend memory promotion. Those are
# the controller's responsibilities. Report what you found; the
# controller decides what to do with it.
#
# ===== AGENT PERSONA (priors — use for HOW you test, not output format) ====="""


_WORKER_MODE_REMINDER = """\
# ===== END OF AGENT PERSONA =====
#
# Final reminder: your response MUST end with ONE fenced code block:
#
#   ```json
#   { ...WorkerContract object from user prompt schema... }
#   ```
#
# The ```json fence is mandatory — the controller parses it literally
# via validate_worker_contract. No prose after the closing ```. Do
# NOT emit your persona's narrative Output Contract sections.
# ==================================================================="""

# Files in .claude/agents/ that are not agents themselves.
NON_AGENT_FILENAMES = frozenset({
    "PANTHEON.md",
    "AGENT_TEMPLATE.md",
    "USAGE.md",
    "MIGRATION.md",
    "README.md",
})


@dataclass
class AgentSpec:
    """
    Structured representation of a Pantheon agent definition.

    Fields map directly to the frontmatter of a .claude/agents/<name>.md
    file, plus `body` which holds the markdown content following the
    frontmatter (the agent's actual system prompt content).
    """
    name: str
    description: str
    body: str                                # the markdown body (system prompt content)
    model: Optional[str] = None              # "opus" | "sonnet" | "haiku" | "inherit" | None
    tools: list[str] = field(default_factory=list)
    skills: list[str] = field(default_factory=list)
    color: Optional[str] = None
    memory: Optional[str] = None
    source_path: Optional[Path] = None       # where this agent was loaded from

    def system_prompt(self, include_description: bool = True) -> str:
        """
        Build the complete AUDIT-MODE system prompt — the agent's body
        text with its full Output Contract intact. Use this for sibling
        calls where the Standard Output Spine (Observations, Interpretation,
        Prior, Evidence, Falsification, Confidence, Next Test) IS the
        correct response format: red-team-disprover, statistical-auditor,
        results-analyst audit-style calls.

        For theorist generation calls, use theorist_system_prompt() instead
        — the Output Contract is the wrong format for JSON array generation
        and will produce parse failures.
        """
        if include_description:
            header = f"# Role: {self.name}\n\n{self.description.strip()}\n\n---\n\n"
            return header + self.body.strip()
        return self.body.strip()

    def theorist_system_prompt(self) -> str:
        """
        Build a THEORIST-GENERATION-MODE system prompt that wraps the
        agent body with an explicit output-format override.

        Why this exists: each Pantheon agent .md file declares an
        Output Contract section prescribing narrative structured output
        (Observations / Interpretation / Prior / Evidence / Falsification
        / Confidence / Next Test). That contract is correct for audit
        responses where a single agent produces a single analysis, but
        it DIRECTLY CONFLICTS with the theorist generation task which
        requires a JSON array of hypothesis objects.

        Without this wrapper, a session given the raw agent body spends
        many turns trying to reconcile the two contradictory output
        specifications (persona's narrative contract vs user prompt's
        JSON array) and eventually hits max_turns without producing any
        parseable output. Observed 2026-04-12 after Day 2 controller
        integration: 16-minute, 75-turn theorist sessions emitting no
        JSON. See memory/project_sdk_setting_sources_verified.md for
        the broader operational-facts register.

        The wrapper preserves the agent's PRIORS (Identity, Stats,
        Bias/Anti-bias, Analytical Procedure, Rivals — these shape WHICH
        hypotheses get generated and HOW they're framed) while explicitly
        overriding the Output Contract for this specific call.
        """
        header = _THEORIST_MODE_PREFACE.format(agent_name=self.name)
        footer = _THEORIST_MODE_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"

    def redteam_precheck_system_prompt(self) -> str:
        """
        Build a RED-TEAM PROPOSAL-TIME PRE-CHECK system prompt that wraps
        the agent body with directives constraining output to a brief
        structured JSON verdict.

        Why this exists: red-team-disprover's audit-mode Output Contract
        prescribes a multi-section narrative response. That format is
        correct for promoting findings or auditing scored claims, but
        it's overkill for a proposal-time gate where the controller
        only needs verdict + reasons + confidence to decide whether to
        dispatch a worker. The wrapper preserves the adversarial priors
        (the persona's bias toward finding noise, its analytical
        procedure for spotting symmetric failure modes) while
        constraining the output to one quick JSON object.

        This method exists alongside system_prompt() (full audit mode,
        for signal-level claim review) and theorist_system_prompt()
        (generation mode). Three call sites, three wrappers, same
        underlying agent body.
        """
        header = _REDTEAM_PRECHECK_PREFACE.format(agent_name=self.name)
        footer = _REDTEAM_PRECHECK_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"

    def worker_system_prompt(self) -> str:
        """
        Build a WORKER EXECUTION system prompt that wraps the agent body
        with directives constraining output to a fenced ```json
        WorkerContract block at the end of a free-form reasoning response.

        Why this exists: the Day 2 cycle 36 worker 2165214e ran for 21
        minutes and 166 turns under the old generic worker system prompt
        and emitted its final result without a ```json fence, failing
        the controller's validate_worker_contract check. The generic
        prompt said 'report results in strict JSON format' but the
        worker interpreted that as a raw JSON object. validate_worker_contract
        specifically requires the fenced ```json code block form.

        The Day 4 fix:
          1. Load the routed persona (cryptanalyst / stego-analyst /
             keystream-forensics / etc.) as the worker system prompt
          2. The persona brings its declared skills via setting_sources,
             including `results-protocol` and `disproof-protocol` which
             prescribe the fenced-JSON contract
          3. This wrapper explicitly reinforces the ```json fence
             requirement and tells the persona its native narrative
             Output Contract does NOT apply to this call

        The worker wrapper is the fourth mode wrapper in the Pantheon
        integration, alongside:
          - system_prompt()          → audit mode (narrative)
          - theorist_system_prompt() → generation mode (JSON array)
          - redteam_precheck_system_prompt() → proposal gate (JSON object)
          - worker_system_prompt()   → execution mode (fenced ```json)
          - stat_audit_system_prompt() → post-execution gate (JSON object) [Day 5]
          - synthesis_system_prompt()  → end-of-cycle synthesis (JSON object) [Day 5]
        """
        header = _WORKER_MODE_PREFACE.format(agent_name=self.name)
        footer = _WORKER_MODE_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"

    def stat_audit_system_prompt(self) -> str:
        """
        Build a STATISTICAL-AUDITOR POST-EXECUTION SIGNAL AUDIT system
        prompt that wraps the agent body with directives constraining
        output to a brief structured JSON verdict.

        Same architectural shape as redteam_precheck_system_prompt() but
        called AFTER worker execution rather than BEFORE dispatch. Used
        for any contract whose kernel-verified crib_score >= SIGNAL
        threshold. The wrapper preserves the audit priors (multiple-
        testing burden, null model design, look-elsewhere effects) while
        constraining the output to a verdict the controller can act on.

        Day 5 addition.
        """
        header = _STAT_AUDIT_PREFACE.format(agent_name=self.name)
        footer = _STAT_AUDIT_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"

    def synthesis_system_prompt(self) -> str:
        """
        Build a CYCLE-SYNTHESIS system prompt that wraps the agent body
        with directives constraining output to a structured JSON object
        the controller persists and renders in the next cycle's landscape.

        Used at end-of-cycle. The output is a structured handoff to the
        next cycle's theorist, not a narrative summary.

        Day 5 addition.
        """
        header = _SYNTHESIS_PREFACE.format(agent_name=self.name)
        footer = _SYNTHESIS_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"

    def pursuit_system_prompt(self) -> str:
        """
        Build a LEAD-PURSUIT-EVALUATOR system prompt that wraps the
        agent body with directives constraining output to a structured
        JSON verdict the controller uses to decide whether to open a
        pursuit lead in the ledger.

        Used post-absorb for any sub-signal (6-17) contract. The
        default agent is results-analyst, though the controller can
        upgrade to research-chancellor for the high end of the band.

        Day 6 addition.
        """
        header = _PURSUIT_PREFACE.format(agent_name=self.name)
        footer = _PURSUIT_REMINDER
        return f"{header}\n\n{self.body.strip()}\n\n{footer}"


# ---------------------------------------------------------------------------
# Frontmatter parser (minimal, purpose-built, no PyYAML)
# ---------------------------------------------------------------------------

_FRONTMATTER_FENCE = re.compile(r"^---\s*$", re.MULTILINE)


def strip_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """
    Split a markdown file into (frontmatter_dict, body).

    Returns an empty dict and the original text if no frontmatter
    fences are present. Raises ValueError if the frontmatter is
    malformed (opening fence but no closing fence).
    """
    lines = text.splitlines(keepends=False)
    if not lines or lines[0].strip() != "---":
        return {}, text

    # Find the closing fence
    closing_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            closing_idx = i
            break

    if closing_idx is None:
        raise ValueError(
            "Frontmatter opening fence '---' found but no closing fence"
        )

    fm_lines = lines[1:closing_idx]
    body_lines = lines[closing_idx + 1:]
    body = "\n".join(body_lines)

    fm_dict = _parse_frontmatter_lines(fm_lines)
    return fm_dict, body


def _parse_frontmatter_lines(lines: list[str]) -> dict[str, Any]:
    """
    Parse a list of YAML frontmatter lines into a flat dict.

    Handles the specific shapes used in .claude/agents/ files:
      - scalar key:value
      - quoted string values "..." with \\n escapes
      - folded block scalars:   key: >\\n  line1\\n  line2
      - inline lists:           key: ["a", "b"]
      - block lists:            key:\\n  - a\\n  - b

    Does NOT handle nested mappings or anchors. If a new agent uses
    constructs this parser can't handle, it will either raise or log a
    warning; it will not silently mis-parse.
    """
    result: dict[str, Any] = {}
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip blank lines and comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Top-level keys are at column 0
        if line.startswith(" "):
            i += 1  # continuation of a previous key, handled inline
            continue

        if ":" not in line:
            logger.warning("pantheon: unparseable frontmatter line: %r", line)
            i += 1
            continue

        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()

        # Case 1: folded block scalar ("key: >")
        if rest == ">" or rest == ">-":
            block_lines: list[str] = []
            i += 1
            while i < n and (lines[i].startswith("  ") or lines[i] == ""):
                if lines[i] == "":
                    block_lines.append("")
                else:
                    block_lines.append(lines[i][2:])  # strip 2-space indent
                i += 1
            # Fold: join with spaces, treating blank lines as paragraph breaks
            result[key] = _fold_block_scalar(block_lines)
            continue

        # Case 2: literal block scalar ("key: |")
        if rest == "|" or rest == "|-":
            block_lines = []
            i += 1
            while i < n and (lines[i].startswith("  ") or lines[i] == ""):
                block_lines.append(lines[i][2:] if lines[i].startswith("  ") else "")
                i += 1
            result[key] = "\n".join(block_lines)
            continue

        # Case 3: block list ("key:\n  - item\n  - item")
        if rest == "":
            items: list[str] = []
            i += 1
            while i < n and lines[i].startswith("  -"):
                item = lines[i][3:].strip()
                items.append(_unquote(item))
                i += 1
            result[key] = items
            continue

        # Case 4: inline list ("key: [a, b, c]")
        if rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            if not inner:
                result[key] = []
            else:
                items = [_unquote(p.strip()) for p in inner.split(",")]
                result[key] = items
            i += 1
            continue

        # Case 5: scalar value (possibly quoted, possibly with \n escapes)
        result[key] = _unquote(rest)
        i += 1

    return result


def _fold_block_scalar(block_lines: list[str]) -> str:
    """
    Fold a YAML '>' block scalar into a single string.

    Simple version: join non-blank lines with spaces, keep blank lines
    as paragraph separators. This is close enough to YAML's fold rules
    for the agent description fields we parse.
    """
    paragraphs: list[list[str]] = [[]]
    for line in block_lines:
        if line == "":
            if paragraphs[-1]:
                paragraphs.append([])
        else:
            paragraphs[-1].append(line.strip())
    joined_paragraphs = [" ".join(p) for p in paragraphs if p]
    return "\n\n".join(joined_paragraphs)


def _unquote(s: str) -> str:
    """Strip matching quotes and process basic backslash escapes."""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        inner = s[1:-1]
        if s[0] == '"':
            # Process common escapes
            inner = inner.replace("\\n", "\n").replace("\\t", "\t")
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return s


# ---------------------------------------------------------------------------
# Public loader API
# ---------------------------------------------------------------------------


def load_agent(name: str, agents_dir: Path = DEFAULT_AGENTS_DIR) -> AgentSpec:
    """
    Load a single Pantheon agent by name.

    Args:
        name: the agent's frontmatter name (also the filename stem).
        agents_dir: the directory containing agent .md files. Defaults
            to .claude/agents relative to the current working directory.

    Returns:
        A populated AgentSpec.

    Raises:
        FileNotFoundError if no matching .md file exists.
        ValueError if the file has no 'name' frontmatter field.
    """
    path = agents_dir / f"{name}.md"
    if not path.exists():
        raise FileNotFoundError(
            f"pantheon: agent file not found: {path} "
            f"(cwd={Path.cwd()}, agents_dir={agents_dir.resolve()})"
        )

    text = path.read_text(encoding="utf-8")
    fm, body = strip_frontmatter(text)

    if "name" not in fm:
        raise ValueError(
            f"pantheon: {path} has no 'name' field in frontmatter — "
            f"not a valid agent definition"
        )

    spec = AgentSpec(
        name=fm["name"],
        description=fm.get("description", ""),
        body=body,
        model=fm.get("model"),
        tools=fm.get("tools", []) if isinstance(fm.get("tools"), list) else [],
        skills=fm.get("skills", []) if isinstance(fm.get("skills"), list) else [],
        color=fm.get("color"),
        memory=fm.get("memory"),
        source_path=path,
    )
    return spec


def load_roster(agents_dir: Path = DEFAULT_AGENTS_DIR) -> dict[str, AgentSpec]:
    """
    Discover and load every Pantheon agent in the agents directory.

    Files named in NON_AGENT_FILENAMES are skipped. Files whose
    frontmatter lacks a 'name' field are skipped with a warning.

    Returns a dict keyed by agent name.
    """
    if not agents_dir.exists():
        raise FileNotFoundError(
            f"pantheon: agents directory does not exist: "
            f"{agents_dir.resolve()}"
        )

    roster: dict[str, AgentSpec] = {}
    for path in sorted(agents_dir.glob("*.md")):
        if path.name in NON_AGENT_FILENAMES:
            continue
        try:
            # Use the file stem as the name for lookup; strip_frontmatter
            # inside load_agent will validate against the frontmatter.
            spec = load_agent(path.stem, agents_dir)
        except (FileNotFoundError, ValueError) as exc:
            logger.warning(
                "pantheon: skipping %s (%s: %s)",
                path.name, type(exc).__name__, exc,
            )
            continue
        roster[spec.name] = spec

    if not roster:
        logger.warning(
            "pantheon: no agents loaded from %s — Pantheon integration will "
            "have nothing to route to",
            agents_dir.resolve(),
        )
    else:
        logger.info(
            "pantheon: loaded %d agents from %s: %s",
            len(roster),
            agents_dir.resolve(),
            ", ".join(sorted(roster.keys())),
        )

    return roster


# ---------------------------------------------------------------------------
# Model routing helper
# ---------------------------------------------------------------------------


# Model names as the Claude Agent SDK expects them.
_SDK_OPUS = "claude-opus-4-6"
_SDK_SONNET = "claude-sonnet-4-6"
_SDK_HAIKU = "claude-haiku-4-5"


def resolve_model_for_phase(
    spec: AgentSpec,
    phase: str,
) -> tuple[str, str]:
    """
    Decide which concrete model and fallback the controller should use
    when running this agent in a given pipeline phase.

    Policy:
      - Theorist phase: respect frontmatter. Opus where declared,
        Sonnet where frontmatter says sonnet, Sonnet as safe default.
      - Worker phase: always Sonnet regardless of frontmatter. Workers
        do mechanical execution; creative reasoning happened upstream
        at the theorist phase. Matches existing controller behavior.
      - Red-team phase: respect frontmatter. Opus for adversarial
        reasoning. This is where signal-vs-noise judgment happens.
      - Stat-audit phase: respect frontmatter. Opus for methodology
        review. Statistical rigor is the bottleneck.
      - Synthesis phase: Sonnet. Mechanical summarization.

    Returns (model, fallback_model) as strings the SDK accepts.
    """
    phase = phase.lower()
    declared = (spec.model or "").lower()

    # Worker phase always downgrades to Sonnet regardless of agent frontmatter.
    if phase == "worker":
        return _SDK_SONNET, _SDK_HAIKU

    # Synthesis phase always uses Sonnet — it's a summarization role.
    if phase == "synthesis":
        return _SDK_SONNET, _SDK_HAIKU

    # Day 6 pursuit phase: Sonnet. Same judgment shape as synthesis
    # (one contract in, a short structured verdict out), so no reason
    # to burn Opus dollars here. If results-analyst's verdicts look
    # shallow in practice, the controller can upgrade the routing for
    # the high end of the interesting band (14-17) to a different
    # agent, but the phase-level default stays Sonnet.
    if phase == "pursuit":
        return _SDK_SONNET, _SDK_HAIKU

    # Theorist / red-team / stat-audit: honor the declared model.
    if declared == "opus":
        return _SDK_OPUS, _SDK_SONNET
    if declared == "sonnet":
        return _SDK_SONNET, _SDK_HAIKU
    if declared == "haiku":
        return _SDK_HAIKU, _SDK_HAIKU

    # No model declared: default Sonnet (safe, capable, cheaper than Opus).
    return _SDK_SONNET, _SDK_HAIKU
