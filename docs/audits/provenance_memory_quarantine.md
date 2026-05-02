# Provenance Memory Quarantine

Date: 2026-05-01

## Action

Live `.claude` agent and skill surfaces that promoted the retired null-palette
claim `{B,G,I,K,O,W,Z}` were rewritten to mark it as historical context only.

## Files Rewritten

- `.claude/agents/keystream-forensics.md`
- `.claude/agents/stego-analyst.md`
- `.claude/skills/cipher-beaufort/SKILL.md`
- `.claude/skills/cipher-running-key-beaufort/SKILL.md`
- `.claude/skills/k4-stego-cracker/SKILL.md`
- `.claude/skills/otp-null-keystream-forensics/SKILL.md`

## Scope

The edits do not rehabilitate the retired palette claim, do not alter canonical
project claims, and do not delete archival evidence. They only prevent live
prompt surfaces from presenting the retired claim as a hard constraint,
must-explain requirement, or model-selection reason.

Generated skill-eval outputs and old agent-memory files still contain historical
palette language. Those are archival artifacts and should not be loaded into
live prompts without provenance guardrails.

The Pantheon prompt wrapper now states explicitly that `.claude/agent-memory/`
and generated skill-eval outputs are archival evidence only. The live roster
loader still reads `.claude/agents/*.md` only; memory files do not become
system prompt text unless a future caller adds a separate, audited memory
injection path.

## Required Policy

The retired palette claim may be mentioned only as:

- retired historical context,
- an example of a failed or overfit statistical claim,
- a target for explicit re-audit.

It must not be used as:

- a hard cryptanalytic constraint,
- an elimination basis,
- a must-explain anomaly,
- a scoring prior,
- a reason to prefer Beaufort or null-insertion models.
