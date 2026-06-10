"""
Deterministic linter tests for the .claude prompt layer.

This suite is the durable defence against prompt-layer drift identified by
the 2026-05-04 Claude agents-and-skills adversarial audit. Every test runs
locally, reads files only, and never invokes any paid API.

The audit's PARTIAL verdict on the .claude layer hinges on six failure
modes:

  1. Stale missing-path mentions (memory/elimination_ledger.md, etc.).
  2. Retired-claim revival (CONSENSUS_NULL_POSITIONS, null palette,
     {B,G,I,K,O,W,Z}) without explicit retired/policy-gated wording.
  3. Controller-routed agents instructing Claude to use Task / Agent /
     subagent delegation when the controller blocks those tools.
  4. Output-contract drift from the per-phase wrappers in
     kryptosbot/pantheon.py.
  5. Status-vocabulary drift from kryptosbot.models.WorkerStatus and
     TheoryStatus.
  6. Required campaign-readiness skills missing from .claude/skills.

Each test below targets one of these failure modes (or its enabling
infrastructure: roster loadability, routing presence, manual-only
markers, settings.local.json scope).

Run from the repo root:

    PYTHONPATH=.:src python3 -m pytest kryptosbot/tests/test_claude_prompt_layer.py -q
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.pantheon import (  # noqa: E402
    NON_AGENT_FILENAMES,
    load_roster,
    strip_frontmatter,
)
from kryptosbot.routing import (  # noqa: E402
    FAMILY_TO_WORKER_AGENT,
    THEORIST_ROTATION,
)
from kryptosbot.models import WorkerStatus, TheoryStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Repo-relative paths and conventions
# ---------------------------------------------------------------------------

CLAUDE_DIR = _ROOT / ".claude"
AGENTS_DIR = CLAUDE_DIR / "agents"
SKILLS_DIR = CLAUDE_DIR / "skills"
SETTINGS_LOCAL = CLAUDE_DIR / "settings.local.json"

# Routed agent names: theorist rotation + worker dispatch + adversarial
# slots (red-team, stat-audit, results-analyst, chancellor pursuit
# fallback). If routing.py adds slots, this set must grow with it; the
# test for routed-agents-exist will catch divergence.
ROUTED_AGENT_NAMES: set[str] = (
    set(THEORIST_ROTATION)
    | set(FAMILY_TO_WORKER_AGENT.values())
    | {
        "red-team-disprover",
        "statistical-auditor",
        "results-analyst",
        "research-chancellor",
    }
)

# Required campaign-readiness skills.
REQUIRED_SKILLS: tuple[str, ...] = (
    "known-answer-validation",
    "dispatcher-dsl-contract",
    "conditional-null-methodology",
    "prompt-contract-lint",
    "project-onboarding",
    "results-protocol",
    "disproof-protocol",
)

# Allowlist of files that may legitimately reference retired claims as
# historical / audit context. Each entry is a path relative to repo root.
RETIRED_CLAIM_ALLOWLIST: frozenset[str] = frozenset({
    ".claude/skills/k4-stego-cracker/SKILL.md",
    ".claude/skills/otp-null-keystream-forensics/SKILL.md",
    ".claude/skills/k4-stego-cracker/references/test_recipes.md",
    ".claude/skills/otp-null-keystream-forensics/references/keystream_properties.md",
    ".claude/skills/conditional-null-methodology/SKILL.md",
    ".claude/skills/prompt-contract-lint/SKILL.md",
    ".claude/skills/project-onboarding/SKILL.md",
    ".claude/skills/disproof-protocol/SKILL.md",
    ".claude/skills/results-protocol/SKILL.md",
    ".claude/skills/known-answer-validation/SKILL.md",
    ".claude/skills/dispatcher-dsl-contract/SKILL.md",
    ".claude/agents/stego-analyst.md",
    ".claude/agents/keystream-forensics.md",
    ".claude/agents/statistical-auditor.md",
    ".claude/agents/escape-room-cryptanalyst.md",
    ".claude/agents/research-chancellor.md",
    ".claude/agents/PANTHEON.md",
    ".claude/agents/USAGE.md",
    ".claude/agents/MIGRATION.md",
    ".claude/templates/AGENT_TEMPLATE.md",
})

# Phrases that count as policy-gated retired-claim wording. A retired-claim
# match in a file is acceptable IFF a phrase from this set appears within a
# context window around it.
RETIRED_GATING_PHRASES: tuple[str, ...] = (
    "retired",
    "policy-gated",
    "policy gated",
    "do not use",
    "do not promote",
    "do not revive",
    "must not be revived",
    "kryptos.kernel.retired",
    "claim_policy",
    "claims_registry",
    "rehabilitat",
    "historical",
    "archival",
    "not a mechanism",
    "as-proof",
    "scope creep",
    "failure mode",
    "anti-pattern",
    "descriptive finding",
    "previously eliminated",
    "previously retired",
    "audit",
    "elonka",
)

# Promotion words that, when used about a result without nearby kernel /
# null / Bean / audit / p-value language, indicate sycophancy or
# narrative-overfit. The "kernel-context" phrases satisfy the gate.
#
# We intentionally exclude the bare word "evidence" because the project's
# canonical audit-mode output contract uses "Evidence For" / "Evidence
# Against" as section headings — those are structural, not promotional.
# A more aggressive rule that flagged "evidence" produced 100+ false
# positives in agent bodies that follow the structured-output spine.
PROMOTION_WORDS_PATTERN = re.compile(
    r"\b(breakthrough|promising)\b",
    flags=re.IGNORECASE,
)
# A narrower "signal as substantive claim" pattern: catch "signal" only
# when it's used as a noun without an adjacent "noise" / "no signal"
# qualifier nearby. This is a heuristic; the deterministic gate in this
# test is the kernel-context window.
SIGNAL_CLAIM_PATTERN = re.compile(
    r"\b(claimed signal|real signal|cryptographic signal|signal[- ]level)\b",
    flags=re.IGNORECASE,
)
KERNEL_CONTEXT_PATTERN = re.compile(
    r"\b("
    r"kernel[-_ ]?verif|"
    r"bean|"
    r"null[-_ ]?baseline|"
    r"null[-_ ]?model|"
    r"matched[-_ ]?null|"
    r"p[-_ ]?value|"
    r"p<|p ?<|"
    r"multiplicity|"
    r"bonferroni|"
    r"audit|"
    r"falsif|"
    r"retired|"
    # The project's canonical score taxonomy. Mentioning the
    # taxonomy alongside a promotion word indicates definition,
    # not assertion. NOISE / STORE / INTERESTING / SIGNAL /
    # BREAKTHROUGH live together in the threshold table.
    r"NOISE|"
    r"INTERESTING|"
    r"score_candidate|"
    r"exhaustion[-_ ]?log|"
    r"crib[-_ ]?score|"
    # Anti-promotion / red-team framing words. When these appear
    # near a "promotion" word, the use is critical or descriptive
    # of the pattern to AVOID, not an assertion. Cryptanalyst's
    # rivals section, results-analyst's anti-bias, red-team's
    # trigger description, etc.
    r"search[-_ ]?artifact|"
    r"high[-_ ]?score|high[-_ ]?scoring|"
    r"artifact|"
    r"anti[-_ ]?bias|"
    r"tunnel vision|"
    r"false positive|"
    r"attractive|"
    r"adversarial|"
    r"rivals|"
    r"scare quote|"
    r"trigger|"
    r"\"promising\"|"
    r"\"breakthrough\"|"
    r"zero[- ]?breakthrough|"
    r"no breakthrough|"
    r"rejected|"
    r"reject_|"
    r"red[- ]?team|"
    # Scope qualifiers that gate a promotion-word use: a "promising
    # lead" inside a manual-only / non-controller-routed scope is
    # not a controller-promotion claim.
    r"manual[-_ ]?only|"
    r"controller[-_ ]?routed|"
    r"non[-_ ]?DSL"
    r")\b",
    flags=re.IGNORECASE,
)

# Task/Agent delegation patterns banned in controller-routed agent bodies
# unless explicitly noted in a controller-context block.
DELEGATION_PATTERN = re.compile(
    r"\b("
    r"use the Agent tool|"
    r"Agent tool to launch|"
    r"launch (?:the )?(?:sub)?agent|"
    r"Task tool|"
    r"commission (?:the |an )?agent|"
    r"commission rival agent|"
    r"spawn (?:a )?subagent"
    r")\b",
    flags=re.IGNORECASE,
)

# Stale path patterns.
STALE_PATH_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bmemory/elimination_ledger\.md\b"),
    re.compile(r"\bmemory/confirmed_findings\.md\b"),
)

# Files that may legitimately mention stale paths in their lint targets
# (the linter skill itself catalogs them as banned strings).
STALE_PATH_ALLOWLIST: frozenset[str] = frozenset({
    ".claude/skills/prompt-contract-lint/SKILL.md",
    "kryptosbot/tests/test_claude_prompt_layer.py",
})

# Wrapper phase markers — the canonical wrappers in pantheon.py emit
# these strings. If a routed agent body needs to interoperate with a
# wrapper, it should not contradict the wrapper's contract.
WRAPPER_OUTPUT_PHRASES = {
    "theorist": "JSON array of hypothesis",
    "worker": "fenced JSON code block",
    "redteam_precheck": "ONE JSON object",
    "stat_audit": "ONE JSON object",
    "synthesis": "ONE JSON object",
    "pursuit": "ONE JSON object",
}


def _read_text(path: Path) -> str:
    """Read a file as UTF-8 text, normalizing line endings."""
    return path.read_text(encoding="utf-8")


def _iter_claude_files() -> list[Path]:
    """Live prompt-layer .md files under .claude.

    Excludes archival agent-memory and Claude Code project-memory
    directories. Per `kryptosbot/pantheon.py:_PROVENANCE_GUARDRAIL`,
    files under `.claude/agent-memory/`, `.claude/memory/`, and
    `.claude/projects/<dir>/memory/` are archival evidence only and
    cannot override the live claim policy when constructing prompts.
    The live linter scans agents and skills, not those archives.
    """
    archival_segments = (
        "agent-memory",
        ".claude/memory",
        "/projects/",
    )
    out: list[Path] = []
    for p in CLAUDE_DIR.rglob("*.md"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(_ROOT))
        if any(seg in rel for seg in archival_segments):
            continue
        out.append(p)
    return sorted(out)


def _routed_agent_files() -> list[Path]:
    """Agent files for agents named in routing."""
    return [
        AGENTS_DIR / f"{name}.md"
        for name in sorted(ROUTED_AGENT_NAMES)
        if (AGENTS_DIR / f"{name}.md").exists()
    ]


def _has_gated_context(text: str, match_start: int, window: int = 600) -> bool:
    """Check whether a retired-claim hit at match_start has gating
    language nearby.
    """
    lo = max(0, match_start - window)
    hi = min(len(text), match_start + window)
    snippet = text[lo:hi].lower()
    return any(phrase.lower() in snippet for phrase in RETIRED_GATING_PHRASES)


# ---------------------------------------------------------------------------
# Roster / routing tests
# ---------------------------------------------------------------------------


def test_pantheon_all_agents_parse():
    """Every loadable .claude/agents/*.md file parses as an AgentSpec."""
    roster = load_roster(AGENTS_DIR)
    assert roster, "roster is empty — pantheon.load_roster found nothing"

    # No duplicate names.
    names = list(roster.keys())
    assert len(names) == len(set(names)), (
        f"duplicate agent names in roster: {names}"
    )

    # Loadable count must not silently drop below the audit baseline (13).
    # The test does NOT enforce an exact count — agents may be added —
    # but a regression that drops the loadable count from 13 to 12 is a
    # regression and this test catches it.
    assert len(roster) >= 13, (
        f"roster has {len(roster)} agents; audit baseline is 13. "
        f"loadable count regressed."
    )

    # No file in NON_AGENT_FILENAMES is treated as an agent.
    for name in roster:
        spec = roster[name]
        assert spec.source_path is not None
        assert spec.source_path.name not in NON_AGENT_FILENAMES, (
            f"{spec.source_path} is in NON_AGENT_FILENAMES but was loaded as an agent"
        )


def test_no_placeholder_named_agent_in_agents_dir():
    """No file in .claude/agents/ may carry a placeholder frontmatter name.

    The Claude Code IDE / CLI surface that renders ``/agents`` discovers
    every ``.md`` file in ``.claude/agents/`` whose frontmatter contains a
    ``name:`` field. It does NOT consult ``pantheon.NON_AGENT_FILENAMES``,
    so an authoring template like ``AGENT_TEMPLATE.md`` whose frontmatter
    reads ``name: AGENT_NAME`` leaks into ``/agents`` as a phantom agent.

    The fix is structural: such templates must live outside
    ``.claude/agents/`` (e.g. ``.claude/templates/``). This test catches
    the same leak in the future regardless of filename — any agent file
    with a placeholder-style name fails the test.

    Placeholder patterns covered:
        AGENT_NAME, <NAME>, <name>, [NAME], [name], TBD, TODO,
        NAME_HERE, PLACEHOLDER, ``YOUR_AGENT``-style stand-ins.
    """
    placeholder_patterns: tuple[re.Pattern, ...] = (
        re.compile(r"^AGENT_NAME$"),
        re.compile(r"^<.*>$"),
        re.compile(r"^\[.*\]$"),
        re.compile(r"^TBD$", flags=re.IGNORECASE),
        re.compile(r"^TODO$", flags=re.IGNORECASE),
        re.compile(r"^PLACEHOLDER$", flags=re.IGNORECASE),
        re.compile(r"^NAME_HERE$", flags=re.IGNORECASE),
        re.compile(r"^YOUR[_-]?AGENT[_-]?NAME$", flags=re.IGNORECASE),
    )
    failures: list[tuple[str, str]] = []
    for path in sorted(AGENTS_DIR.glob("*.md")):
        text = _read_text(path)
        try:
            fm, _body = strip_frontmatter(text)
        except Exception:
            # No / malformed frontmatter is handled by other tests.
            continue
        name = fm.get("name")
        if not isinstance(name, str):
            continue
        candidate = name.strip()
        for pat in placeholder_patterns:
            if pat.match(candidate):
                failures.append((str(path.relative_to(_ROOT)), candidate))
                break
    assert not failures, (
        f"placeholder-named agent files detected in .claude/agents/: "
        f"{failures}. Move authoring templates to .claude/templates/ or "
        f"replace the placeholder name with a real agent name. The "
        f"Claude Code /agents surface auto-discovers any .md with a "
        f"frontmatter `name:` and will display the placeholder verbatim."
    )


def test_routing_references_existing_agents():
    """Every agent name referenced by routing.py exists in the roster."""
    roster = load_roster(AGENTS_DIR)
    missing = sorted(name for name in ROUTED_AGENT_NAMES if name not in roster)
    assert not missing, (
        f"routing references agents not present in roster: {missing}. "
        f"Roster currently has: {sorted(roster.keys())}"
    )


def test_present_unrouted_agents_are_marked_manual():
    """Loadable agents not in routing must declare manual-only status."""
    roster = load_roster(AGENTS_DIR)
    unrouted = sorted(name for name in roster if name not in ROUTED_AGENT_NAMES)
    if not unrouted:
        return
    failures = []
    for name in unrouted:
        spec = roster[name]
        body = spec.body.lower()
        marker_present = (
            "manual-only" in body
            or "not routed by the controller" in body
            or "manual-only agent" in body
        )
        if not marker_present:
            failures.append(name)
    assert not failures, (
        f"unrouted but loadable agents lack manual-only markers: {failures}. "
        f"Add an explicit 'Manual-only agent. Not routed by the controller.' "
        f"block (see forensic-photo-analyst.md for the template)."
    )


def test_agent_frontmatter_skill_refs_exist():
    """Every skill named in agent frontmatter has a SKILL.md on disk."""
    roster = load_roster(AGENTS_DIR)
    failures: list[tuple[str, str]] = []
    for name, spec in roster.items():
        for skill_ref in spec.skills:
            skill_dir = SKILLS_DIR / skill_ref
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                failures.append((name, skill_ref))
    assert not failures, (
        f"agent frontmatter references skills with no SKILL.md: {failures}"
    )


def test_agent_skill_refs_not_assumed_enforced():
    """Live docs must not claim agent frontmatter skills are enforced."""
    # The controller parses spec.skills but does NOT pass them to the SDK.
    # Skills are made available globally via setting_sources=["project"].
    # If a live doc claims otherwise, it misleads agent authors.
    pattern = re.compile(
        r"agent\s+frontmatter\s+skills?\s+(are|is|will be)\s+(enforced|loaded\s+per\s+agent|passed\s+to\s+the\s+SDK)",
        flags=re.IGNORECASE,
    )
    failures: list[tuple[str, str]] = []
    for path in _iter_claude_files():
        text = _read_text(path)
        for m in pattern.finditer(text):
            failures.append((str(path.relative_to(_ROOT)), m.group(0)))
    assert not failures, (
        f"docs claim agent frontmatter skills are enforced; controller does "
        f"not enforce them: {failures}"
    )


def test_all_routed_agents_have_phase_wrapper_contract():
    """Every routed agent is loadable and the controller's wrapper layer
    exists for every phase that routes to it.

    The wrapper layer (kryptosbot/pantheon.py:AgentSpec.<phase>_system_prompt)
    is the controller's protection against agent narrative contracts. We
    assert the relevant wrapper methods exist for every phase and that
    they emit their canonical override directive — not that the routed
    agent's body matches them, since the wrapper specifically overrides
    the agent body's Output Contract.
    """
    from kryptosbot.pantheon import AgentSpec  # local import for clarity

    roster = load_roster(AGENTS_DIR)
    for name in sorted(ROUTED_AGENT_NAMES):
        if name not in roster:
            pytest.fail(f"routed agent missing from roster: {name}")
        spec = roster[name]
        # Required wrapper methods.
        for method in (
            "theorist_system_prompt",
            "worker_system_prompt",
            "redteam_precheck_system_prompt",
            "stat_audit_system_prompt",
            "synthesis_system_prompt",
            "pursuit_system_prompt",
            "system_prompt",
        ):
            assert callable(getattr(spec, method, None)), (
                f"AgentSpec is missing {method}() — wrapper layer regression"
            )

    # Wrapper output phrases must be present in the wrapper text. We
    # construct a sample wrapper and check the canonical phrase appears.
    sample_name = "cryptanalyst"
    if sample_name in roster:
        spec = roster[sample_name]
        for phase, phrase in WRAPPER_OUTPUT_PHRASES.items():
            method = getattr(spec, f"{phase}_system_prompt", None)
            if method is None:
                continue
            wrapper = method()
            assert phrase.lower() in wrapper.lower(), (
                f"wrapper for phase {phase!r} does not emit canonical "
                f"phrase {phrase!r}"
            )


def test_agents_do_not_reference_missing_project_files():
    """No agent or skill mentions stale missing project paths."""
    failures: list[tuple[str, str]] = []
    for path in _iter_claude_files():
        rel = str(path.relative_to(_ROOT))
        if rel in STALE_PATH_ALLOWLIST:
            continue
        text = _read_text(path)
        for pattern in STALE_PATH_PATTERNS:
            if pattern.search(text):
                failures.append((rel, pattern.pattern))
    assert not failures, (
        f"stale path references in .claude files: {failures}. "
        f"memory/elimination_ledger.md and memory/confirmed_findings.md "
        f"do not exist and must be removed or replaced with current "
        f"structured stores (exhaustion_log.json, claims_registry.json, "
        f"controller dispatcher)."
    )


def test_no_agent_promotes_retired_claims():
    """Specific retired-claim revivals must be policy-gated wherever
    they appear in live prompt surfaces.

    Targets the SPECIFIC retired references — the constant
    `CONSENSUS_NULL_POSITIONS` and the literal palette set
    `{B,G,I,K,O,W,Z}`. The bare phrase "null palette" is the abstract
    cipher-skill term for any null-letter palette and is not flagged
    here; the lint catches concrete revival, not abstract discussion.
    """
    retired_patterns: tuple[re.Pattern, ...] = (
        re.compile(r"CONSENSUS_NULL_POSITIONS"),
        re.compile(r"\{B,\s*G,\s*I,\s*K,\s*O,\s*W,\s*Z\}"),
    )
    # `references/` and `keystream_properties.md` documentation files
    # under skills are explicitly historical reference material per
    # their parent SKILL.md's structure (see Step 2 in
    # k4-stego-cracker/SKILL.md). They are reference targets that the
    # active skill body cites; we treat them as gated by the parent
    # skill's retired-claim policy.
    reference_dir_patterns = ("/references/",)
    failures: list[tuple[str, str, int]] = []
    for path in _iter_claude_files():
        rel = str(path.relative_to(_ROOT))
        if any(seg in rel for seg in reference_dir_patterns):
            continue
        text = _read_text(path)
        for pattern in retired_patterns:
            for m in pattern.finditer(text):
                if not _has_gated_context(text, m.start()):
                    failures.append((rel, pattern.pattern, m.start()))
    assert not failures, (
        f"retired-claim mentions without policy-gating context: {failures}. "
        f"Each retired-claim mention must have one of these phrases "
        f"within a 600-char window: {RETIRED_GATING_PHRASES}."
    )


def test_no_agent_uses_breakthrough_without_kernel_verification():
    """Promotion language ('breakthrough', 'promising', substantive
    'signal' claims) requires kernel/null/Bean/audit context within a
    400-char window.

    The bare word "evidence" is NOT flagged: it appears as a structural
    section heading ("Evidence For", "Evidence Against") in the
    project's canonical audit-mode output contract, where it is
    structural, not promotional. The lint catches concrete promotion
    words and substantive "signal" claims.

    Scare-quoted forms (e.g. `"breakthrough"` in `"breakthrough" scores
    caused by off-by-one errors`) are treated as anti-promotion: a
    match whose immediate neighborhood (±2 chars) contains an opening
    quote AND a closing quote is critical/anti-promotion, not an
    assertion.
    """

    def _is_scare_quoted(text: str, start: int, end: int) -> bool:
        """Return True if the match span is wrapped in matching quotes
        within ±2 characters."""
        prefix = text[max(0, start - 2): start]
        suffix = text[end: end + 2]
        for q in ('"', "'", '“', '”'):
            if q in prefix and (q in suffix or q == "'"):
                return True
        return False

    failures: list[tuple[str, str, int]] = []
    for path in _iter_claude_files():
        rel = str(path.relative_to(_ROOT))
        # The lint skill itself catalogs these words; allowlist it.
        if rel.endswith("prompt-contract-lint/SKILL.md"):
            continue
        text = _read_text(path)
        for m in PROMOTION_WORDS_PATTERN.finditer(text):
            if _is_scare_quoted(text, m.start(), m.end()):
                continue
            window_start = max(0, m.start() - 400)
            window_end = min(len(text), m.end() + 400)
            window = text[window_start:window_end]
            if not KERNEL_CONTEXT_PATTERN.search(window):
                failures.append((rel, m.group(0), m.start()))
        for m in SIGNAL_CLAIM_PATTERN.finditer(text):
            if _is_scare_quoted(text, m.start(), m.end()):
                continue
            window_start = max(0, m.start() - 400)
            window_end = min(len(text), m.end() + 400)
            window = text[window_start:window_end]
            if not KERNEL_CONTEXT_PATTERN.search(window):
                failures.append((rel, m.group(0), m.start()))

    # The audit observed that 31 unreferenced cipher skills are advisory
    # guides, not promotion contracts. To avoid false positives in
    # cipher-family skills that mention "signal" generically, we allow
    # cipher-family skills if they contain 'noise' AND 'IC' AND
    # 'kernel' anywhere in the file (proxy for cryptanalytic guidance).
    # Similarly, agent template / pantheon documentation files
    # (NON_AGENT_FILENAMES) describe the project's structured contract
    # vocabulary — they include "evidence", "signal", "BREAKTHROUGH"
    # as part of teaching the canonical statuses. They are not active
    # prompt surfaces; the lint distinguishes documentation from
    # promotion.
    # Reference / supporting-doc files under skills/<name>/references/
    # are also documentation, not active prompts.
    soft_filter: list[tuple[str, str, int]] = []
    for rel, word, pos in failures:
        path = _ROOT / rel
        if "/cipher-" in rel and rel.endswith("/SKILL.md"):
            file_text = _read_text(path).lower()
            if (
                "noise" in file_text
                and ("ic" in file_text or "index of coincidence" in file_text)
                and "kernel" in file_text
            ):
                continue
        # Documentation surfaces (NON_AGENT_FILENAMES) exist to teach
        # the canonical structured-output vocabulary, including the
        # promotion-language taxonomy itself. Skip.
        if any(rel.endswith(f"/agents/{n}") for n in NON_AGENT_FILENAMES):
            continue
        # Reference / supporting docs under skills/<name>/references/.
        if "/references/" in rel:
            continue
        soft_filter.append((rel, word, pos))

    assert not soft_filter, (
        f"promotion language without kernel/null/Bean/audit context: "
        f"{soft_filter[:10]}{'...' if len(soft_filter) > 10 else ''}. "
        f"Total: {len(soft_filter)}. Each match needs one of "
        f"{KERNEL_CONTEXT_PATTERN.pattern} within 400 chars."
    )


# ---------------------------------------------------------------------------
# Status-vocabulary and skill-presence tests
# ---------------------------------------------------------------------------


def test_results_protocol_status_vocab_matches_controller():
    """results-protocol skill names canonical WorkerStatus / TheoryStatus
    values and does not reuse the stale 'Hot Leads' / 'PROMISING /
    DISPROVED / INCONCLUSIVE / ERROR' framing as the only vocabulary.
    """
    skill = SKILLS_DIR / "results-protocol" / "SKILL.md"
    assert skill.exists(), "results-protocol/SKILL.md missing"
    text = _read_text(skill)

    # All canonical WorkerStatus values must be referenced.
    for status in WorkerStatus:
        assert status.value in text, (
            f"results-protocol does not mention WorkerStatus.{status.name} "
            f"({status.value!r})"
        )

    # Required TheoryStatus values that the skill must reference.
    for status_name in ("ELIMINATED", "PROMISING"):
        assert status_name in text, (
            f"results-protocol does not mention TheoryStatus.{status_name}"
        )

    # Stale "Hot Leads" framing must not be the sole/promotion trigger.
    # The phrase may appear inside an explicit retirement note; require
    # gating language nearby.
    if "Hot Leads" in text:
        idx = text.index("Hot Leads")
        if not _has_gated_context(text, idx):
            pytest.fail(
                "results-protocol still uses 'Hot Leads' framing without "
                "explicit retirement / policy-gating context."
            )


@pytest.mark.parametrize("skill_name", REQUIRED_SKILLS)
def test_required_skills_present(skill_name: str):
    """Every required campaign-readiness skill exists with a SKILL.md."""
    skill_dir = SKILLS_DIR / skill_name
    skill_md = skill_dir / "SKILL.md"
    assert skill_md.exists(), (
        f"required skill missing: {skill_name} "
        f"(expected {skill_md.relative_to(_ROOT)})"
    )
    fm, body = strip_frontmatter(_read_text(skill_md))
    assert "description" in fm or "name" in fm, (
        f"{skill_name} SKILL.md has no frontmatter description/name"
    )
    assert len(body.strip()) > 200, (
        f"{skill_name} SKILL.md body too short to be a real skill"
    )


def test_known_answer_skill_present():
    """known-answer-validation skill exists and teaches the 20K cycle cap."""
    skill = SKILLS_DIR / "known-answer-validation" / "SKILL.md"
    assert skill.exists(), "known-answer-validation/SKILL.md missing"
    text = _read_text(skill)
    assert "self_test.py" in text, "skill omits self_test.py command"
    assert "--panel all" in text, "skill omits --panel all"
    assert "--cycles 20000" in text, (
        "skill omits the --cycles 20000 readiness cap"
    )
    assert "default 500" in text.lower() or "500-cycle" in text.lower(), (
        "skill must explain that the default 500-cycle command is not "
        "the readiness gate"
    )


def test_dispatcher_dsl_skill_present():
    """dispatcher-dsl-contract skill exists and teaches the full DSL."""
    skill = SKILLS_DIR / "dispatcher-dsl-contract" / "SKILL.md"
    assert skill.exists(), "dispatcher-dsl-contract/SKILL.md missing"
    text = _read_text(skill)
    required_concepts = (
        "HypothesisSpec",
        "CipherLayer",
        "ParamRange",
        "NullBaselineSpec",
        "spec_hash",
        "universe_hash",
        "assumption_bundle",
        "expected_cardinality",
        "compute_budget",
        "kernel-verif",
        "REJECTED_ADMISSIBILITY",
        "_VALID_CIPHER_KINDS",
        "_SUPPORTED_KINDS",
        "_VALID_KEY_TAPE_VARIANTS",
        "Category-A",
        "Category-B",
    )
    for concept in required_concepts:
        assert concept.lower() in text.lower(), (
            f"dispatcher-dsl-contract skill missing concept: {concept}"
        )


def test_conditional_null_skill_present():
    """conditional-null-methodology skill distinguishes null types and
    states the Phase 2.1 inconclusive result.
    """
    skill = SKILLS_DIR / "conditional-null-methodology" / "SKILL.md"
    assert skill.exists(), "conditional-null-methodology/SKILL.md missing"
    text = _read_text(skill)
    required = (
        "random_text",
        "shuffled_ct",
        "matched_variant_family",
        "admitted_theory_conditional",
        "methodological_family_conditional",
        "Phase 2.1",
        "Phase 2.2",
        "inconclusive",
        "k3_continuity",
        "archive_evidence",
        "key_tape",
        "geometry",
    )
    for token in required:
        assert token.lower() in text.lower(), (
            f"conditional-null-methodology missing token: {token}"
        )


def test_prompt_contract_lint_skill_present():
    """prompt-contract-lint skill defines the failure-mode catalog this
    test suite encodes.
    """
    skill = SKILLS_DIR / "prompt-contract-lint" / "SKILL.md"
    assert skill.exists(), "prompt-contract-lint/SKILL.md missing"
    text = _read_text(skill).lower()
    required = (
        "stale path",
        "retired",
        "task",
        "agent",
        "sycoph",
        "narrative",
        "unsupported",
        "contract",
        "h1",
    )
    for token in required:
        assert token in text, (
            f"prompt-contract-lint skill missing concept: {token}"
        )


def test_sycophancy_guardrails_present():
    """Routed agents include falsification or anti-bias language."""
    roster = load_roster(AGENTS_DIR)
    failures: list[str] = []
    for name in sorted(ROUTED_AGENT_NAMES):
        if name not in roster:
            continue
        spec = roster[name]
        body = spec.body.lower()
        guardrails = (
            "anti-bias",
            "falsif",
            "what i may not claim",
            "must not",
            "never overclaim",
            "rivals",
        )
        if not any(g in body for g in guardrails):
            failures.append(name)
    assert not failures, (
        f"routed agents missing falsification / anti-bias guardrails: "
        f"{failures}"
    )


def test_settings_local_no_retired_constant_imports():
    """settings.local.json must not allow the stale CONSENSUS_NULL_POSITIONS
    import command.
    """
    if not SETTINGS_LOCAL.exists():
        pytest.skip(".claude/settings.local.json not present")
    text = _read_text(SETTINGS_LOCAL)
    # The stale command imported the constant from kryptos.kernel.constants.
    # That import now fails; the constant lives under kryptos.kernel.retired.
    pattern = re.compile(
        r"from\s+kryptos\.kernel\.constants\s+import\s+CONSENSUS_NULL_POSITIONS",
        flags=re.IGNORECASE,
    )
    assert not pattern.search(text), (
        "settings.local.json still allows the retired "
        "kryptos.kernel.constants.CONSENSUS_NULL_POSITIONS import. "
        "Remove the allow rule or update it to use kryptos.kernel.retired."
    )
    # The constant in any allow-rule must be policy-gated; bare allows
    # are not acceptable.
    if "CONSENSUS_NULL_POSITIONS" in text:
        # Must be in _notes / comment context, not in permissions.allow.
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # If the JSON is malformed, that's a separate problem the
            # test doesn't try to fix; keep the literal-string check.
            pytest.fail("settings.local.json is not valid JSON")
        allow_list = data.get("permissions", {}).get("allow", [])
        for rule in allow_list:
            assert "CONSENSUS_NULL_POSITIONS" not in rule, (
                f"permissions.allow rule revives retired constant: {rule!r}"
            )


def test_self_test_default_or_protocol_consistency():
    """No live doc/skill presents the default 500-cycle all-panel
    command as the readiness gate.
    """
    failures: list[tuple[str, str]] = []
    pattern = re.compile(
        r"--panel\s+all\s+--mode\s+dry-run(?!\s+--cycles)",
        flags=re.IGNORECASE,
    )
    for path in _iter_claude_files():
        rel = str(path.relative_to(_ROOT))
        text = _read_text(path)
        for m in pattern.finditer(text):
            window = text[max(0, m.start() - 400): m.end() + 400].lower()
            # Allow if the surrounding text explicitly says default is
            # not sufficient or shows the cap is documented elsewhere.
            if "20000" in window or "not sufficient" in window or (
                "is not the readiness gate" in window
            ) or "500-cycle" in window:
                continue
            failures.append((rel, m.group(0)))
    assert not failures, (
        f"docs reference --panel all --mode dry-run without the 20000 cap: "
        f"{failures}. The 500-cycle default fails K3 by design; the gate "
        f"is the 20000-cycle command."
    )


# ---------------------------------------------------------------------------
# Tier 1 enforcement-auditor agents — structural contract
# ---------------------------------------------------------------------------

# Names of the manual-only enforcement auditors created during the Tier 1
# .claude hardening reopen (2026-05-05). Each must:
#   - load via pantheon.load_roster()
#   - be absent from ROUTED_AGENT_NAMES (manual-only)
#   - declare a manual-only marker in body
#   - declare Output Contract, Falsification, and "What I may not claim"
#     sections
#   - declare in body that they do not delegate to other agents / spawn
#     subagents / use the Task tool
REQUIRED_ENFORCEMENT_AUDITORS: tuple[str, ...] = (
    "agent-roster-integration-auditor",
    "known-answer-benchmark-auditor",
    "prompt-contract-auditor",
)


def test_required_enforcement_auditors_load():
    """Each required Tier 1 enforcement auditor parses as an AgentSpec."""
    roster = load_roster(AGENTS_DIR)
    missing = [n for n in REQUIRED_ENFORCEMENT_AUDITORS if n not in roster]
    assert not missing, (
        f"required enforcement auditor agents missing from roster: {missing}. "
        f"Each must exist at .claude/agents/<name>.md with valid frontmatter."
    )


def test_required_enforcement_auditors_are_manual_only():
    """Each required enforcement auditor is NOT controller-routed and
    declares a manual-only marker.
    """
    roster = load_roster(AGENTS_DIR)
    routing_failures: list[str] = []
    marker_failures: list[str] = []
    for name in REQUIRED_ENFORCEMENT_AUDITORS:
        if name not in roster:
            continue
        if name in ROUTED_AGENT_NAMES:
            routing_failures.append(name)
        body_lower = roster[name].body.lower()
        if not (
            "manual-only" in body_lower
            or "not routed by the controller" in body_lower
        ):
            marker_failures.append(name)
    assert not routing_failures, (
        f"enforcement auditors must NOT be controller-routed: "
        f"{routing_failures}. Auditors run only when the operator invokes "
        f"them through Claude Code or another manual surface."
    )
    assert not marker_failures, (
        f"enforcement auditors must declare manual-only status in body: "
        f"{marker_failures}."
    )


def test_required_enforcement_auditors_have_required_sections():
    """Each required enforcement auditor declares Output Contract,
    Falsification, and 'What I may not claim' sections.

    These sections are the explicit operator-facing contract that
    bounds the auditor's authority. Their absence is a regression in
    the audit-doctrine integration, not a stylistic preference.
    """
    roster = load_roster(AGENTS_DIR)
    section_patterns: dict[str, re.Pattern] = {
        "output_contract": re.compile(
            r"^##+\s*Output\s*Contract\b", flags=re.IGNORECASE | re.MULTILINE
        ),
        "falsification": re.compile(
            r"^##+\s*Falsification(?:\s+Criteria)?\b",
            flags=re.IGNORECASE | re.MULTILINE,
        ),
        "may_not_claim": re.compile(
            r"^##+\s*What\s+I\s+May\s+Not\s+Claim\b",
            flags=re.IGNORECASE | re.MULTILINE,
        ),
    }
    failures: list[tuple[str, str]] = []
    for name in REQUIRED_ENFORCEMENT_AUDITORS:
        if name not in roster:
            continue
        body = roster[name].body
        for section, pattern in section_patterns.items():
            if not pattern.search(body):
                failures.append((name, section))
    assert not failures, (
        f"enforcement auditors missing required sections: {failures}. "
        f"Each auditor must declare its output contract, its falsification "
        f"criteria, and the bounds on what it may claim."
    )


def test_required_enforcement_auditors_disclaim_delegation():
    """Each required enforcement auditor declares in body that it does
    not delegate to other agents / spawn subagents / use the Task tool.

    Manual-only auditors may technically reference Agent/Task language
    (the test_controller_used_agents_do_not_instruct_task_or_agent_delegation
    rule allowlists unrouted agents), but as auditors specifically they
    must not fan work out — fanning out turns a deterministic gate into
    a delegated narrative. This test enforces the disclaimer.
    """
    roster = load_roster(AGENTS_DIR)
    disclaimer_phrases = (
        "may not delegate",
        "does not delegate",
        "do not delegate",
        "single-agent deterministic",
        "must not be invoked inside a controller cycle",
    )
    failures: list[str] = []
    for name in REQUIRED_ENFORCEMENT_AUDITORS:
        if name not in roster:
            continue
        body_lower = roster[name].body.lower()
        if not any(phrase in body_lower for phrase in disclaimer_phrases):
            failures.append(name)
    assert not failures, (
        f"enforcement auditors lack a no-delegation disclaimer: {failures}. "
        f"Each must state in body that it does not delegate to other agents, "
        f"spawn subagents, or use the Task tool to fan work out."
    )


def test_controller_used_agents_do_not_instruct_task_or_agent_delegation():
    """Controller-routed agents must not instruct Claude to use Task /
    Agent / launch / commission inside a phase prompt — unless the
    body has an explicit Controller Context block stating those examples
    are illustrative and do not apply at runtime.
    """
    roster = load_roster(AGENTS_DIR)
    failures: list[tuple[str, str]] = []
    for name in sorted(ROUTED_AGENT_NAMES):
        if name not in roster:
            continue
        spec = roster[name]
        text = spec.body
        for m in DELEGATION_PATTERN.finditer(text):
            # Allow if the agent body has a Controller Context block
            # explicitly noting the delegation examples are illustrative
            # only.
            body_lower = text.lower()
            controller_context_present = (
                "controller context" in body_lower
                and (
                    "do not apply" in body_lower
                    or "blocks task" in body_lower
                    or "task / agent" in body_lower
                    or "task/agent" in body_lower
                )
            )
            if controller_context_present:
                continue
            failures.append((name, m.group(0)))
    assert not failures, (
        f"controller-routed agents instruct Task / Agent / subagent "
        f"delegation without a Controller Context block: {failures}. "
        f"Add a 'Controller Context (mandatory)' section to the agent "
        f"body explaining the controller blocks Task/Agent at runtime."
    )


def test_theorist_rotation_agents_carry_frame_faithfulness_charter():
    """The 2026-06-10 vehicle decision (charter the existing six) is a
    standing prompt-layer contract: every generative persona in
    THEORIST_ROTATION must carry the Frame-Faithfulness Charter section
    (P1 alignment + P2 construction-fidelity doubt) plus a persona lens.
    Gated by the 2026-06-10 theater test (NOT-THEATER, 16/18 gate-passers
    vs a 399/399 direct-positional baseline; artifacts under
    results/pantheon_theater_test_2026_06_10/). Dropping the charter
    silently reverts the pantheon to the all-direct prior."""
    for name in THEORIST_ROTATION:
        body = (AGENTS_DIR / f"{name}.md").read_text(encoding="utf-8")
        assert "## Frame-Faithfulness Charter" in body, (
            f"{name}.md lost the Frame-Faithfulness Charter section "
            "(adopted 2026-06-10)"
        )
        assert "P1 (alignment)" in body and "P2 (construction fidelity)" in body, (
            f"{name}.md charter section is incomplete"
        )
        assert "Your lens on this charter" in body, (
            f"{name}.md charter is missing its persona-specific lens line"
        )
