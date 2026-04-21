# K4 Run Cycle-1 Diagnostic

**Date:** 2026-04-21
**Run:** `db/k4_run_2026_04_21_r3.sqlite` at commit `48b78d0`
**Halt:** operator-commissioned halt after cycle 1 per "something is off" posture
**Run window:** started 18:10:11, halted 18:16 (cycle 2 mid-GENERATE, not persisted)

---

## Summary

The theorist produced an **18,552-character, well-formed JSON array of 5 cogent K4 hypotheses** — including three Category-A theories with valid, translatable DSL specs (vigenere, grille, atbash+vigenere). The controller silently discarded all of it and fell through to `_programmatic_fallback`, which emitted 5 "Explore X family" template stubs. The fallback stubs then burned one cycle of critic + red-team compute before dying.

**Bug class:** same class as R3-3's `dsl_spec: null` template collision — a format assumption that passes under some conditions and breaks under others. Specifically: `controller.py:1028` stringifies SDK `AssistantMessage.content` with `str(message.content)`, which produces a Python repr like `[TextBlock(citations=None, text='[\n  {...', type='text')]` instead of the raw text. `validate_theory_proposals` then cannot locate a valid JSON array inside that repr, returns 0 valid, and the fallback fires.

**Operator instinct was correct.** The D=0 invariant fired at one cycle. The dispatcher wasn't broken; the upstream theorist-output path silently failed.

---

## Question 1 — What did the theorist actually return on cycle 1?

**The theorist ran cleanly and returned a valid, complete response.** No SDK error, no length truncation, no prose collapse.

Evidence from `~/.claude/projects/-home-cpatrick-kryptos/524176a4-ccc4-4a02-b06a-894af1c509ba.jsonl`:

| Field | Value |
|---|---|
| `stop_reason` | `end_turn` (not `max_tokens`, not error) |
| `usage.output_tokens` | 13,589 |
| `usage.input_tokens` | 6 (cache-hit prompt; full prompt was pre-cached at 33,359 cache-creation tokens) |
| Model | `claude-opus-4-7` |
| Assistant message content | TextBlock with `text` = 18,552 char JSON array |

Raw response dumped to `results/k4_run_2026_04_21_r3/theorist_cycle1_raw.txt`.

When passed directly through `validate_theory_proposals(text)`:

| Theory | Family | Category | dsl_spec present? | Parse verdict |
|---|---|---|---|---|
| CT perturbation preregistered variant list | archive_evidence | B | None (correctly) | **VALID** |
| K3 as-carved plaintext as finite OTP-like running key | key_tape | A | dict (vigenere pipeline) | **INVALID** — anomaly id |
| K2-coordinate-to-Kryptos azimuth as pre-Vigenere cyclic shift | k2_coords | B | None (correctly) | **INVALID** — anomaly id |
| Compass-rose 8-position Cardan grille | grille | A | dict (grille pipeline) | **INVALID** — anomaly id |
| KA-internal reflection as 2nd layer over Vigenere-on-KA | encoding | A | dict (atbash+vigenere) | **INVALID** — anomaly id |

The 4 "INVALID" rejections are **unrelated to dsl_spec quality** — they were rejected by the `anomalies_exploited` canonical-id check in `contracts.py::validate_theory_proposals`. Example rejection reasons:

- `"'anomalies_exploited' must contain only canonical anomaly_ids; invalid entries: ['k3_continuity as under-explored source material']"`
- `"'anomalies_exploited' must contain only canonical anomaly_ids; invalid entries: ['aaa_compass_cipher (tie to physical sculpture geometry specifically)']"`

The theorist used canonical anomaly_ids as prefixes but appended free-form commentary, which the exact-match validator rejected. **This is a secondary concern for a later hygiene pass.** The primary bug is different — see Q5.

---

## Question 2 — Which prompt section did the theorist follow?

**The theorist followed the DSL_SPEC CONTRACT correctly.** Three Category-A theories carry valid specs; two Category-B theories correctly set `dsl_spec=None`. The prompt integrity test (from R3-3) passes against this output.

Verified structurally:

| Theory | Category | `dsl_spec` shape | Correct? |
|---|---|---|---|
| #0 archive_evidence | B | `None` | ✓ Category B must have null per §2.1 |
| #1 key_tape | A | `{"pipeline": [{"kind": "vigenere", ...}], ...}` | ✓ |
| #2 k2_coords | B | `None` | ✓ |
| #3 grille | A | `{"pipeline": [{"kind": "grille", ...}], ...}` | ✓ |
| #4 encoding | A | `{"pipeline": [{"kind": "atbash"}, {"kind": "vigenere"}], ...}` | ✓ |

Worked examples A, B, C from DSL_CUTOVER_CONTRACT §1.3 were followed verbatim in shape. The prompt itself is not at fault.

---

## Question 3 — Did programmatic_fallback produce the "Explore X family" templates?

**Yes.** Source-verified at `kryptosbot/controller.py:1593`:

```python
theory = TheoryRecord(
    title=f"Explore {fam_info['name']} family",
    core_claim=f"K4 may use a mechanism from the {fam_info['name']} family",
    ...
)
```

All 5 ledger entries match this template shape exactly (titles "Explore Finite Key Tape (OTP-like) family", "Explore Geodetic family", etc.). The fallback branch at `controller.py:1080-1082` fires **when `report.valid` is empty**, not when validation is partial. See Q5 for why `report.valid` ended up empty despite the theorist's clean response.

---

## Question 4 — What category did each of the 5 fallback theories land in?

| Theory ID | Title | Family | Category | Critic | Red-team | Dispatched? |
|---|---|---|---|---|---|---|
| `8eb219b89a` | Explore Finite Key Tape (OTP-like) family | key_tape | **A** | REJECT_UNDERCONSTRAINED (Physical reassembly scope) | — | no |
| `8cd3222e33` | Explore Geodetic family | geodetic | **B** | APPROVE | REJECT (conf 0.82, "family-level fishing") | no |
| `e37ba83fc8` | Explore K2 Coords family | k2_coords | **B** | APPROVE | REJECT (conf 0.82, "family-level placeholder") | no |
| `554071758b` | Explore Mirror Ka family | mirror_ka | **A** | REJECT_UNDERCONSTRAINED (`dsl_untranslatable`) | — | no |
| `88956952b3` | Explore Overlay family | overlay | **A** | REJECT_UNDERCONSTRAINED (`dsl_untranslatable`) | — | no |

- **3 Category-A theories:** all critic-rejected (1 via prompt-surface scope, 2 via `dsl_untranslatable` — correct because fallback stubs have no spec).
- **2 Category-B theories:** both critic-approved, both red-team-rejected.
- **0 theories dispatched.** `experiments` table is empty.
- **D column = correctly 0 for this cycle.** The "D=0 is a defect" invariant doesn't fire here — nothing survived upstream gates to reach the dispatcher.

The 5th theory the earlier notification batch missed was `8eb219b89a` (key_tape, rejected at prompt-surface scope for physical-reassembly framing).

---

## Question 5 — Expected vs actual theorist output shape; is there a hidden template collision?

**Yes. The collision is at the SDK-message-to-text serialization boundary, not at the prompt level.**

### The flow

1. Theorist agent streams an `AssistantMessage` whose `content` attribute is a list of `ContentBlock` objects (thinking block + text block).
2. `controller.py:1028` stringifies the whole list with `text = str(message.content)`.
3. Python's `str()` on a list of `TextBlock` dataclasses returns a Python repr: `[TextBlock(citations=None, text='[\n  {\n    "title": "CT perturbation ...', type='text')]`.
4. `raw_chunks.append(text)` accumulates repr-strings.
5. `raw_output = "\n".join(raw_chunks)` — still repr-wrapped.
6. `validate_theory_proposals(raw_output)` calls `extract_json_block` which tries to find a `[{` JSON array.
7. `extract_json_block` has an intentional skip rule for `[ThinkingBlock`, `[TextBlock` patterns. It skips the outer `[TextBlock(...)`.
8. The scan then looks for a non-alpha `[` inside the quoted string value, but Python's repr uses single quotes. The scanner's `in_string` flag only tracks double quotes, so the scan ends up trying to parse chunks that include escaped newlines and mismatched quote state. It fails.
9. `report.valid` = 0 → `_programmatic_fallback` fires.

### Simulation confirmation

```python
fake_msg = f"[TextBlock(citations=None, text={theorist_text!r}, type='text')]"
validate_theory_proposals(fake_msg)
→ report.valid=0, report.invalid=1
```

Reproduces the exact ledger behaviour.

### Why R3-3's measurement passed one time

When the Claude Code CLI stream includes a `ResultMessage` at end-of-stream (with a `result: str` attribute), `controller.py:1024` handles it via `raw_chunks.append(str(message.result))` which preserves the raw text. When the stream only emits `AssistantMessage`s (the common case under `claude_agent_sdk`), line 1028's `str(message.content)` mangles the output.

The R3-3 measurement's run #1 and run #5 happened to include a `ResultMessage`; runs #2, #3, #4 and this K4 cycle 1 did not. R3-3 documented "non-deterministic fallback firing" as an operator-facing concern but attributed it to theorist reliability. The real cause is this serialization bug.

### Same class as R3-3's `dsl_spec: null` collision

R3-3 caught a template-default that silently overrode the contract documentation. This bug is structurally identical: a stringification assumption (`str(list_of_blocks)` → clean text) that silently breaks when the SDK yields list content instead of a result message. Both are format assumptions whose failure mode is silent fallback rather than an error.

---

## Fix — pre-K4 hygiene commit

**Change `controller.py:1027-1029` to extract text from ContentBlock lists properly:**

```python
elif hasattr(message, "content"):
    # R3 hygiene (2026-04-21): message.content is typically a list of
    # ContentBlock objects (TextBlock, ThinkingBlock, ToolUseBlock).
    # str(list_of_dataclasses) yields a Python repr that
    # extract_json_block cannot parse. Extract TextBlock text
    # specifically so the downstream validator sees raw JSON.
    content = message.content
    if isinstance(content, list):
        text_parts: list[str] = []
        for block in content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                text_parts.append(str(getattr(block, "text", "")))
            elif block_type == "thinking":
                # Thinking blocks are never JSON; skip them.
                continue
            elif hasattr(block, "text"):
                text_parts.append(str(block.text))
        text = "\n".join(text_parts) if text_parts else str(content)
    else:
        text = str(content)
    raw_chunks.append(text)
```

Same fix must be applied to the legacy worker path at `controller.py:2109` (symmetrical bug, same class).

**Test to add:** a unit test that feeds a synthetic `AssistantMessage.content = [TextBlock(text='[{"title":...}]')]` through the theorist parse path and asserts `report.valid` reflects the embedded theories — not the fallback.

---

## Halt-counter audit at cycle-1 halt

- `programmatic_fallback_cycles`: 1 (observed)
- `D column`: 0 (correctly — nothing survived upstream)
- `dsl_untranslatable` rejections: 2 (Category A fallback stubs)
- Category-B critic approvals: 2 (both red-team rejected)
- Matched-family null consultations: 0 (no alerts fired)
- REJECTED_ADMISSIBILITY contracts: 0 (no dispatch reached)

None of the halt conditions had fired yet. The operator halt was pre-emptive and correct — cycle 1's mortality signature already answered the diagnostic question.

---

## Meta-lesson

The R3-3 phase report flagged fallback-firing as a reliability concern but attributed it to theorist output. The real cause was one level deeper — the controller's message-stringification code. Both R3-3 and this run would have been caught by a single test: dispatch a synthetic AssistantMessage with a list of ContentBlocks through the theorist parse path.

The R3-3 validator-relaxation fix was a correct R3-era hardening but solved a different problem. It allowed malformed dsl_specs to pass boundary validation (so the critic could give a cleaner reject reason). It did NOT address the case where the parser never sees valid specs because the input is already mangled to Python-repr form.

The fix above is small (~15 lines in `controller.py`) and directly addressable. Pre-K4 hygiene class per operator instruction. No retry until it lands.

---

## Rollback posture

This run's ledger (`db/k4_run_2026_04_21_r3.sqlite`) contains 5 fallback theories + 0 experiments. They're all in `TheoryStatus.CRITICIZED` (dispatched to neither worker path). The ledger is safe to keep for audit or safe to delete. The fix + re-run will produce a new ledger regardless.

**No data loss. No escalation beyond operator's diagnostic commission. Ready for the hygiene commit and a fresh K4 run.**

*End of diagnostic. Next action: implement the fix, add unit test, commit as pre-K4 hygiene, then re-commission.*
