# Vertical Word Lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Test the hypothesis that the 28×31 Kryptos master grid is a cylindrical word lock — each row is a rotatable ring, and the correct offsets produce a meaningful 28-character word/phrase reading vertically down one of the 31 columns.

**Architecture:** Single self-contained script with three stages: (C) crib-anchored reverse engineering using K4 rows 24-27 to constrain vertical candidates, (A) dictionary/phrase search testing known keywords and wordlists as vertical alignments, (B) n-gram beam search for open-ended exploration of best vertical strings. Each stage produces scored results; the final output is a ranked JSON file.

**Tech Stack:** Python 3.11+ stdlib only (json, time, os, sys, itertools). Quadgram scorer from `kryptos.kernel.scoring.ngram`. Constants from `kryptos.kernel.constants`. Wordlist from `wordlists/english.txt`.

---

### Task 1: Create the script with panel data and core helpers

**Files:**
- Create: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Create script with metadata header, imports, and panel data**

```python
#!/usr/bin/env python3
"""
Cipher: vertical word lock (cylindrical rotation, vertical alignment)
Family: two_system
Status: active
Keyspace: ~50M (31 cols × beam + dictionary + crib-anchored)
Last run:
Best score:
"""
"""Vertical Word Lock Model for K4

Hypothesis: The 28×31 master cipher grid is a cylinder. Each row is
a rotatable ring (like a Jefferson cipher / combination lock). The
correct rotation offsets produce a meaningful 28-character word or
phrase reading VERTICALLY down one of the 31 columns.

Evidence:
- FIVE appears at row 0 with a single left-rotation
- KRYPTOS is 7 letters, 28/7=4 → KRYPTOS×4 = 28 chars exactly
- Coding chart arrows (→ line 1, ← line 2) = rotation direction
- Row 4 has 32 chars (overflow = one char wraps behind the cylinder)
- Code Room installation is literally a cylinder
- Sanborn's other works (Lingua, etc.) are cylindrical sculptures

Three stages:
C) Crib-anchored: K4 cribs constrain rows 24-27 of vertical
A) Dictionary + phrase search for 28-char vertical candidates
B) N-gram beam search (open-ended, no dictionary required)
"""

import sys
import os
import json
import time
from itertools import product as iterproduct

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS

# ── Full 28×31 master grid (868 characters) ──────────────────────────
# Source: NOVA-confirmed width-31 grid, cylinder_viewer.js PANEL_ROWS
# Row 4 (K2) has 32 chars — the only row with overflow
PANEL_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # 0   K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # 1   K1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # 2   K1→K2
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # 3   K2 (? = pass-through)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQ",   # 4   K2 (32 chars!)
    "ZGZLECGYUXUEENJTBJLBQCRTBJDFHRRY",   # 5   K2
    "IZETKZEMVDUFKSJHKFWHKUWQLSZFTIHH",   # 6   K2
    "DDDUVH?DWKBFUFPWNTDFIYCUQZEREEVL",   # 7   K2 (? = pass-through)
    "DKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLG",   # 8   K2
    "GTEZFKZBSFDQVGOGIPUFXHHDRKFFHQNT",   # 9   K2
    "GPUAECNUVPDJMQCLQUMUNEDFQELZZVRRG",  # 10  K2
    "KFFVOEEXBDMVPNFQXEZLGREDNQFMPNZG",  # 11  K2
    "LFLPMRJQYALMGNUVPDXVKPDQUMEBEDMH",   # 12  K2
    "DAFMJGZNUPLGEWJLLAETGENDYAHROHNL",   # 13  K2→K3
    "SRHEOCPTEOIBIDYSHNAIACHTNREYULDS",    # 14  K3
    "LLSLLNOHSNOSMRWXMNETPRNGATIHNRAR",   # 15  K3
    "PESLNNELEBLPIIACAEWMTWNDITEENRAHC",   # 16  K3
    "TENEUDRETNHAEOETFOLSEDTIWENHAEIO",    # 17  K3
    "YTEYQHEENCTAYCREIFTBRSPAMHHEWENA",    # 18  K3
    "TAMATEGYEERLBTEEFOASFIOTUETUAEOT",    # 19  K3
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPI",   # 20  K3
    "EROAGRIEWFEBAECTDDHILCEIHSITEGOE",    # 21  K3
    "AOSDDRYDLORITRKLMLEHAGTDHARDPNEO",    # 22  K3
    "HMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVD",  # 23  K3→K4
    "OHW?OBKRUOXOGHULBSOLIFBBWFLRVQQP",   # 24  K4 starts at col 4 (O)
    "RNGKSSOTWTQSJQSSEKZZWATJKLUDIAWI",   # 25  K4
    "NFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAU",   # 26  K4
    "EKCAR",                                # 27  K4 ends (5 chars)
]

WINDOW = 31  # visible columns in the cylinder window
K4_START_ROW = 24
K4_START_COL = 4  # K4's first char 'O' is at row 24, col 4 (after ?OBK)
K4_ROWS = range(24, 28)

# ── Precompute: for each row, build char→positions mapping ────────────
ROW_CHAR_AT = []  # ROW_CHAR_AT[row][col] = character at that position
ROW_LEN = []
for row_str in PANEL_ROWS:
    clean = row_str.replace("?", "")  # ? marks are non-positional
    ROW_CHAR_AT.append(clean)
    ROW_LEN.append(len(clean))
```

Wait — the panel data needs careful verification. Let me re-derive it from the confirmed 28×31 grid rather than hand-coding. The script should compute the grid from the known full cipher text.

Actually, looking at the existing cylinder_viewer.js, the PANEL_ROWS there are the authoritative source. But those include ? marks as positional. Let me use those directly and handle ? as a character that can appear in the cylinder.

Let me revise — the script will import the panel rows from the known data and handle the 32-char row and ? marks properly.

- [ ] **Step 2: Verify script file was created and imports work**

Run: `cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -c "import scripts.two_system.e_ts_vertical_wordlock" 2>&1 || PYTHONPATH=src python3 scripts/two_system/e_ts_vertical_wordlock.py --help 2>&1 | head -5`

- [ ] **Step 3: Commit scaffold**

```bash
git add scripts/two_system/e_ts_vertical_wordlock.py
git commit -m "feat: scaffold vertical word lock script (3-stage overnight run)"
```

---

### Task 2: Implement vertical character mapping and crib integration

**Files:**
- Modify: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Add vertical character extraction helpers**

For each column c (0..30) and each row i (0..27):
- Rotating row i by amount r means position `(c - r) % row_len` is visible at column c
- So: `visible_char(row, col, rotation) = ROW_CHARS[row][(col - rotation) % ROW_LEN[row]]`
- Inverse: `rotation_needed(row, col, target_char) = (col - pos_of_char_in_row) % ROW_LEN[row]` for each occurrence of target_char in that row

Build a lookup: for each row and each target letter A-Z (plus ?), what rotation(s) place that letter at a given column.

- [ ] **Step 2: Add K4 crib-to-grid position mapping**

K4 position p (0-96) maps to grid position: row = (K4_GLOBAL_START + p) // 31, col = (K4_GLOBAL_START + p) % 31. K4_GLOBAL_START = 24*31 + 4 = 748 (row 24, col 4, after the ? at col 3).

For crib positions (21-33, 63-73), compute which grid row and column each crib character occupies. This tells us: at the correct rotation for that row, what character MUST appear at each column.

- [ ] **Step 3: Commit**

---

### Task 3: Implement Stage C — Crib-Anchored Reverse Engineering

**Files:**
- Modify: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Implement Stage C logic**

For each of the 31 reference columns c:
1. For K4 rows (24-27), each crib character at grid position (row, col) constrains the rotation of that row. Given rotation r, the character at column c is `ROW_CHARS[row][(c - r) % row_len]`. But we know the rotation must place the correct crib character at the crib's column. So the rotation for row `row` is determined by its crib characters.
2. BUT: each K4 row has multiple crib characters, and they all must be consistent with a SINGLE rotation for that row. Check consistency.
3. For consistent rotations, read the vertical at column c for all 28 rows.
4. Score the vertical using quadgram scorer.
5. Also test vertical against known candidate strings (KRYPTOS×4, etc.)

- [ ] **Step 2: Print progress and top results**

- [ ] **Step 3: Commit**

---

### Task 4: Implement Stage A — Dictionary + Phrase Search

**Files:**
- Modify: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Build candidate vertical strings**

Sources:
- Repeated keywords: KRYPTOS×4, SEVEN×5+"SEV", ABSCISSA×3+"ABSC", etc.
- 28-char words from `wordlists/english.txt`
- Thematic phrases: concatenated words from `wordlists/thematic_keywords.txt` that total 28 chars
- K4-related phrases: "EASTNORTHEASTBERLINCLOCK" (24) + 4-char pad

- [ ] **Step 2: For each candidate, check feasibility at each column**

A 28-char vertical string V is feasible at column c if, for every row i, the character V[i] appears somewhere in ROW_CHARS[i]. If feasible, compute the rotation for each row and evaluate:
- Vertical match score (exact match to candidate)
- Horizontal K4 crib score (after applying those rotations, do K4 cribs align?)

- [ ] **Step 3: Commit**

---

### Task 5: Implement Stage B — N-gram Beam Search

**Files:**
- Modify: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Implement beam search**

For each column c (0..30):
1. Start with 28 empty slots
2. For row 0, seed the beam with each possible character at column c (one per rotation amount, up to row_len options)
3. For each subsequent row, extend each beam candidate with each possible character at that row, score the partial vertical using quadgrams on the last 4 characters, keep top `beam_width` candidates
4. After all 28 rows, score complete verticals and record top results
5. For top verticals, compute rotations and score K4 cribs horizontally

Beam width: 1000 (tunable). Total work: 31 columns × 28 rows × 1000 beam × ~31 extensions = ~27M operations. Should complete in minutes.

- [ ] **Step 2: Add combined scoring**

Combined score = weighted sum of:
- Vertical quadgram score (normalized per char)
- K4 crib match count (0-24)
- Bonus for known keyword matches in vertical

- [ ] **Step 3: Commit**

---

### Task 6: Add main driver, JSON output, and overnight monitoring

**Files:**
- Modify: `scripts/two_system/e_ts_vertical_wordlock.py`

- [ ] **Step 1: Wire up all three stages in main**

```python
if __name__ == "__main__":
    t0 = time.time()
    print("=" * 60)
    print("VERTICAL WORD LOCK — Overnight Run")
    print("=" * 60)

    results = {}

    # Stage C: Crib-anchored
    results["stage_c"] = run_stage_c()

    # Stage A: Dictionary + phrases
    results["stage_a"] = run_stage_a()

    # Stage B: Beam search
    results["stage_b"] = run_stage_b()

    # Summary
    results["elapsed_seconds"] = time.time() - t0
    results["overall_best_crib"] = max(
        results["stage_c"]["best_crib"],
        results["stage_a"]["best_crib"],
        results["stage_b"]["best_crib"],
    )

    with open(os.path.join(RESULTS_DIR, "e_ts_vertical_wordlock.json"), "w") as f:
        json.dump(results, f, indent=2)
```

- [ ] **Step 2: Add progress printing for overnight monitoring**

Each stage prints: start banner, periodic progress (every 10K configs), completion summary with best scores.

- [ ] **Step 3: Final commit and launch**

```bash
git add scripts/two_system/e_ts_vertical_wordlock.py
git commit -m "feat: vertical word lock — 3-stage overnight run (C/A/B)"
PYTHONPATH=src python3 -u scripts/two_system/e_ts_vertical_wordlock.py
```
