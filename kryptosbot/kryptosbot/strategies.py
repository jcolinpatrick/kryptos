"""
Unified strategy registry for KryptosBot.

All strategies live here — deduplicated from the 5+ files that previously
held them (run_blitz_campaign.py, run_bespoke_reasoning.py,
run_split_campaign.py, config.py, framework_strategies.py).

Strategies are organized by mode:
  AGENT      — Claude agent with code execution tools (the active mission)
  REASONING  — Claude agent without tools (pure thinking)
  COMPUTE    — Local CPU only, no API tokens

Updated 2026-03-04: Restructured for grille-focused paradigm.
  - Retired YAR selective sub (stale premise from old grille extract)
  - Merged grille_mask_construction + tableau_matching → tableau_structural
  - Added ka_cycle_grille (AZ→KA cycle-based mask construction)
  - Added instruction_decoder (K1-K3 plaintext as solving instructions)
  - Updated all preambles with KA-from-misspellings discovery
  - Retired old single-layer compute attacks
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class StrategyMode(str, Enum):
    """How a strategy executes."""
    COMPUTE = "compute"       # Local CPU only, no tokens
    AGENT = "agent"           # Agent with code execution tools
    REASONING = "reasoning"   # Agent without tools (pure thinking)


class StrategyCategory(str, Enum):
    """Cipher family or analytical approach."""
    UNSCRAMBLE = auto()       # Current mission: find the permutation
    REASONING = auto()        # Creative / theoretical reasoning
    TRANSPOSITION = auto()
    SUBSTITUTION = auto()
    POLYALPHABETIC = auto()
    HYBRID = auto()
    STATISTICAL = auto()
    KNOWN_PLAINTEXT = auto()
    LATERAL = auto()
    DISPROOF = auto()


# ---------------------------------------------------------------------------
# Strategy dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Strategy:
    """A single cryptanalytic approach to attempt against K4."""
    name: str
    category: StrategyCategory
    mode: StrategyMode
    description: str
    prompt: str = ""           # Agent-specific prompt (empty for COMPUTE)
    priority: int = 5          # 1 = highest
    tags: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Constants inlined for agent prompts (agents shouldn't waste turns reading)
# ---------------------------------------------------------------------------

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# Corrected grille extract (28x31 grid, R->E + squeezed ? removed)
GRILLE_EXTRACT_OLD = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN",
    "SCHEIDT", "BERLIN", "CLOCK", "EAST", "NORTH",
    "LIGHT", "ANTIPODES", "MEDUSA", "ENIGMA",
]

# -- 28x31 MASTER GRID (CONFIRMED 2026-03-03) --------------------------------
# Corrections from Antipodes:
#   1. BQCRTBJ -> BQCETBJ (UNDERGROUND cipher error R->E, NOT a misspelling)
#   2. 3rd K2 ? (GGTEZ?F) squeezed on Antipodes, removed -> 868 = 28x31 exactly
# Evidence: NOVA video 8/8 column matches, perfect 434/434 center split

FULL_CORRECTED_CT = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV"  # Row 0  (K1 starts)
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF"  # Row 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC"  # Row 2  (K1 ends col 0, K2 starts col 1)
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"  # Row 3  (K2, ? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"   # Row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR"   # Row 5  (corrected R->E)
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT"   # Row 6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER"   # Row 7  (K2, ? at col 9)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI"   # Row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK"   # Row 9  (squeezed ? removed)
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"   # Row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"   # Row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"   # Row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"   # Row 13 (K2 ends)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"   # Row 14 (K3 starts -- PERFECT CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"   # Row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"    # Row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"    # Row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"   # Row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT"    # Row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI"    # Row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"   # Row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"    # Row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"   # Row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"   # Row 24 (K3 ends col 25, ? col 26, K4 starts col 27)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"   # Row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"   # Row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"   # Row 27 (K4 ends)
)

# KA Vigenere Tableau (28 rows x 31 cols, as physically engraved)
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",  # Row 0: header
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",  # Row 1: key=A
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",  # Row 2: key=B
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",  # Row 3: key=C
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",  # Row 4: key=D
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",  # Row 5: key=E
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",  # Row 6: key=F
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",  # Row 7: key=G
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",  # Row 8: key=H
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",  # Row 9: key=I
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",  # Row 10: key=J
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",  # Row 11: key=K
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",  # Row 12: key=L
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",  # Row 13: key=M
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJ",  # Row 14: key=N (extra L anomaly)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row 15: key=O
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",  # Row 16: key=P
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",  # Row 17: key=Q
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",  # Row 18: key=R
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",  # Row 19: key=S
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",  # Row 20: key=T
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",  # Row 21: key=U
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",  # Row 22: key=V (extra T anomaly)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",  # Row 23: key=W
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",  # Row 24: key=X
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",  # Row 25: key=Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",  # Row 26: key=Z
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",  # Row 27: footer
]

TABLEAU_STR = "\n".join(TABLEAU_ROWS)

# Grid dimensions
GRID_WIDTH = 31
GRID_HEIGHT = 28

# Section boundaries (0-indexed positions in FULL_CORRECTED_CT)
K1_START, K1_END = 0, 63         # 63 chars
K2_START, K2_END = 63, 434       # 371 positional chars (369 letters + 2 ?'s)
K3_START, K3_END = 434, 770      # 336 chars
K4_BOUNDARY_Q = 770              # ? between K3 and K4
K4_START, K4_END = 771, 868      # 97 chars
K4_GRID_ROW = 24                 # K4 starts at row 24, col 27

# Legacy grille mask (variable widths, under revision)
GRILLE_MASK = """\
Row 01: 000000001010100000000010000000001~~
Row 02: 100000000010000001000100110000011~~
Row 03: 000000000000001000000000000000011~~
Row 04: 00000000000000000000100000010011~~
Row 05: 00000001000000001000010000000011~~
Row 06: 000000001000000000000000000000011~
Row 07: 100000000000000000000000000000011
Row 08: 00000000000000000000000100000100~~
Row 09: 0000000000000000000100000001000~~
Row 10: 0000000000000000000000000000100~~
Row 11: 000000001000000000000000000000~~
Row 12: 00000110000000000000000000000100~~
Row 13: 00000000000000100010000000000001~~
Row 14: 00000000000100000000000000001000~~
Row 15: 000110100001000000000000001000010~~
Row 16: 00001010000000000000000001000001~~
Row 17: 001001000010010000000000000100010~~
Row 18: 00000000000100000000010000010001~~
Row 19: 000000000000010001001000000010001~~
Row 20: 00000000000000001001000000000100~~
Row 21: 000000001100000010100100010001001~~
Row 22: 000000000000000100001010100100011~
Row 23: 00000000100000000000100001100001~~~
Row 24: 100000000000000000001000001000010~
Row 25: 10000001000001000000100000000001~~
Row 26: 000010000000000000010000100000011
Row 27: 0000000000000000000100001000000011
Row 28: 00000000000000100000001010000001~~"""

# K3 exact permutation formula (verified 0/336 mismatches)
# CT[i] = PT[pt_pos] where:
#   a = i // 24; b = i % 24
#   intermediate = 14 * b + 13 - a
#   c = intermediate // 8; d = intermediate % 8
#   pt_pos = 42 * d + 41 - c


# ---------------------------------------------------------------------------
# Shared preamble for AGENT-mode (unscramble) strategies
# ---------------------------------------------------------------------------

SHARED_PREAMBLE = f"""\
## MISSION: Construct the Cardan Grille for the 28x31 Kryptos Grid

**PARADIGM (2026-03-04):** The Kryptos cipher panel (28x31 = 868 chars) and the KA Vigenere
tableau (28x31 with key column included) have IDENTICAL dimensions. A Cardan grille (mask
with holes) mediates between them. The grille defines a scrambling/reading order for K4.

**THE QUESTION:** How is the grille constructed? The answer lies in THREE structural elements
that exist ONLY on Kryptos (not on Antipodes):
1. **Key column** (col 0): blank/A-Z/blank in STANDARD AZ order (not KA)
2. **Header/footer rows** (rows 0,27): ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (standard alphabet)
3. **Extra L on row N** (row 14): 32 chars instead of 31 -- the ONLY row that overflows

### MISSPELLING -> CT LETTER = "KA" -- KEY DISCOVERY (2026-03-04)
The two confirmed deliberate misspellings across K1-K3, when mapped to their CT positions,
spell **KA** -- the Kryptos Alphabet:
- K1 IQLUSION (Q for L) at PT[56] -> CT[56] = **K** (Vigenere, direct position)
- K3 DESPARATLY (A for E) at PT[10] -> CT[89] = **A** (transposition, exact permutation verified)
- K2 UNDERGRUUND is NOT a misspelling -- it was a cipher error (R->E), corrected on Antipodes

This points to the **KA alphabet system** as the key construction element for the grille.
The AZ->KA permutation has cycle structure: **17-cycle + 8-cycle + fixed Z**.
This partition may define hole vs. solid in the grille mask.

### KRYPTOS vs ANTIPODES TABLEAU -- KEY DISCOVERY (2026-03-04)
**Kryptos tableau**: 28 rows x 31 cols (with key column + headers) = **868 positions** = cipher grid
**Antipodes tableau**: 32 rows x 33 cols (pure KA, NO key column, NO headers) = 1056 positions
**Body content is IDENTICAL** (780 cells, zero mismatches). All differences are STRUCTURAL.

The key column makes Kryptos 28x31 = overlayable on cipher grid. Antipodes can't overlay.
These structural elements are FUNCTIONAL, not decorative -- they're the grille construction clues.

**Antipodes wrapping dimensions**: 33 cols = 26+7 (KRYPTOS length), 32 rows = 26+6.

### 28x31 Grid -- CONFIRMED (2026-03-03, high confidence)
- **868 = 28 x 31** -- with Antipodes corrections (squeezed 3rd K2 ? removed, R->E for UNDERGROUND)
- **8/8 NOVA video column readings match** Sanborn's working chart
- **Perfect center split**: top 14 rows = K1+K2 (434 chars), bottom 14 rows = K3+?+K4 (434 chars)
- **434 = 2 x 7 x 31**, 868 = 4 x 7 x 31, 7 = len(KRYPTOS)

### Model 2 -- CONFIRMED (but scramble mechanism UNKNOWN)
```
PT -> Cipher(key) -> real_CT -> SCRAMBLE(sigma) -> carved text
```
Periodic keys (KRYPTOS period 7, ABSCISSA period 8) are ALL VIABLE.
**CRITICAL**: We know scrambling exists but NOT where the grille fits in:
- Grille could define the scrambling permutation sigma
- Or grille could define a reading order
- Or grille could be part of the encipherment itself
- The relationship between grille, scramble, and cipher is OPEN

### 180 degree Rotation Hypothesis -- CRITICAL STRUCTURAL MATCH
At 28x31 (not square), 90 degree rotation is impossible. But 180 degree rotation works perfectly:
- (r,c) -> (27-r, 30-c)
- **868/2 = 434 = K1+K2 = K3+?+K4** -- the grid splits EXACTLY in half!
- Position 1: grille reads 434 chars (one half)
- Position 2 (180 degree flip): grille reads 434 chars (other half)
- K3 at row 14 col 0 = PERFECT center dividing line

### K1-K3 as Solving Instructions
The solved sections may contain grille construction instructions:
- K3 ends "CAN YOU SEE ANYTHING" -- looking through holes (grille instruction)
- K2 contains "LAYER TWO" / "IDBYROWS" -- two-layer system, row-based reading
- K1 describes "the nuance of IQLUSION" -- the misspelling IS the message (K -> KA)
- Previous decryptions provide the context needed to construct the grille

## K4 Carved Text (97 chars)
```
{K4_CARVED}
```
K4 in grid: starts row 24 col 27, ends row 27 col 30 (4 rows)

## Cipher Grid (28 rows x 31 cols, corrected)
```
Row  0: EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV  K1
Row  1: JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF
Row  2: DVFPJUDEEHZWETZYVGWHKKQETGFQJNC  K1->K2
Row  3: EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG  K2
Row  4: TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA
Row  5: QZGZLECGYUXUEENJTBJLBQCETBJDFHR
Row  6: RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT
Row  7: IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER
Row  8: EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI
Row  9: DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK
Row 10: FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ
Row 11: ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE
Row 12: DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP
Row 13: DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG  K2 ends
Row 14: ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI  K3 starts (CENTER)
Row 15: ACHTNREYULDSLLSLLNOHSNOSMRWXMNE
Row 16: TPRNGATIHNRARPESLNNELEBLPIIACAE
Row 17: WMTWNDITEENRAHCTENEUDRETNHAEOET
Row 18: FOLSEDTIWENHAEIOYTEYQHEENCTAYCR
Row 19: EIFTBRSPAMHHEWENATAMATEGYEERLBT
Row 20: EEFOASFIOTUETUAEOTOARMAEERTNRTI
Row 21: BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB
Row 22: AECTDDHILCEIHSITEGOEAOSDDRYDLOR
Row 23: ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE
Row 24: ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR  K4 starts col 27
Row 25: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO
Row 26: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
Row 27: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR  K4 ends
```

## KA Vigenere Tableau (28 rows x 31 cols, physically engraved)
```
{TABLEAU_STR}
```
Each tableau row = key letter (col 0) + 30 body chars (KA shifted).
Row 14 (key=N) has ANOMALOUS extra L. Row 22 (key=V) has extra T.

## Key Structural Facts
- Misspelling CT letters spell **KA**: K1 IQLUSION->K, K3 DESPARATLY->A
- AZ->KA permutation cycles: 17-cycle + 8-cycle + fixed Z
- Tableau anomalies: Extra L at row N (14), extra T at row V (22)
  - V-N = T-L = **8** (period-8 signal). L+T = 30 (body width).
  - "8 Lines 73" from Sanborn's yellow pad. 73 + 24 cribs = 97.
- 39 cells where cipher[r][c] == tableau[r][c] (ambiguous under grille)
- K3 PT/CT are BOTH known -> can verify any grille theory against K3
- K3 exact permutation formula verified (0 mismatches / 336 positions)

## Grille Extract (100 chars, from corrected 28x31 grid)
```
{GRILLE_EXTRACT}
```
All 26 letters present (T now appears). IC = 0.0416.

## Keywords
{', '.join(KEYWORDS)}

## Alphabets
- AZ: {AZ}
- KA: {KA}

## How to test
Import the pre-built harness:
```python
import sys; sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt, apply_permutation, load_quadgrams,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)
```

## What has been ELIMINATED -- DO NOT RE-TEST THESE
- ALL standard transpositions (columnar, double, triple, keyword, Myszkowski, AMSCO, rail fence,
  route, spiral, diagonal, scytale) -- 16M+ configs ZERO hits
- Affine and power permutations mod 97 -- ALL NOISE
- Direct Vig/Beau/VarBeau on carved text with ALL keywords -- NOISE
- SA hill climbing ceiling at -3.73/char (gibberish, not English)
- K3's exact method (double rotational transposition) on K4 -- NOISE
- YAR selective substitution -- stale premise (corrected extract has T)
- KRS frequency overlay on tableau -- IC not significant
- Lower-half frequency equivalences -- statistically normal
- **50+ deterministic grille masks EXHAUSTED (2026-03-05)**: cycle membership (C17/C8/Z),
  period-8 row/col, Fibonacci, prime positions, checkerboard, T-diagonal, cipher-tableau XOR/diff,
  KA parity, 180-degree Cardan rank, KRYPTOS periodic key, misspelling KA signal, cipher==tableau
  match positions, row/col header patterns, letter-value thresholds, complement masks.
  ALL scored in noise range (-5.0 to -7.9 quadgram). ZERO crib hits.
- **"Grille holes = tableau letters = PT" model DISPROVED**: self-encrypting positions give Z,G
  from tableau but known PT requires S,K. Model-level contradiction.
- **10x10 Fleissner pure transposition**: SA best 12/24 from 20 restarts (noise level).
  Pure Fleissner transposition without a substitution layer is very unlikely.

## Structural findings from prior campaigns (USE these, don't re-derive)
- K3 permutation = exactly 2 cycles of length 168. Order 168 = 8 x 7 x 3.
- K3 dominant step within rows is 7 (KRYPTOS length). Inverse has net stride ~47 = 336/7.
- 180-degree rotation: K4 (rows 24-27) <-> K1 (rows 0-3), K3 <-> K2. Zero overlap.
- 8-cycle K4 letters (C,J,Q,U,V,W,X,Y) have IC = 0.1233, anomalously high vs random 0.038.
- IDBYROWS maps to 8 grid rows {1,3,8,14,17,18,22,24} including K3 start (14) and K4 start (24).
- Known Vig keystream: ENE = BLZCDCYYGCKAZ, BC = MUYKLGKORNA -- NOT periodic.
- 3 question marks on sculpture + 97 K4 chars = 100 = 10x10. Grille extract = 100 chars.

## Rules
1. Write scripts in `scripts/grille/`, run with: `cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/grille/YOUR_SCRIPT.py`
2. If you find ANY crib hit (EASTNORTHEAST or BERLINCLOCK), IMMEDIATELY report it
3. Be COMPUTATIONAL -- write code, run it, analyze results, iterate
4. Focus on GRILLE CONSTRUCTION -- determining the binary mask is the goal
5. **KEEP SCRIPTS SHORT** -- under 200 lines. One focused idea per script. Do NOT write 1000-line megascripts.
6. **DO NOT re-test deterministic masks** -- 50+ patterns already exhaustively tested (see eliminations above).
   Instead focus on: constraint propagation, SA with novel objective functions, structural analysis.
7. **DO NOT reinvent infrastructure** -- use `data/english_quadgrams.json` for scoring, import from
   `kryptos.kernel.constants` for CT/cribs. Cipher functions: 5-line helpers, not 50-line frameworks.
"""


# ---------------------------------------------------------------------------
# Reasoning preamble for REASONING-mode strategies
# ---------------------------------------------------------------------------

REASONING_PREAMBLE = f"""\
## CURRENT STATE (2026-03-04): Grille Construction Paradigm

The carved K4 text is SCRAMBLED ciphertext. Model 2 is confirmed:
  PT -> Cipher(key) -> real_CT -> SCRAMBLE(sigma) -> carved text

A Cardan grille on the 28x31 grid mediates between the cipher panel and the KA
Vigenere tableau. The grille defines the scrambling/reading order.

### KEY DISCOVERY: Misspellings spell KA
- K1 IQLUSION -> CT letter K, K3 DESPARATLY -> CT letter A
- K2 UNDERGRUUND was a cipher error (NOT a misspelling)
- "KA" = Kryptos Alphabet. Points to KA system as grille construction key.
- AZ->KA permutation: 17-cycle + 8-cycle + fixed Z

### Three Kryptos-only structural elements (absent from Antipodes):
1. Key column (AZ order, not KA) -- makes tableau 28x31 = overlayable
2. Header/footer rows (standard AZ alphabet)
3. Extra L on row N (row 14) -- only row that overflows

### ELIMINATION LANDSCAPE (560+ experiments, ~700B+ configs):
- ALL single-layer ciphers on carved text: EXHAUSTED
- ALL standard transpositions: 16M+ configs ZERO hits
- SA ceiling at -3.73/char (gibberish)
- Only Bean-compatible periods: {{8, 13, 16, 19, 20, 23, 24, 26}}
- Simple periodic keys REOPENED under Model 2 (KRYPTOS/7, ABSCISSA/8)

### KRYPTOS FACTS:
- CT: {K4_CARVED}
- 97 chars (prime), all 26 letters present
- Known PT (0-indexed): pos 21-33 = EASTNORTHEAST, pos 63-73 = BERLINCLOCK
- Bean EQ: k[27]=k[65], 21 inequalities. Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K
- K1: Vigenere/PALIMPSEST. K2: Vigenere/ABSCISSA. K3: Double rotational transposition.
- KA alphabet: {KA} (all 26 letters, keyed)
- Sanborn: "two separate systems... a major clue in itself"
- Gillogly: K4 method "never appeared in cryptographic literature"
- Scheidt: CIA Crypto Center chairman 1963-1989, 36 CKM patents
- K3 ends "CAN YOU SEE ANYTHING" -- grille instruction (looking through holes)
- K2 ends with "LAYER TWO" / "IDBYROWS"
"""


# ---------------------------------------------------------------------------
# Agent-specific prompts (appended to the appropriate preamble)
# ---------------------------------------------------------------------------

_UNSCRAMBLE_PROMPTS: dict[str, tuple[str, str]] = {
    # name: (title, prompt)

    "tableau_structural": (
        "Tableau Structural Analysis -- Derive grille from Kryptos-only structural clues",
        f"""\
## YOUR MISSION: How do the Kryptos-only tableau elements construct the grille?

**DO NOT** test simple deterministic masks (cycle membership, checkerboard, etc.) -- 50+ already failed.
**DO** focus on structural RELATIONSHIPS that generate the mask algorithmically.

### Focus areas (pick ONE and go deep):
**A. Key column as permutation seed** -- Col 0 has AZ order while body has KA order.
   The AZ->KA permutation (17+8+1 cycles) applied to key column values could generate
   a row-by-row mask via some rule. Explore: does applying the permutation N times to
   each key letter produce a bit sequence? Does the cycle LENGTH (17 vs 8) at each row
   determine a property of that row's mask pattern?

**B. Extra L and Extra T as construction parameters** -- Row 14 has extra L, row 22 has extra T.
   V-N = T-L = 8. These could be key parameters: period 8, or split at row 14.
   Test: read the grid in 8-column strips with L/T determining strip boundaries.

**C. K3 calibration** -- K3 PT+CT both known (336 positions, 0 mismatches). ANY valid grille
   theory MUST produce correct results on K3. Build your theory, test on K3 FIRST.
   K3 permutation has 2 cycles of 168, dominant step-7.

Keep scripts under 200 lines. Test ONE hypothesis deeply rather than 10 superficially.
Write scripts in `scripts/grille/`.""",
    ),

    "fleissner_grille": (
        "Fleissner Turning Grille -- 10x10 grille on K4 + 3 question marks",
        f"""\
## YOUR MISSION: Deep Fleissner (turning) grille search on K4

### Key insight
K4 (97 chars) + 3 question marks on sculpture = 100 = 10x10.
The grille extract is exactly 100 characters. A Fleissner grille on 10x10
has 25 orbits x 4 rotations = 100 cells. This is a CLEAN fit.

### What's been tested
- Pure transposition Fleissner (no sub layer): SA best 12/24 from 20 restarts. Likely noise.
- Fleissner + periodic Vig/Beau (p=7,8): 0 fully consistent grilles in 5M random trials.
- Only ~10^-8 of the 4^25 = 10^15 search space has been sampled.

### What to do (pick ONE):
**A. Fleissner + SA with quadgram scoring** -- Instead of crib-only scoring, use full
   quadgram fitness. For each Fleissner grille, read K4 through the grille, apply
   Vig/Beau decrypt with KRYPTOS or ABSCISSA, score with quadgrams. SA-optimize
   the 25 orbit choices. This tests 4^25 grilles implicitly.

**B. Constraint propagation from cribs** -- For ABSCISSA/AZ Vig:
   real_CT[i] = (PT[i] + ABSCISSA[i%8]) mod 26. At 24 crib positions, this gives
   24 known real_CT values. Each must appear somewhere in K4. The Fleissner maps
   PT position -> grid cell. Use CSP to find valid orbit assignments.
   Key fixed points: sigma(32)=32 (since K4[32]=S=real_CT[32] under ABSCISSA shift A=0).

**C. Grille extract as orbit encoding** -- The 100-char grille extract might encode
   the Fleissner configuration. Group into 25 groups of 4 chars (one per orbit).
   Can the letter values determine which of the 4 cells in each orbit is the hole?

**D. Non-square Fleissner** -- The physical grid is 28x31 (not square).
   Test 180-degree rotation (434 holes, 2 orientations instead of 4).
   K4 positions pair with K1 positions under this rotation.

Keep scripts under 200 lines. Write scripts in `scripts/grille/`.""",
    ),

    "rotation_180": (
        "180-degree Rotation -- K4/K1 pairing and two-pass grille reading",
        f"""\
## YOUR MISSION: Exploit the 180-degree structural symmetry for K4

**ALREADY KNOWN** (don't re-derive):
- 868/2 = 434 = K1+K2 = K3+?+K4 (exact split)
- K4 (rows 24-27) <-> K1 (rows 0-3) under (r,c) -> (27-r, 30-c)
- K3 <-> K2 under same rotation
- 17 reading variants already tested -- all 3-5/24 (noise)

**DO NOT** test simple reflected readings or cycle-membership masks (already failed).

### What to do (pick ONE and go deep):
**A. K1 as key for K4** -- K1 CT at reflected K4 positions could be a running key or
   permutation key for K4. K1 is Vig/PALIMPSEST. Decrypt K1 reflected positions first,
   THEN use the K1 PT as a key element for K4. This uses the solved section as
   an instruction channel.

**B. K3 permutation extended to K4 via rotation** -- K3's exact permutation (2 cycles of 168,
   dominant step 7) maps K3 positions. Under 180-degree rotation, K3 maps to K2.
   Can we derive the K4 permutation by applying the K3 formula to the rotated grid?

**C. 8-cycle IC anomaly** -- K4 letters in the 8-cycle (C,J,Q,U,V,W,X,Y) have IC=0.1233
   (anomalously high). Under 180-degree rotation, where do these letters map?
   Do they cluster in K1? This could reveal structural information about the permutation.

Keep scripts under 200 lines. Write scripts in `scripts/grille/`.""",
    ),

    "k3_grille_verify": (
        "K3 Permutation Analysis -- Reverse-engineer grille construction from known K3",
        """\
## YOUR MISSION: Derive grille construction rules from K3's known permutation

**ALREADY KNOWN** (don't re-derive):
- K3 permutation: 2 cycles of 168, order 168 = 8x7x3, dominant step 7
- K3 formula: a=i//24, b=i%24, int=14*b+13-a, c=int//8, d=int%8, pt=42*d+41-c
- 0 mismatches across 336 positions
- Classical Cardan grille (half-mirror): 0/168 match
- KA cycle mask on K3: no genuine crib hits

### What to do (pick ONE):
**A. Grille reverse-engineering** -- K3's permutation is KNOWN exactly. If a grille
   produced this permutation, what properties must the grille have? For each K3 position i,
   the PT position pt_pos tells us where the grille sends position i. Can you factor
   this into a "grille reading order" (mask + reading direction)?

**B. K3 permutation modular structure** -- The formula uses divisors 24, 14, 8, 42.
   24 = K3_rows_in_grid? 14 = half_grid_height? 8 = ABSCISSA_length?
   42 = 6*7 = (KRYPTOS-1)*KRYPTOS? Map these parameters to grid structure.
   Can K4's permutation use analogous parameters scaled to K4's size?

**C. Step pattern analysis** -- K3 has dominant step 7 = len(KRYPTOS).
   What's the step pattern for K4 positions in the grid? The K4 subgrid is
   4 rows x 31 cols (roughly). If K4 uses ABSCISSA (8), the dominant step might be 8.
   Test permutations with step-8 structure on K4.

Keep scripts under 200 lines. Write scripts in `scripts/grille/`.""",
    ),

    "instruction_decoder": (
        "K1-K3 Instruction Decoder -- Extract actionable parameters from solved sections",
        f"""\
## YOUR MISSION: Extract ACTIONABLE construction parameters from K1-K3

**ALREADY KNOWN** (don't re-derive):
- Misspellings spell KA (K from IQLUSION, A from DESPARATLY)
- IDBYROWS maps to 8 grid rows {{1,3,8,14,17,18,22,24}}
- Known keystream is non-periodic
- "8 Lines 73": 73 + 24 cribs = 97

**DO NOT** just list observations. Each finding must produce a TESTABLE permutation or mask.

### What to do (pick ONE):
**A. IDBYROWS as grille reading order** -- The 8 rows {{1,3,8,14,17,18,22,24}} include
   K3 start (14) and K4 start (24). Read the grid in this row order, then remaining rows.
   Does this reordering + Vig/Beau produce anything? Test systematically with all keywords.

**B. "8 Lines 73" as a 73-hole grille** -- Construct a mask with exactly 73 holes on K4's
   97 positions (73 = 97-24 non-crib positions). The 24 crib positions could be "solid"
   (pass-through), while 73 positions are reordered. SA search over 73-position permutations.

**C. K3's "CAN YOU SEE ANYTHING" as literal grille instruction** -- K3 describes peering
   through a hole. The PHYSICAL act of looking through the grille at the cipher panel
   gives you the PT. What if each solved section's PT tells you WHICH CELLS to look through
   for the NEXT section? K1 PT -> K2 grille, K2 PT -> K3 grille, K3 PT -> K4 grille.
   Test: extract a mask from K3 PT (letter values, positions of specific letters, etc.)
   and apply to K4 region.

Keep scripts under 200 lines. Write scripts in `scripts/grille/`.""",
    ),

    "wildcard": (
        "Wildcard -- Novel approaches that haven't been tried",
        f"""\
## YOUR MISSION: Try something genuinely new

**IMPORTANT**: 50+ deterministic mask patterns and 16M+ standard transpositions have ALL failed.
DO NOT test more masks (cycle, checkerboard, parity, Fibonacci, primes, etc.) -- they're exhausted.

### Genuinely unexplored ideas (pick ONE):
**A. K4 starts "YES WONDERFUL THINGS"** -- K3 ends "CAN YOU SEE ANYTHING" (Carter's question).
   Carter actually replied "Yes, wonderful things." Test "YESWONDERFULTHINGS" as a crib at
   position 0 (21 chars). Combined with existing cribs, this gives 45/97 known PT positions.
   With 45 known PT + any keyword, derive constraints on the permutation.

**B. Permutation from grille extract** -- The 100-char grille extract
   `HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD`
   could directly encode the permutation. Try: KA-index of each letter as a position number
   (mod 97), rank ordering, or use pairs of letters as 2-digit base-26 numbers.

**C. SA on full 97-element permutation with Vig/ABSCISSA** -- Forget grille construction.
   Directly SA-search the permutation sigma where K4[sigma(i)] = real_CT[i], with
   real_CT[i] = Vig_encrypt(PT[i], ABSCISSA[i%8]). Score with quadgrams on the full PT.
   Fix sigma(32)=32 (known fixed point under ABSCISSA). 500K steps x 20 restarts.
   This is the most direct attack on Model 2.

**D. Double transposition** -- K3 uses double rotational transposition. K4 might use
   a DIFFERENT double transposition. Try: columnar(key1) then columnar(key2) for
   key lengths 3-9. Or route cipher followed by columnar. Brute-force small key lengths.

Keep scripts under 200 lines. Write scripts in `scripts/grille/`.""",
    ),
}


_REASONING_PROMPTS: dict[str, tuple[str, str]] = {
    "grille_theory": (
        "How does the KA signal from misspellings construct the Cardan grille?",
        """\
YOUR TASK: Reason deeply about how the KA alphabet signal from misspellings
connects to Cardan grille construction.

KEY FACTS:
- K1 misspelling IQLUSION maps to CT letter K
- K3 misspelling DESPARATLY maps to CT letter A (via exact transposition permutation)
- K2 UNDERGRUUND was NOT a misspelling (cipher error, corrected on Antipodes)
- Together: K, A = "KA" = Kryptos Alphabet designation
- AZ->KA permutation has cycle structure: 17-cycle + 8-cycle + fixed Z
- The 17-cycle contains ALL letters of KRYPTOS (K,R,Y,P,T,O,S)
- The 8-cycle contains C,J,Q,U,V,W,X,Y
- Z is a fixed point

- Kryptos tableau is 28x31 (same as cipher grid) due to key column + headers
- Antipodes tableau is 32x33 (pure KA, no key column)
- These structural differences are FUNCTIONAL -- they enable grille overlay

QUESTIONS TO REASON ABOUT:
1. Does the 17/8/1 cycle partition directly define hole vs solid?
2. Is KA a keyword for generating the grille pattern (like a keyed columnar)?
3. Could the misspelled letters themselves (Q, A) carry additional information?
   Q is in the 8-cycle, A is in the 17-cycle. L is 17-cycle, E is 17-cycle.
4. How does "8 Lines 73" connect to the 8-cycle length?
5. Could the grille be self-keyed: each solved section provides the key for the next?
6. What is the relationship between the extra L (row N) and the KA cycle structure?

For each theory:
- Define it CONCRETELY with step-by-step construction
- Predict how many holes it produces and where
- Explain how it connects to other known facts
- Rate plausibility (1-10)

Write your analysis to results/grille_theory_analysis.md""",
    ),

    "two_systems_grille": (
        "How do 'two separate systems' manifest as grille + substitution?",
        """\
YOUR TASK: Analyze how Sanborn's "two separate systems" maps to the
grille-based paradigm: system 1 = Cardan grille (scrambling/permutation),
system 2 = substitution (Vigenere/Beaufort with keyword).

KEY CONTEXT:
- Model 2: PT -> Cipher(key) -> real_CT -> SCRAMBLE(sigma) -> carved text
- The Cardan grille defines sigma (the scrambling permutation)
- The substitution cipher uses a keyword (KRYPTOS period 7 or ABSCISSA period 8)
- "A major clue in itself" -- the TWO-NESS is important
- K3 used transposition + Vigenere/KRYPTOS -- but K4's transposition is novel

QUESTIONS:
1. In what ORDER are the two systems applied? Does it matter?
2. Could "two systems" refer to the two orientations of the grille (180 degree)?
3. How does the grille interact with the Vigenere key period?
4. Scheidt's CKM patents involve key-splitting. Does the grille split the key?
5. "IDBYROWS" -- could this describe the grille reading order?
6. Are there exactly two pieces of information needed: the mask + the keyword?

For each interpretation, describe it concretely and rate plausibility (1-10).
Write your analysis to results/two_systems_grille.md""",
    ),

    "bespoke_cipher_design": (
        "What bespoke cipher would a CIA crypto chief design for a sculptor?",
        """\
YOUR TASK: Reason about what cipher Scheidt would design, given the grille paradigm.

CONSTRAINTS:
- Scheidt was CIA's top cryptographer (1963-1989)
- Method has "never appeared in cryptographic literature" (Gillogly)
- Must be executable by hand (Sanborn encoded it physically in 1989-1990)
- Uses "two separate systems" (Sanborn)
- We now know: Cardan grille + substitution. The grille is novel, not the substitution.
- Misspellings spell KA. Tableau is designed for overlay. 180 degree structural match.
- 560+ experiments with ~700B+ configs have all produced NOISE on carved text

The NOVELTY is in the grille construction method, not the cipher itself.
What construction method would a CIA crypto chief choose that:
1. Is derivable from the sculpture's own structure
2. Has never appeared in literature
3. Is elegant enough for an art installation
4. Uses the KA alphabet as a key element

Write your analysis to results/bespoke_cipher_design.md""",
    ),

    "receiver_identity": (
        "How does 'receiver identity protection' manifest in 97 characters?",
        """\
YOUR TASK: Analyze Scheidt's "receiver identity protection" concept in context
of the grille paradigm.

CONTEXT:
- Scheidt discussed "receiver identity protection" at ACA 2013
- Medieval guild crypto: verify membership without revealing the guild
- "IDBYROWS may not be a mistake" -- Scheidt
- The grille is a PHYSICAL object -- only someone with the grille can read K4
- The grille extract (100 chars from tableau through grille holes) may be a
  membership verification string

CRITICAL INSIGHT: If the grille must be physically constructed to solve K4,
then the sculpture itself IS the receiver identity -- you must be AT Kryptos
(or have accurate measurements) to derive the grille.

For each proposed mechanism, rate plausibility (1-10).
Write your analysis to results/receiver_identity.md""",
    ),
}


# ---------------------------------------------------------------------------
# Strategy registry -- THE single source of truth
# ---------------------------------------------------------------------------

def _build_strategies() -> dict[str, Strategy]:
    """Build the unified strategy dictionary."""
    strategies: dict[str, Strategy] = {}

    # -- UNSCRAMBLE agents (current mission) -------------------------
    for name, (title, prompt) in _UNSCRAMBLE_PROMPTS.items():
        strategies[name] = Strategy(
            name=name,
            category=StrategyCategory.UNSCRAMBLE,
            mode=StrategyMode.AGENT,
            description=title,
            prompt=prompt,
            priority=1,
            tags=("unscramble", "active"),
        )

    # -- REASONING agents --------------------------------------------
    for name, (title, prompt) in _REASONING_PROMPTS.items():
        strategies[name] = Strategy(
            name=name,
            category=StrategyCategory.REASONING,
            mode=StrategyMode.REASONING,
            description=title,
            prompt=prompt,
            priority=3,
            tags=("reasoning",),
        )

    # -- COMPUTE strategies (local CPU, no tokens) --------------------
    strategies["local_grille_index"] = Strategy(
        name="local_grille_index",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Grille extract -> numeric index permutations (mod97, rank, inv_rank)",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_180_mask_enum"] = Strategy(
        name="local_180_mask_enum",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Enumerate 180-degree rotation compatible masks with K3 calibration",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_ka_cycle_masks"] = Strategy(
        name="local_ka_cycle_masks",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Enumerate masks based on AZ->KA cycle membership (17-cycle/8-cycle/Z)",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_reading_orders"] = Strategy(
        name="local_reading_orders",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Identity, reverse, boustrophedon, col-major, spiral, S-curve reading orders",
        priority=2,
        tags=("compute", "unscramble"),
    )

    # -- LEGACY strategies (kept for reference, not run by default) ---
    strategies["yar_selective_sub"] = Strategy(
        name="yar_selective_sub",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.AGENT,
        description="[RETIRED] YAR Selective Substitution -- stale premise from old grille extract",
        prompt="RETIRED: YAR premise was based on old grille extract. Corrected extract has T present.",
        priority=9,
        tags=("legacy", "retired"),
    )
    strategies["grille_mask_construction"] = Strategy(
        name="grille_mask_construction",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.AGENT,
        description="[RETIRED] Merged into tableau_structural",
        prompt="RETIRED: Merged into tableau_structural strategy.",
        priority=9,
        tags=("legacy", "retired"),
    )
    strategies["tableau_matching"] = Strategy(
        name="tableau_matching",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.AGENT,
        description="[RETIRED] Merged into tableau_structural",
        prompt="RETIRED: Merged into tableau_structural strategy.",
        priority=9,
        tags=("legacy", "retired"),
    )
    strategies["local_columnar"] = Strategy(
        name="local_columnar",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] Columnar unscramble -- exhaustively eliminated",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["local_key_derivation"] = Strategy(
        name="local_key_derivation",
        category=StrategyCategory.HYBRID,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] Key derivation chains -- exhaustively eliminated",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["local_tableau_keys"] = Strategy(
        name="local_tableau_keys",
        category=StrategyCategory.LATERAL,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] KA tableau key extraction -- superseded by grille approach",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["local_positional_keys"] = Strategy(
        name="local_positional_keys",
        category=StrategyCategory.HYBRID,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] Position-dependent keys -- superseded by grille approach",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["local_text_running_key"] = Strategy(
        name="local_text_running_key",
        category=StrategyCategory.KNOWN_PLAINTEXT,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] Installation text running key -- exhaustively eliminated",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["local_alphabet_mapping"] = Strategy(
        name="local_alphabet_mapping",
        category=StrategyCategory.SUBSTITUTION,
        mode=StrategyMode.COMPUTE,
        description="[RETIRED] Alphabet mapping keys -- exhaustively eliminated",
        priority=9,
        tags=("compute", "legacy"),
    )
    strategies["vigenere_analysis"] = Strategy(
        name="vigenere_analysis",
        category=StrategyCategory.POLYALPHABETIC,
        mode=StrategyMode.AGENT,
        description="[RETIRED] Vigenere/Beaufort analysis -- exhaustively eliminated on carved text",
        prompt="RETIRED.",
        priority=9,
        tags=("legacy",),
    )
    strategies["hybrid_trans_vig"] = Strategy(
        name="hybrid_trans_vig",
        category=StrategyCategory.HYBRID,
        mode=StrategyMode.AGENT,
        description="[RETIRED] K3-style trans+Vig -- exhaustively eliminated",
        prompt="RETIRED.",
        priority=9,
        tags=("legacy",),
    )
    strategies["crib_extension"] = Strategy(
        name="crib_extension",
        category=StrategyCategory.KNOWN_PLAINTEXT,
        mode=StrategyMode.AGENT,
        description="[RETIRED] Crib extension -- assumes direct positional correspondence",
        prompt="RETIRED.",
        priority=9,
        tags=("legacy",),
    )
    strategies["keyed_tableau"] = Strategy(
        name="keyed_tableau",
        category=StrategyCategory.LATERAL,
        mode=StrategyMode.AGENT,
        description="[RETIRED] Keyed tableau attacks -- superseded by grille approach",
        prompt="RETIRED.",
        priority=9,
        tags=("legacy",),
    )

    return strategies


STRATEGIES: dict[str, Strategy] = _build_strategies()


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def build_prompt(
    strategy: Strategy,
    project_root: Path | None = None,
    db: Any = None,
) -> str:
    """Construct the full agent prompt: preamble + strategy-specific content.

    Args:
        strategy: The strategy to build a prompt for.
        project_root: Project root (unused currently, reserved for DB injection).
        db: ResultsDB instance for injecting disproof ledger (optional).
    """
    if strategy.mode == StrategyMode.COMPUTE:
        return strategy.prompt  # Compute strategies don't need agent prompts

    if strategy.mode == StrategyMode.REASONING:
        preamble = REASONING_PREAMBLE
    else:
        preamble = SHARED_PREAMBLE

    parts = [preamble, strategy.prompt]

    # Inject disproof ledger if DB is available
    if db is not None:
        try:
            disproof_log = db.get_disproof_log()
            if disproof_log:
                lines = ["\n## ALREADY DISPROVED -- do NOT re-test:"]
                for entry in disproof_log[:20]:
                    lines.append(
                        f"  - {entry['strategy']}: {entry['criteria']}"
                    )
                parts.append("\n".join(lines))
        except Exception:
            pass

    # Append verdict block instruction for all agents
    parts.append(
        "\n## MANDATORY OUTPUT\n"
        "At the END of your response, include:\n"
        "```verdict\n"
        '{"verdict_status": "<disproved|promising|inconclusive|solved>", '
        '"score": <number>, "summary": "<one-line>", '
        '"evidence": "<key evidence>", "best_plaintext": "<if any>"}\n'
        "```"
    )

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def get_strategies(
    mode: StrategyMode | None = None,
    category: StrategyCategory | None = None,
    tags: set[str] | None = None,
    names: list[str] | None = None,
) -> list[Strategy]:
    """Filter strategies by mode, category, tags, or names."""
    result = list(STRATEGIES.values())

    if names:
        name_set = set(names)
        result = [s for s in result if s.name in name_set]
    if mode is not None:
        result = [s for s in result if s.mode == mode]
    if category is not None:
        result = [s for s in result if s.category == category]
    if tags:
        result = [s for s in result if tags & set(s.tags)]

    result.sort(key=lambda s: (s.priority, s.name))
    return result
