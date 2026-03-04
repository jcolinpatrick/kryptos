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

## What has been ELIMINATED
- ALL standard transpositions (columnar, double, triple, keyword, Myszkowski, AMSCO, rail fence,
  route, spiral, diagonal, scytale) -- 16M+ configs ZERO hits
- Affine and power permutations mod 97 -- ALL NOISE
- Direct Vig/Beau/VarBeau on carved text with ALL keywords -- NOISE
- SA hill climbing ceiling at -3.73/char (gibberish, not English)
- K3's exact method (double rotational transposition) on K4 -- NOISE
- YAR selective substitution -- stale premise (from old grille extract, corrected version has T)
- KRS frequency overlay on tableau -- IC not significant (E-GRILLE-KRS-01)
- Lower-half frequency equivalences -- statistically normal (E-FREQ-EQUIV-01)

## Rules
1. Write scripts in `scripts/`, run with: `cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/YOUR_SCRIPT.py`
2. If you find ANY crib hit (EASTNORTHEAST or BERLINCLOCK), IMMEDIATELY report it
3. Be COMPUTATIONAL -- write code, run it, analyze results, iterate
4. Focus on GRILLE CONSTRUCTION -- determining the binary mask is the goal
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
        "Tableau Structural Analysis -- Derive grille from Kryptos-only elements + KA signal",
        f"""\
## YOUR SPECIFIC MISSION: Derive the Grille from Kryptos Tableau Structure + KA Signal

The Kryptos tableau has THREE elements absent from Antipodes. The misspellings spell KA.
Your job: figure out how the KA alphabet structure and tableau elements define the mask.

### The three Kryptos-only elements:
1. **Key column** (col 0): blank, A-Z, blank -- in STANDARD AZ order, not KA
2. **Header/footer** (rows 0,27): ABCDEFGHIJKLMNOPQRSTUVWXYZABCD -- standard alphabet
3. **Extra L** on row N (row 14): 32 chars, only row that overflows the 31-col grid

### The KA signal from misspellings:
- K1 IQLUSION -> K, K3 DESPARATLY -> A = "KA" (Kryptos Alphabet)
- The KA alphabet itself may be the key to grille construction
- AZ->KA permutation: 17-cycle + 8-cycle + fixed Z

### 39 cipher-tableau matches:
- 39 cells where cipher[r][c] == tableau[r][c] -- ambiguous under grille
- Expected: 868/26 = 33.4. Observed: 39. Test if spatial pattern matters.
- At NON-match positions: hole shows tableau, solid shows cipher. Different outputs!

### Approaches (ordered by priority):
**A. AZ->KA cycle-based mask** -- 17-cycle letters -> hole, 8-cycle -> solid (or vice versa).
   For each grid cell (r,c), look at the CIPHER letter there. If it's in the 17-cycle of
   AZ->KA, mark as hole. If 8-cycle, mark solid. Z (fixed) = special.
**B. Key column vs KA body** -- The key column spells A-Z (AZ). Compare to what KA would give.
   The DIFFERENCE (AZ vs KA position) at each row = binary signal for that row.
**C. Header vs KA** -- Where headers DIFFER from KA body -> those columns are special.
**D. Extra L as instruction** -- L marks CUT POINT at row 14 (K3 center). Split upper/lower.
**E. Overlay difference mask** -- Construct "ideal" Kryptos tableau (pure KA body). Compare
   to ACTUAL tableau. Every cell that differs -> mark as hole/solid.
**F. Match-based seeding** -- Start with 39 cipher=tableau matches as candidate holes,
   constrain with 180 degree rotation and K3 verification.
**G. K3 calibration** -- K3 PT+CT both known. Apply each theory to K3 region first.

Write your main script as `scripts/blitz_tableau_structural.py`.""",
    ),

    "ka_cycle_grille": (
        "KA Cycle Grille -- Use AZ->KA permutation cycles to define the mask",
        f"""\
## YOUR SPECIFIC MISSION: Test AZ->KA Permutation Cycle Structure as Grille Definition

The misspellings spell "KA" -- pointing to the KA alphabet as the grille key.
The AZ->KA permutation has a specific cycle structure that may define hole vs solid.

### AZ->KA permutation:
AZ = ABCDEFGHIJKLMNOPQRSTUVWXYZ
KA = KRYPTOSABCDEFGHIJLMNQUVWXZ

Mapping AZ[i] -> KA[i] gives permutation:
  A->K, B->R, C->Y, D->P, E->T, F->O, G->S, H->A, I->B, J->C,
  K->D, L->E, M->F, N->G, O->H, P->I, Q->J, R->L, S->M, T->N,
  U->Q, V->U, W->V, X->W, Y->X, Z->Z

**Cycle decomposition:**
- 17-cycle: (A K D P I B R L E T N G S M F O H) -- contains all KRYPTOS letters
- 8-cycle: (C Y X W V U Q J)
- Fixed point: Z

### Approaches to test:
**A. Cycle membership mask** -- For each cipher grid cell (r,c), check if the LETTER
   at that position belongs to the 17-cycle, 8-cycle, or is Z.
   Test: 17-cycle = hole, 8-cycle = solid (and vice versa).
   How many holes land on K4? What letters do they read from tableau?
**B. Cycle INDEX mask** -- For each letter, its position within its cycle (0-16, 0-7)
   gives a numeric value. Use this value mod 2 to determine hole/solid.
**C. Permutation ORDER mask** -- AZ->KA permutation has order LCM(17,8) = 136.
   Apply the permutation N times to each letter. Test different N values.
**D. Apply cycle structure to TABLEAU positions** -- Instead of cipher letters,
   use the tableau letter at (r,c) to determine cycle membership.
**E. Row/column cycle interaction** -- Key column has AZ letters. Body has KA letters.
   The cycle membership of key_col[r] determines rule for entire row.
**F. Combined: cycle membership of (cipher[r][c] XOR tableau[r][c])** -- the
   difference between cipher and tableau at each position, mapped through cycles.
**G. Verify against K3** -- Apply each mask to K3 region, check if reading produces
   anything consistent with known K3 plaintext under Vig/KRYPTOS.

For EVERY mask variant, count holes in K4 region, read tableau letters at holes,
try Vig/Beau decryption with all keywords, score for English.

Write your main script as `scripts/blitz_ka_cycle_grille.py`.""",
    ),

    "rotation_180": (
        "180 degree Rotation Hypothesis -- Two-pass grille reading",
        f"""\
## YOUR SPECIFIC MISSION: Test the 180 degree Rotation Hypothesis

At 28x31 (not square), only 180 degree rotation works: (r,c) -> (27-r, 30-c).
The structural match is remarkable: 868/2 = 434 = K1+K2 = K3+?+K4.

### The theory
Position 1: grille reads 434 chars from the TOP half (K1+K2)
Position 2 (180 degree flip): grille reads 434 chars from the BOTTOM half (K3+?+K4)
The grille extracts EXACTLY one half per orientation.

### KA cycle integration
The AZ->KA 17-cycle/8-cycle/Z partition may define WHICH cells are holes:
- Test: 17-cycle cipher letters = hole in position 1, solid in position 2
- Under 180 degree flip, each cell switches role: hole <-> solid
- Combined with K3 calibration, this constrains the mask heavily

### Approaches to try:
**A. Symmetric mask search** -- For each cell (r,c) with r<14, assign hole or solid.
   The cell (27-r, 30-c) gets the OPPOSITE assignment. 434 positions to determine.
**B. K3 as calibration** -- K3 occupies rows 14-24. In 180 degree flip, these map to rows 3-13.
   Since K3's PT is known, the grille must read K3's real CT (Vig/KRYPTOS) at those positions.
**C. Half-grid enumeration** -- Only need 434 bits (one half), other half is complement.
**D. Column parity** -- col c <-> col 30-c. Columns pair up (except col 15).
**E. K4 in rotation** -- K4 at rows 24-27 maps to rows 0-3 under 180 degree.
   In position 1: read K1 chars at K4's reflected positions.
   In position 2: read K4 chars directly.

Write your main script as `scripts/blitz_rotation_180.py`.""",
    ),

    "k3_grille_verify": (
        "K3 Grille Calibration -- Use known K3 PT/CT to validate grille methods",
        """\
## YOUR SPECIFIC MISSION: Use K3 as Ground Truth for Grille Validation

K3's plaintext AND ciphertext are both known. K3 occupies rows 14-24 of the grid.
ANY valid grille theory must produce correct results when applied to K3.

### K3 facts:
- K3 CT: 336 chars, rows 14-24 col 0 to row 24 col 25
- K3 PT: SLOWLYDESPARATLY...CANYOUSEEANYTHINGQ (336 chars)
- K3 method: double rotational transposition (24x14 -> 8x42, self-inverting)
- K3 starts at EXACT center (row 14, col 0)
- K3 exact permutation formula:
  ```
  a = i // 24; b = i % 24
  intermediate = 14 * b + 13 - a
  c = intermediate // 8; d = intermediate % 8
  pt_pos = 42 * d + 41 - c
  # CT[i] = PT[pt_pos]
  ```
  Verified: 0 mismatches across all 336 positions.
- K3 DESPARATLY misspelling: PT[10] -> CT[89] = A (part of KA signal)

### KA signal integration:
- Misspellings spell KA -> test if KA cycle membership predicts K3 grille pattern
- For each K3 CT position, check if the cipher letter's cycle membership
  correlates with whether it's a "grille hole" (where tableau shows through)

### Approaches:
**A. Overlay analysis** -- Map K3 CT positions to tableau positions.
   For each K3 position, compare: cipher char, tableau char, known PT, known key.
   Which K3 positions have cipher == tableau? Do these form a pattern?
**B. KA cycle test on K3** -- Apply AZ->KA cycle-based mask to K3 region.
   Read tableau letters at "holes". Decrypt with Vig/KRYPTOS. Compare to known PT.
**C. K3 transposition from grille** -- Can the grille reproduce K3's double rotational
   transposition? GCD(21,28)=7=len(KRYPTOS). Column step pattern {7,7,7,3}.
**D. 180 degree rotation test** -- Under flip, K3 region (rows 14-24) maps to rows 3-13.
   Does K2 region show complementary structure?
**E. K3 as template for K4** -- If K3's grille pattern is found, extend it to K4 region.

Write your main script as `scripts/blitz_k3_grille_verify.py`.""",
    ),

    "instruction_decoder": (
        "K1-K3 Instruction Decoder -- Extract grille construction instructions from solved sections",
        f"""\
## YOUR SPECIFIC MISSION: Systematically Decode K1-K3 Solving Instructions

HYPOTHESIS: Kryptos is not solvable from K4 alone. The solved sections K1-K3 contain
instructions for constructing the K4 grille and decryption method. Different anomalies
serve different functions: misspellings encode "KA", plaintexts describe the method.

### Known instruction channels:
1. **Misspellings -> CT letters**: K1 IQLUSION->K, K3 DESPARATLY->A = "KA"
   - This tells us the KA alphabet is central to the grille
   - What other information might the CHANGED letters carry? (Q for L, A for E)
   - Q is in the 8-cycle, L is in the 17-cycle. A is in the 17-cycle, E is in the 17-cycle.

2. **K3 plaintext (Carter's tomb)**: "CAN YOU SEE ANYTHING?"
   - Looking through holes = grille instruction
   - "slowly...remains of passage debris" = methodical uncovering
   - "widening the hole a little" = iterative grille construction?
   - "I inserted the candle and peered in" = the grille IS the instrument of looking

3. **K2 plaintext**: Contains "LAYER TWO" and "IDBYROWS"
   - "Layer two" = the second system (grille + substitution)
   - "IDBYROWS" = rows-based reading order instruction?
   - "the information was gathered and transmitted underground" = hidden channel

4. **K1 plaintext**: "the nuance of IQLUSION"
   - Nuance = subtle distinction (between AZ and KA? between hole and solid?)
   - IQLUSION = the misspelling IS the nuance (points to K, first letter of KA)

5. **Structural anomalies**:
   - "8 Lines 73": 8 rows x ~9.1 holes = 73 holes? Period 8?
   - Extra L on row N: construction cut point?
   - Extra T on row V: V-N = T-L = 8
   - "T IS YOUR POSITION": T diagonal on KA tableau
   - 53 T's on cipher panel x 2 = 106 = old grille extract length

### What to compute:
**A. Misspelling letter analysis** -- The ORIGINAL letters (L, E) and their REPLACEMENTS
   (Q, A). Map these through AZ->KA cycles. What properties do they share?
**B. K3 plaintext keyword extraction** -- Extract meaningful keywords/phrases from K3 PT
   that could be grille construction parameters (numbers, spatial terms, etc.)
**C. K2 IDBYROWS interpretation** -- Test reading the cipher grid by rows in different
   orders. "ID BY ROWS" could mean identification/indexing by row number.
**D. Cross-reference K1-K3 numbers** -- K1=63 chars, K2=369 letters, K3=336 chars.
   These have specific factorizations. Do they encode grid parameters?
**E. "8 Lines 73" as grille spec** -- Lay K4 (97 chars) in 8 rows. 97=8x12+1.
   73 = 97 - 24 (number of crib positions). Test 73-hole grille patterns.
**F. T-position mechanism** -- Map all T positions in cipher grid. Do they form a
   pattern consistent with "T IS YOUR POSITION"?

Write your main script as `scripts/blitz_instruction_decoder.py`.""",
    ),

    "wildcard": (
        "Lateral & Creative -- Novel grille construction approaches",
        f"""\
## YOUR SPECIFIC MISSION: Creative Approaches to Grille Construction

Think outside the box. The grille pattern may follow rules nobody has considered.
Incorporate the KA-from-misspellings discovery into creative approaches.

### Approaches to try:
**A. KA as key to grille** -- "KA" from misspellings could mean: use the KA alphabet
   as a key for generating the grille. E.g., KA[i] mod 2 for column i determines
   hole pattern. Or KA index of each cipher letter mod N.
**B. "8 Lines 73" as grille spec** -- 8 rows x ~9 holes each = 73 holes? Or 73 holes total?
   "8 Lines 73" from Sanborn's yellow pad. 73 + 24 (cribs) = 97. 73 holes in grille?
**C. Fibonacci/prime positions** -- Holes at prime-numbered cells, Fibonacci indices, etc.
**D. KRYPTOS keyword as mask key** -- Use KRYPTOS (7 chars) to generate a repeating hole pattern
   across 31 columns: hole at col c if KA.index(KRYPTOS[c%7]) meets some condition
**E. K4 as self-referential** -- K4 characters define which of their own positions are holes
**F. KA tableau T-diagonal** -- "T IS YOUR POSITION": T appears on the main diagonal of
   the KA tableau. The T-diagonal could define hole/solid boundaries. 53 T's x 2 = 106.
**G. Checkerboard/chess knight pattern** -- Geometric patterns tested systematically
**H. XOR between cipher and tableau** -- (cipher_ord - tableau_ord) mod 26 encodes binary
   or maps to cycle membership for mask determination
**I. Physical Kryptos constraints** -- The grille must be physically cuttable from a sheet.
   Connected hole regions? No isolated holes?
**J. K3 answer = K4 start** -- K3 ends "CAN YOU SEE ANYTHING", K4 may start
   "YES WONDERFUL THINGS" (Carter's actual reply). Test this as a crib.

For EVERY approach, implement it, test it, and report results.
Write your main script as `scripts/blitz_wildcard_grille.py`.""",
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
