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
    # Strongest survivors (pigeonhole letter-supply test)
    "KRYPTOS", "DEFECTOR", "COLOPHON", "ABSCISSA", "PARALLAX",
    # K-for-C hypothesis: Greek/German K where English uses C
    "KOMPASS", "KOLOPHON", "KRYPTA", "KRYPTEIA", "KLEPSYDRA",
    # Other thematic
    "PALIMPSEST", "SHADOW", "SANBORN", "SCHEIDT", "PEDESTAL",
    "MONOLITH", "SPYPLANE", "TOPOLOGY", "VERDIGRIS",
    # Legacy (kept for completeness)
    "BERLIN", "CLOCK", "EAST", "NORTH", "LIGHT", "ANTIPODES",
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
## MISSION: Solve K4 — Derive the Full Encryption Method

**PARADIGM (2026-03-09):** K4 REQUIRES two systems. This is now PROVEN, not hypothesized.

### CRITICAL PROOF: Single-Layer Periodic Sub is IMPOSSIBLE on Raw 97
ALL 6 cipher variants (Vigenère, Beaufort, Variant Beaufort × AZ, KA alphabets) at ALL
periods 1-26 have KEY CONFLICTS at crib positions. No repeating keyword of any length ≤26
can produce both EASTNORTHEAST and BERLINCLOCK at their confirmed positions in the 97-char
carved text. Pure transposition is also impossible (CT has 2 E's, cribs need 3).

**However**: Grille + substitution IS compatible with 24 fixed cribs. The cribs constrain
the COMBINED effect, not the grille alone. Constraints are mild (period 7: 17 equations
from 97! space). Two-system model REQUIRED.

### 73-Character Null Hypothesis — Two Open Models
Sanborn's legal pad: "8 lines" "73" for K4. Carved text = 97 chars. **97 - 73 = 24 nulls.**

**Model A** (null removal first): `97 carved → remove 24 nulls → 73-char real CT → sub → PT`
Cribs shift after null removal. ~1.66M configs tested: ZERO signal.

**Model B** (decrypt all 97): `97 carved → sub(all 97) → 97-char raw PT → read 73 via mask`
Cribs stay at stated positions. 24 PT chars are garbage. "Second level" = which 73 to read.
Model B is simpler (hand-executable), but since periodic sub on raw 97 is proven impossible,
the cipher must be non-periodic (autokey, running key, keyed differently) OR involve a
transformation before substitution.

**TRIPLE-24**: (1) 97-73=24, (2) EASTNORTHEAST(13)+BERLINCLOCK(11)=24, (3) Weltzeituhr=24 facets.
Punch card parallel: IBM 80-col card cols 1-72=data, 73-80=metadata (Scheidt's CIA era 1963-89).

### W-as-Delimiter / Null Marker
5 W's at positions [20, 36, 48, 58, 74] **bracket the cribs:**
- W at 20 → immediately BEFORE EASTNORTHEAST (21)
- W at 74 → immediately AFTER BERLINCLOCK (73)
- "(CLUE) what's the point?" — W IS the point/period (telegram delimiter)
- Creates 6 segments: 20, 15, 11, 9, 15, 22 chars
- W's may be 5 of the 24 nulls, leaving 19 unknown nulls

### Two Systems CONFIRMED [PRIMARY SOURCE, Sanborn Dedication Speech]
- "There are TWO SYSTEMS of enciphering the bottom text... a major clue in itself"
- "I used that table to encipher the top plate" → K1-K3 use Vigenère. K4 does NOT.
- "designed to UNVEIL ITSELF... pull up one layer, come to the next"
- K4 plaintext "is not standard English, would require a second level of cryptanalysis"
- Scheidt: "mirrors and obfuscation" — novelty is in COMBINATION, not complexity

### d=13 Anomaly [STRONGEST STATISTICAL SIGNAL]
Bean 2021: Beaufort keystream collisions at k%13 are **7.09× expected** (corrected).
Strongest deviation in entire profile. Period 13 = len(EASTNORTHEAST). Bean-compatible.
UNTESTED with null-removal model.

### K2 Coordinates Encode K4 Structure [CONFIRMED 2026-03-13]
K2's "coordinates" (38°57'6.5"N 77°8'44"W) are NOT real coordinates — they encode K4 constants:
- **38**: 3²+8²=**73** (PT length!), 3×8=**24** (null count!), 3+8=**11** (BERLINCLOCK length!)
  - 38 is the UNIQUE two-digit number where d₁²+d₂²=73 AND d₁×d₂=24
- **6.5**: 6.5×2=**13** (EASTNORTHEAST length!), 6+5=**11** (BERLINCLOCK!)
- **77**: 7×11=77 → **11**, 77-44=**33** (last ENE position!)
- **Mod-73 squaring chain**: 44²≡38, 38²≡57 (mod 73). K2 numbers form algebraic chain.
- **Affine map**: y = 27x + 21 (mod 97) maps latitude values to longitude values. 21 = ENE start!
- **A1Z26 word values**: DEGREES=63 (BERLINCLOCK start!), POINT=74 (post-crib!), SECONDS=79 (X position!), X=24 (null count!)
- **Operational mechanism UNKNOWN** — values confirmed but how they derive the cipher key is open.

### Grille as SELECTION MASK (not reorderer)
Old: Cardan grille reorders 97→97. **NEW: grille SELECTS 73 of 97 (null mask).**
This IS the original Cardan grille function — read through holes, ignore blocked positions.

## K4 Carved Text (97 chars)
```
{{K4_CARVED}}
```
K4 in grid: starts row 24 col 27, ends row 27 col 30 (4 rows).

## Cipher Grid (28 rows x 31 cols, corrected)
```
Row  0: EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV  K1
Row  1: JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF
Row  2: DVFPJUDEEHZWETZYVGWHKKQETGFQJNC  K1->K2
Row  3: EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG  K2
...
Row 24: ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR  K4 starts col 27
Row 25: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO
Row 26: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
Row 27: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR  K4 ends
```

## Key Constants
- Length: 97 (prime), IC: 0.0361, all 26 letters present
- Cribs (0-indexed): 21-33=EASTNORTHEAST, 63-73=BERLINCLOCK
- Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K
- Bean EQ: k[27]=k[65], 21 inequalities
- W positions in K4: [20, 36, 48, 58, 74]
- KA: {{KA}} (all 26 letters, keyword-ordered)
- AZ: {{AZ}}
- Bean-compatible periods: {{{{8, 13, 16, 19, 20, 23, 24, 26}}}}

## KA Vigenere Tableau (28 rows x 31 cols, physically engraved)
```
{{TABLEAU_STR}}
```

## Keyword Status
- **ELIMINATED**: HOROLOGE, ENIGMA (pigeonhole analysis, all 6 variants fail)
- **Strongest survivors**: KRYPTOS (5/6), DEFECTOR (4/6), COLOPHON (3/6), ABSCISSA (3/6)
- **NEW — K-for-C hypothesis**: Sanborn uses Greek/German K where English uses C (KRYPTOS=CRYPTOS).
  - **KOMPASS (5/6)** — German for COMPASS. References lodestone. Ties KRYPTOS for survival!
  - KOLOPHON (3/6) — Greek COLOPHON (final inscription). K4 is the last message.
  - KRYPTA (3/6) — German/Greek CRYPT.
  - KRYPTEIA (2/6) — Spartan secret police (ancient intelligence service!)
  - KLEPSYDRA (2/6) — Greek water clock (BERLINCLOCK theme + Kryptos pool)
- **Rescued by KA**: PARALLAX (KA-VBeau), VERDIGRIS (KA-Beau), SHADOW (KA-Vig)
- **Scoring blind spot**: If PT contains acronyms (CIA, KGB, DDR), quadgrams reject correct answers.
  Score by CRIB HITS primarily, not quadgrams, when testing permutations.
- Keywords: {{', '.join(KEYWORDS)}}
- Alphabets: AZ={{AZ}}, KA={{KA}}

## Grille Extract (100 chars, from corrected 28x31 grid)
```
{{GRILLE_EXTRACT}}
```
All 26 letters present. IC = 0.0416.

## K3 Parallel — Key Reference
- Legal pad: "14 Lines 342". 14 × 24 = 336 = exact carved K3 length
- K4: "8 lines 73". 97 - 73 = 24 nulls.
- K3 formula verified: 0 mismatches / 336 positions. 2 cycles of 168. Dominant step 7 = len(KRYPTOS).

## What's ELIMINATED — DO NOT RE-TEST
- **ALL periodic sub (Vig/Beau/VBeau × AZ/KA) periods 1-26 on raw 97-char text**: PROVEN IMPOSSIBLE (key conflicts at cribs)
- **Pure transposition on 97 chars**: IMPOSSIBLE (CT has 2 E's, cribs need 3)
- ALL single-layer ciphers on 97-char carved text (700B+ configs tested)
- ALL standard transpositions on 97 chars: 16M+ configs ZERO hits
- **POINT as keyword/parameter**: 31,600 configs (keyword, coordinate, compass, X-delimiter) ALL NOISE
- **Punch card null models**: ~1.6M configs (4x24, 8x12, IBM zone, two-keyword) ALL NOISE
- SA hill-climbing ceiling at -3.73/char on 97-char permutations
- ALL fractionation, Homophonic, ADFGVX, Hill, Bifid 5x5 (impossible, 26 letters)
- 50+ deterministic grille masks (cycle, checkerboard, Fibonacci, primes, etc.) ALL NOISE
- Gromark: 3.2B primers, ZERO matches. Affine mod 97. Mod-5 on carved text (35.6M keys).
- HOROLOGE/ENIGMA as keyword: eliminated by pigeonhole analysis
- **Total null-mask configs tested: ~2.2M — ALL NEGATIVE**
- **VIC cipher model** (straddling checkerboard + columnar trans): 130.7M configs, 0 hits — ELIMINATED
- **Four-Square** (single-layer): 200 forced-SA restarts max 23/24, NEVER 24/24, digraphic IC inconsistent — ELIMINATED
- **K2 numbers as direct cipher/transposition keys**: 1,928 configs, max 6/24 — ELIMINATED
- **MITM mono + periodic sub (p2-20) × structured transposition**: 244M configs, 0 hits — ELIMINATED
- **Multi-layer CoD (depth 3, known ops × known keys)**: 39.6M evals, best 9/24 — ELIMINATED

## How to test
```python
import sys; sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, score_text, score_text_per_char, has_cribs,
    vig_decrypt, beau_decrypt, apply_permutation, load_quadgrams,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)
```
Or kernel: `from kryptos.kernel.constants import CT, CRIBS`

## Rules
1. Write scripts in `scripts/grille/` or `scripts/campaigns/`
2. Run with: `PYTHONPATH=src python3 -u scripts/<path>`
3. If you find ANY crib match, IMMEDIATELY report it
4. Be COMPUTATIONAL — write code, run it, analyze results, iterate
5. **KEEP SCRIPTS SHORT** — under 200 lines. One focused idea per script.
6. Import constants from `kryptos.kernel.constants` — never hardcode CT/cribs
7. **FOCUS ON THE NULL-MASK PROBLEM**: which 24 of 97 positions are nulls?
8. Every null-mask candidate must be tested: remove nulls → decrypt 73-char CT → score
"""


# ---------------------------------------------------------------------------
# Reasoning preamble for REASONING-mode strategies
# ---------------------------------------------------------------------------

REASONING_PREAMBLE = f"""\
## CURRENT STATE (2026-03-09): Two Systems PROVEN Required + 73-Char Null Hypothesis

### CRITICAL PROOF (2026-03-09):
**No periodic substitution cipher works on the raw 97-char carved text.** ALL 6 variants
(Vig/Beau/VBeau × AZ/KA) at ALL periods 1-26 have key conflicts at crib positions.
Pure transposition also impossible (CT has 2 E's, cribs need 3). TWO SYSTEMS are
mathematically required, not just hypothesized.

### Two Open Models:
**Model A**: `97 carved → remove 24 nulls → 73-char CT → sub(keyword) → 73-char PT`
  - Cribs shift to new positions after null removal. ~1.66M configs tested: ZERO signal.
**Model B**: `97 carved → cipher(all 97) → 97-char raw PT → read 73 → real message`
  - Cribs stay at stated positions. 24 PT chars are garbage. Simpler for hand-solving.
  - But periodic sub on raw 97 is proven impossible, so cipher must be non-standard.

### KEY DISCOVERIES:
- **73-char hypothesis**: Legal pad "8 lines 73". Triple-24: (97-73), (13+11 cribs), (Weltzeituhr facets)
- **Two Systems CONFIRMED**: Sanborn dedication speech (primary source)
- **W-as-delimiter**: 5 W's at [20,36,48,58,74] bracket both cribs
- **Grille + sub compatible with 24 cribs**: Cribs constrain combined effect, not grille alone
- **d=13 anomaly**: Beaufort k%13 collisions 7.09× expected (corrected, strongest signal in Bean 2021)
- **Misspellings spell KA**: K1 IQLUSION→K, K3 DESPARATLY→A. Points to KA alphabet system.
- **Punch card parallel**: IBM cols 1-72=data, 73-80=metadata (Scheidt's CIA era)
- **"Simpler than people think"**: Sanborn/Scheidt repeatedly say this. Hand-executable.
- **K2 COORDINATES ENCODE K4 STRUCTURE** (2026-03-13): 38→(3²+8²=73, 3×8=24, 3+8=11),
  6.5→(×2=13, 6+5=11), 77→(7×11), mod-73 squaring chain (44²≡38≡57), affine y=27x+21 (mod 97),
  A1Z26 word values = K4 position pointers (DEGREES=63, POINT=74, SECONDS=79, X=24, SEVEN=65).
  Monte Carlo: ~1 in 180M by chance. Operational mechanism UNKNOWN.

### ELIMINATION LANDSCAPE (600+ experiments, ~700B+ configs):
- **ALL periodic sub on raw 97: PROVEN IMPOSSIBLE** (key conflicts at cribs)
- ALL single-layer ciphers on 97-char carved text: EXHAUSTED
- ALL standard transpositions + null masks: 16M+ transpositions, 1.66M null masks, ZERO hits
- POINT/coordinate/compass/X-delimiter: 31,600 configs ZERO signal
- SA ceiling at -3.73/char. Gromark: 3.2B primers ZERO.
- Only Bean-compatible periods: {{{{8, 13, 16, 19, 20, 23, 24, 26}}}}

### KRYPTOS FACTS:
- CT: {{K4_CARVED}}
- 97 chars (prime), all 26 letters present
- Cribs (0-indexed): 21-33=EASTNORTHEAST, 63-73=BERLINCLOCK
- Self-encrypting: CT[32]=PT[32]=S, CT[73]=PT[73]=K
- Bean EQ: k[27]=k[65], 21 inequalities
- K1: Vig/PALIMPSEST. K2: Vig/ABSCISSA. K3: Double rotational transposition.
- KA: {{KA}} (all 26 letters, keyed)
- Sanborn: "two separate systems... a major clue in itself"
- K4 PT "is not standard English" — telegram-style with W delimiters?
- "(CLUE) what's the point?" — W as period, compass pole, or meta-question
"""


# ---------------------------------------------------------------------------
# Agent-specific prompts (appended to the appropriate preamble)
# ---------------------------------------------------------------------------

_UNSCRAMBLE_PROMPTS: dict[str, tuple[str, str]] = {
    # name: (title, prompt)

    "null_mask_search": (
        "Null-Mask Search — Find the 24 null positions in K4",
        f"""## YOUR MISSION: Determine which 24 of K4's 97 positions are NULLS

The core computational problem: 97 carved chars contain 73 real CT + 24 nulls.
Remove the right 24 chars, and the remaining 73 decrypt to English with a simple keyword.

### Constraints
- Crib positions (21-33, 63-73) CANNOT be nulls — they anchor the real CT
- W positions [20, 36, 48, 58, 74] are strong null candidates (bracket cribs)
- Non-crib positions: seg1 0-20 (21 chars), seg2 34-62 (29 chars), seg3 74-96 (23 chars)
- All 24 nulls must come from these 73 non-crib positions

### Approaches (pick ONE, go deep):
**A. SA over null masks** — State = 24 null positions. Neighbor = swap one null with one
   non-null (both non-crib). Evaluate: remove nulls → 73-char CT → Vig/Beau decrypt with
   KRYPTOS/DEFECTOR/PARALLAX/COLOPHON → quadgram score. Anneal with 500K+ steps.
   Try both with and without W-positions fixed as nulls.

**B. W-constrained search** — Fix W positions [20,36,48,58,74] as 5 nulls. Search for
   19 more among 68 remaining non-crib positions. C(68,19) ≈ 10^16 but SA can explore this.
   After removing 24 chars, check for EASTNORTHEAST/BERLINCLOCK at compressed positions.

**C. Frequency-guided null selection** — Nulls may have distinctive frequency signature.
   If nulls were inserted as random letters, removing them should push IC toward English (0.067).
   Iteratively remove positions that most improve IC/quadgram score.

**D. Structural null patterns** — Test regular patterns: every 4th position (97/24 ≈ 4),
   every Nth from offset M, Weltzeituhr-clock-mapped positions, positions where cipher
   grid letter equals tableau letter (39 self-matching positions — 24 could be nulls from these).

Keep scripts under 200 lines. Write to `scripts/campaigns/`.""",
    ),

    "d13_exploitation": (
        "d=13 Anomaly — Exploit the strongest statistical signal in K4",
        f"""## YOUR MISSION: Exploit the d=13 Beaufort keystream anomaly

Bean 2021 found Beaufort keystream collisions at k%13 are **3.55× expected** — the single
strongest statistical deviation in K4. Period 13 = len(EASTNORTHEAST). This is untested
with the null-removal model.

### What's known
- d=13 is the strongest modular collision anomaly in Bean's analysis
- Period 13 is ELIMINATED by full 242-pair Bean check (7 Type 1 + 2 Type 2 violations), but d=13 anomaly in keystream statistics remains unexplained
- 13 is len(EASTNORTHEAST) — likely not coincidence
- If K4 uses period 13 substitution, any 13-letter keyword could work
- Under null removal, period structure changes: 73/13 ≈ 5.6 residues per class

### Approaches (pick ONE):
**A. Period-13 Beaufort + null removal** — For each null mask (24 positions removed),
   decrypt the 73-char CT with period-13 Beaufort using Bean-passing 13-letter keywords.
   Key constraint: k[27%13]=k[65%13] → k[1]=k[0]. SA search over null masks + keyword.

**B. Stehle Δ4=5 observation** — Bean noted an untested pattern at Δ4=5 (the 4th-order
   difference in keystream). Investigate: what cipher produces constant 4th differences?
   Test running-key or autokey models with period-13 structure.

**C. EASTNORTHEAST as period key** — If the period IS 13, the crib EASTNORTHEAST
   could BE the key (or derive the key). Test: use EASTNORTHEAST as Beaufort key on
   various null-reduced CTs. Or: EASTNORTHEAST defines the period structure, and a
   different 13-char key decrypts.

Keep scripts under 200 lines. Write to `scripts/campaigns/`.""",
    ),

    "two_system_pipeline": (
        "Two-System Decomposition — Systematically test System1 + System2 models",
        f"""## YOUR MISSION: Systematically test decomposed encryption models

Sanborn confirmed TWO SYSTEMS. The question is exactly how they compose:
```
PT → System1(?) → intermediate → System2(?) → carved text
```

### Known constraints
- System 1 is likely substitution (Vig/Beau with keyword on KA or AZ alphabet)
- System 2 involves expansion (73→97) via null insertion
- "Designed to unveil itself" — layers peel off in reverse order
- K4 PT "is not standard English" — suggests telegram/coded message (W delimiters?)

### Approaches (pick ONE):
**A. Reverse-order peeling** — Try System2 first (remove nulls → 73 chars), then System1
   (decrypt with keyword). Versus: System1 first (treat all 97 as CT, decrypt, then find
   73 meaningful chars among 97 decrypted chars). Which model produces better scores?

**B. Autokey / self-keying** — Instead of periodic keyword, test autokey Vigenère/Beaufort
   where the key extends using plaintext or ciphertext. With null removal, this changes
   the feedback chain. Test all autokey variants (PT-autokey, CT-autokey) on 73-char reduced texts.

**C. Double transposition + substitution** — K3 used double rotational transposition.
   K4 may use a DIFFERENT combination. Test: substitution (keyword) → transposition
   (rectangular grid, different dimensions: 73=prime so only 1×73 or 73×1 — BUT if nulls
   are in specific pattern, the 97 chars form a grid like 4×24+1 or similar).

**D. Berlin Clock base-5 encoding** — The Berlin Clock uses base-5 (rows of 4×5hr + 4×1hr).
   Test: interpret K4 letter positions mod 5 as encoding a base-5 number system.
   Or: group the 73 real chars into groups of 5 and decode.

Keep scripts under 200 lines. Write to `scripts/campaigns/`.""",
    ),

    "grille_as_selector": (
        "Grille as Selection Mask — Use Cardan grille to identify 73 real positions",
        f"""## YOUR MISSION: Construct a Cardan grille that selects 73 of 97 K4 positions

The Cardan grille's ORIGINAL function: holes reveal real text, blocked positions are nulls.
The grille selects which K4 positions are real CT vs. inserted nulls.

### Construction clues
- K4 occupies rows 24-27 of the 28x31 grid (4 rows × ~24-31 cols = 97 positions)
- The grille covers the FULL 28x31 grid; K4's portion has 73 holes and 24 solid cells
- AZ→KA permutation (17-cycle + 8-cycle + Z fixed) may define hole vs. solid
- Misspellings spell KA — pointing to KA cycle structure as construction key
- Key column (AZ order) + header/footer (standard alphabet) are Kryptos-only elements
- 39 positions where cipher[r][c] == tableau[r][c] could mark null positions
- Extra L at row N (14), extra T at row V (22): V-N = T-L = 8 (period-8 signal)

### Approaches (pick ONE):
**A. K3 calibration** — K3 PT+CT both known (336 positions). Any valid grille theory
   MUST produce correct results on K3. Build your grille construction, test on K3 FIRST.
   If it works for K3, apply to K4 to identify nulls.

**B. Cycle-based selection for K4 region** — For K4's 97 positions in the grid,
   determine each position's letter in the cipher grid AND the tableau. Use the
   AZ→KA cycle membership (17-cycle letter → hole, 8-cycle → solid, or vice versa)
   applied to the cipher-tableau RELATIONSHIP at each position.

**C. 180-degree rotation pairs** — Under (r,c)→(27-r,30-c), K4 maps to K1.
   At each K4 position, check its K1 partner. If K1 partner is "meaningful" (in solved
   plaintext), then K4 position is real. If K1 partner is a "filler" character, K4 position
   is a null. Use K1's known plaintext to classify.

Keep scripts under 200 lines. Write to `scripts/grille/`.""",
    ),

    "k2_algebraic": (
        "K2 Algebraic Exploitation — Derive cipher parameters from coordinate encodings",
        f"""## YOUR MISSION: Exploit K2's coordinate encodings to derive the K4 cipher key

### CONFIRMED K2 ENCODINGS (2026-03-13):
K2's "coordinates" (38°57'6.5"N 77°8'44"W) encode K4 structural constants:
- **38**: 3²+8²=73 (PT length), 3×8=24 (null count), 3+8=11 (BERLINCLOCK length)
  - 38 is UNIQUE: only two-digit number where d₁²+d₂²=73 AND d₁×d₂=24
- **6.5**: 6.5×2=13 (ENE length), 6+5=11 (BC length)
- **77**: 7×11=77→11, 77-44=33 (last ENE position)
- **Mod-73 chain**: 44²≡38, 38²≡57 (mod 73)
- **Affine map**: y = 27x + 21 (mod 97) maps lat→long values. 21 = ENE crib start.
- **A1Z26**: DEGREES=63 (BC start), POINT=74 (post-crib), SECONDS=79 (X pos), X=24 (null count)
- SEVEN=65 (Bean equality position k[27]=k[65])

These are CONFIRMED encodings (Monte Carlo: ~1 in 180M by chance). But the OPERATIONAL
mechanism is unknown — how do these parameters derive the actual cipher key?

### Approaches (pick ONE, go deep):
**A. Mod-73 operations on ciphertext** — Since 44²≡38≡57 (mod 73), try:
   - CT position p → p² mod 73 as transposition permutation
   - Squaring chain (44→38→57→6→36→...) as reading order for the 73 real chars
   - CT[i] mapped via x² mod 73 as substitution alphabet

**B. Affine transposition** — y = 27x + 21 (mod 97) maps positions.
   Tested directly (noise). But try: apply affine to 73-char CT (after null removal)
   using y = ax + b (mod 73) with a,b derived from K2 numbers.
   Candidates: a ∈ {{3,5,7,8,11,13,24,27,38,44,57}}, b ∈ same set.

**C. A1Z26 position pointers as key** — DEGREES=63, POINT=74, SECONDS=79 point to
   CT positions. Extract chars at these positions → derive key or alphabet.
   Combined with other A1Z26 values (NORTH=75, WEST=67, EIGHT=49, FORTY=84, FOUR=60)
   to build a keyword or key sequence.

**D. Number sequence as polyalphabetic key** — The numbers 38,57,6,5,77,8,44
   as a numeric key for Beaufort/Vigenère (mod 26). Or their digit sums (11,12,6,5,14,8,8).
   Or A1Z26 word values (63,74,79,24,...) mod 26 as key letters.

**E. Grid dimensions from K2** — 38,57,6,5,77,8,44 suggest grid dimensions.
   3×8=24 (null grid), 7×11=77 (cipher grid?), 7×7=49 (sub-grid).
   Test rectangular transpositions with K2-derived dimensions on 73-char CT.

Keep scripts under 200 lines. Write to `scripts/campaigns/`.""",
    ),

    "wildcard": (
        "Wildcard — Genuinely novel approaches",
        f"""## YOUR MISSION: Try something genuinely new that hasn't been tested

ALL standard approaches on 97 chars are exhausted. The 73-char null hypothesis is the
top lead but other models may exist.

### Genuinely unexplored ideas (pick ONE):
**A. "YES WONDERFUL THINGS" as K4 opening** — K3 ends "CAN YOU SEE ANYTHING" (Carter's
   question at Tutankhamun's tomb). Carter replied "Yes, wonderful things." Test
   "YESWONDERFULTHINGS" as PT at position 0 (18 chars). Combined with cribs, this gives
   42/97 known PT positions. Derive the keyword from these known positions and check consistency.

**B. Telegram with W-delimiters** — If W = STOP, K4 plaintext is a 6-segment telegram:
   `[20 chars]W[EASTNORTHEAST+2]W[11]W[9]W[4+BERLINCLOCK]W[22 chars]`
   What operational Cold War message fits this structure? Test known Cold War intelligence
   message formats (CRITIC, OPREP, FLASH messages) for pattern match.

**C. Physical sculpture geometry** — Kryptos is an INSTALLATION with 3 sites:
   - Site 1: Entrance (Morse + lodestone)
   - Site 2: NW courtyard (cipher sculpture)  
   - Site 3: E courtyard (calm pool, NO text)
   Bearings and distances between sites may encode parameters. Lodestone deflects ENE.
   K2 coordinates (38°57'6.5"N, 77°8'44"W) may point to Site 3.

**D. Maintenance timer as key** — Pump OFF + Light ON = 20:00-24:00 only.
   20 → position 20 → W (first delimiter). 24 → 24 nulls. 4-hour window → 4 K messages.
   8:00 pump start → "8 lines". These numbers may literally be parameters.

Keep scripts under 200 lines. Write to `scripts/campaigns/`.""",
    ),
}


_REASONING_PROMPTS: dict[str, tuple[str, str]] = {
    "null_position_theory": (
        "What structural rule determines which 24 positions are nulls?",
        """YOUR TASK: Reason about what RULE Sanborn used to decide where to insert 24 nulls.

KEY FACTS:
- 97 carved chars = 73 real CT + 24 nulls
- Crib positions (21-33, 63-73) are real, not nulls
- W positions [20, 36, 48, 58, 74] bracket the cribs — strong null candidates
- BERLINCLOCK references Weltzeituhr which has 24 facets
- "8 lines 73" from Sanborn's legal pad. K3: "14 lines 342", 14×24 = 336 = carved K3.
- Cardan grille = selection mask: holes = real text, blocked = nulls
- 39 grid positions where cipher == tableau (self-matching) — could 24 of these be nulls?

QUESTIONS:
1. If W's are 5 nulls, what rule determines the other 19? Regular spacing? Structural?
2. Could the Weltzeituhr's 24 facets map to 24 specific K4 positions?
3. Does the 4×31 K4 sub-grid have a natural 24-position subset (e.g., specific columns)?
4. Could K1-K3 plaintext encode the null positions for K4?
5. Is there a mathematical relationship: 97 = 73 + 24, 73 is prime, 24 = 4! = 3×8?
6. What if nulls were inserted at REGULAR intervals (every ~4th char from some offset)?

For each theory, define it concretely, predict the 24 positions, and rate plausibility (1-10).
Write analysis to results/null_position_theory.md""",
    ),

    "two_systems_theory": (
        "How do the TWO SYSTEMS compose to encrypt K4?",
        """YOUR TASK: Analyze Sanborn's confirmed "two separate systems" in light of the 73-char model.

CONFIRMED (Sanborn dedication speech, primary source):
- "There are TWO SYSTEMS of enciphering the bottom text"
- "a major clue in itself"
- "designed to UNVEIL ITSELF... pull up one layer, come to the next"
- K4 PT "is not standard English, would require a second level of cryptanalysis"
- Scheidt: "mirrors and obfuscation"

MODEL: PT → System1(substitution) → 73-char CT → System2(null insertion) → 97 carved

QUESTIONS:
1. System 1 = substitution. Is it Vigenère, Beaufort, or something else? Period?
2. System 2 = null insertion. How are null characters chosen? Random? Patterned? Related to key?
3. "Not standard English" + "second level of cryptanalysis" — is the PT a telegram with W-delimiters?
4. If PT is 73 chars with W-delimiters, and W's are also inserted as nulls, this is "mirrors"
5. "Unveil itself" = first remove nulls (System 2), then decrypt (System 1)?
6. Could the two systems share a key (e.g., same keyword determines both substitution AND null positions)?
7. K1-K3 used ONE system (Vigenère). K4 uses TWO. The "major clue" may be the count itself.

For each interpretation, describe concretely and rate plausibility (1-10).
Write analysis to results/two_systems_theory.md""",
    ),

    "installation_analysis": (
        "How does Kryptos-as-installation encode the K4 method?",
        """YOUR TASK: Analyze the spatial/physical installation as a clue system for K4.

KEY FACTS:
- Kryptos is an INSTALLATION, not just a sculpture. Three-site design:
  - Site 1: Entrance (Morse code + lodestone compass)
  - Site 2: NW courtyard (cipher sculpture + tableau)
  - Site 3: E courtyard (calm pool, NO text — absence is clue)
- Lodestone points ENE = EASTNORTHEAST crib. Absent from Antipodes = "one clue missing"
- K2 coordinates (38°57'6.5"N, 77°8'44"W) may point to Site 3
- USGS marker buried by Sanborn, removed by CIA, "still important"
- "Who says it is even a math solution?" (Sanborn, Spy Museum, Nov 2025)
- Carter parallel: workers' huts ON TOP of tomb = carved text ON TOP of real CT
- Pump OFF + Light ON = 20:00-24:00 only. 20→pos 20→W. 24→nulls. 4hrs→4 messages.
- CIA page: "bubbling pool symbolizes information being disseminated with unknown destination"

QUESTIONS:
1. What information does the 3-site spatial layout encode? Angles? Distances?
2. Why does Site 3 have NO text? What does "absence of information" tell us?
3. How does the maintenance timer (20:00-24:00) connect to K4 structure?
4. "Not a math solution" — does Sanborn mean the key is physical/spatial, not computational?
5. Could solving K4 require physically being at CIA HQ (measuring angles, reading in specific light)?

For each theory, rate plausibility (1-10).
Write analysis to results/installation_analysis.md""",
    ),

    "bespoke_cipher_design": (
        "What bespoke cipher would Scheidt design for a sculptor?",
        """YOUR TASK: Reason about what cipher Scheidt designed, given the 73-char + Two Systems paradigm.

CONSTRAINTS:
- Scheidt was CIA Crypto Center chairman (1963-1989), 36 CKM patents
- Method "never appeared in cryptographic literature" (Gillogly)
- Must be hand-executable (Sanborn encoded it physically, 1989-1990)
- Uses "two separate systems" — confirmed by Sanborn
- 73-char model: substitution + null insertion
- Novelty is in the COMBINATION, not computational complexity
- "Method is probably embarrassingly simple once seen" (cf. Copiale: 260 years, wrong assumption)

KEY INSIGHT: All Tier 2 eliminations assumed direct positional correspondence (CT[i]→PT[i]).
The null insertion BREAKS this assumption. Every "eliminated" single-layer cipher is REOPENED
as the substitution layer of a two-layer system where nulls are first removed.

QUESTIONS:
1. What null-insertion rule is elegant enough for an art installation?
2. Could the rule be self-keying: the plaintext tells you where the nulls go?
3. Is the "bespoke" element the null insertion pattern, not the substitution cipher?
4. How does a CIA crypto chief hide information in plain sight?
5. What makes this "embarrassingly simple" once you see it?

Write analysis to results/bespoke_cipher_design.md""",
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
    strategies["local_null_mask_sa"] = Strategy(
        name="local_null_mask_sa",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="SA over null-position masks: remove 24 chars, decrypt 73-char CT, score",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_d13_beaufort"] = Strategy(
        name="local_d13_beaufort",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Period-13 Beaufort sweep with null-removal variants (d=13 anomaly)",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_w_null_search"] = Strategy(
        name="local_w_null_search",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="W-constrained null search: fix 5 W's as nulls, search 19 more among 68 positions",
        priority=1,
        tags=("compute", "unscramble", "active"),
    )
    strategies["local_grille_selector"] = Strategy(
        name="local_grille_selector",
        category=StrategyCategory.UNSCRAMBLE,
        mode=StrategyMode.COMPUTE,
        description="Grille-based position selection: test grille constructions as null masks on K4",
        priority=2,
        tags=("compute", "unscramble", "active"),
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
