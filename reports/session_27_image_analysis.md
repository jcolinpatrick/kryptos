# Session 27: Auction Image Analysis — Complete Findings

**Date**: 2026-02-19
**Sources**: 52 images in `reference/Pictures/`, including 5 new auction items

---

## AUCTION ITEMS (NEW — highest priority)

### Letter_1.jpg — Sanborn Transcript [PUBLIC FACT if from published auction catalog]

A typed transcript of Sanborn speaking (likely at the 1990 dedication or shortly after). **Three bombshell statements:**

**Statement 1: "There are two systems of enciphering the bottom text"**
> "No one really asked me if there are two systems to encipher the bottom text until today at sort of the eleventh hour, and yes, there are two separate systems and that is a major clue in itself, apparently."

The "bottom text" is the lower copper plate containing K3 + K4. "Two separate systems" most likely means:
- K3 uses System A (known: columnar transposition + Vigenere with KRYPTOS keyword)
- K4 uses System B (unknown — **a different system from K3**)

Alternative reading: K4 itself uses two systems (substitution + transposition = two systems). Both interpretations support our multi-layer hypothesis.

**Statement 2: "I used that table to encipher the top plate"**
> Confirms Vigenere tableau was used for K1+K2 (top plate). The bottom plate uses "a much more difficult fashion."

**Statement 3: Layered progressive design**
> "The whole piece is designed to unveil itself, as if you were to pull up one layer, then you can come to the next, and you pull up another layer and you figure out the next."

**Statement 4: Four separate copper sheets**
> "These sheets are really composed of four separate copper sheets."

### Picture_2.jpg — Vigenere Tableau Fragment (FRONT) [PUBLIC FACT]

A curved copper piece showing three rows of a STANDARD Vigenere tableau:
- Row 1: **C D E F G H I J**
- Row 2: **D E F G H I J K**
- Row 3: **E F G H I J K L**

These are rows C, D, E of the standard tableau (alphabet shifts +2, +3, +4). This is a physical piece — a section cut from or study piece for the full Vigenere tableau on the left panel of the sculpture.

**Assessment**: This is almost certainly a K1/K2 artifact (the standard tableau), NOT the K4 "coding chart." The K4 coding system is described as "much more difficult" and likely involves non-standard elements not shown here.

### Picture_3.jpg — Vigenere Tableau Fragment (BACK)

The reverse of the same copper piece. Letters appear mirrored since they're cut through the copper. Reading the mirrored text from back confirms the front reading. No additional information beyond Picture_2.

### Picture_4.jpg — Sanborn's Handwritten Working Notes [PUBLIC FACT — CRITICAL]

Three yellow legal pad pages showing Sanborn's working notes during Kryptos construction (~1988-1990).

**Upper page**: K1-K3 plaintext written out in full:
> "Between subtle shading and the absence of light lies the nuance of iqlusion X IT was totally invisible..."
> (continues through K2 coordinates and "Layer Two")

Note: "iqlusion" (the K1 misspelling) is written this way in the original notes — confirming it's intentional, not a cutting error.

**Lower left page**: K3 plaintext with layout annotations:
> "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBBRIS..."
> (Carter tomb-opening account)

Key annotations in boxes:
- **"11 Lines"** | **"342"** — K3 section: 342 characters arranged in 11 lines (~31 chars/line)
- **"8 lines 73"** — [HYPOTHESIS] K4 section: possibly 8 lines, 73 related to some parameter

**Lower right page**: Contains:
- Phone numbers: "Ka 466-2010", "Museum of Art & Architecture — 658-5973", "Art Library — 454-2061" (Sanborn's research contacts, late 1980s)
- A boxed annotation that appears to read **"10.8 rows"** or similar
- A condensed version of the K3/K4 text ending with what appears to be the full Carter quote: "Can you see anything? Yes wonderful things."

### Picture_1.jpg — Auction Lot Close-up

Shows the yellow pad notes alongside a photograph of Sanborn working at a table (constructing the sculpture), plus documents including what appears to be a CIA contract.

---

## THE "10.8 ROWS" HYPOTHESIS [HYPOTHESIS — needs verification]

If the annotation on Sanborn's notes reads "10.8 rows" and refers to K4:

**97 / 9 = 10.778 ≈ 10.8**

This points to a **width-9 grid** (9 columns, ~11 rows), NOT width-7.

### Cross-correlation with existing evidence:

| Evidence | Width 7 | Width 9 |
|----------|---------|---------|
| K3 uses KRYPTOS keyword (7 letters) | Supports | — |
| Lag-7 autocorrelation (z=3.036) | Supports | — |
| Crib alignment GCD(21,63)=21=3×7 | Supports | GCD(21,63)=21=3×7 (also 3×3×...) |
| DFT peak at k=9 (period ~10.8) from E-S-25 | No support (k=14 BELOW expected) | **DIRECT MATCH** (97/9=10.78) |
| "10.8 rows" annotation | 97/7=13.86 (no match) | **97/9=10.78 ≈ 10.8** |
| Width-7 + periodic key tests | EXHAUSTIVELY ELIMINATED | Relatively UNTESTED as multi-layer |

**CRITICAL**: The DFT peak at k=9 (z≈2.83) from E-S-25 and the "10.8 rows" annotation BOTH point to width 9. Width-9 columnar as a transposition layer has NOT been tested as thoroughly as width-7 in the multi-layer context.

### What width-9 looks like:

```
97 = 9 × 10 + 7
Grid: 9 columns, 7 columns of 11 rows + 2 columns of 10 rows

O B K R U O X O G
H U L B S O L I F
B B W F L R V Q Q
P R N G K S S O T
W T Q S J Q S S E
K Z Z W A T J K L
U D I A W I N F B
N Y P V T T M Z F
P K W G D K Z X T
J C D I G K U H U
A U E K C A R . .
```

### What we should test (in order of priority):

1. Width-9 columnar (all 9!=362,880 orderings) + Vigenere/Beaufort periods 2-14
2. Width-9 columnar + running key from various sources
3. Width-9 Model B (transposition applied to CT, then substitute) vs Model A
4. Width-9 + autokey
5. Compare width-9 vs width-7 on identical tests

---

## "TWO SEPARATE SYSTEMS" — Implications

Sanborn's statement that K3+K4 use "two separate systems" has several interpretations:

**Interpretation A** (most likely): K3 and K4 each use a DIFFERENT encipherment method.
- K3 = transposition + Vigenere (known, solved)
- K4 = something DIFFERENT ("much more difficult")
- Implication: K4 may NOT be Vigenere-based at all

**Interpretation B**: K4 itself uses two systems layered together.
- System 1: transposition
- System 2: substitution
- Implication: Supports our multi-layer hypothesis

**Interpretation C**: The two systems are the Vigenere tableau (for K1/K2) and the "coding charts" (for K3/K4).

Under Interpretation A, our extensive testing of Vigenere/Beaufort after transposition may have been targeting the WRONG substitution family. If K4 uses a fundamentally different system from K3, then it might use:
- The "coding charts" (arbitrary substitution tables)
- A completely different cipher type
- Something that is "not a math solution" (Sanborn's quote)

---

## OTHER IMAGES — Assessment

### Cipher Panels (ciphertopleft through cipherlowerright)
The ciphertext is visible but the resolution doesn't allow character-level verification beyond what we already have. K4 area visible in lower-right panels starting with OBKR. Our existing CT transcription has been verified by E-S-125 (no single-character mutation improves scores).

### Vigenere Tableau (centeredtableau.jpg, tableau-overview.jpg)
The full standard 26×26 Vigenere tableau on the left panel. This is the K1/K2 decryption tool. Standard alphabet throughout — no mixed alphabets visible.

### Compass (compass1.jpg, compass2.jpg)
Compass rose set in courtyard ground. Related to "T IS YOUR POSITION" (K2) and magnetic north. Compass-derived key attempts already eliminated (E-S-123).

### Morse Code (morse1-12.jpg, morse-sos.jpg, morse-overview.jpg)
Dots and dashes cut into copper ground plates (K0). Various messages including an SOS pattern visible. K0→K4 links already tested and eliminated (E-S-112).

### Strata and Structure (strata1-4.jpg, block.jpg, digetal.jpg)
Geological strata formations and copper ground plates. Sanborn describes in Letter_1 how these relate to the building's geological line. The "digetal" (digital?) image shows Morse dots/dashes on a ground plate.

### Overview Images (overview, wideview, overview-with-pool)
Wide shots showing full installation: S-curve copper panel, petrified wood log, reflecting pool, stone bench, strata. No new cryptographic details at this resolution.

### gillogly-at-kryptos.jpg
Jim Gillogly visiting the sculpture. Historical interest only.

---

## ACTIONABLE FINDINGS

### Priority 1: Test Width-9 Hypothesis
The convergence of "10.8 rows" (97/9=10.78) with the DFT peak at k=9 is the strongest new lead. Width-9 has NOT been tested as the transposition layer in multi-layer models with the same rigor as width-7.

### Priority 2: Re-examine "Two Separate Systems"
If K4 uses a fundamentally different cipher from K3's Vigenere, we should test non-Vigenere substitution methods after width-9 (and width-7) transposition:
- Simple substitution (monoalphabetic) from non-keyword alphabets
- The "coding charts" model: arbitrary position-dependent substitution tables
- Non-alphabetic systems

### Priority 3: Verify "10.8 rows" Reading
The annotation resolution is limited. We should seek higher-resolution auction catalog images to confirm this reading.

### Priority 4: Full Carter Quote as Plaintext Extension
Sanborn's notes show "Can you see anything? Yes wonderful things." If K4 continues from K3, the text after "CAN YOU SEE ANYTHING" might be "YES WONDERFUL THINGS" or a variation — but this doesn't match the known cribs (EASTNORTHEAST, BERLINCLOCK) unless the full K4 text is longer than the encrypted portion.

---

## UPDATED MEMORY ITEMS

- **Auction transcript confirms**: "Two separate systems" for bottom plate, Vigenere for top plate only
- **Copper fragment**: Standard Vigenere tableau (rows C,D,E), likely K1/K2 artifact
- **"10.8 rows" annotation**: [HYPOTHESIS] suggests width-9 grid, correlates with DFT k=9 peak
- **"8 lines 73" annotation**: K4 physical layout parameter, interpretation uncertain
- **"Yes wonderful things"**: Carter quote continuation visible in Sanborn's notes

---

*Classification: [PUBLIC FACT] for auction items if from published catalog; [HYPOTHESIS] for width-9 interpretation.*
*Artifact: `reports/session_27_image_analysis.md`*
