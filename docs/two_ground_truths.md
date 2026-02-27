# Two Ground Truths: Physical Sculpture vs Sanborn's Intent

**Date:** 2026-02-27
**Rationale:** The IDBYROWS/XLAYERTWO discrepancy proves that the physical copper and Sanborn's
intended message are NOT the same thing. Both ground truths matter for K4 analysis because:
(a) any decryption method must work on the actual ciphertext cut in copper, and (b) Sanborn's
stated corrections tell us what the ciphertext SHOULD produce, revealing where errors entered.

---

## Ground Truth A: Physical Sculpture Reality

### What a person standing at the sculpture would see and read.

No interpretation, no corrections — copper as cut circa 1989-1990.

#### Kryptos (CIA Headquarters, Langley VA)

| Property | Value |
|----------|-------|
| K1 cipher letters | 63 |
| K2 cipher letters | 369 (+ 3 literal `?` = 372 total chars) |
| K3 cipher letters | 336 (+ 1 boundary `?` = 337 total chars) |
| K4 cipher letters | 97 |
| Total cipher letters | 866 |
| Total characters (incl. `?`) | 869 (866 letters + 3 K2 `?` marks, not counting K3/K4 boundary `?`) |
| `?` marks on cipher side | 4 total (3 in K2, 1 at K3/K4 boundary) |
| Periods (`.`) | 0 — NONE on Kryptos |
| Apostrophes (`'`) | 0 — NONE (HOW'S → HOWS) |
| YAR superscript | PRESENT — Y, A, R raised above baseline near K3 start |
| Extra L on tableau | PRESENT — row N has one extra character |
| Justification | Ragged right |
| K2 ending (decrypted) | ...IDBYROWS (NOT XLAYERTWO) |
| K2 position ~115 (decrypted) | UNDERGRUUND (NOT UNDERGROUND) |
| Section order | K1 → K2 → K3 → K4 |

**K2 delimiter X positions (physical sculpture, 0-indexed within K2):**
- Position 67: CT letter `A` — between "IT WAS TOTALLY INVISIBLE" and "HOWS THAT POSSIBLE"
- Position 137: CT letter `S` — between "THEY USED THE EARTHS MAGNETIC FIELD" and "THE INFORMATION..."
- Position 198: CT letter `T` — between "...THAT LOCATION" and "DOES LANGLEY KNOW ABOUT THIS"
- Position 250: CT letter `T` — between "...THIS DISCOVERY" and "THEY SHOULD ITS BURIED..."

**Only 4 delimiter X on physical sculpture.** The 5th (between WEST and LAYERTWO) does not exist.
The physical sculpture decrypts its ending as: `...IDBYROWS` — "ID BY ROWS."

#### Antipodes (Hirshhorn Museum, Washington DC)

| Property | Value |
|----------|-------|
| K3 cipher letters | 336 (1 fewer than Kryptos — `?` replaces final cipher letter) |
| K4 cipher letters | 97 (IDENTICAL to Kryptos) |
| K1 cipher letters | 63 (IDENTICAL to Kryptos) |
| K2 cipher letters | 369 (3 fewer than Kryptos — `?` replaces 3 cipher Q's) |
| Per-cycle total | 865 letters (4 fewer than Kryptos's 869 total chars) |
| Full sculpture | 1,584 letters across ~1.83 cycles |
| `?` marks | Present at K3/K4 boundary + 3 in K2 (same positions as Kryptos) |
| Periods (`.`) | 2 — in `S.` and `F.` on Row 22 (W.W. position) |
| Apostrophes | 0 |
| YAR superscript | ABSENT |
| Extra L on tableau | ABSENT |
| Justification | Full justification (both margins flush) |
| K2 ending (decrypted) | ...IDBYROWS (same as Kryptos — both pre-2006 correction) |
| K2 position ~115 (decrypted) | UNDERGROUND (correct spelling — differs from Kryptos) |
| Section order | K3 → K4 → K1 → K2 (repeating) |
| Space between sections | ONE space at K4→K1 boundary (Pass 1 only, Row 13) |

**Critical:** Antipodes and Kryptos were BOTH built before the 2006 correction. Neither has ever
been physically modified. Both decrypt K2's ending as IDBYROWS, not XLAYERTWO.

#### K4 ciphertext — identical on BOTH sculptures

```
OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
```

This is confirmed by four-source match (CLAUDE.md, ct.txt, Antipodes Pass 1, Antipodes Pass 2).
K4 has NO known errors or corrections. Whatever method works must work on THIS exact text.

---

## Ground Truth B: Sanborn's Stated Intent

### What Sanborn says the sculpture SHOULD say (corrections, coding charts, verbal statements).

These are not on the copper. They come from public statements, private communications, and
the original coding charts (now in the hands of the $962,500 auction buyer).

#### Corrections and Intended Text

| Issue | Physical Sculpture | Sanborn's Intent | When Revealed |
|-------|-------------------|-----------------|---------------|
| **K2 ending** | IDBYROWS | XLAYERTWO | 2006 (Sanborn contacted Kryptos Group) |
| **K2 UNDERGROUND** | UNDERGRUUND (Kryptos) / UNDERGROUND (Antipodes) | UNDERGROUND | Original coding charts show correct spelling |
| **K1 keyword** | PALIMPCEST (produces IQLUSION) | Coding charts show ILLUSION correctly | 2020 (Sanborn: "to mix it up") |
| **K3 DESPERATELY** | DESPARATLY | Sanborn REFUSED TO ANSWER | Never confirmed/denied |
| **K0 DIGITAL** | DIGETAL | "implied deliberate" | Never confirmed outright |
| **K2 ? marks** | Literal `?` on copper | Cipher Q's in coding system (Q enciphers ?) | Original method |

#### K2 Under Sanborn's Intent

If the X-omission is restored:
- K2 would have **373 cipher characters** (369 letters + 3 ? + 1 restored X)
- Or: **370 cipher letters** (369 + 1 restored X) + 3 literal `?`
- The ending decrypts as: `...WESTXLAYERTWO`
- There would be **5 delimiter X** at positions [67, 137, 198, 250, 361]
- The 5th gap (250→361 = 111) breaks the decreasing-by-9 pattern (70, 61, 52, ...)

#### What Sanborn Has Said About the Method

| Statement | Source | Classification |
|-----------|--------|---------------|
| "I generally don't answer method questions, suffice it to say the NSA tried many layered systems on it" | Direct communication 2026-02 | [PRIMARY SOURCE] |
| "kryptos is available to all" | Direct communication 2026-02 | [PRIMARY SOURCE] |
| "Who says it is even a math solution?" | Spy Museum Nov 2025 | [PUBLIC FACT] |
| "They discovered it. They did not decipher it. They do not have the key. They don't have the method." | Re: Kobek/Byrne 2025 | [PUBLIC FACT] |
| Berlin Clock is "A reminder" | Direct communication 2026-02 | [PRIMARY SOURCE] |
| BERLINCLOCK = Weltzeituhr (World Clock at Alexanderplatz) | Open letter Aug 2025 | [PUBLIC FACT] |
| "The codes within Kryptos are about delivering a message" | Open letter Aug 2025 | [PUBLIC FACT] |
| K5 = 97 chars, "similar but not identical" coding to K4 | 2025 disclosures | [PUBLIC FACT] |
| "You could not make any mistake with 1,800 letters" | Earlier interview | [PUBLIC FACT] |

---

## Ground Truth Divergence Map

Where the two ground truths DISAGREE — these are the analytically critical points.

| # | Feature | Physical (A) | Intent (B) | Divergence Type |
|---|---------|-------------|------------|----------------|
| 1 | K2 ending | IDBYROWS | XLAYERTWO | Omitted cipher letter (X) |
| 2 | K2 UNDERGROUND | UNDERGRUUND (Kryptos only) | UNDERGROUND | Transcription error (E→R) |
| 3 | K1 keyword | PALIMPCEST | PALIMPSEST? (disputed) | Keyword spelling |
| 4 | K3 DESPERATELY | DESPARATLY | UNKNOWN (Sanborn refused) | ???  |
| 5 | K2 ? marks | Literal `?` characters | Cipher Q's | Display vs encoding |
| 6 | K3 final character | `?` replaces cipher letter (Antipodes) | Cipher letter present (Kryptos) | Sculpture-specific |
| 7 | W.W. dots | No dots (Kryptos) / S.F. dots (Antipodes) | Unknown which is "correct" | Sculpture-specific |
| 8 | YAR superscript | Present (Kryptos only) | Never addressed by Sanborn | ???  |
| 9 | Extra L | Present (Kryptos only) | "Accidental" per Sanborn | Claimed error |

### Implications for K4

**K4 ciphertext is IDENTICAL across both ground truths.** No corrections have been announced for K4.
This means:
1. Any decryption method must produce valid plaintext from the K4 CT as-is
2. The method itself may depend on which ground truth you use for OTHER sections (K1-K3)
3. "LAYER TWO" (from Ground Truth B) is an instruction — but the physical sculpture says "ID BY ROWS"
4. Both "LAYER TWO" and "ID BY ROWS" could be meaningful operational instructions

**The critical question:** Did Sanborn build the encryption method around the PHYSICAL copper
(errors included), or around his INTENDED text (coding charts)? The UNDERGRUUND divergence
suggests the physical copper has transcription errors, but the Antipodes having the CORRECT
spelling suggests Sanborn was aware and chose differently for each sculpture.

---

## Operational Rules for This Project

[POLICY] **Always specify which ground truth** when referencing K2 character counts, delimiter
positions, or section lengths.

[POLICY] **K4 is ground-truth-agnostic** — the ciphertext is identical everywhere. Analysis of K4
itself does not need to specify a ground truth.

[POLICY] **Default to Physical Sculpture (Ground Truth A)** for primary analysis, because:
- The copper IS the artifact — it's what Sanborn physically created
- "You could not make any mistake with 1,800 letters"
- Both sculptures predate the 2006 correction
- The Antipodes having correct UNDERGROUND suggests Sanborn was aware of the difference

[POLICY] **Test both ground truths** when a method depends on K2 structure (delimiter count,
ending text, character positions). If a method works with one but not the other, document which.

---

## Quick Reference: Character Counts

| Section | Physical Kryptos | Physical Antipodes | Sanborn's Intent |
|---------|------------------|--------------------|-----------------|
| K1 | 63 letters | 63 letters | 63 letters |
| K2 | 369 letters + 3 `?` | 369 letters + 3 `?` | 370 letters + 3 `?` (with restored X) |
| K3 | 336 letters + 1 `?` | 336 letters + 1 `?` | 336 letters (IDENTICAL) |
| K4 | 97 letters | 97 letters | 97 letters |
| K2 delimiter X | 4 | 4 | 5 |
| K2 ending | IDBYROWS | IDBYROWS | XLAYERTWO |

---

*Created 2026-02-27 — Colin Patrick + Claude*
