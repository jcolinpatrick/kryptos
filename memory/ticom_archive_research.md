---
name: ticom_archive_research
description: TICOM archive research - cipher techniques that could relate to K4's two-system model
type: reference
---

# TICOM Archive Research: Cipher Techniques Relevant to Kryptos K4

## Executive Summary

The TICOM (Target Intelligence Committee) archive, declassified in 2009, contains 328+ documents captured by Allied forces from German and Axis cryptographic services during and after WWII. Ed Scheidt served in the Armed Forces Security Agency (NSA predecessor) and then the CIA for 26 years (1963-1989), specializing in one-time pad systems. He would have had direct professional exposure to TICOM material and the cipher techniques described therein. Several cipher systems documented in TICOM reports share structural features with K4's confirmed two-system model (substitution + steganographic masking).

This research identifies **seven cipher families** from the TICOM-era ecosystem with direct relevance to K4, ranked by structural alignment with K4's known properties.

---

## 1. Rasterschlussel 44 (RS 44) — HIGHEST RELEVANCE

**Source:** TICOM archive; detailed analysis at ciphermachinesandcryptology.com
**Type:** Grid-mask transposition (stencil cipher)

### Technical Description
- **Grid:** 24 rows x 25 columns = 600 cells
- **Mask:** Each row contains 10 white (open) cells and 15 black (blocked) cells, irregularly placed
- **Encryption:** Plaintext written left-to-right into white cells only, skipping black cells; ciphertext read column-by-column in a keyed column order
- **Key sheet:** Changes daily — cell pattern, column numbering, row/column digraph labels, substitution alphabets
- **Indicator:** Start position encoded via digraph substitution table

### K4 Parallels — STRIKING
1. **Physical stencil = Cardan grille analog.** RS 44 IS a selection mask: a physical template placed beneath paper, with open holes revealing where to write. This is structurally identical to K4's hypothesized null-mask model.
2. **Two layers combined:** RS 44 combines (a) positional masking (white/black cells) with (b) columnar transposition (keyed column reading order). K4's two systems are (a) null/steganographic masking and (b) substitution cipher.
3. **Grid dimensions matter:** RS 44 uses a 24x25 grid. K4 is carved in a 28x31 grid. The Kryptos master grid is a confirmed artifact.
4. **Hand-executable by non-experts.** Sanborn: "anathamath, confounded by mathematics." RS 44 was designed for field troops — no math required, just follow the stencil.
5. **"Kryptos Decoding Filter" (1994):** Sanborn created a physical grille object (51"x17", perforated metal sheets). This is functionally an RS 44 stencil.
6. **Bletchley gave up.** RS 44 required 40+ letter cribs and ~2 weeks per break. Without captured stencils, it was effectively unbreakable.

### K4 Incompatibilities
- RS 44 produces letter output (transposition only), whereas K4's substitution layer changes letters. RS 44 is pure transposition; K4 requires substitution.
- RS 44's 10-of-25 white ratio (40%) differs from K4's 73-of-97 hypothesis (75%).
- RS 44 was German Army, not Soviet or CIA. However, TICOM captured these techniques and they entered the NSA knowledge base.

### Actionable Implications
- RS 44's mask concept could be the "second system" (steganographic layer). The null mask selects which 73 of 97 positions carry the real message — exactly Cardan grille function.
- The column-order reading in RS 44 may explain why col7 transposition appears in K4 scoring — columnar transposition is integral to mask-based systems.
- RS 44's daily-changing stencil implies the mask IS the key. For K4, the mask might be derivable from K2 coordinates or another Kryptos element.

---

## 2. VIC Cipher — HIGH RELEVANCE

**Source:** Discovered 1953 (hollow nickel), algorithm revealed 1957 (Hayhanen defection). Studied extensively at NSA. Not in TICOM per se, but the evolutionary descendant of Soviet systems that TICOM documented.
**Type:** Multi-stage hand cipher (straddling checkerboard + chain addition + disrupted double transposition)

### Technical Description (Complete Pipeline)
1. **Key derivation:** From (a) 20-letter passphrase ranked to digits, (b) secret date (YYMMDD), (c) personal identifier (1-2 digits). These combine through modulo-10 subtraction and chain addition to produce all subsequent keys.
2. **Chain addition (lagged Fibonacci):** Starting from 10-digit seed, compute d_new = (d_1 + d_2) mod 10, shift left, repeat 40 times to generate 50 pseudorandom digits.
3. **Straddling checkerboard:** 3-row x 10-column grid. Top row has 8 letters (high-frequency: "A SIN TO ERR" mnemonic) at single-digit codes. Two blank positions become row prefixes for the lower rows (10 letters each). Result: variable-length encoding (1 or 2 digits per letter), ~20-30% compression.
4. **Mod-10 addition:** Digit stream from checkerboard + pseudorandom additive (from chain addition), no carrying.
5. **First columnar transposition:** Digits written into grid, read by keyed column order.
6. **Disrupted second transposition:** Grid filled with triangular disruptions — certain positions blanked, creating irregular fill patterns that defeat anagramming.
7. **Serial number insertion:** 5-digit message indicator embedded at predetermined position.

### K4 Parallels
1. **Two-system architecture.** VIC has substitution (checkerboard) + transposition (double columnar). K4 confirmed to have two systems.
2. **Chain addition as key generation.** K4's corrected keystream has IC=0.029 (below random), consistent with chain-addition-generated keys.
3. **Variable-length encoding produces expansion.** Straddling checkerboard turns N letters into ~1.3N digits — analogous to 73 PT chars expanding to 97 CT chars (ratio 1.33).
4. **Disrupted transposition = irregular mask.** The "disrupted" concept (triangular blanking of grid positions) is functionally similar to null insertion — certain positions are unused, creating irregular patterns.
5. **Scheidt's background.** Scheidt was NSA/ASA before CIA. He would have studied the VIC cipher extensively — it was the most famous unbroken hand cipher in NSA history at the time. "Most often he used one-time pad paper systems" — VIC is the pinnacle of non-OTP hand ciphers.
6. **Hand-executable.** VIC was designed for field agents with no access to machines. Sanborn could execute it with Scheidt's coaching.

### K4 Incompatibilities — KEY ISSUE
- **K4 contains 26 LETTERS, not digits.** VIC's straddling checkerboard output is numeric. The repo's K4 mapping matrix marks VIC as "STRUCTURALLY-BLOCKED" for this reason.
- **BUT:** If VIC's digit output undergoes a SECOND substitution (digits back to letters), the structural block is circumvented. The digit-to-letter conversion IS the "second system." Script `e_straddling_checkerboard_k4.py` explores this model: 26 CT letters map to 10 digits via a keyed mapping, producing a 97-digit stream that parses as checkerboard output yielding ~73 PT characters. This model has NOT been exhaustively tested with VIC-derived key generation.

### What's Been Tested vs. Untested
- **TESTED:** `e_vic_model.py` — 130.7M configs with letter-level parsing + single columnar (generic checkerboard, NOT VIC key generation). ZERO hits.
- **TESTED:** `e_straddling_checkerboard_k4.py` — 36.5M configs with digit-level decode + digit permutations (NOT VIC key generation). Status unclear.
- **TESTED:** `e_full_vic_pipeline_k4.py` — Full VIC key generation with phrases, dates, personal numbers. Status: "never run" per header.
- **UNTESTED:** Full VIC pipeline with K2-derived parameters (38,57,6.5 as date/personal number sources), KRYPTOS/PALIMPSEST/ABSCISSA as passphrases, and the digit-to-letter conversion step.

---

## 3. Soviet Nihilist Cipher Family — MEDIUM-HIGH RELEVANCE

**Source:** TICOM documents DF-112 (Survey of Russian Military Systems), RussianCryptology, I-173, I-191; also Rote Kapelle KV3-349.
**Type:** Evolutionary family: Nihilist -> WWII spy variants (Sorge, Rote Kapelle, Lucy) -> VIC

### Technical Description
- **Base Nihilist (1880s):** Polybius square converts letters to 2-digit coordinates. Key phrase also converted to digits. Addition (sometimes with carrying) produces ciphertext digits.
- **WWII Evolution (Sorge/Foote variant):** Replaced Polybius square with straddling checkerboard for compression. Used non-carrying addition (mod 10) instead of carrying addition — dramatically more secure. Additive derived from memorized phrase + chain addition.
- **Rote Kapelle variant (weaker):** Additive generated from a book passage (e.g., The Good Soldier Schweik) converted to digits via checkerboard. Book selection was the vulnerability.
- **Key innovation:** Straddling checkerboard + mod-10 non-carrying addition. These two components persist through to VIC.

### K4 Relevance
- The Nihilist family demonstrates the PATTERN of Soviet cipher evolution that Scheidt would have studied: layered composition of simple operations.
- Rote Kapelle's book-based additive is analogous to running key from a text — and running key is the ONE structured non-periodic model surviving all Bean constraints for K4.
- TICOM's documentation of these systems means they were in the NSA/ASA knowledge base when Scheidt was trained.

---

## 4. German Diplomatic Cipher Systems (TICOM I-56) — MEDIUM RELEVANCE

**Source:** TICOM I-56 "German Diplomatic Ciphers" (fetched successfully)
**Type:** Code + superencipherment (multi-layer)

### Technical Description
Two systems documented:

**System 1 — Blockverfahren (Cipher Pad):**
- Codebook converts words to 5-digit groups
- One-time pad (cipher pad) numbers added without carrying
- Pad = 100 sheets, each with 48 five-digit groups (8 lines x 6 groups)
- Indicator in header: block number + page number

**System 2 — Grundverfahren (Ground Procedure) — THREE LAYERS:**
- **Layer 1:** Codebook word-to-number conversion (same as Block system)
- **Layer 2:** Tangent Table (100-200 pages, 50 lines/page, 6 five-digit groups/line). Encoder selects TWO random lines, adds all groups to the codebook result.
- **Layer 3:** Line numbers themselves enciphered using a separate small cipher pad (Schlusselblock). Complementary construction: line pairs sum to 0000.
- **Final conversion:** 8-digit line indicator converted to 8-letter group via Letter Conversion Table (numbers 01-95 mapped to vowel-consonant pairs).

### K4 Parallels
1. **Multi-layer architecture** with each layer serving a different function.
2. **Number-to-letter conversion table** — direct parallel to the digit-to-letter conversion needed if K4 uses a numeric intermediate form.
3. **Complementary construction** (pairs summing to zero) — mathematically elegant, hand-executable.
4. **Indicator system embedded in message** — K4 may contain embedded indicators (W positions? First 5 characters OBKRU as indicator group?).

---

## 5. Ubchi Cipher — MEDIUM RELEVANCE

**Source:** German WWI cipher documented in TICOM-era literature
**Type:** Double transposition with null insertion

### Technical Description
- **Step 1:** Write plaintext in columnar grid under keyword
- **Step 2:** Read columns in key order (first transposition)
- **Step 3:** INSERT null letters (typically 1-2, sometimes equal to keyword length)
- **Step 4:** Repeat columnar transposition (second transposition) with same or different key

### K4 Relevance
- **Null insertion between transposition layers** is DIRECTLY analogous to K4's two-system model where 24 nulls are inserted.
- "The addition of a single letter is enough to obfuscate the transposition method" — this principle explains why 24 nulls could defeat analysis of 97 characters.
- Ubchi demonstrates that null insertion was a KNOWN technique in the German/TICOM cipher tradition, not a novel invention.

---

## 6. ADFGVX Cipher — MEDIUM RELEVANCE

**Source:** German WWI, well-known in TICOM-era literature
**Type:** Polybius fractionation + columnar transposition

### Technical Description
- **Step 1:** 6x6 Polybius grid (letters + digits) labeled A, D, F, G, V, X
- **Step 2:** Each plaintext character becomes 2 grid coordinates (fractionation)
- **Step 3:** Coordinate pairs undergo columnar transposition
- **Result:** Two-step cipher combining substitution and transposition

### K4 Relevance
1. **Two-step architecture** (substitution then transposition) matches K4's confirmed two-system model.
2. **Fractionation** (one input character becomes multiple output characters) parallels the 73-to-97 expansion.
3. **Polybius-based encoding** — K4's palette {B,G,I,K,O,W,Z} has been connected to a KRYPTOS x SEVEN dual-keyword 5-wide KA Polybius grid.
4. **BUT:** ADFGVX always produces even-length output; K4 = 97 (odd). Structurally blocked per `E-FRAC-21`.

---

## 7. Wehrmacht Manual Ciphers (Doppelwurfelverfahren) — LOWER RELEVANCE

**Source:** TICOM archive, CryptoCellar research (cryptocellar.org)
**Type:** Double columnar transposition

### Systems Documented
- **Doppelkastenschlussel** (Double Box Cipher) — two-grid system
- **Truppenschlussel TS42** (Troop Cipher) — simplified double box
- **Nachrichtenschlussel NS42** (Message Cipher) — more secure variant
- **Doppelwurfelverfahren (DWV)** — standard double transposition with two keywords

### K4 Relevance
- These are pure transposition systems — eliminated for K4 as single layers (CT has 2 E's, cribs need 3).
- BUT as the TRANSPOSITION LAYER in a two-system model, double transposition remains viable (the substitution layer would change letter frequencies before transposition).
- The DWV was declared insecure by Walter Fricke in 1942, leading to RS 44's development — suggesting the cipher community was aware that simple double transposition was insufficient.

---

## 8. Soviet Field Cipher Systems (TICOM DF-112, RussianCryptology)

**Source:** TICOM DF-112, RussianCryptology, I-173, I-191
**Type:** Multi-figure code + superencipherment

### Technical Description (from successfully fetched text)
- **2/3-figure codes:** Used by frontline units. Letter/word-to-figure substitution tables, sometimes with secondary substitution encipherment.
- **4-figure codes (OKK, pre-1942):** 50-page codebooks (5,000 groups, alphabetical). Second layer: substitution table encipherment. Post-1942 replaced by SUV systems where units created their own tables.
- **5-figure codes (high-level):** Codebook + one-time additive. Two types: "General" blocks (31 pages, 300 groups/page, valid one day) and "Individual" blocks (50 pages, 60-120 groups/page, single-use per group). Addition without carrying.
- **Foreign intelligence/Comintern agents:** Three-step process: (1) memorized letter-to-figure table, (2) encode message, (3) encipher using additive derived from book passage. This is the PREDECESSOR to the Nihilist/VIC family.
- **Partisan communications:** Ranged from simple Caesar to double transposition, **stencil-based transposition**, and Caesar + one-time pad additives. NOTE: "stencil-based transposition" used by Soviet partisans is documented in TICOM.

### K4 Relevance
- Soviet partisans used **stencil-based transposition** — a physical grille/mask, exactly the mechanism hypothesized for K4.
- The three-step agent cipher (memorized table + encode + book-passage additive) is structurally similar to K4's hypothesized architecture.
- Addition without carrying (mod 10) is the standard across ALL Soviet cipher layers.
- Scheidt's career in the Armed Forces Security Agency (NSA predecessor) would have included study of exactly these Soviet systems.

---

## Cross-Cutting Analysis: Connections to K4

### The "Two Systems" Pattern in TICOM-Era Ciphers

Every significant TICOM-era hand cipher uses multiple layers:
| System | Layer 1 | Layer 2 | Layer 3+ |
|--------|---------|---------|----------|
| RS 44 | Grid mask (selection) | Columnar transposition | Substitution alphabets |
| VIC | Straddling checkerboard (sub) | Mod-10 additive | Disrupted double transposition |
| German diplomatic | Codebook (sub) | Additive (OTP or table) | Line-number encryption |
| Soviet field | Code table (sub) | Additive (OTP or book) | — |
| Ubchi | Columnar transposition | Null insertion | Second transposition |
| ADFGVX | Polybius fractionation (sub) | Columnar transposition | — |

**K4's confirmed "two systems" fits this pattern exactly.** Sanborn's statement that the two systems "unveil" is consistent with layered composition where removing one layer reveals the next.

### Scheidt's Professional Knowledge

Ed Scheidt's career timeline places him in direct contact with TICOM-derived knowledge:
- **1957-1963:** Army signals intelligence, Armed Forces Security Agency (NSA predecessor)
- **1963-1989:** CIA Office of Communications, rising to Chairman of Cryptographic Center
- **Primary tool:** "Most often he used one-time pad paper systems"
- **Kryptos (late 1980s):** "Presented several options for each encryption" to Sanborn

Key facts about Scheidt's knowledge base:
1. The VIC cipher was discovered in 1953 and studied at NSA. Scheidt entered ASA around 1957 — the VIC would have been a primary training case study.
2. TICOM documents were available within the intelligence community from 1946 onward, declassified publicly only in 2009.
3. Scheidt explicitly confirmed: "I used a bit of stego when designing the fourth part" — steganographic null insertion is a known technique in TICOM-documented systems (RS 44 mask, Ubchi null insertion, Soviet partisan stencils).
4. Scheidt: "The masking technique may not be [a known technique]" — potentially bespoke, but INSPIRED by known TICOM-era techniques.

### Specific TICOM Techniques Matching K4 Observables

| K4 Observable | TICOM Technique | System |
|---|---|---|
| 97 chars with 24 nulls (73 real) | Stencil mask (10/25 = 40% open) | RS 44 |
| Null palette {B,G,I,K,O,W,Z} | Variable-length encoding (some chars = 1 digit, some = 2) | Straddling checkerboard |
| Two confirmed systems | Sub + trans layers | VIC, ADFGVX, German diplomatic |
| IC near random (0.036) | Non-carrying mod-10 addition flattens distribution | VIC, Soviet additive systems |
| Keystream IC below random (0.029) | Chain addition / lagged Fibonacci generator | VIC |
| Physical "Decoding Filter" | Physical stencil template | RS 44 |
| Hand-executable | All TICOM hand ciphers designed for field use | All above |
| Col7 transposition signal | Keyed columnar reading order | RS 44, VIC, DWV |
| "What's the point?" clue | Full stop / period (.) as checkerboard character #27 | Straddling checkerboard |

### Untested TICOM-Inspired Models for K4

Based on this research, the following models have NOT been adequately tested:

#### Model T1: RS 44-Style Mask + Substitution
- 28x31 Kryptos grid as the RS 44 grid
- Physical mask (derivable from K2 coordinates, NDYAHR directions, or sculpture geometry) selects 73 positions
- Substitution cipher (Beaufort, keyed alphabet) applied to the 73 selected characters
- **What's new:** Using the Kryptos-specific 28x31 grid with RS 44-style columnar reading order (not just null mask + direct sub, which has been tested)

#### Model T2: Modified VIC with Digit-to-Letter Conversion
- Straddling checkerboard converts 73 PT chars to ~97 digits
- Digits mapped to letters via a keyed 10-to-26 mapping (or mod-26 table)
- VIC key generation from K2-derived parameters (38,57,6.5 as date, KRYPTOS as passphrase)
- Script `e_full_vic_pipeline_k4.py` exists but header says "never run"
- **What's new:** Using K2-derived checkerboard parameters (3,8 row labels from coordinate digits), which the MEMORY.md notes as UNTESTED

#### Model T3: Ubchi-Style Null Insertion Between Transposition Layers
- First transposition on 73-char plaintext
- Insert 24 null characters at specific positions (from palette {B,G,I,K,O,W,Z})
- Second transposition on the 97-char result
- **What's new:** Null insertion BETWEEN two transposition steps, not as a separate layer

#### Model T4: Soviet Agent Three-Step Cipher
- Memorized conversion table (keyed by KRYPTOS alphabet)
- Encode plaintext to digits
- Encipher with additive derived from K1-K3 plaintext as "book passage"
- Convert digits back to letters
- **What's new:** Using K1-K3 plaintext as the "book passage" for additive generation

#### Model T5: RS 44 Column-Reading on Kryptos 28x31 Grid
- K4 ciphertext fills specific cells of the 28x31 master grid (K4 occupies rows 24-28, cols 27-31 and wrapping)
- Apply RS 44-style keyed column reading (rather than left-to-right row reading)
- Read only "open" cells (73 of 97, per a mask derived from the grid structure)
- **What's new:** Using the actual Kryptos grid coordinates as the RS 44 grid, with column reading order derived from grid labeling

---

## Document References

### TICOM Archive (archive.org/details/ticom/)
- **European Axis Signal Intelligence Vol. 2** — German high-level cryptography (machine ciphers, limited hand cipher references)
- **I-56 German Diplomatic Ciphers** — Blockverfahren and Grundverfahren (3-layer diplomatic cipher). SUCCESSFULLY FETCHED.
- **DF-112 Survey of Russian Military Systems** — Soviet 2/3/4/5-figure codes, SUV systems, additive methods
- **RussianCryptology** — Soviet cipher evolution, one-time additive, SUV systems. PARTIALLY FETCHED.
- **DF-187 (A-G) Fenner Documents** — Comprehensive German cipher survey by Wilhelm Fenner. PDF only, not text-extractable.
- **DF-292 The Cryptologic Service in WWII** — Edwin von Lingen overview. Not fetched (archive page only).
- **I-45 OKW/Chi Research** — Machine cipher analysis (Enigma, Hagelin, teleprinters). FETCHED — no hand cipher content.
- **European Axis Signal Intelligence Vol. 6** — Foreign Office cryptanalytic section. Partially fetched — organizational focus, limited cipher technique detail.
- **European Axis Signal Intelligence Vol. 7** — Goering's Forschungsamt. FETCHED — organizational only, no cipher technique detail.
- **Rote Kapelle KV3-349** — Soviet spy ring documentation. Not fetched.
- **SRH-361, SRH-364** — US Signal Security Agency history. Not fetched.

### External Sources Consulted
- ciphermachinesandcryptology.com/en/rasterschlussel44.htm (RS 44 detailed technical description)
- codedinsights.com/classical-cryptography/vic-cipher/ (VIC cipher analysis)
- prgomez.com/lessons-from-the-vic-cipher/ (VIC cipher security analysis)
- grokipedia.com/page/VIC_cipher (VIC complete technical description)
- grokipedia.com/page/straddling_checkerboard (straddling checkerboard details)
- chris-intel-corner.blogspot.com/2014/07/compromise-of-soviet-codes-in-wwii.html (Soviet cipher system details from TICOM)
- derekbruff.org (RS 44 analysis, hollow nickel case)
- dcode.fr/ubchi-cipher (Ubchi null insertion details)
- cryptocellar.org/wmc/ (Wehrmacht manual cipher catalog)
- pbs.org/wgbh/nova/decoding/doubtrans.html (double transposition)

---

## Priority Recommendations

1. **Run `e_full_vic_pipeline_k4.py`** — header says "never run." Full VIC pipeline with K2-derived parameters is the most promising untested TICOM-inspired model.
2. **Test RS 44-style column reading** on the 28x31 Kryptos grid with mask extraction. The Kryptos "Decoding Filter" IS an RS 44 stencil.
3. **Test K2 digits as straddling checkerboard row labels** — K2 coordinates contain digits 3,8 (from "38 degrees") which are standard VIC-style row label positions. This specific parameter choice has been noted as UNTESTED in MEMORY.md.
4. **Test Ubchi-style null insertion** between transposition layers — nulls from palette {B,G,I,K,O,W,Z} inserted between two columnar transpositions.
5. **Test Soviet partisan stencil model** — stencil-based transposition documented in TICOM for Soviet partisans, applied to the Kryptos grid.

---

*Research conducted: 2026-03-17*
*Sources: TICOM Archive (archive.org/details/ticom/), supplementary web research*
*Status: Reference document for K4 cryptanalysis*
