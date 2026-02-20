# Explorer Report: Military COMSEC Coding Charts & SOI Protocols

**Task:** #1 -- Research military COMSEC coding charts and SOI protocols
**Agent:** Explorer
**Date:** 2026-02-20

---

## Executive Summary

This report catalogs the physical coding chart systems, military authentication tables, and tactical cipher procedures that would have been available to Ed Scheidt (CIA Cryptographic Center chairman, retired December 1989) and Jim Sanborn (artist, no math background) in 1989-1990. The goal is to identify which of these systems match Sanborn's descriptions: "matrix codes," "coding charts," "not a math solution," "coding systems that didn't necessarily depend on mathematics," and "systems that I could then modify in a myriad of ways."

**Key finding:** Several military/CIA paper cipher systems are structurally consistent with K4's properties and Sanborn's descriptions. The strongest candidates are DRYAD-like matrix tables, Slidex-style vocabulary grids, BATCO cipher sheets, and SOI authentication tables -- all of which are physical "coding charts" that use matrix/grid lookups rather than mathematical formulas.

---

## 1. Signal Operating Instructions (SOI / CEOI)

### What They Are
Signal Operating Instructions (SOI), also called Communications-Electronics Operation Instructions (CEOI), are combat orders for technical control of communications within a military command. They are issued as physical booklets, valid for 24 hours, containing multiple tables and procedures.

### Components of a Standard SOI

| Component | Format | Purpose |
|-----------|--------|---------|
| **Callsign Table** | Letter-Number-Letter + 2-digit suffix (e.g., R5T 31) | Identify radio stations |
| **Frequency Table** | PACE: Primary, Alternate, Contingency, Emergency | Assign radio frequencies |
| **Challenge/Password** | Word pair (e.g., Linebacker/Screwdriver) | Voice authentication |
| **Number Combination** | Target sum (e.g., 13) | Numeric challenge-response |
| **Authentication Word** | 10-letter word with NO repeating letters, mapped to digits 1-9,0 | Letter-to-number encoding |
| **Transmission Auth Table** | Numbered columns of digraphs (40 columns x 5 rows) | One-time authenticators |
| **Visual Signals** | Color codes for day/night | Non-radio recognition |

### The Authentication Word System -- Highly Relevant

The authentication word is a 10-character word with no repeating letters (e.g., ANGLERFISH). Each letter is assigned a number:

```
A  N  G  L  E  R  F  I  S  H
1  2  3  4  5  6  7  8  9  0
```

This creates a **substitution table** that converts letters to numbers and vice versa. When challenged with a letter (e.g., "Romeo"), the operator responds with the NEXT letter to the right plus its number (e.g., "Foxtrot Seven" = F7).

**Relevance to K4:** This is a position-dependent encoding table. The word KRYPTOS (or KRYPTOSABCDEFGHIJLMNQUVWXZ, the KA alphabet) could function as an authentication word, creating a mapping between letters and positions. The K0 Morse code phrase "T IS YOUR POSITION" directly invokes this protocol -- in radio authentication, your "position" (call sign suffix) determines which column of the authentication table you use.

### Transmission Authentication Table

Structure: 40 numbered columns, each containing 5 unused digraphs (two-letter pairs). Each station is assigned specific columns. When authenticating, the operator selects the first unused digraph from their assigned column and transmits it phonetically ("Authentication is Hotel Foxtrot"). All stations must cross out used digraphs to prevent reuse. Any reuse = hostile intrusion.

**Key property:** This is a ONE-TIME system. Each digraph is used once then destroyed. The table itself is the "coding chart."

---

## 2. DRYAD Numeral Cipher / Authentication System (KTC 1400 D)

### Overview
The DRYAD is the U.S. military's standard paper cryptographic system for authentication and encryption of short numerical messages. Designation: KTC 1400 D.

### Physical Format

- **25 rows** labeled A through Y (Z excluded, only 25 letters used)
- Each row contains a **random permutation of the letters A through Y**
- Letters grouped into **10 columns labeled 0 through 9**
- Columns 0, 1, 2, and 5 have MORE letters than columns 3, 4, 6, 7, 8, 9 (which have 2 each)
- This asymmetry is designed to resist frequency analysis
- Each sheet has a **cryptoperiod** (e.g., 6 hours) after which it's destroyed
- Matching sets issued to all units in a net

### How Authentication Works

1. Challenger selects a random letter from the LEFT column (row selector)
2. Challenger selects a second random letter from that row (column indicator)
3. Both letters transmitted as the challenge
4. Responder looks up the second letter in the selected row
5. Responds with the letter DIRECTLY BELOW the second letter in the same column

Two-factor variant: Parties agree on secret directional or numeral offsets beforehand, requiring both "something you have" (the DRYAD sheet) and "something you know" (the offset).

### How Encryption Works

1. Operator selects two random letters (row indicator + set letter)
2. The "set letter" is found in the selected row; the letter to its RIGHT becomes the actual working marker
3. Individual digits (0-9) are encrypted by finding the COLUMN number for a letter in the selected row
4. Repeated digits MUST use different letters from the same column (to prevent frequency analysis)

### Relevance to K4

- DRYAD is literally a **matrix code**: a grid of letters used for positional lookup
- It uses 25 of 26 letters (A-Y, no Z) -- K4 uses all 26, so DRYAD cannot be used directly, but Sanborn said he MODIFIED what Scheidt showed him
- The encryption maps numbers to letters via a table -- this is a non-mathematical process, purely procedural
- DRYAD is exactly the kind of "coding chart" that would be physically auctioned
- A DRYAD-style table modified to use all 26 letters in a 26-row matrix would be a natural Sanborn modification

### DRYAD-K4 Hypothesis

If Sanborn modified DRYAD to use a 26x26 letter matrix (or a subset), the "coding chart" for K4 would be a single sheet with scrambled letter rows. The encryption procedure would be:
1. Select a row (determined by position in plaintext or a separate key)
2. Look up plaintext letter in the row
3. Record the column header (or vice versa)

This is a **polyalphabetic substitution using a physical table** -- not a mathematical formula. It's hand-executable, non-mathematical, and the security comes from the physical chart (which Sanborn could modify however he wanted).

---

## 3. BATCO (BATtle COde)

### Overview
BATCO is a British Army tactical cipher used at platoon/troop/section level. It consists of vocabulary cards (code) plus cipher sheets (superencryption). The combination is remarkably similar to Kryptos's structure.

### Physical Format
- Double-sided A5 sheet fitting in a BATCO wallet with sliding rulers
- Each side valid for 24 hours (36 pages per edition)

### Cipher Table Structure

**Main table:** 19 columns x 26 rows
- First 6 columns: key selection (scrambled alphabets)
- Remaining 13 columns: cipher alphabets
- Each ROW is a scrambled alphabet mapping plaintext to ciphertext
- The operator selects a row using a key digit + key letter combination

**Plaintext character set:** 12 symbols (digits 0-9, decimal point, "change" marker)
**Ciphertext character set:** Letters A through Z

### Additional Components

| Component | Structure | Function |
|-----------|-----------|----------|
| **Spelling Box** | 6x5 matrix, labeled with digits | Spell out words not on vocabulary cards |
| **Authentication Table** | 10x5 grid, random 2-digit numbers | Challenge-response authentication |
| **Call Sign Indicators** | Bottom panel letters (A-Y, Z reserved) | Determine encryption start position |

### Key Rules
- Maximum 22 encryptions per key setting
- New key setting per message
- Key settings used in alphanumeric order
- Single use per net

### Relevance to K4

BATCO is the most structurally similar to what Kryptos seems to require:
- **Two-component system**: vocabulary cards (code) + cipher sheet (cipher) = "two separate systems"
- **Physical matrix table** with scrambled alphabets = "matrix codes"
- **Non-mathematical**: purely procedural, table lookup
- **19x26 matrix**: a grid that Sanborn could modify (e.g., to 10x26, 26x26, etc.)
- **Position-dependent**: the key letter/digit determines WHICH alphabet to use for each position
- **The BATCO wallet with sliding rulers** is literally a "coding chart" -- a physical artifact

---

## 4. Slidex (British Tactical Code Device)

### Overview
Slidex is a paper-based manual cipher used for tactical communications, consisting of vocabulary cards arranged in a matrix grid.

### Physical Format
- Card size: ~245 x 157 mm when closed
- **Grid: 12 columns x 17 rows = 204 cells**
- Each cell contains a word/phrase AND a letter/number
- Horizontal slider: 16 cells (4 more than columns = 5 possible positions)
- Vertical ruler: 21 cells (4 more than rows = 5 possible positions)

### Encoding Procedure
1. Locate word on grid card
2. Record column and row identifiers (two-letter code)
3. **Multiple two-letter combinations exist for each position** (slider positions)
4. This hides frequency of common expressions
5. Words not on cards: use SWITCH ON/OFF commands to spell letter-by-letter

### Key Management
Each day uses a unique letter arrangement written onto the rulers. The slider positions + ruler contents constitute the daily key.

### Relevance to K4

- Slidex is literally "matrix codes" -- a matrix of words with coordinate-based encoding
- It produces **bigrams** (two-letter groups) as output
- The multiple-choice encoding (different slider positions) provides homophonic substitution
- Sanborn could modify this to work letter-by-letter instead of word-by-word
- Physical card = "coding chart"
- **Weakness**: German cryptanalysts broke Slidex "relatively easily in a couple of hours" -- Sanborn would need modifications

---

## 5. One-Time Pads (CIA Standard)

### Overview
The one-time pad (OTP) was the primary encryption system used by CIA field officers throughout the Cold War. Ed Scheidt himself stated he "most often used one-time pad paper systems of encryption" during his 26-year CIA career.

### Physical Format
- Sheets of random numbers in **groups of five digits**
- Issued in matched pairs: red (encipher) and black (decipher)
- Each page sealed; opened only when used
- Some printed on nitrocellulose for instant destruction
- Remarkably compact: some as small as 2 x 0.8 cm (fit on postage stamps)

### Encoding Procedure
1. Convert plaintext letters to numbers (A=01, B=02, ... Z=26)
2. Pair message numbers with pad numbers
3. Add using non-carrying arithmetic (mod 10 per digit, or mod 26 per letter)
4. Divide result into 5-digit/letter groups for transmission
5. Destroy the used page

### Relevance to K4

- OTP was Scheidt's DAILY tool -- the system he knew best
- **Mathematically unbreakable** if used correctly
- A modified OTP (e.g., using a shorter key, or a key derived from a physical object) would match "not a math solution" in the sense that the math is trivial (addition) but the key is physical
- The "coding chart" sold at auction could BE an OTP sheet
- **Problem**: True OTP produces random-looking ciphertext, which K4 appears to be. But OTP with a known key would already be solved. Unless the "key" is derived from a physical element of the sculpture itself (compass rose, Morse code, etc.)

---

## 6. VIC Cipher (Soviet Field Cipher)

### Overview
The VIC cipher was the most complex hand cipher ever used by intelligence agents. It remained unbroken from 1953 until the agent's defection in 1957. As Chairman of the CIA Cryptographic Center, Scheidt would have been deeply familiar with this system.

### Components (Multi-Layer)
1. **Key derivation**: Mod 10 chain addition + lagged Fibonacci generator produce pseudorandom digit sequences
2. **Straddling checkerboard**: Converts letters to digits (high-frequency = 1 digit, low-frequency = 2 digits)
3. **Disrupted double transposition**: Rearranges the digit stream using two different transposition keys with "disrupted" (irregular) patterns

### Why It Matters for K4

- **Multi-layer system** matching Sanborn's "two separate systems"
- **Straddling checkerboard** is a matrix/table -- literally a "coding chart"
- **Hand-executable** -- designed for field agents with no equipment
- Before VIC, "it was generally thought that a double transposition alone was the most complex cipher an agent, as a practical matter, could use as a field cipher"
- Scheidt, as CIA crypto chief, would have studied VIC extensively
- VIC combines substitution + transposition, which is exactly the structure our elimination results point to for K4

---

## 7. Military Clock Position Protocol

### How It Works
- Observer imagines themselves at center of a clock face
- 12 o'clock = directly ahead (direction of travel/facing)
- Each hour = 30 degrees (360/12)
- 3 o'clock = 90 degrees right, 6 o'clock = 180 degrees (behind), 9 o'clock = 270 degrees left

### Conversion: Compass Bearing to Clock Position

| Clock | Degrees | Compass |
|-------|---------|---------|
| 12 | 0/360 | N |
| 1 | 30 | NNE |
| 2 | 60 | ENE |
| 3 | 90 | E |
| 4 | 120 | ESE |
| 5 | 150 | SSE |
| 6 | 180 | S |
| 7 | 210 | SSW |
| 8 | 240 | WSW |
| 9 | 270 | W |
| 10 | 300 | WNW |
| 11 | 330 | NNW |

### Relevance to K4

- ENE (East-North-East) = ~67.5 degrees = approximately **2 o'clock**
- The Kryptos compass rose with lodestone deflects compass needle to ENE (~67.5 degrees)
- "BERLINCLOCK" in the crib could be a double-meaning:
  - Surface level: The Berlin Weltzeituhr (World Clock) or Mengenlehreuhr
  - Military level: "Berlin [at] clock [position 2]" -- Berlin is at 2 o'clock from the observer's position
- In military radio: "Berlin at 2 o'clock" means "Berlin is 60 degrees to the right of your direction of travel"
- The K0 Morse phrase "T IS YOUR POSITION" = "What is your position?" (radio protocol)
- This connects COMPASS BEARING -> CLOCK POSITION -> BERLINCLOCK as a unified concept

---

## 8. Ed Scheidt's Background and Expertise

### Career Summary
- **1963**: Hired as CIA communications officer (Office of Communications)
- **1963-1989**: 26-year career, 12 years posted overseas (Vientiane, Damascus, Tel Aviv, Manila, Athens)
- **Field experience**: Used one-time pad paper systems primarily
- **Leadership**: Rose to Chairman of CIA Cryptographic Center
- **December 1989**: Retired (same month the Berlin Wall fell, Nov 9 1989)
- **1990**: Co-founded TecSec Inc. (encryption software); holds 36 patents in cryptographic technologies

### What He Taught Sanborn
From the 2009 Smithsonian oral history (ajax.pdf):

1. **"A primer of ancient encoding systems"** -- historical ciphers (Polybius, Caesar, Vigenere, etc.)
2. **"Contemporary coding systems, more sophisticated systems"** -- modern intelligence tradecraft ciphers
3. **"Systems that didn't necessarily depend on mathematics"** -- physical/procedural systems (DRYAD, BATCO, authentication tables)
4. **"Matrix codes and things like that"** -- grid/table-based encoding (DRYAD, Slidex, straddling checkerboard, BATCO)
5. **"Coding systems that I could then modify in a myriad of ways"** -- flexible, adaptable frameworks

### Key Constraints on K4's Method
- Only **2-3 meetings** between Scheidt and Sanborn
- Sanborn has no math background and "tried to minimize the need for math"
- Method couldn't be too complex for an artist to execute
- Sanborn modified Scheidt's systems so "even he [Scheidt] would not know what it says"
- Sanborn said he "didn't necessarily give them [CIA/Webster] the whole code"

---

## 9. The Auction "Coding Charts" -- What They Likely Are

### What Was Sold ($962,500)
The RR Auction lot included:
- Original handwritten plaintext of K4
- Signed typed letter from Ed Scheidt
- **Original coding charts used to create K1, K2, and K3**
- **The original coding system for K4**
- Unpublished 1988 alternate versions (including K5)
- Physical 12x18 inch copper maquette

### What "Coding Charts" Means

For K1/K2: The "coding charts" are the **Vigenere tableaux** (visible on the sculpture's right panel). This is confirmed by Sanborn: "I used that table to encipher the top plate."

For K3: The coding chart would be the **transposition grid** (columnar transposition worksheet).

For K4: The "original coding system for K4" is something DIFFERENT from K1-K3. Given:
- "The bottom plate is enciphered in a much more difficult fashion"
- "Two separate systems" for the bottom text
- "Change in methodology" from K3 to K4

The K4 coding chart is almost certainly a **matrix/grid table** -- a physical sheet with scrambled alphabets arranged in rows and columns, used for positional lookup. This is consistent with:
- A modified DRYAD sheet (26x26 or 26x10 letter matrix)
- A modified BATCO cipher table (scrambled alphabet rows selected by position)
- A Slidex-style grid (coordinate-based lookup)
- A custom straddling checkerboard + transposition grid (VIC-style)

---

## 10. Synthesis: Which Systems Best Match K4?

### Ranking by Compatibility with All Known Constraints

| System | Matrix/Grid? | Non-mathematical? | Two systems? | Hand-executable? | All 26 letters? | Modifiable? | Score |
|--------|-------------|-------------------|-------------|-----------------|----------------|------------|-------|
| **Modified DRYAD** | Yes (matrix) | Yes (table lookup) | Could add transposition | Yes | Needs mod (has 25) | Yes | HIGH |
| **Modified BATCO** | Yes (19x26) | Yes (table lookup) | Yes (code + cipher) | Yes | Yes (A-Z output) | Yes | HIGH |
| **VIC-style composite** | Yes (checkerboard) | Partially (some addition) | Yes (sub + trans) | Yes | Needs adaptation | Moderate | HIGH |
| **Custom authentication table** | Yes (grid) | Yes (lookup only) | Could combine | Yes | Flexible | Yes | MEDIUM |
| **Modified Slidex** | Yes (12x17) | Yes (coordinate lookup) | Not naturally | Yes | Flexible | Yes | MEDIUM |
| **OTP variant** | No (linear) | Partially (addition) | Not naturally | Yes | Yes | Limited | LOW |
| **Hill cipher** | Yes (matrix) | No (matrix multiplication) | Not naturally | Barely | Yes | No | LOW |

### Top 3 Hypotheses for K4's "Coding System"

**H1: Modified DRYAD/BATCO Matrix Table**
- A custom 26-row matrix where each row is a scrambled A-Z alphabet
- Row selection determined by position in message (or by a running key)
- Each plaintext letter found in the selected row; column header = ciphertext letter
- This is polyalphabetic substitution via physical table -- Vigenere generalized beyond periodic keys
- "Two systems" = row-selection method + alphabet-lookup method
- Perfectly matches: "matrix codes", "coding charts", "not math", "two systems"

**H2: Straddling Checkerboard + Disrupted Transposition (VIC-inspired)**
- Checkerboard converts letters to variable-length digit groups
- Digits arranged in a grid and read out in disrupted transposition order
- Result converted back to letters
- Matches: "matrix codes", "two systems" (sub + trans), difficulty 9/10
- Problem: Produces digit intermediate, requires reconversion. K4 is all letters.
- But: checkerboard can be letter-to-letter instead of letter-to-digit

**H3: Physical Procedural Cipher with Sculpture Elements**
- Encoding uses physical elements of the sculpture as key material:
  - Compass rose bearing (ENE = 67.5 degrees)
  - Morse code values from K0 slabs
  - Vigenere tableau visible on sculpture (keyed alphabet)
  - Petrified tree/geological strata positions
- Each element provides one layer of encoding
- "Not a math solution" because the key is PHYSICAL, not computed
- "Coding chart" = the sculpture itself, or a worksheet derived from it

---

## 11. Critical Observations for Testing

### 11.1 "T IS YOUR POSITION" as Authentication Protocol

In military radio, "What is your position?" (QTH in Morse) initiates an authentication sequence. The K0 Morse code phrase "T IS YOUR POSITION" could mean:
- Literal: The letter T indicates your position in the encoding scheme
- Protocol: Use your assigned position (callsign suffix) to select the correct row/column in the coding chart
- Meta: "Your position in the ciphertext determines which encoding rule to apply" (position-dependent cipher)

### 11.2 The 10-Letter Authentication Word

SOI authentication uses a 10-letter word with no repeating letters. PALIMPSEST has 10 letters but P appears twice. ABSCISSA has 8 letters. But KRYPTOSABCDE... the KA alphabet could serve this function.

More interestingly: many Kryptos-related words have exactly 10 non-repeating letters:
- KRYPTOSAFE (K-R-Y-P-T-O-S-A-F-E) = 10 unique? K,R,Y,P,T,O,S,A,F,E = 10 unique. Yes!
- Could function as an authentication word mapping to 1234567890

### 11.3 Callsign Structure and K4

Military callsigns follow Letter-Number-Letter + 2-digit suffix format. K4 begins with OBKR -- which looks like it could be a callsign fragment. OB could be the first two elements, KR the suffix or partial callsign.

### 11.4 The Coding Chart as Physical Artifact

The auction lot describes "the original coding system for K4" as a physical item. This is most consistent with:
- A sheet of paper with a matrix/grid of scrambled letters
- NOT a mathematical formula or computer algorithm
- Something you could photograph at the Smithsonian (which is how the plaintext was found)

---

## 12. Recommendations for Computational Testing

Based on this research, the following experiments should be prioritized:

1. **DRYAD-style 26x26 matrix substitution**: Generate random 26x26 matrices where each row is a permutation of A-Z. Test with position-dependent row selection (row = position mod 26, or row determined by running key from known text).

2. **BATCO-style cipher table**: Test a 26-row cipher with each row being a random derangement of A-Z. Row selected by combining position with a key element. This is effectively a non-periodic polyalphabetic substitution with a PHYSICAL key.

3. **SOI authentication table structure**: Test the 10-letter-word encoding where KRYPTOS (or extended KRYPTOSABCDEFGHIJLMNQUVWXZ) determines a positional mapping.

4. **Straddling checkerboard as first layer**: Convert K4 CT through a 26-letter checkerboard (no merging I/J since all 26 present), then apply transposition to the variable-length output.

5. **Clock-position encoding**: Test whether "BERLINCLOCK" literally encodes a clock position (2 o'clock from ENE bearing) that indicates a column/row offset in a coding chart.

---

## Sources

- [Signal Operating Instructions - danmorgan76](https://danmorgan76.wordpress.com/2013/10/26/signal-operating-instructions-soi-for-the-tactical-environment/)
- [DRYAD - Crypto Wiki](https://cryptography.fandom.com/wiki/DRYAD)
- [BATCO - jproc.ca](https://jproc.ca/crypto/batco.html)
- [Slidex - Crypto Museum](https://www.cryptomuseum.com/crypto/uk/slidex/index.htm)
- [SOI/CEOI - GlobalSecurity.org](https://www.globalsecurity.org/military/library/policy/army/accp/ss0002/le3.htm)
- [FM 24-12 COMSEC Operations](https://www.globalsecurity.org/military/library/policy/army/fm/24-12/Ch7.htm)
- [Transmission Authentication Table](https://armycommunications.tpub.com/ss0652b/ss0652b0045.htm)
- [CIA One-Time Pads](https://www.cia.gov/legacy/museum/artifact/one-time-pads/)
- [OTP Instructions - numbers-stations.com](https://www.numbers-stations.com/articles/how-a-one-time-pad-works-cia-instructions/)
- [Edward Scheidt - thekryptosproject.com](https://www.thekryptosproject.com/toknow/people/scheidt.php)
- [Kryptos Fan - Ed Scheidt](https://kryptosfan.wordpress.com/tag/ed-scheidt/)
- [Kryptos Fan - Matrix Codes](https://kryptosfan.wordpress.com/tag/matrix-codes/)
- [RR Auction - Kryptos Archive](https://www.rrauction.com/auctions/lot-detail/350761607302001-the-complete-secrets-of-kryptos-jim-sanborns-private-archive/)
- [RR Auction - K4 Discovered Not Solved](https://content.rrauction.com/kryptos-k4-discovered-not-solved-heres-what-actually-happened/)
- [KAL-55B - Flickr (Operating Instructions)](https://www.flickr.com/photos/ideonexus/5176402044)
- [VIC Cipher - Wikipedia (via search)](https://en.wikipedia.org/wiki/VIC_cipher)
- [Straddling Checkerboard](https://en.wikipedia.org/wiki/Straddling_checkerboard)
- [NIST OPCODE Definition](https://csrc.nist.gov/glossary/term/operations_code)
- [TecSec - Scheidt Biography](https://tecsec.com/meet-the-team/)
- [Military Cryptanalytics - Friedman/Callimahos](https://en.wikipedia.org/wiki/Military_Cryptanalytics)
- [DRYAD Generator - Citizen Militem](https://citizenmilitem.com/?page_id=200)
- [Clock Position - thegunzone.com](https://thegunzone.com/how-does-the-military-use-a-clock-as-direction/)

---

*Report generated by Explorer agent, 2026-02-20*
