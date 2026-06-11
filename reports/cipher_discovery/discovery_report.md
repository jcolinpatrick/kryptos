# Cipher Discovery Report
Generated: 2026-03-31 15:22 UTC

## Summary

- **Total cipher systems cataloged:** 83
- **Tested in project:** 73
- **Untested:** 10

### Taxonomy Breakdown

- confirmed_named_manual_cipher: 70
- probable_but_poorly_evidenced: 10
- artistic_or_bespoke_encoding: 3

## Top Candidates by K4 Relevance (novelty-weighted)

Untested ciphers receive a bonus. Exhausted ciphers receive a penalty.

### 1. Astrolabe Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 67.4/100
- **Novelty-weighted Score:** 93.4
- **Obscurity:** 0.60
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** artistic_or_bespoke_encoding
- **Aliases:** astrolabe code, celestial cipher, star chart cipher

**Description:** Hypothetical cipher using astrolabe positions or star chart coordinates. An astrolabe combines compass direction with celestial angle, providing a natural two-coordinate encoding space. Navigation theme is K4-relevant.

**How it works:** Map letters to celestial positions or astrolabe settings

**Hand-executable:** paper_pencil
**Tools needed:** astrolabe diagram or star chart

**K4 relevance factors:** compass_bearing_relation=10.0, artist_feasibility=9.0, bespoke_hybrid=9.0, manual_executability=8.0, spatial_geometric=8.0

**Project scripts:** NONE -- not yet tested

---

### 2. Sundial/Gnomon Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 60.7/100
- **Novelty-weighted Score:** 86.7
- **Obscurity:** 0.60
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** artistic_or_bespoke_encoding
- **Aliases:** sundial cipher, sundial code, gnomon cipher, shadow cipher

**Description:** Hypothetical system using sundial positions (shadow angles) to encode letters. A gnomon's shadow direction throughout the day gives 12+ distinct positions. Could connect to compass directions and time simultaneously.

**How it works:** Map letters to shadow angles/positions on a sundial

**Hand-executable:** paper_pencil
**Tools needed:** sundial diagram

**K4 relevance factors:** spatial_geometric=10.0, artist_feasibility=9.0, bespoke_hybrid=9.0, manual_executability=8.0, compass_bearing_relation=7.5

**Project scripts:** NONE -- not yet tested

**Open questions:**
  - Kryptos sculpture has a shadow-casting element
  - Does the gnomon/shadow connect compass directions to clock positions?

---

### 3. Swagman Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 44.8/100
- **Novelty-weighted Score:** 70.8
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Swagman, Australian cipher

**Description:** Australian transposition cipher using a grid where each row and column contains exactly one marked cell (a Latin square pattern). Text fills marked cells, creating a complex transposition.

**How it works:** Fill cells marked in Latin square pattern, read off in order

**Hand-executable:** grid
**Tools needed:** paper, grid key

**K4 relevance factors:** manual_executability=10.0, short_text_plausibility=8.0, artist_feasibility=7.0, sanborn_theme_compatibility=6.0

**Project scripts:** NONE -- not yet tested

---

### 4. Vatsyayana / Kama Sutra Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 34.4/100
- **Novelty-weighted Score:** 60.4
- **Obscurity:** 0.60
- **Type:** substitution
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Kama Sutra cipher, Mlecchita Vikalpa, secret writing India, Vatsyayana

**Description:** Ancient Indian paired-substitution cipher described in Kama Sutra. Pair the 26 letters randomly into 13 pairs. Each letter is replaced by its pair partner. Self-reciprocal. Equivalent to a specific class of monoalphabetic involutory substitution.

**How it works:** Random pairing of alphabet into 13 pairs; swap each letter with its partner

**Hand-executable:** paper_pencil
**Tools needed:** pairing table

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=4.0

**Project scripts:** NONE -- not yet tested

---

### 5. Alberti Cipher Disk

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 34.3/100
- **Novelty-weighted Score:** 60.3
- **Obscurity:** 0.60
- **Type:** substitution
- **Category:** mechanical
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Alberti disk, Alberti cipher, cipher disk, cipher wheel

**Description:** Earliest known polyalphabetic device. Two concentric disks with alphabets. Rotate inner disk to change cipher alphabet. Index character signals rotation. Important historically as origin of polyalphabetic idea.

**How it works:** Two concentric disks; rotate inner disk periodically during encryption

**Hand-executable:** paper_pencil
**Tools needed:** cipher disk

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** NONE -- not yet tested

---

### 6. Dorabella Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 34.1/100
- **Novelty-weighted Score:** 60.1
- **Obscurity:** 0.60
- **Type:** symbolic
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Elgar cipher, Dorabella, musical cipher

**Description:** Unsolved cipher created by composer Edward Elgar in 1897. Uses symbols based on rotated E-like shapes at 8 orientations x 3 levels. Relevant as an example of an artist creating a bespoke cipher system that defies standard analysis.

**How it works:** Symbol substitution using bespoke character set

**Hand-executable:** paper_pencil
**Tools needed:** symbol reference

**K4 relevance factors:** bespoke_hybrid=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, manual_executability=6.0

**Project scripts:** NONE -- not yet tested

**Open questions:**
  - Parallel to K4: artist-created cipher unsolved for over a century

---

### 7. Solitaire Cipher (Pontifex)

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 33.7/100
- **Novelty-weighted Score:** 59.7
- **Obscurity:** 0.60
- **Type:** substitution
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Pontifex cipher, Schneier Solitaire, playing card cipher, Solitaire

**Description:** Stream cipher using a deck of playing cards as the keystream generator. Designed by Bruce Schneier for Neal Stephenson's Cryptonomicon (1999). Post-dates Kryptos (1990) but demonstrates that card-based hand ciphers are feasible.

**How it works:** Card deck permutation generates keystream; add to plaintext mod 26

**Hand-executable:** paper_pencil
**Tools needed:** playing cards, paper

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** NONE -- not yet tested

**Ambiguity flags:**
  - Post-dates Kryptos construction by 9 years

---

### 8. Tri-Square Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 33.0/100
- **Novelty-weighted Score:** 59.0
- **Obscurity:** 0.60
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** tri-square, three-square, trisquare

**Description:** Trigraphic cipher using three 5x5 grids. Processes three letters at a time using geometric relationships across three grids. Requires 25-letter alphabet.

**How it works:** Three 5x5 grids, process trigraphs via geometric lookup

**Hand-executable:** grid
**Tools needed:** three 5x5 grids

**K4 relevance factors:** manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0, spatial_geometric=4.0

**Project scripts:** NONE -- not yet tested

---

### 9. ADFGVX Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 34.4/100
- **Novelty-weighted Score:** 57.4
- **Obscurity:** 0.30
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** ADFGX cipher, ADFGVX, German WWI cipher, Nebel cipher

**Description:** WWI German cipher: Polybius substitution (6x6 grid labeled ADFGVX) followed by columnar transposition. [INTERNAL RESULT] Structurally eliminated as single layer (requires fractionation output alphabet of only 6 letters, but K4 has 26).

**How it works:** Polybius 6x6 encode, then columnar transposition on the pairs

**Hand-executable:** grid
**Tools needed:** 6x6 grid, keyword

**K4 relevance factors:** manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** NONE -- not yet tested

---

### 10. Dancing Men Cipher

- **Status:** [UNTESTED]
- **K4 Relevance Score:** 27.4/100
- **Novelty-weighted Score:** 53.4
- **Obscurity:** 0.60
- **Type:** symbolic
- **Category:** substitution
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** dancing men, Sherlock Holmes cipher, stick figure cipher

**Description:** Fictional monoalphabetic cipher from Arthur Conan Doyle's 'The Adventure of the Dancing Men'. Each letter represented by a stick figure in a specific pose. Simple substitution with symbolic output.

**How it works:** Monoalphabetic substitution: letter -> stick figure symbol

**Hand-executable:** paper_pencil
**Tools needed:** symbol chart

**K4 relevance factors:** artist_feasibility=8.0, short_text_plausibility=7.0, manual_executability=6.0

**Project scripts:** NONE -- not yet tested

---

### 11. Heliograph/Mirror Signal Cipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 46.5/100
- **Novelty-weighted Score:** 52.5
- **Obscurity:** 0.60
- **Type:** signaling
- **Category:** signaling
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** heliograph cipher, heliograph code, mirror signal cipher, sun telegraph cipher

**Description:** Signaling system using reflected sunlight for long-distance communication. Uses Morse-like patterns (long/short flashes). Relevant because Kryptos involves reflection and light (the petrified wood, the compass rose pool, sunlight reading).

**How it works:** Morse-like encoding via reflected light flashes

**Hand-executable:** paper_pencil
**Tools needed:** mirror/reflector, Morse code chart

**K4 relevance factors:** morse_signaling_relation=7.5, manual_executability=7.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=6.0

**Project scripts:** e_grille_08_tableau_null_model, e_mirror_ka_01_comprehensive
**Exhaustion status:** active

---

### 12. Compass Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 71.5/100
- **Novelty-weighted Score:** 50.5
- **Obscurity:** 0.90
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** artistic_or_bespoke_encoding
- **Aliases:** compass code, bearing cipher, direction cipher, cardinal cipher, azimuth cipher

**Description:** Ambiguous term from Sanborn's handwritten notes. No single standard cipher bears this name. Possible interpretations: (1) A substitution cipher mapping letters to compass bearings (N, NNE, NE, etc. -- 32 points give enough symbols for 26 letters). (2) A transposition guided by compass directions on a grid. (3) A cipher using a compass rose as a key diagram. (4) A Chappe-style direction-based encoding. (5) The BERLIN CLOCK connection -- clock positions as compass points. The term may refer to a b...

**How it works:** Unknown. If directional substitution: letters assigned to compass bearings, then directions encode the message. If grid-based: write plaintext in grid, read off following compass direction pattern. Could also involve physical compass overlay on the sculpture.

**Hand-executable:** grid or diagram
**Tools needed:** compass rose diagram, paper, pencil

**K4 relevance factors:** artist_feasibility=10.0, spatial_geometric=10.0, compass_bearing_relation=10.0, bespoke_hybrid=9.0, manual_executability=8.0

**Project scripts:** e_autokey_bidir_extended, e_autokey_bidirectional, e_compass_misdirection_01, e_compass_point, e_extend_xor_autokey_00 ... (+18 more)
**Exhaustion status:** exhausted

**Open questions:**
  - What exactly did Sanborn mean by 'compass cipher'?
  - Is this related to the compass rose imagery at CIA?
  - Does this connect to EASTNORTHEAST crib (directional)?

**Ambiguity flags:**
  - No standard cipher named 'compass cipher' in cryptographic literature
  - Multiple plausible interpretations
  - May be a Sanborn/Scheidt invention, not a historical system

---

### 13. BATCO

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 38.1/100
- **Novelty-weighted Score:** 44.1
- **Obscurity:** 0.60
- **Type:** substitution
- **Category:** military
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** BATCO cipher, British Army tactical code, SLIDEX, tactical battlefield cipher

**Description:** British Army tactical communication cipher. One-time card system with sliding scales for battlefield use. Simple enough for soldiers under fire. SLIDEX is a related NATO system.

**How it works:** Slide card reveals substitution alphabets for given setting

**Hand-executable:** mechanical_device
**Tools needed:** BATCO/SLIDEX card

**K4 relevance factors:** manual_executability=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=6.0, physical_aid_use=4.0

**Project scripts:** e_s_145_dryad_matrix
**Exhaustion status:** active

---

### 14. Morbit Cipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 35.4/100
- **Novelty-weighted Score:** 41.4
- **Obscurity:** 0.60
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Morbit, Morse bigram cipher

**Description:** Like Pollux but pairs adjacent Morse symbols and substitutes each pair with a single letter. More compact output than Pollux.

**How it works:** Morse encode -> pair symbols -> substitute pairs with letters

**Hand-executable:** paper_pencil
**Tools needed:** Morse code chart, pair table

**K4 relevance factors:** manual_executability=8.0, morse_signaling_relation=7.5, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e01_morse_e_extraction, e_chart_04_morse_pattern, e_frac_43_bigram_discriminator, e_k0_morse_null_mask, e_morse_binary_digital_01 ... (+17 more)
**Exhaustion status:** active

---

### 15. Fractionated Morse

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 35.4/100
- **Novelty-weighted Score:** 41.4
- **Obscurity:** 0.60
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** frac Morse, fractionated Morse cipher

**Description:** Convert PT to Morse, group resulting dots/dashes/separators into trigrams, substitute each trigram with a letter using a keyed alphabet. 26 trigrams -> 26 letters, so output is alphabetic. THIS IS THE ONLY MORSE FRACTIONATION THAT OUTPUTS ALL-ALPHA.

**How it works:** Morse encode -> group into trigrams -> keyed substitution to letters

**Hand-executable:** paper_pencil
**Tools needed:** Morse code chart, keyed trigram table

**K4 relevance factors:** manual_executability=8.0, morse_signaling_relation=7.5, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e01_morse_e_extraction, e_chart_04_morse_pattern, e_k0_morse_null_mask, e_morse_binary_digital_01, e_morse_binary_null_mask_01 ... (+13 more)
**Exhaustion status:** active

**Open questions:**
  - Morse fractionation produces flat IC -- matches K4
  - Sanborn references Morse code -- is fractionated Morse the method?
  - Has this specific variant been tested against K4?

---

### 16. Nomenclator

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 33.0/100
- **Novelty-weighted Score:** 39.0
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** nomenclator cipher, Renaissance cipher, diplomatic cipher code, Great Cipher

**Description:** Hybrid system combining a codebook (for common words/phrases) with a cipher (for letters not in codebook). Used for centuries in diplomatic correspondence. [INTERNAL RESULT] Tested (e_cfm_05_nomenclator): eliminated as pure nomenclator.

**How it works:** Code table for words + cipher for remaining letters

**Hand-executable:** paper_pencil
**Tools needed:** codebook, cipher table

**K4 relevance factors:** manual_executability=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, bespoke_hybrid=6.0

**Project scripts:** e_cfm_05_nomenclator_model, e_s_136_great_big_story_rk, e_team_layered_nomenclator_verify, e_team_nomenclator_super
**Exhaustion status:** active

---

### 17. Book Cipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 35.9/100
- **Novelty-weighted Score:** 38.9
- **Obscurity:** 0.30
- **Type:** substitution
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** book code, Beale cipher, Beale code, dictionary cipher, page-line-word cipher

**Description:** Each plaintext letter or word is encoded as a reference to a position in a shared book (page/line/word or word number). Beale ciphers use word-initial letters from the Declaration of Independence. Output is typically numeric.

**How it works:** Replace each PT letter with a number pointing to a position in the key text

**Hand-executable:** paper_pencil
**Tools needed:** shared book/text

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e_novel_02_book_cipher, e_running_key_crib_drag, e_s_31_carter_running_key, e_straddling_checkerboard_k4, e_team_book_cipher
**Exhaustion status:** active

**Open questions:**
  - Output is numeric -- would need a second layer to produce alphabetic CT

---

### 18. Chaocipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 33.7/100
- **Novelty-weighted Score:** 38.7
- **Obscurity:** 0.50
- **Type:** substitution
- **Category:** mechanical
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Chaocipher, Byrne cipher machine, Byrne cipher

**Description:** Cipher using two circular alphabets that permute after each letter is encrypted. Created by John Byrne in 1918, algorithm secret until 2010. Produces highly irregular substitution. Can be done with two strips of paper in a loop. Interesting because it produces flat frequency distribution (like K4).

**How it works:** Two circular alphabets; after each encryption, extract and reinsert letters

**Hand-executable:** paper_pencil
**Tools needed:** two circular alphabet strips

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e_novel_06_chaocipher_evolving
**Exhaustion status:** active

**Open questions:**
  - Has Chaocipher been tested against K4 CT?

---

### 19. Coordinate/Grid Reference Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 61.1/100
- **Novelty-weighted Score:** 37.1
- **Obscurity:** 0.60
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** grid cipher, coordinate cipher, map grid cipher, grid reference cipher, geographic cipher

**Description:** Letters encoded as grid coordinates (like map grid references). Various schemes: simple (row, col), military grid reference, or geographic coordinates. K4 themes include coordinates and navigation. EASTNORTHEAST crib is directional.

**How it works:** Map letters to coordinate pairs on a grid

**Hand-executable:** grid
**Tools needed:** grid, coordinate system

**K4 relevance factors:** compass_bearing_relation=10.0, artist_feasibility=9.0, manual_executability=8.0, spatial_geometric=8.0, short_text_plausibility=7.0

**Project scripts:** blitz_coordinates_key, e_antipodes_10_coordinate_grid, e_coordinate_punch, e_frac_17_beaufort_running_key, e_geometric_keys_01 ... (+14 more)
**Exhaustion status:** exhausted

---

### 20. Porta Cipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 30.0/100
- **Novelty-weighted Score:** 35.0
- **Obscurity:** 0.50
- **Type:** substitution
- **Category:** polyalphabetic
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Porta, Giambattista della Porta cipher, Porta reciprocal cipher, della Porta

**Description:** Polyalphabetic cipher using 13 alphabets (key letters pair: AB, CD, etc.). Each alphabet swaps pairs of letters. Self-reciprocal within each alphabet. Only uses 13 distinct alphabets, so effective key period is halved.

**How it works:** 13 reciprocal alphabets selected by key letter pairs

**Hand-executable:** tabula_recta
**Tools needed:** Porta tableau

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e_grille_ct_attack3, e_s_100_porta_proper
**Exhaustion status:** active

---

### 21. One-Time Pad (hand variant)

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 33.7/100
- **Novelty-weighted Score:** 34.7
- **Obscurity:** 0.10
- **Type:** substitution
- **Category:** substitution
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** one-time pad, OTP, Vernam cipher, additive cipher, key tape cipher

**Description:** Theoretically unbreakable: each PT letter added to a truly random key letter mod 26. Key must be at least as long as message and used only once. If K4 uses a true OTP, it is unsolvable without the key. But OTP with a pseudorandom or structured key degenerates to another cipher type.

**How it works:** C[i] = (P[i] + K[i]) mod 26 where K is random

**Hand-executable:** paper_pencil
**Tools needed:** key sheet, paper

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e_mitm_periodic_transposition, e_s_10_additive_grid_key
**Exhaustion status:** active

**Open questions:**
  - If K4 is OTP, it requires finding the specific key sheet

---

### 22. Four-Square Cipher

- **Status:** [ACTIVE]
- **K4 Relevance Score:** 30.7/100
- **Novelty-weighted Score:** 33.7
- **Obscurity:** 0.30
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** four-square, Delastelle four-square, 4-square

**Description:** Digraphic substitution using four 5x5 grids arranged in a square. Two are plain alphabets, two are keyed. [INTERNAL RESULT] Structurally eliminated (25-letter alphabet).

**How it works:** Digraph input, locate in plain grids, cross-reference keyed grids

**Hand-executable:** grid
**Tools needed:** four 5x5 grids

**K4 relevance factors:** manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e_four_square_inner_layer
**Exhaustion status:** active

---

### 23. Alphabet Code

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 51.7/100
- **Novelty-weighted Score:** 30.7
- **Obscurity:** 0.90
- **Type:** substitution
- **Category:** substitution
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** alphabet cipher, alphabetical code, letter code, ABC cipher, alphabet substitution

**Description:** Ambiguous term from Sanborn's handwritten notes. Possible interpretations: (1) Simple A=1, B=2, ..., Z=26 numeric cipher. (2) Keyword-mixed alphabet substitution. (3) A specific 'alphabet code' system from espionage tradecraft. (4) Any system using an alphabet tableau. (5) The KA alphabet itself (KRYPTOSABCDEFGHIJLMNQUVWXZ) as a code. Given context with Beaufort and Morse on same page, likely refers to a specific substitution using a particular alphabet ordering.

**How it works:** Unknown -- likely simple substitution with a specific alphabet

**Hand-executable:** paper_pencil
**Tools needed:** paper, pencil, alphabet key

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=9.0, bespoke_hybrid=9.0, sanborn_theme_compatibility=8.0, short_text_plausibility=7.0

**Project scripts:** blitz_t_final, blitz_yar_selective, e02_misspelling_deltas, e04_hill_cipher, e06_autokey ... (+111 more)
**Exhaustion status:** exhausted

**Open questions:**
  - Is this the KA alphabet used as a simple substitution key?
  - Or is it a numeric A=1 encoding?
  - How does it interact with the other systems on Sanborn's list?

**Ambiguity flags:**
  - Extremely generic term
  - Could refer to any alphabet-based substitution
  - Context with other Sanborn notes may narrow meaning

---

### 24. Route Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 53.7/100
- **Novelty-weighted Score:** 29.7
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** route transposition, path cipher, spiral cipher, diagonal cipher, serpentine cipher

**Description:** Write plaintext into a grid, then read off following a specific route (spiral, diagonal, zigzag, etc.). Union Army used extensively in Civil War. Routes can be arbitrary, making exhaustive search difficult. Spatial/geometric nature is K4-relevant.

**How it works:** Fill grid row by row, read out along a path (spiral, diagonal, etc.)

**Hand-executable:** grid
**Tools needed:** grid paper, route specification

**K4 relevance factors:** manual_executability=10.0, spatial_geometric=10.0, short_text_plausibility=8.0, artist_feasibility=7.0, sanborn_theme_compatibility=6.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+145 more)
**Exhaustion status:** exhausted

---

### 25. ABSCISSA Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 53.3/100
- **Novelty-weighted Score:** 29.3
- **Obscurity:** 0.60
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** abscissa code, ABSCISSA, coordinate arithmetic cipher

**Description:** [PUBLIC FACT] 'ABSCISSA' appears in Sanborn's papers at Archives of American Art, on same page as ATBASH. An abscissa is the x-coordinate in a Cartesian system. May indicate a coordinate-based cipher using x-positions. [INTERNAL RESULT] Standard arithmetic interpretation eliminated. May be procedural/physical chart clue.

**How it works:** Unknown -- possibly coordinate-based letter selection

**Hand-executable:** grid
**Tools needed:** coordinate grid

**K4 relevance factors:** artist_feasibility=9.0, bespoke_hybrid=9.0, manual_executability=8.0, spatial_geometric=8.0, short_text_plausibility=7.0

**Project scripts:** blitz_coordinates_key, e_aaa_tableau_struct_06, e_antipodes_10_coordinate_grid, e_bespoke_02_abscissa_linear, e_coordinate_punch ... (+13 more)
**Exhaustion status:** exhausted

**Open questions:**
  - Does ABSCISSA describe a step in the cipher process?
  - Is it the x-coordinate method for a coding chart?
  - Connection to physical sculpture layout?

---

### 26. Chart-Based Cipher (Sanborn)

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 49.6/100
- **Novelty-weighted Score:** 25.6
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** bespoke
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** coding chart cipher, Code Breaker overlay, overlay cipher, transparency cipher, Sanborn chart cipher

**Description:** [PUBLIC FACT] Archives of American Art show Sanborn's 'Code Breaker' overlay sketch and references to 'actual coding charts'. This suggests a physical overlay or transparency-based cipher mechanism, possibly bespoke. [HYPOTHESIS] The overlay could function as a grille, stencil, or routing guide that determines which characters to read or how to permute them.

**How it works:** Unknown -- involves physical overlay on text/grid

**Hand-executable:** stencil
**Tools needed:** coding chart/overlay, grid or text layout

**K4 relevance factors:** bespoke_hybrid=9.0, manual_executability=8.0, physical_aid_use=8.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** e01_morse_e_extraction, e02_misspelling_deltas, e03_k0_e_positions_deep, e_alexandria_street_key_01, e_audit_08_delimiter_x_extraction ... (+33 more)
**Exhaustion status:** exhausted

**Open questions:**
  - What is the exact nature of the 'Code Breaker' overlay?
  - Does it function as a grille, stencil, or route guide?
  - Is it in private hands or publicly accessible?

---

### 27. Clock Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 47.8/100
- **Novelty-weighted Score:** 23.8
- **Obscurity:** 0.60
- **Type:** spatial
- **Category:** spatial
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** clock code, clock position cipher, time cipher, dial cipher, Berlin clock cipher

**Description:** Letters mapped to clock face positions (1-12 or 1-24). Can use hour+minute positions for digraphic encoding. 'BERLINCLOCK' is a K4 crib, making clock-based systems highly relevant. The Berlin Mengenlehreuhr (set-theory clock) uses a unique time display that could serve as an encoding scheme.

**How it works:** Map letters to clock positions; various schemes possible

**Hand-executable:** paper_pencil
**Tools needed:** clock face reference

**K4 relevance factors:** artist_feasibility=9.0, manual_executability=8.0, spatial_geometric=8.0, short_text_plausibility=7.0, compass_bearing_relation=5.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+205 more)
**Exhaustion status:** exhausted

**Open questions:**
  - Does BERLINCLOCK crib imply a clock-based cipher layer?
  - Does the Mengenlehreuhr display map to an encoding scheme?

---

### 28. Checkerboard + Transposition (Soviet pattern)

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 46.5/100
- **Novelty-weighted Score:** 22.5
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** mixed
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Soviet field cipher, checkerboard disrupted transposition, Soviet three-step cipher

**Description:** Common Soviet intelligence pattern: straddling checkerboard -> numeric additive key -> disrupted transposition. VIC cipher is the most elaborate example, but simpler variants existed. [INTERNAL RESULT] Soviet three-step tested: NOISE.

**How it works:** Checkerboard encode -> add key digits -> transposition

**Hand-executable:** paper_pencil
**Tools needed:** checkerboard, key digits, transposition grid

**K4 relevance factors:** manual_executability=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=6.0, bespoke_hybrid=5.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+141 more)
**Exhaustion status:** exhausted

---

### 29. Worm Cipher (spiral/helical transposition)

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 46.3/100
- **Novelty-weighted Score:** 22.3
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** worm cipher, helical cipher, spiral transposition, coil cipher

**Description:** Write plaintext around a cylinder (like scytale) but read off in a helical/spiral pattern. More complex than simple columnar because the helix pitch can vary. Spatial/physical nature is K4-relevant (sculpture is curved copper).

**How it works:** Write on cylinder surface, read along helical path with given pitch

**Hand-executable:** grid
**Tools needed:** cylindrical surface or grid

**K4 relevance factors:** manual_executability=10.0, short_text_plausibility=8.0, artist_feasibility=7.0, spatial_geometric=6.0, physical_aid_use=4.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+138 more)
**Exhaustion status:** exhausted

**Open questions:**
  - Kryptos sculpture is curved -- does the physical shape encode a helical reading?
  - Has helical transposition at various pitches been tested?

---

### 30. Grille + Running Key

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 45.2/100
- **Novelty-weighted Score:** 21.2
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** mixed
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** mask + running key, null extraction + book cipher, stego + polyalphabetic

**Description:** [HYPOTHESIS] Two-layer system: grille/mask extracts meaningful positions from CT97, then running-key Beaufort encrypts the meaningful portion. This is the LEADING open hypothesis for K4. The grille produces the null palette, the running key produces the cipher layer. [INTERNAL RESULT] Mono+Trans+Running key is UNDERDETERMINED (E-FRAC-54).

**How it works:** Phase 1: mask/grille extracts ~73 real characters. Phase 2: running-key Beaufort.

**Hand-executable:** stencil
**Tools needed:** grille/mask, key text (book), Beaufort tableau

**K4 relevance factors:** bespoke_hybrid=9.0, manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=6.0, physical_aid_use=4.0

**Project scripts:** blitz_concealment, blitz_csp_grille_structural, blitz_grille_geometry, blitz_grille_geometry_v2, blitz_grille_geometry_v3 ... (+260 more)
**Exhaustion status:** exhausted

**Open questions:**
  - What source text is the running key?
  - What determines the mask pattern?
  - Is the mask the palette pattern {B,G,I,K,O,W,Z}?

---

### 31. Boy Scout Cipher Systems

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 44.8/100
- **Novelty-weighted Score:** 20.8
- **Obscurity:** 0.60
- **Type:** substitution
- **Category:** educational
- **Taxonomy:** probable_but_poorly_evidenced
- **Aliases:** Scout code, Baden-Powell cipher, camping cipher, scout semaphore

**Description:** Various simple cipher systems taught in scouting: reversed alphabet, number substitution, pigpen, Morse, semaphore. Sanborn's 'alphabet code' and 'compass cipher' could conceivably be scouting terms.

**How it works:** Various simple substitutions and transpositions

**Hand-executable:** paper_pencil
**Tools needed:** paper

**K4 relevance factors:** manual_executability=10.0, artist_feasibility=8.0, short_text_plausibility=7.0, morse_signaling_relation=5.0, spatial_geometric=4.0

**Project scripts:** e_compose_03_partitioned
**Exhaustion status:** exhausted

---

### 32. Rasterschlussel 44 (RS44)

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 44.1/100
- **Novelty-weighted Score:** 20.1
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** grille
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** RS44, Rasterschlussel, German grid cipher, WWII grid mask cipher, Raster key

**Description:** WWII German field cipher: grid mask (grille) selecting positions, combined with substitution. [INTERNAL RESULT] 905.6M configs tested: NOISE. Eliminated.

**How it works:** Grid mask extraction + substitution + transposition

**Hand-executable:** stencil
**Tools needed:** grid mask, substitution table

**K4 relevance factors:** manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0, bespoke_hybrid=6.0, physical_aid_use=6.0

**Project scripts:** e_rs44_24row_cipher_panel_v1, e_rs44_grid_mask_v1
**Exhaustion status:** exhausted

---

### 33. Transposition + Substitution Hybrid

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 43.7/100
- **Novelty-weighted Score:** 19.7
- **Obscurity:** 0.60
- **Type:** mixed
- **Category:** mixed
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** sub-trans hybrid, super-encipherment, product cipher hand, multi-step hand cipher

**Description:** General class of two-layer systems applying substitution and transposition in sequence. Military standard for hand ciphers in WWII era. [PUBLIC FACT] Scheidt confirmed K4 uses 'two encryption systems'. [INTERNAL RESULT] Three-layer Sub+Trans+Sub at p1*p2<=50 eliminated. Many specific combinations eliminated.

**How it works:** Layer 1: substitution (Vigenere, Beaufort, etc). Layer 2: transposition

**Hand-executable:** paper_pencil
**Tools needed:** cipher table, transposition grid

**K4 relevance factors:** manual_executability=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=6.0, bespoke_hybrid=5.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+195 more)
**Exhaustion status:** exhausted

---

### 34. Semaphore Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 41.5/100
- **Novelty-weighted Score:** 17.5
- **Obscurity:** 0.60
- **Type:** signaling
- **Category:** signaling
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** flag semaphore code, semaphore alphabet, visual signaling cipher, optical telegraph cipher

**Description:** Encoding alphabet as arm/flag positions. Each letter = a specific arm position pattern. Could be repurposed as a substitution cipher by mapping letter positions to numbers or coordinates.

**How it works:** Letter -> arm position pattern (angular)

**Hand-executable:** paper_pencil
**Tools needed:** semaphore reference

**K4 relevance factors:** manual_executability=7.0, artist_feasibility=7.0, short_text_plausibility=7.0, morse_signaling_relation=5.0, spatial_geometric=4.0

**Project scripts:** blitz_t_final, e06_autokey, e_aaa_indicator_sweep_07, e_aaa_tableau_struct_06, e_audit_02_strip_stagger ... (+46 more)
**Exhaustion status:** exhausted

**Open questions:**
  - Angular positions could map to compass bearings -- connection to compass cipher?

---

### 35. Straddling Checkerboard

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 42.4/100
- **Novelty-weighted Score:** 17.4
- **Obscurity:** 0.50
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** straddle cipher, straddling board, CT-35 checkerboard, Soviet checkerboard, Russian checkerboard

**Description:** Variable-length substitution cipher using a 3x10 grid. High-frequency letters get single-digit codes, others get two-digit codes. Core component of the VIC cipher. [INTERNAL RESULT] Tested as part of VIC pipeline and standalone; interesting but not breakthrough-level signal.

**How it works:** Map letters to 1 or 2 digit codes via 3-row grid with 2 blank header cells

**Hand-executable:** grid
**Tools needed:** checkerboard grid

**K4 relevance factors:** manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0, sanborn_theme_compatibility=6.0, spatial_geometric=4.0

**Project scripts:** e_k2_checkerboard_decode, e_sanborn_matrix_method_01, e_soviet_threestep_01, e_straddling_checkerboard_k4
**Exhaustion status:** exhausted

---

### 36. Grille Cipher (Stencil/Richelieu)

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 41.1/100
- **Novelty-weighted Score:** 17.1
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** mask cipher, template cipher, Richelieu cipher, window cipher, stencil cipher

**Description:** A card with holes (grille/stencil) placed over text. Only characters visible through holes carry the message. Unlike Fleissner's rotating grille, this is a fixed stencil -- used for either extraction (null cipher) or transposition.

**How it works:** Place stencil on text, read through holes

**Hand-executable:** stencil
**Tools needed:** stencil card, grid paper

**K4 relevance factors:** manual_executability=9.0, physical_aid_use=8.0, short_text_plausibility=8.0, artist_feasibility=7.0

**Project scripts:** blitz_csp_grille_structural, blitz_grille_geometry, blitz_grille_geometry_v2, blitz_grille_geometry_v3, blitz_grille_geometry_v4 ... (+157 more)
**Exhaustion status:** exhausted

---

### 37. VIC Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 42.0/100
- **Novelty-weighted Score:** 17.0
- **Obscurity:** 0.50
- **Type:** mixed
- **Category:** polyalphabetic
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** VIC, Kingdom cipher, Soviet spy cipher, Hayhanen cipher, SC cipher

**Description:** Extremely complex hand cipher used by Soviet spy Reino Hayhanen. Combines: straddling checkerboard + chain addition + disrupted transposition. Considered the most complex hand cipher ever devised. [INTERNAL RESULT] Full VIC pipeline tested (52M+ configs): NOISE. Nonstandard key schedules also tested.

**How it works:** 1) Key derivation via chain addition. 2) Straddling checkerboard substitution. 3) First transposition (disrupted). 4) Second transposition. Multiple key expansion steps.

**Hand-executable:** paper_pencil
**Tools needed:** paper, checkerboard grid, transposition grids

**K4 relevance factors:** manual_executability=9.0, artist_feasibility=7.0, short_text_plausibility=7.0, bespoke_hybrid=5.0

**Project scripts:** e_soviet_threestep_01
**Exhaustion status:** exhausted

---

### 38. Morse Fractionation Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 40.4/100
- **Novelty-weighted Score:** 16.4
- **Obscurity:** 0.60
- **Type:** fractionation
- **Category:** fractionation
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Morse cipher, Pollux cipher, Morbit cipher, Morse code cipher, fractionated Morse

**Description:** Family of ciphers that encode plaintext to Morse code (dots, dashes, spaces), then substitute the Morse symbols with letters. Pollux: assign each of 0-9 as dot, dash, or space, encode in Morse, then replace each symbol with its assigned digit. Morbit: pair Morse symbols and substitute pairs. [PUBLIC FACT] Morse code is referenced in Sanborn's handwritten notes. [INTERNAL RESULT] Pollux tested as part of fractionation campaign, structurally eliminated as single-layer (all 26 letters present in K4...

**How it works:** 1) Convert plaintext to Morse. 2) Assign letters/numbers to dots, dashes, and word/letter separators. 3) Write out the Morse stream using the assigned symbols. Decryption reverses.

**Hand-executable:** paper_pencil
**Tools needed:** Morse code chart, substitution key

**K4 relevance factors:** morse_signaling_relation=10.0, manual_executability=8.0, artist_feasibility=7.0, short_text_plausibility=7.0

**Project scripts:** blitz_yar_selective, e01_morse_e_extraction, e02_misspelling_deltas, e04_hill_cipher, e_affine_mono_disproof ... (+134 more)
**Exhaustion status:** exhausted

---

### 39. AMSCO Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 40.4/100
- **Novelty-weighted Score:** 16.4
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** AMSCO transposition, alternating mono-digraphic

**Description:** Columnar transposition where cells alternate between single letters and digraphs. [INTERNAL RESULT] w8-13 tested: ZERO Bean passes. Eliminated.

**How it works:** Fill grid alternating single and double characters per cell, then read columns

**Hand-executable:** paper_pencil
**Tools needed:** paper, pencil

**K4 relevance factors:** manual_executability=10.0, short_text_plausibility=8.0, artist_feasibility=7.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+138 more)
**Exhaustion status:** exhausted

---

### 40. Ubchi Cipher

- **Status:** [EXHAUSTED]
- **K4 Relevance Score:** 40.4/100
- **Novelty-weighted Score:** 16.4
- **Obscurity:** 0.60
- **Type:** transposition
- **Category:** transposition
- **Taxonomy:** confirmed_named_manual_cipher
- **Aliases:** Ubchi, German WWI transposition, Uebchi, double columnar German, Ubchi double transposition

**Description:** German WWI double columnar transposition. Text written into grid, columns read in key order, result written into second grid, columns read in second key order. [INTERNAL RESULT] Tested as part of TICOM campaign: NOISE.

**How it works:** Double columnar transposition with two keywords

**Hand-executable:** paper_pencil
**Tools needed:** paper, two keywords

**K4 relevance factors:** manual_executability=10.0, short_text_plausibility=8.0, artist_feasibility=7.0

**Project scripts:** agent_k4_columnar7_nonen_scan, blitz_k3_grille_v2, blitz_k3_grille_v5, blitz_strip_cipher, blitz_strip_cipher_v2 ... (+164 more)
**Exhaustion status:** exhausted

---

## Special Analysis: Sanborn-Referenced Ambiguous Terms

### Compass Cipher

Ambiguous term from Sanborn's handwritten notes. No single standard cipher bears this name. Possible interpretations: (1) A substitution cipher mapping letters to compass bearings (N, NNE, NE, etc. -- 32 points give enough symbols for 26 letters). (2) A transposition guided by compass directions on a grid. (3) A cipher using a compass rose as a key diagram. (4) A Chappe-style direction-based encoding. (5) The BERLIN CLOCK connection -- clock positions as compass points. The term may refer to a bespoke system Scheidt taught Sanborn.

**Key ambiguities:**
- No standard cipher named 'compass cipher' in cryptographic literature
- Multiple plausible interpretations
- May be a Sanborn/Scheidt invention, not a historical system

**Unresolved questions:**
- What exactly did Sanborn mean by 'compass cipher'?
- Is this related to the compass rose imagery at CIA?
- Does this connect to EASTNORTHEAST crib (directional)?
- Is it a modifier (compass-directed route) or standalone system?

### Alphabet Code

Ambiguous term from Sanborn's handwritten notes. Possible interpretations: (1) Simple A=1, B=2, ..., Z=26 numeric cipher. (2) Keyword-mixed alphabet substitution. (3) A specific 'alphabet code' system from espionage tradecraft. (4) Any system using an alphabet tableau. (5) The KA alphabet itself (KRYPTOSABCDEFGHIJLMNQUVWXZ) as a code. Given context with Beaufort and Morse on same page, likely refers to a specific substitution using a particular alphabet ordering.

**Key ambiguities:**
- Extremely generic term
- Could refer to any alphabet-based substitution
- Context with other Sanborn notes may narrow meaning

**Unresolved questions:**
- Is this the KA alphabet used as a simple substitution key?
- Or is it a numeric A=1 encoding?
- How does it interact with the other systems on Sanborn's list?

## Untested Systems with K4 Relevance > 30

| Rank | Cipher | K4 Score | Obscurity | Type |
|------|--------|----------|-----------|------|
| 1 | Astrolabe Cipher | 67.4 | 0.60 | spatial |
| 2 | Sundial/Gnomon Cipher | 60.7 | 0.60 | spatial |
| 3 | Swagman Cipher | 44.8 | 0.60 | transposition |
| 4 | Vatsyayana / Kama Sutra Cipher | 34.4 | 0.60 | substitution |
| 5 | Alberti Cipher Disk | 34.3 | 0.60 | substitution |
| 6 | Dorabella Cipher | 34.1 | 0.60 | symbolic |
| 7 | Solitaire Cipher (Pontifex) | 33.7 | 0.60 | substitution |
| 8 | Tri-Square Cipher | 33.0 | 0.60 | fractionation |
| 9 | ADFGVX Cipher | 34.4 | 0.30 | fractionation |

## Coverage Gaps and Remaining Blind Spots

[POLICY] This report does not claim complete coverage.

### Known gaps:
- Bespoke systems that Sanborn/Scheidt may have invented (unknowable without physical evidence)
- Obscure military field ciphers from classified manuals (TICOM archives partially explored)
- Regional/cultural cipher traditions (Indian, Chinese, Japanese, Arabic) beyond well-known examples
- Unpublished cipher contest entries and hobbyist inventions
- Physical/spatial ciphers specific to the Kryptos sculpture geometry
- Systems described only in private correspondence or unpublished manuscripts

### Most productive areas for expansion:
- TICOM and declassified NSA historical documents
- ACA Cryptogram back issues (many obscure cipher types defined there)
- Historical patent filings for cipher devices
- Sanborn's archives (ongoing research)
- Morse fractionation variants (Sanborn references Morse)
- Compass/navigation themed encoding (Sanborn references compass)

## Truth Taxonomy

- Cipher system descriptions: [PUBLIC FACT] from cryptographic literature
- K4 relevance scores: [HYPOTHESIS] based on heuristic rubric
- Exhaustion cross-references: [INTERNAL RESULT] from this project's exhaustion_log.json
- Sanborn/Scheidt references: [PUBLIC FACT] from Archives of American Art
- Coverage assessments: [POLICY] -- no claim of completeness
