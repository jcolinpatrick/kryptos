"""Curated knowledge base of hand-executable cipher systems.

Each entry is a dict describing a cipher system with provenance.
[POLICY] Claims about cipher mechanics are [PUBLIC FACT] from cryptographic literature.
[POLICY] K4 relevance assessments are [HYPOTHESIS] based on the scoring rubric.

This is NOT an exhaustive catalog -- it is a working knowledge base focused on
systems relevant to Kryptos K4 analysis, especially:
- Systems referenced in Sanborn/Scheidt materials
- Obscure or poorly-indexed systems that might escape standard cryptanalysis
- Systems with spatial/geometric/navigational properties
- Military field ciphers usable by non-specialists
- Bespoke or hybrid constructions an artist might devise

Sources abbreviated:
- Kahn = David Kahn, "The Codebreakers" (1967/1996)
- Friedman = William F. Friedman, military cryptography texts
- ACA = American Cryptogram Association cipher type descriptions
- Bauer = Friedrich Bauer, "Decrypted Secrets" (1997/2007)
- Singh = Simon Singh, "The Code Book" (1999)
"""

CIPHER_KNOWLEDGE_BASE = [
    # =========================================================================
    # TIER 1: Sanborn-referenced or directly K4-relevant
    # =========================================================================
    {
        "name": "Compass Cipher",
        "aliases": ["compass code", "bearing cipher", "direction cipher",
                     "cardinal cipher", "azimuth cipher", "compass rose cipher",
                     "compass point cipher", "compass rose code"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "navigational",
        "description": (
            "Ambiguous term from Sanborn's handwritten notes. No single standard "
            "cipher bears this name. Possible interpretations: (1) A substitution "
            "cipher mapping letters to compass bearings (N, NNE, NE, etc. -- 32 "
            "points give enough symbols for 26 letters). (2) A transposition "
            "guided by compass directions on a grid. (3) A cipher using a compass "
            "rose as a key diagram. (4) A Chappe-style direction-based encoding. "
            "(5) The BERLIN CLOCK connection -- clock positions as compass points. "
            "The term may refer to a bespoke system Scheidt taught Sanborn."
        ),
        "mechanics": (
            "Unknown. If directional substitution: letters assigned to compass "
            "bearings, then directions encode the message. If grid-based: write "
            "plaintext in grid, read off following compass direction pattern. "
            "Could also involve physical compass overlay on the sculpture."
        ),
        "execution": "Unknown -- likely paper/pencil with compass rose diagram",
        "tools": ["compass rose diagram", "paper", "pencil"],
        "materials": ["compass rose reference"],
        "manual_type": "grid or diagram",
        "origin": "Referenced in Jim Sanborn's handwritten notes (Archives of American Art)",
        "source_type": "primary_source",
        "source_title": "Jim Sanborn papers, Archives of American Art",
        "confidence_real": 0.4,
        "confidence_distinct": 0.9,
        "confidence_k4": 0.8,
        "historical": False,
        "bespoke": True,
        "ambiguity": [
            "No standard cipher named 'compass cipher' in cryptographic literature",
            "Multiple plausible interpretations",
            "May be a Sanborn/Scheidt invention, not a historical system",
        ],
        "questions": [
            "What exactly did Sanborn mean by 'compass cipher'?",
            "Is this related to the compass rose imagery at CIA?",
            "Does this connect to EASTNORTHEAST crib (directional)?",
            "Is it a modifier (compass-directed route) or standalone system?",
        ],
    },
    {
        "name": "Alphabet Code",
        "aliases": ["alphabet cipher", "alphabetical code", "letter code",
                     "ABC cipher", "alphabet substitution", "A=1 cipher",
                     "letter-number cipher"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "simple substitution",
        "description": (
            "Ambiguous term from Sanborn's handwritten notes. Possible "
            "interpretations: (1) Simple A=1, B=2, ..., Z=26 numeric cipher. "
            "(2) Keyword-mixed alphabet substitution. (3) A specific 'alphabet code' "
            "system from espionage tradecraft. (4) Any system using an alphabet "
            "tableau. (5) The KA alphabet itself (KRYPTOSABCDEFGHIJLMNQUVWXZ) as "
            "a code. Given context with Beaufort and Morse on same page, likely "
            "refers to a specific substitution using a particular alphabet ordering."
        ),
        "mechanics": "Unknown -- likely simple substitution with a specific alphabet",
        "execution": "Paper and pencil with alphabet reference",
        "tools": ["paper", "pencil", "alphabet key"],
        "manual_type": "paper_pencil",
        "origin": "Referenced in Jim Sanborn's handwritten notes",
        "source_type": "primary_source",
        "source_title": "Jim Sanborn papers, Archives of American Art",
        "confidence_real": 0.5,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.7,
        "historical": False,
        "bespoke": True,
        "ambiguity": [
            "Extremely generic term",
            "Could refer to any alphabet-based substitution",
            "Context with other Sanborn notes may narrow meaning",
        ],
        "questions": [
            "Is this the KA alphabet used as a simple substitution key?",
            "Or is it a numeric A=1 encoding?",
            "How does it interact with the other systems on Sanborn's list?",
        ],
    },
    {
        "name": "Beaufort Cipher",
        "aliases": ["Beaufort tableau", "Beaufort square", "Beaufort table",
                     "reciprocal cipher", "Beaufort variant"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Reciprocal polyalphabetic cipher where encryption and decryption "
            "use the same operation: C = (K - P) mod 26. Named after Francis "
            "Beaufort. Self-reciprocal: encrypting twice with same key returns "
            "plaintext. [PUBLIC FACT] Referenced in Sanborn's handwritten notes. "
            "[PUBLIC FACT] K1-K3 use Vigenere, the closely related system. "
            "[DERIVED FACT] The Beaufort A=0 keystream at crib positions shows "
            "the strongest anomalies (AP {G,K,O} at 12/24 positions, p=3.9e-6)."
        ),
        "mechanics": (
            "Use tabula recta. For each plaintext letter, find it in the column "
            "header, go down to the key letter row, read the ciphertext from the "
            "row header. Equivalently: C[i] = (K[i] - P[i]) mod 26."
        ),
        "execution": "Tabula recta or mental arithmetic mod 26",
        "tools": ["tabula recta"],
        "materials": ["alphabet table", "key word/phrase"],
        "manual_type": "tabula_recta",
        "origin": "Admiral Sir Francis Beaufort, 19th century",
        "source_type": "encyclopedia",
        "author": "Francis Beaufort",
        "year": 1857,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.9,
    },
    {
        "name": "Morse Fractionation Cipher",
        "aliases": ["Morse cipher", "Pollux cipher", "Morbit cipher",
                     "Morse code cipher", "fractionated Morse",
                     "Morse substitution"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Morse-based fractionation",
        "description": (
            "Family of ciphers that encode plaintext to Morse code (dots, dashes, "
            "spaces), then substitute the Morse symbols with letters. Pollux: "
            "assign each of 0-9 as dot, dash, or space, encode in Morse, then "
            "replace each symbol with its assigned digit. Morbit: pair Morse symbols "
            "and substitute pairs. [PUBLIC FACT] Morse code is referenced in Sanborn's "
            "handwritten notes. [INTERNAL RESULT] Pollux tested as part of fractionation "
            "campaign, structurally eliminated as single-layer (all 26 letters present "
            "in K4 CT)."
        ),
        "mechanics": (
            "1) Convert plaintext to Morse. 2) Assign letters/numbers to dots, "
            "dashes, and word/letter separators. 3) Write out the Morse stream "
            "using the assigned symbols. Decryption reverses."
        ),
        "execution": "Paper with Morse code reference and substitution key",
        "tools": ["Morse code chart", "substitution key"],
        "manual_type": "paper_pencil",
        "origin": "19th-20th century cryptographic technique",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.7,
    },
    {
        "name": "Running Key Cipher",
        "aliases": ["running key", "book key cipher", "long key cipher",
                     "running key Vigenere", "running key Beaufort",
                     "text key cipher"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Polyalphabetic cipher using a long text (book, document) as the key "
            "instead of a short repeated keyword. Each key letter is used only once. "
            "[INTERNAL RESULT] Model survives Bean constraints structurally -- 13 mono "
            "DOF make statistical detection difficult on short texts. OPEN attack "
            "surface: running key from UNTESTED source texts (Kahn, Schliemann, "
            "pre-1990 Egyptological texts)."
        ),
        "mechanics": (
            "Vigenere/Beaufort encryption where the key is drawn from a specific "
            "passage of a book or document, character by character."
        ),
        "execution": "Tabula recta + book/text as key source",
        "tools": ["tabula recta", "key text"],
        "manual_type": "tabula_recta",
        "origin": "18th century, widely used in espionage",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.85,
    },
    {
        "name": "Chart-Based Cipher (Sanborn)",
        "aliases": ["coding chart cipher", "Code Breaker overlay",
                     "overlay cipher", "transparency cipher",
                     "Sanborn chart cipher", "bespoke chart system"],
        "category": "bespoke",
        "cipher_type": "mixed",
        "family": "bespoke",
        "description": (
            "[PUBLIC FACT] Archives of American Art show Sanborn's 'Code Breaker' "
            "overlay sketch and references to 'actual coding charts'. This suggests "
            "a physical overlay or transparency-based cipher mechanism, possibly "
            "bespoke. [HYPOTHESIS] The overlay could function as a grille, stencil, "
            "or routing guide that determines which characters to read or how to "
            "permute them."
        ),
        "mechanics": "Unknown -- involves physical overlay on text/grid",
        "execution": "Physical overlay/transparency placed on text",
        "tools": ["coding chart/overlay", "grid or text layout"],
        "manual_type": "stencil",
        "origin": "Jim Sanborn, circa 1989-1990",
        "source_type": "archive",
        "source_title": "Jim Sanborn papers, Archives of American Art",
        "bespoke": True,
        "confidence_real": 0.7,
        "confidence_distinct": 0.95,
        "confidence_k4": 0.9,
        "questions": [
            "What is the exact nature of the 'Code Breaker' overlay?",
            "Does it function as a grille, stencil, or route guide?",
            "Is it in private hands or publicly accessible?",
        ],
    },

    # =========================================================================
    # TIER 2: Known hand ciphers with notable K4-relevant properties
    # =========================================================================

    # --- Transposition family ---
    {
        "name": "Turning Grille (Fleissner)",
        "aliases": ["Fleissner grille", "Cardano grille", "rotating grille",
                     "grille cipher", "revolving grille", "Fleissner grid",
                     "quadrant grille"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "grille",
        "description": (
            "Square grid with holes cut in it. Place on paper, write through holes, "
            "rotate 90 degrees, write next letters, repeat. Creates a transposition "
            "whose period is the grid area. [INTERNAL RESULT] Extensively tested -- "
            "133 scripts in grille family, 13% eliminated. Open as one layer of "
            "multi-layer construction."
        ),
        "mechanics": "Write through grille openings, rotate 90 degrees, repeat for 4 positions",
        "execution": "Physical grille on grid paper",
        "tools": ["grille (card with holes)", "grid paper"],
        "manual_type": "stencil",
        "origin": "Girolamo Cardano (1550), Eduard Fleissner (1881)",
        "source_type": "encyclopedia",
        "year": 1881,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.75,
    },
    {
        "name": "Route Cipher",
        "aliases": ["route transposition", "path cipher", "spiral cipher",
                     "diagonal cipher", "serpentine cipher", "boustrophedon cipher",
                     "zigzag route"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "route transposition",
        "description": (
            "Write plaintext into a grid, then read off following a specific route "
            "(spiral, diagonal, zigzag, etc.). Union Army used extensively in Civil War. "
            "Routes can be arbitrary, making exhaustive search difficult. Spatial/geometric "
            "nature is K4-relevant."
        ),
        "mechanics": "Fill grid row by row, read out along a path (spiral, diagonal, etc.)",
        "execution": "Paper grid with predetermined route",
        "tools": ["grid paper", "route specification"],
        "manual_type": "grid",
        "origin": "Ancient, widely used in military (Union Army Civil War)",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.7,
    },
    {
        "name": "Columnar Transposition",
        "aliases": ["columnar cipher", "column transposition",
                     "keyed columnar", "incomplete columnar",
                     "regular columnar"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Write plaintext in rows under a numbered key, read off columns in key "
            "order. [INTERNAL RESULT] Extensively tested: w5-w15 all eliminated via "
            "Bean constraint (ZERO passes at w5,w7; max 13-14/24 at w6,w8-w15). "
            "Open as one layer of multi-layer."
        ),
        "mechanics": "Write PT in rows under keyword; read columns in keyword alphabetical order",
        "execution": "Paper and pencil with keyword",
        "tools": ["paper", "pencil", "keyword"],
        "manual_type": "paper_pencil",
        "origin": "Renaissance era, widely used through WWII",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.5,
    },
    {
        "name": "Double Columnar Transposition",
        "aliases": ["double columnar", "two-pass transposition",
                     "WWII double transposition", "double transposition"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Two successive columnar transpositions with different keys. Used by SOE "
            "and resistance networks in WWII. [INTERNAL RESULT] 9 Bean-compatible "
            "width pairs tested; max 15/24 = random. Eliminated as single layer."
        ),
        "mechanics": "Apply columnar transposition twice with different keys",
        "execution": "Paper and pencil, two transposition passes",
        "tools": ["paper", "pencil", "two keywords"],
        "manual_type": "paper_pencil",
        "origin": "WWII SOE, resistance networks",
        "source_type": "encyclopedia",
        "year": 1940,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.55,
    },
    {
        "name": "Myszkowski Transposition",
        "aliases": ["Myszkowski cipher", "Myszkowski"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Variant of columnar transposition where duplicate letters in the keyword "
            "are read off together in a single pass. [INTERNAL RESULT] w5-13 tested: "
            "max 15/24 = random. Eliminated as single layer."
        ),
        "mechanics": "Like columnar but columns under duplicate key letters read left-to-right together",
        "execution": "Paper and pencil with keyword (allowing repeated letters)",
        "tools": ["paper", "pencil", "keyword"],
        "manual_type": "paper_pencil",
        "origin": "Emile Myszkowski, early 20th century",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.4,
    },
    {
        "name": "AMSCO Cipher",
        "aliases": ["AMSCO transposition", "alternating mono-digraphic"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Columnar transposition where cells alternate between single letters "
            "and digraphs. [INTERNAL RESULT] w8-13 tested: ZERO Bean passes. Eliminated."
        ),
        "mechanics": "Fill grid alternating single and double characters per cell, then read columns",
        "execution": "Paper and pencil with keyword",
        "tools": ["paper", "pencil"],
        "manual_type": "paper_pencil",
        "origin": "American Cryptogram Association",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Rail Fence Cipher",
        "aliases": ["zigzag cipher", "zigzag transposition", "rail fence",
                     "fence cipher"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "rail fence",
        "description": (
            "Write plaintext in zigzag pattern across N rails, read off row by row. "
            "Very simple transposition with limited key space (number of rails)."
        ),
        "mechanics": "Write in zigzag across N rows, read each row left to right",
        "execution": "Paper and pencil",
        "tools": ["paper"],
        "manual_type": "paper_pencil",
        "origin": "Ancient, rediscovered many times",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Redefence Cipher",
        "aliases": ["Redefence", "redefence transposition", "keyed rail fence"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "rail fence",
        "description": (
            "Rail fence variant where the rails are read off in a keyed order "
            "rather than top-to-bottom. Adds a keyword-based permutation to "
            "the rail fence's zigzag pattern."
        ),
        "mechanics": "Zigzag write as rail fence, but read rails in keyword order",
        "execution": "Paper and pencil with keyword",
        "tools": ["paper", "pencil", "keyword"],
        "manual_type": "paper_pencil",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.45,
    },
    {
        "name": "Cadenus Cipher",
        "aliases": ["Cadenus", "keyed period transposition"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Transposition cipher where the message length must be a multiple of 25. "
            "Text is written into a 25-row grid, columns are rearranged by keyword, "
            "then rows are shifted progressively. Unusual: requires exactly 25 rows."
        ),
        "mechanics": "Fill 25-row grid, permute columns, shift rows progressively",
        "execution": "Paper grid with keyword",
        "tools": ["paper", "pencil", "keyword"],
        "manual_type": "grid",
        "origin": "ACA classical cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.35,
        "questions": ["97 chars mod 25 = 22 -- needs padding. Does this eliminate it?"],
    },
    {
        "name": "Swagman Cipher",
        "aliases": ["Swagman", "Australian cipher"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Australian transposition cipher using a grid where each row and column "
            "contains exactly one marked cell (a Latin square pattern). Text fills "
            "marked cells, creating a complex transposition."
        ),
        "mechanics": "Fill cells marked in Latin square pattern, read off in order",
        "execution": "Paper grid with Latin square key",
        "tools": ["paper", "grid key"],
        "manual_type": "grid",
        "origin": "ACA cipher type, possibly Australian military",
        "source_type": "encyclopedia",
        "confidence_real": 0.8,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.35,
    },
    {
        "name": "Disrupted Transposition",
        "aliases": ["irregular transposition", "disrupted columnar",
                     "interrupted columnar", "incomplete transposition"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Columnar transposition where certain cells in the grid are blocked off "
            "(disrupted), causing irregular column lengths. Used by SOE agents in WWII. "
            "The disruption pattern adds complexity beyond standard columnar."
        ),
        "mechanics": "Fill grid skipping blocked cells, then read columns in key order",
        "execution": "Paper grid with disruption pattern and keyword",
        "tools": ["paper", "pencil", "keyword", "disruption key"],
        "manual_type": "grid",
        "origin": "SOE, WWII",
        "source_type": "military_manual",
        "year": 1942,
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.55,
    },

    # --- Fractionation family ---
    {
        "name": "Straddling Checkerboard",
        "aliases": ["straddle cipher", "straddling board", "CT-35 checkerboard",
                     "Soviet checkerboard", "Russian checkerboard"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "checkerboard",
        "description": (
            "Variable-length substitution cipher using a 3x10 grid. High-frequency "
            "letters get single-digit codes, others get two-digit codes. Core component "
            "of the VIC cipher. [INTERNAL RESULT] Tested as part of VIC pipeline and "
            "standalone; interesting but not breakthrough-level signal."
        ),
        "mechanics": "Map letters to 1 or 2 digit codes via 3-row grid with 2 blank header cells",
        "execution": "Paper with checkerboard grid",
        "tools": ["checkerboard grid"],
        "manual_type": "grid",
        "origin": "Russian/Soviet intelligence, 1920s+",
        "source_type": "encyclopedia",
        "year": 1920,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.6,
    },
    {
        "name": "ADFGVX Cipher",
        "aliases": ["ADFGX cipher", "ADFGVX", "German WWI cipher",
                     "Nebel cipher"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "polybius transposition",
        "description": (
            "WWI German cipher: Polybius substitution (6x6 grid labeled ADFGVX) "
            "followed by columnar transposition. [INTERNAL RESULT] Structurally "
            "eliminated as single layer (requires fractionation output alphabet "
            "of only 6 letters, but K4 has 26)."
        ),
        "mechanics": "Polybius 6x6 encode, then columnar transposition on the pairs",
        "execution": "6x6 grid + columnar transposition",
        "tools": ["6x6 grid", "keyword"],
        "manual_type": "grid",
        "origin": "Fritz Nebel, German Army, 1918",
        "source_type": "encyclopedia",
        "year": 1918,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Bifid Cipher",
        "aliases": ["Delastelle bifid", "bifid"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Delastelle",
        "description": (
            "Fractionation cipher using 5x5 Polybius square. Letters become row+column "
            "coordinates, coordinates are interleaved, then converted back to letters. "
            "[INTERNAL RESULT] Structurally eliminated: requires 5x5 grid (25 letters, "
            "I/J merged) but K4 CT contains all 26 distinct letters."
        ),
        "mechanics": "Polybius encode to pairs, interleave row/col digits, Polybius decode",
        "execution": "5x5 grid and paper",
        "tools": ["5x5 Polybius square"],
        "manual_type": "grid",
        "origin": "Felix Delastelle, 1901",
        "source_type": "encyclopedia",
        "year": 1901,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.15,
        "ambiguity": ["Eliminated as single layer due to 25-letter alphabet requirement"],
    },
    {
        "name": "Trifid Cipher",
        "aliases": ["Delastelle trifid", "trifid", "three-dimensional fractionation"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Delastelle",
        "description": (
            "Extension of bifid to three dimensions (3x3x3 = 27 cells). Each letter "
            "gets three coordinates. Fractionation occurs across three coordinate "
            "streams. Can use a 27-symbol alphabet (26 letters + separator). "
            "[INTERNAL RESULT] Structurally eliminated as single layer."
        ),
        "mechanics": "3D coordinate encoding, interleave three streams, decode back",
        "execution": "3x3x3 grid reference and paper",
        "tools": ["trifid grid reference"],
        "manual_type": "grid",
        "origin": "Felix Delastelle, 1901",
        "source_type": "encyclopedia",
        "year": 1901,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.2,
    },
    {
        "name": "Four-Square Cipher",
        "aliases": ["four-square", "Delastelle four-square", "4-square"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Delastelle",
        "description": (
            "Digraphic substitution using four 5x5 grids arranged in a square. "
            "Two are plain alphabets, two are keyed. [INTERNAL RESULT] Structurally "
            "eliminated (25-letter alphabet)."
        ),
        "mechanics": "Digraph input, locate in plain grids, cross-reference keyed grids",
        "execution": "Four 5x5 grids on paper",
        "tools": ["four 5x5 grids"],
        "manual_type": "grid",
        "origin": "Felix Delastelle",
        "source_type": "encyclopedia",
        "year": 1902,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.15,
    },
    {
        "name": "Two-Square Cipher",
        "aliases": ["double Playfair", "two-square", "Playfair variant"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Playfair family",
        "description": (
            "Digraphic cipher using two 5x5 Polybius squares side by side. Input "
            "digraphs are located in the two squares and output is read from the "
            "rectangle corners. Requires 25-letter alphabet."
        ),
        "mechanics": "Two 5x5 grids, locate input pair, read rectangle corners",
        "execution": "Two 5x5 grids on paper",
        "tools": ["two 5x5 grids"],
        "manual_type": "grid",
        "origin": "Variant of Playfair, early 20th century",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.15,
    },
    {
        "name": "Playfair Cipher",
        "aliases": ["Playfair", "Playfair square", "Wheatstone-Playfair"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Playfair family",
        "description": (
            "Digraphic cipher using a single 5x5 grid. [INTERNAL RESULT] Structurally "
            "eliminated: requires 25-letter alphabet (I/J merge), K4 has all 26."
        ),
        "mechanics": "Digraph pairs located in 5x5 grid, encrypt by rectangle/row/column rules",
        "execution": "5x5 grid on paper",
        "tools": ["5x5 keyed grid"],
        "manual_type": "grid",
        "origin": "Charles Wheatstone, 1854 (popularized by Lord Playfair)",
        "source_type": "encyclopedia",
        "year": 1854,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.15,
    },
    {
        "name": "Tri-Square Cipher",
        "aliases": ["tri-square", "three-square", "trisquare"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Playfair family",
        "description": (
            "Trigraphic cipher using three 5x5 grids. Processes three letters at a time "
            "using geometric relationships across three grids. Requires 25-letter alphabet."
        ),
        "mechanics": "Three 5x5 grids, process trigraphs via geometric lookup",
        "execution": "Three 5x5 grids on paper",
        "tools": ["three 5x5 grids"],
        "manual_type": "grid",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 0.9,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.15,
    },
    {
        "name": "Monome-Dinome Cipher",
        "aliases": ["monome dinome", "mono-dinome", "variable-length substitution",
                     "monome-dinome"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "checkerboard",
        "description": (
            "Substitution where some letters get 1-digit codes and others get 2-digit "
            "codes (like straddling checkerboard but may use different grid layouts). "
            "Produces variable-length numeric intermediate that can feed into further "
            "operations."
        ),
        "mechanics": "Map high-frequency letters to 1 digit, others to 2 digits",
        "execution": "Lookup table on paper",
        "tools": ["substitution table"],
        "manual_type": "paper_pencil",
        "origin": "Early 20th century intelligence tradecraft",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.5,
    },
    {
        "name": "Conjugated Matrix Bifid",
        "aliases": ["CM bifid", "conjugated bifid", "seriated bifid",
                     "seriated playfair"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Delastelle",
        "description": (
            "Bifid variant using two different 5x5 matrices -- one for encoding, "
            "one for decoding. More secure than standard bifid. Still requires "
            "25-letter alphabet."
        ),
        "mechanics": "Bifid process but with different encode/decode Polybius squares",
        "execution": "Two 5x5 grids on paper",
        "tools": ["two 5x5 grids"],
        "manual_type": "grid",
        "origin": "ACA extension of bifid",
        "source_type": "encyclopedia",
        "confidence_real": 0.9,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.15,
    },
    {
        "name": "Slidefair Cipher",
        "aliases": ["Slidefair", "sliding Playfair"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Playfair family",
        "description": (
            "Playfair variant where the keyword alphabet 'slides' between digraph "
            "encryptions, creating a polyalphabetic effect. Each digraph uses a "
            "slightly different grid arrangement."
        ),
        "mechanics": "Playfair encryption where grid shifts by keyword for each digraph",
        "execution": "5x5 grid with shifting mechanism",
        "tools": ["5x5 grid", "keyword"],
        "manual_type": "grid",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 0.9,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.2,
    },

    # --- Polyalphabetic family ---
    {
        "name": "Nihilist Cipher",
        "aliases": ["Nihilist substitution", "Russian Nihilist cipher"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Polybius-based",
        "description": (
            "Two-digit Polybius encoding of plaintext, plus two-digit Polybius encoding "
            "of keyword, added together. Result is two-digit numbers. Used by Russian "
            "Nihilist revolutionaries in 19th century."
        ),
        "mechanics": "Polybius-encode PT and key, add digit pairs, output sums",
        "execution": "5x5 Polybius grid and addition",
        "tools": ["5x5 grid"],
        "manual_type": "grid",
        "origin": "Russian Nihilist revolutionaries, 1880s",
        "source_type": "encyclopedia",
        "year": 1880,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.4,
    },
    {
        "name": "VIC Cipher",
        "aliases": ["VIC", "Kingdom cipher", "Soviet spy cipher",
                     "Hayhanen cipher", "SC cipher"],
        "category": "polyalphabetic",
        "cipher_type": "mixed",
        "family": "Soviet intelligence",
        "description": (
            "Extremely complex hand cipher used by Soviet spy Reino Hayhanen. "
            "Combines: straddling checkerboard + chain addition + disrupted "
            "transposition. Considered the most complex hand cipher ever devised. "
            "[INTERNAL RESULT] Full VIC pipeline tested (52M+ configs): NOISE. "
            "Nonstandard key schedules also tested."
        ),
        "mechanics": (
            "1) Key derivation via chain addition. 2) Straddling checkerboard "
            "substitution. 3) First transposition (disrupted). 4) Second "
            "transposition. Multiple key expansion steps."
        ),
        "execution": "Paper with checkerboard and transposition grids",
        "tools": ["paper", "checkerboard grid", "transposition grids"],
        "manual_type": "paper_pencil",
        "origin": "Soviet KGB, 1950s (discovered 1957)",
        "source_type": "encyclopedia",
        "year": 1953,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.5,
    },
    {
        "name": "Porta Cipher",
        "aliases": ["Porta", "Giambattista della Porta cipher",
                     "Porta reciprocal cipher", "della Porta"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "reciprocal polyalphabetic",
        "description": (
            "Polyalphabetic cipher using 13 alphabets (key letters pair: AB, CD, etc.). "
            "Each alphabet swaps pairs of letters. Self-reciprocal within each alphabet. "
            "Only uses 13 distinct alphabets, so effective key period is halved."
        ),
        "mechanics": "13 reciprocal alphabets selected by key letter pairs",
        "execution": "Porta tableau on paper",
        "tools": ["Porta tableau"],
        "manual_type": "tabula_recta",
        "origin": "Giambattista della Porta, 1563",
        "source_type": "encyclopedia",
        "year": 1563,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.35,
    },
    {
        "name": "Gronsfeld Cipher",
        "aliases": ["Gronsfeld", "numeric Vigenere", "Gronsfeld shift"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Vigenere variant where the key is a sequence of digits (0-9) rather than "
            "letters (0-25). Limits each shift to at most 9, reducing key space."
        ),
        "mechanics": "Vigenere with numeric key (each digit 0-9 shifts that position)",
        "execution": "Mental arithmetic or simple table",
        "tools": ["paper", "numeric key"],
        "manual_type": "paper_pencil",
        "origin": "Count de Gronsfeld, 17th century",
        "source_type": "encyclopedia",
        "year": 1670,
        "confidence_real": 1.0,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.3,
    },
    {
        "name": "Quagmire Cipher",
        "aliases": ["Quagmire I", "Quagmire II", "Quagmire III",
                     "Quagmire IV", "mixed-alphabet Vigenere"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Family of polyalphabetic ciphers using mixed alphabets in the Vigenere "
            "tableau. Four variants: I (mixed PT alphabet), II (mixed CT alphabet), "
            "III (both mixed, same keyword), IV (both mixed, different keywords). "
            "More resistant to standard Vigenere attacks."
        ),
        "mechanics": "Vigenere with one or both alphabets keyword-mixed",
        "execution": "Modified Vigenere tableau on paper",
        "tools": ["modified tableau", "keyword(s)"],
        "manual_type": "tabula_recta",
        "origin": "ACA cipher type classification",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.5,
        "questions": ["K1-K3 use keyword-mixed alphabets; is K4 a Quagmire variant?"],
    },
    {
        "name": "Gromark Cipher",
        "aliases": ["Gromark", "grille-marked cipher", "Fibonacci key cipher"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "progressive key",
        "description": (
            "Polyalphabetic cipher using a key sequence generated by a linear "
            "recurrence (like Fibonacci mod 10). [INTERNAL RESULT] Orders 1-8, "
            "8.74 billion configs tested: Bean impossibility. Eliminated."
        ),
        "mechanics": "Polyalphabetic with key from linear recurrence sequence",
        "execution": "Paper with recurrence computation",
        "tools": ["paper", "starting key digits"],
        "manual_type": "paper_pencil",
        "origin": "U.S. Army, WWII era",
        "source_type": "military_manual",
        "year": 1943,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.2,
    },
    {
        "name": "Interrupted Key Cipher",
        "aliases": ["interrupted key", "interrupted keyword",
                     "broken key cipher", "segmented key"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Vigenere variant where the key restarts at word boundaries in the "
            "plaintext. Knowledge of word boundaries is needed. "
            "[INTERNAL RESULT] 14.7M configs tested: eliminated."
        ),
        "mechanics": "Vigenere where key resets at each plaintext word boundary",
        "execution": "Tabula recta with key restart rules",
        "tools": ["tabula recta", "keyword"],
        "manual_type": "tabula_recta",
        "origin": "Historical variant of Vigenere",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.2,
    },
    {
        "name": "Progressive Key Cipher",
        "aliases": ["progressive substitution", "Trithemius progression",
                     "progressive cipher"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "progressive",
        "description": (
            "Polyalphabetic cipher where the key shift increases by a constant "
            "amount at each position (arithmetic progression). Trithemius's "
            "original idea. [INTERNAL RESULT] Eliminated: Bean proof shows "
            "delta must be in {0, 13} only."
        ),
        "mechanics": "Shift increases by constant d each position: key[i] = (start + i*d) mod 26",
        "execution": "Mental arithmetic or table",
        "tools": ["paper"],
        "manual_type": "paper_pencil",
        "origin": "Johannes Trithemius, 1508",
        "source_type": "encyclopedia",
        "year": 1508,
        "confidence_real": 1.0,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.15,
    },
    {
        "name": "Autokey Cipher",
        "aliases": ["autokey", "autokey Vigenere", "self-key cipher",
                     "Blaise de Vigenere autokey"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Vigenere variant where after the keyword, the key continues with the "
            "plaintext itself (PT-autokey) or ciphertext (CT-autokey). "
            "[INTERNAL RESULT] ALL autokey variants eliminated -- structural proof "
            "shows PT-max=16/24, CT-max=21/24 under arbitrary transposition."
        ),
        "mechanics": "Key = keyword || plaintext (or ciphertext) used as continuing key",
        "execution": "Tabula recta with self-extending key",
        "tools": ["tabula recta"],
        "manual_type": "tabula_recta",
        "origin": "Blaise de Vigenere, 1586",
        "source_type": "encyclopedia",
        "year": 1586,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.05,
    },

    # --- Mechanical / device ciphers doable by hand ---
    {
        "name": "Chaocipher",
        "aliases": ["Chaocipher", "Byrne cipher machine", "Byrne cipher"],
        "category": "mechanical",
        "cipher_type": "substitution",
        "family": "dynamic alphabet",
        "description": (
            "Cipher using two circular alphabets that permute after each letter "
            "is encrypted. Created by John Byrne in 1918, algorithm secret until "
            "2010. Produces highly irregular substitution. Can be done with two "
            "strips of paper in a loop. Interesting because it produces flat "
            "frequency distribution (like K4)."
        ),
        "mechanics": "Two circular alphabets; after each encryption, extract and reinsert letters",
        "execution": "Two paper alphabet loops or simulation by hand",
        "tools": ["two circular alphabet strips"],
        "manual_type": "paper_pencil",
        "origin": "John F. Byrne, 1918 (algorithm published 2010)",
        "source_type": "encyclopedia",
        "year": 1918,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.5,
        "questions": ["Has Chaocipher been tested against K4 CT?"],
    },
    {
        "name": "Wheatstone Cryptograph",
        "aliases": ["Wheatstone cipher", "Playfair wheel", "Wheatstone device",
                     "Wheatstone clock cipher"],
        "category": "mechanical",
        "cipher_type": "substitution",
        "family": "mechanical polyalphabetic",
        "description": (
            "Two concentric disks with alphabets. Outer ring has 27 positions "
            "(26 letters + blank), inner has 26. Rotating produces polyalphabetic "
            "effect with irregular period. [INTERNAL RESULT] 327M configs tested: "
            "NOISE. Eliminated."
        ),
        "mechanics": "Two concentric alphabet disks; outer advances by 1, inner by gearing ratio",
        "execution": "Physical disk device (or paper simulation)",
        "tools": ["Wheatstone device or paper disk"],
        "manual_type": "paper_pencil",
        "origin": "Charles Wheatstone, 1867",
        "source_type": "encyclopedia",
        "year": 1867,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Bazeries Cylinder / Jefferson Wheel",
        "aliases": ["Bazeries cipher", "Jefferson wheel", "cipher cylinder",
                     "wheel cipher", "strip cipher", "M-94", "M-138",
                     "Jefferson disk"],
        "category": "mechanical",
        "cipher_type": "transposition",
        "family": "cylinder cipher",
        "description": (
            "Set of numbered disks on an axle, each with a scrambled alphabet around "
            "the edge. Align plaintext on one row, read ciphertext from another row. "
            "M-94 (25 disks) used by U.S. Army through WWII."
        ),
        "mechanics": "Align PT on selected row of multi-disk cylinder, read CT from different row",
        "execution": "Physical cylinder device (or paper strips)",
        "tools": ["cipher cylinder or paper strips"],
        "manual_type": "paper_pencil",
        "origin": "Thomas Jefferson (1795), Bazeries (1891), U.S. Army M-94 (1922)",
        "source_type": "encyclopedia",
        "year": 1795,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.4,
    },
    {
        "name": "Alberti Cipher Disk",
        "aliases": ["Alberti disk", "Alberti cipher", "cipher disk",
                     "cipher wheel"],
        "category": "mechanical",
        "cipher_type": "substitution",
        "family": "polyalphabetic",
        "description": (
            "Earliest known polyalphabetic device. Two concentric disks with alphabets. "
            "Rotate inner disk to change cipher alphabet. Index character signals "
            "rotation. Important historically as origin of polyalphabetic idea."
        ),
        "mechanics": "Two concentric disks; rotate inner disk periodically during encryption",
        "execution": "Physical disk or paper simulation",
        "tools": ["cipher disk"],
        "manual_type": "paper_pencil",
        "origin": "Leon Battista Alberti, 1467",
        "source_type": "encyclopedia",
        "year": 1467,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.35,
    },
    {
        "name": "Hagelin Cipher (C-35/M-209)",
        "aliases": ["Hagelin machine", "C-35", "M-209", "CX-52",
                     "pin-and-lug cipher", "Hagelin"],
        "category": "mechanical",
        "cipher_type": "substitution",
        "family": "mechanical",
        "description": (
            "Mechanical cipher machine using pin wheels and lug bars to generate "
            "keystream. M-209 used extensively by U.S. military in WWII. Not truly "
            "hand-executable without the device, but the mathematical operation "
            "(mod-26 subtraction with variable displacement) is simple."
        ),
        "mechanics": "Pin wheels set displacement, subtract from plaintext mod 26",
        "execution": "Requires physical machine; mathematical operation is simple",
        "tools": ["Hagelin machine"],
        "manual_type": "mechanical_device",
        "origin": "Boris Hagelin, 1935",
        "source_type": "encyclopedia",
        "year": 1935,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.25,
    },

    # --- Book / text / steganographic ---
    {
        "name": "Book Cipher",
        "aliases": ["book code", "Beale cipher", "Beale code",
                     "dictionary cipher", "page-line-word cipher",
                     "straddling book code"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "codebook",
        "description": (
            "Each plaintext letter or word is encoded as a reference to a position "
            "in a shared book (page/line/word or word number). Beale ciphers use "
            "word-initial letters from the Declaration of Independence. Output is "
            "typically numeric."
        ),
        "mechanics": "Replace each PT letter with a number pointing to a position in the key text",
        "execution": "Book/text and counting",
        "tools": ["shared book/text"],
        "manual_type": "paper_pencil",
        "origin": "Ancient, many variants",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.4,
        "questions": ["Output is numeric -- would need a second layer to produce alphabetic CT"],
    },
    {
        "name": "Null Cipher",
        "aliases": ["null code", "open code", "concealment cipher",
                     "first-letter cipher", "acrostic cipher",
                     "hidden word cipher"],
        "category": "steganographic",
        "cipher_type": "steganographic",
        "family": "concealment",
        "description": (
            "Message hidden within cover text by reading specific positions "
            "(first letters, nth words, etc.). K4 null hypothesis: certain positions "
            "carry the real message, others are padding. [INTERNAL RESULT] Null palette "
            "{B,G,I,K,O,W,Z} is statistically anomalous (p~3e-5) but model-conditional."
        ),
        "mechanics": "Select specific positions from cover text to extract hidden message",
        "execution": "Counting and extraction from text",
        "tools": ["paper", "extraction rule"],
        "manual_type": "paper_pencil",
        "origin": "Ancient, used extensively in espionage",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.7,
    },
    {
        "name": "Grille Cipher (Stencil/Richelieu)",
        "aliases": ["mask cipher", "template cipher", "Richelieu cipher",
                     "window cipher", "stencil cipher"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "grille",
        "description": (
            "A card with holes (grille/stencil) placed over text. Only characters "
            "visible through holes carry the message. Unlike Fleissner's rotating "
            "grille, this is a fixed stencil -- used for either extraction (null "
            "cipher) or transposition."
        ),
        "mechanics": "Place stencil on text, read through holes",
        "execution": "Physical stencil on text",
        "tools": ["stencil card", "grid paper"],
        "manual_type": "stencil",
        "origin": "Cardinal Richelieu (attributed), 17th century",
        "source_type": "encyclopedia",
        "year": 1640,
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.7,
    },
    {
        "name": "Homophonic Cipher",
        "aliases": ["homophonic substitution", "multiple-equivalent cipher",
                     "homophonic"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "monoalphabetic extensions",
        "description": (
            "Each plaintext letter can be replaced by one of several symbols "
            "(multiple homophones), chosen to flatten frequency distribution. "
            "[INTERNAL RESULT] Tested (e_cfm_04_homophonic): eliminated as pure "
            "homophonic on 26-letter alphabet (requires more than 26 output symbols)."
        ),
        "mechanics": "Map each PT letter to one of several possible CT symbols",
        "execution": "Lookup table on paper",
        "tools": ["homophonic substitution table"],
        "manual_type": "paper_pencil",
        "origin": "9th century Arabic, widely used in Renaissance",
        "source_type": "encyclopedia",
        "year": 900,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.25,
    },
    {
        "name": "Nomenclator",
        "aliases": ["nomenclator cipher", "Renaissance cipher",
                     "diplomatic cipher code", "Great Cipher"],
        "category": "substitution",
        "cipher_type": "mixed",
        "family": "code-cipher hybrid",
        "description": (
            "Hybrid system combining a codebook (for common words/phrases) with a "
            "cipher (for letters not in codebook). Used for centuries in diplomatic "
            "correspondence. [INTERNAL RESULT] Tested (e_cfm_05_nomenclator): eliminated "
            "as pure nomenclator."
        ),
        "mechanics": "Code table for words + cipher for remaining letters",
        "execution": "Codebook + cipher table on paper",
        "tools": ["codebook", "cipher table"],
        "manual_type": "paper_pencil",
        "origin": "15th century diplomatic use",
        "source_type": "encyclopedia",
        "year": 1400,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.25,
    },

    # --- Military field ciphers ---
    {
        "name": "Rasterschlussel 44 (RS44)",
        "aliases": ["RS44", "Rasterschlussel", "German grid cipher",
                     "WWII grid mask cipher", "Raster key"],
        "category": "grille",
        "cipher_type": "mixed",
        "family": "grid mask",
        "description": (
            "WWII German field cipher: grid mask (grille) selecting positions, "
            "combined with substitution. [INTERNAL RESULT] 905.6M configs tested: "
            "NOISE. Eliminated."
        ),
        "mechanics": "Grid mask extraction + substitution + transposition",
        "execution": "Physical grid mask on message form",
        "tools": ["grid mask", "substitution table"],
        "manual_type": "stencil",
        "origin": "German Wehrmacht, 1944",
        "source_type": "military_manual",
        "year": 1944,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Ubchi Cipher",
        "aliases": ["Ubchi", "German WWI transposition", "Uebchi",
                     "double columnar German", "Ubchi double transposition"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "German WWI double columnar transposition. Text written into grid, "
            "columns read in key order, result written into second grid, columns "
            "read in second key order. [INTERNAL RESULT] Tested as part of TICOM "
            "campaign: NOISE."
        ),
        "mechanics": "Double columnar transposition with two keywords",
        "execution": "Paper and pencil, two transposition passes",
        "tools": ["paper", "two keywords"],
        "manual_type": "paper_pencil",
        "origin": "German Army, WWI",
        "source_type": "military_manual",
        "year": 1916,
        "confidence_real": 1.0,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.3,
    },
    {
        "name": "BATCO",
        "aliases": ["BATCO cipher", "British Army tactical code",
                     "SLIDEX", "tactical battlefield cipher"],
        "category": "military",
        "cipher_type": "substitution",
        "family": "field cipher",
        "description": (
            "British Army tactical communication cipher. One-time card system with "
            "sliding scales for battlefield use. Simple enough for soldiers under fire. "
            "SLIDEX is a related NATO system."
        ),
        "mechanics": "Slide card reveals substitution alphabets for given setting",
        "execution": "Physical slide card",
        "tools": ["BATCO/SLIDEX card"],
        "manual_type": "mechanical_device",
        "origin": "British Army, Cold War era",
        "source_type": "military_manual",
        "year": 1960,
        "confidence_real": 1.0,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.35,
    },
    {
        "name": "Phillips Cipher",
        "aliases": ["Phillips", "progressive Playfair", "Phillips classical cipher"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "Playfair family",
        "description": (
            "Progressive Playfair variant where the 5x5 grid is shifted after "
            "each digraph encryption. Creates a polyalphabetic Playfair effect. "
            "Requires 25-letter alphabet (I/J merged)."
        ),
        "mechanics": "Playfair with grid rotation/shift after each digraph",
        "execution": "5x5 grid with shifting rule",
        "tools": ["5x5 grid", "shift rule"],
        "manual_type": "grid",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 0.9,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.15,
    },
    {
        "name": "Grandpre Cipher",
        "aliases": ["Grandpre", "Grand Pre", "digit substitution",
                     "10x10 cipher table"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "homophonic",
        "description": (
            "Uses a 10x10 grid filled with the alphabet repeated ~4 times. Each "
            "letter can be represented by its row+column coordinate, giving "
            "multiple options (homophonic). Output is two-digit numbers."
        ),
        "mechanics": "10x10 grid lookup, each letter has ~4 possible row-column pairs",
        "execution": "10x10 grid on paper",
        "tools": ["10x10 grid"],
        "manual_type": "grid",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 0.9,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.3,
    },
    {
        "name": "Solitaire Cipher (Pontifex)",
        "aliases": ["Pontifex cipher", "Schneier Solitaire",
                     "playing card cipher", "Solitaire"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "stream cipher",
        "description": (
            "Stream cipher using a deck of playing cards as the keystream generator. "
            "Designed by Bruce Schneier for Neal Stephenson's Cryptonomicon (1999). "
            "Post-dates Kryptos (1990) but demonstrates that card-based hand ciphers "
            "are feasible."
        ),
        "mechanics": "Card deck permutation generates keystream; add to plaintext mod 26",
        "execution": "Deck of 54 cards, paper and pencil",
        "tools": ["playing cards", "paper"],
        "manual_type": "paper_pencil",
        "origin": "Bruce Schneier, 1999",
        "source_type": "book",
        "author": "Bruce Schneier",
        "year": 1999,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.2,
        "ambiguity": ["Post-dates Kryptos construction by 9 years"],
    },

    # --- Signaling / encoding systems ---
    {
        "name": "Polybius Square",
        "aliases": ["Polybius cipher", "Polybius checkerboard", "5x5 grid cipher",
                     "Polybius", "knock code", "tap code", "prison tap code"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Polybius",
        "description": (
            "5x5 grid mapping letters to row-column coordinate pairs. Foundation "
            "of many cipher systems (bifid, trifid, ADFGVX, Nihilist). Also used "
            "as the 'tap code' in prisons/POW camps."
        ),
        "mechanics": "Letter -> (row, column) coordinate pair",
        "execution": "5x5 grid lookup",
        "tools": ["5x5 grid"],
        "manual_type": "grid",
        "origin": "Polybius, ~200 BC",
        "source_type": "encyclopedia",
        "year": -200,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Semaphore Cipher",
        "aliases": ["flag semaphore code", "semaphore alphabet",
                     "visual signaling cipher", "optical telegraph cipher"],
        "category": "signaling",
        "cipher_type": "signaling",
        "family": "visual signaling",
        "description": (
            "Encoding alphabet as arm/flag positions. Each letter = a specific "
            "arm position pattern. Could be repurposed as a substitution cipher "
            "by mapping letter positions to numbers or coordinates."
        ),
        "mechanics": "Letter -> arm position pattern (angular)",
        "execution": "Reference chart",
        "tools": ["semaphore reference"],
        "manual_type": "paper_pencil",
        "origin": "Claude Chappe, 1790s (modern form: ~1860s)",
        "source_type": "encyclopedia",
        "year": 1790,
        "confidence_real": 1.0,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.3,
        "questions": ["Angular positions could map to compass bearings -- connection to compass cipher?"],
    },
    {
        "name": "Pigpen Cipher",
        "aliases": ["Freemason cipher", "Masonic cipher", "pigpen",
                     "tic-tac-toe cipher", "Knights Templar cipher"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "geometric substitution",
        "description": (
            "Geometric substitution: letters mapped to fragments of grid and X "
            "patterns. Output is symbols, not letters. Widely known as a 'secret "
            "code' among children and Freemasons. Not directly applicable to K4 "
            "(output is symbols, not letters) unless used as an intermediate step."
        ),
        "mechanics": "Replace each letter with its geometric symbol from pigpen grid",
        "execution": "Pigpen key diagram",
        "tools": ["pigpen diagram"],
        "manual_type": "paper_pencil",
        "origin": "Freemasons, 18th century (possibly older)",
        "source_type": "encyclopedia",
        "year": 1700,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.1,
        "pedagogical": True,
    },
    {
        "name": "Clock Cipher",
        "aliases": ["clock code", "clock position cipher", "time cipher",
                     "dial cipher", "Berlin clock cipher", "horologe cipher"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "positional",
        "description": (
            "Letters mapped to clock face positions (1-12 or 1-24). Can use "
            "hour+minute positions for digraphic encoding. 'BERLINCLOCK' is a "
            "K4 crib, making clock-based systems highly relevant. The Berlin "
            "Mengenlehreuhr (set-theory clock) uses a unique time display that "
            "could serve as an encoding scheme."
        ),
        "mechanics": "Map letters to clock positions; various schemes possible",
        "execution": "Clock face diagram or mental mapping",
        "tools": ["clock face reference"],
        "manual_type": "paper_pencil",
        "origin": "Various historical uses; Berlin clock since 1975",
        "source_type": "encyclopedia",
        "confidence_real": 0.6,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.75,
        "questions": [
            "Does BERLINCLOCK crib imply a clock-based cipher layer?",
            "Does the Mengenlehreuhr display map to an encoding scheme?",
        ],
    },
    {
        "name": "Coordinate/Grid Reference Cipher",
        "aliases": ["grid cipher", "coordinate cipher", "map grid cipher",
                     "grid reference cipher", "geographic cipher",
                     "geodetic cipher", "latitude longitude cipher"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "positional",
        "description": (
            "Letters encoded as grid coordinates (like map grid references). "
            "Various schemes: simple (row, col), military grid reference, "
            "or geographic coordinates. K4 themes include coordinates and "
            "navigation. EASTNORTHEAST crib is directional."
        ),
        "mechanics": "Map letters to coordinate pairs on a grid",
        "execution": "Grid reference sheet",
        "tools": ["grid", "coordinate system"],
        "manual_type": "grid",
        "origin": "Military cartography, various periods",
        "source_type": "encyclopedia",
        "confidence_real": 0.7,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.65,
    },
    {
        "name": "Scytale Cipher",
        "aliases": ["Scytale", "Spartan cipher", "staff cipher", "rod cipher"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "physical transposition",
        "description": (
            "Oldest known cipher device. Wrap strip of leather/paper around a rod "
            "of specific diameter, write message across, unwrap. Reading the strip "
            "without the correct diameter yields scrambled text. Equivalent to "
            "simple columnar transposition."
        ),
        "mechanics": "Wrap strip around rod, write rows, unwrap = columnar transposition",
        "execution": "Rod/cylinder and strip",
        "tools": ["rod of correct diameter", "paper strip"],
        "manual_type": "paper_pencil",
        "origin": "Spartan military, ~700 BC",
        "source_type": "encyclopedia",
        "year": -700,
        "confidence_real": 1.0,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.2,
    },

    # =========================================================================
    # TIER 3: Obscure, edge-case, or K4-specific interest systems
    # =========================================================================
    {
        "name": "Trithemius Cipher (Ave Maria)",
        "aliases": ["Trithemius tableau", "Ave Maria cipher",
                     "Steganographia cipher", "Trithemius Ave Maria"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "polyalphabetic",
        "description": (
            "Trithemius's Steganographia (1499/1606) encoded messages as prayers "
            "or angel invocations. Each 'angel name' mapped to a letter. Also "
            "developed the first polyalphabetic tableau (predecessor to Vigenere). "
            "Interesting for K4: concealment within seemingly meaningful text."
        ),
        "mechanics": "Substitute letters with words from prepared lists (prayers/names)",
        "execution": "Code table of prayer phrases",
        "tools": ["word-substitution table"],
        "manual_type": "paper_pencil",
        "origin": "Johannes Trithemius, 1499",
        "source_type": "book",
        "year": 1499,
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.3,
    },
    {
        "name": "Nihilist Transposition",
        "aliases": ["Russian Nihilist transposition", "Nihilist columnar"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "columnar",
        "description": (
            "Double columnar transposition used by Russian Nihilist revolutionaries. "
            "First grid written by rows with columnar key, read by columns; "
            "second grid applies another columnar transposition."
        ),
        "mechanics": "Two-pass columnar transposition with keywords",
        "execution": "Paper and pencil with two keywords",
        "tools": ["paper", "two keywords"],
        "manual_type": "paper_pencil",
        "origin": "Russian Nihilists, 1880s",
        "source_type": "encyclopedia",
        "year": 1880,
        "confidence_real": 1.0,
        "confidence_distinct": 0.4,
        "confidence_k4": 0.35,
    },
    {
        "name": "Pollux Cipher",
        "aliases": ["Pollux", "Morse fractionation cipher", "Pollux Morse cipher"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Morse-based fractionation",
        "description": (
            "Convert plaintext to Morse, then replace dots/dashes/separators with "
            "digits (0-9), where each digit is assigned to one of the three Morse "
            "symbols. Output is numeric. A second step can convert back to letters."
        ),
        "mechanics": "Morse encode -> substitute each Morse element with assigned digit",
        "execution": "Morse chart + substitution table",
        "tools": ["Morse code chart", "digit assignment table"],
        "manual_type": "paper_pencil",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.5,
    },
    {
        "name": "Morbit Cipher",
        "aliases": ["Morbit", "Morse bigram cipher"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Morse-based fractionation",
        "description": (
            "Like Pollux but pairs adjacent Morse symbols and substitutes each pair "
            "with a single letter. More compact output than Pollux."
        ),
        "mechanics": "Morse encode -> pair symbols -> substitute pairs with letters",
        "execution": "Morse chart + pair substitution table",
        "tools": ["Morse code chart", "pair table"],
        "manual_type": "paper_pencil",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.7,
        "confidence_k4": 0.5,
    },
    {
        "name": "Fractionated Morse",
        "aliases": ["frac Morse", "fractionated Morse cipher"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Morse-based fractionation",
        "description": (
            "Convert PT to Morse, group resulting dots/dashes/separators into "
            "trigrams, substitute each trigram with a letter using a keyed alphabet. "
            "26 trigrams -> 26 letters, so output is alphabetic. "
            "THIS IS THE ONLY MORSE FRACTIONATION THAT OUTPUTS ALL-ALPHA."
        ),
        "mechanics": "Morse encode -> group into trigrams -> keyed substitution to letters",
        "execution": "Morse chart + trigram substitution table",
        "tools": ["Morse code chart", "keyed trigram table"],
        "manual_type": "paper_pencil",
        "origin": "ACA cipher type",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.65,
        "questions": [
            "Morse fractionation produces flat IC -- matches K4",
            "Sanborn references Morse code -- is fractionated Morse the method?",
            "Has this specific variant been tested against K4?",
        ],
    },
    {
        "name": "Dorabella Cipher",
        "aliases": ["Elgar cipher", "Dorabella", "musical cipher"],
        "category": "substitution",
        "cipher_type": "symbolic",
        "family": "bespoke artistic",
        "description": (
            "Unsolved cipher created by composer Edward Elgar in 1897. Uses "
            "symbols based on rotated E-like shapes at 8 orientations x 3 levels. "
            "Relevant as an example of an artist creating a bespoke cipher system "
            "that defies standard analysis."
        ),
        "mechanics": "Symbol substitution using bespoke character set",
        "execution": "Symbol lookup table",
        "tools": ["symbol reference"],
        "manual_type": "paper_pencil",
        "origin": "Edward Elgar, 1897",
        "source_type": "primary_source",
        "author": "Edward Elgar",
        "year": 1897,
        "bespoke": True,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
        "questions": ["Parallel to K4: artist-created cipher unsolved for over a century"],
    },
    {
        "name": "Sundial/Gnomon Cipher",
        "aliases": ["sundial cipher", "sundial code", "gnomon cipher",
                     "shadow cipher"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "positional",
        "description": (
            "Hypothetical system using sundial positions (shadow angles) to encode "
            "letters. A gnomon's shadow direction throughout the day gives 12+ "
            "distinct positions. Could connect to compass directions and time "
            "simultaneously."
        ),
        "mechanics": "Map letters to shadow angles/positions on a sundial",
        "execution": "Sundial diagram reference",
        "tools": ["sundial diagram"],
        "manual_type": "paper_pencil",
        "origin": "Speculative/historical combination",
        "confidence_real": 0.3,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.45,
        "bespoke": True,
        "questions": [
            "Kryptos sculpture has a shadow-casting element",
            "Does the gnomon/shadow connect compass directions to clock positions?",
        ],
    },
    {
        "name": "Astrolabe Cipher",
        "aliases": ["astrolabe code", "celestial cipher", "star chart cipher"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "positional",
        "description": (
            "Hypothetical cipher using astrolabe positions or star chart coordinates. "
            "An astrolabe combines compass direction with celestial angle, providing "
            "a natural two-coordinate encoding space. Navigation theme is K4-relevant."
        ),
        "mechanics": "Map letters to celestial positions or astrolabe settings",
        "execution": "Astrolabe reference or star chart",
        "tools": ["astrolabe diagram or star chart"],
        "manual_type": "paper_pencil",
        "origin": "Speculative/historical combination",
        "confidence_real": 0.2,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.4,
        "bespoke": True,
    },
    {
        "name": "Vatsyayana / Kama Sutra Cipher",
        "aliases": ["Kama Sutra cipher", "Mlecchita Vikalpa",
                     "secret writing India", "Vatsyayana"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "paired substitution",
        "description": (
            "Ancient Indian paired-substitution cipher described in Kama Sutra. "
            "Pair the 26 letters randomly into 13 pairs. Each letter is replaced "
            "by its pair partner. Self-reciprocal. Equivalent to a specific class "
            "of monoalphabetic involutory substitution."
        ),
        "mechanics": "Random pairing of alphabet into 13 pairs; swap each letter with its partner",
        "execution": "Pairing table on paper",
        "tools": ["pairing table"],
        "manual_type": "paper_pencil",
        "origin": "Vatsyayana, Kama Sutra (~400 AD)",
        "source_type": "book",
        "year": 400,
        "confidence_real": 1.0,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.2,
    },
    {
        "name": "Grille + Substitution Hybrid",
        "aliases": ["grille masking cipher", "mask then encipher",
                     "null insertion + cipher", "two-phase grille"],
        "category": "mixed",
        "cipher_type": "mixed",
        "family": "multi-layer",
        "description": (
            "Two-layer system: first, a grille/mask selects or inserts null "
            "characters; second, a substitution cipher encrypts. This is the "
            "leading hypothesis class for K4 based on the null palette anomaly. "
            "[INTERNAL RESULT] Null mask + periodic sub at all periods 1-23 "
            "eliminated by algebraic proof. BUT running key or non-periodic "
            "substitution remains OPEN."
        ),
        "mechanics": "Phase 1: grille/mask for null insertion. Phase 2: substitution cipher.",
        "execution": "Stencil/mask + substitution table",
        "tools": ["grille/mask", "substitution key"],
        "manual_type": "stencil",
        "origin": "General cryptographic technique",
        "bespoke": True,
        "confidence_real": 0.8,
        "confidence_distinct": 0.9,
        "confidence_k4": 0.85,
        "questions": [
            "What substitution layer (running key? Beaufort? bespoke?) sits on top of the mask?",
            "Is the mask the 'stego' layer and the sub the 'cipher' layer, or reversed?",
        ],
    },
    {
        "name": "Transposition + Substitution Hybrid",
        "aliases": ["sub-trans hybrid", "super-encipherment",
                     "product cipher hand", "multi-step hand cipher"],
        "category": "mixed",
        "cipher_type": "mixed",
        "family": "multi-layer",
        "description": (
            "General class of two-layer systems applying substitution and "
            "transposition in sequence. Military standard for hand ciphers "
            "in WWII era. [PUBLIC FACT] Scheidt confirmed K4 uses 'two encryption "
            "systems'. [INTERNAL RESULT] Three-layer Sub+Trans+Sub at p1*p2<=50 "
            "eliminated. Many specific combinations eliminated."
        ),
        "mechanics": "Layer 1: substitution (Vigenere, Beaufort, etc). Layer 2: transposition",
        "execution": "Substitution table + transposition grid",
        "tools": ["cipher table", "transposition grid"],
        "manual_type": "paper_pencil",
        "origin": "Standard military practice, WWII+",
        "source_type": "military_manual",
        "confidence_real": 1.0,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.8,
    },
    {
        "name": "One-Time Pad (hand variant)",
        "aliases": ["one-time pad", "OTP", "Vernam cipher", "additive cipher",
                     "key tape cipher", "one-time key"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "perfect secrecy",
        "description": (
            "Theoretically unbreakable: each PT letter added to a truly random "
            "key letter mod 26. Key must be at least as long as message and used "
            "only once. If K4 uses a true OTP, it is unsolvable without the key. "
            "But OTP with a pseudorandom or structured key degenerates to another "
            "cipher type."
        ),
        "mechanics": "C[i] = (P[i] + K[i]) mod 26 where K is random",
        "execution": "Paper and pencil + key sheet",
        "tools": ["key sheet", "paper"],
        "manual_type": "paper_pencil",
        "origin": "Gilbert Vernam, 1917 (proven secure by Shannon, 1949)",
        "source_type": "encyclopedia",
        "year": 1917,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
        "questions": ["If K4 is OTP, it requires finding the specific key sheet"],
    },
    {
        "name": "Checkerboard + Transposition (Soviet pattern)",
        "aliases": ["Soviet field cipher", "checkerboard disrupted transposition",
                     "Soviet three-step cipher"],
        "category": "mixed",
        "cipher_type": "mixed",
        "family": "Soviet intelligence",
        "description": (
            "Common Soviet intelligence pattern: straddling checkerboard -> "
            "numeric additive key -> disrupted transposition. VIC cipher is the "
            "most elaborate example, but simpler variants existed. "
            "[INTERNAL RESULT] Soviet three-step tested: NOISE."
        ),
        "mechanics": "Checkerboard encode -> add key digits -> transposition",
        "execution": "Checkerboard grid + key digits + transposition grid",
        "tools": ["checkerboard", "key digits", "transposition grid"],
        "manual_type": "paper_pencil",
        "origin": "Soviet intelligence, 1940s-1960s",
        "source_type": "military_manual",
        "year": 1945,
        "confidence_real": 1.0,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.4,
    },
    {
        "name": "Periodic Beaufort with Mixed Alphabet",
        "aliases": ["Beaufort variant", "mixed Beaufort",
                     "Beaufort with keyword alphabet", "KA Beaufort"],
        "category": "polyalphabetic",
        "cipher_type": "substitution",
        "family": "Vigenere family",
        "description": (
            "Beaufort cipher using the KA (KRYPTOSABCDEFGHIJLMNQUVWXZ) alphabet "
            "instead of standard AZ. [DERIVED FACT] K1-K3 use keyword-mixed alphabets "
            "with Vigenere. K4 might use Beaufort with KA. [INTERNAL RESULT] Periodic "
            "versions eliminated at all periods 1-26. Running-key version remains OPEN."
        ),
        "mechanics": "Beaufort cipher with KA alphabet: C = KA[(KA_idx(K) - KA_idx(P)) mod 26]",
        "execution": "KA-based Beaufort tableau",
        "tools": ["KA alphabet tableau"],
        "manual_type": "tabula_recta",
        "origin": "Combination of K1-K3 methods",
        "confidence_real": 0.8,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.7,
    },
    {
        "name": "ABSCISSA Cipher",
        "aliases": ["abscissa code", "ABSCISSA", "coordinate arithmetic cipher"],
        "category": "spatial",
        "cipher_type": "spatial",
        "family": "mathematical",
        "description": (
            "[PUBLIC FACT] 'ABSCISSA' appears in Sanborn's papers at Archives of "
            "American Art, on same page as ATBASH. An abscissa is the x-coordinate "
            "in a Cartesian system. May indicate a coordinate-based cipher using "
            "x-positions. [INTERNAL RESULT] Standard arithmetic interpretation "
            "eliminated. May be procedural/physical chart clue."
        ),
        "mechanics": "Unknown -- possibly coordinate-based letter selection",
        "execution": "Grid with coordinate system",
        "tools": ["coordinate grid"],
        "manual_type": "grid",
        "origin": "Jim Sanborn's notes, Archives of American Art",
        "source_type": "primary_source",
        "bespoke": True,
        "confidence_real": 0.5,
        "confidence_distinct": 0.8,
        "confidence_k4": 0.7,
        "questions": [
            "Does ABSCISSA describe a step in the cipher process?",
            "Is it the x-coordinate method for a coding chart?",
            "Connection to physical sculpture layout?",
        ],
    },
    {
        "name": "ATBASH with Mixed Alphabet",
        "aliases": ["ATBASH", "reverse alphabet cipher", "ATBASH variant",
                     "ATBASH KA"],
        "category": "substitution",
        "cipher_type": "substitution",
        "family": "simple substitution",
        "description": (
            "A=Z, B=Y, etc. (or using a mixed alphabet: first->last, second->second-to-last). "
            "[PUBLIC FACT] ATBASH appears on same Sanborn notes page as ABSCISSA. "
            "Trivially broken as single layer. May be one step in a multi-layer system."
        ),
        "mechanics": "Reverse the alphabet order; each letter maps to its mirror position",
        "execution": "Mental or simple table",
        "tools": ["paper"],
        "manual_type": "paper_pencil",
        "origin": "Hebrew Bible, ancient",
        "source_type": "encyclopedia",
        "year": -500,
        "confidence_real": 1.0,
        "confidence_distinct": 1.0,
        "confidence_k4": 0.3,
    },
    {
        "name": "Heliograph/Mirror Signal Cipher",
        "aliases": ["heliograph cipher", "heliograph code", "mirror signal cipher",
                     "sun telegraph cipher"],
        "category": "signaling",
        "cipher_type": "signaling",
        "family": "visual signaling",
        "description": (
            "Signaling system using reflected sunlight for long-distance communication. "
            "Uses Morse-like patterns (long/short flashes). Relevant because Kryptos "
            "involves reflection and light (the petrified wood, the compass rose pool, "
            "sunlight reading)."
        ),
        "mechanics": "Morse-like encoding via reflected light flashes",
        "execution": "Mirror + Morse code",
        "tools": ["mirror/reflector", "Morse code chart"],
        "manual_type": "paper_pencil",
        "origin": "Military signaling, 19th century",
        "source_type": "encyclopedia",
        "year": 1860,
        "confidence_real": 1.0,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.3,
    },
    {
        "name": "Dancing Men Cipher",
        "aliases": ["dancing men", "Sherlock Holmes cipher",
                     "stick figure cipher"],
        "category": "substitution",
        "cipher_type": "symbolic",
        "family": "monoalphabetic",
        "description": (
            "Fictional monoalphabetic cipher from Arthur Conan Doyle's 'The Adventure "
            "of the Dancing Men'. Each letter represented by a stick figure in a "
            "specific pose. Simple substitution with symbolic output."
        ),
        "mechanics": "Monoalphabetic substitution: letter -> stick figure symbol",
        "execution": "Symbol reference chart",
        "tools": ["symbol chart"],
        "manual_type": "paper_pencil",
        "origin": "Arthur Conan Doyle, 1903 (fictional)",
        "source_type": "book",
        "year": 1903,
        "confidence_real": 0.5,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.05,
        "pedagogical": True,
    },
    {
        "name": "Boy Scout Cipher Systems",
        "aliases": ["Scout code", "Baden-Powell cipher", "camping cipher",
                     "scout semaphore"],
        "category": "educational",
        "cipher_type": "substitution",
        "family": "educational",
        "description": (
            "Various simple cipher systems taught in scouting: reversed alphabet, "
            "number substitution, pigpen, Morse, semaphore. Sanborn's 'alphabet code' "
            "and 'compass cipher' could conceivably be scouting terms."
        ),
        "mechanics": "Various simple substitutions and transpositions",
        "execution": "Paper and pencil",
        "tools": ["paper"],
        "manual_type": "paper_pencil",
        "origin": "Boy Scout handbooks, early 20th century",
        "source_type": "educational",
        "pedagogical": True,
        "confidence_real": 0.7,
        "confidence_distinct": 0.2,
        "confidence_k4": 0.15,
    },
    {
        "name": "Tomographic Cipher",
        "aliases": ["tomographic", "layer cipher", "fractionation by layer",
                     "three-layer fractionation"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Delastelle extensions",
        "description": (
            "Generalization of bifid/trifid using multiple coordinate layers. "
            "Each letter mapped to N coordinates in an N-dimensional space, "
            "coordinates interleaved across dimensions, then decoded. "
            "Generalizes to arbitrary dimensions."
        ),
        "mechanics": "N-dimensional coordinate encoding, interleave, decode",
        "execution": "N reference grids",
        "tools": ["coordinate grids"],
        "manual_type": "grid",
        "origin": "Theoretical generalization of Delastelle",
        "source_type": "journal",
        "confidence_real": 0.6,
        "confidence_distinct": 0.5,
        "confidence_k4": 0.3,
    },
    {
        "name": "6x6 Polybius (full alphabet)",
        "aliases": ["6x6 grid cipher", "extended Polybius",
                     "ADFGVX-style full alphabet", "6x6 checkerboard"],
        "category": "fractionation",
        "cipher_type": "fractionation",
        "family": "Polybius",
        "description": (
            "6x6 Polybius grid accommodating all 26 letters + 10 digits = 36 symbols. "
            "Unlike 5x5 Polybius, does NOT require merging I/J. Each letter maps to "
            "a pair from {A,D,F,G,V,X} or {1,2,3,4,5,6}. K4-relevant because it "
            "avoids the 25-letter limitation that eliminates standard Polybius systems."
        ),
        "mechanics": "6x6 grid lookup giving coordinate pairs from 6-symbol alphabet",
        "execution": "6x6 grid reference on paper",
        "tools": ["6x6 grid"],
        "manual_type": "grid",
        "origin": "Extension of Polybius, used in ADFGVX",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.5,
        "questions": [
            "6x6 avoids 25-letter problem but output is typically 6-symbol",
            "Would need a second step to produce 26-letter alphabetic output",
        ],
    },
    {
        "name": "Permutation Cipher (arbitrary)",
        "aliases": ["keyed permutation", "arbitrary permutation cipher",
                     "block transposition"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "block transposition",
        "description": (
            "Divide message into blocks of size N, apply fixed permutation to each "
            "block. Key is the permutation pattern. General case of many transposition "
            "ciphers. Key space is N! which grows extremely fast."
        ),
        "mechanics": "Divide into blocks of N, permute positions within each block",
        "execution": "Paper with permutation rule",
        "tools": ["permutation key"],
        "manual_type": "paper_pencil",
        "origin": "General cryptographic primitive",
        "source_type": "encyclopedia",
        "confidence_real": 1.0,
        "confidence_distinct": 0.3,
        "confidence_k4": 0.45,
    },
    {
        "name": "Worm Cipher (spiral/helical transposition)",
        "aliases": ["worm cipher", "helical cipher", "spiral transposition",
                     "coil cipher"],
        "category": "transposition",
        "cipher_type": "transposition",
        "family": "route transposition",
        "description": (
            "Write plaintext around a cylinder (like scytale) but read off in a "
            "helical/spiral pattern. More complex than simple columnar because the "
            "helix pitch can vary. Spatial/physical nature is K4-relevant (sculpture "
            "is curved copper)."
        ),
        "mechanics": "Write on cylinder surface, read along helical path with given pitch",
        "execution": "Cylindrical surface or grid representation",
        "tools": ["cylindrical surface or grid"],
        "manual_type": "grid",
        "origin": "Historical variant of scytale/route cipher",
        "source_type": "encyclopedia",
        "confidence_real": 0.7,
        "confidence_distinct": 0.6,
        "confidence_k4": 0.55,
        "questions": [
            "Kryptos sculpture is curved -- does the physical shape encode a helical reading?",
            "Has helical transposition at various pitches been tested?",
        ],
    },
    {
        "name": "Grille + Running Key",
        "aliases": ["mask + running key", "null extraction + book cipher",
                     "stego + polyalphabetic"],
        "category": "mixed",
        "cipher_type": "mixed",
        "family": "multi-layer",
        "description": (
            "[HYPOTHESIS] Two-layer system: grille/mask extracts meaningful positions "
            "from CT97, then running-key Beaufort encrypts the meaningful portion. "
            "This is the LEADING open hypothesis for K4. The grille produces the null "
            "palette, the running key produces the cipher layer. "
            "[INTERNAL RESULT] Mono+Trans+Running key is UNDERDETERMINED (E-FRAC-54)."
        ),
        "mechanics": "Phase 1: mask/grille extracts ~73 real characters. Phase 2: running-key Beaufort.",
        "execution": "Stencil/mask + book/text + Beaufort tableau",
        "tools": ["grille/mask", "key text (book)", "Beaufort tableau"],
        "manual_type": "stencil",
        "origin": "Hypothesized for K4",
        "bespoke": True,
        "confidence_real": 0.5,
        "confidence_distinct": 0.9,
        "confidence_k4": 0.9,
        "questions": [
            "What source text is the running key?",
            "What determines the mask pattern?",
            "Is the mask the palette pattern {B,G,I,K,O,W,Z}?",
        ],
    },
]
