# ISBN Hunt — Finding the Running Key Book

## Hypothesis

Sanborn encoded a book's ISBN somewhere in Kryptos (K0-K4), and that book's text is the running key for K4's cipher layer. The K2 "coordinates" may not be geographic coordinates at all — they may encode an ISBN. The obvious running-key source (Howard Carter's tomb narrative) is a red herring planted via K3's plaintext. The REAL source book is identified by its ISBN, hidden in the sculpture's numerical structure.

## Constraints

- **ISBN-10 format** (Kryptos installed 1990, pre-2007)
- **Published before 1990** (book must exist when Sanborn built Kryptos)
- **Thematically connected** to Kryptos (espionage, cryptography, Egypt, Berlin, invisible, shadow, art)
- **Available to Sanborn** (English or German language, mainstream publisher)
- **Text length** must be ≥73 chars from some offset (to serve as running key for K4)

## Phase 1: Number Extraction + ISBN Validation

### Number Sources (14 categories)

Extract digit sequences from every structural element of K0-K4:

1. **K2 coordinates** — standard reading (38,57,6.5,77,8,44), split reading (30,8,50,7,6,5,70,7,8,40,4), all digit concatenations, with/without structural word values (DEGREES=56/63, MINUTES=94, etc.)
2. **Grid dimensions** — 14, 24, 7, 31, 42, 8, 336, 97, 98, 434 and pairwise/triple combinations
3. **Keyword gematria** — KRYPTOS, PALIMPSEST, ABSCISSA, BERLINCLOCK, EASTNORTHEAST, SHADOW, DEFECTOR, KOMPASS, COLOPHON under AZ-sum, KA-sum, product, first-letter
4. **Crib positions** — 21, 33, 63, 73, 32 (self-encrypting S), combinations
5. **K0 Morse** — E-group structure [2,5,1,3,2,2,5,3,1,1], inter-group [9,9,7,13,6,6,5,6,15,5], total counts
6. **NDYAHR** — letter values [13,3,24,0,7,17], sum=64, displacement vectors
7. **K3 permutation** — step=-86 (mod 336=250), cycle=168, factor pairs (24×14, 8×42)
8. **Bean values** — equality positions 27/65, keystream values (Vig: 24, Beau: 6)
9. **Null palette** — positions, count=35, letter values {1,6,8,10,14,22,25}
10. **KA alphabet indices** — KRYPTOS=(0,1,2,3,4,5,6), keyword letter positions
11. **K2 residuals** — 44, 57, 6.5 (not consumed by K3 encoding)
12. **Physical constants** — 24 (Weltzeituhr), lodestone bearing, QUADRUPLE-24
13. **Section lengths** — K0≈106, K1=63(?), K2=372(?), K3=336, K4=97
14. **CT97 properties** — letter frequency values, IC digits (0361), spacing (d=13)

### Extraction Method

For each source category:
1. Generate all single values and meaningful combinations (pairwise, triple)
2. Concatenate digits into candidate strings
3. Slide a 9-digit window across each candidate string
4. Compute ISBN-10 check digit for each 9-digit window
5. Form the complete 10-digit ISBN-10
6. Record: ISBN, source category, derivation method

### ISBN-10 Validation

```python
def isbn10_check(digits_9):
    """Compute check digit for 9-digit ISBN prefix."""
    s = sum(d * (10 - i) for i, d in enumerate(digits_9))
    check = (11 - (s % 11)) % 11
    return 'X' if check == 10 else str(check)

def isbn10_valid(isbn_str):
    """Validate a 10-char ISBN string (last char may be X)."""
    digits = []
    for c in isbn_str[:9]:
        digits.append(int(c))
    last = 10 if isbn_str[9] == 'X' else int(isbn_str[9])
    return sum(d * (10-i) for i, d in enumerate(digits)) + last) % 11 == 0
```

**Group code filter:** Focus on 0/1 (English), 3 (German), but don't exclude others entirely.

### Expected output
~500-5000 valid ISBN-10 candidates (most will be unassigned).

## Phase 2: Content-First Book Candidates

### Priority Authors & Books

**Tier 1 — Highest priority (direct Kryptos connections):**
- Howard Carter — ALL editions of tomb discovery narratives (not just the obvious one)
- John le Carré — **The Russia House** (1989, ISBN 0-394-57789-2, confirmed in user's possession), The Spy Who Came in from the Cold, Tinker Tailor Soldier Spy, A Perfect Spy, The Little Drummer Girl, Smiley's People, ALL pre-1990 novels
- David Kahn — The Codebreakers (1967)
- CIA-related: Philip Agee "Inside the Company", Victor Marchetti, Allen Dulles "The Craft of Intelligence"

**Tier 2 — Strong thematic connection:**
- Egyptology: Flinders Petrie, Budge "Egyptian Language", Champollion, Breasted "History of Egypt"
- Cryptography: Friedman "Elements of Cryptanalysis", Callimahos (Military Cryptanalytics), Sinkov
- Berlin/Cold War: John le Carré's Berlin novels, spy novels set in Berlin, Berlin Wall histories
- Art/sculpture: books Sanborn may have studied

**Tier 3 — Keyword-title search:**
- Books with PALIMPSEST, SHADOW, INVISIBLE, LAYER, CIPHER, CODE, SECRET, KRYPTOS, ABSCISSA in title
- Books about steganography or invisible writing
- German-language cryptography or espionage books (group-3 ISBNs)

### For each book
1. Find ALL editions published before 1990
2. Record ISBN-10 for each edition
3. Check if that ISBN's digits appear anywhere in K0-K4 structure (Phase 1 cross-match)
4. Flag thematic relevance score (Tier 1/2/3)

## Phase 3: ISBN Lookup via OpenLibrary API

OpenLibrary has a free, unauthenticated API:
```
GET https://openlibrary.org/isbn/{ISBN}.json
```

For each valid ISBN candidate from Phase 1:
1. Query OpenLibrary
2. If book exists: record title, author, year, publisher
3. Score thematic relevance (keyword matching against Kryptos themes)
4. If year > 1990: ELIMINATE (published after Kryptos)

Rate limit: ~1 request/second (be polite). Batch overnight if needed.

## Phase 4: Running Key Test

For every HIGH-PRIORITY book (thematically relevant, pre-1990, ISBN appears in K0-K4):
1. Obtain the full text (Project Gutenberg, Internet Archive, or user-provided)
2. Test as running key against K4 CT (and CT73 with nulls removed) at all offsets
3. Try Vigenère, Beaufort, Variant Beaufort
4. Score with quadgrams
5. Report any score significantly above noise (-4.0/char threshold)

## Le Carré Priority List

John le Carré novels published before 1990 (ALL are espionage-themed):

| Title | Year | Known ISBN | Notes |
|-------|------|-----------|-------|
| Call for the Dead | 1961 | various | First Smiley novel |
| A Murder of Quality | 1962 | | |
| The Spy Who Came in from the Cold | 1963 | | Berlin Wall, Cold War |
| The Looking Glass War | 1965 | | |
| A Small Town in Germany | 1968 | | GERMANY connection |
| The Naive and Sentimental Lover | 1971 | | |
| Tinker Tailor Soldier Spy | 1974 | | CIA mole hunt |
| The Honourable Schoolboy | 1977 | | |
| Smiley's People | 1979 | | |
| The Little Drummer Girl | 1983 | | |
| A Perfect Spy | 1986 | | |
| **The Russia House** | **1989** | **0-394-57789-2** | **User owns copy. Published 1 year before Kryptos.** |

## Technical Implementation

### Script
`scripts/running_key/e_isbn_hunt_01.py`

### Dependencies
- `requests` (for OpenLibrary API) — available in venv
- `kryptos.kernel.constants` for CT
- `kryptos.kernel.scoring.ngram` for quadgram scoring
- `kryptos.kernel.transforms.vigenere` for running-key decryption

### Output
- `results/isbn_hunt.json` — all valid ISBN candidates with source, lookup result, thematic score
- `results/isbn_hunt_priority.json` — ranked list of books to obtain and test as running keys
- Console: progress reporting, any hits

## Success Criteria

- **Breakthrough**: A valid ISBN derived from K0-K4 structure corresponds to a real pre-1990 book whose text, used as a running key, produces English plaintext for K4 at some offset.
- **Signal**: A valid ISBN from K0-K4 corresponds to a thematically relevant book (espionage, cryptography, Egypt) published before 1990.
- **Noise**: No valid ISBNs correspond to real books, or all corresponding books are thematically irrelevant.

## The Russia House Test (immediate)

Before the full systematic search, test `The Russia House` directly:
1. ISBN 0-394-57789-2 digits: [0,3,9,4,5,7,7,8,9,2]
2. Check if these digits appear encoded in K2 coordinates or other K0-K4 structure
3. Obtain the text and test as running key immediately (don't wait for full ISBN search)

The digits 3,9,4,5,7,7,8,9 overlap significantly with K2 standard digits 3,8,5,7,6,5,7,7,8,4,4. This could be coincidence or could be signal.
