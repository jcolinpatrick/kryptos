"""
Cipher: ISBN Hunt — Running Key Book Identification
Family: running_key
Status: active
Keyspace: ~5000 candidate ISBNs from K0-K4 structure
Last run: 2026-03-19
Best score: TBD
"""
import sys, os, json, time, itertools
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant


# ── ISBN-10 FUNCTIONS ────────────────────────────────────────────────

def isbn10_check_digit(digits_9):
    """Compute ISBN-10 check digit from first 9 digits.
    Returns int 0-10 (10 = 'X')."""
    s = sum(d * (10 - i) for i, d in enumerate(digits_9))
    return (11 - (s % 11)) % 11


def isbn10_check_char(digits_9):
    """Return check digit as character ('0'-'9' or 'X')."""
    c = isbn10_check_digit(digits_9)
    return 'X' if c == 10 else str(c)


def isbn10_valid(isbn_str):
    """Validate a 10-character ISBN string. Last char may be 'X'."""
    if len(isbn_str) != 10:
        return False
    try:
        digits = [int(c) for c in isbn_str[:9]]
    except ValueError:
        return False
    last = 10 if isbn_str[9] == 'X' else int(isbn_str[9])
    return (sum(d * (10 - i) for i, d in enumerate(digits)) + last) % 11 == 0


def format_isbn(isbn_str):
    """Format ISBN with hyphens (simplified approximation)."""
    if len(isbn_str) != 10:
        return isbn_str
    g = isbn_str[0]
    if g in '013':
        return f"{isbn_str[0]}-{isbn_str[1:4]}-{isbn_str[4:9]}-{isbn_str[9]}"
    return f"{isbn_str[0]}-{isbn_str[1:5]}-{isbn_str[5:9]}-{isbn_str[9]}"


def make_isbn10(digits_9):
    """Given 9 digits, return complete ISBN-10 string."""
    check = isbn10_check_digit(digits_9)
    check_char = 'X' if check == 10 else str(check)
    return ''.join(str(d) for d in digits_9) + check_char


# ── NUMBER EXTRACTORS ────────────────────────────────────────────────

def extract_k2_coordinates():
    """Category 1: K2 coordinate numbers."""
    sequences = []
    # Standard: 38, 57, 6.5, 77, 8, 44  → digits
    standard = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    sequences.append(('k2_standard_11', standard))

    # Split reading: 30,8,50,7,6,5,70,7,8,40,4
    split = [3, 0, 8, 5, 0, 7, 6, 5, 7, 0, 7, 8, 4, 0, 4]
    sequences.append(('k2_split_15', split))

    # Combinations of the raw numbers
    nums = [38, 57, 65, 77, 8, 44]
    for r in range(2, len(nums) + 1):
        for combo in itertools.combinations(nums, r):
            digits = []
            for n in combo:
                digits.extend(int(d) for d in str(n))
            if len(digits) >= 9:
                sequences.append((f'k2_combo_{combo}', digits))

    # Useful sub-slices
    sequences.append(('k2_nums_385765778', [3, 8, 5, 7, 6, 5, 7, 7, 8]))
    sequences.append(('k2_nums_577844', [5, 7, 7, 8, 4, 4]))
    sequences.append(('k2_first_38576', [3, 8, 5, 7, 6]))
    sequences.append(('k2_second_77844', [7, 7, 8, 4, 4]))

    return sequences


def extract_grid_dimensions():
    """Category 2: Grid dimensions and combinations."""
    dims = [14, 24, 7, 31, 42, 8, 336, 97, 98, 434, 168, 86, 250]
    sequences = []
    for r in range(2, 5):
        for combo in itertools.combinations(dims, r):
            digits = []
            for n in combo:
                digits.extend(int(d) for d in str(n))
            if 9 <= len(digits) <= 15:
                sequences.append((f'dims_{combo}', digits))
    return sequences


def extract_keyword_values():
    """Category 3: Keyword gematria (AZ A=0 values)."""
    keywords = {
        'KRYPTOS': [10, 17, 24, 15, 19, 14, 18],
        'PALIMPSEST': [15, 0, 11, 8, 12, 15, 18, 4, 18, 19],
        'ABSCISSA': [0, 1, 18, 2, 8, 18, 18, 0],
        'BERLINCLOCK': [1, 4, 17, 11, 8, 13, 2, 11, 14, 2, 10],
        'EASTNORTHEAST': [4, 0, 18, 19, 13, 14, 17, 19, 7, 4, 0, 18, 19],
        'SHADOW': [18, 7, 0, 3, 14, 22],
        'DEFECTOR': [3, 4, 5, 4, 2, 19, 14, 17],
        'SEVEN': [18, 4, 21, 4, 13],
    }
    sequences = []
    for name, vals in keywords.items():
        s = sum(vals)
        sequences.append((f'kw_{name}_sum_{s}', [int(d) for d in str(s)]))
        digit_seq = []
        for v in vals:
            digit_seq.extend(int(d) for d in str(v))
        if len(digit_seq) >= 9:
            sequences.append((f'kw_{name}_vals', digit_seq))
    return sequences


def extract_crib_positions():
    """Category 4: Crib positions and derived numbers."""
    positions = [21, 33, 63, 73, 32, 73, 27, 65]
    digits = []
    for p in positions:
        digits.extend(int(d) for d in str(p))
    sequences = [('crib_positions', digits)]
    sequences.append(('crib_ene_bcl', [2, 1, 3, 3, 6, 3, 7, 3]))
    sequences.append(('crib_lengths', [1, 3, 1, 1, 2, 4]))
    return sequences


def extract_k0_morse():
    """Category 5: K0 Morse code structure."""
    e_groups = [2, 5, 1, 3, 2, 2, 5, 3, 1, 1]
    inter_groups = [9, 9, 7, 13, 6, 6, 5, 6, 15, 5]
    sequences = [
        ('k0_egroups', e_groups),
        ('k0_intergroups', [int(d) for d in ''.join(str(n) for n in inter_groups)]),
    ]
    return sequences


def extract_ndyahr():
    """Category 6: NDYAHR letter values."""
    vals = [13, 3, 24, 0, 7, 17]
    digits = []
    for v in vals:
        digits.extend(int(d) for d in str(v))
    sequences = [
        ('ndyahr_vals', digits),
        ('ndyahr_sum_64', [6, 4]),
    ]
    return sequences


def extract_k3_permutation():
    """Category 7: K3 permutation constants."""
    return [
        ('k3_step_86', [8, 6]),
        ('k3_step_250', [2, 5, 0]),
        ('k3_cycle_168', [1, 6, 8]),
        ('k3_factors', [2, 4, 1, 4, 8, 4, 2]),
    ]


def extract_bean():
    """Category 8: Bean constraint values."""
    return [
        ('bean_eq_2765', [2, 7, 6, 5]),
        ('bean_vig_key_24', [2, 4]),
        ('bean_beau_key_6', [6]),
        ('bean_242_ineq', [2, 4, 2]),
    ]


def extract_null_palette():
    """Category 9: Null palette properties."""
    palette_vals = [1, 6, 8, 10, 14, 22, 25]
    digits = []
    for v in palette_vals:
        digits.extend(int(d) for d in str(v))
    return [
        ('palette_vals', digits),
        ('palette_count_35', [3, 5]),
        ('palette_7letters', [7]),
        ('consensus_nulls_17', [1, 7]),
    ]


def extract_ka_indices():
    """Category 10: KA alphabet keyword indices."""
    return [('ka_kryptos_identity', [0, 1, 2, 3, 4, 5, 6])]


def extract_k2_residuals():
    """Category 11: K2 progressive solve residuals."""
    return [
        ('k2_resid_44_57_65', [4, 4, 5, 7, 6, 5]),
        ('k2_resid_44', [4, 4]),
        ('k2_resid_57', [5, 7]),
    ]


def extract_physical():
    """Category 12: Physical constants."""
    return [
        ('weltzeituhr_24', [2, 4]),
        ('quadruple24', [2, 4, 2, 4, 2, 4, 2, 4]),
        ('panel_31', [3, 1]),
        ('timer_2000_2400', [2, 0, 0, 0, 2, 4, 0, 0]),
    ]


def extract_section_lengths():
    """Category 13: Section lengths."""
    return [
        ('lengths_k1k2k3k4', [6, 3, 3, 7, 2, 3, 3, 6, 9, 7]),
        ('lengths_336_97', [3, 3, 6, 9, 7]),
        ('lengths_434', [4, 3, 4]),
        ('k4_97', [9, 7]),
    ]


def extract_ct_properties():
    """Category 14: CT97 statistical properties."""
    return [
        ('ct_ic_0361', [0, 3, 6, 1]),
        ('ct_d13_anomaly', [1, 3]),
    ]


def extract_all():
    """Run all 14 extractors, return combined list of (name, digit_sequence)."""
    extractors = [
        extract_k2_coordinates, extract_grid_dimensions, extract_keyword_values,
        extract_crib_positions, extract_k0_morse, extract_ndyahr,
        extract_k3_permutation, extract_bean, extract_null_palette,
        extract_ka_indices, extract_k2_residuals, extract_physical,
        extract_section_lengths, extract_ct_properties,
    ]
    all_seqs = []
    for fn in extractors:
        all_seqs.extend(fn())
    return all_seqs


# ── ISBN CANDIDATE GENERATOR ─────────────────────────────────────────

def generate_isbn_candidates(all_sequences):
    """From all digit sequences, generate valid ISBN-10 candidates.
    Uses sliding 9-digit windows + check digit computation."""
    candidates = {}  # isbn_str -> list of sources

    for name, digits in all_sequences:
        if len(digits) < 9:
            # Pad with leading zeros
            padded = [0] * (9 - len(digits)) + digits
            isbn = make_isbn10(padded)
            if isbn not in candidates:
                candidates[isbn] = []
            candidates[isbn].append(f"{name}_padded")
            continue

        # Sliding window of 9 digits
        for start in range(len(digits) - 8):
            window = digits[start:start + 9]
            isbn = make_isbn10(window)
            if isbn not in candidates:
                candidates[isbn] = []
            candidates[isbn].append(f"{name}[{start}:{start + 9}]")

    return candidates


# ── CONTENT-FIRST CANDIDATES ─────────────────────────────────────────

CONTENT_ISBNS = {
    # Le Carré (pre-1990) — first editions
    '0394577892': 'le Carré — The Russia House (1989) [USER CONFIRMED]',
    '0394440560': 'le Carré — Tinker Tailor Soldier Spy (1974)',
    '0394493834': 'le Carré — The Honourable Schoolboy (1977)',
    '0394509625': "le Carré — Smiley's People (1979)",
    '0394530063': 'le Carré — The Little Drummer Girl (1983)',
    '0394553586': 'le Carré — A Perfect Spy (1986)',
    '0698104072': 'le Carré — The Spy Who Came in from the Cold (1963)',
    '0394480252': 'le Carré — The Looking Glass War (1965)',
    '0698107276': 'le Carré — A Small Town in Germany (1968)',

    # Howard Carter
    '0304935093': 'Carter — The Tomb of Tut-Ankh-Amen Vol 1 (1923/1972 reprint)',
    '0525217266': 'Carter — The Tomb of Tutankhamen (1972 Dutton)',
    '0876912935': 'Carter — Wonderful Things (1978)',

    # Cryptography
    '0025175106': 'Kahn — The Codebreakers (1967)',
    '0684831309': 'Kahn — The Codebreakers (1996 rev)',

    # CIA / Espionage
    '0394495497': 'Marchetti/Marks — The CIA and the Cult of Intelligence (1974)',
    '0060117230': 'Agee — Inside the Company: CIA Diary (1975)',
    '0060113251': 'Dulles — The Craft of Intelligence (1963)',

    # Berlin Wall / Cold War
    '0394537025': 'Wyden — Wall: The Inside Story of Divided Berlin (1989)',

    # Steganography / Invisible writing
    '0306805898': 'Zim — Codes and Secret Writing (1948)',

    # Egyptian / Archaeological
    '0394530829': 'Hoving — Tutankhamun: The Untold Story (1978)',
    '0500050589': 'Reeves — The Complete Tutankhamun (1990)',
}


# ── OPENLIBRARY LOOKUP (stdlib only) ─────────────────────────────────

def lookup_isbn_openlibrary(isbn_str):
    """Look up ISBN via OpenLibrary API. Returns dict or None."""
    import urllib.request
    import urllib.error

    url = f"https://openlibrary.org/isbn/{isbn_str}.json"
    req = urllib.request.Request(url, headers={
        'User-Agent': 'KryptosBot/1.0 (isbn-research)'
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return {
                'isbn': isbn_str,
                'title': data.get('title', ''),
                'publish_date': data.get('publish_date', ''),
                'publishers': data.get('publishers', []),
                'number_of_pages': data.get('number_of_pages', 0),
                'subjects': data.get('subjects', []),
                'key': data.get('key', ''),
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return None
    except Exception:
        return None


# ── THEMATIC SCORING ─────────────────────────────────────────────────

KRYPTOS_THEMES = {
    'cipher', 'code', 'crypt', 'secret', 'spy', 'espionage', 'intelligence',
    'cia', 'kgb', 'berlin', 'cold war', 'egypt', 'tomb', 'pharaoh', 'carter',
    'invisible', 'hidden', 'shadow', 'palimpsest', 'sculpture', 'art',
    'steganograph', 'encrypt', 'decipher', 'hieroglyph', 'archaeological',
    'russia', 'soviet', 'le carré', 'le carre', 'smiley', 'mole', 'defector',
}


def score_thematic_relevance(book):
    """Score 0-10 for how thematically relevant a book is to Kryptos."""
    score = 0
    text = (book.get('title', '') + ' ' +
            ' '.join(book.get('subjects', []))).lower()
    for theme in KRYPTOS_THEMES:
        if theme in text:
            score += 1
    pub = book.get('publish_date', '')
    try:
        year = int(''.join(c for c in pub if c.isdigit())[:4])
        if year <= 1990:
            score += 2
    except (ValueError, IndexError):
        pass
    return min(score, 10)


def phase3_lookup(candidates, max_lookups=500):
    """Look up ISBN candidates against OpenLibrary. Rate-limited to 1/sec."""
    print(f"\nPhase 3: Looking up {min(len(candidates), max_lookups)} ISBNs "
          f"on OpenLibrary...")

    found_books = []
    not_found = 0

    # Prioritize: group 0 and 3 first (English and German)
    priority_isbns = sorted(candidates.keys(),
                            key=lambda x: (0 if x[0] in '013' else 1, x))

    for i, isbn in enumerate(priority_isbns[:max_lookups]):
        result = lookup_isbn_openlibrary(isbn)

        if result:
            found_books.append(result)
            sources = candidates[isbn]
            print(f"  [{i + 1}] FOUND: {format_isbn(isbn)} = "
                  f"\"{result['title']}\" ({result['publish_date']}) "
                  f"— sources: {sources[:2]}", flush=True)
        else:
            not_found += 1

        if (i + 1) % 100 == 0:
            print(f"  ... {i + 1}/{min(len(candidates), max_lookups)} "
                  f"({len(found_books)} found, {not_found} not assigned)",
                  flush=True)

        time.sleep(1.0)  # Rate limit: 1 request/second

    print(f"\n  Phase 3 complete: {len(found_books)} books found, "
          f"{not_found} ISBNs not assigned")

    return found_books


# ── RUNNING KEY TEST ─────────────────────────────────────────────────

CONSENSUS_NULLS = frozenset(
    {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
)


def test_running_key(key_text, ct=None, label=""):
    """Test a text as running key against K4 CT at all offsets.
    Returns best (score_per_char, plaintext, variant_name, offset)."""
    if ct is None:
        ct = CT

    qg = get_default_scorer()
    key_clean = ''.join(c.upper() for c in key_text if c.isalpha())

    if len(key_clean) < len(ct):
        print(f"  {label}: key too short ({len(key_clean)} < {len(ct)})")
        return None

    best = (float('-inf'), '', '', 0)

    for offset in range(len(key_clean) - len(ct) + 1):
        key_segment = key_clean[offset:offset + len(ct)]
        key_nums = [ord(c) - 65 for c in key_segment]

        for var_name, var in [('vig', CipherVariant.VIGENERE),
                               ('beau', CipherVariant.BEAUFORT),
                               ('vbeau', CipherVariant.VAR_BEAUFORT)]:
            pt = decrypt_text(ct, key_nums, var)
            pc = qg.score_per_char(pt)

            if pc > best[0]:
                best = (pc, pt, var_name, offset)

    print(f"  {label}: best={best[0]:.3f}/c [{best[2]} off={best[3]}] "
          f"{best[1][:50]}...")
    return best


# ── CONTENT-FIRST LOOKUP ─────────────────────────────────────────────

def phase2_content_first_lookup():
    """Look up all content-first ISBNs on OpenLibrary to verify/enrich."""
    print(f"\nPhase 2b: Verifying content-first ISBNs on OpenLibrary...")
    verified = []
    for isbn, label in CONTENT_ISBNS.items():
        result = lookup_isbn_openlibrary(isbn)
        if result:
            result['content_label'] = label
            verified.append(result)
            print(f"  VERIFIED: {format_isbn(isbn)} = "
                  f"\"{result['title']}\" ({result['publish_date']})")
        else:
            print(f"  NOT FOUND: {format_isbn(isbn)} = {label}")
        time.sleep(0.5)
    return verified


# ── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("ISBN HUNT — Finding the Running Key Book")
    print("=" * 60)

    # Phase 1: Extract numbers, generate ISBN candidates
    print("\nPhase 1: Extracting numbers from K0-K4 structure...")
    all_sequences = extract_all()
    print(f"  {len(all_sequences)} digit sequences from 14 categories")

    candidates = generate_isbn_candidates(all_sequences)
    print(f"  {len(candidates)} unique ISBN-10 candidates generated")

    # Group code distribution
    groups = Counter(isbn[0] for isbn in candidates)
    print(f"  Group distribution: {dict(sorted(groups.items()))}")

    # Phase 2: Cross-match content-first candidates against extracted numbers
    print(f"\nPhase 2: Content-first cross-match ({len(CONTENT_ISBNS)} books)...")
    k2_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    for isbn, title in sorted(CONTENT_ISBNS.items()):
        if isbn in candidates:
            sources = candidates[isbn]
            print(f"  *** MATCH: {format_isbn(isbn)} = {title}")
            print(f"      Sources: {sources}")
        else:
            # Check digit overlap with K2 sequence
            isbn_digits = [int(d) for d in isbn[:9]]
            overlap = sum(min(Counter(isbn_digits)[d], Counter(k2_digits)[d])
                         for d in set(isbn_digits))
            if overlap >= 7:
                print(f"  NEAR: {format_isbn(isbn)} = {title} "
                      f"(K2 digit overlap: {overlap}/9)")

    # Phase 2b: Verify content-first ISBNs exist on OpenLibrary
    verified_content = phase2_content_first_lookup()

    # Phase 3: OpenLibrary lookup of structurally-derived candidates
    found_books = phase3_lookup(candidates, max_lookups=500)

    # Score and rank all found books
    all_found = verified_content + found_books
    for book in all_found:
        book['thematic_score'] = score_thematic_relevance(book)
    all_found.sort(key=lambda b: b['thematic_score'], reverse=True)

    print(f"\nTop thematically relevant books:")
    for book in all_found[:20]:
        print(f"  [{book['thematic_score']}] {format_isbn(book['isbn'])} "
              f"\"{book['title']}\" ({book['publish_date']})")

    # Phase 4: Running key tests on available texts
    print(f"\n{'=' * 60}")
    print("Phase 4: Running Key Tests")
    print("=" * 60)

    # The Russia House — opening paragraph
    russia_house_opening = (
        "In a broad Moscow street not two hundred yards from the "
        "Leningrad station on the upper floor of an ornate and "
        "hideous hotel built by Stalin in the style known to "
        "Muscovites as Empire During the Plague"
    )
    test_running_key(russia_house_opening, label="Russia House opening (CT97)")

    # Also test against CT73 (consensus nulls removed)
    ct73 = ''.join(CT[i] for i in range(97) if i not in CONSENSUS_NULLS)
    test_running_key(russia_house_opening, ct=ct73,
                     label="Russia House opening (CT73)")

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"  ISBN candidates generated: {len(candidates)}")
    print(f"  Books found on OpenLibrary: {len(all_found)}")
    priority = [b for b in all_found if b['thematic_score'] >= 3]
    print(f"  Thematically relevant (score>=3): {len(priority)}")
    if priority:
        print(f"\n  Priority books for text acquisition and running-key test:")
        for book in priority:
            print(f"    {format_isbn(book['isbn'])} \"{book['title']}\" "
                  f"({book['publish_date']}) [score={book['thematic_score']}]")

    # Save results
    final_output = {
        'experiment': 'e_isbn_hunt_01',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'phase1_candidates': len(candidates),
        'phase3_books_found': len(all_found),
        'top_books': [
            {'isbn': b['isbn'], 'title': b['title'],
             'date': b.get('publish_date', ''), 'score': b['thematic_score']}
            for b in all_found[:50]
        ],
        'content_first_verified': [
            {'isbn': b['isbn'], 'title': b['title'],
             'date': b.get('publish_date', '')}
            for b in verified_content
        ],
    }
    os.makedirs(os.path.join(_ROOT, 'results'), exist_ok=True)
    out_path = os.path.join(_ROOT, 'results', 'isbn_hunt.json')
    with open(out_path, 'w') as f:
        json.dump(final_output, f, indent=2)
    print(f"\nResults saved to {out_path}")
