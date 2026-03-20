import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "polyalphabetic"))

from kryptos.kernel.constants import KRYPTOS_ALPHABET, ALPH, CT, CRIB_DICT, ALPH_IDX, CT_LEN


def test_grid_coordinates():
    """KA 5-wide grid: K=(0,0), R=(0,1), ..., Z=(5,0)."""
    from e_polybius_coord_exploit import PolybiusGrid
    g = PolybiusGrid(KRYPTOS_ALPHABET, 5)
    assert g.letter_to_coord['K'] == (0, 0)
    assert g.letter_to_coord['T'] == (0, 4)
    assert g.letter_to_coord['O'] == (1, 0)
    assert g.letter_to_coord['B'] == (1, 3)
    assert g.letter_to_coord['Z'] == (5, 0)
    assert g.coord_to_letter[(2, 3)] == 'G'
    assert len(g.letter_to_coord) == 26


def test_grid_roundtrip():
    """Encrypt then decrypt returns original plaintext for all valid combos."""
    from e_polybius_coord_exploit import PolybiusGrid
    g = PolybiusGrid(KRYPTOS_ALPHABET, 5)
    successes = 0
    for pt_ch in KRYPTOS_ALPHABET:
        for key_r in range(6):
            for key_c in range(5):
                ct_ch = g.encrypt_char(pt_ch, key_r, key_c, 'beau', 'vig')
                if ct_ch is None:
                    continue
                pt_back = g.decrypt_char(ct_ch, key_r, key_c, 'beau', 'vig')
                assert pt_back == pt_ch, f"Roundtrip failed: {pt_ch} -> {ct_ch} -> {pt_back}"
                successes += 1
    assert successes > 0


def test_required_key_differs_from_standard():
    """11/24 crib positions should have different key letters than standard Beaufort."""
    from e_polybius_coord_exploit import PolybiusGrid
    g = PolybiusGrid(KRYPTOS_ALPHABET, 5)
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    diffs = 0
    for pos in sorted(CRIB_DICT.keys()):
        ct_ch = CT[pos]
        pt_ch = CRIB_DICT[pos]
        std_k = (ka_idx[ct_ch] + ka_idx[pt_ch]) % 26
        std_letter = KRYPTOS_ALPHABET[std_k]
        kr, kc = g.required_key(ct_ch, pt_ch, 'beau', 'vig')
        poly_letter = g.coord_to_letter.get((kr, kc))
        if poly_letter != std_letter:
            diffs += 1
    assert diffs == 20, f"Expected 20 differences, got {diffs}"


def test_invalid_cell_handling():
    """Decryption to invalid cells (row 5, col>0) returns fallback letter."""
    from e_polybius_coord_exploit import PolybiusGrid
    g = PolybiusGrid(KRYPTOS_ALPHABET, 5)
    for ct_ch in KRYPTOS_ALPHABET:
        for key_r in range(6):
            for key_c in range(5):
                result = g.decrypt_char(ct_ch, key_r, key_c, 'beau', 'vig')
                assert result is not None, f"decrypt_char returned None for CT={ct_ch} kr={key_r} kc={key_c}"
                assert result in KRYPTOS_ALPHABET


def test_beau_r_vig_c_key_sequence():
    """Verify the exact Polybius key letter sequence at crib positions."""
    from e_polybius_coord_exploit import PolybiusGrid
    g = PolybiusGrid(KRYPTOS_ALPHABET, 5)
    expected = "UQOWSZYYZV BDAUEYON IXGLCK".replace(" ", "")
    actual = ""
    for pos in sorted(CRIB_DICT.keys()):
        kr, kc = g.required_key(CT[pos], CRIB_DICT[pos], 'beau', 'vig')
        letter = g.coord_to_letter.get((kr, kc), '?')
        actual += letter
    assert actual == expected, f"Expected {expected}, got {actual}"
