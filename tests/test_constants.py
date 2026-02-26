"""Tests for kernel constants — invariants that must never break."""
import pytest

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, MOD,
    CRIB_DICT, CRIB_ENTRIES, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    SELF_ENCRYPTING,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)


class TestCiphertext:
    def test_length(self):
        assert len(CT) == CT_LEN == 97

    def test_boundaries(self):
        assert CT[0] == "O"
        assert CT[-1] == "R"

    def test_all_uppercase(self):
        assert CT.isalpha() and CT.isupper()

    def test_all_in_alphabet(self):
        assert all(c in ALPH for c in CT)


class TestCribs:
    def test_count(self):
        assert len(CRIB_ENTRIES) == N_CRIBS == 24

    def test_ene_positions(self):
        for i, ch in enumerate("EASTNORTHEAST"):
            assert CRIB_DICT[21 + i] == ch

    def test_bc_positions(self):
        for i, ch in enumerate("BERLINCLOCK"):
            assert CRIB_DICT[63 + i] == ch

    def test_pos74_not_crib(self):
        assert 74 not in CRIB_DICT

    def test_self_encrypting(self):
        assert CT[32] == CRIB_DICT[32] == "S"
        assert CT[73] == CRIB_DICT[73] == "K"

    def test_not_self_encrypting(self):
        assert CT[27] != CRIB_DICT[27]  # CT=P, PT=R
        assert CT[28] != CRIB_DICT[28]  # CT=R, PT=T


class TestAlphabets:
    def test_az_length(self):
        assert len(ALPH) == MOD == 26

    def test_az_unique(self):
        assert len(set(ALPH)) == 26

    def test_ka_length(self):
        assert len(KRYPTOS_ALPHABET) == 26

    def test_ka_unique(self):
        assert len(set(KRYPTOS_ALPHABET)) == 26

    def test_same_char_set(self):
        assert set(ALPH) == set(KRYPTOS_ALPHABET)


class TestBeanConstraints:
    def test_eq_count(self):
        assert len(BEAN_EQ) == 1

    def test_ineq_count(self):
        assert len(BEAN_INEQ) == 21

    def test_eq_positions(self):
        assert BEAN_EQ[0] == (27, 65)

    def test_all_positions_in_range(self):
        for a, b in BEAN_EQ:
            assert 0 <= a < CT_LEN
            assert 0 <= b < CT_LEN
        for a, b in BEAN_INEQ:
            assert 0 <= a < CT_LEN
            assert 0 <= b < CT_LEN


class TestKnownKeystream:
    def test_ene_length(self):
        assert len(VIGENERE_KEY_ENE) == 13  # EASTNORTHEAST

    def test_bc_length(self):
        assert len(VIGENERE_KEY_BC) == 11  # BERLINCLOCK

    def test_bean_eq_vigenere(self):
        # k[27] should equal k[65] under Vigenere
        # pos 27 is at index 6 within ENE (27-21=6)
        # pos 65 is at index 2 within BC (65-63=2)
        assert VIGENERE_KEY_ENE[6] == VIGENERE_KEY_BC[2] == 24  # Y

    def test_bean_eq_beaufort(self):
        assert BEAUFORT_KEY_ENE[6] == BEAUFORT_KEY_BC[2] == 6  # G


class TestConstantsIntegrity:
    """Regression guard: verify hardcoded CT/crib values in scripts match canonical."""

    # Unique prefix of CT — long enough to avoid false positives
    CT_SIGNATURE = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"

    def _find_py_files_with_pattern(self, pattern: str, search_dir: str) -> list:
        """Find Python files containing a pattern (excluding canonical source)."""
        import re
        from pathlib import Path

        root = Path(search_dir)
        if not root.exists():
            return []

        matches = []
        for p in root.rglob("*.py"):
            rel = str(p)
            # Skip canonical source and tests
            if "kernel/constants.py" in rel or "test_constants.py" in rel:
                continue
            try:
                text = p.read_text()
            except Exception:
                continue
            if re.search(pattern, text):
                matches.append(p)
        return matches

    def test_hardcoded_ct_matches_canonical(self):
        """Every hardcoded CT literal must match the canonical value."""
        import re
        from pathlib import Path

        repo = Path(__file__).resolve().parent.parent
        scripts_dir = repo / "scripts"
        src_dir = repo / "src"

        mismatches = []
        for search_dir in [scripts_dir, src_dir]:
            files = self._find_py_files_with_pattern(
                self.CT_SIGNATURE, str(search_dir)
            )
            for f in files:
                text = f.read_text()
                # Extract all string literals containing the CT signature
                # Match quoted strings that contain the signature
                for m in re.finditer(
                    r'["\'](' + self.CT_SIGNATURE + r'[A-Z]*)["\']', text
                ):
                    found = m.group(1)
                    if found != CT and len(found) >= 50:
                        mismatches.append(
                            (str(f.relative_to(repo)), found[:40] + "...")
                        )

        assert not mismatches, (
            f"Hardcoded CT values differ from canonical:\n"
            + "\n".join(f"  {path}: {val}" for path, val in mismatches)
        )

    def test_ct_matches_data_file(self):
        """CT in constants.py must match data/ct.txt."""
        from pathlib import Path

        repo = Path(__file__).resolve().parent.parent
        ct_file = repo / "data" / "ct.txt"
        if ct_file.exists():
            file_ct = ct_file.read_text().strip()
            assert CT == file_ct, (
                f"CT mismatch: constants.py ({len(CT)} chars) vs "
                f"data/ct.txt ({len(file_ct)} chars)"
            )
