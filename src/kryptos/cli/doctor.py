"""Doctor — environment verification and smoke tests.

Runs a comprehensive check of:
- Python version and dependencies
- Constant invariants
- Alphabet validity
- Transform self-tests
- Database accessibility
- Quadgram data availability
- Quick sweep smoke test
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import List, Tuple


def run_doctor(verbose: bool = True) -> bool:
    """Run all diagnostic checks. Returns True if all pass."""
    checks: list[tuple[str, bool, str]] = []

    # 1. Python version
    py_ok = sys.version_info >= (3, 10)
    checks.append(("python_version", py_ok, f"Python {sys.version_info.major}.{sys.version_info.minor}"))

    # 2. Constants import and verification
    try:
        from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ
        checks.append(("constants_import", True, ""))
        checks.append(("ct_length", len(CT) == CT_LEN, f"len={len(CT)}"))
        checks.append(("ct_boundary", CT[0] == "O" and CT[-1] == "R", ""))
        checks.append(("crib_count", len(CRIB_DICT) == N_CRIBS, f"n={len(CRIB_DICT)}"))
        checks.append(("bean_count", len(BEAN_EQ) == 1 and len(BEAN_INEQ) == 21, ""))
    except Exception as e:
        checks.append(("constants_import", False, str(e)))

    # 3. Alphabet validation
    try:
        from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
        checks.append(("alphabet_az", len(AZ.sequence) == 26, ""))
        checks.append(("alphabet_ka", len(KA.sequence) == 26, ""))
        ka_check = keyword_mixed_alphabet("KRYPTOS")
        checks.append(("alphabet_ka_construct", ka_check == KA.sequence, ""))
    except Exception as e:
        checks.append(("alphabet_validation", False, str(e)))

    # 4. Transform self-tests
    try:
        from kryptos.kernel.transforms.vigenere import (
            vig_recover_key, beau_recover_key, vig_decrypt, vig_encrypt,
            CipherVariant, decrypt_text, encrypt_text,
        )
        # Vigenere round-trip
        pt = "HELLOWORLD"
        key = [3, 7, 11, 2, 5]
        ct = encrypt_text(pt, key, CipherVariant.VIGENERE)
        pt2 = decrypt_text(ct, key, CipherVariant.VIGENERE)
        checks.append(("vig_roundtrip", pt == pt2, f"{pt} -> {ct} -> {pt2}"))

        # Key recovery
        k = vig_recover_key(7, 4)
        checks.append(("vig_key_recovery", k == 3, f"k={k}"))
    except Exception as e:
        checks.append(("transform_self_test", False, str(e)))

    # 5. Transposition self-tests
    try:
        from kryptos.kernel.transforms.transposition import (
            columnar_perm, validate_perm, invert_perm, apply_perm, compose_perms,
        )
        p = columnar_perm(5, [2, 0, 4, 1, 3], 10)
        checks.append(("perm_valid", validate_perm(p, 10), f"len={len(p)}"))
        inv = invert_perm(p)
        # Verify round-trip
        text = "ABCDEFGHIJ"
        ct = apply_perm(text, p)
        pt = apply_perm(ct, inv)
        checks.append(("perm_roundtrip", pt == text, f"{text} -> {ct} -> {pt}"))
    except Exception as e:
        checks.append(("transposition_self_test", False, str(e)))

    # 6. Constraint checks
    try:
        from kryptos.kernel.constraints.bean import verify_bean_simple, expand_keystream_vimark
        from kryptos.kernel.constants import VIGENERE_KEY_ENE
        ks = expand_keystream_vimark(VIGENERE_KEY_ENE[:5])
        # Just check it runs without error
        checks.append(("bean_check_runs", True, ""))
    except Exception as e:
        checks.append(("constraint_checks", False, str(e)))

    # 7. Scoring
    try:
        from kryptos.kernel.scoring.aggregate import score_candidate
        result = score_candidate("A" * 97)
        checks.append(("scoring_runs", result.crib_score >= 0, f"score={result.crib_score}"))
    except Exception as e:
        checks.append(("scoring", False, str(e)))

    # 8. Database
    try:
        from kryptos.kernel.persistence.sqlite import Database
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            tmp_path = f.name
        db = Database(tmp_path)
        db.store_result("test", {"test": True}, 0)
        db.commit()
        results = db.top_results(limit=1)
        db.close()
        os.unlink(tmp_path)
        checks.append(("database", len(results) == 1, ""))
    except Exception as e:
        checks.append(("database", False, str(e)))

    # 9. Quadgram data
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer
        scorer = get_default_scorer()
        test_score = scorer.score("THEQUICKBROWNFOX")
        checks.append(("quadgrams", test_score < 0, f"score={test_score:.1f}"))
    except FileNotFoundError:
        checks.append(("quadgrams", False, "quadgram file not found"))
    except Exception as e:
        checks.append(("quadgrams", False, str(e)))

    # 10. Novelty engine
    try:
        from kryptos.novelty.hypothesis import Hypothesis, ResearchQuestion
        h = Hypothesis(
            description="test",
            research_questions=[ResearchQuestion.RQ1_CIPHER_TYPE],
        )
        checks.append(("novelty_engine", h.hypothesis_id is not None, f"id={h.hypothesis_id}"))
    except Exception as e:
        checks.append(("novelty_engine", False, str(e)))

    # Print results
    all_pass = True
    if verbose:
        print("Kryptos Research Suite — Doctor")
        print("=" * 50)
        for name, passed, detail in checks:
            status = "PASS" if passed else "FAIL"
            if not passed:
                all_pass = False
            line = f"  [{status}] {name}"
            if detail:
                line += f" ({detail})"
            print(line)
        print()
        if all_pass:
            print("All checks passed.")
        else:
            print("SOME CHECKS FAILED — fix before running experiments.")
    else:
        all_pass = all(p for _, p, _ in checks)

    return all_pass
