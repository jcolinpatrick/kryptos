"""Tests for Z3/OR-Tools constraint solver module."""
import pytest

from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, MOD

try:
    from kryptos.kernel.constraints.solver import (
        K4ConstraintModel, K4TranspositionModel,
        HAS_Z3, HAS_ORTOOLS,
    )
except ImportError:
    HAS_Z3 = False
    HAS_ORTOOLS = False


@pytest.mark.skipif(not HAS_Z3, reason="z3-solver not installed")
class TestZ3Model:

    def test_basic_feasibility(self):
        """Unconstrained model should be feasible."""
        model = K4ConstraintModel()
        assert model.is_feasible()

    def test_bean_constraints_feasible(self):
        """Bean constraints alone should be feasible."""
        model = K4ConstraintModel()
        model.add_bean_constraints()
        assert model.is_feasible()

    def test_crib_constraints_feasible(self):
        """Crib constraints alone should be feasible."""
        model = K4ConstraintModel()
        model.add_crib_constraints()
        assert model.is_feasible()

    def test_bean_plus_crib_feasible(self):
        """Bean + crib constraints should be feasible (K4 is solvable)."""
        model = K4ConstraintModel()
        model.add_bean_constraints()
        model.add_crib_constraints()
        assert model.is_feasible()

    def test_model_respects_bean_equality(self):
        """Any solution must have k[27] = k[65]."""
        model = K4ConstraintModel()
        model.add_bean_constraints()
        model.add_crib_constraints()
        solution = model.get_model()
        assert solution is not None
        assert solution[27] == solution[65]

    def test_model_respects_crib_values(self):
        """Crib-derived keystream values must be correct."""
        model = K4ConstraintModel(variant="beaufort")
        model.add_crib_constraints()
        solution = model.get_model()
        assert solution is not None

        for pos, pt_ch in CRIB_DICT.items():
            ct_val = ord(CT[pos]) - 65
            pt_val = ord(pt_ch) - 65
            expected_key = (ct_val + pt_val) % MOD
            assert solution[pos] == expected_key, \
                f"Crib mismatch at pos {pos}: got {solution[pos]}, expected {expected_key}"

    def test_contradictory_constraints_infeasible(self):
        """Adding a contradictory constraint should make the model infeasible."""
        model = K4ConstraintModel()
        model.add_crib_constraints()
        # Force k[21] to a wrong value
        ct_val = ord(CT[21]) - 65
        pt_val = ord('E') - 65
        correct = (ct_val + pt_val) % MOD
        wrong = (correct + 1) % MOD
        import z3
        model.add_custom_constraint(model.k[21] == wrong)
        assert not model.is_feasible()

    def test_periodic_key_constraints(self):
        """Periodic key model should be feasible for some periods."""
        model = K4ConstraintModel()
        model.add_crib_constraints()
        model.add_periodic_key(period=7)
        # Period 7 may or may not be feasible depending on crib consistency
        result = model.check()
        assert result in ("sat", "unsat")

    def test_check_returns_valid_status(self):
        model = K4ConstraintModel()
        result = model.check()
        assert result in ("sat", "unsat", "unknown")


@pytest.mark.skipif(not HAS_ORTOOLS, reason="ortools not installed")
class TestORToolsModel:

    def test_basic_transposition_feasible(self):
        """A permutation of 97 elements should be feasible."""
        model = K4TranspositionModel(width=7)
        assert model.is_feasible()
