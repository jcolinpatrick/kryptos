"""SMT/CSP constraint solver for K4 feasibility analysis.

Uses Z3 and/or OR-Tools CP-SAT to propagate Bean constraints, crib
constraints, and cipher-specific structure to prune infeasible regions
of the search space BEFORE brute-force enumeration.

This is NOT a replacement for the brute-force pipeline — it's a pruning
layer that eliminates impossible configurations symbolically.

Usage:
    from kryptos.kernel.constraints.solver import K4ConstraintModel

    model = K4ConstraintModel(variant="beaufort")
    model.add_bean_constraints()
    model.add_crib_constraints()
    model.add_periodic_key(period=7)
    feasible = model.is_feasible()
    # If feasible, enumerate solutions or extract bounds
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

try:
    from ortools.sat.python import cp_model
    HAS_ORTOOLS = True
except ImportError:
    HAS_ORTOOLS = False

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, CRIB_DICT,
    BEAN_EQ, BEAN_INEQ,
)


class K4ConstraintModel:
    """Z3-backed constraint model for K4 keystream analysis.

    Models the keystream as 97 integer variables in [0, 25] and adds
    constraints from Bean's analysis, known cribs, and cipher structure.
    """

    def __init__(self, variant: str = "beaufort"):
        """Initialize with cipher variant for key recovery.

        variant: 'vigenere' | 'beaufort' | 'var_beaufort'
        """
        if not HAS_Z3:
            raise ImportError("z3-solver is required: pip install z3-solver")

        self.variant = variant
        self.solver = z3.Solver()
        self.k = [z3.Int(f"k_{i}") for i in range(CT_LEN)]

        # Domain constraints: k[i] in [0, 25]
        for i in range(CT_LEN):
            self.solver.add(self.k[i] >= 0, self.k[i] <= 25)

        self._crib_added = False
        self._bean_added = False

    def add_bean_constraints(self) -> "K4ConstraintModel":
        """Add all 243 Bean constraints (1 equality + 242 inequalities)."""
        if self._bean_added:
            return self

        for a, b in BEAN_EQ:
            self.solver.add(self.k[a] == self.k[b])

        for a, b in BEAN_INEQ:
            self.solver.add(self.k[a] != self.k[b])

        self._bean_added = True
        return self

    def add_crib_constraints(self) -> "K4ConstraintModel":
        """Add crib-derived keystream values.

        Under Beaufort (default): K[i] = (CT[i] + PT[i]) mod 26
        Under Vigenere:           K[i] = (CT[i] - PT[i]) mod 26
        Under Var Beaufort:       K[i] = (PT[i] - CT[i]) mod 26
        """
        if self._crib_added:
            return self

        for pos, pt_ch in CRIB_DICT.items():
            ct_val = ord(CT[pos]) - 65
            pt_val = ord(pt_ch) - 65

            if self.variant == "beaufort":
                key_val = (ct_val + pt_val) % MOD
            elif self.variant == "vigenere":
                key_val = (ct_val - pt_val) % MOD
            else:  # var_beaufort
                key_val = (pt_val - ct_val) % MOD

            self.solver.add(self.k[pos] == key_val)

        self._crib_added = True
        return self

    def add_periodic_key(self, period: int) -> "K4ConstraintModel":
        """Add periodicity constraint: k[i] = k[i % period] for all i."""
        for i in range(period, CT_LEN):
            self.solver.add(self.k[i] == self.k[i % period])
        return self

    def add_custom_constraint(self, constraint) -> "K4ConstraintModel":
        """Add an arbitrary Z3 constraint on the keystream variables."""
        self.solver.add(constraint)
        return self

    def is_feasible(self, timeout_ms: int = 5000) -> bool:
        """Check if the current constraint set is satisfiable."""
        self.solver.set("timeout", timeout_ms)
        result = self.solver.check()
        return result == z3.sat

    def check(self, timeout_ms: int = 5000) -> str:
        """Check satisfiability. Returns 'sat', 'unsat', or 'unknown'."""
        self.solver.set("timeout", timeout_ms)
        return str(self.solver.check())

    def get_model(self) -> Optional[Dict[int, int]]:
        """If SAT, return one satisfying keystream assignment."""
        if self.solver.check() != z3.sat:
            return None
        m = self.solver.model()
        return {i: m[self.k[i]].as_long() for i in range(CT_LEN)
                if m[self.k[i]] is not None}

    def count_solutions(self, positions: List[int],
                        max_count: int = 10000,
                        timeout_ms: int = 30000) -> int:
        """Count distinct value assignments at given positions.

        Useful for measuring the remaining degrees of freedom after
        constraint propagation. Enumerates by blocking found solutions.
        """
        self.solver.set("timeout", timeout_ms)
        count = 0
        temp_solver = z3.Solver()
        temp_solver.add(self.solver.assertions())
        temp_solver.set("timeout", timeout_ms)

        while count < max_count:
            if temp_solver.check() != z3.sat:
                break
            m = temp_solver.model()
            # Block this solution
            block = z3.Or([
                self.k[p] != m[self.k[p]].as_long()
                for p in positions
                if m[self.k[p]] is not None
            ])
            temp_solver.add(block)
            count += 1

        return count

    @property
    def variables(self) -> List:
        """Access the Z3 keystream variables for custom constraints."""
        return self.k


class K4TranspositionModel:
    """OR-Tools CP-SAT model for transposition feasibility.

    Models a transposition permutation as an AllDifferent constraint
    combined with crib position requirements.
    """

    def __init__(self, width: int):
        if not HAS_ORTOOLS:
            raise ImportError("ortools is required: pip install ortools")

        self.width = width
        self.model = cp_model.CpModel()
        self.n = CT_LEN

        # Permutation variables: perm[i] = j means position i in output
        # came from position j in input
        self.perm = [
            self.model.new_int_var(0, self.n - 1, f"p_{i}")
            for i in range(self.n)
        ]

        # AllDifferent: it's a permutation
        self.model.add_all_different(self.perm)

    def add_columnar_structure(self, col_order: List[int]) -> "K4TranspositionModel":
        """Constrain perm to be a columnar transposition with given column order."""
        rows = (self.n + self.width - 1) // self.width
        pos = 0
        for col in col_order:
            for row in range(rows):
                input_pos = row * self.width + col
                if input_pos < self.n:
                    self.model.add(self.perm[pos] == input_pos)
                    pos += 1
        return self

    def add_crib_output_positions(self, crib_positions: List[int]) -> "K4TranspositionModel":
        """Require that specific output positions map from specific input positions.

        crib_positions: list of output positions that must contain crib characters.
        """
        for pos in crib_positions:
            if pos < self.n:
                # The value at output position `pos` must come from a crib input position
                # This is a domain restriction on perm[pos]
                pass  # Generic version - specific constraints depend on the cipher model
        return self

    def is_feasible(self, timeout_s: int = 5) -> bool:
        """Check feasibility."""
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = timeout_s
        status = solver.solve(self.model)
        return status in (cp_model.OPTIMAL, cp_model.FEASIBLE)

    def count_solutions(self, max_count: int = 10000, timeout_s: int = 30) -> int:
        """Count feasible permutations up to max_count."""
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = timeout_s

        counter = _SolutionCounter(max_count)
        solver.parameters.enumerate_all_solutions = True
        solver.solve(self.model, counter)
        return counter.count


class _SolutionCounter(cp_model.CpSolverSolutionCallback):
    def __init__(self, limit: int):
        super().__init__()
        self.count = 0
        self.limit = limit

    def on_solution_callback(self):
        self.count += 1
        if self.count >= self.limit:
            self.stop_search()
