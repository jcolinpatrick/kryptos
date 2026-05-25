from kryptos.kernel.constraints.derive import derive_bean_constraints as _derive_core
from kryptos.kernel.constants import CT, CRIB_DICT, MOD, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR

IDENTITY = list(range(26))  # AZ index table: index_table[ord(ch)-65] == position

def test_core_reproduces_canonical_bean_sets():
    eq, ineq, linear = _derive_core(CT, CRIB_DICT, IDENTITY, MOD)
    assert eq == BEAN_EQ
    assert ineq == BEAN_INEQ
    assert linear == BEAN_LINEAR
    assert (len(eq), len(ineq), len(linear)) == (1, 242, 101)


import kryptos.kernel.constants as K

def test_constants_use_the_shared_core():
    # The private per-set derivers are gone; one shared call remains.
    assert not hasattr(K, "_derive_bean_eq")
    assert (len(K.BEAN_EQ), len(K.BEAN_INEQ), len(K.BEAN_LINEAR)) == (1, 242, 101)
    assert K.BEAN_EQ == ((27, 65),)


from kryptos.kernel.constraints.bean import derive_bean_constraints, check_bean, verify_bean
from kryptos.kernel.alphabet import AZ
from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR

def test_alphabet_wrapper_matches_canonical():
    eq, ineq, linear = derive_bean_constraints(CT, CRIB_DICT, AZ)
    assert (eq, ineq, linear) == (BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)

def test_check_bean_parameterized_matches_verify_bean():
    ks = list(range(97))  # arbitrary keystream
    full = verify_bean(ks)
    param = check_bean(ks, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)
    assert param.passed == full.passed
    assert (param.eq_satisfied, param.ineq_satisfied, param.linear_satisfied) == \
           (full.eq_satisfied, full.ineq_satisfied, full.linear_satisfied)

def test_check_bean_accepts_short_keystream_for_masked_use():
    eq, ineq, linear = ((0, 1),), (), ()
    assert check_bean([5, 5, 9], eq, ineq, linear).passed is True
    assert check_bean([5, 7, 9], eq, ineq, linear).passed is False
