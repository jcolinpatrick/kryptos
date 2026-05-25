from kryptos.kernel.constraints.derive import derive_bean_constraints
from kryptos.kernel.constants import CT, CRIB_DICT, MOD, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR

IDENTITY = list(range(26))  # AZ index table: index_table[ord(ch)-65] == position

def test_core_reproduces_canonical_bean_sets():
    eq, ineq, linear = derive_bean_constraints(CT, CRIB_DICT, IDENTITY, MOD)
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
