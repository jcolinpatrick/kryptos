"""Strong cold-start joint (sigma + plaintext) search for the two-sided
E-FRAC-54 detector (src/kryptos/detectors/efrac54_joint.py).

Model: C[i] = sigma(PT[i]) (+)/(-) K[pi(i)]  (PT/CT aligned; key transposed).
For PT index i:  Khat[pi[i]] = invert(CT[i], sigma(PT[i])).

The search maximizes the two-sided statistic t = L_PT + L_K (mean nats/char over
non-crib quadgram windows on the plaintext and on the implied keystream Khat).

Speed: an incremental scorer. The valid quadgram-window sets are fixed by the crib
mask, so running sums are maintained and only touched windows are recomputed:
  - change PT[i]: <=4 PT windows + the single Khat[pi[i]] -> <=4 Khat windows;
  - swap sigma[x],sigma[y]: only the Khat positions of plaintext letters x and y.
The incremental scorer is validated against score_joint (the authority) before use.
"""
from __future__ import annotations
import math
import random
from typing import List, Sequence

from kryptos.kernel.constants import ALPH, ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT_LEN
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm
from kryptos.detectors.efrac54_joint import CandidateTuple, score_joint

_LN10 = math.log(10.0)
_CRIBSET = set(CRIB_POSITIONS)
_NONCRIB = [i for i in range(CT_LEN) if i not in _CRIBSET]


def _pi_for(width: int, kappa: Sequence[int], n: int) -> List[int]:
    if width <= 1 or len(kappa) != width:
        return list(range(n))
    return columnar_perm(width, list(kappa), length=n)


class JointState:
    """Mutable (sigma, pt) state with incremental two-sided quadgram scoring.

    Mirrors efrac54_joint._score_nats exactly: per valid window, contribution is
    log_probs.get(gram, floor_log10) * ln(10); L = sum / count.
    """

    def __init__(self, ct_idx: Sequence[int], pi: Sequence[int], variant: str, scorer):
        self.ct = list(ct_idx)
        self.n = len(ct_idx)
        self.pi = list(pi)
        self.variant = variant
        self.lp = scorer.log_probs
        self.floor10 = scorer._floor
        pi_inv = invert_perm(self.pi)
        self.pt_starts = [s for s in range(self.n - 3)
                          if all((s + k) not in _CRIBSET for k in range(4))]
        self.k_starts = [s for s in range(self.n - 3)
                         if all(pi_inv[s + k] not in _CRIBSET for k in range(4))]
        self.cnt_pt = len(self.pt_starts) or 1
        self.cnt_k = len(self.k_starts) or 1
        self.pt_wins_at: List[List[int]] = [[] for _ in range(self.n)]
        for s in self.pt_starts:
            for k in range(4):
                self.pt_wins_at[s + k].append(s)
        self.k_wins_at: List[List[int]] = [[] for _ in range(self.n)]
        for s in self.k_starts:
            for k in range(4):
                self.k_wins_at[s + k].append(s)
        # state filled by set_state
        self.sigma: List[int] = []
        self.pt: List[int] = []
        self.khat: List[int] = []
        self.pos: List[List[int]] = []
        self.sum_pt = 0.0
        self.sum_k = 0.0

    def _kf(self, c: int, s: int) -> int:
        if self.variant == "vigenere":
            return (c - s) % 26
        if self.variant == "beaufort":
            return (c + s) % 26
        return (s - c) % 26  # var_beaufort

    def _qg_pt(self, s: int) -> float:
        g = ALPH[self.pt[s]] + ALPH[self.pt[s + 1]] + ALPH[self.pt[s + 2]] + ALPH[self.pt[s + 3]]
        return self.lp.get(g, self.floor10) * _LN10

    def _qg_k(self, s: int) -> float:
        g = ALPH[self.khat[s]] + ALPH[self.khat[s + 1]] + ALPH[self.khat[s + 2]] + ALPH[self.khat[s + 3]]
        return self.lp.get(g, self.floor10) * _LN10

    def set_state(self, sigma: Sequence[int], pt: Sequence[int]) -> None:
        self.sigma = list(sigma)
        self.pt = list(pt)
        self.khat = [0] * self.n
        for i in range(self.n):
            self.khat[self.pi[i]] = self._kf(self.ct[i], self.sigma[self.pt[i]])
        self.sum_pt = sum(self._qg_pt(s) for s in self.pt_starts)
        self.sum_k = sum(self._qg_k(s) for s in self.k_starts)
        self.pos = [[] for _ in range(26)]
        for i in range(self.n):
            self.pos[self.pt[i]].append(i)

    def t(self) -> float:
        return self.sum_pt / self.cnt_pt + self.sum_k / self.cnt_k

    def apply_pt_move(self, i: int, new_letter: int) -> float:
        """Set PT[i]=new_letter; return delta-t. Re-call with old to revert."""
        old = self.pt[i]
        if new_letter == old:
            return 0.0
        d_sum_pt = 0.0
        for s in self.pt_wins_at[i]:
            d_sum_pt -= self._qg_pt(s)
        # Khat side: position pi[i] changes
        j = self.pi[i]
        d_sum_k = 0.0
        for s in self.k_wins_at[j]:
            d_sum_k -= self._qg_k(s)
        # mutate
        self.pos[old].remove(i)
        self.pos[new_letter].append(i)
        self.pt[i] = new_letter
        self.khat[j] = self._kf(self.ct[i], self.sigma[new_letter])
        for s in self.pt_wins_at[i]:
            d_sum_pt += self._qg_pt(s)
        for s in self.k_wins_at[j]:
            d_sum_k += self._qg_k(s)
        self.sum_pt += d_sum_pt
        self.sum_k += d_sum_k
        return d_sum_pt / self.cnt_pt + d_sum_k / self.cnt_k

    def apply_sigma_swap(self, x: int, y: int) -> float:
        """Swap sigma[x],sigma[y]; return delta-t. Re-call (x,y) to revert."""
        if x == y:
            return 0.0
        affected = self.pos[x] + self.pos[y]
        touched_windows = set()
        for i in affected:
            for s in self.k_wins_at[self.pi[i]]:
                touched_windows.add(s)
        d_sum_k = 0.0
        for s in touched_windows:
            d_sum_k -= self._qg_k(s)
        self.sigma[x], self.sigma[y] = self.sigma[y], self.sigma[x]
        for i in affected:
            self.khat[self.pi[i]] = self._kf(self.ct[i], self.sigma[self.pt[i]])
        for s in touched_windows:
            d_sum_k += self._qg_k(s)
        self.sum_k += d_sum_k
        return d_sum_k / self.cnt_k


def _build_full_pt(sigma_unused, pt_nc_letters: List[int]) -> List[int]:
    """Weave non-crib PT ints with canonical crib letters -> length-n int list."""
    pt = [0] * CT_LEN
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ALPH_IDX[ch]
    it = iter(pt_nc_letters)
    for i in _NONCRIB:
        pt[i] = next(it)
    return pt


def joint_search(ct: str, width: int, kappa: Sequence[int], variant: str,
                 scorer=None, n_iters: int = 120000, restarts: int = 4,
                 rng: random.Random | None = None):
    """Strong cold-start SA over (sigma, non-crib PT). Returns the best JointScore
    (authoritatively recomputed via score_joint)."""
    if scorer is None:
        scorer = get_default_scorer()
    if rng is None:
        rng = random.Random()
    ct_idx = [ALPH_IDX[c] for c in ct]
    pi = _pi_for(width, kappa, len(ct))
    st = JointState(ct_idx, pi, variant, scorer)
    best_t = -math.inf
    best_sigma: List[int] = list(range(26))
    best_pt: List[int] = [0] * CT_LEN
    for _ in range(restarts):
        sigma = list(range(26))
        rng.shuffle(sigma)
        pt = _build_full_pt(sigma, [rng.randrange(26) for _ in _NONCRIB])
        st.set_state(sigma, pt)
        cur = st.t()
        for it in range(n_iters):
            temp = max(1e-3, 2.0 * (1.0 - it / n_iters))
            if rng.random() < 0.7:
                i = _NONCRIB[rng.randrange(len(_NONCRIB))]
                old = st.pt[i]
                new = rng.randrange(26)
                if new == old:
                    continue
                d = st.apply_pt_move(i, new)
                if d >= 0 or rng.random() < math.exp(d / temp):
                    cur += d
                else:
                    st.apply_pt_move(i, old)
            else:
                a, b = rng.randrange(26), rng.randrange(26)
                if a == b:
                    continue
                d = st.apply_sigma_swap(a, b)
                if d >= 0 or rng.random() < math.exp(d / temp):
                    cur += d
                else:
                    st.apply_sigma_swap(a, b)
            if cur > best_t:
                best_t = cur
                best_sigma = st.sigma[:]
                best_pt = st.pt[:]
    pt_nc = "".join(ALPH[best_pt[i]] for i in _NONCRIB)
    return score_joint(ct, CandidateTuple(tuple(best_sigma), width, tuple(kappa), pt_nc),
                       scorer, variant)
