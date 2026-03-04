"""
Cipher: infrastructure
Family: _infra
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Simulated Annealing plaintext search for K4.
Fixes cribs at known positions and optimizes free positions
to maximize English quadgram score of the full plaintext.
Also enforces Bean equality: k[27] = k[65].
"""
import json, math, os, random, time, sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = Path(os.getenv("K4_BASE_DIR", str(REPO_ROOT)))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

# Cribs
CRIBS = {
    21: 'EASTNORTHEAST',
    63: 'BERLINCLOCK',
}

# Fixed positions from cribs
fixed = {}
for start, text in CRIBS.items():
    for i, ch in enumerate(text):
        fixed[start + i] = ord(ch) - ord('A')

# Free positions
free_pos = sorted(set(range(N)) - set(fixed.keys()))
print(f"Free positions: {len(free_pos)}, Fixed: {len(fixed)}")

# Load quadgrams
QG_PATH = str(BASE_DIR / "data" / "english_quadgrams.json")
with open(QG_PATH) as f:
    quadgrams = json.load(f)

FLOOR = -10.0

def qg_score(text):
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += quadgrams.get(qg, FLOOR)
    return score

def nums_to_text(nums):
    return ''.join(chr(n + ord('A')) for n in nums)

def vig_key(pt_nums):
    return [(CT_NUM[i] - pt_nums[i]) % 26 for i in range(N)]

def bean_penalty(pt_nums):
    """Bean equality: k[27] = k[65], i.e., (CT[27]-PT[27]) = (CT[65]-PT[65]) mod 26"""
    k27 = (CT_NUM[27] - pt_nums[27]) % 26
    k65 = (CT_NUM[65] - pt_nums[65]) % 26
    if k27 == k65:
        return 0.0
    return -50.0  # heavy penalty

def full_score(pt_nums):
    pt_text = nums_to_text(pt_nums)
    return qg_score(pt_text) + bean_penalty(pt_nums)

# Initialize: random letters at free positions, fixed at crib positions
def make_initial():
    pt = [0] * N
    for pos, val in fixed.items():
        pt[pos] = val
    for pos in free_pos:
        pt[pos] = random.randint(0, 25)
    return pt

# SA parameters
T_START = 2.0
T_END = 0.001
STEPS = 2_000_000
RESTARTS = 20

best_global_score = -999999
best_global_pt = None
best_global_key = None

print(f"\nSimulated Annealing: {RESTARTS} restarts × {STEPS:,} steps")
print(f"Temperature: {T_START} → {T_END}")
print("=" * 70)

t0 = time.time()

for restart in range(RESTARTS):
    pt = make_initial()

    # Enforce Bean: adjust PT[65] so k[27]=k[65]
    k27 = (CT_NUM[27] - pt[27]) % 26
    pt[65] = (CT_NUM[65] - k27) % 26

    current_score = full_score(pt)
    best_score = current_score
    best_pt = pt[:]

    accepted = 0
    for step in range(STEPS):
        T = T_START * (T_END / T_START) ** (step / STEPS)

        # Mutation: change one free position
        pos = random.choice(free_pos)
        old_val = pt[pos]
        new_val = random.randint(0, 25)
        if new_val == old_val:
            new_val = (old_val + random.randint(1, 25)) % 26

        pt[pos] = new_val

        # If we changed pos 27, fix pos 65 for Bean
        if pos == 27:
            old_65 = pt[65]
            k27_new = (CT_NUM[27] - new_val) % 26
            pt[65] = (CT_NUM[65] - k27_new) % 26
        elif pos == 65:
            # Fix: set pt[65] to maintain Bean with current pt[27]
            k27 = (CT_NUM[27] - pt[27]) % 26
            pt[65] = (CT_NUM[65] - k27) % 26
            new_val = pt[65]  # update for potential revert

        new_score = full_score(pt)
        delta = new_score - current_score

        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            accepted += 1
            if current_score > best_score:
                best_score = current_score
                best_pt = pt[:]
        else:
            pt[pos] = old_val
            if pos == 27:
                k27_old = (CT_NUM[27] - old_val) % 26
                pt[65] = (CT_NUM[65] - k27_old) % 26
            elif pos == 65:
                pt[65] = old_val  # restore

    pt_text = nums_to_text(best_pt)
    key = vig_key(best_pt)
    key_text = nums_to_text(key)

    elapsed = time.time() - t0
    print(f"\nRestart {restart+1}/{RESTARTS} (elapsed: {elapsed:.0f}s)")
    print(f"  Score: {best_score:.1f} (accepted: {accepted/STEPS*100:.1f}%)")
    print(f"  PT: {pt_text}")
    print(f"  Key: {key_text}")

    # Check Bean
    k27 = key[27]
    k65 = key[65]
    print(f"  Bean: k[27]={k27}, k[65]={k65} {'PASS' if k27==k65 else 'FAIL'}")

    if best_score > best_global_score:
        best_global_score = best_score
        best_global_pt = best_pt[:]
        best_global_key = key[:]

print("\n" + "=" * 70)
print("BEST OVERALL RESULT")
print("=" * 70)
pt_text = nums_to_text(best_global_pt)
key_text = nums_to_text(best_global_key)
print(f"Score: {best_global_score:.1f}")
print(f"PT:  {pt_text}")
print(f"Key: {key_text}")

# Show segments
print(f"\nPT segments:")
print(f"  Pre-ENE (0-20):  {pt_text[:21]}")
print(f"  ENE (21-33):     {pt_text[21:34]}")
print(f"  Mid (34-62):     {pt_text[34:63]}")
print(f"  BC (63-73):      {pt_text[63:74]}")
print(f"  Post-BC (74-96): {pt_text[74:]}")

print(f"\nKey segments:")
print(f"  Pre-ENE (0-20):  {key_text[:21]}")
print(f"  ENE (21-33):     {key_text[21:34]}")
print(f"  Mid (34-62):     {key_text[34:63]}")
print(f"  BC (63-73):      {key_text[63:74]}")
print(f"  Post-BC (74-96): {key_text[74:]}")

# Verify cribs
print(f"\nCrib verification:")
for start, crib in CRIBS.items():
    actual = pt_text[start:start+len(crib)]
    print(f"  pos {start}: expected={crib}, got={actual}, {'PASS' if actual==crib else 'FAIL'}")

k27 = best_global_key[27]
k65 = best_global_key[65]
print(f"  Bean: k[27]={k27}, k[65]={k65} {'PASS' if k27==k65 else 'FAIL'}")
