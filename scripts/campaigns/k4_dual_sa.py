"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Dual-objective SA: search for K4 key that produces English plaintext
AND is itself English-like (running key hypothesis).

Key insight: if the key is derived from an English text (running key),
then BOTH the plaintext AND key should have high quadgram scores.
The combined score may find solutions that single-objective SA misses.

Also includes: SA on Beaufort decryption, and SA on key-as-English.
"""
import json, math, os, random, time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = Path(os.getenv("K4_BASE_DIR", str(REPO_ROOT)))

CT = 'OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR'
CT_NUM = [ord(c) - ord('A') for c in CT]
N = 97

CRIBS = {21: 'EASTNORTHEAST', 63: 'BERLINCLOCK'}

fixed_key = {}
for start, pt in CRIBS.items():
    for i, ch in enumerate(pt):
        pos = start + i
        fixed_key[pos] = (CT_NUM[pos] - (ord(ch) - ord('A'))) % 26

free_pos = sorted(set(range(N)) - set(fixed_key.keys()))

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

def n2c(n): return chr(n % 26 + ord('A'))

def key_to_pt(key):
    return ''.join(n2c((CT_NUM[i] - key[i]) % 26) for i in range(N))

def key_to_text(key):
    return ''.join(n2c(k) for k in key)

def bean_ok(key):
    return key[27] == key[65]

# ============================================================
# MODE 1: DUAL SCORE (PT english + KEY english)
# ============================================================
print("=" * 70)
print("DUAL SA: OPTIMIZE PT + KEY ENGLISH SCORES")
print("=" * 70)

STEPS = 3_000_000
RESTARTS = 10
T_START = 3.0
T_END = 0.001

best_global = {'score': -999999, 'key': None}

t0 = time.time()

for restart in range(RESTARTS):
    key = [0] * N
    for pos, val in fixed_key.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = random.randint(0, 25)
    # Enforce Bean
    key[65] = key[27]

    pt_text = key_to_pt(key)
    key_text = key_to_text(key)
    pt_score = qg_score(pt_text)
    key_score = qg_score(key_text)
    # Weight: PT matters more, but key should be readable too
    current_score = 0.7 * pt_score + 0.3 * key_score
    best_score = current_score
    best_key = key[:]

    accepted = 0
    for step in range(STEPS):
        T = T_START * (T_END / T_START) ** (step / STEPS)

        pos = random.choice(free_pos)
        old_val = key[pos]
        key[pos] = (old_val + random.randint(1, 25)) % 26

        # Enforce Bean
        if pos == 27:
            old_65 = key[65]
            key[65] = key[27]
        elif pos == 65:
            key[65] = key[27]  # override to maintain Bean

        pt_text = key_to_pt(key)
        key_text = key_to_text(key)
        new_score = 0.7 * qg_score(pt_text) + 0.3 * qg_score(key_text)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            accepted += 1
            if current_score > best_score:
                best_score = current_score
                best_key = key[:]
        else:
            key[pos] = old_val
            if pos == 27:
                key[65] = old_65
            elif pos == 65:
                pass  # already restored

    elapsed = time.time() - t0
    pt_final = key_to_pt(best_key)
    key_final = key_to_text(best_key)

    print(f"\nRestart {restart+1}/{RESTARTS} ({elapsed:.0f}s)")
    print(f"  Combined: {best_score:.1f} (acc: {accepted/STEPS*100:.1f}%)")
    print(f"  PT:  {pt_final}")
    print(f"  Key: {key_final}")
    print(f"  PT qg: {qg_score(pt_final):.1f}, Key qg: {qg_score(key_final):.1f}")

    if best_score > best_global['score']:
        best_global = {'score': best_score, 'key': best_key[:]}

# Show best dual result
print("\n" + "=" * 70)
print("BEST DUAL SA RESULT")
print("=" * 70)
key = best_global['key']
pt = key_to_pt(key)
kt = key_to_text(key)
print(f"Score: {best_global['score']:.1f}")
print(f"PT:  {pt}")
print(f"Key: {kt}")
print(f"PT qg:  {qg_score(pt):.1f}")
print(f"Key qg: {qg_score(kt):.1f}")
print(f"Bean: k[27]={key[27]}, k[65]={key[65]} {'PASS' if key[27]==key[65] else 'FAIL'}")

# ============================================================
# MODE 2: SA PURE KEY-AS-ENGLISH
# ============================================================
print("\n" + "=" * 70)
print("SA: OPTIMIZE KEY AS ENGLISH TEXT (running key hypothesis)")
print("=" * 70)

best_global_key = {'score': -999999, 'key': None}

for restart in range(RESTARTS):
    key = [0] * N
    for pos, val in fixed_key.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = random.randint(0, 25)
    key[65] = key[27]

    key_text = key_to_text(key)
    current_score = qg_score(key_text)
    best_score = current_score
    best_key = key[:]

    for step in range(STEPS):
        T = T_START * (T_END / T_START) ** (step / STEPS)

        pos = random.choice(free_pos)
        old_val = key[pos]
        key[pos] = (old_val + random.randint(1, 25)) % 26
        if pos == 27:
            old_65 = key[65]
            key[65] = key[27]
        elif pos == 65:
            key[65] = key[27]

        key_text = key_to_text(key)
        new_score = qg_score(key_text)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            if current_score > best_score:
                best_score = current_score
                best_key = key[:]
        else:
            key[pos] = old_val
            if pos == 27:
                key[65] = old_65

    pt_final = key_to_pt(best_key)
    key_final = key_to_text(best_key)
    elapsed = time.time() - t0

    print(f"\nRestart {restart+1}/{RESTARTS} ({elapsed:.0f}s)")
    print(f"  Key qg: {best_score:.1f}")
    print(f"  Key: {key_final}")
    print(f"  PT:  {pt_final}")

    if best_score > best_global_key['score']:
        best_global_key = {'score': best_score, 'key': best_key[:]}

print("\n" + "=" * 70)
print("BEST KEY-AS-ENGLISH RESULT")
print("=" * 70)
key = best_global_key['key']
pt = key_to_pt(key)
kt = key_to_text(key)
print(f"Key qg: {best_global_key['score']:.1f}")
print(f"Key: {kt}")
print(f"PT:  {pt}")
print(f"PT qg:  {qg_score(pt):.1f}")

# ============================================================
# MODE 3: SA BEAUFORT PLAINTEXT
# ============================================================
print("\n" + "=" * 70)
print("SA: BEAUFORT DECRYPTION (PT = key - CT mod 26)")
print("=" * 70)

# Under Beaufort, PT[i] = (key[i] - CT[i]) mod 26
# Cribs: key[pos] = (CT[pos] + PT[pos]) mod 26
fixed_beau = {}
for start, pt in CRIBS.items():
    for i, ch in enumerate(pt):
        pos = start + i
        fixed_beau[pos] = (CT_NUM[pos] + (ord(ch) - ord('A'))) % 26

def beau_key_to_pt(key):
    return ''.join(n2c((key[i] - CT_NUM[i]) % 26) for i in range(N))

best_global_beau = {'score': -999999, 'key': None}

for restart in range(RESTARTS):
    key = [0] * N
    for pos, val in fixed_beau.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = random.randint(0, 25)
    key[65] = key[27]  # Bean under Beaufort: k[27]=k[65]

    pt_text = beau_key_to_pt(key)
    current_score = qg_score(pt_text)
    best_score = current_score
    best_key = key[:]

    for step in range(STEPS):
        T = T_START * (T_END / T_START) ** (step / STEPS)

        pos = random.choice(free_pos)
        old_val = key[pos]
        key[pos] = (old_val + random.randint(1, 25)) % 26
        if pos == 27:
            old_65 = key[65]
            key[65] = key[27]
        elif pos == 65:
            key[65] = key[27]

        pt_text = beau_key_to_pt(key)
        new_score = qg_score(pt_text)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            if current_score > best_score:
                best_score = current_score
                best_key = key[:]
        else:
            key[pos] = old_val
            if pos == 27:
                key[65] = old_65

    pt_final = beau_key_to_pt(best_key)
    key_final = key_to_text(best_key)
    elapsed = time.time() - t0

    print(f"\nRestart {restart+1}/{RESTARTS} ({elapsed:.0f}s)")
    print(f"  PT qg: {best_score:.1f}")
    print(f"  PT:  {pt_final}")
    print(f"  Key: {key_final}")

    if best_score > best_global_beau['score']:
        best_global_beau = {'score': best_score, 'key': best_key[:]}

print("\n" + "=" * 70)
print("BEST BEAUFORT RESULT")
print("=" * 70)
key = best_global_beau['key']
pt = beau_key_to_pt(key)
kt = key_to_text(key)
print(f"PT qg: {best_global_beau['score']:.1f}")
print(f"PT:  {pt}")
print(f"Key: {kt}")

print("\n" + "=" * 70)
print("DUAL SA COMPLETE")
print("=" * 70)
