#!/usr/bin/env python3
"""E-S-103: Thematic Running Key + Width-7 Columnar (Extended Search)

Tests running keys from thematically relevant texts combined with all
5040 width-7 columnar orderings.

Texts tested:
  - Reagan "Tear down this wall" Berlin speech (1987)
  - JFK "Ich bin ein Berliner" speech (1963)
  - CIA charter text
  - NSA Act of 1947
  - Universal Declaration of Human Rights
  - Carter book (Gutenberg edition — full text)
  - Additional Egypt/Berlin/CIA themed passages

Model B: CT → undo_transposition → intermediate → undo_substitution → PT
  intermediate[j] = CT[perm[j]]
  PT[j] = (intermediate[j] - key[j]) mod 26  (Vigenère)

For each text × offset × ordering × variant: check 24 cribs.
Expected random: 24/26 ≈ 0.92. Signal: ≥18. Breakthrough: 24.
"""

import json, os, time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

W = 7
VNAMES = ['Vig', 'Beau', 'VBeau']


def build_perm(order):
    nr = (N + W - 1) // W
    ns = nr * W - N
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p


def clean_text(text):
    return ''.join(c for c in text.upper() if c in AZ)


ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INTERMEDIATES = [[CT_N[PERMS[oi][j]] for j in range(N)] for oi in range(len(ORDERS))]


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


# ── Load reference texts ─────────────────────────────────────────────
TEXTS = {}

ref_dir = "reference/running_key_texts"
for fname in os.listdir(ref_dir):
    if fname.endswith('.txt'):
        with open(os.path.join(ref_dir, fname)) as f:
            text = clean_text(f.read())
        if len(text) >= N:
            TEXTS[fname.replace('.txt', '')] = text

# Carter full text
for carter_path in ["reference/carter_gutenberg.txt", "reference/carter_text_cache.txt",
                     "reference/carter_vol1_extract.txt"]:
    if os.path.exists(carter_path):
        with open(carter_path) as f:
            text = clean_text(f.read())
        if len(text) >= N:
            name = os.path.basename(carter_path).replace('.txt', '')
            if name not in TEXTS:
                TEXTS[name] = text

# Inline thematic texts not yet in reference/
INLINE_TEXTS = {
    'declaration_independence': clean_text("""
        WHEN IN THE COURSE OF HUMAN EVENTS IT BECOMES NECESSARY FOR ONE PEOPLE
        TO DISSOLVE THE POLITICAL BANDS WHICH HAVE CONNECTED THEM WITH ANOTHER
        AND TO ASSUME AMONG THE POWERS OF THE EARTH THE SEPARATE AND EQUAL STATION
        TO WHICH THE LAWS OF NATURE AND OF NATURES GOD ENTITLE THEM A DECENT RESPECT
        TO THE OPINIONS OF MANKIND REQUIRES THAT THEY SHOULD DECLARE THE CAUSES
        WHICH IMPEL THEM TO THE SEPARATION WE HOLD THESE TRUTHS TO BE SELF EVIDENT
        THAT ALL MEN ARE CREATED EQUAL THAT THEY ARE ENDOWED BY THEIR CREATOR WITH
        CERTAIN UNALIENABLE RIGHTS THAT AMONG THESE ARE LIFE LIBERTY AND THE PURSUIT
        OF HAPPINESS
    """),
    'gettysburg_address': clean_text("""
        FOUR SCORE AND SEVEN YEARS AGO OUR FATHERS BROUGHT FORTH ON THIS CONTINENT
        A NEW NATION CONCEIVED IN LIBERTY AND DEDICATED TO THE PROPOSITION THAT ALL
        MEN ARE CREATED EQUAL NOW WE ARE ENGAGED IN A GREAT CIVIL WAR TESTING WHETHER
        THAT NATION OR ANY NATION SO CONCEIVED AND SO DEDICATED CAN LONG ENDURE WE ARE
        MET ON A GREAT BATTLE FIELD OF THAT WAR WE HAVE COME TO DEDICATE A PORTION OF
        THAT FIELD AS A FINAL RESTING PLACE FOR THOSE WHO HERE GAVE THEIR LIVES THAT
        THAT NATION MIGHT LIVE
    """),
    'kryptos_morse': clean_text("""
        BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LYING VIRTUALLY INVISIBLE
        IT IS ALMOST SUPERNATURAL T IS YOUR POSITION SHADOW FORCES DIGETAL
        INTERPRETATION LUCID MEMORY
    """),
    'k1_plaintext': clean_text("""
        BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION
    """),
    'k2_plaintext': clean_text("""
        IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD
        X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION
        X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE
        X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE
        X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH
        SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST
        X LAYER TWO
    """),
    'k3_plaintext': clean_text("""
        SLOWLY DESPERATELY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED
        THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY
        BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE
        I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER
        CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN
        EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q
    """),
    'egypt_pharaoh': clean_text("""
        THE DISCOVERY OF THE TOMB OF TUTANKHAMUN BY HOWARD CARTER AND LORD CARNARVON
        IN NOVEMBER NINETEEN TWENTY TWO WAS ONE OF THE GREATEST ARCHAEOLOGICAL FINDS
        IN HISTORY THE TOMB WAS NEARLY INTACT AND CONTAINED THOUSANDS OF ARTIFACTS
        INCLUDING THE FAMOUS GOLDEN DEATH MASK OF THE YOUNG PHARAOH THE TREASURES
        OF THE TOMB REVEALED THE SPLENDOR OF ANCIENT EGYPTIAN CIVILIZATION AND THE
        BURIAL PRACTICES OF THE NEW KINGDOM PERIOD WHEN CARTER FIRST PEERED INTO
        THE CHAMBER LORD CARNARVON ASKED CAN YOU SEE ANYTHING AND CARTER REPLIED
        YES WONDERFUL THINGS
    """),
    'berlin_wall_history': clean_text("""
        THE BERLIN WALL WAS A GUARDED CONCRETE BARRIER THAT PHYSICALLY AND
        IDEOLOGICALLY DIVIDED BERLIN FROM NINETEEN SIXTY ONE TO NINETEEN EIGHTY NINE
        CONSTRUCTED BY THE GERMAN DEMOCRATIC REPUBLIC THE WALL COMPLETELY CUT OFF
        WEST BERLIN FROM SURROUNDING EAST GERMANY AND FROM EAST BERLIN THE BARRIER
        INCLUDED GUARD TOWERS PLACED ALONG LARGE CONCRETE WALLS ACCOMPANIED BY A WIDE
        AREA KNOWN AS THE DEATH STRIP THAT CONTAINED ANTI VEHICLE TRENCHES AND OTHER
        DEFENSES THE EASTERN BLOC PORTRAYED THE WALL AS PROTECTING ITS POPULATION
        FROM FASCIST ELEMENTS CONSPIRING TO PREVENT THE WILL OF THE PEOPLE IN BUILDING
        A SOCIALIST STATE IN EAST GERMANY
    """),
    'cia_history': clean_text("""
        THE CENTRAL INTELLIGENCE AGENCY WAS CREATED IN NINETEEN FORTY SEVEN WITH THE
        SIGNING OF THE NATIONAL SECURITY ACT BY PRESIDENT HARRY S TRUMAN THE AGENCY
        WAS FORMED TO COORDINATE THE NATIONS INTELLIGENCE ACTIVITIES AND CORRELATE
        EVALUATE AND DISSEMINATE INTELLIGENCE WHICH AFFECTS NATIONAL SECURITY THE
        CIA HEADQUARTERS BUILDING IN LANGLEY VIRGINIA WAS COMPLETED IN NINETEEN
        SIXTY ONE AND HAS SERVED AS THE AGENCYS MAIN FACILITY SINCE THEN THE LOBBY
        OF THE ORIGINAL HEADQUARTERS BUILDING FEATURES THE MEMORIAL WALL WITH STARS
        REPRESENTING CIA OFFICERS WHO DIED IN THE LINE OF SERVICE THE KRYPTOS
        SCULPTURE BY ARTIST JIM SANBORN WAS DEDICATED ON NOVEMBER THREE NINETEEN
        NINETY AND STANDS IN THE COURTYARD BETWEEN THE OLD AND NEW HEADQUARTERS
    """),
    'rosetta_stone': clean_text("""
        THE ROSETTA STONE IS A GRANODIORITE STELE INSCRIBED WITH THREE VERSIONS OF
        A DECREE ISSUED IN MEMPHIS EGYPT IN ONE NINETY SIX BC DURING THE PTOLEMAIC
        DYNASTY ON BEHALF OF KING PTOLEMY THE FIFTH THE TOP AND MIDDLE TEXTS ARE IN
        ANCIENT EGYPTIAN USING HIEROGLYPHIC AND DEMOTIC SCRIPTS RESPECTIVELY WHILE
        THE BOTTOM IS IN ANCIENT GREEK THE DECREE HAS ONLY MINOR DIFFERENCES BETWEEN
        THE THREE VERSIONS MAKING THE ROSETTA STONE KEY TO THE MODERN UNDERSTANDING
        OF EGYPTIAN HIEROGLYPHS THE STONE WAS FOUND IN SEVENTEEN NINETY NINE BY
        FRENCH SOLDIERS
    """),
    'sanborn_artist_statement': clean_text("""
        MY WORK DEALS WITH THE THEME OF SECRECY AND THE HIDDEN NATURE OF INTELLIGENCE
        GATHERING THE SCULPTURE CONTAINS A RIDDLE WITHIN A RIDDLE WHICH WILL BE
        SOLVABLE ONLY AFTER THE FOUR ENCRYPTED PASSAGES HAVE BEEN DECIPHERED THE
        CIPHERTEXT ON THE MAIN SCULPTURE IS DIVIDED INTO FOUR SECTIONS EACH ENCRYPTED
        WITH A DIFFERENT METHOD THE FIRST THREE SECTIONS WERE SOLVED IN NINETEEN
        NINETY NINE THE FOURTH SECTION REMAINS UNSOLVED
    """),
    'whats_the_point': clean_text("""
        WHAT IS THE POINT OF ALL OF THIS SECRECY THE CODES ARE ABOUT DELIVERING A
        MESSAGE HIDDEN IN PLAIN SIGHT VISIBLE TO ALL WHO PASS BY BUT UNDERSTOOD BY
        NONE POWER RESIDES WITH A SECRET NOT WITHOUT IT THE LOCATION IS BURIED OUT
        THERE SOMEWHERE EAST NORTHEAST OF THE BERLIN CLOCK
    """),
}

for name, text in INLINE_TEXTS.items():
    if len(text) >= N:
        TEXTS[name] = text

print("=" * 70)
print("E-S-103: Thematic Running Key + Width-7 Columnar")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}, texts={len(TEXTS)}")
print("=" * 70)

for name, text in sorted(TEXTS.items()):
    print(f"  {name}: {len(text)} chars")

t0 = time.time()
results = {}

for text_name, text in sorted(TEXTS.items()):
    text_nums = [I2N[c] for c in text]
    text_len = len(text_nums)
    max_offset = text_len - N
    if max_offset < 0:
        continue

    best_score = 0
    best_cfg = None
    tested = 0

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        for offset in range(max_offset + 1):
            key = text_nums[offset:offset + N]

            for vi in range(3):
                pt = [0] * N
                for j in range(N):
                    if vi == 0:  # Vig: PT = I - K
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:  # Beau: PT = K - I
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:  # VBeau: PT = I + K
                        pt[j] = (intermed[j] + key[j]) % 26

                score = check_cribs(pt)
                tested += 1

                if score > best_score:
                    best_score = score
                    best_cfg = (ORDERS[oi], VNAMES[vi], offset)

                if score >= 18:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  *** HIT {text_name}: {score}/24 order={ORDERS[oi]} "
                          f"{VNAMES[vi]} offset={offset}")
                    print(f"      PT: {pt_text}")

                if score >= 24:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"\n  !!!!! BREAKTHROUGH with {text_name} !!!!!")
                    print(f"  PT: {pt_text}")
                    print(f"  Key: {text[offset:offset+40]}...")

    elapsed = time.time() - t0
    print(f"  {text_name}: best={best_score}/24, {tested:,} tested, {elapsed:.0f}s")
    results[text_name] = {'best': best_score, 'cfg': str(best_cfg)}


# ── Also test reverse of each text ────────────────────────────────────
print("\n--- Reversed texts ---")

for text_name, text in sorted(list(TEXTS.items())[:5]):  # Top 5 only
    rev_text = text[::-1]
    rev_nums = [I2N[c] for c in rev_text]
    max_offset = len(rev_nums) - N
    if max_offset < 0:
        continue

    best_score = 0
    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]
        for offset in range(max_offset + 1):
            key = rev_nums[offset:offset + N]
            for vi in range(3):
                pt = [0] * N
                for j in range(N):
                    if vi == 0:
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + key[j]) % 26
                score = check_cribs(pt)
                if score > best_score:
                    best_score = score

    print(f"  {text_name}_reversed: best={best_score}/24")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for name, data in sorted(results.items()):
    print(f"  {name}: {data['best']}/24")
print(f"  Total: {total_elapsed:.1f}s")

best = max(v['best'] for v in results.values()) if results else 0
if best >= 18:
    print(f"\n  Verdict: SIGNAL — {best}/24")
else:
    print(f"\n  Verdict: NOISE — {best}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-103',
    'description': 'Thematic running key + width-7 columnar',
    'results': results,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_103_thematic_running_key.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_103_thematic_running_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_103_thematic_running_key.py")
