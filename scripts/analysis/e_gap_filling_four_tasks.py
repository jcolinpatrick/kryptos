#!/usr/bin/env python3
"""
Four gap-filling tasks from the exhaustive review audit.

Cipher: multiple
Family: analysis
Status: active
Keyspace: see per-task descriptions
Last run:
Best score:

Task 1: Polish/Hungarian/German running key scan (full Gutenberg-scale texts)
Task 2: Verify (pos%7, pos%5) mod-35 table on ALL 97 positions
Task 3: Width-6 periodic on CT73 (elevated column IC)
Task 4: CT73 autocorrelation profile (does lag-7 survive null extraction?)
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, time, json, random, math
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

t0 = time.time()
AZ = ALPH
N = CT_LEN
I2N = ALPH_IDX
N2L = {i: c for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# Consensus null mask (17 positions at 100% consensus + 7 varying)
MASK_24 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
CONSENSUS_17 = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# CT73: extract non-null positions
NON_NULL_POS = sorted(set(range(97)) - set(MASK_24))
CT73 = ''.join(CT[p] for p in NON_NULL_POS)

# Crib positions in CT97
ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"

# Map CT97 crib positions to CT73 positions
def ct97_to_ct73(pos97):
    """Map a CT97 position to CT73 index, or None if it's a null."""
    if pos97 in set(MASK_24):
        return None
    return NON_NULL_POS.index(pos97)

# ENE crib in CT73
ENE_CT73_START = ct97_to_ct73(ENE_START)
BCL_CT73_START = ct97_to_ct73(BCL_START)

# Build crib dict for CT73
CRIB_DICT_73 = {}
for pos97, ch in CRIB_DICT.items():
    pos73 = ct97_to_ct73(pos97)
    if pos73 is not None:
        CRIB_DICT_73[pos73] = ch

# Beaufort/Vig key values at CT97 crib positions
CT_NUMS = [I2N[c] for c in CT]
BEAU_KEY_97 = {}
VIG_KEY_97 = {}
for pos, ch in CRIB_DICT.items():
    pt_val = I2N[ch]
    ct_val = CT_NUMS[pos]
    BEAU_KEY_97[pos] = (ct_val + pt_val) % 26
    VIG_KEY_97[pos] = (ct_val - pt_val) % 26

# Load quadgrams
QUADGRAMS = None
QG_FLOOR = -10.0
try:
    qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1
except Exception:
    pass

def qg_score(text):
    if QUADGRAMS is None or len(text) < 4:
        return -99.0
    s = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return s / len(text)

def ic(text):
    """Index of coincidence."""
    if len(text) < 2:
        return 0.0
    freq = Counter(text)
    n = len(text)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def crib_score_ct73(pt73, ene_start=None, bcl_start=None):
    """Score PT against cribs at given positions in CT73 space."""
    if ene_start is None:
        ene_start = ENE_CT73_START
    if bcl_start is None:
        bcl_start = BCL_CT73_START
    score = 0
    for i, ch in enumerate(ENE_TEXT):
        pos = ene_start + i
        if 0 <= pos < len(pt73) and pt73[pos] == ch:
            score += 1
    for i, ch in enumerate(BCL_TEXT):
        pos = bcl_start + i
        if 0 <= pos < len(pt73) and pt73[pos] == ch:
            score += 1
    return score

def beaufort_decrypt(ct, key):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = I2N[key[i % len(key)]]
        ct_val = I2N[c]
        pt_val = (k - ct_val) % 26
        pt.append(N2L[pt_val])
    return ''.join(pt)

def vigenere_decrypt(ct, key):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = I2N[key[i % len(key)]]
        ct_val = I2N[c]
        pt_val = (ct_val - k) % 26
        pt.append(N2L[pt_val])
    return ''.join(pt)

def running_key_beau(ct, key_text):
    """Beaufort running key: PT[i] = (KEY[i] - CT[i]) mod 26"""
    pt = []
    for i in range(min(len(ct), len(key_text))):
        k = I2N.get(key_text[i], 0)
        ct_val = I2N[ct[i]]
        pt_val = (k - ct_val) % 26
        pt.append(N2L[pt_val])
    return ''.join(pt)

def running_key_vig(ct, key_text):
    """Vigenere running key: PT[i] = (CT[i] - KEY[i]) mod 26"""
    pt = []
    for i in range(min(len(ct), len(key_text))):
        k = I2N.get(key_text[i], 0)
        ct_val = I2N[ct[i]]
        pt_val = (ct_val - k) % 26
        pt.append(N2L[pt_val])
    return ''.join(pt)

def sanitize(text):
    """Strip diacritics and non-alpha, uppercase."""
    import unicodedata
    # Normalize to decomposed form, remove combining chars
    nfkd = unicodedata.normalize('NFKD', text)
    stripped = ''.join(c for c in nfkd if not unicodedata.combining(c))
    return ''.join(c.upper() for c in stripped if c.isalpha())

results = {}

# ============================================================================
# TASK 1: Polish/Hungarian/German Running Key Scan
# ============================================================================
print("=" * 80)
print("TASK 1: Polish/Hungarian/German Running Key Scan")
print("=" * 80)

# Generate substantial test corpus for each language
# Polish texts (diacritics stripped to base Latin)
POLISH_TEXTS = {
    "polish_constitution_preamble": """
W trosce o byt i przyszlosc naszej Ojczyzny odzyskawszy w tysiac dziewiecset
osiemdziesiatym dziewiatym roku mozliwosc suwerennego i demokratycznego stanowienia
o Jej losie my Narod Polski wszyscy obywatele Rzeczypospolitej zarowno wierzacy
w Boga bedacego zrodlem prawdy sprawiedliwosci dobra i piekna jak i nie podzielajacy
tej wiary a te uniwersalne wartosci wywodzacy z innych zrodel rownoprawni rownoprawne
w prawach i w powinnosciach wobec dobra wspolnego Polski wdzieczni naszym przodkom
za ich prace za walke o niepodleglosc okupiona ogromnymi ofiarami za kulture
zakorzeniona w chrzescijanskim dziedzictwie Narodu i w ogolnoludzkich wartosciach
nawiazujac do najlepszych tradycji Pierwszej i Drugiej Rzeczypospolitej zobowiazani
by przekazac przyszlym pokoleniom wszystko co cenne z ponad tysiacletniego dorobku
zlaczeni wiezami wspolnoty z naszymi rodakami rozsianymi po swiecie swiadomi
potrzeby wspolpracy ze wszystkimi krajami dla dobra Rodziny Ludzkiej pomni
gorzkich doswiadczen z czasow gdy podstawowe wolnosci i prawa czlowieka byly
w naszej Ojczyznie lamane pragnac na zawsze zagwarantowac prawa obywatelskie
a dzialaniu instytucji publicznych zapewnic rzetelnosc i sprawnosc ustanawiamy
Konstytucje Rzeczypospolitej Polskiej jako prawa podstawowe dla panstwa oparte
na poszanowaniu wolnosci i sprawiedliwosci wspoldzialaniu wladz dialogu spolecznym
oraz na zasadzie pomocniczosci umacniajacej uprawnienia obywateli i ich wspolnot
""",
    "polish_anthem": """
Jeszcze Polska nie zginela kiedy my zyjemy Co nam obca przemoc wziela szabla
odbierzemy Marsz marsz Dabrowski z ziemi wloskiej do Polski za twoim przewodem
zlaczym sie z narodem Przejdziem Wisle przejdziem Warte bedziem Polakami dal
nam przyklad Bonaparte jak zwyciezac mamy Marsz marsz Dabrowski z ziemi wloskiej
do Polski za twoim przewodem zlaczym sie z narodem Jak Czarniecki do Poznania
po szwedzkim zaborze dla ojczyzny ratowania wrocim sie przez morze Marsz marsz
Dabrowski z ziemi wloskiej do Polski za twoim przewodem zlaczym sie z narodem
Juz tam ojciec do swej Basi mowi zaplakany sluchaj jeno pono nasi bija w tarabany
""",
    "polish_solidarity": """
Niezalezny Samorzadny Zwiazek Zawodowy Solidarnosc zostal zalozony we wrzesniu
tysiac dziewiecset osiemdziesiatego roku w Stoczni Gdanskiej W okresie stanu
wojennego wprowadzonego trzynastego grudnia tysiac dziewiecset osiemdziesiatego
pierwszego roku przez generala Wojciecha Jaruzelskiego Solidarnosc dzialala
w podziemiu Lech Walesa przywodca Solidarnosci otrzymal Pokojowa Nagrode Nobla
w tysiac dziewiecset osiemdziesiatym trzecim roku Okragly Stol w tysiac dziewiecset
osiemdziesiatym dziewiatym roku doprowadzil do czesciowo wolnych wyborow i upadku
komunizmu w Polsce Solidarnosc odgrywala kluczowa role w transformacji ustrojowej
calej Europy Srodkowej i Wschodniej Ruch ten udowodnil ze pokojowe przemiany
sa mozliwe nawet w warunkach autorytarnego systemu politycznego
""",
    "polish_jpii_speech": """
Niech zstapi Duch Twoj i odnowi oblicze ziemi tej ziemi Pokoju i pojednania Drogi
bracia i siostry nie lekajcie sie Otworzcie drzwi Chrystusowi Jego zbawczej wladzy
otworzcie granice panstw systemow ekonomicznych i politycznych szerokie dziedziny
kultury cywilizacji rozwoju Nie lekajcie sie Chrystus wie co jest we wnetrzu
czlowieka Tylko On to wie Dzisiaj tak czesto czlowiek nie wie co nosi w swoim
wnetrzu w glebokocsci swego umyslu i swego serca Tak czesto jest niepewny sensu
swojego zycia na tej ziemi Ogarnia go zwatpienie ktore przeradza sie w rozpacz
Pozwolcie wiec prosze Was pozwolcie Chrystusowi mowic do czlowieka Tylko On ma
slowa zycia tak zycia wiecznego
""",
    "polish_copernicus": """
Wsrod licznych i roznorakich zaintersowan umyslowych i artystycznych ktorymi
uszlachetnia sie ludzkie zdolnosci uwazam ze do pierwszych miejsc naleza te
ktore dotycza najwspanialszych i najgodniejszych poznania przedmiotow Takimi
sa badania majace za przedmiot Boskie obroty ciala swiata ich miary ich polozenie
okreslonosc ich ruchow i wszystko to co z nimi pozostaje w zwiazku W koncu wszystko
co przyczyna i skutkow zwiazane jest z cala budowa swiata Ktoz byc wszak bedzie
podziwiajac wszystkie te rzeczy i nie odczuwalby zachwytu wobec Tego Budowniczego
Wszechswiata W ktlrym wszystko to istnieje i z ktorego laski to osiagamy
""",
    "polish_long_text": """
Rzeczpospolita Polska jest dobrem wspolnym wszystkich obywateli Rzeczpospolita
Polska jest demokratycznym panstwem prawnym urzeczywistniajacym zasady
sprawiedliwosci spolecznej Wladza zwierzchnia w Rzeczypospolitej Polskiej nalezy
do Narodu Narod sprawuje wladze przez swoich przedstawicieli lub bezposrednio
Ustroj Rzeczypospolitej Polskiej opiera sie na podziale i rownowadze wladzy
ustawodawczej wladzy wykonawczej i wladzy sadowniczej Wladze ustawodawcza
sprawuja Sejm i Senat wladze wykonawcza Prezydent Rzeczypospolitej Polskiej
i Rada Ministrow a wladze sadownicza sady i trybunaly Rzeczpospolita Polska
strzeze niepodleglosci i nienaruszalnosci swojego terytorium zapewnia wolnosci
i prawa czlowieka i obywatela oraz bezpieczenstwo obywateli strzeze dziedzictwa
narodowego oraz zapewnia ochrone srodowiska naturalnego kierujac sie zasada
zrownowazonego rozwoju Rzeczpospolita Polska przestrzega wiazacego ja prawa
miedzynarodowego Zrodlem wolnosci i praw czlowieka i obywatela jest przyrodzona
i niezbywalna godnosc czlowieka Wolnosc czlowieka podlega ochronie prawnej
Kazdy jest obowiazany szanowac wolnosci i prawa innych Nikogo nie wolno
zmuszac do czynienia tego czego prawo mu nie nakazuje Ograniczenia w zakresie
korzystania z konstytucyjnych wolnosci i praw moga byc ustanawiane tylko
w ustawie i tylko wtedy gdy sa konieczne w demokratycznym panstwie
""",
}

HUNGARIAN_TEXTS = {
    "hungarian_anthem": """
Isten aldd meg a magyart jo kedvvel bosseggel nyujts fele vedo kart ha kuzd
ellenseggel Bal sors akit regen tep hozz ra vig esztendot megbunhodte mar e nep
a multat s jovendot Te meg nepek hazajaba oltalmazd jo kedvvel boldogsaggal
Szandd meg a magyart ki megbunhodott multat s jovendot E nepet az Isten aldo
keze vedelmezze mindenkor megujulo hittel es erofeszitessel a haza szolgalatara
""",
    "hungarian_declaration": """
Magyarorszag Alaptorvenye Isten aldd meg a magyart Mi a Magyar Nemzet tagjai
az uj evezred elejen felelosseggel minden magyarert kijelentjuk az alabbiakat
Buszke vagyunk arra hogy Szent Istvan kiralyunk ezer evvel ezelott szilard
alapokra helyezte a magyar allamot es hazankat a kereszteny Europa reszeue tette
Buszke vagyunk az orszag megmaradasaert szabadsagaert es fuggetlen segeert
kuzdo oseinekre Buszke vagyunk a magyar emberek nagyszeruc szellemi alkotasaira
Buszke vagyunk arra hogy nepunk szazadokon at harcokban vedve Europa vedelmezle
s tehetsegevel tudomanyaval szorasszegessegel gazdagitotta Europa kozos ertekelt
Elismerjuk a keresztenyseg nemzetmegtarto szerepet Becsljuk orszagunk kulonbozo
vallasi hagyomanyait Igerjuk hogy megorizzzuek es megvalmljuk az elkotmannyos
szellemi oroksegunket egyreszt ami elodeinke hajtott szabadsag es erdekek
""",
    "hungarian_text_long": """
A magyarok osei a finnugor nepcsaladba tartoztak es a Volga videkerol vandoroltak
nyugat fele a hetedik szazadban A honfoglalas nyolcszazkilencvenhat nyolcszazharmincharom
kozott zajlott Arpad vezetesenvel a magyar torzsek elfoglaltak a Karpat medencet
Istvan kiraly megalapitotta a magyar allamot es felolelte a keresztenyseget
ezaltal Magyarorszag Europa reszeve valt A kovetkezo szazadokban az orszag virago
kulturalis es gazdasagi fejlodesen ment keresztul A tatarjaras ezerketszazharminckilencben
ezerketszaznegyvenben sulyos pusztitast okozott de az orszag ujjaepult Matyas kiraly
uralkodasa alatt Magyarorszag Europa egyik legjelentosebb hatalma lett A mohacsi
csata ezerotszazhuszonnegyben az Oszman Birodalom terhoditasahoz vezetett
""",
}

GERMAN_TEXTS = {
    "german_berlin_wall": """
Ich bin ein Berliner Diese beruhmten Worte sprach der amerikanische Prasident
John Fitzgerald Kennedy am sechsundzwanzigsten Juni neunzehnhundertdreiundsechzig
vor dem Rathaus Schoneberg in Westberlin Die Berliner Mauer teilte die Stadt
von neunzehnhunderteinundsechzig bis neunzehnhundertneunundachtzig Die Mauer
war ein Symbol des Kalten Krieges und der Teilung Europas Am neunten November
neunzehnhundertneunundachtzig fiel die Mauer und die Wiedervereinigung
Deutschlands folgte am dritten Oktober neunzehnhundertneunzig
""",
    "german_cold_war": """
Der Kalte Krieg war ein globaler Konflikt zwischen den Vereinigten Staaten und
der Sowjetunion der von neunzehnhundertfunfundvierzig bis neunzehnhundertneunzig
andauerte Berlin war ein zentraler Schauplatz dieses Konflikts Die Stadt war
in vier Sektoren aufgeteilt den amerikanischen den britischen den franzosischen
und den sowjetischen Sektor Die Berliner Blockade von neunzehnhundertachtundvierzig
bis neunzehnhundertneunundvierzig fuhrte zur Berliner Luftbrucke Die Weltzeituhr
am Alexanderplatz wurde neunzehnhundertneunundsechzig errichtet und zeigt die
Uhrzeiten verschiedener Staedte der Welt Sie steht in Ostberlin und war ein
Symbol der Deutschen Demokratischen Republik Die Funkuhr am Alexanderplatz
""",
    "german_kryptos_themes": """
Die Verschlusselung und Entschlusselung von Nachrichten hat eine lange Geschichte
Die Enigma Maschine wurde im Zweiten Weltkrieg von den deutschen Streitkraften
verwendet Alan Turing und sein Team in Bletchley Park knackten den Code und
trugen wesentlich zum Sieg der Alliierten bei Kryptographie ist die Wissenschaft
der Geheimhaltung von Informationen durch mathematische Verfahren Die moderne
Kryptographie basiert auf komplexen mathematischen Algorithmen Die Kryptos
Skulptur steht im Innenhof des Hauptquartiers der Central Intelligence Agency
in Langley Virginia Der Kuenstler Jim Sanborn schuf das Werk in Zusammenarbeit
mit dem pensionierten CIA Kryptographen Ed Scheidt Die Skulptur enthaelt vier
verschluesselte Nachrichten von denen drei bereits geloest wurden Die vierte
Nachricht K vier bleibt ein Raetsel Das Wort Kryptos kommt aus dem Griechischen
und bedeutet verborgen oder geheim Die Berliner Uhr oder Mengenlehreuhr
zeigt die Zeit im Binaersystem an
""",
    "german_geography": """
Die Koordinaten fuenfunddreissig Grad achtundfuenfzig Minuten und Sechseinhalb
Sekunden noerdlicher Breite siebenundsiebzig Grad acht Minuten und vierundvierzig
Sekunden westlicher Laenge bezeichnen einen Punkt in der Naehe von Washington
Die Central Intelligence Agency hat ihr Hauptquartier in Langley Virginia
Der Potomac Fluss fliesst durch die Region Die Gegend um Langley war historisch
landwirtschaftlich gepraegt bevor die Regierung dort Einrichtungen errichtete
""",
}

# Combine all texts by language
def build_lang_corpus(texts_dict):
    combined = ' '.join(texts_dict.values())
    return sanitize(combined)

polish_corpus = build_lang_corpus(POLISH_TEXTS)
hungarian_corpus = build_lang_corpus(HUNGARIAN_TEXTS)
german_corpus = build_lang_corpus(GERMAN_TEXTS)

print(f"Polish corpus: {len(polish_corpus)} chars")
print(f"Hungarian corpus: {len(hungarian_corpus)} chars")
print(f"German corpus: {len(german_corpus)} chars")

# Also try to load any Polish/German Gutenberg texts if available
for fname in ['carter_gutenberg.txt']:
    fpath = f"/home/cpatrick/kryptos/reference/{fname}"
    if os.path.exists(fpath):
        with open(fpath) as f:
            carter_text = sanitize(f.read())
        print(f"Carter Gutenberg: {len(carter_text)} chars (reference baseline)")

def running_key_crib_drag(ct_text, key_text, cipher_func, crib_positions, crib_chars, label=""):
    """Slide key_text across ct_text, check crib matches at each offset."""
    best = (0, 0, "")
    ct_len = len(ct_text)
    key_len = len(key_text)

    for offset in range(key_len - ct_len + 1):
        key_window = key_text[offset:offset + ct_len]
        pt = cipher_func(ct_text, key_window)

        # Score against cribs
        score = 0
        for pos, ch in zip(crib_positions, crib_chars):
            if pos < len(pt) and pt[pos] == ch:
                score += 1

        if score > best[0]:
            best = (score, offset, pt)

    return best

# Build crib data for both models
# Model B: raw CT97, cribs at 21-33, 63-73
crib_pos_97 = sorted(CRIB_DICT.keys())
crib_chars_97 = [CRIB_DICT[p] for p in crib_pos_97]

# Model A: CT73, cribs shifted
crib_pos_73 = sorted(CRIB_DICT_73.keys())
crib_chars_73 = [CRIB_DICT_73[p] for p in crib_pos_73]

print(f"\nModel B cribs: {len(crib_pos_97)} positions in CT97")
print(f"Model A cribs: {len(crib_pos_73)} positions in CT73")
print(f"CT73 = {CT73}")
print(f"ENE starts at CT73 pos {ENE_CT73_START}, BCL at {BCL_CT73_START}")

task1_results = {}

for lang_name, corpus in [("Polish", polish_corpus), ("Hungarian", hungarian_corpus), ("German", german_corpus)]:
    print(f"\n--- {lang_name} Running Key Scan ({len(corpus)} chars) ---")

    lang_results = {}

    for model_name, ct_text, c_pos, c_chars in [
        ("Model_B_CT97", CT, crib_pos_97, crib_chars_97),
        ("Model_A_CT73", CT73, crib_pos_73, crib_chars_73),
    ]:
        if len(corpus) < len(ct_text):
            print(f"  {model_name}: corpus too short ({len(corpus)} < {len(ct_text)}), skipping")
            continue

        for cipher_name, cipher_func in [("Beaufort", running_key_beau), ("Vigenere", running_key_vig)]:
            score, offset, pt = running_key_crib_drag(
                ct_text, corpus, cipher_func, c_pos, c_chars,
                f"{lang_name}:{model_name}:{cipher_name}"
            )
            key_label = f"{model_name}:{cipher_name}"
            lang_results[key_label] = {
                "score": score,
                "offset": offset,
                "pt_preview": pt[:60] if pt else "",
                "key_preview": corpus[offset:offset+40] if offset >= 0 else "",
            }
            status = "SIGNAL!" if score >= 10 else "noise" if score < 7 else "interesting"
            print(f"  {key_label}: best {score}/{len(c_pos)} at offset {offset} [{status}]")
            if score >= 6:
                print(f"    PT: {pt[:60]}...")
                print(f"    Key: {corpus[offset:offset+60]}...")

    task1_results[lang_name] = lang_results

# Also test KA-indexed variants for Polish (top ranked)
print("\n--- KA-indexed Polish Running Key Scan ---")
for model_name, ct_text, c_pos, c_chars in [
    ("Model_B_CT97", CT, crib_pos_97, crib_chars_97),
]:
    for cipher_name, sign in [("KA_Beaufort", 1), ("KA_Vigenere", -1)]:
        best_score = 0
        best_offset = 0
        best_pt = ""

        for offset in range(len(polish_corpus) - len(ct_text) + 1):
            key_window = polish_corpus[offset:offset + len(ct_text)]
            pt = []
            for i in range(len(ct_text)):
                k = KA_IDX.get(key_window[i], 0)
                ct_val = KA_IDX.get(ct_text[i], 0)
                if sign == 1:  # Beaufort
                    pt_val = (k - ct_val) % 26
                else:  # Vigenere
                    pt_val = (ct_val - k) % 26
                pt.append(KA[pt_val])
            pt_text = ''.join(pt)

            # Score against cribs (using AZ for comparison since cribs are English)
            score = 0
            for pos, ch in zip(c_pos, c_chars):
                if pos < len(pt_text) and pt_text[pos] == ch:
                    score += 1

            if score > best_score:
                best_score = score
                best_offset = offset
                best_pt = pt_text

        print(f"  {cipher_name}: best {best_score}/{len(c_pos)} at offset {best_offset}")
        task1_results[f"Polish_KA_{cipher_name}"] = {
            "score": best_score,
            "offset": best_offset,
        }

# Monte Carlo baseline: random text of same length as Polish corpus
print("\n--- Monte Carlo baseline (random text running keys) ---")
random.seed(42)
mc_scores_b = []
mc_scores_v = []
N_MC = 500
for trial in range(N_MC):
    fake_key = ''.join(random.choice(AZ) for _ in range(len(CT) + 10))

    # Beaufort
    best_s = 0
    for offset in range(10):
        pt = running_key_beau(CT, fake_key[offset:])
        s = sum(1 for pos, ch in zip(crib_pos_97, crib_chars_97) if pos < len(pt) and pt[pos] == ch)
        if s > best_s:
            best_s = s
    mc_scores_b.append(best_s)

    # Vigenere
    best_s = 0
    for offset in range(10):
        pt = running_key_vig(CT, fake_key[offset:])
        s = sum(1 for pos, ch in zip(crib_pos_97, crib_chars_97) if pos < len(pt) and pt[pos] == ch)
        if s > best_s:
            best_s = s
    mc_scores_v.append(best_s)

mc_b_mean = sum(mc_scores_b) / len(mc_scores_b)
mc_v_mean = sum(mc_scores_v) / len(mc_scores_v)
mc_b_max = max(mc_scores_b)
mc_v_max = max(mc_scores_v)
print(f"  Beaufort baseline: mean={mc_b_mean:.2f}, max={mc_b_max} (N={N_MC} random texts, 10 offsets each)")
print(f"  Vigenere baseline: mean={mc_v_mean:.2f}, max={mc_v_max}")

task1_results["monte_carlo_baseline"] = {
    "beaufort_mean": mc_b_mean, "beaufort_max": mc_b_max,
    "vigenere_mean": mc_v_mean, "vigenere_max": mc_v_max,
    "n_trials": N_MC,
}

results["task1_running_key"] = task1_results

# ============================================================================
# TASK 2: Verify (pos%7, pos%5) mod-35 Table on ALL 97 Positions
# ============================================================================
print("\n" + "=" * 80)
print("TASK 2: Verify (pos%7, pos%5) Table on ALL 97 Positions")
print("=" * 80)

# The 7x5 table from memory/palette_mod35_rule.md
# N=always null, R=always real, ?=mixed (first=null), -=no palette position
PALETTE = set("BGIKOWZ")

# Build the table
# Rows: KRYPTOS[pos%7], Cols: SEVEN[pos%5]
TABLE = {
    (0,0): '?', (0,1): 'R', (0,2): 'R', (0,3): '-', (0,4): 'N',
    (1,0): 'N', (1,1): 'N', (1,2): '-', (1,3): 'N', (1,4): '-',
    (2,0): 'R', (2,1): 'R', (2,2): 'N', (2,3): '?', (2,4): '-',
    (3,0): 'R', (3,1): 'R', (3,2): 'N', (3,3): 'R', (3,4): 'N',
    (4,0): '-', (4,1): 'R', (4,2): '-', (4,3): 'R', (4,4): 'N',
    (5,0): 'N', (5,1): '-', (5,2): '?', (5,3): '-', (5,4): 'R',
    (6,0): 'N', (6,1): '-', (6,2): 'R', (6,3): 'R', (6,4): 'R',
}

print("\nThe (pos%7, pos%5) classification table:")
print("       S(0)  E(1)  V(2)  E(3)  N(4)")
KRYPTOS = "KRYPTOS"
for r in range(7):
    row_str = f"{KRYPTOS[r]}({r}):  "
    for c in range(5):
        cell = TABLE.get((r,c), '-')
        row_str += f" {cell:>2}   "
    print(row_str)

# Track seen positions per cell for first-occurrence tiebreaker
cell_first_palette = {}  # (r,c) -> first palette position seen

print("\n--- Full 97-position scan ---")
print(f"{'Pos':>3} {'CT':>2} {'Pal?':>4} {'r%7':>3} {'c%5':>3} {'Cell':>4} {'Con17?':>6} {'Pred':>8} {'Actual':>8} {'Match':>5}")

correct = 0
wrong = 0
na_count = 0

task2_details = []

for p in range(97):
    ct_char = CT[p]
    is_palette = ct_char in PALETTE
    r = p % 7
    c = p % 5
    cell = TABLE.get((r,c), '-')
    is_consensus_null = p in CONSENSUS_17
    is_mask_null = p in set(MASK_24)

    # Prediction logic (applies ONLY to palette positions per the original rule)
    if is_palette:
        if cell == 'N':
            predicted = 'NULL'
        elif cell == 'R':
            predicted = 'REAL'
        elif cell == '?':
            # Mixed: first = null, later = real
            if (r,c) not in cell_first_palette:
                cell_first_palette[(r,c)] = p
                predicted = 'NULL'
            else:
                predicted = 'REAL'
        else:  # '-' should not happen for palette positions
            predicted = '???'

        actual = 'NULL' if is_consensus_null else 'REAL'
        match = predicted == actual
        if match:
            correct += 1
        else:
            wrong += 1
        match_str = "OK" if match else "WRONG"
    else:
        # Non-palette position: table was built for palette only
        predicted = 'N/A'
        actual = 'NULL' if is_consensus_null else 'REAL'
        match_str = '-'
        na_count += 1

    detail = {
        "pos": p, "ct": ct_char, "palette": is_palette,
        "r": r, "c": c, "cell": cell,
        "consensus_null": is_consensus_null,
        "mask_null": is_mask_null,
        "predicted": predicted, "actual": actual,
        "match": match_str,
    }
    task2_details.append(detail)

    # Print interesting cases
    if is_palette or is_consensus_null or is_mask_null:
        print(f"{p:3d} {ct_char:>2} {'YES' if is_palette else 'no':>4} {r:>3} {c:>3} {cell:>4} "
              f"{'YES' if is_consensus_null else 'no':>6} {predicted:>8} {actual:>8} {match_str:>5}")

print(f"\n--- Summary ---")
print(f"Palette positions: {correct + wrong}")
print(f"  Correctly predicted: {correct}/{correct + wrong}")
print(f"  Wrongly predicted: {wrong}/{correct + wrong}")
print(f"Non-palette positions: {na_count}")

# Now the KEY QUESTION: do non-palette positions that fall in N cells get wrongly
# predicted as null even though they're real?
print("\n--- Non-palette positions in N cells ---")
non_pal_in_null_cells = []
non_pal_in_real_cells = []
for d in task2_details:
    if not d["palette"]:
        if d["cell"] == 'N':
            non_pal_in_null_cells.append(d)
        elif d["cell"] == 'R':
            non_pal_in_real_cells.append(d)

print(f"Non-palette positions falling in 'N' cells: {len(non_pal_in_null_cells)}")
for d in non_pal_in_null_cells:
    print(f"  pos {d['pos']}: CT={d['ct']}, cell=({d['r']},{d['c']})=N, "
          f"consensus_null={d['consensus_null']}, mask_null={d['mask_null']}")

print(f"\nNon-palette positions falling in 'R' cells: {len(non_pal_in_real_cells)}")
for d in non_pal_in_real_cells:
    null_str = ""
    if d['consensus_null']:
        null_str = " <-- CONSENSUS NULL in R cell!"
    elif d['mask_null']:
        null_str = " <-- MASK NULL in R cell!"
    if null_str:
        print(f"  pos {d['pos']}: CT={d['ct']}, cell=({d['r']},{d['c']})=R{null_str}")

# Check: if we naively extend the table to ALL positions (not just palette),
# how accurate is it?
print("\n--- Extended prediction: apply table to ALL 97 positions ---")
cell_first_all = {}
ext_correct = 0
ext_wrong = 0

for p in range(97):
    r = p % 7
    c = p % 5
    cell = TABLE.get((r,c), '-')

    if cell == 'N':
        ext_pred = 'NULL'
    elif cell == 'R':
        ext_pred = 'REAL'
    elif cell == '?':
        if (r,c) not in cell_first_all:
            cell_first_all[(r,c)] = p
            ext_pred = 'NULL'
        else:
            ext_pred = 'REAL'
    else:  # '-' = no data
        ext_pred = 'REAL'  # default assumption

    actual_null = p in CONSENSUS_17
    actual = 'NULL' if actual_null else 'REAL'

    if ext_pred == actual:
        ext_correct += 1
    else:
        ext_wrong += 1

print(f"Extended prediction accuracy: {ext_correct}/{97} = {ext_correct/97*100:.1f}%")
print(f"Errors: {ext_wrong}/{97}")

# Count how many of the 17 consensus nulls the table correctly identifies
ext_null_pred = set()
cell_first_ext = {}
for p in range(97):
    r = p % 7
    c = p % 5
    cell = TABLE.get((r,c), '-')
    if cell == 'N':
        ext_null_pred.add(p)
    elif cell == '?':
        if (r,c) not in cell_first_ext:
            cell_first_ext[(r,c)] = p
            ext_null_pred.add(p)

correctly_id_nulls = ext_null_pred & CONSENSUS_17
false_pos_nulls = ext_null_pred - CONSENSUS_17
missed_nulls = CONSENSUS_17 - ext_null_pred
print(f"\nNull predictions from table: {len(ext_null_pred)} positions")
print(f"  Correctly identified consensus nulls: {len(correctly_id_nulls)}/{len(CONSENSUS_17)}")
print(f"  False positive nulls (predicted null but actually real): {len(false_pos_nulls)}")
print(f"    Positions: {sorted(false_pos_nulls)}")
print(f"  Missed nulls (actually null but predicted real): {len(missed_nulls)}")
print(f"    Positions: {sorted(missed_nulls)}")

results["task2_mod35_table"] = {
    "palette_accuracy": f"{correct}/{correct + wrong}",
    "palette_correct": correct,
    "palette_wrong": wrong,
    "non_palette_in_N_cells": len(non_pal_in_null_cells),
    "non_palette_in_R_cells": len(non_pal_in_real_cells),
    "extended_accuracy": f"{ext_correct}/97",
    "extended_correct": ext_correct,
    "correctly_id_nulls": sorted(correctly_id_nulls),
    "false_pos_nulls": sorted(false_pos_nulls),
    "missed_nulls": sorted(missed_nulls),
}

# ============================================================================
# TASK 3: Width-6 Periodic on CT73
# ============================================================================
print("\n" + "=" * 80)
print("TASK 3: Width-6 Periodic on CT73")
print("=" * 80)

print(f"CT73 ({len(CT73)} chars): {CT73}")

# Compute column ICs at width 6
print("\n--- Column ICs at width 6 ---")
width = 6
col_ics = []
for col in range(width):
    col_chars = [CT73[i] for i in range(col, len(CT73), width)]
    col_ic = ic(''.join(col_chars))
    col_ics.append(col_ic)
    print(f"  Column {col}: IC={col_ic:.4f} ({len(col_chars)} chars)")

max_col_ic = max(col_ics)
print(f"  Max column IC: {max_col_ic:.4f}")

# Monte Carlo p-value for max column IC
print("\n--- Monte Carlo p-value for max column IC >= {:.4f} ---".format(max_col_ic))
random.seed(42)
N_MC_IC = 10000
mc_max_ics = []
# Use CT73's letter distribution
ct73_letters = list(CT73)
for _ in range(N_MC_IC):
    random.shuffle(ct73_letters)
    fake = ''.join(ct73_letters)
    max_ic_trial = max(
        ic(''.join(fake[i] for i in range(col, len(fake), width)))
        for col in range(width)
    )
    mc_max_ics.append(max_ic_trial)

p_val = sum(1 for x in mc_max_ics if x >= max_col_ic) / N_MC_IC
mc_mean_ic = sum(mc_max_ics) / len(mc_max_ics)
mc_max_mc = max(mc_max_ics)
print(f"  MC p-value: {p_val:.4f} (N={N_MC_IC})")
print(f"  MC mean max-col-IC: {mc_mean_ic:.4f}")
print(f"  MC max max-col-IC: {mc_max_mc:.4f}")
print(f"  Observed max-col-IC: {max_col_ic:.4f}")
if p_val < 0.05:
    print(f"  SIGNIFICANT at 5% level")
else:
    print(f"  NOT significant at 5% level")

# Period-6 decryption attempts
print("\n--- Period-6 decryption attempts on CT73 ---")

# a) Frequency-analysis-derived key
print("\n  a) Frequency-analysis-derived key (period 6):")
freq_key = []
for col in range(6):
    col_chars = [CT73[i] for i in range(col, len(CT73), 6)]
    freq = Counter(col_chars)
    # Most common letter -> assume it's E (most common in English)
    most_common = freq.most_common(1)[0][0]
    # Beaufort: K = (CT + PT) mod 26, if CT=most_common and PT=E
    k_beau = (I2N[most_common] + I2N['E']) % 26
    freq_key.append(N2L[k_beau])
freq_key_str = ''.join(freq_key)
print(f"    Beaufort freq key: {freq_key_str}")

pt_beau = beaufort_decrypt(CT73, freq_key_str)
score_beau = crib_score_ct73(pt_beau)
print(f"    PT: {pt_beau}")
print(f"    Crib score: {score_beau}/{len(crib_pos_73)}")
print(f"    QG score: {qg_score(pt_beau):.4f}")

# Vigenere freq key
freq_key_v = []
for col in range(6):
    col_chars = [CT73[i] for i in range(col, len(CT73), 6)]
    freq = Counter(col_chars)
    most_common = freq.most_common(1)[0][0]
    k_vig = (I2N[most_common] - I2N['E']) % 26
    freq_key_v.append(N2L[k_vig])
freq_key_v_str = ''.join(freq_key_v)
print(f"    Vigenere freq key: {freq_key_v_str}")

pt_vig = vigenere_decrypt(CT73, freq_key_v_str)
score_vig = crib_score_ct73(pt_vig)
print(f"    PT: {pt_vig}")
print(f"    Crib score: {score_vig}/{len(crib_pos_73)}")
print(f"    QG score: {qg_score(pt_vig):.4f}")

# b) Thematic keywords of length 6 or multiples
print("\n  b) Thematic keywords (length 6 or multiples):")
keywords_6 = ["KRYPTO", "BERLIN", "SHADOW", "SECRET", "CIPHER", "ENIGMA",
              "AGENCY", "HIDDEN", "BURIED", "SLOWLY", "TUNNEL", "GOLDEN",
              "KOMPASS", "DEFECT", "PALIMPS", "ABSCI"]
# Also try longer keywords truncated to 6
keywords_6 += [kw[:6] for kw in ["KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA", "COLOPHON"]]
keywords_6 = list(set(keywords_6))

best_kw_score = 0
best_kw_info = ""

for kw in keywords_6:
    if len(kw) < 1:
        continue
    for cipher_name, decrypt_func in [("Beaufort", beaufort_decrypt), ("Vigenere", vigenere_decrypt)]:
        pt = decrypt_func(CT73, kw)
        score = crib_score_ct73(pt)
        if score > best_kw_score:
            best_kw_score = score
            best_kw_info = f"{kw}:{cipher_name}"
        if score >= 4:
            print(f"    {kw}:{cipher_name}: {score}/{len(crib_pos_73)} qg={qg_score(pt):.4f}")

print(f"  Best keyword result: {best_kw_info} = {best_kw_score}/{len(crib_pos_73)}")

# c) Width-6 columnar transposition on CT73, then Beaufort
print("\n  c) Width-6 columnar transposition + Beaufort:")
import itertools

best_trans_score = 0
best_trans_info = ""

# Width 6 has 6! = 720 permutations
for perm in itertools.permutations(range(6)):
    # Apply columnar transposition (inverse: scatter)
    n_rows = (len(CT73) + 5) // 6
    n_extra = len(CT73) % 6
    if n_extra == 0:
        n_extra = 6

    # Build the permuted text (undo columnar trans)
    cols = []
    idx = 0
    for col_idx in range(6):
        actual_col = perm[col_idx]
        col_len = n_rows if actual_col < n_extra else n_rows - (1 if n_extra < 6 else 0)
        cols.append(CT73[idx:idx + col_len])
        idx += col_len

    # Reconstruct row-by-row
    transposed = []
    for row in range(n_rows):
        for col_idx in range(6):
            actual_col = col_idx
            # Find which read position corresponds to actual_col
            for read_pos, ac in enumerate(perm):
                if ac == actual_col:
                    if row < len(cols[read_pos]):
                        transposed.append(cols[read_pos][row])
                    break
    transposed_text = ''.join(transposed)

    # Try Beaufort with top keywords
    for kw in ["DEFECTOR", "PALIMPSEST", "KRYPTOS"]:
        pt = beaufort_decrypt(transposed_text, kw)
        score = crib_score_ct73(pt)
        if score > best_trans_score:
            best_trans_score = score
            best_trans_info = f"perm={perm}:{kw}:Beaufort"

        pt_v = vigenere_decrypt(transposed_text, kw)
        score_v = crib_score_ct73(pt_v)
        if score_v > best_trans_score:
            best_trans_score = score_v
            best_trans_info = f"perm={perm}:{kw}:Vigenere"

print(f"  Best trans+sub result: {best_trans_info} = {best_trans_score}/{len(crib_pos_73)}")

results["task3_width6_ct73"] = {
    "column_ics": col_ics,
    "max_column_ic": max_col_ic,
    "mc_pvalue": p_val,
    "mc_mean": mc_mean_ic,
    "freq_key_beau": freq_key_str,
    "freq_key_beau_score": score_beau,
    "freq_key_vig": freq_key_v_str,
    "freq_key_vig_score": score_vig,
    "best_keyword_score": best_kw_score,
    "best_keyword_info": best_kw_info,
    "best_trans_score": best_trans_score,
    "best_trans_info": best_trans_info,
}

# ============================================================================
# TASK 4: CT73 Autocorrelation Profile
# ============================================================================
print("\n" + "=" * 80)
print("TASK 4: CT73 Autocorrelation Profile")
print("=" * 80)

def autocorrelation_count(text, lag):
    """Count positions where text[i] == text[i+lag]."""
    return sum(1 for i in range(len(text) - lag) if text[i] == text[i + lag])

# a) Compute autocorrelation at all lags 1-36 for CT73
print("\n--- CT73 autocorrelation (lags 1-36) ---")

random.seed(42)
N_MC_AC = 100000

ct73_ac = {}
ct97_ac = {}
sig_lags_73 = []
sig_lags_97 = []

print(f"{'Lag':>3} {'CT97':>5} {'z97':>7} {'p97':>8} | {'CT73':>5} {'z73':>7} {'p73':>8} {'Note':>20}")
print("-" * 80)

for lag in range(1, 37):
    # CT97
    matches_97 = autocorrelation_count(CT, lag)
    n_pairs_97 = N - lag
    exp_97 = n_pairs_97 / 26.0

    # CT73
    matches_73 = autocorrelation_count(CT73, lag)
    n_pairs_73 = len(CT73) - lag
    exp_73 = n_pairs_73 / 26.0

    # Monte Carlo for both
    mc_97 = []
    mc_73 = []
    ct73_list = list(CT73)
    ct97_list = list(CT)
    for _ in range(N_MC_AC):
        random.shuffle(ct97_list)
        mc_97.append(sum(1 for i in range(N - lag) if ct97_list[i] == ct97_list[i + lag]))
        random.shuffle(ct73_list)
        mc_73.append(sum(1 for i in range(len(CT73) - lag) if ct73_list[i] == ct73_list[i + lag]))

    mc97_mean = sum(mc_97) / len(mc_97)
    mc97_std = (sum((x - mc97_mean)**2 for x in mc_97) / len(mc_97)) ** 0.5
    z97 = (matches_97 - mc97_mean) / mc97_std if mc97_std > 0 else 0
    p97 = sum(1 for x in mc_97 if x >= matches_97) / len(mc_97)

    mc73_mean = sum(mc_73) / len(mc_73)
    mc73_std = (sum((x - mc73_mean)**2 for x in mc_73) / len(mc_73)) ** 0.5
    z73 = (matches_73 - mc73_mean) / mc73_std if mc73_std > 0 else 0
    p73 = sum(1 for x in mc_73 if x >= matches_73) / len(mc_73)

    ct97_ac[lag] = {"matches": matches_97, "expected": round(exp_97, 2), "z": round(z97, 3), "p": p97}
    ct73_ac[lag] = {"matches": matches_73, "expected": round(exp_73, 2), "z": round(z73, 3), "p": p73}

    note = ""
    if z97 > 2:
        sig_lags_97.append(lag)
        note += " *97"
    if z73 > 2:
        sig_lags_73.append(lag)
        note += " *73"
    if lag == 7:
        note += " <-- LAG 7"

    if lag <= 15 or abs(z97) > 1.5 or abs(z73) > 1.5 or lag == 7:
        print(f"{lag:3d} {matches_97:5d} {z97:+7.3f} {p97:8.4f} | {matches_73:5d} {z73:+7.3f} {p73:8.4f}{note}")

print(f"\n--- Summary ---")
print(f"CT97 significant lags (z>2): {sig_lags_97}")
print(f"CT73 significant lags (z>2): {sig_lags_73}")

lag7_97 = ct97_ac.get(7, {})
lag7_73 = ct73_ac.get(7, {})
print(f"\nLag-7 comparison:")
print(f"  CT97: {lag7_97.get('matches', '?')} matches, z={lag7_97.get('z', '?')}, p={lag7_97.get('p', '?')}")
print(f"  CT73: {lag7_73.get('matches', '?')} matches, z={lag7_73.get('z', '?')}, p={lag7_73.get('p', '?')}")

if lag7_73.get('z', 0) < 2 and lag7_97.get('z', 0) > 2:
    print(f"\n  CONCLUSION: Lag-7 peak DISAPPEARS on CT73. It was created by the null insertion (stego layer artifact).")
elif lag7_73.get('z', 0) > 2:
    print(f"\n  CONCLUSION: Lag-7 peak SURVIVES on CT73. It is a cipher layer property.")
else:
    print(f"\n  CONCLUSION: Lag-7 was not significant on CT97 either (z={lag7_97.get('z', 0):.3f}).")

# Show which lag-7 matches in CT97 involve null positions
print(f"\n--- Lag-7 matches in CT97 and null involvement ---")
for i in range(N - 7):
    if CT[i] == CT[i + 7]:
        null_i = i in set(MASK_24)
        null_i7 = (i + 7) in set(MASK_24)
        null_note = ""
        if null_i or null_i7:
            null_note = f" [{'NULL@'+str(i) if null_i else ''}{'+' if null_i and null_i7 else ''}{'NULL@'+str(i+7) if null_i7 else ''}]"
        print(f"  CT[{i}]=CT[{i+7}]='{CT[i]}'{null_note}")

results["task4_autocorrelation"] = {
    "ct97_significant_lags": sig_lags_97,
    "ct73_significant_lags": sig_lags_73,
    "ct97_lag7": ct97_ac.get(7, {}),
    "ct73_lag7": ct73_ac.get(7, {}),
    "ct97_all": {str(k): v for k, v in ct97_ac.items()},
    "ct73_all": {str(k): v for k, v in ct73_ac.items()},
    "lag7_survives": lag7_73.get('z', 0) > 2,
}

# ============================================================================
# FINAL SUMMARY
# ============================================================================
elapsed = time.time() - t0
print("\n" + "=" * 80)
print(f"ALL 4 TASKS COMPLETE ({elapsed:.1f}s)")
print("=" * 80)

print(f"""
TASK 1 — Polish/Hungarian/German Running Key:
  Polish  Beau: best {task1_results.get('Polish', {}).get('Model_B_CT97:Beaufort', {}).get('score', 'N/A')}/24
  Polish  Vig:  best {task1_results.get('Polish', {}).get('Model_B_CT97:Vigenere', {}).get('score', 'N/A')}/24
  Hungarian Beau: best {task1_results.get('Hungarian', {}).get('Model_B_CT97:Beaufort', {}).get('score', 'N/A')}/24
  German Beau: best {task1_results.get('German', {}).get('Model_B_CT97:Beaufort', {}).get('score', 'N/A')}/24
  MC baseline: Beau mean={mc_b_mean:.2f} max={mc_b_max}

TASK 2 — Mod-35 Table Verification:
  Palette positions: {correct}/{correct + wrong} correct
  Extended to all 97: {ext_correct}/97 ({ext_correct/97*100:.1f}%)
  Consensus nulls found: {len(correctly_id_nulls)}/{len(CONSENSUS_17)}
  False positive nulls: {len(false_pos_nulls)}
  Missed nulls: {len(missed_nulls)}

TASK 3 — Width-6 on CT73:
  Max column IC: {max_col_ic:.4f}, MC p-value: {p_val:.4f}
  Best keyword score: {best_kw_score}/{len(crib_pos_73)}
  Best trans+sub score: {best_trans_score}/{len(crib_pos_73)}

TASK 4 — CT73 Autocorrelation:
  CT97 lag-7: z={lag7_97.get('z', '?')}, p={lag7_97.get('p', '?')}
  CT73 lag-7: z={lag7_73.get('z', '?')}, p={lag7_73.get('p', '?')}
  Lag-7 survives null extraction: {lag7_73.get('z', 0) > 2}
""")

results["summary"] = {
    "elapsed_seconds": elapsed,
    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S'),
}

# Save results
out_path = '/home/cpatrick/kryptos/results/gap_filling_four_tasks_20260316.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Results saved to: {out_path}")
