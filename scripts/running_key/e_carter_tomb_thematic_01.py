#!/usr/bin/env python3
"""
E-CARTER-TOMB-THEMATIC-01: Thematic Carter passage analysis for K4 running key

Tests specific passages, chapters, and thematic keywords from Carter's
"Tomb of Tut-Ankh-Amen" Vol 1 as K4 key sources.

Phases:
  1. Extract all chapters, report titles and char counts
  2. Chapter X as standalone running key (all offsets, Vig/Beau/VarBeau)
  3. Famous passages as running keys (direct + cycled)
  4. Passage-as-keyword periodic Vigenere/Beaufort
  5. Key letter analysis at K3 source offset

Family: running_key
Status: active
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json, re
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.text import sanitize

# Corpus policy declaration — Carter Vol 1 (allowlisted as `carter_tomb_vol1`).
SOURCE_ID = "carter_tomb_vol1"

# ── Helpers ──────────────────────────────────────────────────────────────

def alpha_only(text):
    """Strip to uppercase alpha only."""
    return re.sub(r'[^A-Za-z]', '', text).upper()

def load_carter():
    path = os.path.join(_ROOT, "reference", "carter_vol1.txt")
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def decrypt_vig(ct, key):
    """Vigenere decrypt: PT = (CT - KEY) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if len(key) <= len(ct) else key[i]
        pt.append(chr((ord(c) - ord(k)) % 26 + ord('A')))
    return ''.join(pt)

def decrypt_beau(ct, key):
    """Beaufort decrypt: PT = (KEY - CT) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if len(key) <= len(ct) else key[i]
        pt.append(chr((ord(k) - ord(c)) % 26 + ord('A')))
    return ''.join(pt)

def decrypt_var_beau(ct, key):
    """Variant Beaufort decrypt: PT = (CT + KEY) mod 26 (= encrypt direction swap)"""
    # Variant Beaufort: K = (PT - CT) mod 26, so PT = (K + CT) mod 26
    pt = []
    for i, c in enumerate(ct):
        k = key[i % len(key)] if len(key) <= len(ct) else key[i]
        pt.append(chr((ord(k) + ord(c) - 2*ord('A')) % 26 + ord('A')))
    return ''.join(pt)

def running_key_decrypt(ct, key_text, variant='vigenere'):
    """Decrypt using running key (key_text must be >= len(ct))."""
    n = len(ct)
    if len(key_text) < n:
        return None
    key = key_text[:n]
    if variant == 'vigenere':
        return decrypt_vig(ct, key)
    elif variant == 'beaufort':
        return decrypt_beau(ct, key)
    elif variant == 'var_beaufort':
        return decrypt_var_beau(ct, key)

def cycled_key(key_text, length):
    """Repeat key_text to fill length."""
    if len(key_text) == 0:
        return ''
    reps = (length // len(key_text)) + 1
    return (key_text * reps)[:length]

def score_pt(pt):
    """Score plaintext using score_candidate (anchored cribs)."""
    result = score_candidate(pt)
    return result.crib_score

def extract_key_values(ct, pt, variant='vigenere'):
    """Extract key values from CT/PT pair."""
    keys = []
    for i in range(len(ct)):
        c = ord(ct[i]) - ord('A')
        p = ord(pt[i]) - ord('A')
        if variant == 'vigenere':
            k = (c - p) % 26
        elif variant == 'beaufort':
            k = (c + p) % 26
        else:  # var_beaufort
            k = (p - c) % 26
        keys.append(k)
    return keys

# ── Phase 1: Extract chapters ───────────────────────────────────────────

def phase1_extract_chapters(raw_text):
    print("=" * 70)
    print("PHASE 1: Extract all chapters")
    print("=" * 70)

    lines = raw_text.split('\n')

    # Find chapter boundaries
    chapter_starts = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r'^CHAPTER\s+(I{1,3}|IV|V|VI{0,3}|IX|X|XI{0,3})\s*$', stripped):
            chapter_starts.append(i)

    # Also catch "CHAPTER" alone as TOC header (skip it)
    # We want actual chapter starts with roman numerals

    chapters = {}
    for idx, start_line in enumerate(chapter_starts):
        # Get chapter number and title
        ch_num_line = lines[start_line].strip()
        # Title is typically the next non-empty line
        title = ""
        for j in range(start_line + 1, min(start_line + 5, len(lines))):
            if lines[j].strip():
                title = lines[j].strip()
                break

        # End is either next chapter or end of text
        if idx + 1 < len(chapter_starts):
            end_line = chapter_starts[idx + 1]
        else:
            end_line = len(lines)

        chapter_text = '\n'.join(lines[start_line:end_line])
        chapter_alpha = alpha_only(chapter_text)

        chapters[ch_num_line] = {
            'title': title,
            'start_line': start_line + 1,  # 1-indexed for display
            'end_line': end_line,
            'raw_length': len(chapter_text),
            'alpha_length': len(chapter_alpha),
            'alpha_text': chapter_alpha,
            'first_sentence_raw': '',
        }

        # Extract first sentence (up to first period after chapter heading)
        body_start = start_line + 3  # skip chapter header and title
        first_sent = []
        for j in range(body_start, min(body_start + 20, len(lines))):
            first_sent.append(lines[j])
            if '.' in lines[j]:
                break
        chapters[ch_num_line]['first_sentence_raw'] = ' '.join(first_sent).strip()

        print(f"  {ch_num_line}: {title}")
        print(f"    Lines {start_line+1}-{end_line}, alpha chars: {len(chapter_alpha)}")

    return chapters

# ── Phase 2: Chapter X running key ──────────────────────────────────────

def phase2_chapter_x(chapters):
    print("\n" + "=" * 70)
    print("PHASE 2: Chapter X as standalone running key")
    print("=" * 70)

    ch_x = None
    for key in chapters:
        if 'X' in key and 'XI' not in key:
            ch_x = chapters[key]
            break

    if ch_x is None:
        print("  ERROR: Chapter X not found!")
        return {}

    ch_text = ch_x['alpha_text']
    print(f"  Chapter X alpha length: {len(ch_text)}")
    print(f"  Max offsets to test: {len(ch_text) - len(CT)}")

    results = {'best_per_variant': {}, 'hits_ge_6': [], 'hits_ge_8': []}
    variants = ['vigenere', 'beaufort', 'var_beaufort']

    for variant in variants:
        best_score = 0
        best_offset = -1
        best_pt = ""
        max_offset = len(ch_text) - len(CT)

        for offset in range(max_offset + 1):
            key = ch_text[offset:offset + len(CT)]
            pt = running_key_decrypt(CT, key, variant)
            if pt is None:
                continue
            sc = score_pt(pt)
            if sc > best_score:
                best_score = sc
                best_offset = offset
                best_pt = pt
            if sc >= 6:
                results['hits_ge_6'].append({
                    'variant': variant, 'offset': offset,
                    'score': sc, 'pt': pt[:40]
                })
            if sc >= 8:
                results['hits_ge_8'].append({
                    'variant': variant, 'offset': offset,
                    'score': sc, 'pt': pt[:40]
                })

        results['best_per_variant'][variant] = {
            'score': best_score, 'offset': best_offset, 'pt': best_pt[:50]
        }
        print(f"  {variant}: best {best_score}/24 at offset {best_offset}")
        if best_score > 0:
            print(f"    PT: {best_pt[:60]}")

    print(f"  Hits >= 6: {len(results['hits_ge_6'])}")
    print(f"  Hits >= 8: {len(results['hits_ge_8'])}")
    return results

# ── Phase 3: Famous passages as running keys ────────────────────────────

def phase3_famous_passages(raw_text):
    print("\n" + "=" * 70)
    print("PHASE 3: Famous passages as running keys")
    print("=" * 70)

    lines = raw_text.split('\n')

    # (a) "Slowly desperately slowly..." passage (K3 source area)
    slowly_lines = []
    for i, line in enumerate(lines):
        if 'Slowly' in line and 'desperately' in line:
            # Grab from here to "electric torch"
            for j in range(i, min(i + 40, len(lines))):
                slowly_lines.append(lines[j])
                if 'electric' in lines[j] and 'torch' in lines[j]:
                    break
            break
    slowly_text = alpha_only(' '.join(slowly_lines))

    # (b) "Can you see anything? Yes wonderful things"
    can_you_see = alpha_only("Can you see anything Yes wonderful things")

    # (c) Dedication
    ded_lines = []
    for i, line in enumerate(lines):
        if 'full  sympathy' in line.lower() or 'full sympathy' in line.lower():
            for j in range(i, min(i + 15, len(lines))):
                ded_lines.append(lines[j])
                if 'triumph' in lines[j].lower():
                    break
            break
    dedication_text = alpha_only(' '.join(ded_lines))

    # (d) First sentence of each chapter — collected in phase 1
    # We'll pass these separately

    # (e) Bead-work passage from Chapter X
    bead_lines = []
    for i, line in enumerate(lines):
        if 'Bead-work  is  in  itself' in line or 'Beadwork is in itself' in line:
            for j in range(i, min(i + 80, len(lines))):
                bead_lines.append(lines[j])
                if 'archaeological  value' in lines[j] or 'archaeological value' in lines[j]:
                    break
            break
    beadwork_text = alpha_only(' '.join(bead_lines))

    passages = {
        'slowly_desperately': slowly_text,
        'can_you_see': can_you_see,
        'dedication': dedication_text,
        'beadwork': beadwork_text,
    }

    results = {}
    variants = ['vigenere', 'beaufort', 'var_beaufort']

    for name, passage in passages.items():
        print(f"\n  Passage: {name} ({len(passage)} alpha chars)")
        print(f"    Text: {passage[:80]}...")

        results[name] = {'length': len(passage), 'direct': {}, 'cycled': {}}

        for variant in variants:
            # Direct (if long enough)
            if len(passage) >= len(CT):
                max_offset = len(passage) - len(CT)
                best_sc = 0
                best_off = -1
                best_pt = ""
                for offset in range(max_offset + 1):
                    key = passage[offset:offset + len(CT)]
                    pt = running_key_decrypt(CT, key, variant)
                    if pt is None:
                        continue
                    sc = score_pt(pt)
                    if sc > best_sc:
                        best_sc = sc
                        best_off = offset
                        best_pt = pt
                results[name]['direct'][variant] = {
                    'best_score': best_sc, 'best_offset': best_off,
                    'pt': best_pt[:50]
                }
                print(f"    {variant} direct: best {best_sc}/24 at offset {best_off}")
            else:
                results[name]['direct'][variant] = {'best_score': 0, 'note': 'too_short'}
                print(f"    {variant} direct: passage too short ({len(passage)} < {len(CT)})")

            # Cycled
            key = cycled_key(passage, len(CT))
            pt = running_key_decrypt(CT, key, variant)
            sc = score_pt(pt)
            results[name]['cycled'][variant] = {'score': sc, 'pt': pt[:50]}
            tag = " ***" if sc >= 8 else ""
            print(f"    {variant} cycled: {sc}/24{tag}")

    return results

# ── Phase 4: Passage-as-keyword periodic Vigenere/Beaufort ──────────────

def phase4_keyword_test(chapters):
    print("\n" + "=" * 70)
    print("PHASE 4: Thematic keywords as periodic Vigenere/Beaufort keys")
    print("=" * 70)

    keywords = {
        'TUTANKHAMEN': 'TUTANKHAMEN',
        'TUTANKHAMUN': 'TUTANKHAMUN',
        'TUTANKHAMON': 'TUTANKHAMON',
        'WONDERFULTHINGS': 'WONDERFULTHINGS',
        'CARNARVON': 'CARNARVON',
        'HOWARDCARTER': 'HOWARDCARTER',
        'VALLEYOFTHEKINGS': 'VALLEYOFTHEKINGS',
        'ANTECHAMBER': 'ANTECHAMBER',
        'CANDLE': 'CANDLE',
        'SLOWLY': 'SLOWLY',
        'DESPERATELY': 'DESPERATELY',
    }

    # Add chapter titles as keywords
    for ch_key, ch_data in chapters.items():
        title_alpha = alpha_only(ch_data['title'])
        if title_alpha:
            kw_name = f"CH_{ch_key.replace(' ', '_')}_{title_alpha[:20]}"
            keywords[kw_name] = title_alpha

    # Also add first sentences
    for ch_key, ch_data in chapters.items():
        fs_alpha = alpha_only(ch_data['first_sentence_raw'])
        if fs_alpha and len(fs_alpha) > 5:
            kw_name = f"FS_{ch_key.replace(' ', '_')}"
            keywords[kw_name] = fs_alpha

    results = {}
    hits_ge_8 = []

    for name, kw in sorted(keywords.items()):
        key = cycled_key(kw, len(CT))
        row = {'keyword': kw, 'length': len(kw)}

        for variant in ['vigenere', 'beaufort', 'var_beaufort']:
            pt = running_key_decrypt(CT, key, variant)
            sc = score_pt(pt)
            row[f'{variant}_score'] = sc
            row[f'{variant}_pt'] = pt[:50]

            if sc >= 8:
                hits_ge_8.append({
                    'name': name, 'keyword': kw, 'variant': variant,
                    'score': sc, 'pt': pt[:60]
                })

        best_v = max(row.get('vigenere_score', 0),
                     row.get('beaufort_score', 0),
                     row.get('var_beaufort_score', 0))
        results[name] = row

        if best_v >= 6:
            print(f"  {name} ({kw[:30]}): V={row['vigenere_score']} "
                  f"B={row['beaufort_score']} VB={row['var_beaufort_score']} ***")
        elif best_v >= 4:
            print(f"  {name} ({kw[:30]}): V={row['vigenere_score']} "
                  f"B={row['beaufort_score']} VB={row['var_beaufort_score']}")

    print(f"\n  Total keywords tested: {len(keywords)}")
    print(f"  Hits >= 8: {len(hits_ge_8)}")
    for h in hits_ge_8:
        print(f"    {h['name']}/{h['variant']}: {h['score']}/24  PT={h['pt']}")

    return {'results': results, 'hits_ge_8': hits_ge_8}

# ── Phase 5: Key letter analysis at K3 source offset ────────────────────

def phase5_k3_key_analysis(raw_text):
    print("\n" + "=" * 70)
    print("PHASE 5: Key letter analysis at K3 source offset")
    print("=" * 70)

    full_alpha = alpha_only(raw_text)
    print(f"  Full alpha text length: {len(full_alpha)}")

    # The K3 source passage: "SLOWLY DESPERATELY SLOWLY..."
    # Find it in the alpha stream
    target = alpha_only("SLOWLYDESPERATELYSLOWLYITSEEMEDTOUSASWEWATCHED")
    pos = full_alpha.find(target)
    if pos == -1:
        # Try shorter
        target = alpha_only("SLOWLYDESPERATELYSLOWLY")
        pos = full_alpha.find(target)

    if pos == -1:
        print("  WARNING: Could not find K3 source passage in alpha text")
        # Try to find approximate location
        for test_pos in range(140000, 150000):
            if full_alpha[test_pos:test_pos+10] == alpha_only("SLOWLYDESP"):
                pos = test_pos
                break

    if pos == -1:
        print("  ERROR: K3 source passage not found!")
        return {}

    print(f"  K3 source passage found at alpha position: {pos}")
    print(f"  Context: ...{full_alpha[pos:pos+60]}...")

    # At this offset, extract the 97 key values for each variant
    key_text = full_alpha[pos:pos + len(CT)]
    if len(key_text) < len(CT):
        print(f"  ERROR: Not enough text ({len(key_text)} < {len(CT)})")
        return {}

    print(f"  Key text (97 chars): {key_text}")

    analysis = {}
    for variant in ['vigenere', 'beaufort', 'var_beaufort']:
        key_vals = extract_key_values(CT, key_text, variant)

        # Check for arithmetic progressions
        diffs = [key_vals[i+1] - key_vals[i] for i in range(len(key_vals)-1)]
        constant_runs = []
        run_start = 0
        for i in range(1, len(diffs)):
            if diffs[i] != diffs[i-1]:
                if i - run_start >= 3:
                    constant_runs.append({
                        'start': run_start, 'length': i - run_start + 1,
                        'diff': diffs[run_start],
                        'values': key_vals[run_start:i+1]
                    })
                run_start = i
        if len(diffs) - run_start >= 3:
            constant_runs.append({
                'start': run_start, 'length': len(diffs) - run_start + 1,
                'diff': diffs[run_start],
                'values': key_vals[run_start:]
            })

        # Check for repeated values
        from collections import Counter
        val_counts = Counter(key_vals)
        most_common = val_counts.most_common(5)

        # Check periodicity
        period_scores = {}
        for p in range(2, 26):
            match_count = 0
            total = 0
            for i in range(len(key_vals)):
                if i + p < len(key_vals):
                    total += 1
                    if key_vals[i] == key_vals[i+p]:
                        match_count += 1
            period_scores[p] = match_count / total if total > 0 else 0

        # Key as letters
        key_letters = ''.join(chr(v + ord('A')) for v in key_vals)

        analysis[variant] = {
            'key_values': key_vals,
            'key_letters': key_letters,
            'constant_diff_runs': constant_runs,
            'value_frequencies': dict(most_common),
            'period_scores': {p: round(s, 4) for p, s in sorted(period_scores.items())
                             if s > 0.06},  # > random expectation ~0.038
            'unique_values': len(set(key_vals)),
            'mean': sum(key_vals) / len(key_vals),
        }

        # Also decrypt and score
        pt = running_key_decrypt(CT, key_text, variant)
        sc = score_pt(pt)

        print(f"\n  {variant}:")
        print(f"    Key letters: {key_letters}")
        print(f"    PT: {pt[:60]}")
        print(f"    Score: {sc}/24")
        print(f"    Unique key values: {len(set(key_vals))}/26")
        print(f"    Most common: {most_common[:3]}")
        if constant_runs:
            print(f"    Arithmetic progressions (len>=4): {len(constant_runs)}")
            for run in constant_runs[:3]:
                print(f"      pos {run['start']}, len {run['length']}, diff {run['diff']}")
        notable_periods = {p: s for p, s in period_scores.items() if s > 0.06}
        if notable_periods:
            print(f"    Notable periodicities: {notable_periods}")

    return analysis

# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print(f"E-CARTER-TOMB-THEMATIC-01")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"CT: {CT}")
    print(f"CT length: {len(CT)}")

    raw_text = load_carter()
    print(f"Carter text loaded: {len(raw_text)} chars, {len(raw_text.splitlines())} lines")

    # Phase 1
    chapters = phase1_extract_chapters(raw_text)

    # Phase 2
    ch_x_results = phase2_chapter_x(chapters)

    # Phase 3
    passage_results = phase3_famous_passages(raw_text)

    # Phase 4
    keyword_results = phase4_keyword_test(chapters)

    # Phase 5
    k3_analysis = phase5_k3_key_analysis(raw_text)

    # ── Summary ──────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Compile all results
    output = {
        'experiment': 'E-CARTER-TOMB-THEMATIC-01',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'ciphertext': CT,
        'phase1_chapters': {
            k: {'title': v['title'], 'alpha_length': v['alpha_length'],
                 'start_line': v['start_line']}
            for k, v in chapters.items()
        },
        'phase2_chapter_x': ch_x_results,
        'phase3_passages': {
            k: {'length': v['length'],
                 'direct': v['direct'],
                 'cycled': v['cycled']}
            for k, v in passage_results.items()
        },
        'phase4_keywords': keyword_results,
        'phase5_k3_key_analysis': k3_analysis,
        'verdict': 'TBD'
    }

    # Determine verdict
    all_scores = []
    # Phase 2
    for v, d in ch_x_results.get('best_per_variant', {}).items():
        all_scores.append(d.get('score', 0))
    # Phase 3
    for name, data in passage_results.items():
        for v, d in data.get('direct', {}).items():
            all_scores.append(d.get('best_score', 0))
        for v, d in data.get('cycled', {}).items():
            all_scores.append(d.get('score', 0))
    # Phase 4
    for name, row in keyword_results.get('results', {}).items():
        for v in ['vigenere', 'beaufort', 'var_beaufort']:
            all_scores.append(row.get(f'{v}_score', 0))

    max_score = max(all_scores) if all_scores else 0
    hits_ge_8 = len(keyword_results.get('hits_ge_8', []))
    hits_ge_8 += len(ch_x_results.get('hits_ge_8', []))

    if max_score >= 10:
        output['verdict'] = 'INTERESTING'
    elif max_score >= 8:
        output['verdict'] = 'MARGINAL'
    else:
        output['verdict'] = 'NOISE'

    print(f"  Max score across all phases: {max_score}/24")
    print(f"  Hits >= 8: {hits_ge_8}")
    print(f"  Verdict: {output['verdict']}")

    # Save
    out_path = os.path.join(_ROOT, "results", "e_carter_tomb_thematic_01.json")
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Results saved to: {out_path}")

if __name__ == '__main__':
    main()
