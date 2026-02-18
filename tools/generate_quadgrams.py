#!/usr/bin/env python3
import json, math, os, re, sys, urllib.request, urllib.error
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = Path(os.getenv("K4_BASE_DIR", str(REPO_ROOT)))

REFERENCE = BASE_DIR / "reference"
WORDLISTS = BASE_DIR / "wordlists"
DATA = BASE_DIR / "data"

INPUT_FILES = [
    BASE_DIR / "reference" / "carter_gutenberg.txt",
    BASE_DIR / "reference" / "carter_text_cache.txt",
    BASE_DIR / "reference" / "carter_vol1.txt",
    BASE_DIR / "reference" / "running_key_texts" / "cia_charter.txt",
    BASE_DIR / "reference" / "running_key_texts" / "jfk_berlin.txt",
    BASE_DIR / "reference" / "running_key_texts" / "nsa_act_1947.txt",
    BASE_DIR / "reference" / "running_key_texts" / "reagan_berlin.txt",
    BASE_DIR / "reference" / "running_key_texts" / "udhr.txt",
    BASE_DIR / "reference" / "sanborn_correspondence.md",
    BASE_DIR / "reference" / "smithsonian_archive.md",
    BASE_DIR / "reference" / "youtube_transcript.md",
    BASE_DIR / "wordlists" / "english.txt",
]
OUTPUT_PATH = BASE_DIR / "data" / "english_quadgrams.json"





GUTENBERG_URLS = [
    'https://www.gutenberg.org/cache/epub/2600/pg2600.txt',
    'https://www.gutenberg.org/cache/epub/2701/pg2701.txt',
    'https://www.gutenberg.org/cache/epub/1342/pg1342.txt',
    'https://www.gutenberg.org/cache/epub/1400/pg1400.txt',
    'https://www.gutenberg.org/cache/epub/98/pg98.txt',
    'https://www.gutenberg.org/cache/epub/1661/pg1661.txt',
    'https://www.gutenberg.org/cache/epub/1184/pg1184.txt',
    'https://www.gutenberg.org/cache/epub/135/pg135.txt',
    'https://www.gutenberg.org/cache/epub/766/pg766.txt',
    'https://www.gutenberg.org/cache/epub/4300/pg4300.txt',
    'https://www.gutenberg.org/cache/epub/84/pg84.txt',
    'https://www.gutenberg.org/cache/epub/345/pg345.txt',
    'https://www.gutenberg.org/cache/epub/1260/pg1260.txt',
    'https://www.gutenberg.org/cache/epub/1399/pg1399.txt',
    'https://www.gutenberg.org/cache/epub/6130/pg6130.txt',
    'https://www.gutenberg.org/cache/epub/1727/pg1727.txt',
    'https://www.gutenberg.org/cache/epub/996/pg996.txt',
    'https://www.gutenberg.org/cache/epub/145/pg145.txt',
    'https://www.gutenberg.org/cache/epub/158/pg158.txt',
    'https://www.gutenberg.org/cache/epub/768/pg768.txt',
]

LOCAL_TEXT_FILES = [
    '/home/cpatrick/kryptos/reference/carter_gutenberg.txt',
    '/home/cpatrick/kryptos/reference/carter_text_cache.txt',
    '/home/cpatrick/kryptos/reference/carter_vol1.txt',
    '/home/cpatrick/kryptos/reference/running_key_texts/cia_charter.txt',
    '/home/cpatrick/kryptos/reference/running_key_texts/jfk_berlin.txt',
    '/home/cpatrick/kryptos/reference/running_key_texts/nsa_act_1947.txt',
    '/home/cpatrick/kryptos/reference/running_key_texts/reagan_berlin.txt',
    '/home/cpatrick/kryptos/reference/running_key_texts/udhr.txt',
    '/home/cpatrick/kryptos/reference/sanborn_correspondence.md',
    '/home/cpatrick/kryptos/reference/smithsonian_archive.md',
    '/home/cpatrick/kryptos/reference/youtube_transcript.md',
    '/home/cpatrick/kryptos/wordlists/english.txt',
]

OUTPUT_PATH = Path('/home/cpatrick/kryptos/data/english_quadgrams.json')
ALPHA_RE = re.compile(r'[^A-Z]')

def sanitize(text):
    return ALPHA_RE.sub('', text.upper())

def download_text(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'QuadgramBuilder/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return raw.decode('latin-1')
    except Exception as e:
        sys.stderr.write('  WARN: failed ' + url + ': ' + str(e) + '\n')
        return ''

def read_local(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        sys.stderr.write('  WARN: failed ' + path + ': ' + str(e) + '\n')
        return ''

def count_qg(text, ctr):
    clean = sanitize(text)
    n = len(clean)
    added = 0
    for i in range(n - 3):
        ctr[clean[i:i+4]] += 1
        added += 1
    return added, len(clean)

def main():
    print('=== English Quadgram Generator ===')
    ctr = Counter()
    dl_chars = 0

    print('Phase 1: Downloading %d texts from Project Gutenberg...' % len(GUTENBERG_URLS))
    for i, url in enumerate(GUTENBERG_URLS, 1):
        short = url.split('/')[-1]
        sys.stdout.write('  [%d/%d] %s... ' % (i, len(GUTENBERG_URLS), short))
        sys.stdout.flush()
        text = download_text(url, timeout=30)
        if text:
            added, clen = count_qg(text, ctr)
            dl_chars += clen
            print('OK (%s alpha chars, %s quadgrams)' % (format(clen, ','), format(added, ',')))
        else:
            print('FAILED')
    print('  Downloaded total: %s alpha chars' % format(dl_chars, ','))
    print()

    print('Phase 2: Adding local text files...')
    for path in LOCAL_TEXT_FILES:
        if os.path.exists(path):
            text = read_local(path)
            if text:
                added, clen = count_qg(text, ctr)
                print('  %s: %s alpha chars' % (os.path.basename(path), format(clen, ',')))
    print()

    unique_qg = len(ctr)
    total_count = sum(ctr.values())
    print('Total quadgrams counted: %s' % format(total_count, ','))
    print('Unique quadgrams: %s' % format(unique_qg, ','))

    if total_count == 0:
        sys.stderr.write('ERROR: No quadgrams counted.\n')
        sys.exit(1)

    max_possible = 26 ** 4
    coverage = unique_qg / max_possible * 100
    print('Coverage: %d/%d (%.1f%%)' % (unique_qg, max_possible, coverage))

    print()
    print('Applying Laplace smoothing (add-1) to all %s possible quadgrams...' % format(max_possible, ','))
    smoothed_total = total_count + max_possible
    result = {}
    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    qg = chr(65+a) + chr(65+b) + chr(65+c) + chr(65+d)
                    c_val = ctr.get(qg, 0) + 1
                    result[qg] = round(math.log10(c_val / smoothed_total), 6)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    print()
    print('Writing %s entries to %s...' % (format(len(result), ','), OUTPUT_PATH))
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(result, f, separators=(',', ':'))

    file_size = OUTPUT_PATH.stat().st_size
    print('Done! File size: %s bytes (%.1f MB)' % (format(file_size, ','), file_size / 1024 / 1024))

    print()
    print('=== Sanity Checks ===')
    top_20 = ctr.most_common(20)
    print('Top 20 quadgrams by raw count:')
    for qg, cnt in top_20:
        logp = result.get(qg, 'N/A')
        print('  %s: count=%s, log10(p)=%s' % (qg, format(cnt, ','), logp))

    for qg in ['TION', 'THER', 'THAT', 'MENT', 'WITH', 'HAVE', 'FROM']:
        logp = result.get(qg, 'N/A')
        raw = ctr.get(qg, 0)
        print('  %s: count=%s, log10(p)=%s' % (qg, format(raw, ','), logp))

    total_entries = len(result)
    if total_entries >= 100000:
        print()
        print('SUCCESS: %s entries (>= 100,000 required)' % format(total_entries, ','))
    else:
        print()
        print('WARNING: Only %s entries (< 100,000 required)' % format(total_entries, ','))
        sys.exit(1)

    print()
    print('Output: %s' % OUTPUT_PATH)

if __name__ == '__main__':
    main()
