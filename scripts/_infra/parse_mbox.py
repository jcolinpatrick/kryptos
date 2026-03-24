#!/usr/bin/env python3
"""Parse kryptos.groups.io mbox and extract K4-relevant substantive posts.

Outputs JSON with structured message data, pre-filtered for:
- K4 relevance (mentions K4, part 4, fourth, section 4, or general cipher discussion)
- Substantive content (>100 chars of body text, not just quotes/signatures)
- Deduplication (by message-id)

Usage:
    python3 scripts/_infra/parse_mbox.py reference/messages.mbox > reference/k4_posts.jsonl
"""

import mailbox
import email
import json
import re
import sys
import html
from email.utils import parsedate_to_datetime
from datetime import timezone

MBOX_PATH = sys.argv[1] if len(sys.argv) > 1 else "reference/messages.mbox"

# Keywords that indicate K4-relevant discussion
K4_KEYWORDS = re.compile(
    r'\b(k[\-_\s]?4|part\s*4|fourth\s*(part|section|passage|panel)|'
    r'unsolved|97\s*char|cipher|decrypt|encrypt|plaintext|ciphertext|'
    r'vigen[eè]re|beaufort|transpos|substitu|polyalpha|grille|'
    r'autokey|running.?key|columnar|bifid|playfair|hill\s*cipher|'
    r'fractionat|null\s*(insert|mask|char)|stegan|'
    r'sanborn|scheidt|gillogly|stein|elonka|'
    r'berlin\s*clock|east\s*north|northeast|longitude|latitude|'
    r'palimpsest|abscissa|defector|shadow|'
    r'morse|polybius|tableau|alphabet|keyword|'
    r'quadgram|bigram|frequency|index\s*of\s*coincidence|kasiski|'
    r'period|keystream|key\s*length|'
    r'sculpture|cia|langley|courtyard)\b',
    re.IGNORECASE
)

# Patterns to strip from body text
QUOTE_LINE = re.compile(r'^[>\|].*$', re.MULTILINE)
SIG_MARKER = re.compile(r'^-- ?\n.*', re.DOTALL | re.MULTILINE)
YAHOO_FOOTER = re.compile(r'Yahoo!\s*Groups.*$', re.DOTALL | re.IGNORECASE)
GROUPS_FOOTER = re.compile(r'-{3,}\n.*groups\.io.*$', re.DOTALL | re.IGNORECASE)
URL_PATTERN = re.compile(r'https?://\S+')

def clean_body(raw):
    """Strip quotes, signatures, footers, and HTML tags."""
    if not raw:
        return ""
    # Decode if bytes
    if isinstance(raw, bytes):
        for enc in ('utf-8', 'latin-1', 'cp1252'):
            try:
                raw = raw.decode(enc)
                break
            except (UnicodeDecodeError, AttributeError):
                continue
        else:
            return ""
    # Strip HTML tags if present
    if '<html' in raw.lower() or '<div' in raw.lower():
        raw = re.sub(r'<[^>]+>', ' ', raw)
        raw = html.unescape(raw)
    # Remove footers
    raw = YAHOO_FOOTER.sub('', raw)
    raw = GROUPS_FOOTER.sub('', raw)
    # Remove signature
    raw = SIG_MARKER.sub('', raw)
    # Remove quoted lines
    raw = QUOTE_LINE.sub('', raw)
    # Collapse whitespace
    raw = re.sub(r'\n{3,}', '\n\n', raw)
    raw = re.sub(r'[ \t]+', ' ', raw)
    return raw.strip()


def extract_body(msg):
    """Get plain text body from message."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    return clean_body(payload)
            elif ct == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    return clean_body(payload)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return clean_body(payload)
    return ""


def categorize_post(subject, body):
    """Categorize what type of hypothesis/discussion this is."""
    text = (subject or "") + " " + body
    text_lower = text.lower()

    categories = []

    if re.search(r'transpos|columnar|rail.?fence|route|spiral|grille|fleissner|permut', text_lower):
        categories.append("transposition")
    if re.search(r'substitu|vigen|beaufort|caesar|mono|poly|affine|porta|gronsfeld', text_lower):
        categories.append("substitution")
    if re.search(r'autokey|running.?key|book\s*cipher', text_lower):
        categories.append("autokey_or_running_key")
    if re.search(r'null|stegan|hidden|filler|insert', text_lower):
        categories.append("steganography")
    if re.search(r'fractionat|bifid|trifid|adfg|playfair|polybius|two.?square|four.?square', text_lower):
        categories.append("fractionation")
    if re.search(r'hill|matrix|linear\s*algebra', text_lower):
        categories.append("hill_matrix")
    if re.search(r'physical|overlay|transparen|mirror|reflect|rotat|angle|position|grid', text_lower):
        categories.append("physical_or_spatial")
    if re.search(r'morse|binary|ascii|encoding|base', text_lower):
        categories.append("encoding")
    if re.search(r'anagram|rearrang|shuffle|scrambl', text_lower):
        categories.append("anagram")
    if re.search(r'clock|time|berlin|compass|direction|coordinate|lat|lon|degree', text_lower):
        categories.append("positional_or_geographic")
    if re.search(r'two.?layer|double|multi|combin|composit|cascade|chain|layer', text_lower):
        categories.append("multi_layer")
    if re.search(r'egypt|pharaoh|carter|tomb|tut|hieroglyph|archaeol', text_lower):
        categories.append("egyptological")
    if re.search(r'masonic|templar|illumin|esoteric|occult|kabbal|gematria', text_lower):
        categories.append("esoteric")
    if re.search(r'enigma|rotor|machine|mechanical', text_lower):
        categories.append("machine_cipher")
    if re.search(r'homophon|nomenclat', text_lower):
        categories.append("homophonic")
    if re.search(r'one.?time|otp|pad|random\s*key', text_lower):
        categories.append("one_time_pad")
    if re.search(r'nihilist|straddling|checkerboard', text_lower):
        categories.append("nihilist_or_checkerboard")
    if re.search(r'code\s*book|chart|table|matrix|lookup', text_lower):
        categories.append("codebook_or_chart")
    if re.search(r'pattern|anomal|statistic|frequen|distribut|index|coincidence', text_lower):
        categories.append("statistical_analysis")
    if re.search(r'antipod|opposite|complement|inver', text_lower):
        categories.append("antipodal")

    return categories if categories else ["general"]


def compute_substance_score(body):
    """Score how substantive a post is (0-10). Higher = more analytical."""
    score = 0
    if len(body) > 300: score += 1
    if len(body) > 800: score += 1
    if len(body) > 2000: score += 1
    # Contains specific letter sequences or cipher operations
    if re.search(r'[A-Z]{10,}', body): score += 2  # Long uppercase sequences (CT/PT)
    if re.search(r'\d+[\s,]+\d+[\s,]+\d+', body): score += 1  # Number sequences
    if re.search(r'mod\s*\d|position\s*\d|\bpos\b', body, re.I): score += 1
    if re.search(r'key\s*=|period\s*=|shift|offset', body, re.I): score += 1
    if re.search(r'decrypt|encipher|decipher|transform', body, re.I): score += 1
    if re.search(r'proof|theorem|lemma|therefore|implies|contradiction', body, re.I): score += 1
    return min(score, 10)


seen_ids = set()
total = 0
kept = 0

mbox = mailbox.mbox(MBOX_PATH)
for msg in mbox:
    total += 1

    # Dedup by message-id
    msg_id = msg.get("message-id", "")
    if msg_id in seen_ids:
        continue
    seen_ids.add(msg_id)

    subject = msg.get("subject", "") or ""
    body = extract_body(msg)

    # Filter: must have substantive body
    if len(body) < 80:
        continue

    # Filter: must match K4 keywords in subject or body
    combined = subject + " " + body
    if not K4_KEYWORDS.search(combined):
        continue

    # Parse date
    date_str = msg.get("date", "")
    try:
        dt = parsedate_to_datetime(date_str)
        date_iso = dt.isoformat()
    except Exception:
        date_iso = date_str

    # Extract author
    from_addr = msg.get("from", "")

    categories = categorize_post(subject, body)
    substance = compute_substance_score(body)

    record = {
        "msg_id": msg_id,
        "date": date_iso,
        "from": from_addr,
        "subject": subject,
        "body": body[:5000],  # Cap body at 5000 chars
        "categories": categories,
        "substance_score": substance,
        "body_len": len(body),
    }

    print(json.dumps(record), flush=True)
    kept += 1

print(json.dumps({"_summary": True, "total": total, "kept": kept, "unique_ids": len(seen_ids)}),
      file=sys.stderr)
