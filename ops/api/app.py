"""FastAPI theory classifier API for kryptosbot.com."""

import logging
import os
import re
import urllib.request
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# Uvicorn runs under systemd, so this reaches journalctl. Used to count usage
# of the deprecated status path form; it never records the token itself.
logger = logging.getLogger("kryptosbot.api")

from ops.api.classifier import classify_theory, load_elimination_index, ClassifyResult
from ops.api.queue import (
    add_theory, get_by_token, init_db, record_request,
    log_classification, get_classification_stats,
)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

# Elimination index context string (loaded on startup)
_index_context: Optional[str] = None

RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

# ---------------------------------------------------------------------------
# Content moderation — fast local pre-screen (no API cost)
# ---------------------------------------------------------------------------

# Patterns that indicate content violating Anthropic usage policy or
# that have no plausible relation to cryptanalysis.  Case-insensitive.
_BLOCKED_PATTERNS: list[re.Pattern] = [
    # Hate speech / slurs (representative, not exhaustive)
    re.compile(
        r"\b(kill\s+(all|every|those)|ethnic\s+cleansing|white\s+power"
        r"|racial\s+supremacy|gas\s+the|heil\s+hitler)\b", re.I,
    ),
    # CSAM / sexual content involving minors
    re.compile(r"\b(child\s+porn|csam|underage\s+sex|sexual.*\bminor)\b", re.I),
    # Explicit violence / terrorism instructions
    re.compile(
        r"\b(how\s+to\s+(make|build)\s+(a\s+)?(bomb|explosive|weapon)"
        r"|biological\s+weapon|nerve\s+agent)\b", re.I,
    ),
    # Prompt injection attempts targeting the classifier
    re.compile(
        r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)"
        r"|you\s+are\s+now\s+(?!classif)|system\s*prompt|<\s*/?\s*system\s*>)", re.I,
    ),
]

# Maximum ratio of non-ASCII to total characters (filters binary/encoded junk)
_MAX_NON_ASCII_RATIO = 0.3


def _check_content(text: str) -> Optional[dict]:
    """Fast local content pre-screen.

    Returns None if the content passes, or a JSON-serialisable error dict
    if it should be rejected (returned as 422 to the client).
    """
    # Check for blocked patterns
    for pattern in _BLOCKED_PATTERNS:
        if pattern.search(text):
            return {
                "detail": "Your submission contains content that violates our usage policy. "
                "Please keep submissions focused on cryptanalysis of Kryptos K4.",
                "status": "error",
            }

    # Check for excessive non-ASCII (binary paste, encoded payloads)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if len(text) > 0 and non_ascii / len(text) > _MAX_NON_ASCII_RATIO:
        return {
            "detail": "Submission contains too many non-ASCII characters. "
            "Please use plain English text.",
            "status": "error",
        }

    return None

SEARCH_INDEX_PATH = os.environ.get(
    "SEARCH_INDEX_PATH", "site/search-index.json"
)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load elimination index on startup."""
    global _index_context
    try:
        _index_context = load_elimination_index(SEARCH_INDEX_PATH)
    except FileNotFoundError:
        _index_context = None
    init_db()
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Kryptosbot Theory Classifier",
    version="1.0.0",
    lifespan=lifespan,
)

_CORS_ORIGINS = [
    "https://kryptosbot.com",
    "https://www.kryptosbot.com",
]
# Allow local dev origins only when explicitly opted in
if os.environ.get("KBOT_DEV_CORS"):
    _CORS_ORIGINS += [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# ---------------------------------------------------------------------------
# Rate limiting helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """Extract the CloudFront viewer IP from the trusted proxy chain.

    The EC2 security group accepts HTTP only from CloudFront. CloudFront adds
    the viewer address to ``X-Forwarded-For`` and nginx appends the trusted
    CloudFront peer address when proxying to Uvicorn. A viewer can prepend
    arbitrary values, so the first address is not a safe rate-limit key.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        addresses = [address.strip() for address in forwarded.split(",") if address.strip()]
        if len(addresses) >= 2:
            return addresses[-2]
        # Local development does not have the CloudFront-nginx two-hop chain.
        return addresses[0]
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ClassifyRequest(BaseModel):
    theory: str = Field(..., min_length=10, max_length=2000)

    @field_validator("theory")
    @classmethod
    def sanitize_theory(cls, v: str) -> str:
        # Strip null bytes and control characters (except newline/tab)
        v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)
        # Collapse excessive whitespace (>3 consecutive blank lines)
        v = re.sub(r"\n{4,}", "\n\n\n", v)
        return v.strip()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "index_loaded": _index_context is not None}


def _extract_bearer(header_value: Optional[str]) -> Optional[str]:
    """Pull the token out of an ``Authorization: Bearer <token>`` header.

    The scheme must be stripped BEFORE the strict ``len(token) != 32`` check
    below, or every header-form request answers 400.
    """
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def _status_response(token: Optional[str]):
    """Shared body for both entry points, so they cannot drift apart."""
    if not token or len(token) != 32 or not all(c in "0123456789abcdef" for c in token):
        return JSONResponse(status_code=400, content={"detail": "Invalid token format."})
    theory = get_by_token(token)
    if theory is None:
        return JSONResponse(status_code=404, content={"detail": "No submission found for this token."})
    # Return status info without exposing internal IDs or IP hashes
    response = {
        "status": theory["status"],
        "submitted": theory["timestamp"],
        "theory_preview": theory["theory_text"][:200],
    }
    # Never return a bare terminal status. The submit page promises "detailed
    # results", and three early rejections (ids 1, 4, 5) carry no note, so
    # their submitters saw only the word "rejected". A default keeps that
    # promise even where the note was never backfilled.
    note = theory.get("result_note")
    if not note:
        note = _DEFAULT_STATUS_NOTES.get(theory["status"])
    if note:
        response["note"] = note
    return response


@app.get("/api/status")
async def theory_status_by_header(request: Request):
    """Look up a submission by a token carried in the Authorization header.

    This is the form the site uses. It exists because AWS WAF logs record
    ``httpRequest.uri`` verbatim and only query strings are redactable, so a
    token in the URL path is written to a log file on every request. The
    ``authorization`` header is already redacted in the WAF logging config, and
    CloudFront access logs do not record request headers at all.
    """
    return _status_response(_extract_bearer(request.headers.get("authorization")))


@app.get("/api/status/{token}")
async def theory_status(token: str):
    """DEPRECATED path form, kept so nothing breaks mid-transition.

    Removing it outright would be an invisible, actively misleading failure:
    an unmatched /api/* falls through to the StaticFiles mount and answers a
    JSON 404, and status.js renders ANY 404 as "No submission found for this
    token." Every user holding cached JS would be told their submission was
    lost, and nothing would alarm - the canary only checks /api/health and a
    404 is not a 5xx.

    Retire it once this counter stops moving. Logged rather than counted in
    memory because the process restarts on every release.
    """
    logger.info("deprecated_status_path_form used")
    return _status_response(token)


_DEFAULT_STATUS_NOTES = {
    "rejected": (
        "This submission was reviewed and not taken forward. It predates our "
        "practice of recording a written reason for every decision, so the "
        "specific finding was not saved. That is our omission, not a comment "
        "on the idea. If you would like it re-reviewed with a written result, "
        "resubmit it and it will get one."
    ),
    "testing": (
        "This submission is currently being run through the framework. The "
        "result will appear here when the run completes."
    ),
    "pending": (
        "This submission is queued for review. It has not been tested yet."
    ),
}


@app.get("/api/classify/stats")
async def classify_stats():
    """Return classification analytics: how often theories match existing eliminations.

    Useful for measuring whether the site is effectively communicating what's
    been tested — a high matched:novel ratio means people are proposing things
    we've already tried.
    """
    try:
        stats = get_classification_stats()
        return stats
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to load classification stats."},
        )


@app.post("/api/classify")
async def classify(body: ClassifyRequest, request: Request):
    # Check that the index is loaded
    if _index_context is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "Elimination index not loaded. The site may still be building."},
        )

    # Rate limiting (persistent — survives server restarts)
    ip = _client_ip(request)
    try:
        retry_after = record_request(ip, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX)
    except Exception:
        # DB unavailable — skip rate limiting rather than crashing the endpoint
        retry_after = None
    if retry_after is not None:
        minutes = (retry_after + 59) // 60
        return JSONResponse(
            status_code=429,
            content={
                "detail": f"Rate limit exceeded. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
                "retry_after": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    # Content moderation pre-screen (fast, no API cost)
    moderation = _check_content(body.theory)
    if moderation is not None:
        return JSONResponse(status_code=422, content=moderation)

    # Classify
    try:
        result: ClassifyResult = await classify_theory(body.theory, _index_context)
    except Exception:
        return JSONResponse(
            status_code=502,
            content={"detail": "Classification service temporarily unavailable."},
        )

    # Log every classification for analytics (best-effort)
    try:
        log_classification(
            ip_address=ip,
            theory_text=body.theory,
            status=result.status,
            elimination_id=result.elimination_id,
            feasibility=result.feasibility,
        )
    except Exception:
        pass  # Never let logging failure affect the response

    # Only queue genuinely feasible novel theories
    if result.status == "novel" and result.feasibility == "feasible":
        queue_pos, token = add_theory(body.theory, ip)
        result.message = "This theory hasn't been tested yet. It has been logged for evaluation."
        result.queue_position = queue_pos
        result.token = token
        # Fire notification (best-effort, never block the response)
        try:
            _notify_novel_theory(body.theory, queue_pos)
        except Exception:
            pass
    elif result.status == "rejected":
        # Theory was novel but infeasible/untestable/impossible — don't queue
        pass

    return result.to_dict()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
NTFY_CHALLENGE_TOPIC = os.environ.get("NTFY_CHALLENGE_TOPIC", "kbot-challenge-k4")

# Challenge K4 verification
CHALLENGE_K4_HASH = "ab491ee62d455cf627859b836591c355643b7da738ce4f6a55aacf6743fdae51"


class ChallengeSubmission(BaseModel):
    answer: str = Field(..., min_length=10, max_length=200)


@app.post("/api/challenge/verify")
async def verify_challenge(submission: ChallengeSubmission, request: Request):
    """Verify a Challenge K4 submission against the known hash."""
    import hashlib
    cleaned = submission.answer.upper().strip().replace(" ", "")
    h = hashlib.sha256(cleaned.encode()).hexdigest()
    correct = h == CHALLENGE_K4_HASH

    if correct:
        ip = str(request.client.host)
        # Durable record FIRST (survives ntfy's ~12h retention), then notify.
        # ntfy truncates the answer to 50 chars; the log keeps the full plaintext.
        _persist_challenge_solve(cleaned, ip)
        _notify_challenge_solved(cleaned, ip)

    return JSONResponse({
        "correct": correct,
        "hash": h,
        "expected_hash": CHALLENGE_K4_HASH,
    })


# Durable, append-only solve log. logs/ is gitignored, so the full plaintext
# recorded here never reaches the public repo.
CHALLENGE_SOLVES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "logs", "challenge_solves.json"
)


def _persist_challenge_solve(answer: str, ip: str) -> None:
    """Append a full, server-verified solve record to CHALLENGE_SOLVES_FILE.

    Best-effort and fail-safe: a logging failure must never break the verify
    endpoint. Unlike the ntfy push, this captures the COMPLETE plaintext.
    """
    import json
    import time
    try:
        os.makedirs(os.path.dirname(CHALLENGE_SOLVES_FILE), exist_ok=True)
        data = {"solves": []}
        if os.path.exists(CHALLENGE_SOLVES_FILE):
            try:
                with open(CHALLENGE_SOLVES_FILE) as f:
                    data = json.load(f)
            except Exception:
                data = {"solves": []}
        data.setdefault("solves", [])
        data["solves"].append({
            "solved": True,
            "server_verified": True,
            "unix_time": int(time.time()),
            "source_ip": ip,
            "expected_hash": CHALLENGE_K4_HASH,
            "full_plaintext": answer,
            "answer_prefix": answer[:50],
            "solver_name": None,
            "solver_method": None,
            "credit_status": "pending",
        })
        with open(CHALLENGE_SOLVES_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _notify_challenge_solved(answer: str, ip: str) -> None:
    """URGENT notification when someone solves Challenge K4."""
    topic = NTFY_CHALLENGE_TOPIC or NTFY_TOPIC
    if not topic:
        return
    try:
        data = f"SOLVED! Answer: {answer[:50]}... from {ip}".encode("utf-8")
        req = urllib.request.Request(
            f"https://ntfy.sh/{topic}",
            data=data,
            headers={
                "Title": "Challenge K4 SOLVED!",
                "Priority": "urgent",
                "Tags": "trophy,tada,kryptos",
                "Click": "https://kryptosbot.com/challenge/",
            },
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


# Challenge attempt counter (simple file-based, no DB needed)
CHALLENGE_STATS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "logs", "challenge_attempts.json"
)


class ChallengeAttempt(BaseModel):
    length: int = Field(..., ge=1, le=500)
    correct: bool = False
    ts: int = 0


@app.post("/api/challenge/attempt")
async def log_challenge_attempt(attempt: ChallengeAttempt):
    """Log an anonymous challenge attempt (no personal data, just a counter)."""
    import json
    os.makedirs(os.path.dirname(CHALLENGE_STATS_FILE), exist_ok=True)

    stats = {"total": 0, "correct": 0, "by_length": {}}
    if os.path.exists(CHALLENGE_STATS_FILE):
        try:
            with open(CHALLENGE_STATS_FILE) as f:
                stats = json.load(f)
        except Exception:
            pass

    stats["total"] = stats.get("total", 0) + 1
    if attempt.correct:
        stats["correct"] = stats.get("correct", 0) + 1
    lk = str(attempt.length)
    by_len = stats.get("by_length", {})
    by_len[lk] = by_len.get(lk, 0) + 1
    stats["by_length"] = by_len

    try:
        with open(CHALLENGE_STATS_FILE, "w") as f:
            json.dump(stats, f)
    except Exception:
        pass

    return JSONResponse({"ok": True})


@app.get("/api/challenge/stats")
async def challenge_stats():
    """Return anonymous challenge attempt statistics."""
    import json
    stats = {"total": 0, "correct": 0, "by_length": {}}
    if os.path.exists(CHALLENGE_STATS_FILE):
        try:
            with open(CHALLENGE_STATS_FILE) as f:
                stats = json.load(f)
        except Exception:
            pass
    return JSONResponse(stats)


def _notify_novel_theory(theory: str, queue_pos: int) -> None:
    """Send push notification via ntfy.sh when a novel theory arrives.

    Set NTFY_TOPIC in .env to enable. Install the ntfy app on your phone
    and subscribe to the same topic to receive notifications.
    """
    if not NTFY_TOPIC:
        return
    try:
        preview = theory[:200].replace("\n", " ")
        data = f"#{queue_pos}: {preview}".encode("utf-8")
        req = urllib.request.Request(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data=data,
            headers={
                "Title": "New K4 Theory Submitted",
                "Priority": "high",
                "Tags": "brain,kryptos",
                "Click": "https://kryptosbot.com/submit/",
            },
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # Never let notification failure affect the API


# ---------------------------------------------------------------------------
# Static file serving (must be AFTER API routes)
# ---------------------------------------------------------------------------

SITE_DIR = os.environ.get("SITE_DIR", "site")
if os.path.isdir(SITE_DIR):
    app.mount("/", StaticFiles(directory=SITE_DIR, html=True), name="static")
