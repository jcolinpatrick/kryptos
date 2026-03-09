"""FastAPI theory classifier API for kryptosbot.com."""

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

from api.classifier import classify_theory, load_elimination_index, ClassifyResult
from api.queue import add_theory, init_db, record_request

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
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Rate limiting helpers
# ---------------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For behind a reverse proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
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
    retry_after = record_request(ip, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX)
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

    # Only queue genuinely feasible novel theories
    if result.status == "novel" and result.feasibility == "feasible":
        queue_pos = add_theory(body.theory, ip)
        result.message = "This theory hasn't been tested yet. It has been logged for evaluation."
        result.queue_position = queue_pos
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
