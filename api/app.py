"""FastAPI theory classifier API for kryptosbot.com."""

import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.classifier import classify_theory, load_elimination_index, ClassifyResult
from api.queue import add_theory, init_db

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

# Elimination index context string (loaded on startup)
_index_context: Optional[str] = None

# Rate limiting: IP -> list of request timestamps (epoch seconds)
_rate_limits: dict[str, list[float]] = {}

RATE_LIMIT_MAX = 10
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://kryptosbot.com",
        "https://www.kryptosbot.com",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
        "http://192.168.1.156:8000",
        "http://192.168.1.179:8000",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
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


def _check_rate_limit(ip: str) -> Optional[int]:
    """Check rate limit for an IP.

    Returns None if under the limit, or seconds until the oldest request
    expires if the limit is exceeded.
    """
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW

    # Prune stale IPs on every call (cheap — dict iteration)
    stale_ips = [k for k, v in _rate_limits.items() if not v or v[-1] < cutoff]
    for k in stale_ips:
        del _rate_limits[k]

    # Get or create timestamp list for this IP
    timestamps = _rate_limits.get(ip, [])

    # Prune expired timestamps for this IP
    timestamps = [t for t in timestamps if t > cutoff]
    _rate_limits[ip] = timestamps

    if len(timestamps) >= RATE_LIMIT_MAX:
        # Seconds until the oldest timestamp expires
        retry_after = int(timestamps[0] - cutoff) + 1
        return max(retry_after, 1)

    # Record this request
    timestamps.append(now)
    return None


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ClassifyRequest(BaseModel):
    theory: str = Field(..., min_length=10, max_length=2000)


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

    # Rate limiting
    ip = _client_ip(request)
    retry_after = _check_rate_limit(ip)
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
    elif result.status == "rejected":
        # Theory was novel but infeasible/untestable/impossible — don't queue
        pass

    return result.to_dict()


# ---------------------------------------------------------------------------
# Static file serving (must be AFTER API routes)
# ---------------------------------------------------------------------------

SITE_DIR = os.environ.get("SITE_DIR", "site")
if os.path.isdir(SITE_DIR):
    app.mount("/", StaticFiles(directory=SITE_DIR, html=True), name="static")
