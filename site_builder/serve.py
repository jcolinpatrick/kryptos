#!/usr/bin/env python3
"""Serve kryptosbot.com: FastAPI backend + static site."""

import sys
from pathlib import Path

# Ensure project root is on sys.path so `api.*` imports work
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dotenv import load_dotenv
load_dotenv(Path(PROJECT_ROOT) / ".env")

import uvicorn
from api.app import app  # noqa: F401 (used by uvicorn)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
