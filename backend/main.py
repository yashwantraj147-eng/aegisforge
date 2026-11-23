"""
Entrypoint alias for Vercel and ASGI runners.
"""
import sys
from pathlib import Path

# Ensure backend directory and repo root are in sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

REPO_ROOT = CURRENT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.main import app

__all__ = ["app"]
