"""
Agentic SOC Co-Pilot — src package.

Auto-loads the project .env file so that tool classes can resolve
their connection parameters via os.getenv() without each caller
having to remember to call load_dotenv().
"""
import os
from pathlib import Path

_DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"
if _DOTENV_PATH.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_DOTENV_PATH)
    except Exception:
        # Fallback: parse .env manually if python-dotenv isn't installed
        with open(_DOTENV_PATH, "r") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())
