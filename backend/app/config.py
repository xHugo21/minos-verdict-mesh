import os
from pathlib import Path
from dotenv import load_dotenv
from multiagent_firewall.config import GuardConfig

load_dotenv()

# Load firewall environment variables from the sibling directory
try:
    MULTIAGENT_FIREWALL_ENV_PATH = (
        Path(__file__).resolve().parent.parent.parent / "multiagent-firewall" / ".env"
    )
    if MULTIAGENT_FIREWALL_ENV_PATH.exists():
        load_dotenv(dotenv_path=MULTIAGENT_FIREWALL_ENV_PATH)
except Exception:
    # Fallback or ignore if file structure is different (e.g. installed as package)
    pass

PORT = int(os.getenv("PORT", "8000"))

ALLOW_ORIGINS = [
    "https://chatgpt.com",
    "https://gemini.google.com",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]


def _str_to_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


DEBUG_MODE = _str_to_bool(os.getenv("DEBUG_MODE"), False)


GUARD_CONFIG = GuardConfig.from_env()


# Hardcoded default block level (most restrictive: low)
DEFAULT_BLOCK_LEVEL = "low"


BACKEND_AUTH_TOKEN = os.getenv("BACKEND_AUTH_TOKEN", "").strip()
