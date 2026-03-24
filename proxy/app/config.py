import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _parse_float(value: str | None, default: float) -> float:
    try:
        return float(value) if value is not None else default
    except ValueError:
        return default


def _parse_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


def _parse_list(value: str | None, default: list[str]) -> list[str]:
    if value is None or not value.strip():
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "http://127.0.0.1:8000/detect",
).rstrip("/")
BACKEND_TIMEOUT_SECONDS = _parse_float(os.getenv("BACKEND_TIMEOUT_SECONDS"), 30.0)
MIN_BLOCK_LEVEL = os.getenv("MIN_BLOCK_LEVEL", "low")
BACKEND_AUTH_TOKEN = os.getenv("BACKEND_AUTH_TOKEN", "").strip()

PROXY_HOST = os.getenv("PROXY_HOST", "127.0.0.1")
PROXY_PORT = _parse_int(os.getenv("PROXY_PORT"), 8080)
PROXY_AUTH_HTPASSWD_FILE = os.getenv("PROXY_AUTH_HTPASSWD_FILE", "").strip()


def get_proxy_auth_spec() -> str | None:
    if PROXY_AUTH_HTPASSWD_FILE:
        return f"@{Path(PROXY_AUTH_HTPASSWD_FILE).expanduser()}"
    return None


INTERCEPTED_HOSTS = _parse_list(
    os.getenv("INTERCEPTED_HOSTS"),
    [
        "api.openai.com",  # OpenAI GPT-4, GPT-4 Vision
        "api.anthropic.com",  # Claude (Anthropic)
        "api.githubcopilot.com",  # GitHub Copilot
        "api.groq.com",  # Groq
        "generativelanguage.googleapis.com",  # Google Gemini
    ],
)

INTERCEPTED_PATHS = _parse_list(
    os.getenv("INTERCEPTED_PATHS"),
    [
        "/v1/chat/completions",  # OpenAI, Groq, Copilot
        "/v1/completions",  # OpenAI legacy
        "/v1/engines/",  # OpenAI legacy
        "/v1/messages",  # Anthropic Claude
        "/chat/completions",  # GitHub Copilot
        "/completions",  # Generic completions
    ],
)

INTERCEPTED_WS_PATHS = _parse_list(
    os.getenv("INTERCEPTED_WS_PATHS"),
    [],
)
