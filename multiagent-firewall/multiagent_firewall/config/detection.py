"""
Loads detection configuration from detection.json and exposes it as module-level constants.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .file_types import FileTypeConfig

_CONFIG_PATH = Path(__file__).parent / "detection.json"


def _load_config() -> dict[str, Any]:
    if not _CONFIG_PATH.exists():
        raise FileNotFoundError(f"Detection config not found: {_CONFIG_PATH}")
    try:
        with open(_CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {_CONFIG_PATH}: {e}") from e


_config = _load_config()

LLM_DETECTOR_PROMPT: str = _config["prompts"]["llm_detector"]
OCR_DETECTOR_PROMPT: str = _config["prompts"]["ocr_detector"]

REGEX_PATTERNS: dict[str, dict[str, Any]] = _config["regex_patterns"]

KEYWORDS: dict[str, list[str]] = _config["keywords"]

CHECKSUM_VALIDATORS: dict[str, str] = _config.get("checksum_validators", {})

NER_LABELS: dict[str, str] = _config["ner_labels"]

RISK_SCORE: dict[str, int] = _config["risk"]["scores"]

_raw_thresholds = _config["risk"]["thresholds"]
RISK_SCORE_THRESHOLDS: dict[str, Any] = {
    k: tuple(v) if isinstance(v, list) else v for k, v in _raw_thresholds.items()
}

HIGH_RISK_FIELDS: set[str] = set(_config["risk_fields"]["high"])
MEDIUM_RISK_FIELDS: set[str] = set(_config["risk_fields"]["medium"])
LOW_RISK_FIELDS: set[str] = set(_config["risk_fields"]["low"])

FILE_TYPE_CONFIG = FileTypeConfig(_config)
