from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from typing_extensions import NotRequired, TypedDict

if TYPE_CHECKING:
    from .config.env import GuardConfig
else:
    GuardConfig = Any

FieldList = List[Dict[str, Any]]


class GuardState(TypedDict, total=False):
    # INPUT
    file_paths: NotRequired[list[str] | None]
    raw_text: str
    min_block_level: NotRequired[str | None]
    llm_provider: NotRequired[str]
    force_llm_detector: NotRequired[bool]

    # PROCESSING
    anonymized_text: NotRequired[str]
    normalized_text: str
    metadata: Dict[str, Any]
    warnings: List[str]
    errors: List[str]

    # DETECTION
    llm_fields: FieldList
    dlp_fields: FieldList
    ner_fields: FieldList
    code_similarity_fields: FieldList
    detected_fields: FieldList

    # DECISION
    risk_level: str
    decision: str
    remediation: str
