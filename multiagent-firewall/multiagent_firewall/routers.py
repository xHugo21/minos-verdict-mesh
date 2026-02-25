from __future__ import annotations

from langgraph.graph import END

from .types import GuardState


def should_read_document(state: GuardState) -> str:
    """Route to document reader if file_paths is provided."""
    if state.get("file_paths"):
        return "read_document"
    return "normalize"


def should_run_llm_ocr(state: GuardState) -> str:
    """Route to llm_ocr if there are images needing LLM OCR fallback."""
    metadata = state.get("metadata", {})
    images_needing_ocr = metadata.get("images_needing_llm_ocr", [])

    if images_needing_ocr:
        return "llm_ocr"
    return "normalize"


def should_run_llm(state: GuardState) -> str:
    """Route to anonymize_dlp_ner unless policy already blocks."""
    if state.get("force_llm_detector"):
        return "anonymize_dlp_ner"
    decision = (state.get("decision") or "").lower()
    if decision == "block":
        return "remediation"
    return "anonymize_dlp_ner"


def route_after_dlp_ner(state: GuardState) -> str:
    """Skip pre-LLM risk/policy if no DLP/NER detections were found."""
    if (
        state.get("detected_fields")
        or state.get("dlp_fields")
        or state.get("ner_fields")
    ):
        return "risk_dlp_ner"
    return "llm_detector"


def route_after_merge_final(state: GuardState) -> str:
    """Avoid redundant final risk/policy when nothing new was added."""
    detected_fields = state.get("detected_fields") or []
    llm_fields = state.get("llm_fields") or []
    dlp_fields = state.get("dlp_fields") or []
    ner_fields = state.get("ner_fields") or []

    def signatures(fields) -> set[tuple[str, str]]:
        seen = set()
        for item in fields:
            if not isinstance(item, dict):
                continue
            field = str(item.get("field") or "").strip().lower()
            value = str(item.get("value") or "").strip().lower()
            if not field and not value:
                continue
            seen.add((field, value))
        return seen

    # If no detections at all, skip directly to END (no remediation needed)
    if not detected_fields:
        return END

    # If we have a decision already and no new fields from LLM, skip to remediation
    pre_llm_signatures = signatures(dlp_fields) | signatures(ner_fields)
    detected_signatures = signatures(detected_fields)
    no_new_fields = detected_signatures.issubset(pre_llm_signatures)
    if no_new_fields and state.get("decision"):
        return "remediation"
    if not llm_fields and state.get("decision"):
        return "remediation"

    return "risk_final"
