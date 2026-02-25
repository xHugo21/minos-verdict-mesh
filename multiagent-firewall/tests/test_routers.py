"""Tests for routing logic."""

from multiagent_firewall.routers import (
    should_read_document,
    should_run_llm_ocr,
    should_run_llm,
    route_after_dlp_ner,
    route_after_merge_final,
)
from multiagent_firewall.types import GuardState


def test_should_read_document_routes_to_read_document_when_file_paths_present():
    """Test routing to read_document when file_paths is present."""
    state: GuardState = {"file_paths": ["/path/to/file.txt"]}
    result = should_read_document(state)
    assert result == "read_document"


def test_should_read_document_routes_to_normalize_when_no_file_paths():
    """Test routing to normalize when file_paths is absent."""
    state: GuardState = {}
    result = should_read_document(state)
    assert result == "normalize"


def test_should_run_llm_ocr_routes_to_llm_ocr_when_images_need_ocr():
    """Test routing to llm_ocr when images_needing_llm_ocr list is present."""
    state: GuardState = {
        "metadata": {"images_needing_llm_ocr": ["/path/to/image.png"]},
        "raw_text": "Some text from a PDF",  # Has text but image still needs OCR
    }
    result = should_run_llm_ocr(state)
    assert result == "llm_ocr"


def test_should_run_llm_ocr_routes_to_normalize_when_no_images_need_ocr():
    """Test routing to normalize when images_needing_llm_ocr list is empty."""
    state: GuardState = {
        "metadata": {"images_needing_llm_ocr": []},
        "raw_text": "Some text",
    }
    result = should_run_llm_ocr(state)
    assert result == "normalize"


def test_should_run_llm_ocr_routes_to_normalize_when_list_not_present():
    """Test routing to normalize when images_needing_llm_ocr list doesn't exist."""
    state: GuardState = {
        "metadata": {},
        "raw_text": "Some text",
    }
    result = should_run_llm_ocr(state)
    assert result == "normalize"


def test_should_run_llm_ocr_handles_multi_file_scenario():
    """Test that router works correctly when PDF + PNG uploaded together.

    This is the bug fix: when a PNG (Tesseract fails) and PDF (text extracted)
    are uploaded together, the PNG should still trigger LLM OCR even though
    raw_text has content from the PDF.
    """
    state: GuardState = {
        "raw_text": "Text from PDF file",  # PDF successfully extracted text
        "metadata": {
            "file_types": ["pdf", "image"],
            "images_needing_llm_ocr": ["/path/to/image.png"],  # PNG needs OCR
        },
    }
    result = should_run_llm_ocr(state)
    assert result == "llm_ocr", (
        "Should route to llm_ocr even when raw_text has content from other files"
    )


def test_should_run_llm_routes_to_anonymize_when_force_flag_set():
    """Test routing to anonymize_dlp_ner when force_llm_detector flag is set."""
    state: GuardState = {"force_llm_detector": True}
    result = should_run_llm(state)
    assert result == "anonymize_dlp_ner"


def test_should_run_llm_routes_to_remediation_when_decision_is_block():
    """Test routing to remediation when decision is block."""
    state: GuardState = {"decision": "block"}
    result = should_run_llm(state)
    assert result == "remediation"


def test_should_run_llm_routes_to_anonymize_by_default():
    """Test routing to anonymize_dlp_ner by default."""
    state: GuardState = {}
    result = should_run_llm(state)
    assert result == "anonymize_dlp_ner"


def test_route_after_dlp_ner_routes_to_risk_when_detections_present():
    """Test routing to risk_dlp_ner when detections are found."""
    state: GuardState = {
        "detected_fields": [{"field": "email", "value": "test@example.com"}]
    }
    result = route_after_dlp_ner(state)
    assert result == "risk_dlp_ner"


def test_route_after_dlp_ner_routes_to_llm_when_no_detections():
    """Test routing to llm_detector when no detections are found."""
    state: GuardState = {}
    result = route_after_dlp_ner(state)
    assert result == "llm_detector"


def test_route_after_merge_final_routes_to_end_when_no_detections():
    """Test routing to END when no detections at all."""
    state: GuardState = {}
    result = route_after_merge_final(state)
    assert result == "__end__"


def test_route_after_merge_final_routes_to_remediation_when_no_new_fields():
    """Test routing to remediation when no new fields from LLM."""
    state: GuardState = {
        "detected_fields": [{"field": "email", "value": "test@example.com"}],
        "dlp_fields": [{"field": "email", "value": "test@example.com"}],
        "decision": "warn",
    }
    result = route_after_merge_final(state)
    assert result == "remediation"


def test_route_after_merge_final_routes_to_risk_when_new_fields_present():
    """Test routing to risk_final when new fields from LLM are present."""
    state: GuardState = {
        "detected_fields": [
            {"field": "email", "value": "test@example.com"},
            {"field": "phone", "value": "123-456-7890"},
        ],
        "dlp_fields": [{"field": "email", "value": "test@example.com"}],
        "llm_fields": [{"field": "phone", "value": "123-456-7890"}],
    }
    result = route_after_merge_final(state)
    assert result == "risk_final"
