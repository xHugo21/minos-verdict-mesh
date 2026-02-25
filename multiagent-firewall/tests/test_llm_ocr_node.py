from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from multiagent_firewall.nodes.document import llm_ocr_document
from multiagent_firewall.types import GuardState


def test_llm_ocr_document_skips_non_image(guard_config):
    """Test that LLM OCR skips when no images need processing"""
    state: GuardState = {
        "raw_text": "",
        "metadata": {"file_type": "pdf"},  # No images_needing_llm_ocr list
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # State should be unchanged
    assert result["raw_text"] == ""
    assert len(result.get("warnings", [])) == 0


def test_llm_ocr_document_skips_when_text_exists(guard_config):
    """Test that LLM OCR skips when no images need processing"""
    state: GuardState = {
        "raw_text": "Already extracted text",
        "metadata": {"file_type": "image"},  # No images_needing_llm_ocr list
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # State should be unchanged (no images in the list to process)
    assert result["raw_text"] == "Already extracted text"
    assert len(result.get("warnings", [])) == 0


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_skips_when_text_is_whitespace(
    mock_ocr_detector, guard_config
):
    """Test that LLM OCR runs when image is in processing list"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.return_value = "Extracted by LLM"
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "   \n  ",  # Only whitespace
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should have extracted text via LLM
    assert "Extracted by LLM" in result["raw_text"]
    assert result["metadata"]["llm_ocr_used"] is True
    assert result["metadata"]["ocr_method"] == "llm"


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_extracts_text_successfully(mock_ocr_detector, guard_config):
    """Test successful text extraction via LLM OCR"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.return_value = "Text extracted by LLM OCR"
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should have extracted text
    assert result["raw_text"] == "Text extracted by LLM OCR"
    assert result["metadata"]["llm_ocr_used"] is True
    assert result["metadata"]["ocr_method"] == "llm"
    assert len(result.get("warnings", [])) == 0
    assert len(result.get("errors", [])) == 0


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_appends_to_existing_text(mock_ocr_detector, guard_config):
    """Test that LLM OCR appends to existing text if present"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.return_value = "New text from LLM"
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "Existing content",  # Already has content (e.g., from PDF)
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should append to existing text with single space separator
    assert "Existing content" in result["raw_text"]
    assert "New text from LLM" in result["raw_text"]
    assert result["raw_text"] == "Existing content New text from LLM"


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_adds_warning_when_no_text_extracted(
    mock_ocr_detector, guard_config
):
    """Test that warning is added when LLM returns empty text"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.return_value = ""  # Empty result
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should have warning
    assert len(result["warnings"]) == 1
    assert "did not extract any text" in result["warnings"][0]
    assert result["raw_text"] == ""


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_handles_detector_exception(mock_ocr_detector, guard_config):
    """Test that exceptions from detector are handled gracefully"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.side_effect = RuntimeError("API call failed")
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should have error
    assert len(result["errors"]) == 1
    assert "LLM OCR failed" in result["errors"][0]
    assert "API call failed" in result["errors"][0]
    assert result["raw_text"] == ""


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_handles_from_env_exception(mock_ocr_detector, guard_config):
    """Test that exceptions from initialization are handled gracefully"""
    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    mock_ocr_detector.side_effect = RuntimeError("Missing API key")
    result = llm_ocr_document(state, fw_config=guard_config)

    # Should have error
    assert len(result["errors"]) == 1
    assert "LLM OCR" in result["errors"][0]
    assert "Missing API key" in result["errors"][0]


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_metadata_not_present(mock_ocr_detector, guard_config):
    """Test that node skips when no images_needing_llm_ocr list"""
    mock_detector = MagicMock()
    mock_detector.model = "gpt-4o"
    mock_detector.return_value = "Extracted text"
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "warnings": [],
        "errors": [],
    }
    # Note: metadata not in state, so no images_needing_llm_ocr list

    result = llm_ocr_document(state, fw_config=guard_config)

    # Should skip because no images in processing list
    assert result["raw_text"] == ""


@patch("multiagent_firewall.nodes.document.LLMOCRDetector")
def test_llm_ocr_document_sets_metadata_correctly(mock_ocr_detector, guard_config):
    """Test that metadata is set correctly after successful extraction"""
    mock_detector = MagicMock()
    mock_detector.model = "claude-3-opus"
    mock_detector.return_value = "Claude extracted this"
    mock_ocr_detector.return_value = mock_detector

    state: GuardState = {
        "raw_text": "",
        "file_path": "/fake/image.png",
        "metadata": {
            "file_type": "image",
            "other_key": "value",
            "images_needing_llm_ocr": ["/fake/image.png"],  # Image needs LLM OCR
        },
        "warnings": [],
        "errors": [],
    }

    result = llm_ocr_document(state, fw_config=guard_config)

    # Check metadata
    assert result["metadata"]["llm_ocr_used"] is True
    assert result["metadata"]["ocr_method"] == "llm"
    assert result["metadata"]["file_type"] == "image"
    assert result["metadata"]["other_key"] == "value"
    # images_needing_llm_ocr should be removed after processing
    assert "images_needing_llm_ocr" not in result["metadata"]
