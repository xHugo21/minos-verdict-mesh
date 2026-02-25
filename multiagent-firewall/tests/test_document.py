from __future__ import annotations

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from multiagent_firewall.nodes.document import (
    read_document,
    sanitize_file_path,
    extract_text_from_file,
    is_image_file,
)
from multiagent_firewall.types import GuardState


def test_sanitize_file_path_decodes_file_uri():
    raw = "file:///tmp/some%20folder/some%20file.txt"
    sanitized = sanitize_file_path(raw)
    assert sanitized.endswith("some file.txt")
    if os.name != "nt":
        assert sanitized == "/tmp/some folder/some file.txt"


def test_sanitize_file_path_handles_regular_path():
    raw = "/tmp/regular/path.txt"
    sanitized = sanitize_file_path(raw)
    assert sanitized == "/tmp/regular/path.txt"


def test_extract_text_from_file_returns_none_for_missing_file(tmp_path):
    missing_path = tmp_path / "missing.txt"
    assert extract_text_from_file(str(missing_path)) is None


def test_extract_text_from_file_reads_plain_text(tmp_path):
    file_path = tmp_path / "doc.txt"
    file_path.write_text("line one\nline two", encoding="utf-8")
    result = extract_text_from_file(str(file_path))
    assert result == "line one\nline two"


def test_extract_text_from_file_reads_pdf(monkeypatch, tmp_path):
    """Test PDF extraction using pdfplumber"""
    pytest.importorskip("pdfplumber")
    pdf_path = tmp_path / "doc.pdf"
    pdf_path.write_bytes(b"%PDF-FAKE")

    class FakePage:
        def __init__(self, text):
            self._text = text

        def extract_text(self):
            return self._text

    class FakePdf:
        def __init__(self):
            self.pages = [
                FakePage("First page"),
                FakePage(None),
                FakePage("Second page"),
            ]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_open(path):
        assert path == str(pdf_path)
        return FakePdf()

    import multiagent_firewall.nodes.document as document_module
    import pdfplumber

    monkeypatch.setattr(pdfplumber, "open", fake_open)

    content = extract_text_from_file(str(pdf_path))
    assert content == "First page\nSecond page"


def test_read_document_with_file_path(tmp_path, guard_config):
    """Extract text from file when file_path provided"""
    file_path = tmp_path / "test.txt"
    file_path.write_text("file content", encoding="utf-8")

    state: GuardState = {
        "file_paths": [str(file_path)],
        "warnings": [],
        "errors": [],
    }
    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == "file content"
    assert len(result.get("errors", [])) == 0


def test_read_document_with_missing_file(tmp_path, guard_config):
    """Handle missing file gracefully and preserve existing raw_text"""
    missing_path = tmp_path / "missing.txt"

    state: GuardState = {
        "file_paths": [str(missing_path)],
        "warnings": [],
        "errors": [],
    }
    result = read_document(state, fw_config=guard_config)

    # raw_text should remain empty since there was no existing text
    assert result["raw_text"] == ""
    assert len(result["errors"]) > 0
    assert "File not found" in result["errors"][0]


def test_read_document_preserves_text_on_file_error(tmp_path, guard_config):
    """Test that existing raw_text is preserved when file reading fails"""
    missing_path = tmp_path / "missing.txt"

    state: GuardState = {
        "raw_text": "existing text",
        "file_paths": [str(missing_path)],
        "warnings": [],
        "errors": [],
    }
    result = read_document(state, fw_config=guard_config)

    # Existing raw_text should be preserved even though file read failed
    assert result["raw_text"] == "existing text"
    assert len(result["errors"]) > 0
    assert "File not found" in result["errors"][0]


def test_read_document_appends_file_to_existing_text(tmp_path, guard_config):
    """Test that file content is appended to existing raw_text"""
    file_path = tmp_path / "test.txt"
    file_path.write_text("file content", encoding="utf-8")

    state: GuardState = {
        "raw_text": "existing text",
        "file_paths": [str(file_path)],
        "warnings": [],
        "errors": [],
    }
    result = read_document(state, fw_config=guard_config)

    # Both existing text and file content should be present
    assert "existing text" in result["raw_text"]
    assert "file content" in result["raw_text"]
    assert result["raw_text"] == "existing text file content"


def test_is_image_file_detects_png():
    assert is_image_file("photo.png") == True
    assert is_image_file("PHOTO.PNG") == True


def test_is_image_file_detects_jpg():
    assert is_image_file("photo.jpg") == True
    assert is_image_file("photo.jpeg") == True
    assert is_image_file("PHOTO.JPG") == True


def test_is_image_file_rejects_non_images():
    assert is_image_file("document.pdf") == False
    assert is_image_file("text.txt") == False
    assert is_image_file("data.csv") == False


@patch("multiagent_firewall.nodes.document._get_default_ocr_detector")
@patch("multiagent_firewall.nodes.document._has_ocr_support", return_value=True)
def test_read_document_with_image_file_and_ocr_detector(
    mock_has_ocr_support, mock_get_detector, tmp_path, guard_config
):
    """Test reading image file with OCR detector"""
    image_path = tmp_path / "screenshot.png"
    image_path.write_bytes(b"fake image data")

    mock_detector = MagicMock()
    mock_detector.return_value = "Some text from image test@example.com"
    mock_get_detector.return_value = mock_detector

    state: GuardState = {
        "file_paths": [str(image_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == "Some text from image test@example.com"
    assert result.get("metadata", {}).get("file_type") == "image"


@patch("multiagent_firewall.nodes.document._get_default_ocr_detector")
@patch("multiagent_firewall.nodes.document._has_ocr_support", return_value=True)
def test_read_document_with_image_file_no_ocr_detector(
    mock_has_ocr_support, mock_get_detector, tmp_path, guard_config
):
    """Test reading image file when OCR detector fails to initialize"""
    image_path = tmp_path / "screenshot.jpg"
    image_path.write_bytes(b"fake image data")

    mock_get_detector.return_value = None

    state: GuardState = {
        "file_paths": [str(image_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == ""
    assert "Image file detected but no OCR detector available" in result["warnings"][0]
    assert result.get("metadata", {}).get("file_type") == "image"


def test_read_document_sets_file_type_metadata_for_pdf(tmp_path, guard_config):
    pdf_path = tmp_path / "document.pdf"
    pdf_path.write_bytes(b"%PDF-fake")

    state: GuardState = {
        "file_paths": [str(pdf_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    # Even if extraction fails, metadata should be set
    assert result.get("metadata", {}).get("file_type") == "pdf"


def test_read_document_sets_file_type_metadata_for_text(tmp_path, guard_config):
    text_path = tmp_path / "document.txt"
    text_path.write_text("Some content", encoding="utf-8")

    state: GuardState = {
        "file_paths": [str(text_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == "Some content"
    assert result.get("metadata", {}).get("file_type") == "text"


@patch("multiagent_firewall.nodes.document._get_default_ocr_detector")
@patch("multiagent_firewall.nodes.document._has_ocr_support", return_value=True)
def test_read_document_handles_ocr_exception(
    mock_has_ocr_support, mock_get_detector, tmp_path, guard_config
):
    """Test handling OCR detector exceptions"""
    image_path = tmp_path / "bad_image.png"
    image_path.write_bytes(b"corrupt image")

    mock_detector = MagicMock()
    mock_detector.side_effect = RuntimeError("OCR service unavailable")
    mock_get_detector.return_value = mock_detector

    state: GuardState = {
        "file_paths": [str(image_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == ""
    assert any("OCR detection failed" in e for e in result["errors"])


@patch("multiagent_firewall.nodes.document._has_pdf_support", return_value=False)
def test_read_document_warns_when_pdf_support_missing(
    mock_has_pdf_support, tmp_path, guard_config
):
    pdf_path = tmp_path / "missing_support.pdf"
    pdf_path.write_bytes(b"%PDF-fake")

    state: GuardState = {
        "file_paths": [str(pdf_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == ""
    assert any(
        "PDF file detected but PDF support is not installed" in warning
        for warning in result["warnings"]
    )
    assert result["errors"] == []


@patch("multiagent_firewall.nodes.document._has_ocr_support", return_value=False)
def test_read_document_warns_when_ocr_support_missing(
    mock_has_ocr_support, tmp_path, guard_config
):
    image_path = tmp_path / "missing_support.png"
    image_path.write_bytes(b"fake image data")

    state: GuardState = {
        "file_paths": [str(image_path)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == ""
    assert any(
        "OCR dependencies are not installed" in warning
        for warning in result["warnings"]
    )
    assert result["errors"] == []


def test_read_document_with_multiple_files(tmp_path, guard_config):
    """Test reading multiple files with file_paths parameter"""
    file1 = tmp_path / "file1.txt"
    file1.write_text("first file", encoding="utf-8")

    file2 = tmp_path / "file2.txt"
    file2.write_text("second file", encoding="utf-8")

    file3 = tmp_path / "file3.txt"
    file3.write_text("third file", encoding="utf-8")

    state: GuardState = {
        "file_paths": [str(file1), str(file2), str(file3)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    assert result["raw_text"] == "first file second file third file"
    assert result["metadata"]["file_type"] == "text"
    assert result["warnings"] == []
    assert result["errors"] == []


def test_read_document_with_multiple_files_and_existing_text(tmp_path, guard_config):
    """Test reading multiple files with existing text"""
    file1 = tmp_path / "file1.txt"
    file1.write_text("file one", encoding="utf-8")

    file2 = tmp_path / "file2.txt"
    file2.write_text("file two", encoding="utf-8")

    state: GuardState = {
        "raw_text": "existing text",
        "file_paths": [str(file1), str(file2)],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    # Existing text should be preserved and files appended with single space
    assert result["raw_text"] == "existing text file one file two"
    assert result["warnings"] == []
    assert result["errors"] == []


def test_read_document_with_empty_file_paths_list(tmp_path, guard_config):
    """Test reading with empty file_paths list"""
    state: GuardState = {
        "raw_text": "existing text",
        "file_paths": [],
        "warnings": [],
        "errors": [],
        "metadata": {},
    }

    result = read_document(state, fw_config=guard_config)

    # Should preserve existing text
    assert result["raw_text"] == "existing text"
    assert result["warnings"] == []
    assert result["errors"] == []
