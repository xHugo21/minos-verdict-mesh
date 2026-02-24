from __future__ import annotations

import importlib.util
import logging
import os
import sys
import warnings
from pathlib import Path
from urllib.parse import urlparse, unquote

from ..detectors import TesseractOCRDetector, LLMOCRDetector
from ..types import GuardState
from ..utils import (
    append_error,
    append_warning,
)
from ..config import FILE_TYPE_CONFIG

logger = logging.getLogger(__name__)
FILE_ANALYSIS_EXTRA = "multiagent-firewall[file-analysis]"


def sanitize_file_path(file_path: str) -> str:
    """
    Sanitize file path by decoding file:// URLs and handling platform differences.
    """
    if file_path.startswith("file://"):
        parsed_path = urlparse(file_path).path
        parsed_path = unquote(parsed_path)
        if os.name == "nt":
            # Windows: remove leading slash from /C:/path
            parsed_path = parsed_path.lstrip("/")
        return parsed_path
    return file_path


def _has_module(module_name: str) -> bool:
    if module_name in sys.modules:
        return True
    return importlib.util.find_spec(module_name) is not None


def _has_pdf_support() -> bool:
    return _has_module("pdfplumber")


def _has_ocr_support() -> bool:
    return _has_module("pytesseract") and _has_module("PIL")


def is_image_file(file_path: str) -> bool:
    """
    Check if file is an image using FileTypeConfig.
    """
    image_config = FILE_TYPE_CONFIG.categories.get("image")
    if not image_config:
        return False
    return image_config.is_extension_supported(Path(file_path).suffix)


def read_pdf(file_path: str) -> str | None:
    """
    Extract text from PDF file.
    """
    try:
        import pdfplumber

        path = Path(file_path)

        # Get PDF file type config
        pdf_config = FILE_TYPE_CONFIG.categories.get("pdf")
        if not pdf_config:
            return None

        text = ""
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                extracted_text = page.extract_text()
                if extracted_text:
                    text += extracted_text + "\n"

        return text.strip()
    except Exception as e:
        logger.warning(f"PDF extraction failed: {e}")
        return None


def read_text_file(file_path: str) -> str | None:
    """
    Read plain text file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return None


def extract_text_from_file(file_path: str) -> str | None:
    """
    Extract text from file based on extension.
    """
    try:
        file_path = sanitize_file_path(file_path)

        if not os.path.exists(file_path):
            return None

        if file_path.lower().endswith(".pdf"):
            return read_pdf(file_path)
        else:
            # Try as plain text for all other formats
            return read_text_file(file_path)
    except Exception:
        return None


def _get_default_ocr_detector(fw_config):
    """
    Get default OCR detector from configuration.

    Returns None if Tesseract is not available or fails to initialize.
    """
    try:
        return TesseractOCRDetector(
            lang=fw_config.ocr.lang,
            config=fw_config.ocr.config,
            confidence_threshold=fw_config.ocr.confidence_threshold,
            tesseract_cmd=fw_config.ocr.tesseract_cmd,
        )
    except Exception as e:
        # Log warning but don't crash
        warnings.warn(
            f"Failed to initialize OCR detector: {e}. "
            "Image text extraction won't be executed. "
            f"Install {FILE_ANALYSIS_EXTRA} and Tesseract.",
            RuntimeWarning,
        )
        return None


def read_document(state: GuardState, *, fw_config) -> GuardState:
    """
    Document ingestion node: Extracts text from file if file_path provided.

    - For images: Run OCR detector if available
    - For PDFs: Extract text using pdfplumber
    - For other files: Read as plain text
    """
    if "raw_text" not in state:
        state["raw_text"] = ""

    # Get file_path if provided
    file_path = state.get("file_path")

    # Sanitize and validate file path
    try:
        assert isinstance(file_path, str), "file_path must be a string"
        file_path_clean = sanitize_file_path(file_path)

        if not os.path.exists(file_path_clean):
            append_error(state, f"File not found: {file_path}")
            return state

        # Detect file type and handle accordingly
        if is_image_file(file_path_clean):
            # Handle image files with OCR
            if "metadata" not in state:
                state["metadata"] = {}
            state["metadata"]["file_type"] = "image"

            if not _has_ocr_support():
                append_warning(
                    state,
                    "Image file detected but OCR dependencies are not installed. "
                    f"Install {FILE_ANALYSIS_EXTRA} and Tesseract.",
                )
            else:
                ocr_detector = _get_default_ocr_detector(fw_config)
                if ocr_detector:
                    try:
                        # Call OCR detector with current state - returns plain text
                        text = ocr_detector(state) or ""

                        # Track OCR metadata
                        state["metadata"]["ocr_attempted"] = True
                        state["metadata"]["tesseract_text_found"] = bool(text)

                        # Append to existing raw_text
                        existing_text = state.get("raw_text", "")
                        if existing_text and text:
                            state["raw_text"] = f"{existing_text}\n{text}"
                        elif text:
                            state["raw_text"] = text

                        if text:
                            state["metadata"]["ocr_method"] = "tesseract"
                        else:
                            append_warning(
                                state, f"No text extracted from image: {file_path}"
                            )
                    except Exception as e:
                        append_error(state, f"OCR detection failed: {str(e)}")
                else:
                    append_warning(
                        state,
                        f"Image file detected but no OCR detector available: {file_path}",
                    )
        else:
            # Handle PDF and text files
            if file_path_clean.lower().endswith(".pdf") and not _has_pdf_support():
                append_warning(
                    state,
                    "PDF file detected but PDF support is not installed. "
                    f"Install {FILE_ANALYSIS_EXTRA}.",
                )
                text = ""
            else:
                text = extract_text_from_file(file_path_clean)

            if text is None:
                append_error(state, f"Failed to extract text from file: {file_path}")
            else:
                # Append to existing raw_text
                existing_text = state.get("raw_text", "")
                if existing_text and text:
                    state["raw_text"] = f"{existing_text}\n{text}"
                elif text:
                    state["raw_text"] = text

            # Set file type metadata
            if "metadata" not in state:
                state["metadata"] = {}
            if file_path_clean.lower().endswith(".pdf"):
                state["metadata"]["file_type"] = "pdf"
            else:
                state["metadata"]["file_type"] = "text"

    except Exception as e:
        append_error(state, f"Document extraction error: {str(e)}")

    return state


def llm_ocr_document(state: GuardState, *, fw_config) -> GuardState:
    """
    LLM OCR fallback node: Uses vision-capable LLM to extract text from images
    when Tesseract OCR fails or returns empty results.

    Only runs if:
    1. File is an image (metadata["file_type"] == "image")
    2. No text was extracted (raw_text is empty or whitespace)
    """
    # Check if this is an image with no extracted text
    metadata = state.get("metadata", {})
    raw_text = (state.get("raw_text") or "").strip()
    is_image = metadata.get("file_type") == "image"

    if not is_image or raw_text:
        return state

    try:
        llm_ocr_settings = fw_config.llm_ocr_config()
        llm_ocr = LLMOCRDetector(
            provider=llm_ocr_settings.provider,
            model=llm_ocr_settings.model,
            client_params=llm_ocr_settings.client_params,
        )

        text = llm_ocr(state) or ""

        if text:
            existing_text = state.get("raw_text", "")
            if existing_text and text:
                state["raw_text"] = f"{existing_text}\n{text}"
            elif text:
                state["raw_text"] = text

            if "metadata" not in state:
                state["metadata"] = {}
            state["metadata"]["llm_ocr_used"] = True
            state["metadata"]["ocr_method"] = "llm"
        else:
            append_warning(
                state,
                f"LLM OCR did not extract any text from image: {state.get('file_path')}",
            )

    except Exception as e:
        append_error(state, f"LLM OCR failed: {str(e)}")

    return state


__all__ = [
    "read_document",
    "llm_ocr_document",
    "sanitize_file_path",
    "extract_text_from_file",
    "is_image_file",
]
