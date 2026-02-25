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
    Extract text from file based on category from FileTypeConfig.
    """
    try:
        file_path = sanitize_file_path(file_path)

        if not os.path.exists(file_path):
            return None

        # Use FileTypeConfig to determine file category
        file_type_def = FILE_TYPE_CONFIG.get_by_extension(file_path)

        if file_type_def and file_type_def.category == "pdf":
            return read_pdf(file_path)
        else:
            # Try as plain text for text/unknown formats
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


def _process_image_file(
    file_path_clean: str, state: GuardState, fw_config
) -> str | None:
    """
    Process an image file with OCR.

    Returns extracted text or None if extraction failed.
    """
    if not _has_ocr_support():
        append_warning(
            state,
            "Image file detected but OCR dependencies are not installed. "
            f"Install {FILE_ANALYSIS_EXTRA} and Tesseract.",
        )
        if "metadata" not in state:
            state["metadata"] = {}
        if "images_needing_llm_ocr" not in state["metadata"]:
            state["metadata"]["images_needing_llm_ocr"] = []
        state["metadata"]["images_needing_llm_ocr"].append(file_path_clean)
        return None

    ocr_detector = _get_default_ocr_detector(fw_config)
    if not ocr_detector:
        append_warning(
            state,
            f"Image file detected but no OCR detector available: {file_path_clean}",
        )
        if "metadata" not in state:
            state["metadata"] = {}
        if "images_needing_llm_ocr" not in state["metadata"]:
            state["metadata"]["images_needing_llm_ocr"] = []
        state["metadata"]["images_needing_llm_ocr"].append(file_path_clean)
        return None

    try:
        temp_state: dict = dict(state)  # type: ignore
        temp_state["file_path"] = file_path_clean

        text = ocr_detector(temp_state) or ""  # type: ignore

        if "metadata" not in state:
            state["metadata"] = {}
        state["metadata"]["ocr_attempted"] = True
        state["metadata"]["tesseract_text_found"] = bool(text)

        if text:
            state["metadata"]["ocr_method"] = "tesseract"
        else:
            append_warning(state, f"No text extracted from image: {file_path_clean}")
            if "images_needing_llm_ocr" not in state["metadata"]:
                state["metadata"]["images_needing_llm_ocr"] = []
            state["metadata"]["images_needing_llm_ocr"].append(file_path_clean)

        return text
    except Exception as e:
        append_error(state, f"OCR detection failed for {file_path_clean}: {str(e)}")
        if "metadata" not in state:
            state["metadata"] = {}
        if "images_needing_llm_ocr" not in state["metadata"]:
            state["metadata"]["images_needing_llm_ocr"] = []
        state["metadata"]["images_needing_llm_ocr"].append(file_path_clean)
        return None


def _process_pdf_file(file_path_clean: str, state: GuardState) -> str | None:
    """
    Process a PDF file.

    Returns extracted text or None if extraction failed.
    """
    if not _has_pdf_support():
        append_warning(
            state,
            "PDF file detected but PDF support is not installed. "
            f"Install {FILE_ANALYSIS_EXTRA}.",
        )
        return None

    text = extract_text_from_file(file_path_clean)

    if text is None:
        append_error(state, f"Failed to extract text from PDF: {file_path_clean}")
        return None

    return text


def _process_text_file(file_path_clean: str, state: GuardState) -> str | None:
    """
    Process a plain text file.

    Returns extracted text or None if extraction failed.
    """
    text = extract_text_from_file(file_path_clean)

    if text is None:
        append_error(state, f"Failed to extract text from file: {file_path_clean}")
        return None

    return text


def read_document(state: GuardState, *, fw_config) -> GuardState:
    """
    Document ingestion node: Extracts text from multiple files.

    Supports:
    - images: Run OCR detector if available or fallback to VLM
    - PDFs: Extract text using pdfplumber
    - text files: Read as plain text

    Processes file_paths list and merges text with double newline separator.
    """
    if "raw_text" not in state:
        state["raw_text"] = ""

    file_paths = state.get("file_paths") or []

    if not file_paths:
        return state

    if "metadata" not in state:
        state["metadata"] = {}

    extracted_texts = []
    file_types_seen = []

    for file_path in file_paths:
        try:
            # Sanitize and validate file path
            if not isinstance(file_path, str):
                append_error(state, f"Invalid file path type: {type(file_path)}")
                continue

            file_path_clean = sanitize_file_path(file_path)

            if not os.path.exists(file_path_clean):
                append_error(state, f"File not found: {file_path}")
                continue

            file_type_def = FILE_TYPE_CONFIG.get_by_extension(file_path_clean)

            if not file_type_def:
                append_error(state, f"Unsupported file type: {file_path}")
                continue

            category = file_type_def.category
            file_types_seen.append(category)

            text = None
            if category == "image":
                text = _process_image_file(file_path_clean, state, fw_config)
            elif category == "pdf":
                text = _process_pdf_file(file_path_clean, state)
            elif category == "text":
                text = _process_text_file(file_path_clean, state)
            else:
                append_error(state, f"Unknown file category: {category}")
                continue

            if text:
                extracted_texts.append(text)

        except Exception as e:
            append_error(state, f"Document extraction error for {file_path}: {str(e)}")
            continue

    if file_types_seen:
        # For single file, store as file_type for backward compatibility
        state["metadata"]["file_type"] = file_types_seen[0]
        # Store all types for multi-file scenarios
        if len(file_types_seen) > 1:
            state["metadata"]["file_types"] = file_types_seen
            state["metadata"]["files_processed"] = len(extracted_texts)

    if extracted_texts:
        existing_text = state.get("raw_text", "")
        all_texts = [existing_text] if existing_text else []
        all_texts.extend(extracted_texts)
        state["raw_text"] = " ".join(all_texts)

    return state


def llm_ocr_document(state: GuardState, *, fw_config) -> GuardState:
    """
    LLM OCR fallback node: Uses vision-capable LLM to extract text from images
    when Tesseract OCR fails or returns empty results.

    Handles both single and multiple file scenarios by processing each image
    that needs OCR fallback individually.
    """
    metadata = state.get("metadata", {})
    images_needing_ocr = metadata.get("images_needing_llm_ocr", [])

    if not images_needing_ocr:
        return state

    try:
        llm_ocr_settings = fw_config.llm_ocr_config()
        llm_ocr = LLMOCRDetector(
            provider=llm_ocr_settings.provider,
            model=llm_ocr_settings.model,
            client_params=llm_ocr_settings.client_params,
        )

        extracted_texts = []

        for image_path in images_needing_ocr:
            try:
                temp_state: dict = dict(state)  # type: ignore
                temp_state["file_path"] = image_path

                text = llm_ocr(temp_state) or ""  # type: ignore

                if text:
                    extracted_texts.append(text)
                else:
                    append_warning(
                        state,
                        f"LLM OCR did not extract any text from image: {image_path}",
                    )
            except Exception as e:
                append_error(state, f"LLM OCR failed for {image_path}: {str(e)}")
                continue

        if extracted_texts:
            existing_text = state.get("raw_text", "")
            all_texts = [existing_text] if existing_text else []
            all_texts.extend(extracted_texts)
            state["raw_text"] = " ".join(all_texts)

            if "metadata" not in state:
                state["metadata"] = {}
            state["metadata"]["llm_ocr_used"] = True
            state["metadata"]["ocr_method"] = "llm"
            state["metadata"]["llm_ocr_images_processed"] = len(extracted_texts)

        if "images_needing_llm_ocr" in state["metadata"]:
            del state["metadata"]["images_needing_llm_ocr"]

    except Exception as e:
        append_error(state, f"LLM OCR initialization failed: {str(e)}")

    return state


__all__ = [
    "read_document",
    "llm_ocr_document",
    "sanitize_file_path",
    "extract_text_from_file",
    "is_image_file",
]
