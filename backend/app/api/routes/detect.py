import logging
import os
import tempfile
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Optional, Tuple, Dict, Any

from app.utils import debug_log
from multiagent_firewall import GuardOrchestrator
from multiagent_firewall.config import FILE_TYPE_CONFIG
from multiagent_firewall.utils import (
    FileValidationError,
    sanitize_filename,
    validate_file_size,
    validate_mime_type,
    validate_path_traversal,
)
from app.config import GUARD_CONFIG, DEFAULT_BLOCK_LEVEL

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_SNIPPET_LENGTH = 400


async def _validate_and_save_uploaded_file(
    file: UploadFile,
) -> Tuple[Path, Dict[str, Any]]:
    """
    Validate file security and save to temporary directory.

    - File size limits
    - Random filename
    - Path traversal protection
    - Extension validation
    - MIME type validation

    Args:
        file: Uploaded file

    Returns:
        Tuple of (file_path, metadata_dict) where metadata contains:
        - file_size_bytes: Size of uploaded file
        - original_filename: Original filename from upload

    Raises:
        HTTPException: For any validation failures (400, 413)
    """
    tmp_dir = Path(tempfile.gettempdir())

    safe_filename_str = sanitize_filename(file.filename)
    tmp_path = tmp_dir / safe_filename_str

    try:
        validate_path_traversal(tmp_path, tmp_dir)
    except FileValidationError as e:
        raise HTTPException(status_code=400, detail="Invalid file path")

    try:
        file_size = await validate_file_size(
            file,
            tmp_path,
            FILE_TYPE_CONFIG.global_max_size_bytes,
            FILE_TYPE_CONFIG.chunk_size_bytes,
        )
    except FileValidationError as e:
        raise HTTPException(status_code=413, detail=str(e))

    try:
        debug_log(
            f"[SensitiveDataDetectorBackend] Saved file to {tmp_path} ({file_size} bytes)"
        )

        file_type_def = FILE_TYPE_CONFIG.get_by_extension(file.filename or "")
        if not file_type_def:
            tmp_path.unlink()
            ext = Path(file.filename or "").suffix or "(no extension)"
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {ext}",
            )

        if FILE_TYPE_CONFIG.require_mime_validation:
            try:
                detected_mime = validate_mime_type(tmp_path, file_type_def.mime_types)
                debug_log(
                    f"[SensitiveDataDetectorBackend] Detected MIME: {detected_mime}"
                )
            except FileValidationError as e:
                tmp_path.unlink()
                raise HTTPException(
                    status_code=400,
                    detail="File validation failed: invalid file format",
                )

        metadata = {
            "file_size_bytes": file_size,
            "original_filename": file.filename,
        }
        return tmp_path, metadata

    except HTTPException:
        raise
    except Exception as e:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        logger.exception(f"Unexpected error saving file: {file.filename}")
        raise HTTPException(status_code=500, detail="File processing failed")


@router.post("/detect")
async def detect(
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    min_block_level: Optional[str] = Form(None),
):
    """
    Unified detection endpoint

    Args:
        text: Direct text input
        file: File upload
        min_block_level: Minimum risk level to trigger blocking actions

    Returns:
        Detection results from multiagent-firewall package
    """
    try:
        block_level = min_block_level or DEFAULT_BLOCK_LEVEL

        if not text and not file:
            raise HTTPException(
                status_code=400, detail="Either text or file must be provided"
            )

        if file:
            tmp_path, metadata = await _validate_and_save_uploaded_file(file)

            try:
                result = await GuardOrchestrator(GUARD_CONFIG).run(
                    file_path=str(tmp_path),
                    min_block_level=block_level,
                )

                if result.get("raw_text"):
                    result["extracted_snippet"] = result["raw_text"][
                        :MAX_SNIPPET_LENGTH
                    ]
                result.update(metadata)

                return result

            finally:
                try:
                    tmp_path.unlink()
                except FileNotFoundError:
                    pass  # Already deleted
                except OSError as e:
                    logger.warning(f"Failed to cleanup temp file: {e}")

        debug_log("[SensitiveDataDetectorBackend] Processing text:", text)
        result = await GuardOrchestrator(GUARD_CONFIG).run(
            text=text,
            min_block_level=block_level,
        )

        debug_log(
            "[SensitiveDataDetectorBackend] Detected fields:",
            result.get("detected_fields", []),
        )
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in /detect")
        raise HTTPException(status_code=500, detail="Internal server error")
