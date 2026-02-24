from __future__ import annotations

import logging
import secrets
from pathlib import Path

from .exceptions import FileValidationError

logger = logging.getLogger(__name__)


async def validate_file_size(
    file_obj,
    file_path: Path,
    max_size_bytes: int,
    chunk_size_bytes: int,
) -> int:
    """
    Validates file size during streaming to prevent writing
    oversized files to disk

    Args:
        file_obj: Async file-like object to read from (e.g., FastAPI UploadFile)
        file_path: Destination path to write file
        max_size_bytes: Maximum allowed size in bytes
        chunk_size_bytes: Size of chunks to read/write

    Returns:
        Total bytes written

    Raises:
        FileValidationError: If file exceeds size limit during streaming
    """
    file_size = 0

    try:
        with open(file_path, "wb") as f:
            while chunk := await file_obj.read(chunk_size_bytes):
                file_size += len(chunk)

                if file_size > max_size_bytes:
                    try:
                        file_path.unlink()
                    except OSError:
                        pass

                    max_mb = max_size_bytes / (1024 * 1024)
                    actual_mb = file_size / (1024 * 1024)
                    raise FileValidationError(
                        f"File size {actual_mb:.2f}MB exceeds limit of {max_mb:.0f}MB"
                    )

                f.write(chunk)
    except FileValidationError:
        raise
    except Exception as e:
        try:
            file_path.unlink()
        except OSError:
            pass
        raise FileValidationError(f"Failed to write file: {str(e)}") from e

    return file_size


def validate_mime_type(
    file_path: Path,
    allowed_mimes: set[str],
) -> str:
    """
    Validate file MIME type using filetype library.

    Args:
        file_path: Path to file to validate
        allowed_mimes: Set of allowed MIME types

    Returns:
        Detected MIME type string

    Raises:
        FileValidationError: If MIME type is not allowed or cannot be determined
        ImportError: If filetype library is not installed (falls back to warning)
    """
    try:
        import filetype
    except ImportError:
        logger.warning("filetype library not installed, skipping MIME validation")
        return "application/octet-stream"

    kind = filetype.guess(str(file_path))

    if kind is None:
        # No magic number - assume text file
        logger.info(f"No magic number detected, assuming text file: {file_path.name}")
        # Check if text MIME is allowed
        if "text/plain" in allowed_mimes:
            return "text/plain"
        raise FileValidationError(f"Cannot determine file type for {file_path.name}")

    detected_mime = kind.mime

    if detected_mime not in allowed_mimes:
        raise FileValidationError(
            f"File type '{detected_mime}' not supported. "
            f"Allowed types: {', '.join(sorted(allowed_mimes))}"
        )

    return detected_mime


def sanitize_filename(filename: str | None) -> str:
    """
    Generate safe random filename preserving extension.
    Prevents path traversal attacks.

    Args:
        filename: Original filename (may contain path separators)

    Returns:
        Cryptographically secure random filename with preserved extension

    Example:
        >>> sanitize_filename("../../etc/passwd.txt")
        'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.txt'
    """
    if filename:
        ext = Path(filename).suffix.lower()
    else:
        ext = ""

    safe_name = f"{secrets.token_hex(16)}{ext}"
    return safe_name


def validate_path_traversal(file_path: Path, allowed_dir: Path) -> None:
    """
    Ensure file_path is within allowed_dir (no path traversal).

    Args:
        file_path: Path to validate
        allowed_dir: Directory that path must be within

    Raises:
        FileValidationError: If path is outside allowed directory
    """
    try:
        resolved = file_path.resolve()
        allowed = allowed_dir.resolve()

        # Check if resolved path is relative to allowed directory
        resolved.relative_to(allowed)
    except (ValueError, RuntimeError) as e:
        raise FileValidationError(
            f"Invalid file path: {file_path} is outside allowed directory {allowed_dir}"
        ) from e
