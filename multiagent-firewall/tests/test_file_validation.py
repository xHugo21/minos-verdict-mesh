from __future__ import annotations

import pytest
import tempfile
from pathlib import Path
from io import BytesIO
from multiagent_firewall.utils import (
    FileValidationError,
    validate_file_size,
    validate_mime_type,
    sanitize_filename,
    validate_path_traversal,
)


# Mock async file object for testing
class MockAsyncFile:
    """Mock async file-like object for testing streaming validation"""

    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    async def read(self, size: int) -> bytes:
        """Read up to size bytes from the data"""
        chunk = self.data[self.position : self.position + size]
        self.position += len(chunk)
        return chunk


# Test validate_file_size (async streaming)
@pytest.mark.asyncio
async def test_validate_file_size_within_limit():
    """Valid file size should pass without error"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "test_file.bin"
        mock_file = MockAsyncFile(b"x" * 1024)  # 1 KB

        file_size = await validate_file_size(
            mock_file,
            tmp_path,
            max_size_bytes=1024 * 1024,  # 1 MB limit
            chunk_size_bytes=4096,
        )

        assert file_size == 1024
        assert tmp_path.exists()
        assert tmp_path.stat().st_size == 1024


@pytest.mark.asyncio
async def test_validate_file_size_at_exact_limit():
    """File at exact size limit should pass"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "test_file.bin"
        mock_file = MockAsyncFile(b"x" * (1024 * 1024))  # Exactly 1 MB

        file_size = await validate_file_size(
            mock_file,
            tmp_path,
            max_size_bytes=1024 * 1024,  # 1 MB limit
            chunk_size_bytes=4096,
        )

        assert file_size == 1024 * 1024
        assert tmp_path.exists()


@pytest.mark.asyncio
async def test_validate_file_size_exceeds_limit():
    """File exceeding size limit should raise FileValidationError"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "test_file.bin"
        mock_file = MockAsyncFile(b"x" * (2 * 1024 * 1024))  # 2 MB

        with pytest.raises(FileValidationError, match="File size .* exceeds"):
            await validate_file_size(
                mock_file,
                tmp_path,
                max_size_bytes=1024 * 1024,  # 1 MB limit
                chunk_size_bytes=4096,
            )

        # File should be cleaned up after error
        assert not tmp_path.exists()


@pytest.mark.asyncio
async def test_validate_file_size_nonexistent_file():
    """Writing to nonexistent directory should raise error"""
    fake_path = Path("/nonexistent/directory/file.txt")
    mock_file = MockAsyncFile(b"x" * 1024)

    with pytest.raises(FileValidationError, match="Failed to write file"):
        await validate_file_size(
            mock_file, fake_path, max_size_bytes=10 * 1024 * 1024, chunk_size_bytes=4096
        )


# Test validate_mime_type
def test_validate_mime_type_valid_png():
    """Valid PNG file should pass MIME validation"""
    # PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
    png_header = b"\x89PNG\r\n\x1a\n"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(png_header)
        tmp.write(b"fake image data")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        validate_mime_type(tmp_path, allowed_mimes={"image/png"})
    finally:
        tmp_path.unlink()


def test_validate_mime_type_valid_pdf():
    """Valid PDF file should pass MIME validation"""
    # PDF magic bytes: %PDF-
    pdf_header = b"%PDF-1.4\n"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        tmp.write(pdf_header)
        tmp.write(b"fake pdf content")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        validate_mime_type(tmp_path, allowed_mimes={"application/pdf"})
    finally:
        tmp_path.unlink()


def test_validate_mime_type_invalid_mime():
    """File with wrong MIME type should raise FileValidationError"""
    # Text file pretending to be a PDF
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", mode="w") as tmp:
        tmp.write("This is just text, not a PDF")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        with pytest.raises(FileValidationError, match="Cannot determine file type"):
            validate_mime_type(tmp_path, allowed_mimes={"application/pdf"})
    finally:
        tmp_path.unlink()


def test_validate_mime_type_unknown_type():
    """File with no detected MIME type should raise FileValidationError"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"random binary data")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        with pytest.raises(FileValidationError, match="Cannot determine file type"):
            validate_mime_type(tmp_path, allowed_mimes={"image/png"})
    finally:
        tmp_path.unlink()


def test_validate_mime_type_multiple_allowed():
    """File matching one of multiple allowed MIME types should pass"""
    png_header = b"\x89PNG\r\n\x1a\n"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(png_header)
        tmp.write(b"fake image data")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        validate_mime_type(
            tmp_path, allowed_mimes={"image/jpeg", "image/png", "application/pdf"}
        )
    finally:
        tmp_path.unlink()


# Test sanitize_filename
def test_sanitize_filename_basic():
    """Generated filename should be secure and random"""
    filename1 = sanitize_filename("original.txt")
    filename2 = sanitize_filename("original.txt")

    # Should be different (random)
    assert filename1 != filename2

    # Should be 32 characters + extension (16 bytes in hex + ".txt")
    assert len(filename1) == 36  # 32 hex + ".txt"
    assert len(filename2) == 36

    # Should end with correct extension
    assert filename1.endswith(".txt")
    assert filename2.endswith(".txt")

    # Base name should only contain hex characters
    base1 = filename1[:-4]
    base2 = filename2[:-4]
    assert all(c in "0123456789abcdef" for c in base1)
    assert all(c in "0123456789abcdef" for c in base2)


def test_sanitize_filename_with_extension():
    """Generated filename with different extensions should preserve them"""
    filename1 = sanitize_filename("document.pdf")
    filename2 = sanitize_filename("image.png")

    # Should end with correct extension
    assert filename1.endswith(".pdf")
    assert filename2.endswith(".png")

    # Should still have random base name
    base1 = filename1[:-4]
    base2 = filename2[:-4]
    assert len(base1) == 32
    assert len(base2) == 32
    assert base1 != base2


def test_sanitize_filename_no_path_traversal():
    """Generated filenames should never contain path traversal sequences"""
    for _ in range(100):
        filename = sanitize_filename("test.txt")
        assert ".." not in filename
        assert "/" not in filename
        assert "\\" not in filename


# Test validate_path_traversal
def test_validate_path_traversal_safe_path():
    """Path within allowed directory should pass"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir)
        safe_file = allowed_dir / "safe_file.txt"
        safe_file.touch()

        validate_path_traversal(safe_file, allowed_dir)


def test_validate_path_traversal_nested_safe_path():
    """Nested path within allowed directory should pass"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir)
        subdir = allowed_dir / "subdir"
        subdir.mkdir()
        safe_file = subdir / "safe_file.txt"
        safe_file.touch()

        validate_path_traversal(safe_file, allowed_dir)


def test_validate_path_traversal_parent_directory():
    """Path outside allowed directory should raise FileValidationError"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir) / "allowed"
        allowed_dir.mkdir()

        # Try to access parent
        dangerous_path = allowed_dir / ".." / "dangerous.txt"

        with pytest.raises(FileValidationError, match="outside allowed directory"):
            validate_path_traversal(dangerous_path, allowed_dir)


def test_validate_path_traversal_symlink_attack():
    """Symlink pointing outside allowed directory should raise FileValidationError"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir) / "allowed"
        allowed_dir.mkdir()

        outside_dir = Path(tmpdir) / "outside"
        outside_dir.mkdir()
        outside_file = outside_dir / "secret.txt"
        outside_file.write_text("secret data")

        # Create symlink inside allowed_dir pointing to outside file
        symlink_path = allowed_dir / "link_to_secret.txt"
        symlink_path.symlink_to(outside_file)

        with pytest.raises(FileValidationError, match="outside allowed directory"):
            validate_path_traversal(symlink_path, allowed_dir)


def test_validate_path_traversal_absolute_path_outside():
    """Absolute path outside allowed directory should raise FileValidationError"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir) / "allowed"
        allowed_dir.mkdir()

        # Absolute path to /etc/passwd (or similar)
        dangerous_path = Path("/etc/passwd")

        with pytest.raises(FileValidationError, match="outside allowed directory"):
            validate_path_traversal(dangerous_path, allowed_dir)


# Edge cases and integration tests
@pytest.mark.asyncio
async def test_validate_file_size_empty_file():
    """Empty file should pass validation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "empty_file.bin"
        mock_file = MockAsyncFile(b"")  # Empty file

        file_size = await validate_file_size(
            mock_file,
            tmp_path,
            max_size_bytes=1024 * 1024,  # 1 MB limit
            chunk_size_bytes=4096,
        )

        assert file_size == 0
        assert tmp_path.exists()
        assert tmp_path.stat().st_size == 0


def test_validate_mime_type_text_file():
    """Plain text file should fail validation if not in allowed types"""
    with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".txt") as tmp:
        tmp.write("This is plain text")
        tmp.flush()
        tmp_path = Path(tmp.name)

    try:
        with pytest.raises(FileValidationError):
            validate_mime_type(tmp_path, allowed_mimes={"image/png", "application/pdf"})
    finally:
        tmp_path.unlink()


def test_sanitize_filename_uniqueness():
    """Generated filenames should be statistically unique"""
    filenames = {sanitize_filename("test.txt") for _ in range(1000)}

    # All 1000 should be unique
    assert len(filenames) == 1000


@pytest.mark.asyncio
async def test_full_validation_workflow():
    """Complete workflow: stream file, validate size, MIME, and path"""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_dir = Path(tmpdir)

        # Create a valid PNG file via streaming
        safe_filename = sanitize_filename("upload.png")
        file_path = allowed_dir / safe_filename

        png_header = b"\x89PNG\r\n\x1a\n"
        png_data = png_header + b"image data"
        mock_file = MockAsyncFile(png_data)

        # Stream and validate size
        file_size = await validate_file_size(
            mock_file,
            file_path,
            max_size_bytes=1024 * 1024,  # 1 MB limit
            chunk_size_bytes=4096,
        )

        assert file_size == len(png_data)

        # Validate MIME and path
        validate_mime_type(file_path, allowed_mimes={"image/png"})
        validate_path_traversal(file_path, allowed_dir)
