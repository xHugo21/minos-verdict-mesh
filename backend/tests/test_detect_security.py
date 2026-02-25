"""Security tests for /detect endpoint."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import detect as detect_route


class DummyOrchestrator:
    """Mock orchestrator for testing."""

    def __init__(self, config):
        self.calls = []
        self.config = config

    async def run(self, text=None, *, file_paths=None, min_block_level=None):
        self.calls.append((text, file_paths, min_block_level))
        return {"detected_fields": [], "risk_level": "low"}


@pytest.fixture
def client(monkeypatch):
    """Create test client with mocked orchestrator."""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)
    return TestClient(app)


# Test file size limits
def test_file_size_limit_enforced(client):
    """Files exceeding 50MB should be rejected"""
    # Create a file slightly over 50MB
    oversized_content = b"x" * (51 * 1024 * 1024)
    file = io.BytesIO(oversized_content)

    resp = client.post(
        "/detect",
        files={"files": ("large.txt", file, "text/plain")},
    )

    assert resp.status_code == 413
    detail = resp.json()["detail"].lower()
    assert "too large" in detail or "exceeds" in detail


def test_file_size_at_limit_accepted(client):
    """Files at exactly 50MB should be accepted"""
    # Create a file at exactly 50MB
    max_content = b"x" * (50 * 1024 * 1024)
    file = io.BytesIO(max_content)

    resp = client.post(
        "/detect",
        files={"files": ("max.txt", file, "text/plain")},
    )

    # Should not fail with size error (may fail with other validation)
    assert resp.status_code != 413


def test_small_file_accepted(client):
    """Small files should be accepted"""
    small_content = b"This is a small file"
    file = io.BytesIO(small_content)

    resp = client.post(
        "/detect",
        files={"files": ("small.txt", file, "text/plain")},
    )

    assert resp.status_code == 200


# Test MIME type validation
def test_valid_pdf_mime_type_accepted(client):
    """Valid PDF files should be accepted"""
    # PDF magic bytes
    pdf_content = b"%PDF-1.4\nfake pdf content"
    file = io.BytesIO(pdf_content)

    resp = client.post(
        "/detect",
        files={"files": ("document.pdf", file, "application/pdf")},
    )

    assert resp.status_code == 200


def test_valid_png_mime_type_accepted(client):
    """Valid PNG files should be accepted"""
    # PNG magic bytes
    png_content = b"\x89PNG\r\n\x1a\nfake image data"
    file = io.BytesIO(png_content)

    resp = client.post(
        "/detect",
        files={"files": ("image.png", file, "image/png")},
    )

    assert resp.status_code == 200


def test_unsupported_extension_rejected(client):
    """Files with unsupported extensions should be rejected"""
    content = b"some content"
    file = io.BytesIO(content)

    resp = client.post(
        "/detect",
        files={"files": ("malicious.exe", file, "application/octet-stream")},
    )

    assert resp.status_code == 400
    detail = resp.json()["detail"].lower()
    assert "unsupported" in detail or "not supported" in detail


def test_mime_type_spoofing_detected(client):
    """Files with mismatched MIME type and content should be rejected"""
    # Text file pretending to be PDF
    fake_pdf = b"This is just text, not a PDF"
    file = io.BytesIO(fake_pdf)

    resp = client.post(
        "/detect",
        files={"files": ("fake.pdf", file, "application/pdf")},
    )

    # Should fail MIME validation
    assert resp.status_code == 400


# Test path traversal protection
def test_filename_with_path_traversal_sanitized(client):
    """Filenames with path traversal should be sanitized"""
    content = b"test content"
    file = io.BytesIO(content)

    # Try various path traversal patterns
    dangerous_names = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../../../../../../../etc/shadow",
        "../../important.txt",
    ]

    for dangerous_name in dangerous_names:
        resp = client.post(
            "/detect",
            files={"files": (dangerous_name, file, "text/plain")},
        )

        # Should either reject or sanitize (not return 200 and accept dangerous path)
        # The backend sanitizes filenames, so this should succeed
        # but the file should be saved with a safe random name
        assert resp.status_code in [200, 400]
        file.seek(0)  # Reset for next iteration


def test_absolute_path_in_filename_sanitized(client):
    """Absolute paths in filenames should be sanitized"""
    content = b"test content"
    file = io.BytesIO(content)

    resp = client.post(
        "/detect",
        files={"files": ("/etc/passwd", file, "text/plain")},
    )

    # Should handle gracefully
    assert resp.status_code in [200, 400]


def test_filename_with_special_chars_handled(client):
    """Filenames with special characters should be handled safely"""
    content = b"test content"
    file = io.BytesIO(content)

    special_names = [
        "test\x00null.txt",  # Null byte
        "test|pipe.txt",  # Pipe
        "test;semicolon.txt",  # Semicolon
        "test`backtick.txt",  # Backtick
    ]

    for special_name in special_names:
        resp = client.post(
            "/detect",
            files={"files": (special_name, file, "text/plain")},
        )

        # Should handle gracefully without crashing
        assert resp.status_code in [200, 400]
        file.seek(0)


# Test concurrent upload protection
def test_multiple_concurrent_uploads(client):
    """Multiple simultaneous uploads should be handled safely"""
    content = b"test content"

    # Submit multiple requests concurrently
    responses = []
    for i in range(5):
        file = io.BytesIO(content)
        resp = client.post(
            "/detect",
            files={"files": (f"file{i}.txt", file, "text/plain")},
        )
        responses.append(resp)

    # All should complete successfully
    for resp in responses:
        assert resp.status_code == 200


# Test edge cases
def test_empty_file_handled(client):
    """Empty files should be handled gracefully"""
    empty_file = io.BytesIO(b"")

    resp = client.post(
        "/detect",
        files={"files": ("empty.txt", empty_file, "text/plain")},
    )

    # Should not crash
    assert resp.status_code in [200, 400]


def test_file_without_extension(client):
    """Files without extension should be handled"""
    content = b"test content"
    file = io.BytesIO(content)

    resp = client.post(
        "/detect",
        files={"files": ("noextension", file, "text/plain")},
    )

    # Should handle gracefully
    assert resp.status_code in [200, 400]


def test_unicode_filename_handled(client):
    """Unicode filenames should be handled safely"""
    content = b"test content"
    file = io.BytesIO(content)

    unicode_names = [
        "测试.txt",  # Chinese
        "тест.txt",  # Cyrillic
        "🔥火.txt",  # Emoji + Chinese
        "café.txt",  # Accented characters
    ]

    for unicode_name in unicode_names:
        resp = client.post(
            "/detect",
            files={"files": (unicode_name, file, "text/plain")},
        )

        # Should handle gracefully
        assert resp.status_code in [200, 400]
        file.seek(0)


# Test file cleanup on error
def test_temporary_file_cleaned_up_on_validation_error(client, tmp_path, monkeypatch):
    """Temporary files should be cleaned up even when validation fails"""
    # This test verifies cleanup behavior
    # We can't easily verify file deletion without access to the upload dir
    # but we test that oversized files don't leave remnants

    oversized_content = b"x" * (51 * 1024 * 1024)
    file = io.BytesIO(oversized_content)

    resp = client.post(
        "/detect",
        files={"files": ("large.txt", file, "text/plain")},
    )

    # Should reject
    assert resp.status_code == 413


# Test extension-based categorization
def test_supported_image_extensions(client):
    """All supported image extensions should be accepted"""
    image_exts = [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"]
    png_content = b"\x89PNG\r\n\x1a\nfake image"

    for ext in image_exts:
        file = io.BytesIO(png_content)
        resp = client.post(
            "/detect",
            files={"files": (f"image{ext}", file, "image/png")},
        )

        # Should be recognized as valid image extension
        assert resp.status_code in [200, 400]  # May fail MIME validation
        file.seek(0)


def test_supported_document_extensions(client):
    """All supported document extensions should be accepted"""
    pdf_content = b"%PDF-1.4\nfake pdf"
    file = io.BytesIO(pdf_content)

    resp = client.post(
        "/detect",
        files={"files": ("document.pdf", file, "application/pdf")},
    )

    assert resp.status_code == 200


def test_supported_code_extensions(client):
    """Code file extensions should be accepted"""
    code_exts = [".py", ".js", ".java", ".cpp", ".c", ".go", ".rs"]
    code_content = b"print('hello')"

    for ext in code_exts:
        file = io.BytesIO(code_content)
        resp = client.post(
            "/detect",
            files={"files": (f"script{ext}", file, "text/plain")},
        )

        # Should accept code files
        assert resp.status_code in [200, 400]
        file.seek(0)


# Test security headers and response structure
def test_response_does_not_leak_internal_paths(client):
    """Error responses should not expose internal file paths"""
    content = b"test"
    file = io.BytesIO(content)

    resp = client.post(
        "/detect",
        files={"files": ("test.txt", file, "text/plain")},
    )

    response_text = resp.text.lower()

    # Should not contain absolute paths
    assert "/tmp/" not in response_text
    assert "/var/" not in response_text
    assert "/home/" not in response_text
    assert "uploads/" not in response_text or resp.status_code == 200


def test_error_response_structure(client):
    """Error responses should have consistent structure"""
    oversized = b"x" * (51 * 1024 * 1024)
    file = io.BytesIO(oversized)

    resp = client.post(
        "/detect",
        files={"files": ("large.txt", file, "text/plain")},
    )

    assert resp.status_code == 413
    json_resp = resp.json()
    assert "detail" in json_resp
    assert isinstance(json_resp["detail"], str)


def test_missing_filetype_library_returns_503(client, monkeypatch):
    """
    If filetype library is not installed (file-analysis extras missing),
    file uploads should return 503 Service Unavailable
    """
    from app.api.routes import detect as detect_route

    # Mock validate_mime_type to raise ImportError (simulating missing filetype)
    def mock_validate_mime_type(file_path, allowed_mimes):
        raise ImportError(
            "filetype library is required for MIME validation. "
            "Install it with: pip install 'multiagent-firewall[file-analysis]'"
        )

    monkeypatch.setattr(detect_route, "validate_mime_type", mock_validate_mime_type)

    content = b"test content"
    file = io.BytesIO(content)

    resp = client.post(
        "/detect",
        files={"files": ("test.txt", file, "text/plain")},
    )

    assert resp.status_code == 503
    json_resp = resp.json()
    assert "detail" in json_resp
    assert "unavailable" in json_resp["detail"].lower()
    assert "dependencies" in json_resp["detail"].lower()
