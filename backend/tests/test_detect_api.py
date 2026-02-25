from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import detect as detect_route


class DummyOrchestrator:
    def __init__(self, config):
        self.calls = []
        self.config = config

    async def run(self, text=None, *, file_paths=None, min_block_level=None):
        self.calls.append((text, file_paths, min_block_level))
        return {"detected_fields": [{"field": "EMAIL"}], "risk_level": "low"}


def test_detect_endpoint_with_text_uses_orchestrator(monkeypatch):
    """Test detect endpoint with text parameter"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)
    resp = client.post("/detect", data={"text": "hello"})

    assert resp.status_code == 200
    assert resp.json()["detected_fields"] == [{"field": "EMAIL"}]
    call_text, call_file_paths, call_threshold = dummy.calls[0]
    assert call_text == "hello"
    assert call_file_paths is None
    assert call_threshold == "medium"


def test_detect_endpoint_with_min_block_level_override(monkeypatch):
    """Test detect endpoint with explicit min_block_level parameter"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "high")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)
    resp = client.post("/detect", data={"text": "hello", "min_block_level": "low"})

    assert resp.status_code == 200
    call_text, call_file_paths, call_threshold = dummy.calls[0]
    assert call_threshold == "low"


def test_detect_endpoint_with_file(monkeypatch, tmp_path):
    """Test detect endpoint with file upload"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)
    file_path = tmp_path / "sample.txt"
    file_path.write_text("file text content", encoding="utf-8")

    with file_path.open("rb") as f:
        resp = client.post(
            "/detect",
            files={"files": ("sample.txt", f, "text/plain")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert dummy.calls
    call_text, call_file_paths, call_threshold = dummy.calls[0]
    assert call_text is None
    # File should now be passed via file_paths (list)
    assert call_file_paths is not None
    assert len(call_file_paths) == 1
    assert call_threshold == "medium"


def test_detect_endpoint_with_text_and_file(monkeypatch, tmp_path):
    """Test detect endpoint with BOTH text and file upload"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)
    file_path = tmp_path / "sample.txt"
    file_path.write_text("file text content", encoding="utf-8")

    with file_path.open("rb") as f:
        resp = client.post(
            "/detect",
            data={"text": "user provided text"},
            files={"files": ("sample.txt", f, "text/plain")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert dummy.calls
    call_text, call_file_paths, call_threshold = dummy.calls[0]
    # Both text and file should be passed to orchestrator
    assert call_text == "user provided text"
    assert call_file_paths is not None
    assert len(call_file_paths) == 1
    assert call_threshold == "medium"


def test_detect_endpoint_requires_input():
    """Test that detect endpoint requires either text or files"""
    client = TestClient(app)
    resp = client.post("/detect", data={})

    assert resp.status_code == 400
    body = resp.json()
    assert "detail" in body
    assert "text or files" in body["detail"].lower()


def test_detect_endpoint_with_multiple_files(monkeypatch, tmp_path):
    """Test detect endpoint with multiple file uploads"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)

    # Create multiple test files
    file1 = tmp_path / "file1.txt"
    file1.write_text("first file content", encoding="utf-8")

    file2 = tmp_path / "file2.txt"
    file2.write_text("second file content", encoding="utf-8")

    file3 = tmp_path / "file3.txt"
    file3.write_text("third file content", encoding="utf-8")

    with file1.open("rb") as f1, file2.open("rb") as f2, file3.open("rb") as f3:
        resp = client.post(
            "/detect",
            data={"text": "user text"},
            files=[
                ("files", ("file1.txt", f1, "text/plain")),
                ("files", ("file2.txt", f2, "text/plain")),
                ("files", ("file3.txt", f3, "text/plain")),
            ],
        )

    assert resp.status_code == 200
    body = resp.json()
    assert dummy.calls
    call_text, call_file_paths, call_threshold = dummy.calls[0]
    assert call_text == "user text"
    assert call_file_paths is not None
    assert len(call_file_paths) == 3
    assert call_threshold == "medium"


def test_detect_endpoint_max_files_limit(monkeypatch, tmp_path):
    """Test that detect endpoint enforces max files limit"""
    dummy = DummyOrchestrator("dummy-config")
    monkeypatch.setattr(detect_route, "GUARD_CONFIG", "dummy-config")
    monkeypatch.setattr(detect_route, "DEFAULT_BLOCK_LEVEL", "medium")
    monkeypatch.setattr(detect_route, "GuardOrchestrator", lambda config: dummy)

    client = TestClient(app)

    # Create 11 test files (exceeds limit of 10)
    files_list = []
    for i in range(11):
        file_path = tmp_path / f"file{i}.txt"
        file_path.write_text(f"content {i}", encoding="utf-8")
        files_list.append(file_path)

    with (
        open(files_list[0], "rb") as f0,
        open(files_list[1], "rb") as f1,
        open(files_list[2], "rb") as f2,
        open(files_list[3], "rb") as f3,
        open(files_list[4], "rb") as f4,
        open(files_list[5], "rb") as f5,
        open(files_list[6], "rb") as f6,
        open(files_list[7], "rb") as f7,
        open(files_list[8], "rb") as f8,
        open(files_list[9], "rb") as f9,
        open(files_list[10], "rb") as f10,
    ):
        resp = client.post(
            "/detect",
            files=[
                ("files", (f"file{i}.txt", f, "text/plain"))
                for i, f in enumerate([f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10])
            ],
        )

    assert resp.status_code == 400
    body = resp.json()
    assert "detail" in body
    assert "Too many files" in body["detail"]
    assert "10" in body["detail"]
