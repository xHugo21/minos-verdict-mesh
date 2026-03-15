from __future__ import annotations

import json

import pytest
from mitmproxy import http
from mitmproxy.test.tflow import tflow

from app.llm_request_guard import LLMRequestGuard


def make_flow(
    payload: dict | str | bytes,
    *,
    url: str = "https://api.openai.com/v1/chat/completions",
) -> http.HTTPFlow:
    if isinstance(payload, dict):
        content: str | bytes = json.dumps(payload)
    else:
        content = payload

    request = http.Request.make(
        "POST",
        url,
        content=content,
        headers={"Content-Type": "application/json"},
    )
    return tflow(req=request)


@pytest.fixture
def guard() -> LLMRequestGuard:
    return LLMRequestGuard()


@pytest.mark.integration
def test_request_then_response_adds_detection_headers_to_forwarded_response(
    guard: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow({"messages": [{"role": "user", "content": "hello"}]})
    result = {
        "decision": "allow",
        "risk_level": "low",
        "detected_fields": [{"field": "email"}],
    }
    monkeypatch.setattr(guard, "_ask_backend", lambda text: result)

    guard.request(flow)

    assert flow.response is None
    assert flow.metadata[guard.DETECTION_RESULT_KEY] == result

    flow.response = http.Response.make(200, b'{"ok":true}')

    guard.response(flow)

    assert flow.response.headers["X-LLM-Guard-Risk-Level"] == "low"
    assert flow.response.headers["X-LLM-Guard-Detected-Fields"] == "email"


@pytest.mark.integration
def test_request_blocks_and_skips_upstream_response_processing(
    guard: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow({"messages": [{"role": "user", "content": "secret 123"}]})
    monkeypatch.setattr(
        guard,
        "_ask_backend",
        lambda text: {
            "decision": "block",
            "risk_level": "high",
            "detected_fields": [{"field": "api_key"}],
            "remediation": "remove secrets",
        },
    )

    guard.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.json()["error"]["code"] == "sensitive_data"
    assert flow.response.headers["X-LLM-Guard-Detected-Fields"] == "api_key"


@pytest.mark.integration
def test_request_with_images_uses_combined_backend_submission(
    guard: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "check this"},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
                            },
                        },
                    ],
                }
            ]
        }
    )
    calls: list[tuple[str, list[dict[str, str]]]] = []

    def fake_backend(text: str, images: list[dict[str, str]]):
        calls.append((text, images))
        return {"decision": "allow", "risk_level": "low", "detected_fields": []}

    monkeypatch.setattr(guard, "_ask_backend_with_text_and_files", fake_backend)

    guard.request(flow)

    assert flow.response is None
    assert len(calls) == 1
    assert calls[0][0] == "check this"
    assert calls[0][1][0]["source"] == "openai"


@pytest.mark.integration
def test_request_blocks_when_payload_has_no_supported_content(guard: LLMRequestGuard):
    flow = make_flow({"messages": [{"role": "assistant", "content": "ignored"}]})

    guard.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.json()["error"]["code"] == "analysis_unavailable"


@pytest.mark.integration
def test_request_for_non_intercepted_endpoint_bypasses_analysis(
    guard: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow(
        {"messages": [{"role": "user", "content": "hello"}]},
        url="https://example.com/v1/chat/completions",
    )
    called = False

    def fake_backend(text: str):
        nonlocal called
        called = True
        return {"decision": "allow", "risk_level": "low", "detected_fields": []}

    monkeypatch.setattr(guard, "_ask_backend", fake_backend)

    guard.request(flow)

    assert flow.response is None
    assert not called
