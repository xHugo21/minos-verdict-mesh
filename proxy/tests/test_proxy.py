from __future__ import annotations

import json

import pytest
from mitmproxy import http
from mitmproxy.test.tflow import tflow

from app import llm_request_guard
from app.llm_request_guard import LLMRequestGuard


def make_flow(
    body: str | bytes, url: str = "https://api.openai.com/v1/chat/completions"
):
    request = http.Request.make(
        "POST",
        url,
        content=body,
        headers={"Content-Type": "application/json"},
    )
    return tflow(req=request)


@pytest.fixture
def interceptor() -> LLMRequestGuard:
    return LLMRequestGuard()


def test_stringify_handles_nested_structures(interceptor: LLMRequestGuard):
    payload = ["alpha", 42, {"text": "nested"}, None]

    assert interceptor._stringify(payload) == "alpha\n42\nnested"


def test_extract_payload_text_prefers_chat_messages(
    interceptor: LLMRequestGuard,
):
    payload = {
        "messages": [
            {"role": "system", "content": "setup"},
            {"role": "user", "content": ["hello", {"text": "world"}]},
            {"role": "assistant", "content": "ignored"},
        ],
        "prompt": "fallback",
    }

    text = interceptor._extract_payload_text(payload, "/v1/chat/completions")

    assert text == "hello\nworld"


def test_extract_payload_text_uses_prompt_for_non_chat_path(
    interceptor: LLMRequestGuard,
):
    payload = {"prompt": {"text": "linear"}}

    text = interceptor._extract_payload_text(payload, "/v1/completions")

    assert text == "linear"


def test_detection_headers_include_detected_fields(
    interceptor: LLMRequestGuard,
):
    result = {
        "risk_level": "high",
        "detected_fields": [
            {"field": "password"},
            {"field": "api_key"},
        ],
    }

    headers = interceptor._detection_headers(result)

    assert headers["X-LLM-Guard-Risk-Level"] == "high"
    assert "password" in headers["X-LLM-Guard-Detected-Fields"]
    assert "api_key" in headers["X-LLM-Guard-Detected-Fields"]


def test_should_block_uses_decision(interceptor: LLMRequestGuard):
    assert interceptor._should_block({"decision": "block"})
    assert not interceptor._should_block({"decision": "allow"})
    assert not interceptor._should_block({"risk_level": "high"})


def test_should_intercept_matches_configured_endpoints(
    interceptor: LLMRequestGuard,
):
    from unittest.mock import Mock

    flow = Mock()
    flow.request.method = "POST"
    flow.request.host = "api.openai.com"
    flow.request.path = "/v1/chat/completions"

    assert interceptor._should_intercept(flow)


def test_should_intercept_ignores_non_post_requests(
    interceptor: LLMRequestGuard,
):
    from unittest.mock import Mock

    flow = Mock()
    flow.request.method = "GET"
    flow.request.host = "api.openai.com"
    flow.request.path = "/v1/chat/completions"

    assert not interceptor._should_intercept(flow)


def test_should_intercept_ignores_non_configured_hosts(
    interceptor: LLMRequestGuard,
):
    from unittest.mock import Mock

    flow = Mock()
    flow.request.method = "POST"
    flow.request.host = "example.com"
    flow.request.path = "/v1/chat/completions"

    assert not interceptor._should_intercept(flow)


def test_should_intercept_ignores_non_configured_paths(
    interceptor: LLMRequestGuard,
):
    from unittest.mock import Mock

    flow = Mock()
    flow.request.method = "POST"
    flow.request.host = "api.openai.com"
    flow.request.path = "/v1/models"

    assert not interceptor._should_intercept(flow)


def test_ask_backend_handles_empty_text(interceptor: LLMRequestGuard):
    result = interceptor._ask_backend("")

    assert result is not None
    assert result["risk_level"] == "none"
    assert result["detected_fields"] == []


def test_ask_backend_posts_to_configured_url(
    interceptor: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    from unittest.mock import Mock, patch

    mock_url = "http://backend.test/detect"
    monkeypatch.setattr(llm_request_guard.config, "BACKEND_URL", mock_url)

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"risk_level": "none", "detected_fields": []}

    with patch("app.llm_request_guard.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.post.return_value = (
            mock_response
        )

        interceptor_with_mode = LLMRequestGuard()
        result = interceptor_with_mode._ask_backend("test text")

        call_args = mock_client.return_value.__enter__.return_value.post.call_args
        assert call_args[0][0] == mock_url
        assert call_args[1]["data"] == {
            "text": "test text",
            "min_block_level": llm_request_guard.config.MIN_BLOCK_LEVEL,
        }


def test_ask_backend_adds_auth_header_when_configured(
    interceptor: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    from unittest.mock import Mock, patch

    monkeypatch.setattr(llm_request_guard.config, "BACKEND_AUTH_TOKEN", "secret-token")

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"risk_level": "none", "detected_fields": []}

    with patch("app.llm_request_guard.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.post.return_value = (
            mock_response
        )

        interceptor._ask_backend("test text")

        call_args = mock_client.return_value.__enter__.return_value.post.call_args
        assert call_args[1]["headers"] == {"Authorization": "Bearer secret-token"}


def test_request_blocks_invalid_json_payload(interceptor: LLMRequestGuard):
    flow = make_flow(b"{not-json")

    interceptor.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.json()["error"]["code"] == "analysis_unavailable"


def test_request_blocks_when_backend_is_unavailable(
    interceptor: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow(json.dumps({"messages": [{"role": "user", "content": "hello"}]}))
    monkeypatch.setattr(interceptor, "_ask_backend", lambda text: None)

    interceptor.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 403
    assert flow.response.json()["error"]["code"] == "analysis_unavailable"


def test_request_stores_detection_result_for_response_hook(
    interceptor: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    flow = make_flow(json.dumps({"messages": [{"role": "user", "content": "hello"}]}))
    result = {
        "decision": "allow",
        "risk_level": "low",
        "detected_fields": [{"field": "email"}],
    }
    monkeypatch.setattr(interceptor, "_ask_backend", lambda text: result)

    interceptor.request(flow)

    assert flow.metadata[interceptor.DETECTION_RESULT_KEY] == result


def test_response_adds_detection_headers_from_flow_metadata(
    interceptor: LLMRequestGuard,
):
    flow = make_flow(json.dumps({"messages": [{"role": "user", "content": "hello"}]}))
    flow.response = http.Response.make(200, b"ok")
    flow.metadata[interceptor.DETECTION_RESULT_KEY] = {
        "risk_level": "medium",
        "detected_fields": [{"field": "password"}],
    }

    interceptor.response(flow)

    assert flow.response.headers["X-LLM-Guard-Risk-Level"] == "medium"
    assert flow.response.headers["X-LLM-Guard-Detected-Fields"] == "password"


def test_should_intercept_matches_gemini_host_when_path_is_configured(
    interceptor: LLMRequestGuard,
):
    interceptor.intercepted_hosts = ["generativelanguage.googleapis.com"]
    interceptor.intercepted_paths = ["/v1/chat/completions"]

    flow = make_flow(
        json.dumps({"contents": [{"parts": [{"text": "hello"}]}]}),
        url="https://generativelanguage.googleapis.com/v1/chat/completions",
    )

    assert interceptor._should_intercept(flow)
