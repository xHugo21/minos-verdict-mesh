from __future__ import annotations

import pytest

from app.llm_request_guard import LLMRequestGuard


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

    assert result["risk_level"] == "none"
    assert result["detected_fields"] == []


def test_ask_backend_posts_to_configured_url(
    interceptor: LLMRequestGuard, monkeypatch: pytest.MonkeyPatch
):
    from app import config
    from unittest.mock import Mock, patch

    mock_url = "http://backend.test/detect"
    monkeypatch.setattr(config, "BACKEND_URL", mock_url)

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
            "min_block_level": config.MIN_BLOCK_LEVEL,
        }
