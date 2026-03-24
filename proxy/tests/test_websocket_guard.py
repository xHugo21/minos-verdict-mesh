from __future__ import annotations

import json

import pytest
from mitmproxy import websocket
from mitmproxy.test.tflow import twebsocketflow
from wsproto.frame_protocol import Opcode

from app.llm_request_guard import LLMRequestGuard


def make_ws_flow(
    message: websocket.WebSocketMessage,
    *,
    host: str = "api.openai.com",
    path: str = "/v1/realtime",
):
    flow = twebsocketflow(messages=False)
    flow.request.host = host
    flow.request.path = path
    assert flow.websocket is not None
    flow.websocket.messages = [message]
    return flow


@pytest.fixture
def guard() -> LLMRequestGuard:
    interceptor = LLMRequestGuard()
    interceptor.intercepted_hosts = ["api.openai.com"]
    interceptor.intercepted_ws_paths = ["/v1/realtime"]
    return interceptor


def test_should_intercept_websocket_requires_configured_paths(guard: LLMRequestGuard):
    flow = make_ws_flow(websocket.WebSocketMessage(Opcode.TEXT, True, b"hello"))
    guard.intercepted_ws_paths = []

    guard._sync_engines()
    assert not guard.websocket_guard.should_intercept_websocket(flow)


def test_should_intercept_websocket_matches_host_and_path(guard: LLMRequestGuard):
    flow = make_ws_flow(websocket.WebSocketMessage(Opcode.TEXT, True, b"hello"))

    guard._sync_engines()
    assert guard.websocket_guard.should_intercept_websocket(flow)


def test_websocket_message_ignores_server_to_client_frames(guard: LLMRequestGuard):
    payload = json.dumps({"messages": [{"role": "user", "content": "hello"}]})
    flow = make_ws_flow(
        websocket.WebSocketMessage(Opcode.TEXT, False, payload.encode())
    )

    called = False

    def fake_backend(text: str):
        nonlocal called
        called = True
        return {"decision": "allow", "risk_level": "low", "detected_fields": []}

    guard.ask_backend = fake_backend  # type: ignore[method-assign]

    guard.websocket_message(flow)

    assert not called


def test_websocket_message_sends_text_and_media_to_backend(
    guard: LLMRequestGuard,
):
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "check this image"},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                        },
                    },
                ],
            }
        ]
    }
    flow = make_ws_flow(
        websocket.WebSocketMessage(Opcode.TEXT, True, json.dumps(payload).encode())
    )

    calls: list[tuple[str, list[dict[str, str]]]] = []

    def fake_backend(text: str, images: list[dict[str, str]]):
        calls.append((text, images))
        return {"decision": "allow", "risk_level": "low", "detected_fields": []}

    guard.ask_backend_with_text_and_files = fake_backend  # type: ignore[method-assign]

    guard.websocket_message(flow)

    assert len(calls) == 1
    assert "check this image" in calls[0][0]
    assert calls[0][1][0]["mime_type"] == "image/png"
    assert calls[0][1][0]["source"] == "websocket_openai"


def test_websocket_message_drops_client_frame_when_blocked(guard: LLMRequestGuard):
    payload = json.dumps({"messages": [{"role": "user", "content": "secret 123"}]})
    message = websocket.WebSocketMessage(Opcode.TEXT, True, payload.encode())
    flow = make_ws_flow(message)

    guard.ask_backend = (  # type: ignore[method-assign]
        lambda text: {
            "decision": "block",
            "risk_level": "high",
            "detected_fields": [{"field": "api_key"}],
        }
    )

    guard.websocket_message(flow)

    assert message.dropped


def test_websocket_message_drops_on_backend_unavailable(guard: LLMRequestGuard):
    payload = json.dumps({"messages": [{"role": "user", "content": "hello"}]})
    message = websocket.WebSocketMessage(Opcode.TEXT, True, payload.encode())
    flow = make_ws_flow(message)

    guard.ask_backend = lambda text: None  # type: ignore[method-assign]

    guard.websocket_message(flow)

    assert message.dropped


def test_websocket_message_extracts_binary_images(guard: LLMRequestGuard):
    png_stub = b"\x89PNG\r\n\x1a\nrest"
    message = websocket.WebSocketMessage(Opcode.BINARY, True, png_stub)
    flow = make_ws_flow(message)

    calls: list[tuple[str, list[dict[str, str]]]] = []

    def fake_backend(text: str, images: list[dict[str, str]]):
        calls.append((text, images))
        return {"decision": "allow", "risk_level": "low", "detected_fields": []}

    guard.ask_backend_with_text_and_files = fake_backend  # type: ignore[method-assign]

    guard.websocket_message(flow)

    assert len(calls) == 1
    assert calls[0][0] == ""
    assert calls[0][1][0]["mime_type"] == "image/png"
    assert calls[0][1][0]["source"] == "websocket_binary"
