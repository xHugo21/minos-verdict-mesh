from __future__ import annotations

import json
from typing import Any

from mitmproxy.http import HTTPFlow

from .extractors import PayloadExtractor
from .http_guard import DetectorClient
from .http_guard import HTTPGuardEngine


class WebSocketGuardEngine:
    def __init__(
        self,
        *,
        intercepted_hosts: list[str],
        intercepted_ws_paths: list[str],
        detector_client: DetectorClient,
        extractor: PayloadExtractor,
        http_guard: HTTPGuardEngine,
        websocket_detection_results_key: str,
    ):
        self.intercepted_hosts = intercepted_hosts
        self.intercepted_ws_paths = [path.lower() for path in intercepted_ws_paths]
        self.detector_client = detector_client
        self.extractor = extractor
        self.http_guard = http_guard
        self.websocket_detection_results_key = websocket_detection_results_key

    def should_intercept_websocket(self, flow: HTTPFlow) -> bool:
        if not self.intercepted_ws_paths:
            return False
        if flow.websocket is None:
            return False

        host = flow.request.host.lower()
        if not any(host.endswith(h) for h in self.intercepted_hosts):
            return False

        path = flow.request.path.lower()
        if not any(path.startswith(p) for p in self.intercepted_ws_paths):
            return False

        return True

    def store_websocket_detection_result(
        self, flow: HTTPFlow, result: dict[str, Any]
    ) -> None:
        existing = flow.metadata.get(self.websocket_detection_results_key)
        if not isinstance(existing, list):
            existing = []
        existing.append(result)
        flow.metadata[self.websocket_detection_results_key] = existing

    def on_websocket_message(self, flow: HTTPFlow) -> None:
        if not self.should_intercept_websocket(flow):
            return
        if flow.websocket is None or not flow.websocket.messages:
            return

        message = flow.websocket.messages[-1]
        if not message.from_client:
            return

        payload: Any = None
        if message.is_text:
            try:
                payload = json.loads(message.text)
            except json.JSONDecodeError:
                payload = message.text

        images: list[dict[str, str]] = []
        text_to_check = ""

        if payload is not None:
            text_to_check = self.extractor.extract_ws_text(payload)
            images = self.extractor.extract_ws_images(payload)

        if not images and not message.is_text:
            images = self.extractor.extract_image_from_binary_message(message.content)

        if not text_to_check and not images:
            return

        result = None
        if images:
            result = self.detector_client.ask_backend_with_text_and_files(
                text_to_check, images
            )
        elif text_to_check:
            result = self.detector_client.ask_backend(text_to_check)

        if result is None:
            message.drop()
            return

        self.store_websocket_detection_result(flow, result)
        if self.http_guard.should_block(result):
            message.drop()
