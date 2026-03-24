from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import httpx
from mitmproxy.http import HTTPFlow

from app.guards import (
    BackendDetectorClient,
    HTTPGuardEngine,
    PayloadExtractor,
    WebSocketGuardEngine,
)

try:
    from . import config
except ImportError:
    from app import config

if not hasattr(config, "INTERCEPTED_HOSTS"):
    config_spec = importlib.util.spec_from_file_location(
        "proxy_local_config",
        Path(__file__).with_name("config.py"),
    )
    if config_spec is None or config_spec.loader is None:
        raise ImportError("Could not load proxy config module")
    config = importlib.util.module_from_spec(config_spec)
    config_spec.loader.exec_module(config)


class LLMRequestGuard:
    DETECTION_RESULT_KEY = "detection_result"
    WEBSOCKET_DETECTION_RESULTS_KEY = "websocket_detection_results"

    def __init__(self):
        self.intercepted_hosts = config.INTERCEPTED_HOSTS
        self.intercepted_paths = config.INTERCEPTED_PATHS
        self.intercepted_ws_paths = [
            path.lower() for path in config.INTERCEPTED_WS_PATHS
        ]

        self._detector_client = BackendDetectorClient(httpx_module=httpx)
        self.extractor = PayloadExtractor()
        self.http_guard = HTTPGuardEngine(
            intercepted_hosts=self.intercepted_hosts,
            intercepted_paths=self.intercepted_paths,
            detector_client=self,
            extractor=self.extractor,
            detection_result_key=self.DETECTION_RESULT_KEY,
        )
        self.websocket_guard = WebSocketGuardEngine(
            intercepted_hosts=self.intercepted_hosts,
            intercepted_ws_paths=self.intercepted_ws_paths,
            detector_client=self,
            extractor=self.extractor,
            http_guard=self.http_guard,
            websocket_detection_results_key=self.WEBSOCKET_DETECTION_RESULTS_KEY,
        )

    def _sync_engines(self) -> None:
        self.http_guard.intercepted_hosts = self.intercepted_hosts
        self.http_guard.intercepted_paths = self.intercepted_paths
        self.websocket_guard.intercepted_hosts = self.intercepted_hosts
        self.websocket_guard.intercepted_ws_paths = [
            path.lower() for path in self.intercepted_ws_paths
        ]

    def ask_backend(self, text: str) -> dict[str, Any] | None:
        return self._detector_client.ask_backend(text)

    def ask_backend_with_text_and_files(
        self, text: str, images: list[dict[str, str]]
    ) -> dict[str, Any] | None:
        return self._detector_client.ask_backend_with_text_and_files(text, images)

    def request(self, flow: HTTPFlow) -> None:
        self._sync_engines()
        self.http_guard.on_request(flow)

    def response(self, flow: HTTPFlow) -> None:
        self._sync_engines()
        self.http_guard.on_response(flow)

    def websocket_message(self, flow: HTTPFlow) -> None:
        self._sync_engines()
        self.websocket_guard.on_websocket_message(flow)


addons = [LLMRequestGuard()]
