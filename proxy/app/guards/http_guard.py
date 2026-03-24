from __future__ import annotations

import json
from typing import Any, Protocol

from mitmproxy import http
from mitmproxy.http import HTTPFlow

from .extractors import PayloadExtractor


class DetectorClient(Protocol):
    def ask_backend(self, text: str) -> dict[str, Any] | None: ...

    def ask_backend_with_text_and_files(
        self, text: str, images: list[dict[str, str]]
    ) -> dict[str, Any] | None: ...


class HTTPGuardEngine:
    def __init__(
        self,
        *,
        intercepted_hosts: list[str],
        intercepted_paths: list[str],
        detector_client: DetectorClient,
        extractor: PayloadExtractor,
        detection_result_key: str,
    ):
        self.intercepted_hosts = intercepted_hosts
        self.intercepted_paths = intercepted_paths
        self.detector_client = detector_client
        self.extractor = extractor
        self.detection_result_key = detection_result_key

    def should_intercept(self, flow: HTTPFlow) -> bool:
        if flow.request.method != "POST":
            return False

        host = flow.request.host.lower()
        if not any(host.endswith(h) for h in self.intercepted_hosts):
            return False

        path = flow.request.path.lower()
        if not any(path.startswith(p) for p in self.intercepted_paths):
            return False

        return True

    def should_block(self, result: dict[str, Any]) -> bool:
        decision = (result.get("decision") or "").strip().lower()
        return decision == "block"

    def detection_headers(self, result: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        risk = result.get("risk_level")
        if risk:
            headers["X-LLM-Guard-Risk-Level"] = str(risk)
        detected = result.get("detected_fields")
        if isinstance(detected, list) and detected:
            header_value = ", ".join(
                item.get("field", "unknown")
                for item in detected
                if isinstance(item, dict)
            )
            if header_value:
                headers["X-LLM-Guard-Detected-Fields"] = header_value
        return headers

    def create_block_response(self, flow: HTTPFlow, result: dict[str, Any]) -> None:
        detected = result.get("detected_fields", [])
        field_names = ", ".join(
            item.get("field", "unknown") for item in detected if isinstance(item, dict)
        )

        if field_names:
            message = f"[MinosVerdictBackend] Guardrail violation detected: {field_names}. Request blocked."
        else:
            message = (
                "[MinosVerdictBackend] Guardrail violation detected. Request blocked."
            )

        payload = {
            "error": {
                "message": message,
                "type": "sensitive_data_detected",
                "code": "sensitive_data",
            },
            "detected_fields": detected,
            "risk_level": result.get("risk_level", "Unknown"),
            "remediation": result.get("remediation", ""),
        }

        flow.response = http.Response.make(
            status_code=403,
            content=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **self.detection_headers(result),
            },
        )

    def create_analysis_error_response(self, flow: HTTPFlow, reason: str) -> None:
        payload = {
            "error": {
                "message": f"[MinosVerdictBackend] Request blocked because it could not be analyzed: {reason}.",
                "type": "analysis_unavailable",
                "code": "analysis_unavailable",
            },
            "detected_fields": [],
            "risk_level": "unknown",
            "remediation": "Retry the request or inspect proxy/backend configuration.",
        }

        flow.response = http.Response.make(
            status_code=403,
            content=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-LLM-Guard-Risk-Level": "unknown",
            },
        )

    def store_detection_result(self, flow: HTTPFlow, result: dict[str, Any]) -> None:
        flow.metadata[self.detection_result_key] = result

    def on_request(self, flow: HTTPFlow) -> None:
        if not self.should_intercept(flow):
            return

        try:
            body_text = (flow.request.content or b"").decode("utf-8")
            payload = json.loads(body_text or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.create_analysis_error_response(flow, "invalid JSON payload")
            return

        text_to_check = self.extractor.extract_payload_text(payload, flow.request.path)
        images = self.extractor.extract_base64_images(payload)

        result = None
        if images:
            result = self.detector_client.ask_backend_with_text_and_files(
                text_to_check or "", images
            )
        elif text_to_check:
            result = self.detector_client.ask_backend(text_to_check)
        else:
            self.create_analysis_error_response(
                flow, "no supported text or image content found"
            )
            return

        if result is None:
            self.create_analysis_error_response(
                flow, "backend detection service unavailable"
            )
            return

        self.store_detection_result(flow, result)

        if self.should_block(result):
            self.create_block_response(flow, result)

    def on_response(self, flow: HTTPFlow) -> None:
        if not self.should_intercept(flow):
            return

        if flow.response is None:
            return

        result = flow.metadata.get(self.detection_result_key)
        if not isinstance(result, dict):
            return

        for key, value in self.detection_headers(result).items():
            flow.response.headers[key] = value
