from __future__ import annotations

import base64
import io
import json
from typing import Any, Dict

import httpx
from mitmproxy import http
from mitmproxy.http import HTTPFlow

from app import config


class SensitiveDataDetector:
    def __init__(self):
        self.intercepted_hosts = config.INTERCEPTED_HOSTS
        self.intercepted_paths = config.INTERCEPTED_PATHS

    def _should_intercept(self, flow: HTTPFlow) -> bool:
        if flow.request.method != "POST":
            return False

        host = flow.request.host.lower()
        if not any(host.endswith(h) for h in self.intercepted_hosts):
            return False

        path = flow.request.path.lower()
        if not any(path.startswith(p) for p in self.intercepted_paths):
            return False

        return True

    def _extract_base64_images(self, payload: Dict[str, Any]) -> list[Dict[str, str]]:
        """
        Extract base64-encoded images from various LLM API formats.

        Supports:
        - OpenAI/GPT-4 Vision: content[].image_url.url
        - GitHub Copilot: attachments[].data
        - Anthropic Claude: content[].source.data
        - Google Gemini: parts[].inline_data.data

        Returns:
            List of dicts with:
            - data: base64 string (without data URL prefix)
            - mime_type: e.g., image/png, image/jpeg
            - source: API format (openai, copilot, claude, gemini)
        """
        images = []

        messages = payload.get("messages", [])

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            content = msg.get("content")

            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue

                    # OpenAI: {"type": "image_url", "image_url": {"url": "data:..."}}
                    if item.get("type") == "image_url":
                        image_url = item.get("image_url", {})
                        url = image_url.get("url", "")

                        if url.startswith("data:"):
                            # Parse data URL: data:image/png;base64,xxx
                            try:
                                parts = url.split(",", 1)
                                if len(parts) == 2:
                                    mime_part = parts[0].split(":")[1].split(";")[0]
                                    base64_data = parts[1]
                                    images.append(
                                        {
                                            "data": base64_data,
                                            "mime_type": mime_part,
                                            "source": "openai",
                                        }
                                    )
                            except (IndexError, ValueError):
                                continue

                    # Claude: {"type": "image", "source": {"type": "base64", "data": "..."}}
                    elif item.get("type") == "image":
                        source = item.get("source", {})
                        if source.get("type") == "base64":
                            images.append(
                                {
                                    "data": source.get("data", ""),
                                    "mime_type": source.get("media_type", "image/png"),
                                    "source": "claude",
                                }
                            )

            # GitHub Copilot format: attachments array
            attachments = msg.get("attachments", [])
            for att in attachments:
                if isinstance(att, dict) and att.get("type") == "image":
                    images.append(
                        {
                            "data": att.get("data", ""),
                            "mime_type": att.get("mime_type", "image/png"),
                            "source": "copilot",
                        }
                    )

        # Google Gemini format: contents[].parts[]
        contents = payload.get("contents", [])
        for content_item in contents:
            if not isinstance(content_item, dict):
                continue

            parts = content_item.get("parts", [])
            for part in parts:
                if not isinstance(part, dict):
                    continue

                inline_data = part.get("inline_data", {})
                if inline_data and "data" in inline_data:
                    images.append(
                        {
                            "data": inline_data.get("data", ""),
                            "mime_type": inline_data.get("mime_type", "image/png"),
                            "source": "gemini",
                        }
                    )

        return images

    def _ask_backend_with_text_and_files(
        self, text: str, images: list[Dict[str, str]]
    ) -> Dict[str, Any] | None:
        """
        Send text + multiple image files to backend in same request.

        Uses multipart form-data with:
        - text: form field
        - file: multiple file fields

        Args:
            text: Text content from the request
            images: List of dicts with 'data' (base64), 'mime_type', 'source'

        Returns:
            Detection result dict or None on error
        """
        detect_url = config.BACKEND_URL

        files_to_send = []
        for idx, image_data in enumerate(images):
            if not image_data.get("data"):
                continue

            try:
                image_bytes = base64.b64decode(image_data["data"], validate=True)
            except Exception:
                continue

            mime_type = image_data.get("mime_type", "image/png")
            extension = mime_type.split("/")[-1]
            if extension == "jpeg":
                extension = "jpg"

            filename = f"image_{idx}.{extension}"

            file_tuple = ("file", (filename, io.BytesIO(image_bytes), mime_type))
            files_to_send.append(file_tuple)

        # If no valid images, fallback to text-only
        if not files_to_send:
            return self._ask_backend(text) if text else None

        try:
            with httpx.Client(timeout=config.BACKEND_TIMEOUT_SECONDS) as client:
                data = {"text": text, "min_block_level": config.MIN_BLOCK_LEVEL}
                response = client.post(detect_url, files=files_to_send, data=data)

            if response.status_code >= 400:
                return None

            return response.json()
        except Exception:
            return None

    def _stringify(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "\n".join(filter(None, (self._stringify(item) for item in value)))
        if isinstance(value, dict):
            text = value.get("text")
            if isinstance(text, str):
                return text
            return "\n".join(
                filter(None, (self._stringify(item) for item in value.values()))
            )
        return ""

    def _extract_payload_text(self, payload: Dict[str, Any], path: str) -> str:
        path_lower = path.lower()
        if "chat" in path_lower:
            messages = payload.get("messages")
            if isinstance(messages, list):
                chunks = []
                for item in messages:
                    if not isinstance(item, dict):
                        continue
                    role = item.get("role")
                    if role != "user":
                        continue
                    text = self._stringify(item.get("content"))
                    if text:
                        chunks.append(text.strip())
                if chunks:
                    return "\n\n".join(chunks)
        prompt = payload.get("prompt")
        if prompt is not None:
            return self._stringify(prompt).strip()
        return ""

    def _ask_backend(self, text: str) -> Dict[str, Any] | None:
        if not text.strip():
            return {"detected_fields": [], "risk_level": "none"}

        data = {"text": text, "min_block_level": config.MIN_BLOCK_LEVEL}
        detect_url = config.BACKEND_URL

        try:
            with httpx.Client(timeout=config.BACKEND_TIMEOUT_SECONDS) as client:
                # Send as form-data (not JSON) to match backend's expected format
                response = client.post(detect_url, data=data)

            if response.status_code >= 400:
                return None

            return response.json()
        except Exception:
            return None

    def _should_block(self, result: Dict[str, Any]) -> bool:
        decision = (result.get("decision") or "").strip().lower()
        return decision == "block"

    def _detection_headers(self, result: Dict[str, Any]) -> Dict[str, str]:
        headers: Dict[str, str] = {}
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

    def _create_block_response(self, flow: HTTPFlow, result: Dict[str, Any]) -> None:
        detected = result.get("detected_fields", [])
        field_names = ", ".join(
            item.get("field", "unknown") for item in detected if isinstance(item, dict)
        )

        if field_names:
            message = f"[SensitiveDataDetectorBackend] Sensitive data detected: {field_names}. Request blocked."
        else:
            message = "[SensitiveDataDetectorBackend] Sensitive data detected. Request blocked."

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
                **self._detection_headers(result),
            },
        )

    def request(self, flow: HTTPFlow) -> None:
        if not self._should_intercept(flow):
            return

        try:
            body_text = flow.request.content.decode("utf-8")
            payload = json.loads(body_text or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        # Extract text content and images once
        text_to_check = self._extract_payload_text(payload, flow.request.path)
        images = self._extract_base64_images(payload)

        # Send ONE combined request instead of N+1 separate requests
        result = None

        if images:
            # Text + images together in a single request
            result = self._ask_backend_with_text_and_files(text_to_check or "", images)
        elif text_to_check:
            # Text only
            result = self._ask_backend(text_to_check)
        else:
            # Nothing to check
            return

        # Check result once
        if result is None:
            # Backend error, allow request to continue
            return

        if self._should_block(result):
            self._create_block_response(flow, result)

    def response(self, flow: HTTPFlow) -> None:
        if not self._should_intercept(flow):
            return

        if not hasattr(flow, "_detection_result"):
            return

        for key, value in self._detection_headers(flow._detection_result).items():
            flow.response.headers[key] = value


addons = [SensitiveDataDetector()]
