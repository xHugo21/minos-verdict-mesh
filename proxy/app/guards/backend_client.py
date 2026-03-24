from __future__ import annotations

import base64
import io
from typing import Any

import httpx

from app import config


class BackendDetectorClient:
    def __init__(self, httpx_module=httpx):
        self.httpx = httpx_module

    def _backend_headers(self) -> dict[str, str]:
        if not config.BACKEND_AUTH_TOKEN:
            return {}
        return {"Authorization": f"Bearer {config.BACKEND_AUTH_TOKEN}"}

    def ask_backend(self, text: str) -> dict[str, Any] | None:
        if not text.strip():
            return {"detected_fields": [], "risk_level": "none"}

        data = {"text": text, "min_block_level": config.MIN_BLOCK_LEVEL}
        detect_url = config.BACKEND_URL
        headers = self._backend_headers()

        try:
            with self.httpx.Client(timeout=config.BACKEND_TIMEOUT_SECONDS) as client:
                response = client.post(detect_url, data=data, headers=headers)

            if response.status_code >= 400:
                return None

            return response.json()
        except Exception:
            return None

    def ask_backend_with_text_and_files(
        self, text: str, images: list[dict[str, str]]
    ) -> dict[str, Any] | None:
        detect_url = config.BACKEND_URL
        headers = self._backend_headers()

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

        if not files_to_send:
            return self.ask_backend(text) if text else None

        try:
            with self.httpx.Client(timeout=config.BACKEND_TIMEOUT_SECONDS) as client:
                data = {"text": text, "min_block_level": config.MIN_BLOCK_LEVEL}
                response = client.post(
                    detect_url,
                    files=files_to_send,
                    data=data,
                    headers=headers,
                )

            if response.status_code >= 400:
                return None

            return response.json()
        except Exception:
            return None
