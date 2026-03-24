from __future__ import annotations

import base64
import re
from typing import Any


class PayloadExtractor:
    WEBSOCKET_MAX_TEXT_BYTES = 16384
    _BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\n\r]+$")

    def stringify(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "\n".join(filter(None, (self.stringify(item) for item in value)))
        if isinstance(value, dict):
            text = value.get("text")
            if isinstance(text, str):
                return text
            return "\n".join(
                filter(None, (self.stringify(item) for item in value.values()))
            )
        return ""

    def extract_payload_text(self, payload: dict[str, Any], path: str) -> str:
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
                    content = item.get("content")
                    if isinstance(content, list):
                        text = "\n".join(
                            filter(
                                None,
                                (
                                    part
                                    if isinstance(part, str)
                                    else part.get("text", "")
                                    if isinstance(part, dict)
                                    else ""
                                    for part in content
                                ),
                            )
                        )
                    else:
                        text = self.stringify(content)
                    if text:
                        chunks.append(text.strip())
                if chunks:
                    return "\n\n".join(chunks)
        prompt = payload.get("prompt")
        if prompt is not None:
            return self.stringify(prompt).strip()
        return ""

    def extract_base64_images(self, payload: dict[str, Any]) -> list[dict[str, str]]:
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

                    if item.get("type") == "image_url":
                        image_url = item.get("image_url", {})
                        url = image_url.get("url", "")

                        if isinstance(url, str) and url.startswith("data:"):
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

    def is_data_url(self, value: str) -> bool:
        return value.startswith("data:") and "," in value

    def parse_data_url_image(self, value: str) -> dict[str, str] | None:
        if not self.is_data_url(value):
            return None
        try:
            metadata, base64_data = value.split(",", 1)
            mime_type = metadata.split(":", 1)[1].split(";", 1)[0]
            if not mime_type.startswith("image/"):
                return None
            if not base64_data:
                return None
            return {
                "data": base64_data,
                "mime_type": mime_type,
                "source": "websocket_data_url",
            }
        except (IndexError, ValueError):
            return None

    def looks_like_base64(self, value: str) -> bool:
        compact = value.strip()
        if len(compact) < 16:
            return False
        if len(compact) % 4 != 0:
            return False
        return bool(self._BASE64_RE.match(compact))

    def infer_image_mime_type(self, content: bytes) -> str | None:
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if content.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if content.startswith(b"GIF87a") or content.startswith(b"GIF89a"):
            return "image/gif"
        if content.startswith(b"RIFF") and b"WEBP" in content[:16]:
            return "image/webp"
        return None

    def extract_image_from_binary_message(self, content: bytes) -> list[dict[str, str]]:
        mime_type = self.infer_image_mime_type(content)
        if not mime_type:
            return []
        return [
            {
                "data": base64.b64encode(content).decode("ascii"),
                "mime_type": mime_type,
                "source": "websocket_binary",
            }
        ]

    def _collect_ws_images(self, value: Any, images: list[dict[str, str]]) -> None:
        if isinstance(value, list):
            for item in value:
                self._collect_ws_images(item, images)
            return

        if not isinstance(value, dict):
            if isinstance(value, str):
                image = self.parse_data_url_image(value)
                if image:
                    images.append(image)
            return

        if value.get("type") == "image_url":
            image_url = value.get("image_url")
            if isinstance(image_url, dict):
                url = image_url.get("url")
                if isinstance(url, str):
                    image = self.parse_data_url_image(url)
                    if image:
                        image["source"] = "websocket_openai"
                        images.append(image)
            elif isinstance(image_url, str):
                image = self.parse_data_url_image(image_url)
                if image:
                    image["source"] = "websocket_openai"
                    images.append(image)

        source = value.get("source")
        if isinstance(source, dict) and source.get("type") == "base64":
            data = source.get("data")
            if isinstance(data, str) and data:
                mime_type = source.get("media_type", "image/png")
                images.append(
                    {
                        "data": data,
                        "mime_type": str(mime_type),
                        "source": "websocket_claude",
                    }
                )

        inline_data = value.get("inline_data")
        if isinstance(inline_data, dict):
            data = inline_data.get("data")
            if isinstance(data, str) and data:
                mime_type = inline_data.get("mime_type", "image/png")
                images.append(
                    {
                        "data": data,
                        "mime_type": str(mime_type),
                        "source": "websocket_gemini",
                    }
                )

        attachments = value.get("attachments")
        if isinstance(attachments, list):
            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue
                if attachment.get("type") != "image":
                    continue
                data = attachment.get("data")
                if not isinstance(data, str) or not data:
                    continue
                mime_type = attachment.get("mime_type", "image/png")
                images.append(
                    {
                        "data": data,
                        "mime_type": str(mime_type),
                        "source": "websocket_copilot",
                    }
                )

        data = value.get("data")
        mime_type = value.get("mime_type")
        if (
            isinstance(data, str)
            and isinstance(mime_type, str)
            and mime_type.startswith("image/")
            and self.looks_like_base64(data)
        ):
            images.append(
                {
                    "data": data,
                    "mime_type": mime_type,
                    "source": "websocket_generic",
                }
            )

        for nested in value.values():
            self._collect_ws_images(nested, images)

    def extract_ws_images(self, payload: Any) -> list[dict[str, str]]:
        images: list[dict[str, str]] = []
        self._collect_ws_images(payload, images)
        deduplicated: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for image in images:
            data = image.get("data")
            mime_type = image.get("mime_type")
            if not isinstance(data, str) or not isinstance(mime_type, str):
                continue
            key = (mime_type, data)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(image)
        return deduplicated

    def _collect_ws_text(self, value: Any, chunks: list[str]) -> None:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped and not self.is_data_url(stripped):
                chunks.append(stripped)
            return

        if isinstance(value, list):
            for item in value:
                self._collect_ws_text(item, chunks)
            return

        if not isinstance(value, dict):
            return

        for key in ("text", "prompt", "input_text"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                chunks.append(candidate.strip())

        if "messages" in value and isinstance(value["messages"], list):
            for message in value["messages"]:
                if not isinstance(message, dict):
                    continue
                role = message.get("role")
                if isinstance(role, str) and role != "user":
                    continue
                self._collect_ws_text(message.get("content"), chunks)

        if "contents" in value and isinstance(value["contents"], list):
            for content in value["contents"]:
                if not isinstance(content, dict):
                    continue
                role = content.get("role")
                if isinstance(role, str) and role != "user":
                    continue
                parts = content.get("parts")
                if isinstance(parts, list):
                    for part in parts:
                        if isinstance(part, dict):
                            text = part.get("text")
                            if isinstance(text, str) and text.strip():
                                chunks.append(text.strip())

    def truncate_text(self, text: str) -> str:
        encoded = text.encode("utf-8")
        if len(encoded) <= self.WEBSOCKET_MAX_TEXT_BYTES:
            return text
        return encoded[: self.WEBSOCKET_MAX_TEXT_BYTES].decode("utf-8", errors="ignore")

    def extract_ws_text(self, payload: Any) -> str:
        if isinstance(payload, str):
            return self.truncate_text(payload.strip())

        chunks: list[str] = []
        self._collect_ws_text(payload, chunks)
        if not chunks:
            return ""
        return self.truncate_text("\n\n".join(chunks))
