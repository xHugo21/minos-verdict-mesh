from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..config.detection import OCR_DETECTOR_PROMPT

from ..types import GuardState
from .utils import (
    build_chat_litellm,
    coerce_litellm_content_to_text,
)


class TesseractOCRDetector:
    """OCR detector using Tesseract"""

    def __init__(
        self,
        *,
        lang: str = "eng",
        config: str = "",
        confidence_threshold: int = 0,
        tesseract_cmd: str | None = None,
    ):
        self.lang = lang
        self.config = config
        self.confidence_threshold = confidence_threshold
        self.tesseract_cmd = tesseract_cmd

        if tesseract_cmd:
            import pytesseract

            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

    def __call__(self, state: GuardState) -> str:
        """
        Extract text from image file

        Returns:
            Extracted text as a plain string, or empty string if extraction fails.
        """
        file_path = state.get("file_path")

        if not file_path:
            return ""

        if not os.path.exists(file_path):
            return ""

        try:
            import pytesseract
            from PIL import Image
            from ..config import FILE_TYPE_CONFIG

            path = Path(file_path)

            # Get image config
            image_config = FILE_TYPE_CONFIG.categories.get("image")
            if not image_config:
                return ""

            image = Image.open(file_path)

            ocr_data = pytesseract.image_to_data(
                image,
                lang=self.lang,
                config=self.config,
                output_type=pytesseract.Output.DICT,
            )

            text_parts = []

            # Process each detected text element
            n_boxes = len(ocr_data["text"])
            for i in range(n_boxes):
                text = ocr_data["text"][i].strip()
                conf = int(ocr_data["conf"][i]) if ocr_data["conf"][i] != "-1" else 0

                # Skip empty text or low confidence
                if not text or conf < self.confidence_threshold:
                    continue

                text_parts.append(text)

            return " ".join(text_parts)

        except Exception as e:
            raise RuntimeError(
                f"Tesseract OCR failed to process image: {str(e)}"
            ) from e


class LLMOCRDetector:
    """LLM-based OCR detector"""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        client_params: dict[str, Any],
    ):
        self.provider = provider
        self.model = model
        prompt_path = (
            Path(__file__).resolve().parent.parent / "prompts" / OCR_DETECTOR_PROMPT
        )
        if not prompt_path.exists():
            raise FileNotFoundError(f"OCR prompt file not found: {prompt_path}")
        self._system_prompt = (
            prompt_path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
        )

        self._llm = build_chat_litellm(
            provider=self.provider, model=self.model, client_params=client_params
        )

    def __call__(self, state: GuardState) -> str:
        """
        Extract text from image file using vision-capable LLM.

        Returns:
            Extracted text as a plain string, or empty string if extraction fails.
        """
        file_path = state.get("file_path")

        if not file_path:
            return ""

        if not os.path.exists(file_path):
            return ""

        try:
            import base64
            import mimetypes
            from langchain_core.messages import HumanMessage, SystemMessage
            from ..config import FILE_TYPE_CONFIG

            # Get image config
            image_config = FILE_TYPE_CONFIG.categories.get("image")
            if not image_config:
                return ""

            mime_type, _ = mimetypes.guess_type(file_path)

            # Default to image/jpeg if not recognized or not an image type
            if not mime_type or not mime_type.startswith("image/"):
                mime_type = "image/jpeg"

            with open(file_path, "rb") as f:
                image_data = base64.b64encode(f.read()).decode("utf-8")

            data_url = f"data:{mime_type};base64,{image_data}"

            message = [
                SystemMessage(content=self._system_prompt),
                HumanMessage(
                    content=[
                        {
                            "type": "image_url",
                            "image_url": {"url": data_url},
                        }
                    ]
                ),
            ]

            response = self._llm.invoke(message)
            return coerce_litellm_content_to_text(response)

        except Exception as e:
            raise RuntimeError(f"LLM OCR failed to process image: {str(e)}") from e


__all__ = ["TesseractOCRDetector", "LLMOCRDetector"]
