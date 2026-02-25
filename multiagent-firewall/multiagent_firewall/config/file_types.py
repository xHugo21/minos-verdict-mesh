"""File type configuration loader."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

# MIME type overrides for extensions that Python's mimetypes library doesn't know
MIME_OVERRIDES = {
    ".webp": "image/webp",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
}


class FileTypeDefinition:
    """Represents a file type category."""

    def __init__(self, category: str, extensions: list[str]):
        self.category = category
        self.extensions = set(ext.lower() for ext in extensions)
        self.mime_types = self._generate_mime_types()

    def _generate_mime_types(self) -> set[str]:
        """
        Auto-generate MIME types from extensions using Python's mimetypes library.

        Falls back to hardcoded overrides for extensions not in mimetypes database.
        """
        mime_set = set()

        for ext in self.extensions:
            # Check hardcoded overrides first
            if ext in MIME_OVERRIDES:
                mime_set.add(MIME_OVERRIDES[ext])
                continue

            # Use Python's mimetypes library to guess
            guessed_mime, _ = mimetypes.guess_type(f"file{ext}")

            if guessed_mime:
                mime_set.add(guessed_mime)
            else:
                # If mimetypes doesn't know, assume text/plain for safety
                # (most unknown extensions are text-based)
                mime_set.add("text/plain")

        return mime_set

    def is_extension_supported(self, ext: str) -> bool:
        """Check if file extension is supported."""
        return ext.lower() in self.extensions

    def is_mime_supported(self, mime: str) -> bool:
        """Check if MIME type is supported."""
        return mime.lower() in self.mime_types


class FileTypeConfig:
    """Global file type configuration."""

    def __init__(self, config: dict[str, Any]):
        self.categories: dict[str, FileTypeDefinition] = {}

        # New format: file_types is { "category": [".ext1", ".ext2", ...] }
        for category, extensions in config["file_types"].items():
            self.categories[category] = FileTypeDefinition(category, extensions)

        validation = config.get("file_validation", {})
        self.global_max_size_mb = validation.get("global_max_size_mb", 50)
        self.max_files_per_request = validation.get("max_files_per_request", 10)

    def get_by_extension(self, filename: str) -> FileTypeDefinition | None:
        """Get file type definition by filename extension."""
        ext = Path(filename).suffix.lower()
        for category in self.categories.values():
            if category.is_extension_supported(ext):
                return category
        return None

    def get_by_mime(self, mime_type: str) -> FileTypeDefinition | None:
        """Get file type definition by MIME type."""
        for category in self.categories.values():
            if category.is_mime_supported(mime_type):
                return category
        return None

    @property
    def global_max_size_bytes(self) -> int:
        """Get global max file size in bytes."""
        return self.global_max_size_mb * 1024 * 1024

    @property
    def all_supported_extensions(self) -> set[str]:
        """Get all supported extensions across all categories."""
        extensions = set()
        for category in self.categories.values():
            extensions.update(category.extensions)
        return extensions

    @property
    def all_supported_mimes(self) -> set[str]:
        """Get all supported MIME types across all categories."""
        mimes = set()
        for category in self.categories.values():
            mimes.update(category.mime_types)
        return mimes
