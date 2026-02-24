"""File type configuration loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class FileTypeDefinition:
    """Represents a file type category."""

    def __init__(self, category: str, config: dict[str, Any]):
        self.category = category
        self.extensions = set(config["extensions"])
        self.mime_types = set(config["mime_types"])
        self.parser = config["parser"]
        self.enabled = config.get("enabled", True)

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
        for category, cat_config in config["file_types"].items():
            self.categories[category] = FileTypeDefinition(category, cat_config)

        validation = config.get("file_validation", {})
        self.global_max_size_mb = validation.get("global_max_size_mb", 50)
        self.chunk_size_kb = validation.get("chunk_size_kb", 8)
        self.require_mime_validation = validation.get("require_mime_validation", True)

    def get_by_extension(self, filename: str) -> FileTypeDefinition | None:
        """Get file type definition by filename extension."""
        ext = Path(filename).suffix.lower()
        for category in self.categories.values():
            if category.enabled and category.is_extension_supported(ext):
                return category
        return None

    def get_by_mime(self, mime_type: str) -> FileTypeDefinition | None:
        """Get file type definition by MIME type."""
        for category in self.categories.values():
            if category.enabled and category.is_mime_supported(mime_type):
                return category
        return None

    @property
    def global_max_size_bytes(self) -> int:
        """Get global max file size in bytes."""
        return self.global_max_size_mb * 1024 * 1024

    @property
    def chunk_size_bytes(self) -> int:
        """Get chunk size for streaming in bytes."""
        return self.chunk_size_kb * 1024

    @property
    def all_supported_extensions(self) -> set[str]:
        """Get all enabled extensions across all categories."""
        extensions = set()
        for category in self.categories.values():
            if category.enabled:
                extensions.update(category.extensions)
        return extensions

    @property
    def all_supported_mimes(self) -> set[str]:
        """Get all enabled MIME types across all categories."""
        mimes = set()
        for category in self.categories.values():
            if category.enabled:
                mimes.update(category.mime_types)
        return mimes
