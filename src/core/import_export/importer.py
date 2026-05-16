import re
from typing import Any, Dict, Iterable, List

from .exceptions import ImportValidationError
from .models import ImportOptions


class VaultImporter:
    MALICIOUS_PATTERNS = (
        re.compile(r"<\s*script", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"<\s*iframe", re.IGNORECASE),
    )

    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def validate_entries(self, entries: Iterable[Dict[str, Any]], options: ImportOptions | None = None) -> List[Dict[str, Any]]:
        _ = options or ImportOptions()
        validated = []
        for index, entry in enumerate(entries, start=1):
            normalized = self._sanitize_entry(entry)
            if not normalized["title"]:
                raise ImportValidationError(f"Entry #{index} is missing title")
            if not normalized["password"]:
                raise ImportValidationError(f"Entry #{index} is missing password")
            validated.append(normalized)
        return validated

    def _sanitize_entry(self, entry: Dict[str, Any]) -> Dict[str, str]:
        normalized = {
            "title": self._sanitize_text(entry.get("title", "")),
            "username": self._sanitize_text(entry.get("username", "")),
            "password": str(entry.get("password", "") or ""),
            "url": self._sanitize_text(entry.get("url", "")),
            "notes": self._sanitize_text(entry.get("notes", "")),
            "category": self._sanitize_text(entry.get("category", "")),
            "tags": self._sanitize_text(entry.get("tags", "")),
        }
        return normalized

    def _sanitize_text(self, value: Any) -> str:
        text = str(value or "").replace("\x00", "").strip()
        for pattern in self.MALICIOUS_PATTERNS:
            if pattern.search(text):
                raise ImportValidationError("Imported data contains blocked active content")
        return text
