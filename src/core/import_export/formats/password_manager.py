import json
from typing import Any, Dict, List

from ..exceptions import ImportValidationError


class BitwardenJSONFormat:
    name = "bitwarden_json"

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("Bitwarden JSON is invalid") from exc
        items = parsed.get("items") if isinstance(parsed, dict) else None
        if not isinstance(items, list):
            raise ImportValidationError("Bitwarden JSON does not contain items")
        entries = []
        for item in items:
            if not isinstance(item, dict) or item.get("type") not in {None, 1}:
                continue
            login = item.get("login") or {}
            if not isinstance(login, dict):
                login = {}
            uris = login.get("uris") or []
            url = ""
            if uris and isinstance(uris[0], dict):
                url = str(uris[0].get("uri") or "")
            fields = item.get("fields") or []
            tags = ",".join(str(field.get("name", "")).strip() for field in fields if isinstance(field, dict) and field.get("name"))
            entries.append(
                {
                    "title": str(item.get("name") or ""),
                    "username": str(login.get("username") or ""),
                    "password": str(login.get("password") or ""),
                    "url": url,
                    "notes": str(item.get("notes") or ""),
                    "category": str(item.get("folderId") or ""),
                    "tags": tags,
                }
            )
        return entries


class LastPassCSVFormat:
    name = "lastpass_csv"

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        from .csv_format import CSVVaultFormat

        return CSVVaultFormat().parse_rows(payload)
