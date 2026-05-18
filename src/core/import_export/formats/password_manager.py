import json
from typing import Any, Dict, List

from ..exceptions import ImportValidationError


class BitwardenJSONFormat:
    name = "bitwarden_json"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        items = []
        for entry in entries:
            tags = [
                {"name": tag.strip(), "type": 0, "value": "true"}
                for tag in str(entry.get("tags", "") or "").split(",")
                if tag.strip()
            ]
            items.append(
                {
                    "type": 1,
                    "name": str(entry.get("title", "") or ""),
                    "notes": str(entry.get("notes", "") or ""),
                    "folderId": str(entry.get("category", "") or ""),
                    "login": {
                        "username": str(entry.get("username", "") or ""),
                        "password": str(entry.get("password", "") or ""),
                        "uris": [{"uri": str(entry.get("url", "") or "")}] if entry.get("url") else [],
                    },
                    "fields": tags,
                }
            )
        return json.dumps({"encrypted": False, "items": items}, ensure_ascii=False, sort_keys=True)

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

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        import csv
        import io

        output = io.StringIO(newline="")
        fieldnames = ["url", "username", "password", "extra", "name", "grouping"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "url": str(entry.get("url", "") or ""),
                    "username": str(entry.get("username", "") or ""),
                    "password": str(entry.get("password", "") or ""),
                    "extra": str(entry.get("notes", "") or ""),
                    "name": str(entry.get("title", "") or ""),
                    "grouping": str(entry.get("category", "") or ""),
                }
            )
        return output.getvalue()

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        from .csv_format import CSVVaultFormat

        return CSVVaultFormat().parse_rows(payload)
