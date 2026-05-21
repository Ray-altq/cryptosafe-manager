import json
import uuid
from typing import Any, Dict, List

from ..exceptions import ImportValidationError


class BitwardenJSONFormat:
    name = "bitwarden_json"

    def serialize_entries(self, entries: List[Dict[str, Any]]) -> str:
        folder_ids: Dict[str, str] = {}
        for entry in entries:
            category = str(entry.get("category", "") or "").strip()
            if category and category not in folder_ids:
                folder_ids[category] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-folder:{category}"))

        folders = [
            {
                "id": folder_id,
                "name": folder_name,
            }
            for folder_name, folder_id in sorted(folder_ids.items())
        ]
        items = []
        for entry in entries:
            title = str(entry.get("title", "") or "Untitled")
            category = str(entry.get("category", "") or "").strip()
            url = str(entry.get("url", "") or "").strip()
            tags = [
                {"name": tag.strip(), "type": 0, "value": "true"}
                for tag in str(entry.get("tags", "") or "").split(",")
                if tag.strip()
            ]
            items.append(
                {
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cryptosafe-item:{entry.get('id', title)}:{title}")),
                    "organizationId": None,
                    "folderId": folder_ids.get(category),
                    "type": 1,
                    "reprompt": 0,
                    "name": title,
                    "notes": str(entry.get("notes", "") or ""),
                    "favorite": False,
                    "login": {
                        "uris": [{"match": None, "uri": url}] if url else [],
                        "username": str(entry.get("username", "") or ""),
                        "password": str(entry.get("password", "") or ""),
                        "totp": None,
                    },
                    "fields": tags,
                }
            )
        return json.dumps({"encrypted": False, "folders": folders, "items": items}, ensure_ascii=False, sort_keys=True)

    def parse_entries(self, payload: str) -> List[Dict[str, str]]:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("Bitwarden JSON is invalid") from exc
        folders = parsed.get("folders", []) if isinstance(parsed, dict) else []
        folder_names = {
            str(folder.get("id")): str(folder.get("name") or "")
            for folder in folders
            if isinstance(folder, dict) and folder.get("id")
        }
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
                    "category": folder_names.get(str(item.get("folderId")), str(item.get("folderId") or "")),
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
