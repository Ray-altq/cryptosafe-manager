import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from ..events import Event, EventType, event_bus
from .encryption_service import AESGCMEncryptionService, VaultEncryptionError


class EntryNotFoundError(Exception):
    pass


class EntryManager:
    PAYLOAD_VERSION = 1

    def __init__(self, database, encryption_service: AESGCMEncryptionService, legacy_encryption_service=None):  #класс для управления записями в хранилище, который взаимодействует с базой данных и службой шифрования для создания, получения, обновления и удаления записей
        self.database = database
        self.encryption_service = encryption_service
        self.legacy_encryption_service = legacy_encryption_service

    def create_entry(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._normalize_entry_data(data_dict)
        now = datetime.now()
        encrypted_payload = self._encrypt_payload(normalized, created_at=now)

        with self.database.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, encrypted_data, url, notes, category, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["title"],
                    normalized["username"],
                    b"",
                    encrypted_payload,
                    normalized["url"],
                    normalized["notes"],
                    normalized["category"],
                    now.isoformat(),
                    now.isoformat(),
                    normalized["tags"],
                ),
            )
            entry_id = cursor.lastrowid

        entry = self.get_entry(entry_id)
        event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": entry_id, "title": entry["title"]}))
        return entry

    def get_entry(self, entry_id: int) -> Dict[str, Any]:
        row = self.database.get_entry(entry_id)
        if row is None:
            raise EntryNotFoundError("Requested entry is unavailable")
        return self._deserialize_entry(row)

    def get_all_entries(self) -> List[Dict[str, Any]]:
        entries = self.database.get_all_entries()
        return [self._deserialize_entry(entry) for entry in entries]

    def search_entries(
        self,
        query: str = "",
        category: str = "",
        entries: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        source_entries = entries if entries is not None else self.get_all_entries()
        search_text = str(query or "").strip().lower()
        selected_category = str(category or "").strip()
        general_terms, field_filters = self._parse_search_query(search_text)

        filtered_entries = []
        for entry in source_entries:
            if selected_category not in {"", "Все"} and str(entry.get("category", "")).strip() != selected_category:
                continue
            if not self._matches_field_filters(entry, field_filters):
                continue
            if self._matches_general_terms(entry, general_terms):
                filtered_entries.append(entry)

        return filtered_entries

    def update_entry(self, entry_id: int, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        current_entry = self.database.get_entry(entry_id)
        if current_entry is None:
            raise EntryNotFoundError("Requested entry is unavailable")

        current_data = self._deserialize_entry(current_entry)
        merged_data = {
            "title": current_data["title"],
            "username": current_data["username"],
            "password": current_data["password"],
            "url": current_data["url"],
            "notes": current_data["notes"],
            "category": current_data["category"],
            "tags": current_data["tags"],
            "totp_secret": current_data["totp_secret"],
            "sharing_metadata": current_data["sharing_metadata"],
        }
        merged_data.update(data_dict)

        normalized = self._normalize_entry_data(merged_data)
        updated_at = datetime.now()
        encrypted_payload = self._encrypt_payload(normalized, created_at=current_entry.created_at or updated_at)

        with self.database.transaction() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, encrypted_data = ?, url = ?, notes = ?, category = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (
                    normalized["title"],
                    normalized["username"],
                    current_entry.encrypted_password,
                    encrypted_payload,
                    normalized["url"],
                    normalized["notes"],
                    normalized["category"],
                    updated_at.isoformat(),
                    normalized["tags"],
                    entry_id,
                ),
            )

        entry = self.get_entry(entry_id)
        event_bus.publish(Event(EventType.ENTRY_UPDATED, {"id": entry_id, "title": entry["title"]}))
        return entry

    def delete_entry(self, entry_id: int, soft_delete: bool = True):
        existing_entry = self.database.get_entry(entry_id)
        if existing_entry is None:
            raise EntryNotFoundError("Requested entry is unavailable")

        title = existing_entry.title
        with self.database.transaction() as conn:
            if soft_delete:
                conn.execute(
                    """
                    INSERT INTO deleted_entries (original_entry_id, encrypted_data, title, deleted_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        entry_id,
                        existing_entry.encrypted_data or existing_entry.encrypted_password,
                        title,
                        datetime.now().isoformat(),
                        self._default_soft_delete_expiration().isoformat(),
                    ),
                )
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

        event_bus.publish(Event(EventType.ENTRY_DELETED, {"id": entry_id, "title": title}))

    def _normalize_entry_data(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            "title": str(data_dict.get("title", "")).strip(),
            "username": str(data_dict.get("username", "")).strip(),
            "password": str(data_dict.get("password", "")),
            "url": str(data_dict.get("url", "")).strip(),
            "notes": str(data_dict.get("notes", "")).strip(),
            "category": str(data_dict.get("category", "")).strip(),
            "tags": self._normalize_tags(data_dict.get("tags", "")),
            "totp_secret": str(data_dict.get("totp_secret", "")).strip(),
            "sharing_metadata": self._normalize_sharing_metadata(data_dict.get("sharing_metadata")),
        }

        if not normalized["title"]:
            raise ValueError("Entry title is required")
        if not normalized["password"]:
            raise ValueError("Entry password is required")

        return normalized

    def _normalize_tags(self, raw_tags: Any) -> str:
        if isinstance(raw_tags, list):
            return ",".join(str(tag).strip() for tag in raw_tags if str(tag).strip())
        return str(raw_tags or "").strip()

    def _normalize_sharing_metadata(self, raw_metadata: Any) -> Dict[str, Any]:
        if isinstance(raw_metadata, dict):
            return dict(raw_metadata)
        return {}

    def _parse_search_query(self, search_text: str):
        field_aliases = {
            "title": "title",
            "user": "username",
            "username": "username",
            "category": "category",
            "url": "url",
            "notes": "notes",
        }
        general_terms = []
        field_filters = []

        for raw_token in search_text.split():
            field_name, separator, raw_value = raw_token.partition(":")
            if separator and field_name in field_aliases and raw_value:
                field_filters.append((field_aliases[field_name], raw_value))
            else:
                general_terms.append(raw_token)

        return general_terms, field_filters

    def _matches_field_filters(self, entry: Dict[str, Any], field_filters) -> bool:
        for field_name, expected_value in field_filters:
            field_value = self._entry_search_value(entry, field_name)
            if expected_value not in field_value:
                return False
        return True

    def _matches_general_terms(self, entry: Dict[str, Any], general_terms) -> bool:
        if not general_terms:
            return True

        haystack = " ".join(
            [
                self._entry_search_value(entry, "title"),
                self._entry_search_value(entry, "username"),
                self._entry_search_value(entry, "category"),
                self._entry_search_value(entry, "url"),
                self._entry_search_value(entry, "notes"),
            ]
        )
        return all(term in haystack for term in general_terms)

    def _entry_search_value(self, entry: Dict[str, Any], field_name: str) -> str:
        return str(entry.get(field_name, "")).lower()

    def _encrypt_payload(self, data_dict: Dict[str, Any], created_at: datetime) -> bytes:
        payload = {
            "title": data_dict["title"],
            "username": data_dict["username"],
            "password": data_dict["password"],
            "url": data_dict["url"],
            "notes": data_dict["notes"],
            "category": data_dict["category"],
            "totp_secret": data_dict["totp_secret"],
            "sharing_metadata": data_dict["sharing_metadata"],
            "version": self.PAYLOAD_VERSION,
            "created_at": created_at.isoformat(),
        }
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self.encryption_service.encrypt(plaintext)

    def _deserialize_entry(self, entry) -> Dict[str, Any]:
        payload = self._decrypt_payload(entry)  #если расшифровка не удалась, будет выброшено исключение, которое может быть перехвачено для обработки устаревших данных
        return {
            "id": entry.id,
            "title": payload.get("title", entry.title),
            "username": payload.get("username", entry.username),
            "password": payload.get("password", ""),
            "url": payload.get("url", entry.url),
            "notes": payload.get("notes", entry.notes),
            "category": payload.get("category", ""),
            "totp_secret": payload.get("totp_secret", ""),
            "sharing_metadata": self._normalize_sharing_metadata(payload.get("sharing_metadata")),
            "version": payload.get("version", self.PAYLOAD_VERSION),
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }

    def _decrypt_payload(self, entry) -> Dict[str, Any]:  #метод для расшифровки данных записи, который пытается расшифровать данные с помощью службы шифрования
        encrypted_payload = entry.encrypted_data or entry.encrypted_password
        try:
            plaintext = self.encryption_service.decrypt(encrypted_payload)
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Entry payload must be a JSON object")
            return data
        except (VaultEncryptionError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            if self.legacy_encryption_service is None:
                raise
            password = self.legacy_encryption_service.decrypt(entry.encrypted_password).decode("utf-8")
            return {
                "title": entry.title,
                "username": entry.username,
                "password": password,
                "url": entry.url,
                "notes": entry.notes,
                "category": entry.category,
                "totp_secret": "",
                "sharing_metadata": {},
                "version": self.PAYLOAD_VERSION,
            }

    def _default_soft_delete_expiration(self) -> datetime:
        return (datetime.now() + timedelta(days=30)).replace(microsecond=0)
