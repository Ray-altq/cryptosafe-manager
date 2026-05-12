import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from .log_signer import AuditLogSigner


class AuditLogger:
    def __init__(self, database, bus, key_provider: Optional[Callable[[], Optional[bytes]]] = None, config=None):
        self.database = database
        self.event_bus = bus
        self.key_provider = key_provider or (lambda: None)
        self.config = config or {}
        self.signer = AuditLogSigner(self.key_provider)
        self._subscribed_types = []
        self._ensure_genesis_entry()
        self._subscribe_all_events()

    def close(self):
        for event_type in self._subscribed_types:
            self.event_bus.unsubscribe(event_type, self._log_event)
        self._subscribed_types.clear()

    def _subscribe_all_events(self):
        from ..events import EventType

        self._subscribed_types = list(EventType)
        for event_type in self._subscribed_types:
            self.event_bus.subscribe(event_type, self._log_event)

    def _ensure_genesis_entry(self):
        if self.database.get_audit_log_chain(limit=1):
            return
        if not self.key_provider():
            return
        self.log_event(
            event_type="system_genesis",
            severity="INFO",
            source="audit_logger",
            details={"message": "Audit log initialized"},
            user_id="system",
            entry_id=None,
        )

    def log_event(
        self,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        user_id: str = "local-user",
        entry_id: Optional[int] = None,
    ) -> int:
        if event_type != "system_genesis" and not self.database.get_audit_log_chain(limit=1):
            self._ensure_genesis_entry()
        previous_entry = self.database.get_audit_log_chain(limit=1)
        previous_hash = previous_entry[-1].entry_hash if previous_entry else "0" * 64
        sequence_number = (previous_entry[-1].sequence_number if previous_entry else 0) + 1
        timestamp = self._utc_now()

        payload = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "user_id": user_id,
            "source": source,
            "entry_id": entry_id,
            "details": self._sanitize_details(details),
            "sequence_number": sequence_number,
            "previous_hash": previous_hash,
        }
        entry_data = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        entry_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
        signature = self.signer.sign(entry_data.encode("utf-8"))
        self.database.register_audit_public_key(self.signer.algorithm, self.signer.public_key_hex)
        return self.database.add_audit_log(
            action=event_type,
            event_type=event_type,
            timestamp=datetime.fromisoformat(timestamp.replace("Z", "+00:00")),
            severity=severity,
            user_id=user_id,
            source=source,
            entry_id=entry_id,
            details=json.dumps(payload["details"], ensure_ascii=False, sort_keys=True),
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            entry_data=entry_data,
            signature=signature,
            public_key=self.signer.public_key_hex,
        )

    def _log_event(self, event):
        entry_id = None
        details: Dict[str, Any]
        if isinstance(event.data, dict):
            entry_id = event.data.get("id") or event.data.get("entry_id")
            details = dict(event.data)
        elif event.data is None:
            details = {}
        else:
            details = {"message": str(event.data)}

        self.log_event(
            event_type=event.type.value,
            severity=self._map_severity(event.type.value),
            source=self._map_source(event.type.value),
            details=details,
            entry_id=entry_id,
        )

    def _map_severity(self, event_type: str) -> str:
        if event_type in {"clipboard_error"}:
            return "ERROR"
        if "failed" in event_type or "suspicious" in event_type:
            return "WARN"
        return "INFO"

    def _map_source(self, event_type: str) -> str:
        if event_type.startswith("clipboard_"):
            return "clipboard"
        if event_type.startswith("entry_"):
            return "vault"
        if event_type.startswith("user_"):
            return "authentication"
        if event_type.startswith("vault_"):
            return "system"
        return "application"

    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        sanitized: Dict[str, Any] = {}
        for key, value in details.items():
            normalized_key = str(key).lower()
            if any(marker in normalized_key for marker in ("password", "secret", "key")):
                sanitized[key] = "[REDACTED]"
                continue
            if isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
                continue
            if isinstance(value, list):
                sanitized[key] = [self._sanitize_list_value(item) for item in value]
                continue
            sanitized[key] = value
        return sanitized

    def _sanitize_list_value(self, value: Any):
        if isinstance(value, dict):
            return self._sanitize_details(value)
        return value

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
