import hashlib
import json
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from .log_signer import AuditLogSigner
from .log_verifier import AuditLogVerifier


class AuditLogger:
    def __init__(self, database, bus, key_provider: Optional[Callable[[], Optional[bytes]]] = None, config=None):
        self.database = database
        self.event_bus = bus
        self.key_provider = key_provider or (lambda: None)
        self.config = self._build_config(config)
        self.signer = AuditLogSigner(self.key_provider)
        self.verifier = AuditLogVerifier(self.database, self.signer)
        self._subscribed_types = []
        self._write_lock = threading.RLock()
        self._async_queue: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue()
        self._async_stop_event = threading.Event()
        self._async_worker = None
        self._async_worker_error: Optional[Exception] = None
        self._last_retention_check_sequence = 0
        if hasattr(self.database, "set_audit_protection_callback"):
            self.database.set_audit_protection_callback(self._record_protection_violation)
        self._start_async_worker()
        self._ensure_genesis_entry()
        self._subscribe_all_events()

    def close(self):
        self.flush()
        self._stop_async_worker()
        for event_type in self._subscribed_types:
            self.event_bus.unsubscribe(event_type, self._log_event)
        self._subscribed_types.clear()
        if hasattr(self.database, "set_audit_protection_callback"):
            self.database.set_audit_protection_callback(None)
        if hasattr(self.signer, "clear"):
            self.signer.clear()

    def flush(self):
        self._async_queue.join()
        if self._async_worker_error is not None:
            error = self._async_worker_error
            self._async_worker_error = None
            raise error

    def _subscribe_all_events(self):
        from ..events import EventType

        self._subscribed_types = list(EventType)
        for event_type in self._subscribed_types:
            self.event_bus.subscribe(event_type, self._log_event)

    def verify_integrity(self, start_sequence: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        return self.verifier.verify(start_sequence=start_sequence, limit=limit)

    def _ensure_genesis_entry(self):
        if self._get_latest_entry() is not None:
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
        *,
        force_sync: bool = False,
    ) -> int:
        if self._should_use_async_logging(event_type, severity, force_sync=force_sync):
            self._async_queue.put(
                {
                    "event_type": event_type,
                    "severity": severity,
                    "source": source,
                    "details": dict(details),
                    "user_id": user_id,
                    "entry_id": entry_id,
                }
            )
            return 0
        return self._write_entry(
            event_type=event_type,
            severity=severity,
            source=source,
            details=details,
            user_id=user_id,
            entry_id=entry_id,
            apply_retention=True,
        )

    def _write_entry(
        self,
        *,
        event_type: str,
        severity: str,
        source: str,
        details: Dict[str, Any],
        user_id: str,
        entry_id: Optional[int],
        apply_retention: bool,
    ) -> int:
        with self._write_lock:
            if event_type != "system_genesis" and self._get_latest_entry() is None:
                self._ensure_genesis_entry()
            previous_entry = self._get_latest_entry()
            previous_hash = previous_entry.entry_hash if previous_entry else "0" * 64
            sequence_number = (previous_entry.sequence_number if previous_entry else 0) + 1
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
            record_id = self.database.add_audit_log(
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
            if apply_retention:
                self._apply_retention_policy(sequence_number)
            return record_id

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

    def _build_config(self, config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        base_rotation_policy = {"enabled": True, "max_entries": 10000, "max_age_days": 365}
        if hasattr(self.database, "get_audit_retention_policy"):
            base_rotation_policy.update(self.database.get_audit_retention_policy())

        user_config = dict(config or {})
        user_rotation_policy = user_config.pop("rotation_policy", {}) or {}
        base_rotation_policy.update(user_rotation_policy)

        return {
            "async_logging_enabled": bool(user_config.pop("async_logging_enabled", True)),
            "rotation_policy": base_rotation_policy,
            **user_config,
        }

    def _should_use_async_logging(self, event_type: str, severity: str, *, force_sync: bool) -> bool:
        if force_sync or not self.config.get("async_logging_enabled", True):
            return False
        if event_type in {
            "system_genesis",
            "audit_log_archived",
            "audit_log_protection_triggered",
            "audit_verification_failed",
        }:
            return False
        if severity == "INFO":
            return True
        return event_type in {
            "settings_changed",
            "search_performed",
            "app_started",
            "app_shutdown",
            "user_logged_out",
        }

    def _start_async_worker(self):
        if not self.config.get("async_logging_enabled", True):
            return
        self._async_worker = threading.Thread(
            target=self._run_async_worker,
            name="audit-log-writer",
            daemon=True,
        )
        self._async_worker.start()

    def _stop_async_worker(self):
        if self._async_worker is None:
            return
        self._async_stop_event.set()
        self._async_queue.put(None)
        self._async_worker.join(timeout=2.0)
        self._async_worker = None

    def _run_async_worker(self):
        while not self._async_stop_event.is_set() or not self._async_queue.empty():
            try:
                payload = self._async_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                if payload is None:
                    continue
                self._write_entry(
                    event_type=str(payload["event_type"]),
                    severity=str(payload["severity"]),
                    source=str(payload["source"]),
                    details=dict(payload["details"]),
                    user_id=str(payload["user_id"]),
                    entry_id=payload["entry_id"],
                    apply_retention=True,
                )
            except Exception as error:
                self._async_worker_error = error
            finally:
                self._async_queue.task_done()

    def _apply_retention_policy(self, current_sequence: int):
        rotation_policy = self.config.get("rotation_policy", {})
        if not rotation_policy.get("enabled", True):
            return
        if not hasattr(self.database, "archive_audit_logs"):
            return
        max_entries = int(rotation_policy.get("max_entries", 10000))
        if current_sequence <= max_entries:
            return
        check_interval = 1 if max_entries <= 100 else max(100, max_entries // 10)
        if current_sequence - self._last_retention_check_sequence < check_interval:
            return
        self._last_retention_check_sequence = current_sequence
        archive_result = self.database.archive_audit_logs(
            max_entries=max_entries,
            max_age_days=int(rotation_policy.get("max_age_days", 365)),
        )
        if not archive_result.get("archived"):
            return
        self._write_entry(
            event_type="audit_log_archived",
            severity="INFO",
            source="audit",
            details={
                "archive_id": archive_result.get("archive_id"),
                "entry_count": archive_result.get("entry_count"),
                "range_start_sequence": archive_result.get("range_start_sequence"),
                "range_end_sequence": archive_result.get("range_end_sequence"),
                "reason": archive_result.get("reason", "retention_policy"),
            },
            user_id="system",
            entry_id=None,
            apply_retention=False,
        )

    def _record_protection_violation(self, operation: str, details: Dict[str, Any]):
        payload = dict(details)
        payload["operation"] = operation
        self._write_entry(
            event_type="audit_log_protection_triggered",
            severity="CRITICAL",
            source="audit_storage",
            details=payload,
            user_id="system",
            entry_id=None,
            apply_retention=False,
        )

    def _map_severity(self, event_type: str) -> str:
        if event_type in {"clipboard_error", "audit_verification_failed"}:
            return "ERROR"
        if event_type in {"user_login_failed", "settings_changed"}:
            return "WARN"
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
        if event_type.startswith("audit_"):
            return "audit"
        if event_type.startswith("search_"):
            return "vault_search"
        if event_type.startswith("settings_"):
            return "configuration"
        if event_type.startswith("app_"):
            return "application"
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
            if normalized_key in {"query", "username", "email", "ip", "search_text"}:
                sanitized[key] = self._hash_value(value)
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

    def _hash_value(self, value: Any) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _get_latest_entry(self):
        if hasattr(self.database, "get_latest_audit_log"):
            return self.database.get_latest_audit_log()
        rows = self.database.get_audit_log_chain(limit=1)
        if not rows:
            return None
        return rows[-1]
