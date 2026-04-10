from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from ..events import Event, EventType, event_bus


class ClipboardAccessError(RuntimeError):
    pass


@dataclass
class SecureClipboardItem:
    text_mask: bytearray
    mask: bytes
    data_type: str
    source_entry_id: Optional[int] = None
    source_label: str = ""
    copied_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    fingerprint: str = ""

    @classmethod
    def create(
        cls,
        value: str,
        data_type: str,
        source_entry_id: Optional[int] = None,
        source_label: str = "",
        timeout_seconds: int = 30,
    ) -> "SecureClipboardItem":
        plain_bytes = value.encode("utf-8")
        mask = secrets.token_bytes(max(len(plain_bytes), 1))
        masked = bytearray(byte ^ mask[index] for index, byte in enumerate(plain_bytes))
        expires_at = None if timeout_seconds <= 0 else datetime.now() + timedelta(seconds=timeout_seconds)
        fingerprint = hashlib.sha256(plain_bytes).hexdigest()
        return cls(
            text_mask=masked,
            mask=mask,
            data_type=data_type,
            source_entry_id=source_entry_id,
            source_label=source_label,
            expires_at=expires_at,
            fingerprint=fingerprint,
        )

    def reveal(self) -> str:
        plain_bytes = bytes(byte ^ self.mask[index] for index, byte in enumerate(self.text_mask))
        return plain_bytes.decode("utf-8")

    def secure_wipe(self):
        for index in range(len(self.text_mask)):
            self.text_mask[index] = 0


@dataclass
class ClipboardStatus:
    active: bool
    data_type: str = ""
    source_entry_id: Optional[int] = None
    source_label: str = ""
    preview: str = ""
    remaining_seconds: int = 0
    warning_emitted: bool = False
    suspicious_activity: bool = False
    blocked_future_copies: bool = False


class ClipboardService:
    SETTINGS_KEY = "security.clipboard"
    PROFILE_KEY = "security.clipboard_profile"
    PRESETS = {
        "standard": {
            "timeout_seconds": 30,
            "notifications_enabled": True,
            "security_level": "basic",
            "blocked_on_suspicious": False,
        },
        "secure": {
            "timeout_seconds": 15,
            "notifications_enabled": True,
            "security_level": "advanced",
            "blocked_on_suspicious": False,
        },
        "public_computer": {
            "timeout_seconds": 5,
            "notifications_enabled": True,
            "security_level": "paranoid",
            "blocked_on_suspicious": True,
        },
    }

    def __init__(self, adapter, database=None, config=None, state_manager=None, bus=event_bus):
        self.adapter = adapter
        self.database = database
        self.config = config
        self.state_manager = state_manager
        self.event_bus = bus
        self._lock = threading.RLock()
        self._observers: list[Callable[[ClipboardStatus], None]] = []
        self._current_item: Optional[SecureClipboardItem] = None
        self._warning_emitted = False
        self._suspicious_activity = False
        self._blocked_future_copies = False
        self._last_clear_reason: Optional[str] = None
        self._last_clear_failed = False
        self._settings = self._load_settings()

    def subscribe(self, callback: Callable[[ClipboardStatus], None]):
        self._observers.append(callback)

    def unsubscribe(self, callback: Callable[[ClipboardStatus], None]):
        if callback in self._observers:
            self._observers.remove(callback)

    def configure(
        self,
        *,
        timeout_seconds: Optional[int] = None,
        notifications_enabled: Optional[bool] = None,
        security_level: Optional[str] = None,
        blocked_on_suspicious: Optional[bool] = None,
        preset: Optional[str] = None,
    ):
        with self._lock:
            if preset:
                normalized_preset = str(preset).strip().lower()
                if normalized_preset in self.PRESETS:
                    self._settings.update(self.PRESETS[normalized_preset])
                self._settings["preset"] = normalized_preset or "standard"

            if timeout_seconds is not None:
                self._settings["timeout_seconds"] = self._normalize_timeout(timeout_seconds)
            if notifications_enabled is not None:
                self._settings["notifications_enabled"] = bool(notifications_enabled)
            if security_level is not None:
                self._settings["security_level"] = self._normalize_security_level(security_level)
            if blocked_on_suspicious is not None:
                self._settings["blocked_on_suspicious"] = bool(blocked_on_suspicious)

            self._persist_settings()
            self._notify()

    def get_settings(self) -> dict:
        with self._lock:
            return dict(self._settings)

    def _publish_clipboard_error(
        self,
        *,
        operation: str,
        error_code: str,
        data_type: str = "",
        source_entry_id: Optional[int] = None,
        extra_details: Optional[dict] = None,
    ):
        payload = {
            "operation": operation,
            "error_code": error_code,
            "data_type": data_type,
            "entry_id": source_entry_id,
        }
        if extra_details:
            payload.update(extra_details)
        self.event_bus.publish(
            Event(
                EventType.CLIPBOARD_ERROR,
                payload,
            )
        )

    def copy_text(
        self,
        value: str,
        *,
        data_type: str = "password",
        source_entry_id: Optional[int] = None,
        source_label: str = "",
    ):
        normalized_value = str(value or "")
        if not normalized_value:
            self._publish_clipboard_error(operation="copy", error_code="empty_value", data_type=data_type)
            raise ClipboardAccessError("Нельзя копировать пустое значение")

        with self._lock:
            if self._blocked_future_copies:
                self._publish_clipboard_error(
                    operation="copy",
                    error_code="blocked_on_suspicious",
                    data_type=data_type,
                    source_entry_id=source_entry_id,
                )
                raise ClipboardAccessError("Копирование временно заблокировано из-за подозрительной активности")
            if self.state_manager is not None and hasattr(self.state_manager, "is_locked") and self.state_manager.is_locked():
                self._publish_clipboard_error(
                    operation="copy",
                    error_code="vault_locked",
                    data_type=data_type,
                    source_entry_id=source_entry_id,
                )
                raise ClipboardAccessError("Буфер обмена доступен только при разблокированном vault")

            self.clear(reason="replacement", publish_event=False)
            item = SecureClipboardItem.create(
                normalized_value,
                data_type=data_type,
                source_entry_id=source_entry_id,
                source_label=source_label,
                timeout_seconds=self._settings["timeout_seconds"],
            )
            if not self.adapter.copy_to_clipboard(normalized_value):
                item.secure_wipe()
                self._publish_clipboard_error(
                    operation="copy",
                    error_code="adapter_write_failed",
                    data_type=data_type,
                    source_entry_id=source_entry_id,
                )
                raise ClipboardAccessError("Не удалось записать данные в буфер обмена")

            self._current_item = item
            self._warning_emitted = False
            self._suspicious_activity = False
            self._last_clear_reason = None
            self._last_clear_failed = False

            if self.state_manager is not None and hasattr(self.state_manager, "set_clipboard"):
                self.state_manager.set_clipboard(normalized_value, self._settings["timeout_seconds"])

            self.event_bus.publish(
                Event(
                    EventType.CLIPBOARD_COPIED,
                    {
                        "entry_id": source_entry_id,
                        "data_type": data_type,
                        "timeout_seconds": self._settings["timeout_seconds"],
                        "source_label": source_label,
                    },
                )
            )
            self._notify()

    def clear(self, reason: str = "manual", publish_event: bool = True) -> bool:
        with self._lock:
            had_content = self._current_item is not None
            adapter_cleared = True
            if had_content:
                try:
                    adapter_cleared = bool(self.adapter.clear_clipboard())
                except Exception:
                    adapter_cleared = False
                self._current_item.secure_wipe()
                self._current_item = None

            self._warning_emitted = False
            self._last_clear_reason = reason
            self._last_clear_failed = had_content and not adapter_cleared
            if self.state_manager is not None and hasattr(self.state_manager, "clear_clipboard"):
                self.state_manager.clear_clipboard()

            if self._last_clear_failed:
                self._publish_clipboard_error(
                    operation="clear",
                    error_code="adapter_clear_failed",
                    extra_details={"clear_reason": reason},
                )

            if had_content and publish_event:
                self.event_bus.publish(
                    Event(EventType.CLIPBOARD_CLEARED, {"reason": reason, "clear_failed": self._last_clear_failed})
                )
            self._notify()
            return had_content

    def tick(self) -> Optional[str]:
        with self._lock:
            if self._current_item is None:
                return None

            if self._current_item.expires_at is not None:
                remaining = int((self._current_item.expires_at - datetime.now()).total_seconds())
                if remaining <= 0:
                    self.clear(reason="timeout")
                    return "timeout"
                if remaining <= 5 and not self._warning_emitted:
                    self._warning_emitted = True
                    self._notify()
                    return "warning"

            self._notify()
            return None

    def register_suspicious_activity(self, *, reason: str, observed_value: Optional[str] = None):
        with self._lock:
            if self._current_item is None:
                return

            self._suspicious_activity = True
            if self._settings.get("blocked_on_suspicious", False):
                self._blocked_future_copies = True

            if self._current_item.expires_at is not None:
                accelerated_expiration = datetime.now() + timedelta(seconds=1)
                if self._current_item.expires_at > accelerated_expiration:
                    self._current_item.expires_at = accelerated_expiration

            details = {
                "reason": reason,
                "entry_id": self._current_item.source_entry_id,
                "data_type": self._current_item.data_type,
            }
            if observed_value is not None:
                details["observed_length"] = len(observed_value)

            self.event_bus.publish(Event(EventType.CLIPBOARD_CLEARED, {"reason": "monitor_warning", **details}))
            self._notify()

    def get_status(self) -> ClipboardStatus:
        with self._lock:
            if self._current_item is None:
                return ClipboardStatus(
                    active=False,
                    suspicious_activity=self._suspicious_activity,
                    blocked_future_copies=self._blocked_future_copies,
                )

            remaining_seconds = 0
            if self._current_item.expires_at is not None:
                remaining_seconds = max(0, int((self._current_item.expires_at - datetime.now()).total_seconds()))

            return ClipboardStatus(
                active=True,
                data_type=self._current_item.data_type,
                source_entry_id=self._current_item.source_entry_id,
                source_label=self._current_item.source_label,
                preview=self._build_masked_preview(self._current_item.reveal(), self._current_item.data_type),
                remaining_seconds=remaining_seconds,
                warning_emitted=self._warning_emitted,
                suspicious_activity=self._suspicious_activity,
                blocked_future_copies=self._blocked_future_copies,
            )

    def get_last_clear_reason(self) -> Optional[str]:
        return self._last_clear_reason

    def did_last_clear_fail(self) -> bool:
        return self._last_clear_failed

    def reveal_current_text(self) -> str:
        with self._lock:
            if self._current_item is None:
                return ""
            return self._current_item.reveal()

    def has_active_content(self) -> bool:
        return self._current_item is not None

    def matches_current_text(self, value: Optional[str]) -> bool:
        with self._lock:
            if self._current_item is None:
                return value in {None, ""}
            return value == self._current_item.reveal()

    def _notify(self):
        status = self.get_status()
        for callback in list(self._observers):
            callback(status)

    def _load_settings(self) -> dict:
        defaults = {
            "timeout_seconds": self._normalize_timeout(
                self.config.get("security.clipboard_timeout", 30) if self.config is not None else 30
            ),
            "notifications_enabled": True,
            "security_level": "basic",
            "blocked_on_suspicious": False,
            "preset": "standard",
        }

        if self.database is None:
            return defaults

        stored = self.database.get_setting(self.SETTINGS_KEY, {})
        if isinstance(stored, dict):
            defaults.update(stored)
        defaults["timeout_seconds"] = self._normalize_timeout(defaults.get("timeout_seconds", 30))
        defaults["security_level"] = self._normalize_security_level(defaults.get("security_level", "basic"))
        defaults["notifications_enabled"] = bool(defaults.get("notifications_enabled", True))
        defaults["blocked_on_suspicious"] = bool(defaults.get("blocked_on_suspicious", False))
        defaults["preset"] = str(defaults.get("preset", "standard")).strip().lower() or "standard"
        return defaults

    def _persist_settings(self):
        if self.database is not None:
            self.database.set_setting(self.SETTINGS_KEY, self._settings, encrypted=True)
            self.database.set_setting(self.PROFILE_KEY, self._settings.get("preset", "standard"), encrypted=True)
        if self.config is not None:
            self.config.set("security.clipboard_timeout", self._settings["timeout_seconds"])

    def _normalize_timeout(self, timeout_seconds: int) -> int:
        try:
            normalized = int(timeout_seconds)
        except (TypeError, ValueError):
            normalized = 30
        if normalized <= 0:
            return 0
        return max(5, min(300, normalized))

    def _normalize_security_level(self, security_level: str) -> str:
        normalized = str(security_level or "basic").strip().lower()
        if normalized not in {"basic", "advanced", "paranoid"}:
            return "basic"
        return normalized

    def _build_masked_preview(self, value: str, data_type: str) -> str:
        if not value:
            return ""
        if data_type == "password":
            if len(value) <= 3:
                return "*" * len(value)
            return f"{value[:3]}{'*' * min(max(len(value) - 3, 3), 8)}"
        if len(value) <= 2:
            return "*" * len(value)
        return f"{value[0]}{'*' * min(max(len(value) - 2, 2), 6)}{value[-1]}"
