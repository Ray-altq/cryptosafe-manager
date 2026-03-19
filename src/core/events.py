from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class EventType(Enum):
    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGGED_OUT = "user_logged_out"
    CLIPBOARD_COPIED = "clipboard_copied"
    CLIPBOARD_CLEARED = "clipboard_cleared"
    VAULT_UNLOCKED = "vault_unlocked"
    VAULT_LOCKED = "vault_locked"


class Event:
    def __init__(self, event_type: EventType, data: Any):
        self.type = event_type
        self.data = data
        self.timestamp = datetime.now()


class EventBus:
    def __init__(self):
        self._subscribers: Dict[EventType, List[Callable]] = {}

    def subscribe(self, event_type: EventType, callback: Callable):
        self._subscribers.setdefault(event_type, []).append(callback)

    def unsubscribe(self, event_type: EventType, callback: Callable):
        callbacks = self._subscribers.get(event_type, [])
        if callback in callbacks:
            callbacks.remove(callback)

    def publish(self, event: Event):
        for callback in self._subscribers.get(event.type, []):
            callback(event)


event_bus = EventBus()


class AuditLogger:
    def __init__(self, database, bus: EventBus):
        self.database = database
        self.event_bus = bus
        self._subscribed_types = list(EventType)
        for event_type in EventType:
            self.event_bus.subscribe(event_type, self._log_event)

    def close(self):
        for event_type in self._subscribed_types:
            self.event_bus.unsubscribe(event_type, self._log_event)

    def _log_event(self, event: Event):
        entry_id: Optional[int] = None
        details = ""

        if isinstance(event.data, dict):
            entry_id = event.data.get("id") or event.data.get("entry_id")
            details = ", ".join(f"{key}={value}" for key, value in event.data.items())
        elif event.data is not None:
            details = str(event.data)

        self.database.add_audit_log(
            action=event.type.value,
            timestamp=event.timestamp,
            entry_id=entry_id,
            details=details,
        )


class AuditLoggerStub:
    def __init__(self, bus: EventBus):
        self.event_bus = bus
        events = [
            EventType.ENTRY_ADDED,
            EventType.ENTRY_UPDATED,
            EventType.ENTRY_DELETED,
            EventType.USER_LOGGED_IN,
            EventType.USER_LOGGED_OUT,
        ]
        for event_type in events:
            self.event_bus.subscribe(event_type, self._log_event)

    def _log_event(self, event: Event):
        print(f"[AUDIT] {event.timestamp} - {event.type.value}: {event.data}")
