from enum import Enum
from typing import Callable, Dict, List, Any
from datetime import datetime

class EventType(Enum):  #типы событий
    ENTRY_ADDED = "entry_added"
    ENTRY_UPDATED = "entry_updated"
    ENTRY_DELETED = "entry_deleted"
    USER_LOGGED_IN = "user_logged_in"
    USER_LOGGED_OUT = "user_logged_out"
    CLIPBOARD_COPIED = "clipboard_copied"
    CLIPBOARD_CLEARED = "clipboard_cleared"

class Event:  #событие
    def __init__(self, event_type: EventType, data: Any):
        self.type = event_type
        self.data = data
        self.timestamp = datetime.now()

class EventBus:
    def __init__(self):
        self._subscribers: Dict[EventType, List[Callable]] = {}
    
    def subscribe(self, event_type: EventType, callback: Callable):  #подписка на событие
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def publish(self, event: Event):  #публикация события
        if event.type in self._subscribers:
            for callback in self._subscribers[event.type]:
                callback(event)

event_bus = EventBus()

class AuditLoggerStub:  #заглушка журнала аудита
    
    def __init__(self, event_bus):
        self.event_bus = event_bus
        #подписываемся на все обязательные события
        events = [
            EventType.ENTRY_ADDED,
            EventType.ENTRY_UPDATED,
            EventType.ENTRY_DELETED,
            EventType.USER_LOGGED_IN,
            EventType.USER_LOGGED_OUT
        ]
        for event_type in events:
            self.event_bus.subscribe(event_type, self._log_event)
    
    def _log_event(self, event: Event):  #записываем событие в лог
        print(f"[AUDIT] {event.timestamp} - {event.type.value}: {event.data}")