import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.events import AuditLoggerStub, Event, EventBus, EventType


class TestEvents(unittest.TestCase):  # Проверяем работу шины событий и аудит-заглушки
    def setUp(self):
        self.event_bus = EventBus()
        self.received_events = []

    def test_publish_subscribe(self):
        def callback(event):
            self.received_events.append(event)

        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback)
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": 1}))

        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0].type, EventType.ENTRY_ADDED)

    def test_multiple_subscribers(self):
        count1 = 0
        count2 = 0

        def callback1(_event):
            nonlocal count1
            count1 += 1

        def callback2(_event):
            nonlocal count2
            count2 += 1

        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback1)
        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback2)
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))

        self.assertEqual(count1, 1)
        self.assertEqual(count2, 1)

    def test_different_event_types(self):
        added = 0
        deleted = 0
        clipboard_copied = 0

        def on_add(_event):
            nonlocal added
            added += 1

        def on_delete(_event):
            nonlocal deleted
            deleted += 1

        def on_clipboard(_event):
            nonlocal clipboard_copied
            clipboard_copied += 1

        self.event_bus.subscribe(EventType.ENTRY_ADDED, on_add)
        self.event_bus.subscribe(EventType.ENTRY_DELETED, on_delete)
        self.event_bus.subscribe(EventType.CLIPBOARD_COPIED, on_clipboard)

        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
        self.event_bus.publish(Event(EventType.ENTRY_DELETED, {}))
        self.event_bus.publish(Event(EventType.CLIPBOARD_COPIED, {"entry_id": 1}))

        self.assertEqual(added, 1)
        self.assertEqual(deleted, 1)
        self.assertEqual(clipboard_copied, 1)

    def test_audit_logger_stub(self):
        logger = AuditLoggerStub(self.event_bus)
        self.assertIsNotNone(logger)
        try:
            self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
            self.event_bus.publish(Event(EventType.USER_LOGGED_IN, "test"))
        except Exception as error:
            self.fail(f"AuditLoggerStub вызвал ошибку: {error}")


if __name__ == "__main__":
    unittest.main()
