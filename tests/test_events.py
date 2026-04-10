import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.events import AuditLogger, AuditLoggerStub, Event, EventBus, EventType


class FakeAuditDatabase:
    def __init__(self):
        self.records = []

    def add_audit_log(self, action, timestamp, entry_id=None, details=""):
        self.records.append(
            {
                "action": action,
                "timestamp": timestamp,
                "entry_id": entry_id,
                "details": details,
            }
        )


class TestEvents(unittest.TestCase):
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

    def test_audit_logger_records_clipboard_events_with_details(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus)
        self.addCleanup(logger.close)

        copied_event = Event(
            EventType.CLIPBOARD_COPIED,
            {"entry_id": 7, "data_type": "password", "timeout_seconds": 30, "source_label": "GitHub"},
        )
        copied_event.timestamp = datetime(2026, 4, 7, 12, 0, 0)
        cleared_event = Event(
            EventType.CLIPBOARD_CLEARED,
            {"reason": "monitor_warning", "entry_id": 7, "data_type": "password", "observed_length": 21},
        )
        cleared_event.timestamp = datetime(2026, 4, 7, 12, 0, 1)

        self.event_bus.publish(copied_event)
        self.event_bus.publish(cleared_event)

        self.assertEqual(len(database.records), 2)
        self.assertEqual(database.records[0]["action"], "clipboard_copied")
        self.assertEqual(database.records[0]["entry_id"], 7)
        self.assertIn("data_type=password", database.records[0]["details"])
        self.assertIn("timeout_seconds=30", database.records[0]["details"])
        self.assertEqual(database.records[1]["action"], "clipboard_cleared")
        self.assertEqual(database.records[1]["entry_id"], 7)
        self.assertIn("reason=monitor_warning", database.records[1]["details"])
        self.assertIn("observed_length=21", database.records[1]["details"])

    def test_audit_logger_records_clipboard_error_without_secret_payload(self):
        database = FakeAuditDatabase()
        logger = AuditLogger(database, self.event_bus)
        self.addCleanup(logger.close)

        error_event = Event(
            EventType.CLIPBOARD_ERROR,
            {"operation": "copy", "error_code": "adapter_write_failed", "entry_id": 7, "data_type": "password"},
        )
        self.event_bus.publish(error_event)

        self.assertEqual(database.records[-1]["action"], "clipboard_error")
        self.assertEqual(database.records[-1]["entry_id"], 7)
        self.assertIn("error_code=adapter_write_failed", database.records[-1]["details"])
        self.assertNotIn("Secret!123", database.records[-1]["details"])


if __name__ == "__main__":
    unittest.main()
