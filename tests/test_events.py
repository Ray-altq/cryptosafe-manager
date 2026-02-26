import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.events import EventBus, Event, EventType, AuditLoggerStub

class TestEvents(unittest.TestCase):
    """Тесты для системы событий (TEST-1)"""
    
    def setUp(self):
        self.event_bus = EventBus()
        self.received_events = []
    
    def test_publish_subscribe(self):
        """Тест: подписка и публикация"""
        def callback(event):
            self.received_events.append(event)
        
        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback)
        test_event = Event(EventType.ENTRY_ADDED, {"id": 1})
        self.event_bus.publish(test_event)
        
        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0].type, EventType.ENTRY_ADDED)
    
    def test_multiple_subscribers(self):
        """Тест: несколько подписчиков"""
        count1 = 0
        count2 = 0
        
        def callback1(event):
            nonlocal count1
            count1 += 1
        
        def callback2(event):
            nonlocal count2
            count2 += 1
        
        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback1)
        self.event_bus.subscribe(EventType.ENTRY_ADDED, callback2)
        
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
        
        self.assertEqual(count1, 1)
        self.assertEqual(count2, 1)
    
    def test_different_event_types(self):
        """Тест: разные типы событий"""
        added = 0
        deleted = 0
        
        def on_add(event):
            nonlocal added
            added += 1
        
        def on_delete(event):
            nonlocal deleted
            deleted += 1
        
        self.event_bus.subscribe(EventType.ENTRY_ADDED, on_add)
        self.event_bus.subscribe(EventType.ENTRY_DELETED, on_delete)
        
        self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
        self.event_bus.publish(Event(EventType.ENTRY_DELETED, {}))
        
        self.assertEqual(added, 1)
        self.assertEqual(deleted, 1)
    
    def test_audit_logger_stub(self):
        """Тест: заглушка аудита"""
        logger = AuditLoggerStub(self.event_bus)
        # просто проверяем что нет ошибок
        try:
            self.event_bus.publish(Event(EventType.ENTRY_ADDED, {}))
            self.event_bus.publish(Event(EventType.USER_LOGGED_IN, "test"))
        except:
            self.fail("AuditLoggerStub вызвал ошибку")

if __name__ == '__main__':
    unittest.main()