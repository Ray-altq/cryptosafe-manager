import os
import sqlite3
import sys
import tempfile
import time
import tracemalloc
import unittest
import json
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.audit import AuditLogger, AuditLogVerifier, export_logs_to_cef, export_logs_to_json, import_logs_from_json
from src.core.events import EventBus
from src.database.db import Database


class TestAuditLogging(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        self.event_bus = EventBus()
        self.logger = AuditLogger(self.database, self.event_bus, key_provider=lambda: b"a" * 32)
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)

    def tearDown(self):
        self.logger.close()
        self.database.close()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def _generate_logs(self, total: int, *, flush: bool = True):
        for index in range(total):
            self.logger.log_event(
                event_type="settings_changed",
                severity="WARN" if index % 10 == 0 else "INFO",
                source="configuration",
                details={
                    "scope": "security",
                    "changed_keys": [f"setting_{index % 5}"],
                    "record": index,
                },
                user_id="local-user",
            )
        if flush:
            self.logger.flush()

    def test_integrity_test_detects_database_tampering_after_1000_entries(self):
        self._generate_logs(1000)

        with self.database._get_connection() as conn:
            conn.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update")
            conn.execute(
                "UPDATE audit_log SET entry_data = ? WHERE sequence_number = ?",
                ('{"tampered":true}', 501),
            )

        results = self.verifier.verify()

        self.assertFalse(results["verified"])
        self.assertTrue(any(item["sequence_number"] == 501 for item in results["invalid_entries"]))

    def test_performance_test_handles_10000_events_with_target_thresholds(self):
        started_at = time.perf_counter()
        self._generate_logs(10000, flush=False)
        enqueue_elapsed = time.perf_counter() - started_at
        average_logging_time = enqueue_elapsed / 10000

        flush_started_at = time.perf_counter()
        self.logger.flush()
        flush_elapsed = time.perf_counter() - flush_started_at

        verification_started_at = time.perf_counter()
        verification_result = self.verifier.verify(start_sequence=9001)
        verification_elapsed = time.perf_counter() - verification_started_at

        query_started_at = time.perf_counter()
        filtered_logs = self.database.query_audit_logs(
            search_text="security",
            event_type="settings_changed",
            limit=100,
            offset=0,
        )
        query_elapsed = time.perf_counter() - query_started_at

        tracemalloc.start()
        _ = self.database.query_audit_logs(limit=10000, offset=0)
        _current, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertTrue(verification_result["verified"])
        self.assertEqual(len(filtered_logs), 100)
        self.assertGreaterEqual(self.database.count_audit_logs(), 10001)
        self.assertLess(average_logging_time, 0.01)
        self.assertGreater(flush_elapsed, 0.0)
        self.assertLess(verification_elapsed, 1.0)
        self.assertLess(query_elapsed, 0.5)
        self.assertLess(peak_memory, 50 * 1024 * 1024)

    def test_export_import_test_verifies_signed_json_and_reimported_chain(self):
        self._generate_logs(25)
        original_logs = self.database.get_audit_log_chain()
        exported_json = export_logs_to_json(original_logs, public_key=self.logger.signer.public_key_hex)

        exported_verification = self.verifier.verify_exported_json(exported_json)
        self.assertTrue(exported_verification["verified"])

        imported_entries = import_logs_from_json(exported_json)
        imported_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        imported_temp.close()
        imported_database = Database(imported_temp.name)
        try:
            imported_database.import_audit_logs(imported_entries)
            imported_verifier = AuditLogVerifier(imported_database, self.logger.signer)
            imported_results = imported_verifier.verify()
            self.assertTrue(imported_results["verified"])
            self.assertEqual(imported_results["total_entries"], len(imported_entries))
        finally:
            imported_database.close()
            try:
                os.unlink(imported_temp.name)
            except OSError:
                pass

    def test_cef_export_contains_standard_header_and_extensions(self):
        self._generate_logs(2)
        logs = self.database.get_audit_log_chain()

        cef_payload = export_logs_to_cef(logs)
        first_line = cef_payload.splitlines()[0]

        self.assertTrue(first_line.startswith("CEF:0|CryptoSafe|Manager|5|"))
        self.assertIn("rt=", first_line)
        self.assertIn("suser=", first_line)
        self.assertIn("cn1Label=sequence_number", first_line)

    def test_failure_recovery_test_reports_database_corruption_gracefully(self):
        self._generate_logs(5)

        with patch.object(self.database, "get_audit_log_chain", side_effect=sqlite3.DatabaseError("corrupted")):
            results = self.verifier.verify()

        self.assertFalse(results["verified"])
        self.assertEqual(results["invalid_entries"][0]["reason"], "database_error")
        self.assertIn("restore_from_backup", results["recovery_options"])

    def test_security_test_blocks_sql_injection_style_queries_and_keeps_audit_table_intact(self):
        self._generate_logs(10)
        malicious_search = "'; DROP TABLE audit_log; --"

        results = self.database.query_audit_logs(search_text=malicious_search, limit=10, offset=0)
        remaining_count = self.database.count_audit_logs()

        self.assertEqual(results, [])
        self.assertEqual(remaining_count, 11)

    def test_audit_log_entry_data_is_encrypted_at_rest_and_decrypted_on_read(self):
        self._generate_logs(1)

        with self.database._get_connection() as conn:
            raw_row = conn.execute(
                "SELECT entry_data FROM audit_log WHERE sequence_number = 2"
            ).fetchone()

        raw_entry_data = raw_row["entry_data"]
        self.assertNotIn('"event_type": "settings_changed"', raw_entry_data)
        self.assertTrue(json.loads(raw_entry_data)["encrypted"])

        log = self.database.get_audit_log_by_sequence(2)
        self.assertIn('"event_type": "settings_changed"', log.entry_data)

    def test_audit_entry_includes_utc_reliable_time_source_metadata(self):
        self._generate_logs(1)

        log = self.database.get_audit_log_by_sequence(2)
        payload = json.loads(log.entry_data)

        self.assertTrue(payload["timestamp"].endswith("Z"))
        self.assertEqual(payload["time_source"]["timezone"], "UTC")
        self.assertTrue(payload["time_source"]["synchronized"])
        self.assertEqual(payload["time_source"]["reliable_source"], "operating_system_clock")

    def test_append_only_protection_blocks_update_attempt_and_logs_violation(self):
        self._generate_logs(3)

        with self.assertRaises(sqlite3.DatabaseError):
            self.database.try_update_audit_log_entry(2, '{"tampered":true}')
        with self.assertRaises(PermissionError):
            self.database.try_disable_audit_guards()
        self.logger.flush()

        logs = self.database.get_audit_log_chain()
        self.assertEqual(logs[-2].event_type, "audit_log_protection_triggered")
        self.assertIn('"operation": "update"', logs[-2].details)
        self.assertEqual(logs[-1].event_type, "audit_log_protection_triggered")
        self.assertIn('"operation": "disable_protection"', logs[-1].details)
        security_events = self.database.get_audit_security_events(limit=5)
        self.assertEqual(security_events[0]["event_type"], "audit_log_protection_triggered")
        self.assertEqual(security_events[1]["event_type"], "audit_log_protection_triggered")

    def test_rotation_policy_archives_ranges_without_breaking_active_chain(self):
        self.logger.close()
        self.database.set_audit_retention_policy(max_entries=5, max_age_days=3650, enabled=True)
        self.logger = AuditLogger(
            self.database,
            self.event_bus,
            key_provider=lambda: b"a" * 32,
            config={"async_logging_enabled": False},
        )
        self.verifier = AuditLogVerifier(self.database, self.logger.signer)

        self._generate_logs(7)

        archives = self.database.get_audit_archives()
        archived_count = sum(int(item["entry_count"]) for item in archives)
        verification_result = self.verifier.verify()

        self.assertGreaterEqual(archived_count, 3)
        self.assertTrue(verification_result["verified"])

    def test_async_logging_flushes_non_critical_events_and_keeps_critical_sync(self):
        record_id = self.logger.log_event(
            event_type="settings_changed",
            severity="INFO",
            source="configuration",
            details={"scope": "security"},
            user_id="local-user",
        )
        self.assertEqual(record_id, 0)

        self.logger.flush()
        self.assertEqual(self.database.count_audit_logs(), 2)

        critical_record_id = self.logger.log_event(
            event_type="audit_verification_failed",
            severity="ERROR",
            source="audit",
            details={"reason": "chain_break"},
            user_id="system",
        )
        self.assertGreater(critical_record_id, 0)

    def test_integration_hook_receives_signed_audit_payload_without_breaking_logging(self):
        received_payloads = []
        self.logger.register_integration_hook(
            "siem",
            lambda payload: received_payloads.append(payload),
            event_types=["panic_mode_activated"],
        )

        record_id = self.logger.log_event(
            event_type="panic_mode_activated",
            severity="CRITICAL",
            source="panic_mode",
            details={"reason": "user_request", "secret": "Sensitive"},
            user_id="local-user",
            force_sync=True,
        )

        self.assertGreater(record_id, 0)
        self.assertEqual(len(received_payloads), 1)
        self.assertEqual(received_payloads[0]["event_type"], "panic_mode_activated")
        self.assertEqual(received_payloads[0]["details"]["secret"], "[REDACTED]")
        self.assertIn("entry_hash", received_payloads[0])

    def test_integration_hook_failure_is_recorded_in_secure_log(self):
        def failing_hook(_payload):
            raise RuntimeError("hook unavailable")

        self.logger.register_integration_hook("broken-hook", failing_hook)

        self.logger.log_event(
            event_type="totp_code_generated",
            severity="INFO",
            source="totp",
            details={"account": "example"},
            user_id="local-user",
            force_sync=True,
        )

        security_events = self.database.get_audit_security_events(limit=1)
        self.assertEqual(security_events[0]["event_type"], "audit_integration_hook_failed")
        self.assertIn("broken-hook", security_events[0]["details"])


if __name__ == "__main__":
    unittest.main()
