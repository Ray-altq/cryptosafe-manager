import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.import_export import ExportOptions, ImportValidationError, KeyExchangeService, SharePermissions
from src.core.import_export.crypto import EXPORT_KEY_CONTEXT, SHARE_KEY_CONTEXT, derive_separated_key
from src.core.import_export.exporter import VaultExporter
from src.core.import_export.importer import VaultImporter
from src.core.import_export.sharing_service import SharingService
from src.database.db import Database
from src.database.models import VaultEntry


class FakeEntryManager:
    def __init__(self):
        self.entries = [
            {
                "id": 1,
                "title": "GitHub",
                "username": "ray",
                "password": "Secret!123",
                "notes": "personal",
                "category": "Dev",
                "tags": "git,code",
            },
            {
                "id": 2,
                "title": "Mail",
                "username": "ray@example.test",
                "password": "MailSecret!123",
                "notes": "",
                "category": "Personal",
                "tags": "mail",
            },
        ]

    def get_all_entries(self):
        return list(self.entries)

    def get_entry(self, entry_id):
        return next(entry for entry in self.entries if entry["id"] == entry_id)


class TestImportExportFoundation(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.db = Database(self.temp_file.name)
        self.entry = VaultEntry(
            title="Shared",
            username="user",
            encrypted_password=b"secret",
            encrypted_data=b"secret",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

    def tearDown(self):
        self.db.close()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def test_separated_export_and_share_keys_do_not_reuse_master_key(self):
        master_key = b"master-key-material"

        export_key = derive_separated_key(master_key, EXPORT_KEY_CONTEXT)
        share_key = derive_separated_key(master_key, SHARE_KEY_CONTEXT)

        self.assertNotEqual(export_key, master_key)
        self.assertNotEqual(share_key, master_key)
        self.assertNotEqual(export_key, share_key)
        self.assertEqual(len(export_key), 32)

    def test_exporter_supports_selected_entries_and_field_exclusion(self):
        exporter = VaultExporter(FakeEntryManager())

        entries = exporter.get_entries_for_export(ExportOptions(entry_ids=[2]))
        filtered = exporter.filter_entry_fields(entries, ["title", "username"])

        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0], {"title": "Mail", "username": "ray@example.test"})

    def test_importer_sanitizes_active_content_before_import(self):
        importer = VaultImporter(FakeEntryManager())

        with self.assertRaises(ImportValidationError):
            importer.validate_entries(
                [
                    {
                        "title": "Bad",
                        "username": "user",
                        "password": "Secret!123",
                        "notes": "<script>alert(1)</script>",
                    }
                ]
            )

    def test_sharing_metadata_is_remembered_in_database(self):
        entry_id = self.db.add_entry(self.entry)
        service = SharingService(FakeEntryManager(), database=self.db)

        metadata = service.build_share_metadata(
            entry_id=entry_id,
            recipient="student@example.test",
            encryption_method="password",
            permissions=SharePermissions(read=True, edit=False, expires_in_days=3),
        )
        service.remember_share(metadata)
        shares = self.db.get_shared_entries(limit=5)

        self.assertEqual(shares[0]["share_id"], metadata["share_id"])
        self.assertEqual(shares[0]["original_entry_id"], entry_id)
        self.assertIn('"expires_in_days": 3', shares[0]["permissions"])

    def test_key_exchange_qr_payload_validates_checksum_and_remembers_contact(self):
        service = KeyExchangeService(database=self.db)

        payload = service.build_qr_payload(identifier="alice@example.test", public_key="public-key")
        serialized = service.serialize_qr_payload(payload)
        parsed = service.parse_qr_payload(serialized)
        contact_id = service.remember_contact(parsed, name="Alice")

        contacts = self.db.get_contacts(limit=5)
        self.assertGreater(contact_id, 0)
        self.assertEqual(parsed.fingerprint, service.fingerprint_public_key("public-key"))
        self.assertEqual(contacts[0]["identifier"], "alice@example.test")

    def test_key_exchange_qr_payload_rejects_tampering(self):
        service = KeyExchangeService()
        payload = service.build_qr_payload(identifier="alice@example.test", public_key="public-key")
        tampered = json.loads(service.serialize_qr_payload(payload))
        tampered["public_key"] = "attacker-key"

        with self.assertRaises(ImportValidationError):
            service.parse_qr_payload(json.dumps(tampered))


if __name__ == "__main__":
    unittest.main()
