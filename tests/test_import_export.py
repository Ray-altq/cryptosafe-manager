import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.import_export import ExportOptions, ImportOptions, ImportValidationError, KeyExchangeService, SharePermissions
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

    def create_entry(self, entry):
        created = dict(entry)
        created["id"] = max((item["id"] for item in self.entries), default=0) + 1
        self.entries.append(created)
        return created

    def update_entry(self, entry_id, entry):
        for index, existing in enumerate(self.entries):
            if existing["id"] == entry_id:
                updated = dict(existing)
                updated.update(entry)
                self.entries[index] = updated
                return updated
        raise KeyError(entry_id)


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

    def test_native_encrypted_json_export_import_roundtrip(self):
        source_manager = FakeEntryManager()
        target_manager = FakeEntryManager()
        target_manager.entries = []
        exporter = VaultExporter(source_manager, database=self.db)
        importer = VaultImporter(target_manager, database=self.db)

        exported = exporter.export_encrypted_json("ExportPassword!123", ExportOptions(compression=True))
        preview = importer.preview_encrypted_json(exported, "ExportPassword!123")
        result = importer.import_encrypted_json(
            exported,
            "ExportPassword!123",
            ImportOptions(format="encrypted_json", mode="merge", duplicate_strategy="skip"),
        )
        history = self.db.get_import_export_history(limit=5)

        self.assertEqual(len(preview), 2)
        self.assertEqual(result["created"], 2)
        self.assertEqual(target_manager.entries[0]["title"], "GitHub")
        self.assertEqual(target_manager.entries[0]["password"], "Secret!123")
        self.assertEqual(history[0]["operation_type"], "import")
        self.assertEqual(history[1]["operation_type"], "export")

    def test_native_encrypted_json_rejects_tampered_ciphertext_before_import(self):
        exporter = VaultExporter(FakeEntryManager(), database=self.db)
        importer = VaultImporter(FakeEntryManager(), database=self.db)
        exported = json.loads(exporter.export_encrypted_json("ExportPassword!123"))
        exported["data"]["ciphertext"] = exported["data"]["ciphertext"][:-4] + "AAAA"

        with self.assertRaises(ImportValidationError):
            importer.preview_encrypted_json(json.dumps(exported), "ExportPassword!123")

    def test_native_encrypted_json_dry_run_does_not_create_entries(self):
        target_manager = FakeEntryManager()
        target_manager.entries = []
        exported = VaultExporter(FakeEntryManager(), database=self.db).export_encrypted_json("ExportPassword!123")

        result = VaultImporter(target_manager, database=self.db).import_encrypted_json(
            exported,
            "ExportPassword!123",
            ImportOptions(format="encrypted_json", mode="dry-run"),
        )

        self.assertEqual(result["validated"], 2)
        self.assertEqual(target_manager.entries, [])

    def test_native_encrypted_json_duplicate_skip_avoids_second_copy(self):
        manager = FakeEntryManager()
        exported = VaultExporter(manager, database=self.db).export_encrypted_json("ExportPassword!123")

        result = VaultImporter(manager, database=self.db).import_encrypted_json(
            exported,
            "ExportPassword!123",
            ImportOptions(format="encrypted_json", mode="merge", duplicate_strategy="skip"),
        )

        self.assertEqual(result["skipped"], 2)
        self.assertEqual(len(manager.entries), 2)

    def test_csv_export_requires_explicit_plaintext_allow_and_roundtrips(self):
        exporter = VaultExporter(FakeEntryManager(), database=self.db)

        with self.assertRaises(ValueError):
            exporter.export_csv(ExportOptions(format="csv", plaintext_allowed=False))

        exported = exporter.export_csv(ExportOptions(format="csv", plaintext_allowed=True))
        preview = VaultImporter(FakeEntryManager(), database=self.db).preview_plaintext(
            exported,
            ImportOptions(format="csv"),
        )

        self.assertIn("title,username,password", exported)
        self.assertEqual(preview[0]["title"], "GitHub")
        self.assertEqual(preview[0]["password"], "Secret!123")

    def test_lastpass_csv_import_maps_known_columns(self):
        manager = FakeEntryManager()
        manager.entries = []
        payload = "url,username,password,extra,name,grouping\nhttps://example.test,alice,Secret!123,notes,Example,Work\n"

        result = VaultImporter(manager, database=self.db).import_plaintext(
            payload,
            ImportOptions(format="lastpass_csv", mode="merge"),
        )

        self.assertEqual(result["created"], 1)
        self.assertEqual(manager.entries[0]["title"], "Example")
        self.assertEqual(manager.entries[0]["category"], "Work")

    def test_bitwarden_json_import_maps_login_items(self):
        manager = FakeEntryManager()
        manager.entries = []
        payload = json.dumps(
            {
                "items": [
                    {
                        "type": 1,
                        "name": "Vault Item",
                        "notes": "safe notes",
                        "folderId": "Personal",
                        "login": {
                            "username": "bob",
                            "password": "Secret!123",
                            "uris": [{"uri": "https://vault.example"}],
                        },
                        "fields": [{"name": "tag-one"}, {"name": "tag-two"}],
                    }
                ]
            }
        )

        preview = VaultImporter(manager, database=self.db).preview_plaintext(
            payload,
            ImportOptions(format="bitwarden_json"),
        )
        result = VaultImporter(manager, database=self.db).import_plaintext(
            payload,
            ImportOptions(format="bitwarden_json", mode="merge"),
        )

        self.assertEqual(preview[0]["title"], "Vault Item")
        self.assertEqual(preview[0]["url"], "https://vault.example")
        self.assertEqual(preview[0]["tags"], "tag-one,tag-two")
        self.assertEqual(result["created"], 1)

    def test_plaintext_import_dry_run_does_not_create_entries(self):
        manager = FakeEntryManager()
        manager.entries = []
        payload = "title,username,password,url,notes,category,tags\nExample,alice,Secret!123,,,,\n"

        result = VaultImporter(manager, database=self.db).import_plaintext(
            payload,
            ImportOptions(format="csv", mode="dry-run"),
        )

        self.assertEqual(result["validated"], 1)
        self.assertEqual(manager.entries, [])


if __name__ == "__main__":
    unittest.main()
