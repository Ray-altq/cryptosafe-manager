import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import AuditLog, KeyStore, VaultEntry


class Database:
    def __init__(self, db_path: str = "cryptosafe.db"):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._create_schema(conn)
                conn.execute("PRAGMA user_version = 2")
            elif version == 1:
                self._migrate_v1_to_v2(conn)
                conn.execute("PRAGMA user_version = 2")

    def _create_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )
        conn.execute("CREATE INDEX idx_title ON vault_entries(title)")
        conn.execute("CREATE INDEX idx_entries_updated_at ON vault_entries(updated_at)")

        conn.execute(
            """
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                entry_id INTEGER,
                details TEXT,
                signature BLOB
            )
            """
        )
        conn.execute("CREATE INDEX idx_audit_timestamp ON audit_log(timestamp)")

        conn.execute(
            """
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                encrypted BOOLEAN DEFAULT 0
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                hash TEXT NOT NULL,
                params TEXT,
                created_at TIMESTAMP NOT NULL,
                last_rotated_at TIMESTAMP NOT NULL
            )
            """
        )

    def _migrate_v1_to_v2(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(key_store)").fetchall()}
        if "created_at" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN created_at TIMESTAMP")
        if "last_rotated_at" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN last_rotated_at TIMESTAMP")

        now = datetime.now().isoformat()
        conn.execute(
            """
            UPDATE key_store
            SET created_at = COALESCE(created_at, ?),
                last_rotated_at = COALESCE(last_rotated_at, ?)
            """,
            (now, now),
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON vault_entries(updated_at)")

    def add_entry(self, entry: VaultEntry) -> int:
        with self._get_connection() as conn:
            created_at = entry.created_at.isoformat() if entry.created_at else datetime.now().isoformat()
            updated_at = entry.updated_at.isoformat() if entry.updated_at else datetime.now().isoformat()
            cursor = conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    created_at,
                    updated_at,
                    entry.tags,
                ),
            )
            return cursor.lastrowid

    def get_entry(self, entry_id: int) -> Optional[VaultEntry]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,)).fetchone()
            return self._row_to_entry(row) if row else None

    def get_all_entries(self) -> List[VaultEntry]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM vault_entries ORDER BY updated_at DESC").fetchall()
            return [self._row_to_entry(row) for row in rows]

    def update_entry(self, entry: VaultEntry):
        if entry.id is None:
            raise ValueError("ID cannot be None")
        entry.updated_at = datetime.now()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title=?, username=?, encrypted_password=?, url=?, notes=?, updated_at=?, tags=?
                WHERE id=?
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.updated_at.isoformat(),
                    entry.tags,
                    entry.id,
                ),
            )

    def delete_entry(self, entry_id: int):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    def add_audit_log(self, action: str, timestamp: datetime, entry_id: Optional[int] = None, details: str = ""):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action, timestamp.isoformat(), entry_id, details, None),
            )

    def get_audit_logs(self, limit: int = 200) -> List[AuditLog]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            logs = []
            for row in rows:
                data = dict(row)
                if data.get("timestamp"):
                    data["timestamp"] = datetime.fromisoformat(data["timestamp"])
                logs.append(AuditLog(**data))
            return logs

    def backup(self, backup_path: str):
        backup_file = Path(backup_path)
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        source = sqlite3.connect(self.db_path)
        destination = sqlite3.connect(str(backup_file))
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

    def set_setting(self, key: str, value, encrypted: bool = False):
        serialized = json.dumps(value, ensure_ascii=False)
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    encrypted = excluded.encrypted
                """,
                (key, serialized, int(encrypted)),
            )

    def get_setting(self, key: str, default=None):
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT setting_value FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
            if not row:
                return default
            try:
                return json.loads(row["setting_value"])
            except (TypeError, json.JSONDecodeError):
                return row["setting_value"]

    def save_key_store(self, key_store: KeyStore):
        now = datetime.now()
        created_at = (key_store.created_at or now).isoformat()
        last_rotated_at = (key_store.last_rotated_at or now).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, salt, hash, params, created_at, last_rotated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    salt = excluded.salt,
                    hash = excluded.hash,
                    params = excluded.params,
                    last_rotated_at = excluded.last_rotated_at
                """,
                (
                    key_store.key_type,
                    key_store.salt,
                    key_store.hash,
                    key_store.params,
                    created_at,
                    last_rotated_at,
                ),
            )

    def get_key_store(self, key_type: str = "master") -> Optional[KeyStore]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM key_store WHERE key_type = ?", (key_type,)).fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("created_at"):
                data["created_at"] = datetime.fromisoformat(data["created_at"])
            if data.get("last_rotated_at"):
                data["last_rotated_at"] = datetime.fromisoformat(data["last_rotated_at"])
            return KeyStore(**data)

    def _row_to_entry(self, row: sqlite3.Row) -> VaultEntry:
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("updated_at"):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return VaultEntry(**data)
