import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from .models import AuditLog, KeyStore, VaultEntry


class Database:
    SCHEMA_VERSION = 4

    def __init__(self, db_path: str = "cryptosafe.db"):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._get_connection() as conn:
            try:
                conn.execute("BEGIN")
                yield conn
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()

    def _init_db(self):
        with self._get_connection() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._create_schema(conn)
                conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            else:
                if version == 1:
                    self._migrate_v1_to_v2(conn)
                    version = 2
                if version == 2:
                    self._migrate_v2_to_v3(conn)
                    version = 3
                if version == 3:
                    self._migrate_v3_to_v4(conn)
                    version = 4
                conn.execute(f"PRAGMA user_version = {max(version, self.SCHEMA_VERSION)}")

    def _create_schema(self, conn: sqlite3.Connection):
        conn.execute(
            """
            CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                encrypted_data BLOB,
                url TEXT,
                notes TEXT,
                category TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )
        conn.execute("CREATE INDEX idx_title ON vault_entries(title)")
        conn.execute("CREATE INDEX idx_entries_created_at ON vault_entries(created_at)")
        conn.execute("CREATE INDEX idx_entries_updated_at ON vault_entries(updated_at)")
        conn.execute("CREATE INDEX idx_entries_tags ON vault_entries(tags)")

        conn.execute(
            """
            CREATE TABLE deleted_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_entry_id INTEGER,
                encrypted_data BLOB NOT NULL,
                title TEXT,
                deleted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX idx_deleted_entries_expires_at ON deleted_entries(expires_at)")

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
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL,
                salt BLOB,
                hash TEXT,
                params TEXT,
                last_rotated_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX idx_key_store_type ON key_store(key_type)")

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

    def _migrate_v2_to_v3(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(key_store)").fetchall()}
        if "key_data" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN key_data BLOB")
        if "version" not in columns:
            conn.execute("ALTER TABLE key_store ADD COLUMN version INTEGER DEFAULT 1")

        rows = conn.execute("SELECT id, key_type, salt, hash, params, key_data FROM key_store").fetchall()
        for row in rows:
            key_data = row["key_data"]
            if key_data is None:
                if row["hash"]:
                    key_data = row["hash"].encode("utf-8")
                elif row["salt"]:
                    key_data = row["salt"]
                elif row["params"]:
                    key_data = row["params"].encode("utf-8")
                else:
                    key_data = b""
                conn.execute("UPDATE key_store SET key_data = ? WHERE id = ?", (key_data, row["id"]))

        conn.execute("UPDATE key_store SET version = COALESCE(version, 1)")

    def _migrate_v3_to_v4(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(vault_entries)").fetchall()}
        if "encrypted_data" not in columns:
            conn.execute("ALTER TABLE vault_entries ADD COLUMN encrypted_data BLOB")
        if "category" not in columns:
            conn.execute("ALTER TABLE vault_entries ADD COLUMN category TEXT NOT NULL DEFAULT ''")

        conn.execute(
            """
            UPDATE vault_entries
            SET encrypted_data = COALESCE(encrypted_data, encrypted_password)
            """
        )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_created_at ON vault_entries(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_updated_at ON vault_entries(updated_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_tags ON vault_entries(tags)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_entry_id INTEGER,
                encrypted_data BLOB NOT NULL,
                title TEXT,
                deleted_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deleted_entries_expires_at ON deleted_entries(expires_at)")

    def add_entry(self, entry: VaultEntry) -> int:
        with self._get_connection() as conn:
            created_at = entry.created_at.isoformat() if entry.created_at else datetime.now().isoformat()
            updated_at = entry.updated_at.isoformat() if entry.updated_at else datetime.now().isoformat()
            cursor = conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, encrypted_data, url, notes, category, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.encrypted_data or entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.category,
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
                SET title=?, username=?, encrypted_password=?, encrypted_data=?, url=?, notes=?, category=?, updated_at=?, tags=?
                WHERE id=?
                """,
                (
                    entry.title,
                    entry.username,
                    entry.encrypted_password,
                    entry.encrypted_data or entry.encrypted_password,
                    entry.url,
                    entry.notes,
                    entry.category,
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
                INSERT INTO key_store
                (key_type, key_data, version, created_at, salt, hash, params, last_rotated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET
                    key_data = excluded.key_data,
                    version = excluded.version,
                    salt = excluded.salt,
                    hash = excluded.hash,
                    params = excluded.params,
                    last_rotated_at = excluded.last_rotated_at
                """,
                (
                    key_store.key_type,
                    key_store.key_data,
                    key_store.version,
                    created_at,
                    key_store.salt,
                    key_store.hash,
                    key_store.params,
                    last_rotated_at,
                ),
            )

    def get_key_store(self, key_type: str) -> Optional[KeyStore]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM key_store WHERE key_type = ?", (key_type,)).fetchone()
            if not row:
                return None
            return self._row_to_key_store(row)

    def reencrypt_passwords(
        self,
        transform,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        pause_event=None,
    ) -> int:
        with self.transaction() as conn:
            rows = conn.execute("SELECT id, encrypted_password FROM vault_entries ORDER BY id").fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)
            for index, row in enumerate(rows, start=1):
                if pause_event is not None:
                    pause_event.wait()
                updated_password = transform(row["encrypted_password"])
                conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, encrypted_data = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_password, updated_password, datetime.now().isoformat(), row["id"]),
                )
                if progress_callback is not None:
                    progress_callback(index, total)
            return total

    def reencrypt_entry_payloads(
        self,
        transform,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        pause_event=None,
    ) -> int:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id, encrypted_password, encrypted_data FROM vault_entries ORDER BY id"
            ).fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)
            for index, row in enumerate(rows, start=1):
                if pause_event is not None:
                    pause_event.wait()
                updated_password, updated_data = transform(row["encrypted_password"], row["encrypted_data"])
                conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, encrypted_data = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_password, updated_data, datetime.now().isoformat(), row["id"]),
                )
                if progress_callback is not None:
                    progress_callback(index, total)
            return total

    def _row_to_entry(self, row: sqlite3.Row) -> VaultEntry:
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("updated_at"):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return VaultEntry(**data)

    def _row_to_key_store(self, row: sqlite3.Row) -> KeyStore:
        data = dict(row)
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("last_rotated_at"):
            data["last_rotated_at"] = datetime.fromisoformat(data["last_rotated_at"])
        return KeyStore(**data)
