import json
import queue
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from .models import AuditLog, KeyStore, VaultEntry


class Database:
    SCHEMA_VERSION = 5

    def __init__(self, db_path: str = "cryptosafe.db", pool_size: int = 4):
        self.db_path = db_path
        self.pool_size = max(1, int(pool_size))
        self._connection_pool: "queue.LifoQueue[sqlite3.Connection]" = queue.LifoQueue(maxsize=self.pool_size)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._acquire_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release_connection(conn)

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

    def _acquire_connection(self) -> sqlite3.Connection:
        try:
            return self._connection_pool.get_nowait()
        except queue.Empty:
            return self._create_connection()

    def _release_connection(self, conn: sqlite3.Connection):
        try:
            self._connection_pool.put_nowait(conn)
        except queue.Full:
            conn.close()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def close(self):
        while True:
            try:
                conn = self._connection_pool.get_nowait()
            except queue.Empty:
                break
            conn.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

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
                if version == 4:
                    self._migrate_v4_to_v5(conn)
                    version = 5
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
                sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id TEXT NOT NULL,
                source TEXT NOT NULL,
                entry_id INTEGER,
                details TEXT,
                action TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                entry_data BLOB NOT NULL,
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX idx_audit_event_type ON audit_log(event_type)")
        conn.execute("CREATE UNIQUE INDEX idx_audit_sequence ON audit_log(sequence_number)")

        conn.execute(
            """
            CREATE TABLE audit_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX idx_audit_public_keys_active ON audit_public_keys(public_key)")

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

    def _migrate_v4_to_v5(self, conn: sqlite3.Connection):
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "event_type" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN event_type TEXT")
        if "severity" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN severity TEXT")
        if "user_id" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN user_id TEXT")
        if "source" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN source TEXT")
        if "previous_hash" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
        if "entry_hash" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
        if "entry_data" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN entry_data BLOB")
        if "public_key" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN public_key TEXT")
        if "sequence_number" not in columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN sequence_number INTEGER")

        rows = conn.execute(
            "SELECT rowid, action, timestamp, entry_id, details FROM audit_log ORDER BY COALESCE(timestamp, ''), rowid"
        ).fetchall()
        previous_hash = "0" * 64
        for index, row in enumerate(rows, start=1):
            details_text = row["details"] or ""
            event_payload = {
                "timestamp": row["timestamp"] or datetime.utcnow().isoformat() + "Z",
                "event_type": row["action"] or "legacy_event",
                "severity": "INFO",
                "user_id": "local-user",
                "source": "legacy_migration",
                "entry_id": row["entry_id"],
                "details": {"legacy_details": details_text},
                "sequence_number": index,
                "previous_hash": previous_hash,
            }
            entry_data = json.dumps(event_payload, ensure_ascii=False, sort_keys=True)
            entry_hash = self._compute_hash(entry_data)
            conn.execute(
                """
                UPDATE audit_log
                SET event_type = COALESCE(event_type, ?),
                    severity = COALESCE(severity, ?),
                    user_id = COALESCE(user_id, ?),
                    source = COALESCE(source, ?),
                    previous_hash = COALESCE(previous_hash, ?),
                    entry_hash = COALESCE(entry_hash, ?),
                    entry_data = COALESCE(entry_data, ?),
                    public_key = COALESCE(public_key, ?),
                    sequence_number = COALESCE(sequence_number, ?),
                    signature = COALESCE(signature, ?)
                WHERE rowid = ?
                """,
                (
                    row["action"] or "legacy_event",
                    "INFO",
                    "local-user",
                    "legacy_migration",
                    previous_hash,
                    entry_hash,
                    entry_data,
                    "legacy",
                    index,
                    "legacy",
                    row["rowid"],
                ),
            )
            previous_hash = entry_hash

        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_public_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_public_keys_active ON audit_public_keys(public_key)")

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

    def add_audit_log(
        self,
        action: str,
        timestamp: datetime,
        entry_id: Optional[int] = None,
        details: str = "",
        *,
        event_type: Optional[str] = None,
        severity: str = "INFO",
        user_id: str = "local-user",
        source: str = "unknown",
        previous_hash: str = "",
        entry_hash: str = "",
        entry_data: str = "",
        signature: str = "",
        public_key: str = "",
    ) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp,
                    event_type,
                    severity,
                    user_id,
                    source,
                    entry_id,
                    details,
                    action,
                    previous_hash,
                    entry_hash,
                    entry_data,
                    signature,
                    public_key
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp.isoformat(),
                    event_type or action,
                    severity,
                    user_id,
                    source,
                    entry_id,
                    details,
                    action,
                    previous_hash,
                    entry_hash,
                    entry_data,
                    signature,
                    public_key,
                ),
            )
            return int(cursor.lastrowid)

    def get_audit_logs(self, limit: int = 200, offset: int = 0) -> List[AuditLog]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT rowid AS id, * FROM audit_log ORDER BY sequence_number DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            logs = []
            for row in rows:
                data = dict(row)
                if data.get("timestamp"):
                    data["timestamp"] = datetime.fromisoformat(data["timestamp"])
                if not data.get("action"):
                    data["action"] = data.get("event_type", "")
                if not data.get("details") and data.get("entry_data"):
                    try:
                        payload = json.loads(data["entry_data"])
                        data["details"] = json.dumps(payload.get("details", {}), ensure_ascii=False, sort_keys=True)
                    except (TypeError, json.JSONDecodeError):
                        data["details"] = ""
                logs.append(AuditLog(**data))
            return logs

    def query_audit_logs(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: Optional[Any] = None,
        date_to: Optional[Any] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AuditLog]:
        where_clauses = []
        params: List[Any] = []

        normalized_search = str(search_text or "").strip().lower()
        if normalized_search:
            where_clauses.append(
                "(LOWER(event_type) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(source) LIKE ? OR LOWER(details) LIKE ?)"
            )
            like_value = f"%{normalized_search}%"
            params.extend([like_value, like_value, like_value, like_value, like_value])

        normalized_event_type = str(event_type or "").strip().lower()
        if normalized_event_type and normalized_event_type not in {"all", "все"}:
            where_clauses.append("LOWER(event_type) = ?")
            params.append(normalized_event_type)

        normalized_severity = str(severity or "").strip().upper()
        if normalized_severity and normalized_severity not in {"ALL", "ВСЕ"}:
            where_clauses.append("severity = ?")
            params.append(normalized_severity)

        normalized_user = str(user_id or "").strip().lower()
        if normalized_user and normalized_user not in {"all", "все"}:
            where_clauses.append("LOWER(user_id) LIKE ?")
            params.append(f"%{normalized_user}%")

        from_dt = self._normalize_audit_datetime(date_from, is_end=False)
        if from_dt is not None:
            where_clauses.append("timestamp >= ?")
            params.append(from_dt.isoformat())

        to_dt = self._normalize_audit_datetime(date_to, is_end=True)
        if to_dt is not None:
            where_clauses.append("timestamp <= ?")
            params.append(to_dt.isoformat())

        query = "SELECT rowid AS id, * FROM audit_log"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        query += " ORDER BY sequence_number DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return self._rows_to_audit_logs(rows)

    def count_audit_logs(
        self,
        *,
        search_text: str = "",
        event_type: str = "",
        severity: str = "",
        user_id: str = "",
        date_from: Optional[Any] = None,
        date_to: Optional[Any] = None,
    ) -> int:
        where_clauses = []
        params: List[Any] = []

        normalized_search = str(search_text or "").strip().lower()
        if normalized_search:
            where_clauses.append(
                "(LOWER(event_type) LIKE ? OR LOWER(severity) LIKE ? OR LOWER(user_id) LIKE ? OR LOWER(source) LIKE ? OR LOWER(details) LIKE ?)"
            )
            like_value = f"%{normalized_search}%"
            params.extend([like_value, like_value, like_value, like_value, like_value])

        normalized_event_type = str(event_type or "").strip().lower()
        if normalized_event_type and normalized_event_type not in {"all", "все"}:
            where_clauses.append("LOWER(event_type) = ?")
            params.append(normalized_event_type)

        normalized_severity = str(severity or "").strip().upper()
        if normalized_severity and normalized_severity not in {"ALL", "ВСЕ"}:
            where_clauses.append("severity = ?")
            params.append(normalized_severity)

        normalized_user = str(user_id or "").strip().lower()
        if normalized_user and normalized_user not in {"all", "все"}:
            where_clauses.append("LOWER(user_id) LIKE ?")
            params.append(f"%{normalized_user}%")

        from_dt = self._normalize_audit_datetime(date_from, is_end=False)
        if from_dt is not None:
            where_clauses.append("timestamp >= ?")
            params.append(from_dt.isoformat())

        to_dt = self._normalize_audit_datetime(date_to, is_end=True)
        if to_dt is not None:
            where_clauses.append("timestamp <= ?")
            params.append(to_dt.isoformat())

        query = "SELECT COUNT(*) AS total FROM audit_log"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        with self._get_connection() as conn:
            return int(conn.execute(query, tuple(params)).fetchone()["total"])

    def get_audit_log_chain(self, start_sequence: int = 0, limit: Optional[int] = None) -> List[AuditLog]:
        query = "SELECT rowid AS id, * FROM audit_log WHERE sequence_number >= ? ORDER BY sequence_number ASC"
        params: List[Any] = [start_sequence]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        with self._get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return self._rows_to_audit_logs(rows)

    def get_audit_log_by_sequence(self, sequence_number: int) -> Optional[AuditLog]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT rowid AS id, * FROM audit_log WHERE sequence_number = ?",
                (sequence_number,),
            ).fetchone()
            if row is None:
                return None
            return self._rows_to_audit_logs([row])[0]

    def get_latest_audit_log(self) -> Optional[AuditLog]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT rowid AS id, * FROM audit_log ORDER BY sequence_number DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            return self._rows_to_audit_logs([row])[0]

    def register_audit_public_key(self, algorithm: str, public_key: str):
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_public_keys (algorithm, public_key, created_at, is_active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(public_key) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    is_active = 1
                """,
                (algorithm, public_key, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )

    def import_audit_logs(self, entries: List[Dict[str, Any]]):
        with self.transaction() as conn:
            for entry in entries:
                conn.execute(
                    """
                    INSERT INTO audit_log (
                        sequence_number,
                        timestamp,
                        event_type,
                        severity,
                        user_id,
                        source,
                        entry_id,
                        details,
                        action,
                        previous_hash,
                        entry_hash,
                        entry_data,
                        signature,
                        public_key
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(entry.get("sequence_number", 0) or 0),
                        str(entry.get("timestamp", "")),
                        str(entry.get("event_type", entry.get("action", "")) or ""),
                        str(entry.get("severity", "INFO") or "INFO"),
                        str(entry.get("user_id", "local-user") or "local-user"),
                        str(entry.get("source", "unknown") or "unknown"),
                        entry.get("entry_id"),
                        str(entry.get("details", "") or ""),
                        str(entry.get("event_type", entry.get("action", "")) or ""),
                        str(entry.get("previous_hash", "") or ""),
                        str(entry.get("entry_hash", "") or ""),
                        str(entry.get("entry_data", "") or ""),
                        str(entry.get("signature", "") or ""),
                        str(entry.get("public_key", "") or ""),
                    ),
                )

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

    def _compute_hash(self, value: str) -> str:
        import hashlib

        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _rows_to_audit_logs(self, rows) -> List[AuditLog]:
        result: List[AuditLog] = []
        for row in rows:
            data = dict(row)
            if data.get("timestamp"):
                data["timestamp"] = datetime.fromisoformat(data["timestamp"])
            if not data.get("action"):
                data["action"] = data.get("event_type", "")
            if not data.get("details") and data.get("entry_data"):
                try:
                    payload = json.loads(data["entry_data"])
                    data["details"] = json.dumps(payload.get("details", {}), ensure_ascii=False, sort_keys=True)
                except (TypeError, json.JSONDecodeError):
                    data["details"] = ""
            result.append(AuditLog(**data))
        return result

    def _normalize_audit_datetime(self, raw_value: Any, *, is_end: bool) -> Optional[datetime]:
        if isinstance(raw_value, datetime):
            return raw_value
        if isinstance(raw_value, date):
            return datetime.combine(raw_value, time.max if is_end else time.min)

        value = str(raw_value or "").strip()
        if not value:
            return None

        try:
            parsed_date = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None

        return datetime.combine(parsed_date, time.max if is_end else time.min)

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
