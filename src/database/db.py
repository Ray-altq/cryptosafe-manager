import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List
from .models import VaultEntry

class Database:
    
    def __init__(self, db_path: str = "cryptosafe.db"):
        self.db_path = db_path
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
            #проверяем версию 
            cursor = conn.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]
            
            if version == 0:
                #таблица vault_entries
                conn.execute("""
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
                """)
                conn.execute("CREATE INDEX idx_title ON vault_entries(title)")
                
                #таблица audit_log
                conn.execute("""
                    CREATE TABLE audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        entry_id INTEGER,
                        details TEXT,
                        signature BLOB
                    )
                """)
                
                #таблица settings
                conn.execute("""
                    CREATE TABLE settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        setting_key TEXT UNIQUE NOT NULL,
                        setting_value TEXT,
                        encrypted BOOLEAN DEFAULT 0
                    )
                """)
                
                #таблица key_store
                conn.execute("""
                    CREATE TABLE key_store (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_type TEXT NOT NULL,
                        salt BLOB NOT NULL,
                        hash BLOB NOT NULL,
                        params TEXT
                    )
                """)
                
                conn.execute("PRAGMA user_version = 1")
    
    def add_entry(self, entry: VaultEntry) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO vault_entries 
                (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (entry.title, entry.username, entry.encrypted_password,
                  entry.url, entry.notes, entry.created_at, entry.updated_at, entry.tags))
            return cursor.lastrowid
    
    def get_entry(self, entry_id: int) -> Optional[VaultEntry]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,))
            row = cursor.fetchone()
            if row:
                return VaultEntry(**dict(row))
            return None
    
    def get_all_entries(self) -> List[VaultEntry]:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM vault_entries ORDER BY updated_at DESC")
            return [VaultEntry(**dict(row)) for row in cursor.fetchall()]
    
    def update_entry(self, entry: VaultEntry):
        if entry.id is None:
            raise ValueError("ID не может быть None")
        entry.updated_at = datetime.now()
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE vault_entries 
                SET title=?, username=?, encrypted_password=?, url=?, 
                    notes=?, updated_at=?, tags=?
                WHERE id=?
            """, (entry.title, entry.username, entry.encrypted_password,
                  entry.url, entry.notes, entry.updated_at, entry.tags, entry.id))
    
    def delete_entry(self, entry_id: int):
        with self._get_connection() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
