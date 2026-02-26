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
            #преобразуем datetime в строку для SQLite
            created_at = entry.created_at.isoformat() if entry.created_at else datetime.now().isoformat()
            updated_at = entry.updated_at.isoformat() if entry.updated_at else datetime.now().isoformat()
        
            cursor = conn.execute("""
              INSERT INTO vault_entries 
              (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
              entry.title, 
              entry.username, 
              entry.encrypted_password,
              entry.url, 
              entry.notes, 
              created_at,  # строка
              updated_at,  # строка
              entry.tags
            ))
            return cursor.lastrowid
    
    def get_entry(self, entry_id: int) -> Optional[VaultEntry]:
        with self._get_connection() as conn:
          cursor = conn.execute(
            "SELECT * FROM vault_entries WHERE id = ?",
            (entry_id,)
          )
          row = cursor.fetchone()
          if row:
              data = dict(row)
              # преобразуем строки обратно в datetime
              if data.get('created_at'):
                  data['created_at'] = datetime.fromisoformat(data['created_at'])
              if data.get('updated_at'):
                  data['updated_at'] = datetime.fromisoformat(data['updated_at'])
              return VaultEntry(**data)
          return None

    def get_all_entries(self) -> List[VaultEntry]:
        with self._get_connection() as conn:
          cursor = conn.execute(
              "SELECT * FROM vault_entries ORDER BY updated_at DESC"
          )
          entries = []
          for row in cursor.fetchall():
              data = dict(row)
              # преобразуем строки обратно в datetime
              if data.get('created_at'):
                  data['created_at'] = datetime.fromisoformat(data['created_at'])
              if data.get('updated_at'):
                  data['updated_at'] = datetime.fromisoformat(data['updated_at'])
              entries.append(VaultEntry(**data))
          return entries
    
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
