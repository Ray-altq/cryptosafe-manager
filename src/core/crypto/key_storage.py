import json
from datetime import datetime
from typing import Optional

from ...database.db import Database
from ...database.models import KeyStore


class KeyStorage:
    def __init__(self, database: Database, key_type: str = "master"):
        self.database = database
        self.key_type = key_type
        self._cached_key: Optional[bytearray] = None

    def has_master_key(self) -> bool:
        return self.database.get_key_store(self.key_type) is not None

    def store_metadata(self, auth_hash: str, encryption_salt: bytes, params: dict):
        record = KeyStore(
            key_type=self.key_type,
            salt=encryption_salt,
            hash=auth_hash,
            params=json.dumps(params, ensure_ascii=False),
            created_at=datetime.now(),
            last_rotated_at=datetime.now(),
        )
        self.database.save_key_store(record)

    def load_metadata(self) -> Optional[KeyStore]:
        return self.database.get_key_store(self.key_type)

    def cache_active_key(self, key: bytes):
        self.clear_cached_key()
        self._cached_key = bytearray(key)

    def get_cached_key(self) -> Optional[bytes]:
        if self._cached_key is None:
            return None
        return bytes(self._cached_key)

    def clear_cached_key(self):
        if self._cached_key is None:
            return
        for index in range(len(self._cached_key)):
            self._cached_key[index] = 0
        self._cached_key = None
