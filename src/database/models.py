from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class VaultEntry:  #запись пароля
    id: Optional[int] = None
    title: str = ""
    username: str = ""
    encrypted_password: bytes = b""
    url: str = ""
    notes: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: str = ""

@dataclass
class AuditLog:  #журнал аудита
    id: Optional[int] = None
    action: str = ""
    timestamp: Optional[datetime] = None
    entry_id: Optional[int] = None
    details: str = ""
    signature: bytes = b""

@dataclass
class Setting:  #настройки
    id: Optional[int] = None
    setting_key: str = ""  # обрати внимание: setting_key, не key
    setting_value: str = ""  # setting_value, не value
    encrypted: bool = False

@dataclass
class KeyStore:  #хранилище ключей
    id: Optional[int] = None
    key_type: str = ""
    salt: bytes = b""
    hash: bytes = b""
    params: str = ""
