from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
from typing import Dict, Tuple, Optional

class KeyDerivation:  #понадобится для управления формированием ключей (argon2 для хэширования мастер-пароля, PBKDF2 для ключа шифрования)

    def __init__(self, config: Dict):  #инициализируем параметрами из конфига
        #параметры argon2
        self.argon2_time = config.get('argon2_time', 3)           #временная стоимость
        self.argon2_memory = config.get('argon2_memory', 65536)   #64 MiB в кибибайтах
        self.argon2_parallelism = config.get('argon2_parallelism', 4)  #потоки
        self.argon2_hash_len = config.get('argon2_hash_len', 32)  #32 байта
        
        #параметры PBKDF2
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)  #минимум 100k
        self.pbkdf2_salt_len = config.get('pbkdf2_salt_len', 16)           #16 байт
        self.pbkdf2_key_len = config.get('pbkdf2_key_len', 32)             #32 байта
        
        #инициализация argon2 хэшера
        self.argon2_hasher = PasswordHasher(
            time_cost=self.argon2_time,
            memory_cost=self.argon2_memory,
            parallelism=self.argon2_parallelism,
            hash_len=self.argon2_hash_len,
            salt_len=16,
            type=Type.ID  #argon2id
        )

    def create_auth_hash(self, password: str) -> dict:
        hash_str = self.argon2_hasher.hash(password)  #argon2 сам генерирует соль и кодирует все параметры в строке хэша
    
        return {   #возвращаем словарь с хэшем и параметрами для сохранения в БД
          'hash': hash_str,
          'algorithm': 'argon2id',
          'time_cost': self.argon2_time,
          'memory_cost': self.argon2_memory,
          'parallelism': self.argon2_parallelism,
          'hash_len': self.argon2_hash_len,
          'version': 19  
    }

    def verify_auth_hash(self, password: str, stored_hash: str) -> bool:
      
      try:
          self.argon2_hasher.verify(stored_hash, password)  #argon2 сам обеспечивает защиту от timing-атак
          return True
        
      except Exception:
        #выполняем фиктивную проверку для константного времени
          self._dummy_verify()
          return False

    def hash_needs_rehash(self, stored_hash: str) -> bool:
      try:
          return self.argon2_hasher.check_needs_rehash(stored_hash)
      except Exception:
          return True

    def _dummy_verify(self):
      secrets.compare_digest(  #secrets.compare_digest всегда выполняется за константное время
         b"dummy_constant_time_string",
         b"dummy_constant_time_string"
    )