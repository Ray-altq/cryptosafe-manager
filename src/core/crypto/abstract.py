from abc import ABC, abstractmethod

class EncryptionService(ABC):
    """Абстрактный класс для шифрования"""
    
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Шифрует данные"""
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает данные"""
        pass
