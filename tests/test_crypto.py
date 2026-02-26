import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.crypto.abstract import EncryptionService
from src.core.crypto.placeholder import AES256Placeholder
from src.core.key_manager import KeyManager

class TestCrypto(unittest.TestCase):
    """Тесты для криптографии (TEST-1)"""
    
    def setUp(self):
        """Подготовка перед каждым тестом"""
        self.crypto = AES256Placeholder()
        self.key_manager = KeyManager()
        self.test_key = b"test_key_16_bytes"
        self.test_data = b"Hello, World!"
    
    def test_encryption_service_abstract(self):
        """Тест: можно ли создать экземпляр абстрактного класса"""
        with self.assertRaises(TypeError):
            EncryptionService()
    
    def test_encrypt_decrypt(self):
        """Тест: шифрование и расшифровка работают"""
        encrypted = self.crypto.encrypt(self.test_data, self.test_key)
        decrypted = self.crypto.decrypt(encrypted, self.test_key)
        self.assertEqual(self.test_data, decrypted)
    
    def test_different_keys(self):
        """Тест: разные ключи дают разный результат"""
        key1 = b"key123"
        key2 = b"key456"
        
        encrypted1 = self.crypto.encrypt(self.test_data, key1)
        encrypted2 = self.crypto.encrypt(self.test_data, key2)
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_key_manager_derive(self):
        """Тест: key_manager создает ключ из пароля"""
        password = "test_password"
        key, salt = self.key_manager.derive_key(password)
        
        self.assertIsInstance(key, bytes)
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(key), 32)  # 32 байта для AES-256
    
    def test_key_manager_store_load(self):
        """Тест: сохранение и загрузка ключа"""
        test_key = b"test_key_123"
        self.key_manager.store_key("test", test_key)
        loaded = self.key_manager.load_key("test")
        self.assertEqual(test_key, loaded)

if __name__ == '__main__':
    unittest.main()
