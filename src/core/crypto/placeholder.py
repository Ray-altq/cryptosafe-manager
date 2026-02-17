from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):   #будет временной заглушкой для шифрования
   
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        data - это байты для шифрования
        key - это ключ шифрования
        потом происходит возврат зашифрованных байт
        """
        pass
    
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """
        для XOR шифрование = расшифрование
        просто нужно вызвать encrypt с теми же параметрами
        """
        pass
    
    def _prepare_key(self, key: bytes, length: int) -> bytes: #делает ключ нужной длины
        """
        length - это нужная длина
        потом возвращение ключа, повторенного до длины length
        """
        pass
