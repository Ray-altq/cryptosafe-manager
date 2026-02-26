from .abstract import EncryptionService

class AES256Placeholder(EncryptionService):  #временная заглушка с XOR
   
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        #если ключ короче данных, повторяем его
        if len(key) < len(data):
            key = key * (len(data) // len(key) + 1)
        
        #обрезаем до нужной длины
        key = key[:len(data)]
        
        #XOR побайтово
        result = bytes([data[i] ^ key[i] for i in range(len(data))])
        return result
    
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:  #Расшифровка XOR (симметрична шифрованию)
        return self.encrypt(ciphertext, key)
    
    def _prepare_key(self, key: bytes, length: int) -> bytes:  #подготовка ключа нужной длины
        if len(key) >= length:
            return key[:length]
        repetitions = (length + len(key) - 1) // len(key)
        return (key * repetitions)[:length]