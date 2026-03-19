from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes = None) -> bytes:
        key = self._resolve_key(key)
        if len(key) < len(data):
            key = key * (len(data) // len(key) + 1)

        key = key[: len(data)]
        return bytes(data[i] ^ key[i] for i in range(len(data)))

    def decrypt(self, ciphertext: bytes, key: bytes = None) -> bytes:
        return self.encrypt(ciphertext, key)

    def _prepare_key(self, key: bytes, length: int) -> bytes:
        if len(key) >= length:
            return key[:length]
        repetitions = (length + len(key) - 1) // len(key)
        return (key * repetitions)[:length]
