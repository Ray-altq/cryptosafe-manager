import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto.abstract import EncryptionService


class VaultEncryptionError(Exception):
    pass


class AESGCMEncryptionService(EncryptionService):
    NONCE_LENGTH = 12

    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        resolved_key = self._resolve_key(key)
        self._validate_key(resolved_key)

        nonce = os.urandom(self.NONCE_LENGTH)
        ciphertext = AESGCM(resolved_key).encrypt(nonce, data, None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        resolved_key = self._resolve_key(key)
        self._validate_key(resolved_key)

        if len(ciphertext) <= self.NONCE_LENGTH:
            raise VaultEncryptionError("Encrypted payload is invalid")

        nonce = ciphertext[: self.NONCE_LENGTH]
        encrypted_payload = ciphertext[self.NONCE_LENGTH :]

        try:
            return AESGCM(resolved_key).decrypt(nonce, encrypted_payload, None)
        except InvalidTag as error:
            raise VaultEncryptionError("Encrypted payload failed authentication") from error

    def _validate_key(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
