import base64
import hashlib
import hmac
from typing import Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class AuditLogSigner:
    CONTEXT = b"audit-signing"

    def __init__(self, key_provider: Callable[[], Optional[bytes]]):
        self._key_provider = key_provider
        self._cached_key_fingerprint: Optional[str] = None
        self._cached_seed: Optional[bytearray] = None
        self._private_key = None
        self._public_key_hex = ""
        self._algorithm = ""
        self._hmac_key: Optional[bytes] = None

    @property
    def algorithm(self) -> str:
        self._ensure_initialized()
        return self._algorithm

    @property
    def public_key_hex(self) -> str:
        self._ensure_initialized()
        return self._public_key_hex

    def sign(self, data: bytes) -> str:
        self._ensure_initialized()
        if self._algorithm == "ed25519":
            return self._private_key.sign(data).hex()
        return hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature_hex: str, public_key_hex: Optional[str] = None) -> bool:
        self._ensure_initialized()
        if self._algorithm == "ed25519":
            key_hex = public_key_hex or self._public_key_hex
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
            try:
                public_key.verify(bytes.fromhex(signature_hex), data)
                return True
            except (InvalidSignature, ValueError):
                return False
        expected = hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)

    def clear(self):
        self._clear_cached_material()

    def _ensure_initialized(self):
        active_key = self._key_provider()
        if not active_key:
            if self._cached_key_fingerprint and self._algorithm:
                return
            raise RuntimeError("Активный ключ шифрования недоступен для подписи журнала аудита")

        key_fingerprint = hashlib.sha256(active_key).hexdigest()
        if key_fingerprint == self._cached_key_fingerprint:
            return

        self._clear_cached_material()
        derived_seed = self._derive_signing_seed(active_key)
        self._cached_seed = bytearray(derived_seed)
        self._cached_key_fingerprint = key_fingerprint

        try:
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(derived_seed)
            self._public_key_hex = self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
            self._algorithm = "ed25519"
            self._hmac_key = None
        except Exception:
            self._private_key = None
            self._public_key_hex = base64.b16encode(derived_seed).decode("ascii").lower()
            self._algorithm = "hmac-sha256"
            self._hmac_key = derived_seed

    def _derive_signing_seed(self, active_key: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=self.CONTEXT,
        )
        return hkdf.derive(active_key)

    def _clear_cached_material(self):
        if self._cached_seed is not None:
            for index in range(len(self._cached_seed)):
                self._cached_seed[index] = 0
        self._cached_seed = None
        self._cached_key_fingerprint = None
        self._private_key = None
        self._public_key_hex = ""
        self._algorithm = ""
        self._hmac_key = None
