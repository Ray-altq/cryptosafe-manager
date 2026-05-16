import hashlib
import hmac
import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


EXPORT_KEY_CONTEXT = b"cryptosafe-export-v1"
SHARE_KEY_CONTEXT = b"cryptosafe-share-v1"


def random_bytes(length: int) -> bytes:
    return os.urandom(max(1, int(length)))


def derive_password_key(password: str, salt: bytes, *, bits: int = 256, iterations: int = 100000) -> bytes:
    if bits not in {128, 256}:
        raise ValueError("Encryption strength must be 128 or 256 bits")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=bits // 8,
        salt=bytes(salt),
        iterations=max(100000, int(iterations)),
    )
    return kdf.derive(str(password).encode("utf-8"))


def derive_separated_key(source_key: bytes, context: bytes, *, bits: int = 256) -> bytes:
    if bits not in {128, 256}:
        raise ValueError("Encryption strength must be 128 or 256 bits")
    digest = hmac.new(bytes(source_key), bytes(context), hashlib.sha256).digest()
    return digest[: bits // 8]


def checksum(data: bytes) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def new_salt_and_nonce() -> Tuple[bytes, bytes]:
    return random_bytes(16), random_bytes(12)
