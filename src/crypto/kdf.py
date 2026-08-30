"""
Funciones de derivación de claves (KDF) usadas por SICN.

- ``derive_shared_key``: convierte un secreto ECDH (X25519) en una clave
  simétrica de 32 bytes apta para AES-256-GCM, usando HKDF-SHA256.
- ``derive_key_from_passphrase``: convierte una contraseña humana en una
  clave simétrica de 32 bytes usando scrypt (costoso de fuerza bruta a
  propósito), para cifrar la clave privada del usuario en disco.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SYMMETRIC_KEY_LEN = 32  # AES-256


def derive_shared_key(ecdh_secret: bytes, info: bytes = b"sicn-v1-message") -> bytes:
    """HKDF-SHA256 sobre un secreto ECDH crudo -> clave AES-256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_LEN,
        salt=None,
        info=info,
    ).derive(ecdh_secret)


def derive_key_from_passphrase(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Deriva una clave simétrica de una contraseña con scrypt.

    Devuelve (clave, salt). Si no se pasa salt, se genera uno nuevo aleatorio
    (para cifrar por primera vez); si se pasa el salt guardado, se reproduce
    la misma clave (para descifrar).
    """
    if salt is None:
        salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=SYMMETRIC_KEY_LEN, n=2**15, r=8, p=1)
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt
