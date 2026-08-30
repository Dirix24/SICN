"""Cifrado simétrico autenticado (AES-256-GCM) usado en todo SICN."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12  # 96 bits, tamaño estándar recomendado para GCM


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Cifra con AES-256-GCM. Devuelve (nonce, ciphertext_con_tag)."""
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
    """Descifra y verifica la integridad. Lanza excepción si algo fue alterado."""
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
