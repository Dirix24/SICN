import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.crypto import symmetric
from src.crypto.kdf import derive_key_from_passphrase
from src.crypto.keys import generate_identity, load_identity, pretty_fingerprint, save_identity


def test_symmetric_roundtrip():
    key = b"0" * 32
    nonce, ciphertext = symmetric.encrypt(key, b"hola mundo")
    assert symmetric.decrypt(key, nonce, ciphertext) == b"hola mundo"


def test_symmetric_detects_tampering():
    key = b"0" * 32
    nonce, ciphertext = symmetric.encrypt(key, b"mensaje secreto")
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(Exception):
        symmetric.decrypt(key, nonce, bytes(tampered))


def test_passphrase_kdf_deterministic_with_same_salt():
    key1, salt = derive_key_from_passphrase("correcto caballo grapadora")
    key2, _ = derive_key_from_passphrase("correcto caballo grapadora", salt=salt)
    assert key1 == key2


def test_passphrase_kdf_different_without_salt():
    key1, salt1 = derive_key_from_passphrase("misma-frase")
    key2, salt2 = derive_key_from_passphrase("misma-frase")
    assert salt1 != salt2
    assert key1 != key2


def test_identity_save_and_load_roundtrip(tmp_path):
    identity = generate_identity("Ana")
    path = str(tmp_path / "identity.enc")
    save_identity(identity, path, "contraseña-larga-y-segura")

    loaded = load_identity(path, "contraseña-larga-y-segura")
    assert loaded.name == "Ana"
    assert loaded.fingerprint == identity.fingerprint


def test_identity_load_wrong_passphrase_fails(tmp_path):
    identity = generate_identity("Ana")
    path = str(tmp_path / "identity.enc")
    save_identity(identity, path, "contraseña-correcta")

    with pytest.raises(ValueError):
        load_identity(path, "contraseña-incorrecta")


def test_pretty_fingerprint_format():
    fp = "ab" * 32  # 64 caracteres hex
    pretty = pretty_fingerprint(fp)
    assert " " in pretty
    assert pretty.replace(" ", "") == fp
