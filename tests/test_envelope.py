import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.core.envelope import TamperedMessageError, open_message, seal_message
from src.crypto.keys import generate_identity


def test_seal_and_open_roundtrip():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")

    envelope = seal_message(alice, bob.public_bundle(), b"Hola Bob, este mensaje es privado.")
    plaintext = open_message(bob, alice.public_bundle(), envelope)

    assert plaintext == b"Hola Bob, este mensaje es privado."


def test_wrong_recipient_cannot_decrypt():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    eve = generate_identity("Eve")

    envelope = seal_message(alice, bob.public_bundle(), b"secreto para Bob")

    with pytest.raises(TamperedMessageError):
        open_message(eve, alice.public_bundle(), envelope)


def test_tampered_ciphertext_is_rejected():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")

    envelope = seal_message(alice, bob.public_bundle(), b"mensaje original")
    envelope.ciphertext = envelope.ciphertext[:-4] + ("AAAA" if envelope.ciphertext[-4:] != "AAAA" else "BBBB")

    with pytest.raises(TamperedMessageError):
        open_message(bob, alice.public_bundle(), envelope)


def test_impersonation_is_rejected():
    """Un tercero no puede hacerse pasar por Alice: la firma no coincidirá
    con la clave pública de Alice que Bob tiene guardada como contacto."""
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    mallory = generate_identity("Mallory")

    # Mallory firma un mensaje pero lo presenta como si fuera de Alice
    # (envelope.sender_fp manipulado a mano).
    envelope = seal_message(mallory, bob.public_bundle(), b"mensaje falso")
    envelope.sender_fp = alice.fingerprint

    with pytest.raises(TamperedMessageError):
        open_message(bob, alice.public_bundle(), envelope)


def test_file_attachment_roundtrip():
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")

    data = b"\x89PNG\r\n contenido binario simulado \x00\x01\x02"
    envelope = seal_message(alice, bob.public_bundle(), data, filename="foto.png")

    assert envelope.filename == "foto.png"
    plaintext = open_message(bob, alice.public_bundle(), envelope)
    assert plaintext == data
