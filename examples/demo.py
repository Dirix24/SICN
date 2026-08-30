#!/usr/bin/env python3
"""
Demo mínima de SICN sin servidor: genera dos identidades (Alice y Bob),
Alice cifra y firma un mensaje para Bob, y Bob lo verifica y descifra.

Sirve para comprobar rápidamente que la parte criptográfica funciona sin
necesitar levantar el servidor HTTP. Ejecutar con:

    python examples/demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.envelope import open_message, seal_message
from src.crypto.keys import generate_identity, pretty_fingerprint


def main() -> None:
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")

    print(f"Alice — huella digital: {pretty_fingerprint(alice.fingerprint)}")
    print(f"Bob   — huella digital: {pretty_fingerprint(bob.fingerprint)}")
    print()

    mensaje_original = b"Hola Bob, este mensaje es privado."
    print(f"Mensaje original: {mensaje_original.decode()}")

    envelope = seal_message(alice, bob.public_bundle(), mensaje_original)
    print()
    print("Sobre cifrado (esto es lo único que vería un servidor o un fisgón):")
    print(f"  ciphertext (base64): {envelope.ciphertext[:60]}...")
    print(f"  firmado por (huella): {pretty_fingerprint(envelope.sender_fp)}")

    descifrado = open_message(bob, alice.public_bundle(), envelope)
    print()
    print(f"Bob descifra y verifica: {descifrado.decode()}")
    assert descifrado == mensaje_original
    print()
    print("✅ El mensaje llegó íntegro y autenticado.")


if __name__ == "__main__":
    main()
