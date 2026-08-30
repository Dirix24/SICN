"""
Formato de mensaje ("envelope") de SICN y funciones para cifrar/descifrar.

Diseño (v1, "sealed sender" simplificado tipo ECIES):

1. El remitente genera un par de claves X25519 **efímero** (de un solo uso)
   para este mensaje concreto.
2. Calcula el secreto ECDH entre su clave efímera y la clave X25519
   **estática** del destinatario, y deriva de ahí una clave AES-256 con
   HKDF.
3. Cifra el contenido con AES-256-GCM.
4. Firma (Ed25519, con su clave estática de identidad) el conjunto
   {clave efímera pública, nonce, ciphertext, remitente, destinatario,
   timestamp} para que el destinatario pueda verificar quién lo envió y
   que nadie lo ha modificado por el camino.
5. El servidor solo ve y almacena este sobre: nunca ve la clave privada de
   nadie ni el contenido en claro.

El destinatario, con su clave X25519 estática privada y la clave efímera
pública incluida en el sobre, recalcula el mismo secreto ECDH y por tanto
la misma clave AES-256, y puede descifrar. Verifica la firma con la clave
Ed25519 pública del remitente (que debe conocer de antemano, p. ej. porque
lo tiene como contacto).

Nota honesta: al usar una clave efímera nueva por mensaje se consigue
secreto hacia adelante por mensaje, pero esto NO es un "double ratchet"
como el protocolo Signal (no hay recuperación tras compromiso de claves a
mitad de conversación, ni tantos matices de seguridad de sesión). Es una
construcción ECIES razonable para un sistema de mensajería tipo email
cifrado, pero debe auditarse antes de proteger información realmente
sensible, como indica docs/seguridad.md.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ..crypto import symmetric
from ..crypto.kdf import derive_shared_key
from ..crypto.keys import Identity, PublicBundle

PROTOCOL_VERSION = 1


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


class TamperedMessageError(Exception):
    """El sobre fue modificado, la firma no coincide o la clave es incorrecta."""


@dataclass
class Envelope:
    version: int
    sender_fp: str
    recipient_fp: str
    ephemeral_public: str  # base64
    nonce: str  # base64
    ciphertext: str  # base64
    timestamp: str
    filename: str | None
    signature: str = ""  # base64, se rellena al firmar

    def _signable_bytes(self) -> bytes:
        """Bytes canónicos que se firman (todo excepto la propia firma)."""
        payload = {
            "version": self.version,
            "sender_fp": self.sender_fp,
            "recipient_fp": self.recipient_fp,
            "ephemeral_public": self.ephemeral_public,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "timestamp": self.timestamp,
            "filename": self.filename,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> dict:
        d = self._json_fields()
        d["signature"] = self.signature
        return d

    def _json_fields(self) -> dict:
        return {
            "version": self.version,
            "sender_fp": self.sender_fp,
            "recipient_fp": self.recipient_fp,
            "ephemeral_public": self.ephemeral_public,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "timestamp": self.timestamp,
            "filename": self.filename,
        }

    @staticmethod
    def from_dict(d: dict) -> "Envelope":
        return Envelope(
            version=d["version"],
            sender_fp=d["sender_fp"],
            recipient_fp=d["recipient_fp"],
            ephemeral_public=d["ephemeral_public"],
            nonce=d["nonce"],
            ciphertext=d["ciphertext"],
            timestamp=d["timestamp"],
            filename=d.get("filename"),
            signature=d.get("signature", ""),
        )


def seal_message(
    sender: Identity,
    recipient: PublicBundle,
    plaintext: bytes,
    filename: str | None = None,
) -> Envelope:
    """Cifra y firma un mensaje para un destinatario. Solo el destinatario
    (con su clave privada) podrá descifrarlo, y cualquiera que conozca la
    clave pública del remitente podrá verificar que lo envió él."""

    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    shared_secret = ephemeral_private.exchange(recipient.x25519_key())
    aes_key = derive_shared_key(shared_secret)

    associated_data = f"{sender.fingerprint}->{recipient.fingerprint}".encode("utf-8")
    nonce, ciphertext = symmetric.encrypt(aes_key, plaintext, associated_data)

    envelope = Envelope(
        version=PROTOCOL_VERSION,
        sender_fp=sender.fingerprint,
        recipient_fp=recipient.fingerprint,
        ephemeral_public=_b64(ephemeral_public_bytes),
        nonce=_b64(nonce),
        ciphertext=_b64(ciphertext),
        timestamp=datetime.now(timezone.utc).isoformat(),
        filename=filename,
    )

    signature = sender.ed25519_private.sign(envelope._signable_bytes())
    envelope.signature = _b64(signature)
    return envelope


def open_message(recipient: Identity, sender: PublicBundle, envelope: Envelope) -> bytes:
    """Verifica la firma y descifra un sobre recibido.

    Lanza ``TamperedMessageError`` si la firma no es válida, el sobre fue
    modificado, o las claves no corresponden (mensaje no destinado a este
    receptor / no proviene de quien dice el remitente indicado).
    """
    if envelope.recipient_fp != recipient.fingerprint:
        raise TamperedMessageError("El sobre no está dirigido a esta identidad.")
    if envelope.sender_fp != sender.fingerprint:
        raise TamperedMessageError("El remitente indicado no coincide con el sobre.")

    try:
        sender.ed25519_key().verify(_unb64(envelope.signature), envelope._signable_bytes())
    except InvalidSignature as exc:
        raise TamperedMessageError(
            "Firma inválida: el mensaje fue alterado o no proviene de quien dice."
        ) from exc

    ephemeral_public = _unb64(envelope.ephemeral_public)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared_secret = recipient.x25519_private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
    aes_key = derive_shared_key(shared_secret)

    associated_data = f"{envelope.sender_fp}->{envelope.recipient_fp}".encode("utf-8")
    try:
        plaintext = symmetric.decrypt(
            aes_key, _unb64(envelope.nonce), _unb64(envelope.ciphertext), associated_data
        )
    except Exception as exc:
        raise TamperedMessageError(
            "No se pudo descifrar: datos corruptos, alterados o clave incorrecta."
        ) from exc

    return plaintext
