"""
Gestión de identidad criptográfica del usuario.

Cada usuario de SICN tiene dos pares de claves:

- Un par **X25519** (curva elíptica para intercambio de claves, ECDH),
  usado para derivar el secreto compartido con el que se cifran los
  mensajes.
- Un par **Ed25519** (curva elíptica para firmas), usado para firmar cada
  mensaje enviado, de modo que el receptor pueda verificar que realmente
  proviene de quien dice ser (autenticidad) y que no ha sido modificado.

La clave privada nunca sale del dispositivo del usuario ni se envía al
servidor. En disco se guarda cifrada con una clave derivada de una
contraseña (ver ``crypto/kdf.py``), nunca en claro.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from . import symmetric
from .kdf import derive_key_from_passphrase


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


@dataclass
class Identity:
    """Identidad completa de un usuario (claves públicas + privadas)."""

    name: str
    x25519_private: X25519PrivateKey
    ed25519_private: Ed25519PrivateKey

    @property
    def x25519_public(self) -> X25519PublicKey:
        return self.x25519_private.public_key()

    @property
    def ed25519_public(self) -> Ed25519PublicKey:
        return self.ed25519_private.public_key()

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.ed25519_public, self.x25519_public)

    def public_bundle(self) -> "PublicBundle":
        return PublicBundle(
            name=self.name,
            fingerprint=self.fingerprint,
            x25519_public=_b64(
                self.x25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            ed25519_public=_b64(
                self.ed25519_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        )


@dataclass
class PublicBundle:
    """Solo las claves públicas de un usuario (lo que se comparte/publica)."""

    name: str
    fingerprint: str
    x25519_public: str  # base64
    ed25519_public: str  # base64

    def x25519_key(self) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(_unb64(self.x25519_public))

    def ed25519_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(_unb64(self.ed25519_public))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "fingerprint": self.fingerprint,
            "x25519_public": self.x25519_public,
            "ed25519_public": self.ed25519_public,
        }

    @staticmethod
    def from_dict(d: dict) -> "PublicBundle":
        return PublicBundle(
            name=d["name"],
            fingerprint=d["fingerprint"],
            x25519_public=d["x25519_public"],
            ed25519_public=d["ed25519_public"],
        )


def fingerprint_of(ed25519_pub: Ed25519PublicKey, x25519_pub: X25519PublicKey) -> str:
    """Huella digital canónica (hex, sin espacios) de un par de claves públicas.

    Se calcula un SHA-256 sobre la concatenación de ambas claves públicas.
    Este es el identificador que se usa internamente (URLs, claves de base
    de datos, enrutado de mensajes) por lo que debe ser estable y sin
    espacios. Para mostrarla a un humano, usa ``pretty_fingerprint``.
    """
    ed_bytes = ed25519_pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    x_bytes = x25519_pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(ed_bytes + x_bytes).hexdigest()


def pretty_fingerprint(fingerprint: str) -> str:
    """Formatea una huella digital en grupos de 4 caracteres (estilo PGP/Signal)
    para que dos personas puedan compararla en voz alta o visualmente y así
    detectar un posible ataque de intermediario (MITM)."""
    digest = fingerprint.replace(" ", "")
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


def generate_identity(name: str) -> Identity:
    return Identity(
        name=name,
        x25519_private=X25519PrivateKey.generate(),
        ed25519_private=Ed25519PrivateKey.generate(),
    )


# --------------------------------------------------------------- persistencia


def save_identity(identity: Identity, path: str, passphrase: str) -> None:
    """Guarda la identidad en disco, con las claves privadas cifradas.

    Formato del fichero (JSON):
        {
          "name": ...,
          "salt": base64,               # para volver a derivar la clave con scrypt
          "nonce": base64,
          "ciphertext": base64,         # claves privadas cifradas con AES-256-GCM
        }
    """
    x_priv_bytes = identity.x25519_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ed_priv_bytes = identity.ed25519_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = json.dumps(
        {"x25519_private": _b64(x_priv_bytes), "ed25519_private": _b64(ed_priv_bytes)}
    ).encode("utf-8")

    key, salt = derive_key_from_passphrase(passphrase)
    nonce, ciphertext = symmetric.encrypt(key, payload)

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "name": identity.name,
                "salt": _b64(salt),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
            },
            f,
            indent=2,
        )
    os.chmod(path, 0o600)  # solo el propietario puede leer el fichero de claves


def load_identity(path: str, passphrase: str) -> Identity:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    salt = _unb64(data["salt"])
    key, _ = derive_key_from_passphrase(passphrase, salt=salt)
    nonce = _unb64(data["nonce"])
    ciphertext = _unb64(data["ciphertext"])

    try:
        payload = symmetric.decrypt(key, nonce, ciphertext)
    except Exception as exc:  # cryptography lanza InvalidTag
        raise ValueError("Contraseña incorrecta o fichero de claves dañado.") from exc

    inner = json.loads(payload.decode("utf-8"))
    x25519_private = X25519PrivateKey.from_private_bytes(_unb64(inner["x25519_private"]))
    ed25519_private = Ed25519PrivateKey.from_private_bytes(_unb64(inner["ed25519_private"]))
    return Identity(name=data["name"], x25519_private=x25519_private, ed25519_private=ed25519_private)
