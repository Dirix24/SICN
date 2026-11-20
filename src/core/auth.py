"""Canonical, domain-separated proofs for relay requests."""
import base64
import hashlib
import json

from ..crypto.keys import PublicBundle, fingerprint_of


def decode(value: str, length: int) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Codificación o longitud inválida")
    return raw


def check_bundle(bundle: PublicBundle) -> None:
    decode(bundle.ed25519_public, 32)
    decode(bundle.x25519_public, 32)
    if bundle.fingerprint != fingerprint_of(bundle.ed25519_key(), bundle.x25519_key()):
        raise ValueError("Huella y claves no coinciden")


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def context(payload: dict) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def proof_bytes(challenge: dict) -> bytes:
    return b"SICN-RELAY-AUTH-v1\x00" + canonical(challenge)
