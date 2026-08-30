"""
Servidor SICN: API HTTP mínima de directorio de claves + buzón cifrado.

Endpoints:
- ``POST /register``            Publica las claves públicas de un usuario.
- ``GET  /keys/{fingerprint}``   Consulta las claves públicas de alguien.
- ``POST /messages``             Deposita un sobre cifrado para un destinatario.
- ``GET  /messages/{fingerprint}`` Recoge (y vacía) los mensajes pendientes.
- ``GET  /health``                Comprobación básica de estado.

El servidor es deliberadamente "tonto": no descifra nada, no puede
descifrar nada (no tiene ninguna clave privada de nadie), y no retiene
metadatos más allá de lo necesario para entregar el mensaje.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .storage import Storage

app = FastAPI(title="SICN Server", version="0.2.0")
storage = Storage()


class RegisterRequest(BaseModel):
    fingerprint: str
    name: str
    x25519_public: str
    ed25519_public: str


class EnvelopeIn(BaseModel):
    version: int
    sender_fp: str
    recipient_fp: str
    ephemeral_public: str
    nonce: str
    ciphertext: str
    timestamp: str
    filename: str | None = None
    signature: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/register")
def register(req: RegisterRequest) -> dict:
    storage.register_public_key(req.fingerprint, req.name, req.x25519_public, req.ed25519_public)
    return {"status": "registrado", "fingerprint": req.fingerprint}


@app.get("/keys/{fingerprint}")
def get_key(fingerprint: str) -> dict:
    key = storage.get_public_key(fingerprint)
    if key is None:
        raise HTTPException(status_code=404, detail="No existe ninguna identidad con esa huella digital.")
    return key


@app.post("/messages")
def send_message(envelope: EnvelopeIn) -> dict:
    if storage.get_public_key(envelope.recipient_fp) is None:
        raise HTTPException(status_code=404, detail="El destinatario no está registrado en este servidor.")
    storage.push_message(envelope.recipient_fp, envelope.model_dump())
    return {"status": "entregado_al_buzon"}


@app.get("/messages/{fingerprint}")
def get_messages(fingerprint: str) -> dict:
    messages = storage.pop_messages(fingerprint)
    return {"messages": messages}
