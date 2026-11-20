"""SICN public directory and authenticated encrypted mailbox."""
from contextlib import asynccontextmanager
import ipaddress
import os
import sqlite3
import time
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..core.auth import check_bundle, context, decode, proof_bytes
from ..core.envelope import Envelope, MAX_CIPHERTEXT, validate_envelope
from ..crypto.keys import PublicBundle
from .limits import RequestBodyLimit
from .storage import CapacityError, Storage

Hex = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class IdentityIn(StrictModel):
    fingerprint: Hex
    name: Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[^\x00-\x1f\x7f]+$")]
    x25519_public: Annotated[str, Field(min_length=44, max_length=44)]
    ed25519_public: Annotated[str, Field(min_length=44, max_length=44)]


class ChallengeIn(StrictModel):
    fingerprint: Hex
    operation: Literal["register", "inbox", "ack"]
    context: Hex


class Proof(StrictModel):
    nonce: Hex
    signature: Annotated[str, Field(min_length=88, max_length=88)]


class RegisterRequest(IdentityIn):
    proof: Proof


class InboxRequest(StrictModel):
    proof: Proof
    after: Annotated[int, Field(ge=0, lt=2**63)] = 0


class AckRequest(StrictModel):
    proof: Proof
    id: Annotated[int, Field(gt=0, lt=2**63)]


class EnvelopeIn(StrictModel):
    version: Literal[1]
    sender_fp: Hex
    recipient_fp: Hex
    ephemeral_public: Annotated[str, Field(max_length=44)]
    nonce: Annotated[str, Field(max_length=16)]
    ciphertext: Annotated[str, Field(max_length=4 * ((MAX_CIPHERTEXT + 2) // 3))]
    timestamp: Annotated[str, Field(max_length=40)]
    filename: Annotated[str, Field(max_length=150)] | None = None
    signature: Annotated[str, Field(max_length=88)]


def verified_bundle(values):
    try:
        bundle = PublicBundle.from_dict(values)
        check_bundle(bundle)
        return bundle
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(422, "Huella o claves inválidas") from exc


def create_app(storage=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.storage = storage or Storage(
            os.environ.get("SICN_DB", "sicn_server.db"),
            retention=int(os.environ.get("SICN_RETENTION_SECONDS", str(30 * 86400))),
        )
        yield

    app = FastAPI(title="SICN Server", version="0.2.0", lifespan=lifespan)

    app.add_middleware(RequestBodyLimit)
    rate_window = {}

    @app.middleware("http")
    async def transport(request: Request, call_next):
        if request.url.scheme != "https":
            try:
                peer_local = ipaddress.ip_address(request.client.host).is_loopback
            except (ValueError, AttributeError):
                peer_local = False
            if not peer_local or request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
                return JSONResponse({"detail": "Se requiere HTTPS fuera de loopback"}, status_code=403)
        now = int(time.monotonic() // 60)
        if rate_window.get("minute") != now:
            rate_window.clear()
            rate_window["minute"] = now
        peer = request.client.host if request.client else ""
        if len(rate_window) >= 4096 and peer not in rate_window or rate_window.get(peer, 0) >= 180:
            return JSONResponse({"detail": "Demasiadas solicitudes"}, status_code=429)
        rate_window[peer] = rate_window.get(peer, 0) + 1
        reply = await call_next(request)
        reply.headers["Cache-Control"] = "no-store"
        reply.headers["X-Content-Type-Options"] = "nosniff"
        return reply

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        return JSONResponse({"detail": "Solicitud inválida"}, status_code=422)

    @app.exception_handler(CapacityError)
    async def capacity(request, exc):
        return JSONResponse({"detail": "Límite de capacidad alcanzado"}, status_code=429)

    @app.exception_handler(sqlite3.Error)
    async def unavailable(request, exc):
        return JSONResponse({"detail": "Almacenamiento no disponible"}, status_code=503)

    def db(request):
        return storage if storage is not None else request.app.state.storage

    def bundle_for(store, fingerprint):
        value = store.get_public_key(fingerprint)
        if value is None:
            raise HTTPException(404, "Identidad no registrada")
        return verified_bundle(value)

    def verifier(store, bundle, operation, payload, proof):
        digest = context(payload)

        def verify(challenge):
            if (challenge["fingerprint"], challenge["operation"], challenge["context"], challenge["audience"]) != (
                bundle.fingerprint, operation, digest, store.audience,
            ):
                return False
            try:
                bundle.ed25519_key().verify(decode(proof.signature, 64), proof_bytes(challenge))
                return True
            except (InvalidSignature, ValueError):
                return False
        return verify

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ready")
    def ready(request: Request):
        with db(request)._connect() as conn:
            conn.execute("SELECT 1 FROM relay_meta LIMIT 1")
        return {"status": "ready"}

    @app.post("/challenge")
    def challenge(req: ChallengeIn, request: Request):
        return db(request).issue(req.fingerprint, req.operation, req.context)

    @app.post("/register")
    def register(req: RegisterRequest, request: Request):
        store = db(request)
        payload = req.model_dump(exclude={"proof"})
        bundle = verified_bundle(payload)
        with store.authenticate(req.proof.nonce, verifier(store, bundle, "register", payload, req.proof)) as conn:
            if conn is None:
                raise HTTPException(401, "Prueba inválida, caducada o utilizada")
            accepted = store.register(conn, bundle)
        if not accepted:
            raise HTTPException(409, "La identidad ya está registrada")
        return {"status": "registrado", "fingerprint": bundle.fingerprint}

    @app.get("/keys/{fingerprint}")
    def get_key(fingerprint: Hex, request: Request):
        return bundle_for(db(request), fingerprint).to_dict()

    @app.post("/messages")
    def send_message(req: EnvelopeIn, request: Request):
        store = db(request)
        envelope = Envelope.from_dict(req.model_dump())
        sender = bundle_for(store, envelope.sender_fp)
        bundle_for(store, envelope.recipient_fp)
        try:
            validate_envelope(envelope)
            sender.ed25519_key().verify(decode(envelope.signature, 64), envelope._signable_bytes())
        except (ValueError, InvalidSignature) as exc:
            raise HTTPException(422, "Sobre o firma inválidos") from exc
        payload = envelope.to_dict()
        message_id = store.push_message(envelope.recipient_fp, payload, context(payload))
        return {"status": "entregado_al_buzon", "id": message_id}

    @app.get("/messages/{fingerprint}")
    def legacy_inbox(fingerprint: Hex):
        raise HTTPException(401, "El buzón requiere prueba autenticada mediante POST")

    @app.post("/messages/{fingerprint}")
    def inbox(fingerprint: Hex, req: InboxRequest, request: Request):
        store = db(request)
        bundle = bundle_for(store, fingerprint)
        with store.authenticate(req.proof.nonce, verifier(store, bundle, "inbox", {"after": req.after}, req.proof)) as conn:
            if conn is None:
                raise HTTPException(401, "Prueba inválida, caducada o utilizada")
            messages = store.pending(conn, fingerprint, req.after)
        return {"messages": messages, "next_after": messages[-1]["id"] if len(messages) == 10 else None}

    @app.post("/messages/{fingerprint}/ack")
    def acknowledge(fingerprint: Hex, req: AckRequest, request: Request):
        store = db(request)
        bundle = bundle_for(store, fingerprint)
        with store.authenticate(req.proof.nonce, verifier(store, bundle, "ack", {"id": req.id}, req.proof)) as conn:
            if conn is None:
                raise HTTPException(401, "Prueba inválida, caducada o utilizada")
            found = store.ack(conn, fingerprint, req.id)
        if not found:
            raise HTTPException(404, "Mensaje no encontrado")
        return {"status": "acknowledged"}

    return app


app = create_app()
