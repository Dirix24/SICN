import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from src.core.auth import context, proof_bytes
from src.core.envelope import open_message, seal_message
from src.crypto.keys import generate_identity
from src.server.app import create_app
from src.server.storage import Storage


@pytest.fixture
def storage(tmp_path):
    return Storage(str(tmp_path / "test.db"))


@pytest.fixture
def client(storage):
    with TestClient(create_app(storage), base_url="https://relay.test") as client:
        yield client


def _sign(client, identity, operation, payload, signer=None):
    response = client.post("/challenge", json={
        "fingerprint": identity.fingerprint, "operation": operation, "context": context(payload),
    })
    assert response.status_code == 200
    challenge = response.json()
    signature = (signer or identity).ed25519_private.sign(proof_bytes(challenge))
    return {"nonce": challenge["nonce"], "signature": base64.b64encode(signature).decode()}


def _register(client, identity):
    bundle = identity.public_bundle()
    payload = bundle.to_dict()
    resp = client.post("/register", json={**payload, "proof": _sign(client, identity, "register", payload)})
    assert resp.status_code == 200
    return bundle


def _inbox(client, identity):
    body = {"after": 0}
    return client.post(f"/messages/{identity.fingerprint}", json={
        **body, "proof": _sign(client, identity, "inbox", body),
    })


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_register_and_lookup(client):
    alice = generate_identity("Alice")
    bundle = _register(client, alice)

    resp = client.get(f"/keys/{bundle.fingerprint}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Alice"
    assert data["x25519_public"] == bundle.x25519_public


def test_lookup_unknown_fingerprint_404(client):
    resp = client.get("/keys/" + "0" * 64)
    assert resp.status_code == 404


def test_send_requires_registered_recipient(client):
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    _register(client, alice)  # Bob no se registra

    envelope = seal_message(alice, bob.public_bundle(), b"hola")
    resp = client.post("/messages", json=envelope.to_dict())
    assert resp.status_code == 404


def test_full_send_and_receive_flow(client):
    alice = generate_identity("Alice")
    bob = generate_identity("Bob")
    _register(client, alice)
    _register(client, bob)

    envelope = seal_message(alice, bob.public_bundle(), b"Hola Bob, mensaje de prueba end-to-end.")
    resp = client.post("/messages", json=envelope.to_dict())
    assert resp.status_code == 200

    resp = _inbox(client, bob)
    assert resp.status_code == 200
    messages = resp.json()["messages"]
    assert len(messages) == 1

    from src.core.envelope import Envelope

    received = Envelope.from_dict(messages[0]["envelope"])
    plaintext = open_message(bob, alice.public_bundle(), received)
    assert plaintext == b"Hola Bob, mensaje de prueba end-to-end."

    assert _inbox(client, bob).json()["messages"] == messages
    assert client.get(f"/messages/{bob.fingerprint}").status_code == 401
    assert client.post("/messages", json=envelope.to_dict()).json()["id"] == messages[0]["id"]
    ack = {"id": messages[0]["id"]}
    alien = _sign(client, alice, "ack", ack)
    assert client.post(f"/messages/{alice.fingerprint}/ack", json={**ack, "proof": alien}).status_code == 404
    for _ in range(2):
        signed = _sign(client, bob, "ack", ack)
        assert client.post(f"/messages/{bob.fingerprint}/ack", json={**ack, "proof": signed}).status_code == 200
    assert _inbox(client, bob).json()["messages"] == []


def test_registration_requires_proof_and_rejects_replacement(client):
    alice, mallory = generate_identity("Alice"), generate_identity("Mallory")
    payload = alice.public_bundle().to_dict()
    assert client.post("/register", json=payload).status_code == 422
    invalid = _sign(client, alice, "register", payload, signer=mallory)
    assert client.post("/register", json={**payload, "proof": invalid}).status_code == 401
    _register(client, alice)
    _register(client, alice)
    substituted = {**mallory.public_bundle().to_dict(), "fingerprint": alice.fingerprint}
    forged = _sign(client, alice, "register", substituted, signer=mallory)
    assert client.post("/register", json={**substituted, "proof": forged}).status_code == 422
    assert client.get(f"/keys/{alice.fingerprint}").json() == payload


def test_expiry_replay_and_racing_proofs(client, storage):
    from concurrent.futures import ThreadPoolExecutor

    alice = generate_identity("Alice")
    now = [1700000000]
    storage.clock = lambda: now[0]
    _register(client, alice)
    body = {"after": 0}
    path = f"/messages/{alice.fingerprint}"
    expired = _sign(client, alice, "inbox", body)
    now[0] += 60
    assert client.post(path, json={**body, "proof": expired}).status_code == 401
    current = _sign(client, alice, "inbox", body)
    assert client.post(path, json={"after": 1, "proof": current}).status_code == 401
    with ThreadPoolExecutor(2) as pool:
        replies = list(pool.map(lambda _: client.post(path, json={**body, "proof": current}).status_code, range(2)))
    assert sorted(replies) == [200, 401]


def test_unacknowledged_message_survives_server_restart(client, storage):
    alice, bob = generate_identity("Alice"), generate_identity("Bob")
    _register(client, alice)
    _register(client, bob)
    envelope = seal_message(alice, bob.public_bundle(), b"persistente")
    assert client.post("/messages", json=envelope.to_dict()).status_code == 200
    pending = _inbox(client, bob).json()["messages"]
    with TestClient(create_app(Storage(storage.db_path)), base_url="https://relay.test") as restarted:
        assert _inbox(restarted, bob).json()["messages"] == pending


@pytest.mark.parametrize("filename", ["../test", "/etc/test", r"x\test", "CON.txt", "file."])
def test_invalid_attachment_name(filename):
    alice, bob = generate_identity("Alice"), generate_identity("Bob")
    with pytest.raises(ValueError):
        seal_message(alice, bob.public_bundle(), b"test", filename=filename)


def test_tls_and_body_limit(client, storage):
    with TestClient(create_app(storage), base_url="http://relay.test") as public_http:
        assert public_http.get("/health").status_code == 403
    assert client.post("/messages", content=b"x" * 360001).status_code == 413


def test_local_persistence_refuses_symlinks_and_overwrite(tmp_path):
    from src.client.local import persist
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(OSError):
        persist(str(tmp_path), "link", b"replacement")
    assert outside.read_bytes() == b"original"
    persist(str(tmp_path), "message", b"first")
    persist(str(tmp_path), "message", b"first")
    with pytest.raises(FileExistsError):
        persist(str(tmp_path), "message", b"second")


def test_cli_retries_after_local_write_and_failed_ack(client, tmp_path, monkeypatch):
    from argparse import Namespace
    from src.client import cli

    alice, bob = generate_identity("Alice"), generate_identity("Bob")
    _register(client, alice)
    _register(client, bob)
    envelope = seal_message(alice, bob.public_bundle(), b"archivo", filename="test.txt")
    client.post("/messages", json=envelope.to_dict()).raise_for_status()
    monkeypatch.setattr(cli, "_ask_passphrase", lambda: "")
    monkeypatch.setattr(cli, "load_identity", lambda *_: bob)
    monkeypatch.setattr(cli, "load_contacts", lambda *_: {"Alice": alice.public_bundle()})
    fail_ack = True

    def request(method, server, path, **kwargs):
        if fail_ack and path.endswith("/ack"):
            raise OSError("conexión interrumpida")
        return client.request(method, path, **kwargs).raise_for_status().json()

    monkeypatch.setattr(cli, "request", request)
    args = Namespace(data_dir=str(tmp_path), server="https://relay.test")
    with pytest.raises(OSError, match="interrumpida"):
        cli.cmd_inbox(args)
    assert list((tmp_path / "inbox").glob("*.json"))
    assert [p.read_bytes() for p in (tmp_path / "received").iterdir()] == [b"archivo"]
    assert len(_inbox(client, bob).json()["messages"]) == 1
    fail_ack = False
    cli.cmd_inbox(args)
    assert len(list((tmp_path / "received").iterdir())) == 1
    assert _inbox(client, bob).json()["messages"] == []


def test_legacy_database_keeps_message_and_identity(tmp_path):
    import json
    import sqlite3

    alice, bob = generate_identity("Alice"), generate_identity("Bob")
    envelope = seal_message(alice, bob.public_bundle(), b"antiguo")
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE public_keys(fingerprint TEXT PRIMARY KEY, name TEXT NOT NULL,
              x25519_public TEXT NOT NULL, ed25519_public TEXT NOT NULL);
            CREATE TABLE mailbox(id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_fp TEXT NOT NULL,
              envelope_json TEXT NOT NULL, received_at TEXT NOT NULL DEFAULT (datetime('now')));
        """)
        for identity in (alice, bob):
            b = identity.public_bundle()
            db.execute("INSERT INTO public_keys VALUES (?,?,?,?)",
                       (b.fingerprint, b.name, b.x25519_public, b.ed25519_public))
        db.execute("INSERT INTO mailbox(id, recipient_fp, envelope_json) VALUES (42, ?, ?)",
                   (bob.fingerprint, json.dumps(envelope.to_dict())))
    with TestClient(create_app(Storage(path)), base_url="https://relay.test") as client:
        assert _register(client, bob) == bob.public_bundle()
        pending = _inbox(client, bob).json()["messages"]
        assert pending == [{"id": 42, "envelope": envelope.to_dict()}]
        for _ in range(2):
            ack = {"id": 42}
            assert client.post(f"/messages/{bob.fingerprint}/ack",
                               json={**ack, "proof": _sign(client, bob, "ack", ack)}).status_code == 200
