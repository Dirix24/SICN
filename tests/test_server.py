import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from src.core.envelope import open_message, seal_message
from src.crypto.keys import generate_identity
from src.server.app import app, storage


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Cada test usa su propia base de datos SQLite temporal."""
    from src.server import storage as storage_module

    test_storage = storage_module.Storage(str(tmp_path / "test.db"))
    monkeypatch.setattr("src.server.app.storage", test_storage)
    yield test_storage


@pytest.fixture
def client():
    return TestClient(app)


def _register(client, identity):
    bundle = identity.public_bundle()
    resp = client.post(
        "/register",
        json={
            "fingerprint": bundle.fingerprint,
            "name": bundle.name,
            "x25519_public": bundle.x25519_public,
            "ed25519_public": bundle.ed25519_public,
        },
    )
    assert resp.status_code == 200
    return bundle


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

    resp = client.get(f"/messages/{bob.fingerprint}")
    assert resp.status_code == 200
    messages = resp.json()["messages"]
    assert len(messages) == 1

    from src.core.envelope import Envelope

    received = Envelope.from_dict(messages[0])
    plaintext = open_message(bob, alice.public_bundle(), received)
    assert plaintext == b"Hola Bob, mensaje de prueba end-to-end."

    # El buzón se vacía tras recogerlo (entrega única).
    resp = client.get(f"/messages/{bob.fingerprint}")
    assert resp.json()["messages"] == []
