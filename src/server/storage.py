"""
Almacenamiento persistente (SQLite) del servidor SICN.

El servidor guarda dos cosas, y nada más:

1. **Directorio de claves públicas**: para que un remitente pueda buscar la
   clave pública de un destinatario por su huella digital (fingerprint).
   Esto es equivalente a un "servidor de claves" de PGP: información
   pública por definición, no sensible.
2. **Cola de mensajes cifrados**: sobres (envelopes) ya cifrados y firmados
   por el cliente, pendientes de que el destinatario los recoja. El
   servidor nunca ve el contenido en claro ni ninguna clave privada.

Minimiza la información retenida: al entregar un mensaje se borra de la
cola (no queda un histórico permanente de metadatos en el servidor).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager


SCHEMA = """
CREATE TABLE IF NOT EXISTS public_keys (
    fingerprint TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    x25519_public TEXT NOT NULL,
    ed25519_public TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_fp TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_fp);
"""


class Storage:
    def __init__(self, db_path: str = "sicn_server.db"):
        self.db_path = db_path
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------- claves
    def register_public_key(self, fingerprint: str, name: str, x25519_public: str, ed25519_public: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO public_keys (fingerprint, name, x25519_public, ed25519_public)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    name=excluded.name,
                    x25519_public=excluded.x25519_public,
                    ed25519_public=excluded.ed25519_public
                """,
                (fingerprint, name, x25519_public, ed25519_public),
            )

    def get_public_key(self, fingerprint: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT fingerprint, name, x25519_public, ed25519_public FROM public_keys WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return {"fingerprint": row[0], "name": row[1], "x25519_public": row[2], "ed25519_public": row[3]}

    # ---------------------------------------------------------- mensajes
    def push_message(self, recipient_fp: str, envelope: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO mailbox (recipient_fp, envelope_json) VALUES (?, ?)",
                (recipient_fp, json.dumps(envelope)),
            )

    def pop_messages(self, recipient_fp: str) -> list[dict]:
        """Devuelve todos los mensajes pendientes de un destinatario y los
        elimina de la cola (entrega única, como un buzón que se vacía)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, envelope_json FROM mailbox WHERE recipient_fp = ? ORDER BY id",
                (recipient_fp,),
            ).fetchall()
            ids = [r[0] for r in rows]
            if ids:
                conn.executemany("DELETE FROM mailbox WHERE id = ?", [(i,) for i in ids])
        return [json.loads(r[1]) for r in rows]
