"""SQLite persistence for immutable identities, single-use proofs and mailbox ACKs."""
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS public_keys (
 fingerprint TEXT PRIMARY KEY, name TEXT NOT NULL,
 x25519_public TEXT NOT NULL, ed25519_public TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mailbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_fp TEXT NOT NULL,
 envelope_json TEXT NOT NULL, received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_fp, id);
CREATE TABLE IF NOT EXISTS relay_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS challenges (
 nonce TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, expires_at INTEGER NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_expiry ON challenges(expires_at);
CREATE TABLE IF NOT EXISTS deliveries (
 recipient_fp TEXT NOT NULL, digest TEXT NOT NULL, message_id INTEGER NOT NULL,
 created_at INTEGER NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY (recipient_fp, digest)
);
CREATE INDEX IF NOT EXISTS idx_delivery_message ON deliveries(recipient_fp, message_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_expiry ON deliveries(created_at);
"""


class CapacityError(Exception):
    pass


class Storage:
    def __init__(self, db_path="sicn_server.db", retention=30 * 86400, clock=time.time):
        if retention < 60:
            raise ValueError("SICN_RETENTION_SECONDS debe ser al menos 60")
        self.db_path = db_path
        self.retention = retention
        self.clock = clock
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
            db.execute("INSERT OR IGNORE INTO relay_meta VALUES ('audience', ?)", (secrets.token_hex(32),))
            db.execute("INSERT OR IGNORE INTO relay_meta VALUES ('schema_version', '1')")
            if db.execute("SELECT value FROM relay_meta WHERE key='schema_version'").fetchone()[0] != "1":
                raise RuntimeError("Versión SQLite incompatible")
            self.audience = db.execute("SELECT value FROM relay_meta WHERE key='audience'").fetchone()[0]

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def issue(self, fingerprint, operation, digest):
        now = int(self.clock())
        challenge = {"nonce": secrets.token_hex(32), "fingerprint": fingerprint, "operation": operation,
                     "context": digest, "audience": self.audience, "expires_at": now + 60}
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM challenges WHERE expires_at <= ?", (now,))
            if db.execute("SELECT count(*) FROM challenges").fetchone()[0] >= 4096:
                raise CapacityError()
            if db.execute("SELECT count(*) FROM challenges WHERE fingerprint=?", (fingerprint,)).fetchone()[0] >= 32:
                raise CapacityError()
            db.execute("INSERT INTO challenges VALUES (?, ?, ?, ?)",
                       (challenge["nonce"], fingerprint, now + 60, json.dumps(challenge)))
        return challenge

    @contextmanager
    def authenticate(self, nonce, verify):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM challenges WHERE nonce=? AND expires_at>?",
                             (nonce, int(self.clock()))).fetchone()
            if row is None or not verify(json.loads(row[0])):
                yield None
                return
            db.execute("DELETE FROM challenges WHERE nonce=?", (nonce,))
            yield db

    def get_public_key(self, fingerprint):
        with self._connect() as db:
            row = db.execute("SELECT * FROM public_keys WHERE fingerprint=?", (fingerprint,)).fetchone()
            return dict(row) if row else None

    def register(self, db, bundle):
        values = bundle.to_dict()
        row = db.execute("SELECT * FROM public_keys WHERE fingerprint=?", (bundle.fingerprint,)).fetchone()
        if row:
            return dict(row) == values
        if db.execute("SELECT count(*) FROM public_keys").fetchone()[0] >= 10000:
            raise CapacityError()
        db.execute("INSERT INTO public_keys VALUES (?, ?, ?, ?)",
                   (bundle.fingerprint, bundle.name, bundle.x25519_public, bundle.ed25519_public))
        return True

    def _expire(self, db):
        cutoff = int(self.clock()) - self.retention
        db.execute("DELETE FROM mailbox WHERE received_at <= datetime(?, 'unixepoch')", (cutoff,))
        db.execute("DELETE FROM deliveries WHERE created_at <= ?", (cutoff,))

    def push_message(self, recipient, envelope, digest):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db)
            prior = db.execute("SELECT message_id FROM deliveries WHERE recipient_fp=? AND digest=?",
                               (recipient, digest)).fetchone()
            if prior:
                return prior[0]
            if db.execute("SELECT count(*) FROM mailbox WHERE recipient_fp=?", (recipient,)).fetchone()[0] >= 100:
                raise CapacityError()
            if (db.execute("SELECT count(*) FROM deliveries").fetchone()[0] >= 10000
                or db.execute("SELECT count(*) FROM mailbox").fetchone()[0] >= 2000):
                raise CapacityError()
            now = int(self.clock())
            row = db.execute("INSERT INTO mailbox(recipient_fp, envelope_json, received_at) "
                             "VALUES (?, ?, datetime(?, 'unixepoch'))", (recipient, json.dumps(envelope), now))
            db.execute("INSERT INTO deliveries VALUES (?, ?, ?, ?, 0)", (recipient, digest, row.lastrowid, now))
            return row.lastrowid

    def pending(self, db, recipient, after):
        self._expire(db)
        return [{"id": row[0], "envelope": json.loads(row[1])} for row in db.execute(
            "SELECT id, envelope_json FROM mailbox WHERE recipient_fp=? AND id>? ORDER BY id LIMIT 10",
            (recipient, after),
        )]

    def ack(self, db, recipient, message_id):
        self._expire(db)
        removed = db.execute("DELETE FROM mailbox WHERE recipient_fp=? AND id=?", (recipient, message_id)).rowcount
        updated = db.execute("UPDATE deliveries SET acknowledged=1 WHERE recipient_fp=? AND message_id=?",
                             (recipient, message_id)).rowcount
        if removed and not updated:  # legacy pending message
            db.execute("INSERT INTO deliveries VALUES (?, ?, ?, ?, 1)",
                       (recipient, f"legacy:{message_id}", message_id, int(self.clock())))
        return bool(removed or updated)
