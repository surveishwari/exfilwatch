"""
ExfilWatch — audit log
Every scan gets persisted so the service can answer "what did we catch,
and when" — the thing a company's security/compliance team actually
needs, not just a live demo.
"""

import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("EXFILWATCH_DB", "exfilwatch.db")
GENESIS = "0" * 64  # prev_hash of the first audit entry


def init_db():
    with _conn() as c:
        c.execute("PRAGMA journal_mode=WAL")  # readers never block the audit writer
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                text_preview TEXT NOT NULL,
                text_length INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                decoded_message TEXT,
                action TEXT NOT NULL,
                client TEXT,
                prev_hash TEXT,
                entry_hash TEXT
            )
        """)
        _migrate_chain(c)
        # Real per-tenant API keys, not one shared demo string. We only ever
        # store a SHA-256 hash of the key, the same way a real secrets
        # manager would — the raw key is shown to the caller exactly once,
        # at creation time, and never persisted anywhere.
        c.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                created_at REAL NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                last_used_at REAL
            )
        """)


# --- Tamper-evident audit chain ----------------------------------------------
# Each entry stores prev_hash and entry_hash = SHA-256(prev_hash || entry
# fields). Editing or deleting any past row breaks every hash after it, and
# verify_chain() pinpoints the first bad row. The head hash can be anchored
# externally (printed, e-mailed, written to a ledger) to also catch truncation.

def _entry_hash(prev: str, ts, preview, length, risk, verdict, decoded, action, client) -> str:
    payload = json.dumps([prev, ts, preview, length, risk, verdict, decoded, action, client],
                         separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _mask_secret(value: str | None) -> str | None:
    """Audit logs must not become a second copy of the secret they caught."""
    if not value:
        return None
    return f"{value[:2]}{'*' * min(max(len(value) - 2, 0), 8)} ({len(value)} chars, masked)"


def _migrate_chain(c):
    cols = {r[1] for r in c.execute("PRAGMA table_info(scans)")}
    for col in ("prev_hash", "entry_hash"):
        if col not in cols:
            c.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
    prev = GENESIS
    rows = c.execute(
        "SELECT id, ts, text_preview, text_length, risk_score, verdict, decoded_message, "
        "action, client, entry_hash FROM scans ORDER BY id"
    ).fetchall()
    for r in rows:
        if r[9] is None:  # legacy row written before the chain existed
            h = _entry_hash(prev, *r[1:9])
            c.execute("UPDATE scans SET prev_hash=?, entry_hash=? WHERE id=?", (prev, h, r[0]))
            prev = h
        else:
            prev = r[9]


def verify_chain() -> dict:
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, text_preview, text_length, risk_score, verdict, decoded_message, "
            "action, client, prev_hash, entry_hash FROM scans ORDER BY id"
        ).fetchall()
    prev = GENESIS
    for n, r in enumerate(rows, 1):
        if r[9] != prev or r[10] != _entry_hash(prev, *r[1:9]):
            return {"valid": False, "checked": n, "first_bad_id": r[0], "head": None}
        prev = r[10]
    return {"valid": True, "checked": len(rows), "first_bad_id": None, "head": prev}


# --- Per-tenant API key management -----------------------------------------

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def create_api_key(tenant: str) -> str:
    """Issue a new key for `tenant`. Returns the raw key — this is the ONLY
    time the raw value is ever available; only its hash is stored."""
    raw_key = "ew_live_" + secrets.token_urlsafe(24)
    with _conn() as c:
        c.execute(
            "INSERT INTO api_keys (tenant, key_hash, key_prefix, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            (tenant, _hash_key(raw_key), raw_key[:12], time.time()),
        )
    return raw_key


def verify_api_key(raw_key: str) -> str | None:
    """Return the tenant name if `raw_key` is a valid, active key; else None."""
    if not raw_key:
        return None
    with _conn() as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT id, tenant FROM api_keys WHERE key_hash = ? AND active = 1",
            (_hash_key(raw_key),),
        ).fetchone()
        if not row:
            return None
        c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), row["id"]))
        return row["tenant"]


def list_api_keys():
    with _conn() as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT id, tenant, key_prefix, created_at, active, last_used_at "
            "FROM api_keys ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def revoke_api_key(key_id: int) -> bool:
    with _conn() as c:
        cur = c.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,))
        return cur.rowcount > 0


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def log_scan(text: str, risk_score: int, verdict: str, decoded_message: str | None,
             action: str, client: str = "unknown"):
    preview = text[:120]
    decoded = _mask_secret(decoded_message)
    ts = time.time()
    with _conn() as c:
        c.execute("BEGIN IMMEDIATE")  # serialize writers so the chain can't fork
        row = c.execute("SELECT entry_hash FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row and row[0] else GENESIS
        h = _entry_hash(prev, ts, preview, len(text), risk_score, verdict, decoded, action, client)
        c.execute(
            "INSERT INTO scans (ts, text_preview, text_length, risk_score, verdict, "
            "decoded_message, action, client, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, preview, len(text), risk_score, verdict, decoded, action, client, prev, h),
        )


def recent_scans(limit: int = 20):
    with _conn() as c:
        c.row_factory = sqlite3.Row
        rows = c.execute(
            "SELECT ts, text_preview, text_length, risk_score, verdict, decoded_message, action, client "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def stats():
    with _conn() as c:
        c.row_factory = sqlite3.Row
        row = c.execute(
            "SELECT COUNT(*) as total, "
            "COALESCE(SUM(CASE WHEN action='BLOCK' THEN 1 ELSE 0 END), 0) as blocked, "
            "COALESCE(SUM(CASE WHEN action='REVIEW' THEN 1 ELSE 0 END), 0) as review, "
            "COALESCE(SUM(CASE WHEN action='ALLOW' THEN 1 ELSE 0 END), 0) as allowed "
            "FROM scans"
        ).fetchone()
        return dict(row) if row else {"total": 0, "blocked": 0, "review": 0, "allowed": 0}
