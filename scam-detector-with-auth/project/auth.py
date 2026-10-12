"""
auth.py
Simple user accounts for the Scam Detection Assistant.

- Users and scan history are stored in a local SQLite file (users.db).
- Passwords are NEVER stored as plain text: they are salted and hashed
  with PBKDF2-HMAC-SHA256 (Python standard library, no extra packages).
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("SCAM_APP_DB", "users.db")

PBKDF2_ROUNDS = 200_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LEN = 8


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Creates the tables if they do not exist yet."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                message    TEXT NOT NULL,
                risk       TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, id DESC);
            """
        )


# ---------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, rounds, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------
# Register / login
# ---------------------------------------------------------------------

def register_user(username, email, password, confirm_password):
    """Returns (ok, message). On success the account is created."""
    username = (username or "").strip()
    email = (email or "").strip()

    if not USERNAME_RE.match(username):
        return False, "Username must be 3-20 characters: letters, numbers, _ or . only."
    if not EMAIL_RE.match(email):
        return False, "Please enter a valid email address."
    if len(password or "") < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if password != confirm_password:
        return False, "Passwords do not match."

    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, hash_password(password), _now()),
            )
    except sqlite3.IntegrityError:
        return False, "That username or email is already registered."
    return True, "Account created! You can log in now."


def login_user(identifier, password):
    """identifier = username or email. Returns user dict or None."""
    identifier = (identifier or "").strip()
    if not identifier or not password:
        return None
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (identifier, identifier)
        ).fetchone()
    if row is None:
        # Spend similar time as a real check so timing does not reveal valid usernames
        verify_password(password, hash_password("dummy-password"))
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"], "email": row["email"]}


# ---------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------

def save_scan(user_id, message, risk, confidence):
    with _connect() as conn:
        conn.execute(
            "INSERT INTO scans (user_id, message, risk, confidence, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, message, risk, float(confidence), _now()),
        )


def get_history(user_id, limit=50):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT message, risk, confidence, created_at FROM scans "
            "WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats(user_id):
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN risk IN ('High Risk','Suspicious') THEN 1 ELSE 0 END) AS risky "
            "FROM scans WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return {"total": row["total"] or 0, "risky": row["risky"] or 0}


def clear_history(user_id):
    with _connect() as conn:
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
