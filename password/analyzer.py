"""Core password analysis utilities."""
from __future__ import annotations

import math
import re
import secrets
import sqlite3
import hashlib
from typing import Dict, List, Tuple

COMMON_PASSWORDS_FILE = __import__("pkgutil").get_data(__name__, "../common_passwords.txt")
if COMMON_PASSWORDS_FILE:
    COMMON_PASSWORDS = set(x.strip().decode() for x in COMMON_PASSWORDS_FILE.splitlines() if x.strip())
else:
    COMMON_PASSWORDS = set()


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length  # bits


def _has_upper(s: str) -> bool:
    return any(c.isupper() for c in s)


def _has_lower(s: str) -> bool:
    return any(c.islower() for c in s)


def _has_digit(s: str) -> bool:
    return any(c.isdigit() for c in s)


def _has_symbol(s: str) -> bool:
    return any(not c.isalnum() for c in s)


def evaluate_password(password: str) -> Dict[str, object]:
    """Evaluate strength of `password` and return a summary dict.

    Returned dict contains:
    - score: 0-100
    - entropy_bits: estimated entropy in bits
    - checks: dict of boolean checks
    - suggestions: list of text suggestions
    """
    suggestions: List[str] = []

    length = len(password)
    entropy = _shannon_entropy(password)

    checks = {
        "length>=12": length >= 12,
        "has_upper": _has_upper(password),
        "has_lower": _has_lower(password),
        "has_digit": _has_digit(password),
        "has_symbol": _has_symbol(password),
        "not_common": password.lower() not in COMMON_PASSWORDS,
        "no_repeat_sequence": not bool(re.search(r"(.+)\1{2,}", password)),
    }

    # Base score from entropy (cap)
    score = min(100, int(entropy * 2))

    # Bonuses and penalties
    if checks["length>=12"]:
        score += 5
    if checks["has_upper"] and checks["has_lower"]:
        score += 5
    if checks["has_digit"]:
        score += 3
    if checks["has_symbol"]:
        score += 5
    if not checks["not_common"]:
        score = max(0, score - 40)

    score = max(0, min(100, score))

    # Suggestions
    if length < 12:
        suggestions.append("Use a longer password (12+ characters). Consider a passphrase.")
    if not checks["has_upper"]:
        suggestions.append("Add uppercase letters.")
    if not checks["has_lower"]:
        suggestions.append("Add lowercase letters.")
    if not checks["has_digit"]:
        suggestions.append("Add digits.")
    if not checks["has_symbol"]:
        suggestions.append("Add symbols (e.g., !@#$%).")
    if not checks["not_common"]:
        suggestions.append("Avoid common passwords or obvious patterns.")
    if checks["no_repeat_sequence"] is False:
        suggestions.append("Avoid repeated sequences like 'abcabcabc' or 'aaaaaa'.")

    if not suggestions:
        suggestions.append("Consider using a password manager to generate and store a random password.")

    return {
        "score": score,
        "entropy_bits": round(entropy, 1),
        "length": length,
        "checks": checks,
        "suggestions": suggestions,
    }


def generate_strong_password(length: int = 16) -> str:
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}:;.,<>?/"
    )
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _ensure_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS old_passwords (id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
    )
    conn.commit()
    conn.close()


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def store_password_to_db(password: str, db_path: str) -> None:
    """Store a password hash to the sqlite DB to prevent reuse checks later."""
    _ensure_db(db_path)
    h = _hash_password(password)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO old_passwords (sha256) VALUES (?)", (h,))
        conn.commit()
    finally:
        conn.close()


def is_reused_password(password: str, db_path: str) -> bool:
    """Return True if the password (by hash) is present in DB."""
    try:
        _ensure_db(db_path)
        h = _hash_password(password)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM old_passwords WHERE sha256 = ? LIMIT 1", (h,))
        found = cur.fetchone() is not None
        conn.close()
        return found
    except Exception:
        return False


if __name__ == "__main__":
    print("Run the CLI `cli.py` for an interactive demo.")
