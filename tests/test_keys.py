import time
from app.keys import (
    generate_key_pair,
    get_unexpired_keys,
    get_expired_key,
    save_key_to_db,
)
from app.settings import DEFAULT_KEY_LIFETIME_SECONDS, EXPIRED_KEY_LIFETIME_SECONDS
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
import pytest


def test_generate_key_pair(temp_db):
    key = generate_key_pair()
    assert "kid" in key
    assert "expiry" in key
    assert key["expiry"] > int(time.time())
    assert "private" in key
    assert "public" in key


def test_generate_expired_key_pair(temp_db):
    key = generate_key_pair(EXPIRED_KEY_LIFETIME_SECONDS)
    assert key["expiry"] < int(time.time())


def test_get_unexpired_keys(temp_db):
    generate_key_pair()
    generate_key_pair(EXPIRED_KEY_LIFETIME_SECONDS)
    unexpired = get_unexpired_keys()
    assert len(unexpired) >= 1


def test_get_expired_key(temp_db):
    generate_key_pair(EXPIRED_KEY_LIFETIME_SECONDS)
    expired = get_expired_key()
    assert expired is not None


def test_save_key_to_db(temp_db):
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    count_before = cursor.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    assert count_before == 0

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expiry = int(time.time()) + DEFAULT_KEY_LIFETIME_SECONDS
    save_key_to_db(private_key, expiry)

    count_after = cursor.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
    assert count_after == 1

    row = cursor.execute("SELECT key, exp FROM keys").fetchone()
    assert row[1] == expiry
    conn.close()


def test_get_unexpired_keys_empty(temp_db):
    unexpired = get_unexpired_keys()
    assert len(unexpired) == 0


def test_get_expired_key_none(temp_db):
    expired = get_expired_key()
    assert expired is None


def test_save_key_to_db_error(temp_db, monkeypatch):
    def mock_connect(*args, **kwargs):
        raise sqlite3.OperationalError("Database connection failed")

    monkeypatch.setattr("sqlite3.connect", mock_connect)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expiry = int(time.time()) + DEFAULT_KEY_LIFETIME_SECONDS
    with pytest.raises(sqlite3.OperationalError):
        save_key_to_db(private_key, expiry)
