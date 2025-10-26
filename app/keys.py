# Key manager: generate, store, and query RSA keys

from cryptography.hazmat.primitives.asymmetric import rsa
from .settings import DEFAULT_KEY_LIFETIME_SECONDS, EXPIRED_KEY_LIFETIME_SECONDS
import uuid
import time
import sqlite3
import os

keys_store = []

# Sets DB path to navigate dir structure
DB_PATH = os.path.join(os.getcwd(), "totally_not_my_privateKeys.db")


def init_db():
    """
    Initializes the database and creates the keys table if it doesn't exist.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """
        )
        connection.commit()


def save_key_to_db(private_key, expiry):
    """
    Saves the private key to the SQLite database as BLOB
    """
    from .jwk_utils import private_key_to_pem

    key_bytes = private_key_to_pem(private_key)

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (key_bytes, expiry),
        )
        connection.commit()


def generate_key_pair(lifetime_seconds=DEFAULT_KEY_LIFETIME_SECONDS):
    """
    Generates RSA key pair with unique key ID; sets expiry timestamp
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    expiry = int(time.time()) + lifetime_seconds

    key_info = {
        "kid": str(uuid.uuid4()),
        "expiry": expiry,
        "private": private_key,
        "public": public_key,
    }

    keys_store.append(key_info)
    save_key_to_db(private_key, expiry)

    return key_info


def get_unexpired_keys():
    """
    Returns unexpired keys in a list
    """
    current_time = int(time.time())
    return [key for key in keys_store if key["expiry"] > current_time]


def get_expired_key():
    """
    Returns one key that has expired, or None if none exist
    """
    current_time = int(time.time())
    expired = [key for key in keys_store if key["expiry"] <= current_time]
    return expired[0] if expired else None
