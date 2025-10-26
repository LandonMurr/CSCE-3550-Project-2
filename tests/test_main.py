import jwt
from fastapi.testclient import TestClient
from app.main import app
from app.settings import ALGORITHM, ISSUER
import time
import sqlite3
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import serialization
import pytest


def jwk_to_public_key(jwk):
    """
    Converts a JWK to an RSA public key object for verification.
    """
    n_bytes = urlsafe_b64decode(jwk["n"] + "===")
    e_bytes = urlsafe_b64decode(jwk["e"] + "===")
    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    return RSAPublicNumbers(e, n).public_key(default_backend())


def test_jwks_endpoint(temp_db):
    """
    Tests the JWKS endpoint.
    """
    with TestClient(app) as client:
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) == 1  # Assuming one unexpired key
        for key in data["keys"]:
            assert key["kty"] == "RSA"
            assert "kid" in key
            assert "n" in key
            assert "e" in key
            assert key["alg"] == "RS256"
            assert key["use"] == "sig"


def test_auth_endpoint_valid(temp_db):
    """
    Tests the auth endpoint under valid condition.
    """
    with TestClient(app) as client:
        response = client.post("/auth")
        assert response.status_code == 200
        token = response.text
        headers = jwt.get_unverified_header(token)
        assert "kid" in headers
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "notta-raelporsohn"
        assert payload["iss"] == ISSUER
        assert payload["exp"] > int(time.time())
        assert payload["iat"] <= int(time.time())


def test_auth_endpoint_valid_verify(temp_db):
    """
    Tests the auth endpoint with full signature verification using JWKS.
    """
    with TestClient(app) as client:
        response = client.post("/auth")
        assert response.status_code == 200
        token = response.text
        headers = jwt.get_unverified_header(token)
        kid = headers["kid"]

        # Fetch JWKS
        jwks_response = client.get("/.well-known/jwks.json")
        assert jwks_response.status_code == 200
        jwks = jwks_response.json()["keys"]
        jwk = next((k for k in jwks if k["kid"] == kid), None)
        assert jwk is not None

        # Convert JWK to public key
        public_key = jwk_to_public_key(jwk)

        # Verify token signature
        payload = jwt.decode(
            token, public_key, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
        assert payload["iss"] == ISSUER
        assert payload["sub"] == "notta-raelporsohn"


def test_auth_endpoint_expired(temp_db):
    """
    Tests the auth endpoint under expired condition.
    """
    with TestClient(app) as client:
        response = client.post("/auth?expired")
        assert response.status_code == 200
        token = response.text
        headers = jwt.get_unverified_header(token)
        assert "kid" in headers
        payload = jwt.decode(token, options={"verify_signature": False})
        assert payload["sub"] == "notta-raelporsohn"
        assert payload["iss"] == ISSUER
        assert payload["exp"] <= int(time.time())
        assert payload["iat"] <= int(time.time())


def test_auth_endpoint_expired_verify(temp_db):
    """
    Tests the auth endpoint under expired condition with DB-fetched key.
    """
    with TestClient(app) as client:
        response = client.post("/auth?expired")
        assert response.status_code == 200
        token = response.text
        headers = jwt.get_unverified_header(token)
        kid = headers["kid"]

        # Fetch expired private key and derive public key
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT rowid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
                (int(time.time()),),
            )
            row = cursor.fetchone()
            assert row is not None
            rowid, key_bytes, expiry = row
        assert str(rowid) == kid

        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        public_key = private_key.public_key()

        payload = jwt.decode(
            token, public_key, algorithms=[ALGORITHM], options={"verify_exp": False}
        )
        assert payload["iss"] == ISSUER
        assert payload["sub"] == "notta-raelporsohn"


def test_no_unexpired_keys(temp_db):
    """
    Tests auth endpoint when no unexpired keys exist.
    """
    with TestClient(app) as client:
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys WHERE exp > ?", (int(time.time()),))
            conn.commit()
        response = client.post("/auth")
        assert response.status_code == 500
        data = response.json()
        assert "error" in data
        assert "No unexpired key exists" in data["error"]


def test_no_expired_key(temp_db):
    """
    Tests auth endpoint when no expired keys exist.
    """
    with TestClient(app) as client:
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys WHERE exp <= ?", (int(time.time()),))
            conn.commit()
        response = client.post("/auth?expired")
        assert response.status_code == 500
        data = response.json()
        assert "error" in data
        assert "No expired key exists" in data["error"]


def test_jwks_endpoint_empty(temp_db):
    """
    Tests the JWKS endpoint when no unexpired keys exist.
    """
    with TestClient(app) as client:
        with sqlite3.connect(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys WHERE exp > ?", (int(time.time()),))
            conn.commit()
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) == 0


def test_auth_endpoint_db_error(temp_db, monkeypatch):
    """
    Tests the auth endpoint when database connection fails.
    """

    def mock_connect(*args, **kwargs):
        raise sqlite3.OperationalError("Database connection failed")

    monkeypatch.setattr("sqlite3.connect", mock_connect)
    with pytest.raises(sqlite3.OperationalError):
        with TestClient(app) as client:
            client.post("/auth")
