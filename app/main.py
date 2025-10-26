# FastAPI app that provides JWKS and JWT

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from contextlib import asynccontextmanager
from .keys import generate_key_pair, init_db, DB_PATH  # Import DB_PATH if needed
from .jwk_utils import public_key_to_jwk
from .settings import ALGORITHM, ISSUER
from .settings import EXPIRED_KEY_LIFETIME_SECONDS
from .settings import DEFAULT_KEY_LIFETIME_SECONDS
from cryptography.hazmat.primitives import serialization
import jwt
import time
import sqlite3

app = FastAPI()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """
    Runs when the server starts and stops
    Generates one active key and one expired key for testing if they don't exist
    """
    init_db()  # Always initialize database
    current_time = int(time.time())

    # Check for unexpired key
    with sqlite3.connect(DB_PATH, timeout=5) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp > ?", (current_time,))
        unexpired_count = cursor.fetchone()[0]
        cursor.close()

    if unexpired_count == 0:
        generate_key_pair()  # Generate unexpired only if none exist

    # Check for expired key
    with sqlite3.connect(DB_PATH, timeout=5) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys WHERE exp <= ?", (current_time,))
        expired_count = cursor.fetchone()[0]

    if expired_count == 0:
        generate_key_pair(
            EXPIRED_KEY_LIFETIME_SECONDS
        )  # Generate expired only if none exist

    yield  # Shutdown code would go here if needed


app = FastAPI(lifespan=lifespan)


# JWKS endpoint
@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    with sqlite3.connect(DB_PATH, timeout=5) as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?", (int(time.time()),)
        )
        rows = cursor.fetchall()
        cursor.close()

    jwks = []
    for row in rows:
        kid, key_bytes, expiry = row
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        public_key = private_key.public_key()
        jwks.append(public_key_to_jwk(public_key, str(kid)))

    del rows, cursor
    return JSONResponse(content={"keys": jwks}, status_code=200)


# Auth endpoint
@app.post("/auth")
async def auth_endpoint(request: Request):
    sub = "notta-raelporsohn"
    try:
        body = await request.json()
        if "username" in body:
            sub = body["username"]
    except Exception:
        pass

    query_params = request.query_params
    use_expired = "expired" in query_params

    with sqlite3.connect(DB_PATH, timeout=5) as connection:
        cursor = connection.cursor()

        if use_expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
                (int(time.time()),),
            )
            key_type = "expired"
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
                (int(time.time()),),
            )
            key_type = "unexpired"

        row = cursor.fetchone()

    if not row:
        return JSONResponse(
            content={"error": f"No {key_type} key exists"}, status_code=500
        )

    kid, key_bytes, expiry = row
    private_key = serialization.load_pem_private_key(key_bytes, password=None)

    payload = {
        "sub": sub,
        "iss": ISSUER,
        "exp": expiry,
        "iat": int(time.time()),
    }
    headers = {"kid": str(kid)}

    token = jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=headers)

    return Response(content=token, media_type="text/plain")
