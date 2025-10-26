# Helpers to convert public key to JWK format and serialize private keys

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64encode


def public_key_to_jwk(public_key, kid):
    """
    Converts an RSA public key to JWK format
    - public_key: The RSA public key object
    - kid:        The key ID (string)
    Returns a dict in JWK format; to be used in a JWKS endpoint
    """

    # Extract modulus and exponent from the public key
    public_numbers = public_key.public_numbers()

    def int_to_base64(n):
        # Convert integer to base64 (URL-safe) without padding; for 'n' and 'e' in JWK
        bys = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return urlsafe_b64encode(bys).rstrip(b"=").decode("utf-8")

    # Construct JWK dict
    jwk = {
        "kty": "RSA",  # Key type (RSA)
        "use": "sig",  # Use case (signing)
        "kid": kid,  # Key ID (key ID)
        "n": int_to_base64(public_numbers.n),  # RSA modulus
        "e": int_to_base64(public_numbers.e),  # RSA exponent
        "alg": "RS256",  # Algorithm (RS256)
    }
    return jwk


def private_key_to_pem(private_key):
    """
    Serializes a private RSA key to PEM bytes
    - private_key: The RSA private key object
    Returns: PEM-encoded bytes
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
