from cryptography.hazmat.primitives.asymmetric import rsa
from app.jwk_utils import public_key_to_jwk, private_key_to_pem


def test_public_key_to_jwk():
    """
    Tests the public_key_to_jwk function
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = "test-kid"
    jwk = public_key_to_jwk(public_key, kid)
    assert jwk["kty"] == "RSA"
    assert jwk["kid"] == kid
    assert "n" in jwk
    assert "e" in jwk
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"


def test_private_key_to_pem():
    """
    Tests the private_key_to_pem function
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key_to_pem(private_key)
    assert isinstance(pem, bytes)
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pem.endswith(b"-----END PRIVATE KEY-----\n")
