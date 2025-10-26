# Constants for the JWKS server

PORT = 8080
ALGORITHM = "RS256"  # JWT signing algorithm
DEFAULT_KEY_LIFETIME_SECONDS = 3600  # 1 hour
EXPIRED_KEY_LIFETIME_SECONDS = (
    -3600
)  # For testing expired keys (negative to make it already expired)
ISSUER = "settings.py"  # JWT issuer claim
