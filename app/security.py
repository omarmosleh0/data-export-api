# JWT VERIFICATION ONLY ya m3allem
import logging
from typing import Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
import requests
import os
from functools import lru_cache
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
logger = logging.getLogger(__name__)

# --- CONFIG FROM ENVIRONMENT ---
ISSUER = os.environ.get("JWT_ISSUER")  # e.g., "https://your-wiley.okta.com/oauth2/default"
AUDIENCE = os.environ.get("JWT_AUDIENCE")  # e.g., "query-engine-api"
JWKS_URL = f"{ISSUER}/v1/keys"  # Standard OpenID Connect JWKS endpoint

if not ISSUER or not AUDIENCE:
    raise ValueError("JWT_ISSUER and JWT_AUDIENCE must be set in environment")

# Reusable security scheme
bearer_scheme = HTTPBearer()


@lru_cache()  # Cache JWKS to avoid HTTP call on every request
def get_jwks() -> Dict[str, Any]:
    """Fetch and cache the JSON Web Key Set from the IdP."""
    try:
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.critical(f"Failed to fetch JWKS from {JWKS_URL}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth configuration error"
        )


def verify_jwt(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT issued by the enterprise IdP."""
    try:
        # Use the cached JWKS for key lookup
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise JWTError("Missing 'kid' in token header")

        jwks = get_jwks()
        public_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                # Build the public key object
                from jose.backends.cryptography_backend import CryptographyRSA
                public_key = CryptographyRSA.load_key(key)
                break

        if public_key is None:
            raise JWTError(f"Public key not found for kid={kid}")

        # Verify signature + claims
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTClaimsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid claim: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected JWT error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


async def get_current_user(
    credentials: HTTPBearer = Depends(bearer_scheme)
) -> Dict[str, Any]:
    """Dependency to extract and verify user from Bearer token."""
    token = credentials.credentials
    payload = verify_jwt(token)
    return payload