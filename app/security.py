"""
JWT Authentication Module

Handles OAuth2 JWT token verification using JWKS from enterprise IdP (Okta).
Implements secure token validation with caching and rate limiting support.
"""

import logging
import os
from typing import Dict, Any
from functools import lru_cache

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError, JWTClaimsError
import requests
from cachetools import TTLCache, cached
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
import math
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

ISSUER = os.environ.get("JWT_ISSUER")
AUDIENCE = os.environ.get("JWT_AUDIENCE")

if not ISSUER or not AUDIENCE:
    raise ValueError(
        "JWT_ISSUER and JWT_AUDIENCE must be set in environment. "
        "Example: JWT_ISSUER=https://wiley.okta.com/oauth2/default"
    )

JWKS_URL = f"{ISSUER.rstrip('/')}/v1/keys"

# Security scheme for FastAPI dependency injection
bearer_scheme = HTTPBearer()

# JWKS cache: 1 hour TTL (Okta rotates keys ~90 days, hourly refresh is safe)
JWKS_CACHE = TTLCache(maxsize=1, ttl=3600)


# ============================================================================
# JWKS FETCHING & CACHING
# ============================================================================

@cached(cache=JWKS_CACHE)
def get_jwks() -> Dict[str, Any]:
    """
    Fetch and cache the JSON Web Key Set from the IdP.
    
    Returns:
        JWKS dictionary containing public keys for token verification
        
    Raises:
        HTTPException: If JWKS fetch fails (500 Internal Server Error)
    """
    try:
        response = requests.get(JWKS_URL, timeout=5)
        response.raise_for_status()
        jwks = response.json()
        logger.info(f"JWKS fetched successfully from {JWKS_URL}")
        return jwks
    except requests.exceptions.RequestException as e:
        logger.critical(f"Failed to fetch JWKS from {JWKS_URL}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication configuration error: JWKS unavailable"
        )

def jwk_to_pem(jwk: Dict[str, Any]) -> str:
    """Convert RSA JWK to PEM format."""
    if jwk.get("kty") != "RSA":
        raise ValueError("Only RSA keys supported")

    # Decode base64url components
    n = int.from_bytes(base64url_decode(jwk["n"]), "big")
    e = int.from_bytes(base64url_decode(jwk["e"]), "big")

    # Handle large modulus (avoid OverflowError)
    if n.bit_length() > 16384:  # 16KB keys are unrealistic
        raise ValueError("Invalid RSA modulus size")

    # Build public key
    pub_numbers = RSAPublicNumbers(e, n)
    public_key = pub_numbers.public_key()
    
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _get_public_key(kid: str, jwks: Dict[str, Any]) -> Optional[str]:
    """Get PEM-formatted public key by KID."""
    for key in jwks["keys"]:
        if key["kid"] == kid and key.get("kty") == "RSA":
            return jwk_to_pem(key)
    return None

# ============================================================================
# JWT VERIFICATION (Full Validation)
# ============================================================================

def verify_jwt(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token with full validation.
    
    Validates:
    - Signature (RS256)
    - Expiration
    - Issuer
    - Audience
    - Key ID (kid)
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: 401 for invalid/expired tokens, 500 for config errors
    """
    try:
        # Extract key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if not kid:
            raise JWTError("Missing 'kid' in token header")

        # Get public key from JWKS
        jwks = get_jwks()
        public_key = _get_public_key(kid, jwks)

        # If key not found, refresh JWKS cache and retry once
        if public_key is None:
            logger.warning(f"KID '{kid}' not found in cached JWKS. Refreshing cache.")
            JWKS_CACHE.clear()
            jwks = get_jwks()
            public_key = _get_public_key(kid, jwks)
            
            if public_key is None:
                raise JWTError(f"Public key not found for kid={kid} even after cache refresh")

        # Verify signature and all claims
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
            detail=f"Invalid token claim: {str(e)}",
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
        logger.error(f"Unexpected error during JWT verification: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


# ============================================================================
# LIGHTWEIGHT TOKEN PARSING (For Rate Limiting)
# ============================================================================

def get_user_id_from_token(token: str) -> str:
    """
    Extract user ID from JWT for rate limiting purposes.
    
    Performs minimal validation (signature + expiry only) for performance.
    This is called on every request for rate limiting, so speed matters.
    
    Args:
        token: JWT token string
        
    Returns:
        User ID (sub claim) or "invalid_user" if token is malformed
        
    Note:
        Does not raise exceptions - returns "invalid_user" on any failure.
        This allows rate limiting to work even with invalid tokens.
    """
    try:
        # Extract key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if not kid:
            return "invalid_user"

        # Get public key
        jwks = get_jwks()
        public_key = _get_public_key(kid, jwks)

        # Refresh JWKS if key not found
        if public_key is None:
            logger.debug(f"KID '{kid}' not found in rate-limiting path. Refreshing JWKS.")
            JWKS_CACHE.clear()
            jwks = get_jwks()
            public_key = _get_public_key(kid, jwks)
            
            if public_key is None:
                return "invalid_user"

        # Verify only essential claims for performance
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"verify_exp": True}
        )
        
        return payload.get("sub", "unknown_user")
    
    except Exception as e:
        # Silently fail for rate limiting - don't expose errors
        logger.debug(f"Failed to extract user ID from token: {e}")
        return "invalid_user"


# ============================================================================
# FASTAPI DEPENDENCY
# ============================================================================

async def get_current_user(
    credentials: HTTPBearer = Depends(bearer_scheme)
) -> Dict[str, Any]:
    """
    FastAPI dependency for extracting and validating current user from JWT.
    
    Usage:
        @app.get("/protected")
        async def protected_route(user: dict = Depends(get_current_user)):
            user_id = user["sub"]
            # ... your logic
    
    Args:
        credentials: Bearer token from Authorization header
        
    Returns:
        Decoded JWT payload containing user information
        
    Raises:
        HTTPException: 401 if token is invalid or expired
    """
    token = credentials.credentials
    payload = verify_jwt(token)
    return payload