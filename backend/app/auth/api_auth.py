"""API bearer-token authentication dependency.

Single source of truth for authenticating the local /api surface:

    from ..auth.api_auth import require_api_token
    ...
    APIRouter(prefix="/api", dependencies=[Depends(require_api_token)])

The routers are mounted behind a centralized dependency in app.main (see
``api_router_guard`` there), so a newly added /api endpoint cannot
accidentally bypass authentication.

The dependency reads the ``Authorization: Bearer <token>`` header (FastAPI
resolves the Header object before this function runs, so the function only
ever sees a plain string). Missing, malformed, or wrong tokens get a 401.
No token is logged anywhere, and no token ever reaches a URL.
"""

from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException, status

from .token_manager import get_manager

_UNAUTHORIZED_HEADERS = {"WWW-Authenticate": "Bearer"}


def check_bearer_token(authorization: Optional[str]) -> None:
    """Validate a raw Authorization header value; raise 401 unless valid.

    This is the one place that knows *how* a request is authenticated. The
    FastAPI dependency below and the ASGI middleware both call it, so the
    rules can never drift apart.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers=_UNAUTHORIZED_HEADERS,
        )

    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() != "bearer" or not credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
            headers=_UNAUTHORIZED_HEADERS,
        )

    if get_manager().validate(credential):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired bearer token",
        headers=_UNAUTHORIZED_HEADERS,
    )


def require_api_token(authorization: Optional[str] = None) -> bool:
    """FastAPI dependency: enforce the local bearer token.

    ``authorization`` is injected by FastAPI from the ``Authorization``
    request header via ``Depends(require_api_token)`` — see
    ``require_api_token_header`` below, which is what the router mounts.
    """
    check_bearer_token(authorization)
    return True


# Header-bound variant used by the centralized router dependency. Declaring
# the Header here (instead of in the signature above) keeps
# ``require_api_token`` callable as a plain function from the middleware.
def require_api_token_header(
    authorization: Optional[str] = Header(default=None, alias="authorization"),
) -> bool:
    check_bearer_token(authorization)
    return True


def get_token_value() -> Optional[str]:
    """Return the active plaintext token for the internal bootstrap console.

    Deliberately NOT exposed through the API, never logged, never in a URL.
    Returns None when the token is not set (e.g. in tests that reset the
    manager directly).
    """
    return get_manager().get_session_token()
