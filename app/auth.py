"""OAuth 2.0 client-credentials flow.

A client trades its id and secret for a short-lived signed token (JWT), then sends
that token on every request. This is the same pattern Zscaler OneAPI and Microsoft
Graph use for service-to-service calls.
"""
from __future__ import annotations

import hmac
import time
from dataclasses import dataclass

import jwt
from fastapi import Depends, Form, HTTPException, Request, status
from fastapi.openapi.models import OAuthFlowClientCredentials, OAuthFlows
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2

from .config import Settings

ISSUER = "compliance-triage-api"
ALGORITHM = "HS256"
BEARER = "bearer"

SCOPE_DESCRIPTIONS = {
    "findings:read": "Read findings and cleared actions",
    "findings:write": "Submit findings for triage",
    "findings:approve": "Approve or reject high-impact fixes",
    "audit:read": "Read the audit log",
}

oauth2_scheme = OAuth2(
    flows=OAuthFlows(
        clientCredentials=OAuthFlowClientCredentials(
            tokenUrl="/oauth/token", scopes=SCOPE_DESCRIPTIONS
        )
    ),
    auto_error=False,
)
basic_scheme = HTTPBasic(auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Who is calling, taken from a verified token."""

    client_id: str
    scopes: frozenset[str]


def _oauth_error(code: int, error: str, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=code, headers=headers)


def issue_token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    basic: HTTPBasicCredentials | None = Depends(basic_scheme),
):
    """POST /oauth/token. Credentials may arrive as HTTP Basic or in the form body."""
    settings: Settings = request.app.state.settings
    if grant_type != "client_credentials":
        return _oauth_error(400, "unsupported_grant_type")
    if basic is not None:
        client_id, client_secret = basic.username, basic.password
    if not client_id or not client_secret:
        return _oauth_error(401, "invalid_client", {"WWW-Authenticate": "Basic"})

    client = settings.clients.get(client_id)
    # Compare against a dummy value when the client is unknown so the response
    # takes the same time either way, then compare in constant time.
    expected = client.secret if client else "x" * 43
    secret_ok = hmac.compare_digest(client_secret.encode(), expected.encode())
    if client is None or not secret_ok:
        request.app.state.store.audit("token_denied", actor=client_id[:64])
        return _oauth_error(401, "invalid_client", {"WWW-Authenticate": "Basic"})

    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": client.client_id,
            "scope": " ".join(client.scopes),
            "iat": now,
            "exp": now + settings.token_ttl_seconds,
        },
        settings.jwt_secret,
        algorithm=ALGORITHM,
    )
    request.app.state.store.audit("token_issued", actor=client.client_id)
    return JSONResponse(
        {
            "access_token": token,
            "token_type": BEARER,
            "expires_in": settings.token_ttl_seconds,
            "scope": " ".join(client.scopes),
        },
        headers={"Cache-Control": "no-store"},
    )


def require(scope: str):
    """Dependency: the request must carry a valid token that includes `scope`."""

    def dependency(
        request: Request, authorization: str | None = Depends(oauth2_scheme)
    ) -> Principal:
        settings: Settings = request.app.state.settings
        unauthorized = HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Missing or invalid access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise unauthorized
        try:
            claims = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[ALGORITHM],  # never trust the algorithm named in the token
                issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "scope"]},
            )
        except jwt.PyJWTError:
            raise unauthorized from None

        principal = Principal(claims["sub"], frozenset(str(claims["scope"]).split()))
        if scope not in principal.scopes:
            request.app.state.store.audit(
                "access_denied", actor=principal.client_id, detail={"needed": scope}
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Token lacks scope {scope}")
        return principal

    return dependency
