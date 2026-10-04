"""Access-token validation shared by the agent runtime and the resource servers."""

import os
import ssl
import time

import jwt
from flask import jsonify


class TokenError(Exception):
    def __init__(self, status: int, error: str, description: str, scope: str | None = None):
        super().__init__(description)
        self.status, self.error, self.description, self.scope = status, error, description, scope

    def response(self, realm: str):
        hdr = f'Bearer realm="{realm}", error="{self.error}", error_description="{self.description}"'
        if self.scope:
            hdr += f', scope="{self.scope}"'
        resp = jsonify(error=self.error, error_description=self.description)
        resp.status_code = self.status
        resp.headers["WWW-Authenticate"] = hdr
        return resp


class JwtValidator:
    def __init__(self, jwks_url: str, issuer: str, tls_ca: str | None = None):
        self.issuer = issuer
        self.jwks_url = jwks_url
        # CA for an HTTPS JWKS endpoint (a real PingFederate, or a SPIFFE bundle file).
        self.tls_ca = tls_ca or os.environ.get("PF_TLS_CA")
        self._jwks = None

    @property
    def jwks(self) -> jwt.PyJWKClient:
        if self._jwks is None:   # lazy: the CA file may only exist once the service is up
            ctx = ssl.create_default_context(cafile=self.tls_ca) if self.tls_ca else None
            self._jwks = jwt.PyJWKClient(self.jwks_url, cache_keys=True, lifespan=300, ssl_context=ctx)
        return self._jwks

    def validate(self, token: str, audience: str) -> dict:
        try:
            key = self.jwks.get_signing_key_from_jwt(token)
            return jwt.decode(
                token, key.key, algorithms=["RS256", "ES256", "PS256"],
                audience=audience, issuer=self.issuer, leeway=30,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise TokenError(401, "invalid_token", str(exc)) from exc


def bearer_token(request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise TokenError(401, "invalid_request", "missing bearer token")
    return auth.split(" ", 1)[1].strip()


def scopes_of(claims: dict) -> set[str]:
    scope = claims.get("scope", "")
    return set(scope.split()) if isinstance(scope, str) else set(scope)


def unverified_claims(token: str) -> dict:
    """For display only - never for authorization decisions."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


def ttl(claims: dict) -> int:
    return int(claims.get("exp", 0) - time.time())
