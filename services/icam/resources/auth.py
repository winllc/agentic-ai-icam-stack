"""Resource-server side of the delegation model.

Every request must arrive over mTLS with a SPIFFE X.509-SVID (enforced by the TLS
listener) and carry a delegated access token that:
  * is signed by the authorization server and addressed to this resource (aud),
  * is bound to the presented client certificate (cnf.x5t#S256, RFC 8705),
  * names the same workload as actor (act.sub == SPIFFE ID in the cert),
  * carries the scope the operation needs.
"""

import functools
import os
import time
from collections import deque

from flask import g, jsonify, request

from icam.common.spiffe_identity import peer_cert_from_environ, spiffe_ids, x5t_s256
from icam.common.tokens import JwtValidator, TokenError, bearer_token, scopes_of

RESOURCE_URI = os.environ["RESOURCE_URI"]
# Both default on; relax only when pointing at an AS that cannot emit them (see pingfederate/README.md).
REQUIRE_CNF = os.environ.get("REQUIRE_CNF", "true").lower() == "true"
REQUIRE_ACT = os.environ.get("REQUIRE_ACT", "true").lower() == "true"
validator = JwtValidator(os.environ["PF_JWKS_URL"], os.environ["PF_ISSUER"])
audit: deque = deque(maxlen=200)


def authorize(required_scope: str) -> dict:
    """Validate the caller; returns token claims or raises TokenError."""
    cert = peer_cert_from_environ(request.environ)
    if cert is None:
        raise TokenError(401, "invalid_request", "client certificate required")
    claims = validator.validate(bearer_token(request), audience=RESOURCE_URI)
    bound = claims.get("cnf", {}).get("x5t#S256")
    if REQUIRE_CNF and (not bound or bound != x5t_s256(cert)):
        raise TokenError(401, "invalid_token", "token is not bound to the presented client certificate")
    actor = claims.get("act", {}).get("sub")
    if REQUIRE_ACT and actor not in spiffe_ids(cert):
        raise TokenError(401, "invalid_token", "token actor does not match the mTLS peer identity")
    if required_scope not in scopes_of(claims):
        raise TokenError(403, "insufficient_scope", f"requires scope {required_scope}", scope=required_scope)
    return claims


def log_decision(required_scope: str, claims: dict | None, outcome: str):
    audit.appendleft({
        "ts": time.strftime("%H:%M:%S"), "path": request.path, "scope": required_scope,
        "user": (claims or {}).get("sub"), "actor": (claims or {}).get("act", {}).get("sub"),
        "outcome": outcome,
    })


def requires(scope: str, realm: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            try:
                g.claims = authorize(scope)
            except TokenError as err:
                log_decision(scope, None, f"{err.status} {err.error}")
                return err.response(realm)
            log_decision(scope, g.claims, "allowed")
            return fn(*a, **kw)
        return wrapper
    return deco


def principal() -> dict:
    actor = g.claims.get("act", {}).get("sub") or (spiffe_ids(peer_cert_from_environ(request.environ)) or [None])[0]
    return {"user": g.claims["sub"], "actor": actor, "scope": g.claims["scope"]}


def audit_view():
    return jsonify(list(audit))
