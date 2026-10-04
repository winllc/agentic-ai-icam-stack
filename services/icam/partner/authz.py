"""Authorization server of the EXTERNAL partner (trust domain partner.example).

Redeems JWT authorization grants minted by demo.local's authorization server (RFC 7523
jwt-bearer, identity chaining across domains) and issues the partner's own access tokens
for partner-api. Clients authenticate with mTLS using SPIFFE SVIDs from the federated
demo.local trust domain.

Checks on every grant:
  * signature + issuer: a trusted issuer's JWKS        * aud = this AS
  * short-lived (exp - iat <= max_grant_lifetime)      * single use (jti)
  * holder of key: grant cnf.x5t#S256 = the mTLS client certificate
  * actor: grant act.sub = the client's SPIFFE ID, from the issuer's trust domain
  * scope = requested ∩ grant scope ∩ issuer ceiling ∩ this client's ceiling (narrowed, not rejected:
    the partner applies its own policy to whatever the other domain vouched for)
"""

import os
import threading
import time
import uuid

import jwt
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from icam.common import logs
from icam.common.federation import JWT_BEARER
from icam.common.spiffe_identity import WorkloadIdentity, peer_cert_from_environ, spiffe_ids, x5t_s256
from icam.common.tokens import JwtValidator, TokenError

log = logs.setup("partner-as")
POLICY = yaml.safe_load(open(os.environ.get("PARTNER_POLICY", "/config/partner-policy.yaml")))
ISSUER = POLICY["issuer"]
# The other domain's assertion issuer differs per mode (simulator vs PingFederate).
ORIGIN = POLICY["trusted_issuers"]["demo.local"]
ORIGIN_ISSUER = os.environ["ORIGIN_ISSUER"]
origin_tokens = JwtValidator(os.environ["ORIGIN_JWKS_URL"], ORIGIN_ISSUER, tls_ca=os.environ.get("ORIGIN_TLS_CA"))

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "partner-" + uuid.uuid4().hex[:8]
used_jti: dict[str, float] = {}
lock = threading.Lock()
app = Flask(__name__)


def error(code: str, description: str, status: int = 400):
    log.info("rejected: %s %s", code, description)
    return jsonify(error=code, error_description=description), status


@app.get("/.well-known/oauth-authorization-server")
def metadata():
    return jsonify(issuer=ISSUER, token_endpoint=f"{ISSUER}/token", jwks_uri=f"{ISSUER}/jwks",
                   grant_types_supported=[JWT_BEARER], token_endpoint_auth_methods_supported=["tls_client_auth"],
                   tls_client_certificate_bound_access_tokens=True, scopes_supported=ORIGIN["scopes"])


@app.get("/jwks")
def jwks():
    return jsonify(keys=[{**jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=True),
                          "kid": KID, "use": "sig", "alg": "RS256"}])


@app.post("/token")
def token():
    cert = peer_cert_from_environ(request.environ)
    if cert is None:
        return error("invalid_client", "mTLS with a SPIFFE SVID is required", 401)
    client_id = next(iter(spiffe_ids(cert)), None)
    client = POLICY["clients"].get(client_id)
    if not client:
        return error("invalid_client", f"{client_id} is not a registered federated client", 401)
    if request.form.get("grant_type") != JWT_BEARER:
        return error("unsupported_grant_type", "only jwt-bearer grants are accepted")

    try:
        grant = origin_tokens.validate(request.form.get("assertion", ""), audience=ISSUER)
    except TokenError as err:
        return error("invalid_grant", f"assertion rejected: {err.description}")
    if grant["exp"] - grant.get("iat", 0) > ORIGIN["max_grant_lifetime"]:
        return error("invalid_grant", "assertion lifetime too long")
    if grant.get("cnf", {}).get("x5t#S256") != x5t_s256(cert):
        return error("invalid_grant", "assertion is bound to a different client certificate")
    actor = grant.get("act", {}).get("sub", "")
    if actor != client_id or not actor.startswith(f"spiffe://{ORIGIN['trust_domain']}/"):
        return error("invalid_grant", "assertion actor does not match the authenticated client")
    # Consume the jti only for the rightful holder: otherwise anyone who saw the grant could
    # burn it (denial of service) by presenting it first.
    with lock:
        now = time.time()
        for j in [j for j, exp in used_jti.items() if exp < now]:
            del used_jti[j]
        if grant.get("jti") in used_jti or not grant.get("jti"):
            return error("invalid_grant", "assertion already used (jti replay)")
        used_jti[grant["jti"]] = grant["exp"]

    requested = set(request.form.get("scope", "").split()) or set(grant["scope"].split())
    granted = requested & set(grant["scope"].split()) & set(ORIGIN["scopes"]) & set(client["scopes"])
    if not granted:
        return error("invalid_scope", "nothing in the request is allowed by the partner's policy")
    resource = request.form.get("resource") or POLICY["resources"][0]
    if resource not in POLICY["resources"]:
        return error("invalid_target", f"unknown resource {resource}")

    now = int(time.time())
    access = jwt.encode({
        "iss": ISSUER, "sub": grant["sub"], "aud": resource, "scope": " ".join(sorted(granted)),
        "iat": now, "exp": now + POLICY["token_ttl"], "jti": uuid.uuid4().hex, "client_id": client_id,
        "act": {"sub": client_id},
        "cnf": {"x5t#S256": x5t_s256(cert)},
        # Provenance: which domain vouched for this subject, via which grant.
        "federated": {"iss": grant["iss"], "grant_jti": grant["jti"], "origin_client": grant.get("client_id")},
    }, KEY, algorithm="RS256", headers={"kid": KID})
    log.info("issued token sub=%s actor=%s scope=%s (requested %s)", grant["sub"], client_id,
             sorted(granted), sorted(requested))
    return jsonify(access_token=access, token_type="Bearer", expires_in=POLICY["token_ttl"],
                   scope=" ".join(sorted(granted)), issued_token_type="urn:ietf:params:oauth:token-type:access_token",
                   partner_policy={"requested": sorted(requested), "grant": grant["scope"].split(),
                                   "client_ceiling": client["scopes"], "granted": sorted(granted)})


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    identity = WorkloadIdentity(workdir="/run/svid")
    identity.wait_for_svid()
    identity.start_rotation()
    # Client certs are optional at the TLS layer (metadata/JWKS are public); /token requires one.
    ctx = identity.server_context(require_client_cert=False, trust_federated=True)
    log.info("partner AS %s as %s, trusting assertions from %s", ISSUER, identity.info["spiffe_id"], ORIGIN_ISSUER)
    make_server("0.0.0.0", 8443, app, threaded=True, ssl_context=ctx).serve_forever()
