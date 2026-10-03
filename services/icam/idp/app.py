"""PingFederate-compatible demo authorization server.

Implements the subset of PingFederate's OAuth/OIDC surface the demo needs, on
PingFederate's endpoint paths, so clients are written against discovery and work
unchanged against a real PingFederate (see pingfederate/README.md):

  /.well-known/openid-configuration   discovery (+ RFC 8705 mtls_endpoint_aliases)
  /pf/JWKS                            signing keys
  /as/authorization.oauth2            authorization code + PKCE (S256 required)
  /as/token.oauth2                    authorization_code, token-exchange (RFC 8693)
  /idp/userinfo.openid                userinfo
  /idp/startSLO.ping                  logout

Listeners:
  :9031 HTTP   browser + confidential-client back channel
  :9443 HTTPS  mTLS alias of the token endpoint; server cert and client-cert trust
               both come from SPIRE (this container is itself a SPIFFE workload)
"""

import base64
import hashlib
import html
import os
import secrets
import threading
import time
import uuid
from collections import deque
from urllib.parse import urlencode

import jwt
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, make_response, redirect, render_template_string, request
from werkzeug.serving import make_server

from icam.common import logs
from icam.common.spiffe_identity import WorkloadIdentity, peer_cert_from_environ, spiffe_ids, x5t_s256
from icam.common.tokens import scopes_of

log = logs.setup("pingfederate-sim")

ISSUER = os.environ.get("PF_ISSUER", "http://localhost:9031").rstrip("/")
MTLS_BASE = os.environ.get("PF_MTLS_BASE", "https://pingfederate:9443").rstrip("/")
POLICY = yaml.safe_load(open(os.environ.get("PF_POLICY", "/config/idp-policy.yaml")))
EXPLAIN = os.environ.get("DEMO_EXPLAIN", "true").lower() == "true"

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TT_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "demo-" + uuid.uuid4().hex[:8]

codes: dict[str, dict] = {}
sessions: dict[str, str] = {}
audit: deque = deque(maxlen=200)

app = Flask(__name__)


# ---------------------------------------------------------------- helpers

def record(event: str, **details):
    entry = {"ts": time.strftime("%H:%M:%S"), "event": event, **details}
    audit.appendleft(entry)
    log.info("%s %s", event, details)


def sign(claims: dict) -> str:
    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256", headers={"kid": KID, "typ": "JWT"})


def verify_own(token: str) -> dict:
    return jwt.decode(token, SIGNING_KEY.public_key(), algorithms=["RS256"], issuer=ISSUER,
                      options={"verify_aud": False, "require": ["exp", "sub"]})


def oauth_error(error: str, description: str, status: int = 400):
    record("token_error", error=error, description=description)
    return make_response(jsonify(error=error, error_description=description), status)


def client_from_basic_or_post():
    auth = request.authorization
    if auth and auth.type == "basic":
        return auth.username, auth.password
    return request.form.get("client_id"), request.form.get("client_secret")


def ordered(scopes) -> str:
    known = list(POLICY["scopes"])
    return " ".join(sorted(scopes, key=lambda s: known.index(s) if s in known else 99))


def jwk() -> dict:
    nums = SIGNING_KEY.public_key().public_numbers()
    b64 = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": b64(nums.n), "e": b64(nums.e)}


# ---------------------------------------------------------------- discovery

@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/as/authorization.oauth2",
        token_endpoint=f"{ISSUER}/as/token.oauth2",
        userinfo_endpoint=f"{ISSUER}/idp/userinfo.openid",
        jwks_uri=f"{ISSUER}/pf/JWKS",
        end_session_endpoint=f"{ISSUER}/idp/startSLO.ping",
        scopes_supported=list(POLICY["scopes"]),
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", TOKEN_EXCHANGE],
        code_challenge_methods_supported=["S256"],
        token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "tls_client_auth"],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=["RS256"],
        tls_client_certificate_bound_access_tokens=True,
        mtls_endpoint_aliases={"token_endpoint": f"{MTLS_BASE}/as/token.oauth2"},
    )


@app.get("/pf/JWKS")
def jwks():
    return jsonify(keys=[jwk()])


# ---------------------------------------------------------------- authorization code + PKCE

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Sign On</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;background:#f1f3f6;margin:0;display:grid;place-items:center;min-height:100vh}
 .card{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 12px #0002;width:min(360px,90vw)}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#667;font-size:13px;margin-bottom:20px}
 label{display:block;font-size:13px;margin:12px 0 4px} input{width:100%;padding:9px;box-sizing:border-box;border:1px solid #ccd;border-radius:4px}
 button{margin-top:20px;width:100%;padding:10px;border:0;border-radius:4px;background:#b3282d;color:#fff;font-size:15px;cursor:pointer}
 .err{color:#b3282d;font-size:13px;margin-top:8px} .hint{font-size:12px;color:#667;margin-top:18px;border-top:1px solid #eee;padding-top:12px}
 code{background:#f4f4f6;padding:1px 4px;border-radius:3px}
</style></head><body><form class="card" method="post">
<h1>Sign On</h1><div class="sub">PingFederate (demo simulator) &middot; client <code>{{ client_id }}</code></div>
{% for k, v in params.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
<label>Username</label><input name="pf.username" autofocus>
<label>Password</label><input name="pf.pass" type="password">
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<button type="submit">Sign On</button>
<div class="hint">Demo users: <code>alice / alice</code> (SRE lead, broad entitlements) &middot;
<code>bob / bob</code> (analyst, read-only)<br>PKCE: <code>{{ params.code_challenge_method }}</code> challenge
<code>{{ params.code_challenge[:16] }}…</code></div>
</form></body></html>"""

AUTHZ_PARAMS = ("response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
                "code_challenge", "code_challenge_method")


def authz_error_page(msg: str):
    return make_response(f"<h1>Authorization error</h1><p>{html.escape(msg)}</p>", 400)


@app.route("/as/authorization.oauth2", methods=["GET", "POST"])
def authorize():
    src = request.values
    params = {k: src.get(k, "") for k in AUTHZ_PARAMS}
    client = POLICY["clients"].get(params["client_id"])
    if not client or "authorization_code" not in client.get("grant_types", []):
        return authz_error_page("unknown client_id")
    if params["redirect_uri"] not in client["redirect_uris"]:
        return authz_error_page("redirect_uri is not registered for this client")
    if params["response_type"] != "code":
        return authz_error_page("only response_type=code is supported")
    if client.get("require_pkce") and (not params["code_challenge"] or params["code_challenge_method"] != "S256"):
        return authz_error_page("PKCE with code_challenge_method=S256 is required for this client")

    user = sessions.get(request.cookies.get("PF", ""))
    error = None
    if request.method == "POST":
        name, pw = src.get("pf.username", ""), src.get("pf.pass", "")
        u = POLICY["users"].get(name)
        if u and secrets.compare_digest(u["password"], pw):
            user = name
            record("authn_success", user=name, client_id=params["client_id"], method="HTML form")
        else:
            error = "Invalid username or password."
            record("authn_failure", user=name)

    if not user:
        return render_template_string(LOGIN_PAGE, params=params, client_id=params["client_id"], error=error)

    code = secrets.token_urlsafe(32)
    codes[code] = {**params, "user": user, "exp": time.time() + 60}
    record("authz_code_issued", user=user, client_id=params["client_id"], pkce="S256")
    resp = redirect(params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"]}))
    if request.method == "POST":
        sid = secrets.token_urlsafe(24)
        sessions[sid] = user
        resp.set_cookie("PF", sid, httponly=True, samesite="Lax")
    return resp


@app.get("/idp/startSLO.ping")
def logout():
    sessions.pop(request.cookies.get("PF", ""), None)
    target = request.args.get("TargetResource") or request.args.get("post_logout_redirect_uri") or "/"
    allowed = [u.rsplit("/", 1)[0] for c in POLICY["clients"].values() for u in c.get("redirect_uris", [])]
    if not any(target == a or target.startswith(a + "/") for a in allowed):
        target = "/"
    resp = redirect(target)
    resp.delete_cookie("PF")
    return resp


# ---------------------------------------------------------------- token endpoint

@app.post("/as/token.oauth2")
def token():
    grant = request.form.get("grant_type")
    if grant == "authorization_code":
        return grant_authorization_code()
    if grant == TOKEN_EXCHANGE:
        return grant_token_exchange()
    return oauth_error("unsupported_grant_type", f"grant_type {grant!r} is not supported")


def grant_authorization_code():
    client_id, secret = client_from_basic_or_post()
    client = POLICY["clients"].get(client_id or "")
    if not client or not secret or not secrets.compare_digest(client.get("client_secret", ""), secret):
        return oauth_error("invalid_client", "client authentication failed", 401)
    data = codes.pop(request.form.get("code", ""), None)
    if not data or data["exp"] < time.time() or data["client_id"] != client_id:
        return oauth_error("invalid_grant", "authorization code is invalid or expired")
    if request.form.get("redirect_uri") != data["redirect_uri"]:
        return oauth_error("invalid_grant", "redirect_uri mismatch")
    verifier = request.form.get("code_verifier", "")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not verifier or not secrets.compare_digest(challenge, data["code_challenge"]):
        return oauth_error("invalid_grant", "PKCE verification failed")

    user = POLICY["users"][data["user"]]
    requested = set(data["scope"].split())
    oidc = requested & {"openid", "profile", "email"}
    granted = (requested & set(client["allowed_scopes"]) & set(user["entitlements"])) | oidc
    now = int(time.time())
    ttl = client.get("access_token_ttl", 900)
    access = sign({
        "iss": ISSUER, "sub": data["user"], "aud": client["access_token_audience"],
        "client_id": client_id, "scope": ordered(granted), "iat": now, "exp": now + ttl,
        "jti": uuid.uuid4().hex, "name": user["name"], "groups": user["groups"],
    })
    id_token = sign({
        "iss": ISSUER, "sub": data["user"], "aud": client_id, "iat": now, "exp": now + ttl,
        "nonce": data["nonce"], "name": user["name"], "email": user["email"], "groups": user["groups"],
        "auth_time": now, "amr": ["pwd"],
    })
    record("token_issued", grant="authorization_code+PKCE", user=data["user"], client_id=client_id,
           scope=ordered(granted))
    return jsonify(access_token=access, id_token=id_token, token_type="Bearer",
                   expires_in=ttl, scope=ordered(granted))


def grant_token_exchange():
    # --- 1. Client authentication: RFC 8705 tls_client_auth with a SPIFFE X.509-SVID.
    cert = peer_cert_from_environ(request.environ)
    if cert is None:
        return oauth_error("invalid_client",
                           "token exchange requires mTLS - use the mtls_endpoint_aliases token endpoint", 401)
    presented_ids = spiffe_ids(cert)
    client_id = request.form.get("client_id")
    client = POLICY["clients"].get(client_id or "")
    if not client or client.get("token_endpoint_auth_method") != "tls_client_auth":
        return oauth_error("invalid_client", f"unknown mTLS client {client_id!r}", 401)
    if client["tls_client_auth_san_uri"] not in presented_ids:
        return oauth_error("invalid_client",
                           f"certificate SAN URI {presented_ids} does not match registered "
                           f"{client['tls_client_auth_san_uri']}", 401)
    if TOKEN_EXCHANGE not in client["grant_types"]:
        return oauth_error("unauthorized_client", "client may not use token exchange")

    # --- 2. Subject token: the end user's access token, issued by us to an allowed audience.
    if request.form.get("subject_token_type") != TT_ACCESS:
        return oauth_error("invalid_request", "subject_token_type must be access_token")
    try:
        subject = verify_own(request.form.get("subject_token", ""))
    except jwt.PyJWTError as exc:
        return oauth_error("invalid_grant", f"subject_token invalid: {exc}")
    if subject.get("aud") not in client["subject_token_audiences"]:
        return oauth_error("invalid_grant", "subject_token audience not accepted for this agent")
    if "act" in subject:
        return oauth_error("invalid_grant", "re-delegation of a delegated token is not allowed")

    # --- 3. Resources (RFC 8707 resource / RFC 8693 audience).
    resources = request.form.getlist("resource") + request.form.getlist("audience")
    if not resources:
        return oauth_error("invalid_target", "resource or audience is required")
    bad = [r for r in resources if r not in client["allowed_resources"]]
    if bad:
        return oauth_error("invalid_target", f"agent may not obtain tokens for {bad}")

    # --- 4. Scope: User ∩ Agent ∩ Requested.
    user_scopes = scopes_of(subject) - {"openid", "profile", "email"}
    if "entitlements" in subject:
        user_scopes &= set(subject["entitlements"].split())
    agent_scopes = set(client["allowed_scopes"])
    requested = set(request.form.get("scope", "").split()) or agent_scopes
    granted = user_scopes & agent_scopes & requested
    evaluation = {
        "user_scopes": ordered(user_scopes), "agent_scopes": ordered(agent_scopes),
        "requested_scopes": ordered(requested), "granted_scopes": ordered(granted),
        "denied": {s: ("not entitled (user)" if s not in user_scopes else "not allowed for agent")
                   for s in sorted(requested - granted)},
    }
    # Like PingFederate: never silently narrow - a request outside User ∩ Agent is rejected,
    # so the agent must ask for exactly what it may have.
    if requested - granted or not granted:
        record("token_exchange_denied", user=subject["sub"], agent=client_id, **evaluation)
        return oauth_error("invalid_scope", "requested scope must be within user ∩ agent: "
                           + ", ".join(f"{s} ({why})" for s, why in evaluation["denied"].items()) or "empty")

    now = int(time.time())
    ttl = client.get("access_token_ttl", 300)
    spiffe_id = client["tls_client_auth_san_uri"]
    delegated = sign({
        "iss": ISSUER, "sub": subject["sub"], "aud": resources if len(resources) > 1 else resources[0],
        "client_id": client_id, "scope": ordered(granted), "iat": now, "exp": min(now + ttl, subject["exp"]),
        "jti": uuid.uuid4().hex,
        "act": {"sub": spiffe_id, "client_id": client_id},          # RFC 8693 actor = the agent workload
        "cnf": {"x5t#S256": x5t_s256(cert)},                          # RFC 8705 certificate-bound
        "delegated_from": {"client_id": subject.get("client_id"), "jti": subject.get("jti")},
    })
    record("token_exchange", user=subject["sub"], agent=client_id, actor=spiffe_id,
           granted=ordered(granted), resources=resources)
    body = {"access_token": delegated, "issued_token_type": TT_ACCESS, "token_type": "Bearer",
            "expires_in": ttl, "scope": ordered(granted)}
    if EXPLAIN:
        body["demo_policy_evaluation"] = evaluation
    return jsonify(body)


# ---------------------------------------------------------------- misc

@app.get("/idp/userinfo.openid")
def userinfo():
    auth = request.headers.get("Authorization", "")
    try:
        claims = verify_own(auth.split(" ", 1)[1])
    except Exception:
        return oauth_error("invalid_token", "bad access token", 401)
    u = POLICY["users"][claims["sub"]]
    return jsonify(sub=claims["sub"], name=u["name"], email=u["email"], groups=u["groups"])


@app.get("/demo/audit")
def audit_log():
    return jsonify(list(audit))


@app.get("/healthz")
def healthz():
    return "ok"


def main():
    identity = WorkloadIdentity(workdir="/run/svid")
    identity.wait_for_svid()
    identity.start_rotation()
    mtls_ctx = identity.server_context(require_client_cert=False)
    servers = [
        make_server("0.0.0.0", 9031, app, threaded=True),
        make_server("0.0.0.0", 9443, app, threaded=True, ssl_context=mtls_ctx),
    ]
    log.info("issuer %s | mTLS token endpoint %s/as/token.oauth2 | SVID %s",
             ISSUER, MTLS_BASE, identity.info["spiffe_id"])
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
