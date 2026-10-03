"""Agentic AI Service - the user-facing app.

Signs users in with OIDC Authorization Code + PKCE against PingFederate, then
hands tasks plus the user's access token to an Agent Runtime and renders the
full 1-10 trace of what happened.
"""

import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import urlencode

import requests
from flask import Flask, abort, redirect, render_template, request, session, url_for

from icam.common import logs
from icam.common.tokens import JwtValidator, TokenError, unverified_claims

log = logs.setup("agentic-ai-service")

ISSUER = os.environ["PF_ISSUER"].rstrip("/")                      # browser-facing
INTERNAL = os.environ.get("PF_INTERNAL_BASE", ISSUER).rstrip("/")  # container-facing
PF_TLS = os.environ.get("PF_TLS_CA") or True                      # CA for PingFederate's HTTPS
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "agentic-ai-portal")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "portal-secret")
REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8080/callback")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:8080")
SCOPES = os.environ.get("OIDC_SCOPES",
                        "openid profile email systems:read systems:analyze metrics:read tickets:read tickets:write")
AGENTS = {
    "analysis-agent": {"url": os.environ.get("ANALYSIS_AGENT_URL", "http://analysis-agent:8090"),
                       "label": "Analysis agent - diagnostics & telemetry, read-only"},
    "remediation-agent": {"url": os.environ.get("REMEDIATION_AGENT_URL", "http://remediation-agent:8090"),
                          "label": "Remediation agent - may open tickets, no diagnostics"},
}
SYSTEMS = {"payments-api": "Payments API", "erp-db": "ERP Database", "hr-portal": "HR Portal"}

app = Flask(__name__)
app.secret_key = os.environ.get("PORTAL_SESSION_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_NAME="ai_portal", SESSION_COOKIE_SAMESITE="Lax")
store: dict[str, dict] = {}  # server-side session data (tokens never go to the browser cookie)
_disco: dict = {}


def backchannel(url: str) -> str:
    return INTERNAL + url[len(ISSUER):] if url.startswith(ISSUER) else url


def discovery() -> dict:
    if not _disco:
        _disco.update(requests.get(f"{INTERNAL}/.well-known/openid-configuration", timeout=10, verify=PF_TLS).json())
    return _disco


def current() -> dict | None:
    data = store.get(session.get("sid", ""))
    if data and data["expires_at"] < time.time():
        store.pop(session["sid"], None)
        return None
    return data


@app.template_filter("pretty")
def pretty(obj):
    return json.dumps(obj, indent=2, default=str)


@app.get("/")
def index():
    return render_template("index.html", user=current(), agents=AGENTS, systems=SYSTEMS, issuer=ISSUER)


# ------------------------------------------------------------------ 1-3: OIDC + PKCE

@app.get("/login")
def login():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    session["oidc"] = {"state": secrets.token_urlsafe(16), "nonce": secrets.token_urlsafe(16),
                       "verifier": verifier, "challenge": challenge, "t": time.time()}
    params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "scope": SCOPES,
              "state": session["oidc"]["state"], "nonce": session["oidc"]["nonce"],
              "code_challenge": challenge, "code_challenge_method": "S256"}
    return redirect(discovery()["authorization_endpoint"] + "?" + urlencode(params))


@app.get("/callback")
def callback():
    pending = session.pop("oidc", None)
    if not pending or request.args.get("state") != pending["state"]:
        abort(400, "state mismatch - start the sign-in again")
    if "error" in request.args:
        abort(400, f"{request.args['error']}: {request.args.get('error_description', '')}")

    disco = discovery()
    resp = requests.post(backchannel(disco["token_endpoint"]), timeout=10, verify=PF_TLS,
                         auth=(CLIENT_ID, CLIENT_SECRET), data={
        "grant_type": "authorization_code", "code": request.args["code"],
        "redirect_uri": REDIRECT_URI, "code_verifier": pending["verifier"]})
    if not resp.ok:
        abort(502, f"token endpoint error: {resp.text}")
    tokens = resp.json()

    validator = JwtValidator(backchannel(disco["jwks_uri"]), disco["issuer"])
    try:
        id_claims = validator.validate(tokens["id_token"], audience=CLIENT_ID)
    except TokenError as err:
        abort(401, f"invalid id_token: {err.description}")
    if id_claims.get("nonce") != pending["nonce"]:
        abort(401, "nonce mismatch")

    at_claims = unverified_claims(tokens["access_token"])
    sid = secrets.token_urlsafe(24)
    store[sid] = {
        "id_claims": id_claims, "id_token": tokens["id_token"],
        "access_token": tokens["access_token"], "at_claims": at_claims,
        "expires_at": time.time() + tokens.get("expires_in", 900), "results": [],
        "login_steps": [
            {"n": 1, "title": "User accessed the Agentic AI Service", "actor": "User → Agentic AI Service",
             "status": "ok", "detail": {"url": PUBLIC_URL}},
            {"n": 2, "title": "OIDC Authorization Code + PKCE", "actor": "Agentic AI Service ↔ PingFederate",
             "status": "ok", "detail": {
                 "authorization_endpoint": disco["authorization_endpoint"], "client_id": CLIENT_ID,
                 "code_challenge_method": "S256", "code_challenge": pending["challenge"],
                 "code_verifier": pending["verifier"][:12] + "… (kept server-side, sent only to the token endpoint)",
                 "requested_scope": SCOPES}},
            {"n": 3, "title": "User authenticated - ID token + access token issued", "actor": "PingFederate → Agentic AI Service",
             "status": "ok", "detail": {"user": id_claims["sub"], "granted_scope": tokens.get("scope"),
                                        "access_token_audience": at_claims.get("aud"),
                                        "expires_in": tokens.get("expires_in")}},
        ],
    }
    session["sid"] = sid
    log.info("user %s signed in, scope=%s", id_claims["sub"], tokens.get("scope"))
    return redirect(url_for("index"))


@app.get("/logout")
def logout():
    user = store.pop(session.pop("sid", ""), None)
    end = discovery().get("end_session_endpoint")
    if not end:
        return redirect(url_for("index"))
    params = {"post_logout_redirect_uri": PUBLIC_URL + "/"}  # OIDC RP-initiated logout
    if user:
        params["id_token_hint"] = user["id_token"]
    return redirect(f"{end}?{urlencode(params)}")


# ------------------------------------------------------------------ 4-10: delegate to an agent

@app.post("/task")
def task():
    user = current()
    if not user:
        return redirect(url_for("login"))
    agent = request.form.get("agent", "analysis-agent")
    system = request.form.get("system", "payments-api")
    if agent not in AGENTS or system not in SYSTEMS:
        abort(400)
    text = request.form.get("task") or f"Analyze system {system}"
    try:
        resp = requests.post(f"{AGENTS[agent]['url']}/tasks", json={"task": text, "system": system},
                             headers={"Authorization": f"Bearer {user['access_token']}"}, timeout=200)
        result = resp.json() if resp.ok else {"error": f"agent runtime returned {resp.status_code}: {resp.text}",
                                              "steps": []}
    except requests.RequestException as exc:
        result = {"error": f"agent runtime unreachable: {exc}", "steps": []}
    result.update(agent=agent, task=text, system=system, at=time.strftime("%H:%M:%S"))
    user["results"].insert(0, result)
    if request.accept_mimetypes.best == "application/json":
        return result
    return render_template("result.html", user=user, r=result)


@app.get("/healthz")
def healthz():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
