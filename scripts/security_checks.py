#!/usr/bin/env python3
"""Negative tests against the running stack - each one is an attack the design must stop.

    pip install requests && python3 scripts/security_checks.py
"""
import base64
import hashlib
import json
import re
import secrets
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urlparse

import requests

PF = "http://localhost:9031"
PORTAL = "http://localhost:8080"
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"

http = requests.Session()
http.trust_env = False


def user_access_token(user: str) -> str:
    """Run the portal client's OIDC + PKCE flow directly and capture the code."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": "agentic-ai-portal", "redirect_uri": "http://localhost:8080/callback",
         "scope": "openid systems:read systems:analyze metrics:read tickets:read tickets:write", "state": "s",
         "nonce": "n", "code_challenge": challenge, "code_challenge_method": "S256"}
    form = http.post(f"{PF}/as/authorization.oauth2", data={**q, "pf.username": user, "pf.pass": user},
                     allow_redirects=False)
    code = parse_qs(urlparse(form.headers["Location"]).query)["code"][0]
    tok = http.post(f"{PF}/as/token.oauth2", auth=("agentic-ai-portal", "portal-secret"), data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": q["redirect_uri"],
        "code_verifier": verifier}).json()
    return tok["access_token"]


def delegated_token_via_portal(user: str, agent: str) -> str:
    s = requests.Session()
    s.trust_env = False
    r = s.get(f"{PORTAL}/login")
    hidden = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', r.text))
    s.post(r.url.split("?")[0], data={**hidden, "pf.username": user, "pf.pass": user})
    res = s.post(f"{PORTAL}/task", headers={"Accept": "application/json"},
                 data={"agent": agent, "system": "payments-api"}).json()
    return res["delegated_token"]["jwt"]


def in_container(service: str, code: str, **env) -> dict:
    """Run python inside a stack container (so it gets *that* workload's SVID)."""
    prelude = ("import json, os, requests\n"
               "from icam.common.spiffe_identity import WorkloadIdentity\n"
               "args = json.loads(os.environ['ARGS'])\n")
    cmd = ["docker", "compose", "exec", "-T", "-e", f"ARGS={json.dumps(env)}", service, "python", "-c", prelude + code]
    out = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"error": out.stderr.strip()[-400:]}


CALL_WITH_OWN_SVID = """
me = WorkloadIdentity(); me.fetch()
r = requests.request(args.get('method', 'GET'), args['url'], data=args.get('data'), cert=me.client_cert,
                     verify=str(me.bundle_path), headers=args.get('headers', {}), timeout=10)
print(json.dumps({'status': r.status_code, 'body': r.text[:300], 'www': r.headers.get('WWW-Authenticate'),
                  'me': me.info['spiffe_id']}))
"""

NO_CLIENT_CERT = """
import ssl, socket
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # attacker does not care who the server is
try:
    with socket.create_connection(('systems-api', 8443), 5) as raw, ctx.wrap_socket(raw) as tls:
        tls.sendall(b'GET /systems HTTP/1.1\\r\\nHost: systems-api\\r\\n\\r\\n')
        data = tls.recv(200)
        print(json.dumps({'status': 'connected', 'body': data.decode(errors='replace')}))
except Exception as exc:
    print(json.dumps({'status': 'rejected', 'error': repr(exc)}))
"""


def main() -> int:
    alice = user_access_token("alice")
    stolen = delegated_token_via_portal("alice", "analysis-agent")
    te = {"grant_type": TE, "subject_token": alice, "subject_token_type": AT, "scope": "systems:read",
          "resource": "https://systems-api:8443"}
    checks = []

    # 1. Token exchange without a workload certificate (plain HTTPS/HTTP, no mTLS).
    r = http.post(f"{PF}/as/token.oauth2", data={**te, "client_id": "analysis-agent"})
    checks.append(("Token exchange without an SVID (no mTLS)", r.status_code == 401, f"{r.status_code} {r.text}"))

    # 2. remediation-agent's SVID tries to act as analysis-agent.
    out = in_container("remediation-agent", CALL_WITH_OWN_SVID, method="POST",
                       url="https://pingfederate:9443/as/token.oauth2", data={**te, "client_id": "analysis-agent"})
    checks.append(("Agent impersonation (SVID ≠ registered SAN URI)", out.get("status") == 401, out))

    # 3. Token stolen from analysis-agent replayed by another SPIFFE workload.
    out = in_container("remediation-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                       headers={"Authorization": f"Bearer {stolen}"})
    checks.append(("Replay of another agent's delegated token (cnf binding)", out.get("status") == 401, out))

    # 4. Agent skips delegation and uses the user's own access token at the resource.
    out = in_container("analysis-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                       headers={"Authorization": f"Bearer {alice}"})
    checks.append(("User token used directly at resource (wrong audience)", out.get("status") == 401, out))

    # 5. Non-SPIFFE client (the portal container has no SVID) talks to a resource.
    out = in_container("agentic-ai-service", NO_CLIENT_CERT)
    checks.append(("Resource access without a client certificate", out.get("status") == "rejected", out))

    # 6. Re-delegation: exchange a delegated token again to widen/extend it.
    out = in_container("analysis-agent", CALL_WITH_OWN_SVID, method="POST",
                       url="https://pingfederate:9443/as/token.oauth2",
                       data={**te, "subject_token": stolen, "client_id": "analysis-agent"})
    checks.append(("Re-delegation of a delegated token", out.get("status") == 400, out))

    # 7. Positive control: the legitimate agent with the legitimate token works.
    legit = in_container("analysis-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                         headers={"Authorization": f"Bearer {stolen}"})
    checks.append(("Control: token used by the agent it was bound to", legit.get("status") == 200, legit))

    failed = 0
    for name, ok, detail in checks:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        brief = detail if isinstance(detail, str) else (detail.get("www") or detail.get("body") or detail.get("error"))
        print(f"        {str(brief)[:160]}")
    print("\nall security checks passed" if not failed else f"\n{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
