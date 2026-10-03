#!/usr/bin/env python3
"""Negative tests against the running stack (simulator or real PingFederate) - each one
is an attack or policy violation the design must stop.

    pip install requests && python3 scripts/security_checks.py
"""
import base64
import hashlib
import json
import secrets
import subprocess
import sys
from urllib.parse import parse_qs, urlencode, urlparse

from stack import PORTAL, Stack

TE = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"
RESOURCES = ["https://systems-api:8443", "https://ops-mcp:8443/mcp"]
stack = Stack()


def user_access_token(user: str, scope: str) -> str:
    """Run the portal client's OIDC + PKCE flow directly and capture the code."""
    s = stack.session()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"response_type": "code", "client_id": "agentic-ai-portal", "redirect_uri": f"{PORTAL}/callback",
         "scope": scope, "state": "s", "nonce": "n", "code_challenge": challenge, "code_challenge_method": "S256"}
    page = s.get(f"{stack.pf}/as/authorization.oauth2?{urlencode(q)}")
    r = stack.follow_to(s, stack.submit_login(s, page, user, user), PORTAL)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    tok = s.post(f"{stack.pf}/as/token.oauth2", auth=("agentic-ai-portal", "portal-secret"), data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": q["redirect_uri"],
        "code_verifier": verifier}).json()
    return tok["access_token"]


def delegated_token_via_portal(user: str, agent: str) -> str:
    s = stack.portal_login(user)
    res = s.post(f"{PORTAL}/task", headers={"Accept": "application/json"},
                 data={"agent": agent, "system": "payments-api"}).json()
    return res["delegated_token"]["jwt"]


def in_container(service: str, code: str, **env) -> dict:
    """Run python inside a stack container (so it gets *that* workload's SVID)."""
    prelude = ("import json, os, requests\n"
               "from icam.common.spiffe_identity import WorkloadIdentity\n"
               "args = json.loads(os.environ['ARGS'])\n")
    cmd = ["docker", "exec", "-e", f"ARGS={json.dumps(env)}", f"agentic-icam-{service}-1",
           "python", "-c", prelude + code]
    out = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"error": out.stderr.strip()[-400:]}


CALL_WITH_OWN_SVID = """
me = WorkloadIdentity(); me.fetch()
r = requests.request(args.get('method', 'GET'), args['url'], data=args.get('data'), cert=me.client_cert,
                     verify=args.get('ca') or str(me.bundle_path), headers=args.get('headers', {}), timeout=10)
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


def exchange(service: str, **form) -> dict:
    return in_container(service, CALL_WITH_OWN_SVID, method="POST", url=stack.mtls_token_endpoint,
                        ca=stack.container_ca, data=form)


def main() -> int:
    print(f"identity provider: {stack.name}\n")
    alice = user_access_token("alice", "openid systems:read systems:analyze metrics:read tickets:read tickets:write")
    bob = user_access_token("bob", "openid systems:read systems:analyze metrics:read tickets:read tickets:write")
    stolen = delegated_token_via_portal("alice", "analysis-agent")
    te = {"grant_type": TE, "subject_token": alice, "subject_token_type": AT, "scope": "systems:read",
          "resource": RESOURCES}
    checks = []

    # 1. Token exchange without a workload certificate (plain token endpoint, no mTLS).
    r = stack.session().post(f"{stack.pf}/as/token.oauth2", data={**te, "client_id": "analysis-agent"})
    checks.append(("Token exchange without an SVID (no mTLS)", r.status_code == 401, f"{r.status_code} {r.text}"))

    # 2. remediation-agent's SVID tries to act as analysis-agent.
    out = exchange("remediation-agent", **{**te, "client_id": "analysis-agent"})
    checks.append(("Agent impersonation (SVID does not match the client)", out.get("status") == 401, out))

    # 3. Agent asks for more than its registered ceiling.
    out = exchange("analysis-agent", **{**te, "client_id": "analysis-agent", "scope": "systems:read tickets:write"})
    checks.append(("Agent requests scope beyond its ceiling", out.get("status") == 400, out))

    # 4. Agent asks for a scope the user is not entitled to (bob cannot run diagnostics).
    out = exchange("analysis-agent", **{**te, "subject_token": bob, "client_id": "analysis-agent",
                                        "scope": "systems:read systems:analyze"})
    checks.append(("Agent requests scope beyond the user's entitlements", out.get("status") in (400, 401), out))

    # 5. Token stolen from analysis-agent replayed by another SPIFFE workload.
    out = in_container("remediation-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                       headers={"Authorization": f"Bearer {stolen}"})
    checks.append(("Replay of another agent's delegated token (cnf binding)", out.get("status") == 401, out))

    # 6. Agent skips delegation and uses the user's own access token at the resource.
    out = in_container("analysis-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                       headers={"Authorization": f"Bearer {alice}"})
    checks.append(("User token used directly at resource (wrong audience)", out.get("status") == 401, out))

    # 7. Non-SPIFFE client (the portal container has no SVID) talks to a resource.
    out = in_container("agentic-ai-service", NO_CLIENT_CERT)
    checks.append(("Resource access without a client certificate", out.get("status") == "rejected", out))

    # 8. Re-delegation: exchange a delegated token again to widen/extend it.
    out = exchange("analysis-agent", **{**te, "subject_token": stolen, "client_id": "analysis-agent"})
    checks.append(("Re-delegation of a delegated token", out.get("status") in (400, 401), out))

    # 9. Positive control: the legitimate agent with the legitimate token works.
    legit = in_container("analysis-agent", CALL_WITH_OWN_SVID, url="https://systems-api:8443/systems/payments-api",
                         headers={"Authorization": f"Bearer {stolen}"})
    checks.append(("Control: token used by the agent it was bound to", legit.get("status") == 200, legit))

    failed = 0
    for name, ok, detail in checks:
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        brief = detail if isinstance(detail, str) else (detail.get("www") or detail.get("body") or detail.get("error"))
        print(f"        {str(brief)[:170]}")
    print("\nall security checks passed" if not failed else f"\n{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
