#!/usr/bin/env python3
"""Negative tests against the running stack (simulator or real PingFederate) - each one
is an attack or policy violation the design must stop, inside demo.local and across the
federation boundary to partner.example.

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


FEDERATE = """
me = WorkloadIdentity(); me.fetch()
TE, AT = 'urn:ietf:params:oauth:grant-type:token-exchange', 'urn:ietf:params:oauth:token-type:access_token'
r = requests.post(args['token_ep'], cert=me.client_cert, verify=args.get('ca') or str(me.bundle_path), data={
    'grant_type': TE, 'client_id': args['client_id'], 'subject_token': args['user_token'],
    'subject_token_type': AT, 'scope': 'partner:status.read',
    'resource': 'https://partner-as:8443'})
out = {'grant': r.json().get('access_token'), 'grant_status': r.status_code}
if args.get('redeem') and out['grant']:
    p = requests.post('https://partner-as:8443/token', cert=me.client_cert, verify=str(me.federated_bundle_path),
                      data={'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': out['grant'],
                            'scope': 'partner:status.read', 'resource': 'https://partner-api:8443'})
    out['partner_token'] = p.json().get('access_token'); out['partner_status'] = p.status_code
print(json.dumps(out))
"""

REDEEM = """
me = WorkloadIdentity(); me.fetch()
r = requests.post('https://partner-as:8443/token', cert=me.client_cert, verify=str(me.federated_bundle_path),
                  data={'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': args['assertion'],
                        'scope': 'partner:status.read'})
print(json.dumps({'status': r.status_code, 'body': r.text[:300]}))
"""

PARTNER_CALL = """
me = WorkloadIdentity(); me.fetch()
r = requests.get('https://partner-api:8443/v1/services/fraud-scoring/status', cert=me.client_cert,
                 verify=str(me.federated_bundle_path), headers={'Authorization': 'Bearer ' + args['token']})
print(json.dumps({'status': r.status_code, 'www': r.headers.get('WWW-Authenticate'), 'body': r.text[:200]}))
"""


def exchange(service: str, **form) -> dict:
    return in_container(service, CALL_WITH_OWN_SVID, method="POST", url=stack.mtls_token_endpoint,
                        ca=stack.container_ca, data=form)


def main() -> int:
    print(f"identity provider: {stack.name}\n")
    all_scopes = ("openid systems:read systems:analyze metrics:read tickets:read tickets:write "
                  "partner:status.read partner:cases.write")
    alice = user_access_token("alice", all_scopes)
    bob = user_access_token("bob", all_scopes)
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

    # --- Cross-domain (identity chaining to partner.example) ------------------------------
    fed = dict(token_ep=stack.mtls_token_endpoint, ca=stack.container_ca, user_token=alice, client_id="analysis-agent")
    g1 = in_container("analysis-agent", FEDERATE, **fed)                    # a grant for analysis-agent
    g2 = in_container("analysis-agent", FEDERATE, **fed, redeem=True)       # grant + partner token
    if not (g1.get("grant") and g2.get("partner_token")):
        print("could not obtain a federation grant / partner token for the cross-domain checks:", g1, g2)
        return 1

    # 10. A grant minted for analysis-agent redeemed by another (federated) workload.
    out = in_container("remediation-agent", REDEEM, assertion=g1.get("grant") or "")
    checks.append(("Federation grant redeemed by a different workload (holder-of-key)",
                   out.get("status") == 400 and "different client certificate" in out.get("body", ""), out))

    # 11. The same grant redeemed twice by its rightful holder.
    first = in_container("analysis-agent", REDEEM, assertion=g1.get("grant") or "")
    again = in_container("analysis-agent", REDEEM, assertion=g1.get("grant") or "")
    checks.append(("Federation grant replayed (single-use jti)",
                   first.get("status") == 200 and again.get("status") == 400 and "replay" in again.get("body", ""),
                   again))

    # 12. Asking our AS for a grant to a partner that is not on the agent's egress allowlist.
    out = exchange("analysis-agent", **{**te, "client_id": "analysis-agent", "scope": "partner:status.read",
                                        "resource": "https://evil-as.example:8443"})
    checks.append(("Grant for a partner not on the egress allowlist", out.get("status") in (400, 401), out))

    # 13. Smuggling an egress scope into an internal token (it may only leave inside a grant).
    out = exchange("analysis-agent", **{**te, "client_id": "analysis-agent", "scope": "systems:read partner:status.read"})
    checks.append(("Egress scope requested in an internal token", out.get("status") in (400, 401), out))

    # 14. demo.local's internal delegated token presented directly to the partner API.
    out = in_container("analysis-agent", PARTNER_CALL, token=stolen)
    checks.append(("Internal token used at the external API (foreign issuer)",
                   out.get("status") == 401 and stolen != "", out))

    # 15. A partner token lifted from analysis-agent and used by another workload.
    out = in_container("remediation-agent", PARTNER_CALL, token=g2.get("partner_token") or "")
    checks.append(("Partner token replayed by a different workload (cnf binding)",
                   out.get("status") == 401 and "not bound" in (out.get("www") or ""), out))

    # 16. Control: the rightful agent calls the partner API with its partner token.
    out = in_container("analysis-agent", PARTNER_CALL, token=g2.get("partner_token") or "")
    checks.append(("Control: partner token used by the agent it was issued to", out.get("status") == 200, out))

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
