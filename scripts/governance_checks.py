#!/usr/bin/env python3
"""Hybrid-model checks: the LDAP directory is the system of record for agent identities and
user entitlements, and SPIRE's CA chains to the enterprise PKI. Each check changes the
directory the way an administrator or an access review would, waits for directory-sync,
observes the runtime effect, and restores the original state.

    pip install requests && python3 scripts/governance_checks.py
"""
import json
import subprocess
import sys
import time

from stack import PORTAL, Stack

stack = Stack()
LDAP_ADMIN = ["-x", "-H", "ldap://localhost", "-D", "cn=admin,dc=demo,dc=local", "-w", "admin"]
AGENTS = "ou=agents,dc=demo,dc=local"
WAIT = 60   # directory-sync (10 s) + SPIRE Agent cache refresh + pf-configurator sync


def sh(*cmd, stdin=None) -> str:
    out = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}...: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def ldap_modify(ldif: str):
    sh("docker", "exec", "-i", "agentic-icam-ldap-1", "ldapmodify", *LDAP_ADMIN, stdin=ldif)


def set_attr(dn: str, attr: str, values: list[str]):
    ldap_modify(f"dn: {dn}\nchangetype: modify\nreplace: {attr}\n" + "".join(f"{attr}: {v}\n" for v in values))


def get_attr(dn: str, attr: str) -> list[str]:
    out = sh("docker", "exec", "agentic-icam-ldap-1", "ldapsearch", *LDAP_ADMIN, "-LLL", "-b", dn, "-s", "base",
             "(objectClass=*)", attr)
    return [line.split(": ", 1)[1] for line in out.splitlines() if line.startswith(f"{attr}: ")]


def effective_client(name: str) -> dict:
    import yaml
    out = sh("docker", "exec", "agentic-icam-directory-sync-1", "cat", "/policy/effective-policy.yaml")
    return yaml.safe_load(out)["clients"].get(name, {})


def spire_agent_ids() -> set[str]:
    out = sh("docker", "exec", "agentic-icam-directory-sync-1", "spire-server", "entry", "show", "-parentID",
             "spiffe://demo.local/node/docker-host", "-output", "json",
             "-socketPath", "/tmp/spire-server/private/api.sock")
    return {f"spiffe://{e['spiffe_id']['trust_domain']}{e['spiffe_id']['path']}"
            for e in json.loads(out).get("entries") or [] if e["spiffe_id"]["path"].startswith("/agent/")}


def run_task(user: str, agent: str) -> dict:
    s = stack.portal_login(user)
    return s.post(f"{PORTAL}/task", headers={"Accept": "application/json"},
                  data={"agent": agent, "system": "payments-api"}).json()


def granted(res: dict) -> set[str]:
    return set(res.get("delegated_token", {}).get("claims", {}).get("scope", "").split())


def wait_until(predicate, what: str, timeout: int = WAIT):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(3)
    raise TimeoutError(f"timed out waiting for {what}")


IN_AGENT = """
import json, os, requests, shutil
from icam.common.spiffe_identity import WorkloadIdentity
args = json.loads(os.environ['ARGS'])
if args['op'] == 'hold':          # fetch an SVID now and keep it, like a long-running agent would
    w = WorkloadIdentity(workdir='/tmp/held-svid'); w.fetch(); print(json.dumps(w.info))
elif args['op'] == 'chain':       # the SVID chain as PEM, for a legacy trust-store check
    w = WorkloadIdentity(); w.fetch(); print(json.dumps({'pem': open(w.cert_path).read()}))
else:                             # token exchange with the HELD SVID (no new fetch)
    r = requests.post(args['token_ep'], cert=('/tmp/held-svid/svid.pem', '/tmp/held-svid/svid.key'),
                      verify=args.get('ca') or '/tmp/held-svid/bundle.pem', data=args['form'])
    print(json.dumps({'status': r.status_code, 'body': r.text[:300]}))
"""


def in_agent(agent: str, **args) -> dict:
    out = sh("docker", "exec", "-e", f"ARGS={json.dumps(args)}", f"agentic-icam-{agent}-1", "python", "-c", IN_AGENT)
    return json.loads(out.strip().splitlines()[-1])


def user_token(user: str) -> str:
    """Access token for `user` via the portal client (OIDC + PKCE), as security_checks does."""
    from security_checks import user_access_token
    return user_access_token(user, "openid systems:read systems:analyze metrics:read tickets:read tickets:write "
                                   "partner:status.read partner:cases.write")


# ------------------------------------------------------------------ checks
def check_parity():
    """Every active directory agent has a SPIRE entry and an enabled OAuth client, with the LDAP ceiling."""
    ids = spire_agent_ids()
    problems = []
    for name in ("analysis-agent", "remediation-agent"):
        dn = f"cn={name},{AGENTS}"
        client = effective_client(name)
        if get_attr(dn, "icamSpiffeId")[0] not in ids:
            problems.append(f"{name}: no SPIRE entry")
        if not client.get("enabled"):
            problems.append(f"{name}: client not enabled")
        if sorted(client.get("allowed_scopes", [])) != sorted(get_attr(dn, "icamScopeCeiling")):
            problems.append(f"{name}: ceiling differs from LDAP")
    return not problems, problems or f"SPIRE entries {sorted(ids)} and clients match ou=agents"


def check_legacy_trust():
    """An SVID validates with only the enterprise root in the trust store (any legacy TLS stack)."""
    pem = in_agent("analysis-agent", op="chain")["pem"]
    out = subprocess.run(
        ["docker", "run", "--rm", "-i", "-v", "agentic-icam_spire-pki:/pki:ro", "--entrypoint", "sh",
         "agentic-icam/spire-tools:latest", "-c",
         "cat > /tmp/chain.pem && awk 'BEGIN{n=0} /BEGIN CERT/{n++} {print > \"/tmp/c\" n \".pem\"}' /tmp/chain.pem"
         " && cat /tmp/c2.pem /tmp/c3.pem > /tmp/inter.pem 2>/dev/null;"
         " openssl verify -CAfile /pki/enterprise/root-ca.crt -untrusted /tmp/inter.pem /tmp/c1.pem;"
         " for f in /tmp/c1.pem /tmp/c2.pem /tmp/c3.pem; do [ -f $f ] && openssl x509 -in $f -noout -subject -issuer;"
         " done"], input=pem, capture_output=True, text=True)
    ok = "/tmp/c1.pem: OK" in out.stdout
    return ok, out.stdout.strip().replace("\n", " | ")[:400] or out.stderr


def check_disable_revokes():
    """Disabling an agent in LDAP revokes it twice over: its SPIRE entry goes (no new SVIDs) AND its
    OAuth client is disabled, so even an SVID fetched earlier (valid up to 1 h) is refused."""
    dn = f"cn=remediation-agent,{AGENTS}"
    held = in_agent("remediation-agent", op="hold")
    alice = user_token("alice")
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": "remediation-agent",
            "subject_token": alice, "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": "systems:read", "resource": "https://systems-api:8443"}
    exch = dict(op="exchange", token_ep=stack.mtls_token_endpoint, ca=stack.container_ca, form=form)
    before = in_agent("remediation-agent", **exch)
    set_attr(dn, "icamLifecycleStatus", ["disabled"])
    t0 = time.time()
    try:
        wait_until(lambda: "spiffe://demo.local/agent/remediation-agent" not in spire_agent_ids()
                   and not effective_client("remediation-agent").get("enabled"), "directory-sync to revoke")
        # Layer 1 - the IdP: the OAuth client is disabled, so a still-valid SVID is refused.
        wait_until(lambda: in_agent("remediation-agent", **exch)["status"] in (400, 401),
                   "the IdP to refuse the disabled client")
        t_idp = time.time() - t0
        with_held_svid = in_agent("remediation-agent", **exch)
        # Layer 2 - SPIRE: once the SPIRE Agent drops the entry, new instances get no SVID at all.
        wait_until(lambda: run_task("alice", "remediation-agent").get("steps", [{}])[-1].get("n") == 5,
                   "the SPIRE Agent to stop issuing SVIDs", timeout=120)
        t_spire = time.time() - t0
        task = run_task("alice", "remediation-agent")
    finally:
        set_attr(dn, "icamLifecycleStatus", ["active"])
    wait_until(lambda: granted(run_task("alice", "remediation-agent")), "the agent to be re-enabled")
    ok = before["status"] == 200 and with_held_svid["status"] in (400, 401) and task["steps"][-1]["n"] == 5
    return ok, (f"before: {before['status']}; after disable - IdP refuses the held SVID (valid until "
                f"{held['not_after'][11:16]}) in {t_idp:.0f}s: {with_held_svid['status']} "
                f"{with_held_svid['body'][:90]}; new instances get no SVID in {t_spire:.0f}s "
                f"(step {task['steps'][-1]['n']}); restored")


def check_expiry():
    """An expired agent identity (icamExpires in the past, no recertification) stops working."""
    dn = f"cn=analysis-agent,{AGENTS}"
    original = get_attr(dn, "icamExpires")
    set_attr(dn, "icamExpires", ["20200101000000Z"])
    try:
        wait_until(lambda: "expired" in effective_client("analysis-agent").get("directory", {}).get("reason", ""),
                   "expiry to be rendered")
        wait_until(lambda: run_task("bob", "analysis-agent").get("error") is not None, "the expired agent to fail")
        reason = effective_client("analysis-agent")["directory"]["reason"]
    finally:
        set_attr(dn, "icamExpires", original)
    wait_until(lambda: granted(run_task("bob", "analysis-agent")), "the agent to be recertified")
    return True, f"analysis-agent {reason} -> denied; expiry restored -> works again"


def check_ceiling_change():
    """Narrowing an agent's ceiling in LDAP narrows every delegation it receives."""
    dn = f"cn=analysis-agent,{AGENTS}"
    original = get_attr(dn, "icamScopeCeiling")
    set_attr(dn, "icamScopeCeiling", [v for v in original if v != "systems:analyze"])
    try:
        wait_until(lambda: "systems:analyze" not in effective_client("analysis-agent")["allowed_scopes"],
                   "the ceiling change to be rendered")
        wait_until(lambda: granted(run_task("alice", "analysis-agent")) and
                   "systems:analyze" not in granted(run_task("alice", "analysis-agent")), "PingFederate to apply it")
        narrowed = granted(run_task("alice", "analysis-agent"))
    finally:
        set_attr(dn, "icamScopeCeiling", original)
    wait_until(lambda: "systems:analyze" in granted(run_task("alice", "analysis-agent")), "the ceiling restore")
    return "systems:analyze" not in narrowed, f"alice + analysis-agent while narrowed: {' '.join(sorted(narrowed))}"


def check_entitlement_change():
    """Removing a user entitlement in LDAP removes it from every agent acting for that user."""
    dn = "uid=bob,ou=people,dc=demo,dc=local"
    original = get_attr(dn, "icamEntitlement")
    set_attr(dn, "icamEntitlement", [v for v in original if v != "metrics:read"])
    try:
        res = run_task("bob", "analysis-agent")            # new login reads entitlements from LDAP
        narrowed = granted(res)
    finally:
        set_attr(dn, "icamEntitlement", original)
    restored = granted(run_task("bob", "analysis-agent"))
    return ("metrics:read" not in narrowed and "metrics:read" in restored,
            f"bob + analysis-agent: {' '.join(sorted(narrowed))} -> restored: {' '.join(sorted(restored))}")


def main() -> int:
    print(f"identity provider: {stack.name}\n")
    failed = 0
    for check in (check_parity, check_legacy_trust, check_entitlement_change, check_ceiling_change,
                  check_expiry, check_disable_revokes):
        try:
            ok, detail = check()
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {check.__doc__.strip().splitlines()[0]}")
        print(f"        {detail if isinstance(detail, str) else detail}")
    print("\nall governance checks passed" if not failed else f"\n{failed} check(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
