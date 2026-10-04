#!/usr/bin/env python3
"""End-to-end check of the running stack (simulator or real PingFederate): signs in
through the IdP's login form (OIDC + PKCE), runs a task for each user/agent pair and
asserts the delegated scope is exactly User ∩ Agent ∩ Task, that every resource
decision matches it, and that the cross-domain call to partner.example (steps 11-14)
gets User ∩ Agent ∩ Partner policy with a pairwise subject and the same SVID binding.

    pip install requests && python3 scripts/smoke_test.py
"""
import sys

from stack import PORTAL, Stack, run_task

TASK = {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"}
USERS = {"alice": {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"},
         "bob": {"systems:read", "metrics:read"}}
AGENTS = {"analysis-agent": {"systems:read", "systems:analyze", "metrics:read", "tickets:read"},
          "remediation-agent": {"systems:read", "tickets:read", "tickets:write"}}
# Cross-domain (steps 11-14): payments-api is degraded, so the task needs both partner scopes.
PARTNER_NEEDS = {"partner:status.read", "partner:cases.write"}
USER_EGRESS = {"alice": {"partner:status.read", "partner:cases.write"}, "bob": {"partner:status.read"}}
AGENT_EGRESS = {"analysis-agent": {"partner:status.read"},
                "remediation-agent": {"partner:status.read", "partner:cases.write"}}


def main() -> int:
    stack = Stack()
    print(f"identity provider: {stack.name}\n")
    failures = 0
    for user, entitled in USERS.items():
        s = stack.portal_login(user)
        for agent, allowed in AGENTS.items():
            res = run_task(s, agent)       # free text: the agent picks the system, the user approves

            expected = entitled & allowed & TASK
            claims = res.get("delegated_token", {}).get("claims", {})
            granted = set(claims.get("scope", "").split())
            steps = [st["n"] for st in res.get("steps", [])]
            calls = next((st["detail"]["calls"] for st in res.get("steps", []) if st["n"] == 10), [])
            by_n = {st["n"]: st for st in res.get("steps", [])}
            partner_expected = PARTNER_NEEDS & USER_EGRESS[user] & AGENT_EGRESS[agent]
            pclaims = by_n.get(13, {}).get("detail", {}).get("claims") or {}
            partner_granted = set(pclaims.get("scope", "").split())
            pcalls = by_n.get(14, {}).get("detail", {}).get("calls", [])
            ok = granted == expected and steps == [4, 5, 6, 7, "7a", "7b", "7c", 8, 9, 10, 11, 12, 13, 14]
            ok &= res.get("approval", {}).get("status") == "approval_required"     # PCI target asked first
            ok &= res.get("targets") == ["payments-api"]
            ad = claims.get("authorization_details")
            ad = ad if isinstance(ad, list) else [ad]          # PingFederate collapses 1-element lists
            bound = [d for d in ad if isinstance(d, dict) and d.get("type") == "system_access"]
            systems = bound[0].get("systems") if bound else None
            ok &= (systems if isinstance(systems, list) else [systems]) == ["payments-api"]
            ok &= partner_granted == partner_expected
            ok &= pclaims.get("sub") not in (None, user)            # pairwise, never the internal id
            ok &= pclaims.get("cnf") == claims.get("cnf")            # bound to the same SVID across domains
            for c in pcalls:
                ok &= (c["http_status"] in (200, 201)) == (c["scope"] in partner_granted)
            ok &= claims.get("act", {}).get("sub") == f"spiffe://demo.local/agent/{agent}"
            ok &= "x5t#S256" in claims.get("cnf", {})
            for c in calls:   # every resource decision must match the delegated scope
                ok &= (200 <= c["http_status"] < 300) == (c["scope"] in granted)
            ok &= {"VAULT", "SQL"} <= {c["kind"] for c in calls}     # legacy DB via a Vault dynamic user
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {user:5} + {agent:17} -> {' '.join(sorted(granted)) or res.get('error')}"
                  f"  [plan {res.get('targets')} approved]")
            for c in calls + pcalls:
                print(f"        {c['kind']:4} {c['operation']:38} {c['scope']:20} {c['http_status']}")
            print(f"        partner.example token: scope={' '.join(sorted(partner_granted))} sub={pclaims.get('sub')}")
            if not ok:
                print("        expected", sorted(expected), "steps", steps, "claims", claims)
    # A non-sensitive target runs without asking.
    res = run_task(stack.portal_login("alice"), "analysis-agent",
                   "Is the ERP database healthy? Finance says invoices are slow", approve=False)
    ok = res.get("targets") == ["erp-db"] and "approval" not in res and res.get("status") != "approval_required"
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  alice + analysis-agent, 'ERP invoices are slow' -> agent picked "
          f"{res.get('targets')} without asking (not sensitive)")
    print("\nall checks passed" if not failures else f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
