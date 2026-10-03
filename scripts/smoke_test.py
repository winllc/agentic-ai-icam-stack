#!/usr/bin/env python3
"""End-to-end check of the running stack (simulator or real PingFederate): signs in
through the IdP's login form (OIDC + PKCE), runs a task for each user/agent pair and
asserts the delegated scope is exactly User ∩ Agent ∩ Task, and that every resource
decision matches it.

    pip install requests && python3 scripts/smoke_test.py
"""
import sys

from stack import PORTAL, Stack

TASK = {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"}
USERS = {"alice": {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"},
         "bob": {"systems:read", "metrics:read"}}
AGENTS = {"analysis-agent": {"systems:read", "systems:analyze", "metrics:read", "tickets:read"},
          "remediation-agent": {"systems:read", "tickets:read", "tickets:write"}}


def main() -> int:
    stack = Stack()
    print(f"identity provider: {stack.name}\n")
    failures = 0
    for user, entitled in USERS.items():
        s = stack.portal_login(user)
        for agent, allowed in AGENTS.items():
            res = s.post(f"{PORTAL}/task", headers={"Accept": "application/json"},
                         data={"agent": agent, "system": "payments-api", "task": "Analyze system payments-api"}).json()
            expected = entitled & allowed & TASK
            claims = res.get("delegated_token", {}).get("claims", {})
            granted = set(claims.get("scope", "").split())
            steps = [st["n"] for st in res.get("steps", [])]
            calls = next((st["detail"]["calls"] for st in res.get("steps", []) if st["n"] == 10), [])
            ok = granted == expected and steps == list(range(4, 11))
            ok &= claims.get("act", {}).get("sub") == f"spiffe://demo.local/agent/{agent}"
            ok &= "x5t#S256" in claims.get("cnf", {})
            for c in calls:   # every resource decision must match the delegated scope
                ok &= (c["http_status"] in (200, 202)) == (c["scope"] in granted)
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {user:5} + {agent:17} -> {' '.join(sorted(granted)) or res.get('error')}")
            for c in calls:
                print(f"        {c['kind']:4} {c['operation']:34} {c['scope']:16} {c['http_status']}")
            if not ok:
                print("        expected", sorted(expected), "steps", steps, "claims", claims)
    print("\nall checks passed" if not failures else f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
