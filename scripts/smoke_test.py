#!/usr/bin/env python3
"""End-to-end check of the running stack: signs in through the real browser flow
(OIDC + PKCE login form), runs tasks for each user/agent pair and asserts that
the delegated scope is exactly User ∩ Agent ∩ Requested.

    pip install requests && python3 scripts/smoke_test.py
"""
import re
import sys

import requests

PORTAL = "http://localhost:8080"
REQUESTED = {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"}
USERS = {"alice": {"systems:read", "systems:analyze", "metrics:read", "tickets:read", "tickets:write"},
         "bob": {"systems:read", "metrics:read"}}
AGENTS = {"analysis-agent": {"systems:read", "systems:analyze", "metrics:read", "tickets:read"},
          "remediation-agent": {"systems:read", "tickets:read", "tickets:write"}}


def login(user: str) -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    r = s.get(f"{PORTAL}/login")                       # -> PingFederate login form
    assert "Sign On" in r.text, r.text[:300]
    hidden = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', r.text))
    assert hidden["code_challenge_method"] == "S256"
    r = s.post(r.url.split("?")[0], data={**hidden, "pf.username": user, "pf.pass": user})
    assert r.url.rstrip("/") == PORTAL and "Signed in as" in r.text, (r.url, r.text[:300])
    return s


def main() -> int:
    failures = 0
    for user, entitled in USERS.items():
        s = login(user)
        for agent, allowed in AGENTS.items():
            res = s.post(f"{PORTAL}/task", headers={"Accept": "application/json"},
                         data={"agent": agent, "system": "payments-api", "task": "Analyze system payments-api"}).json()
            expected = entitled & allowed & REQUESTED
            granted = set(res.get("delegated_token", {}).get("claims", {}).get("scope", "").split())
            steps = [st["n"] for st in res.get("steps", [])]
            calls = next((st["detail"]["calls"] for st in res.get("steps", []) if st["n"] == 10), [])
            ok = granted == expected and steps == list(range(4, 11))
            for c in calls:   # every resource decision must match the delegated scope
                ok &= (c["http_status"] == 200) == (c["scope"] in granted) or c["kind"] == "MCP" and c["http_status"] == 202
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {user:5} + {agent:17} -> {' '.join(sorted(granted)) or res.get('error')}")
            for c in calls:
                print(f"        {c['kind']:4} {c['operation']:34} {c['scope']:16} {c['http_status']}")
            if not ok:
                print("        expected", sorted(expected), "steps", steps)
    print("\nall checks passed" if not failures else f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
