"""directory-sync: the LDAP directory is the system of record for agentic identities; this
job turns it into runtime configuration, continuously.

  LDAP ou=agents (sponsor, lifecycle, expiry, ceiling, selectors)
     ├─► SPIRE registration entries   active + unexpired agents get an SVID; disabled,
     │                                expired or deleted agents lose theirs (within the
     │                                SPIRE Agent's sync interval + the SVID TTL at most)
     └─► effective IdP policy         one OAuth client per agent (enabled, ceiling, resources)
                                      for PingFederate (pf-configurator) or the simulator,
                                      and the agents' own manifest
"""

import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import time

import yaml

from icam.directory.ldapdir import Directory

logging.basicConfig(level=logging.INFO, format="%(asctime)s [directory-sync] %(message)s")
log = logging.getLogger("directory-sync")

BASE_POLICY = os.environ.get("BASE_POLICY", "/config/idp-policy.yaml")
EFFECTIVE = os.environ.get("EFFECTIVE_POLICY", "/policy/effective-policy.yaml")
INTERVAL = int(os.environ.get("SYNC_INTERVAL", "10"))
SOCK = os.environ.get("SPIRE_SERVER_SOCKET", "/tmp/spire-server/private/api.sock")
TRUST_DOMAIN = os.environ.get("SPIFFE_TRUST_DOMAIN", "demo.local")
PARENT = os.environ.get("AGENT_PARENT_ID", f"spiffe://{TRUST_DOMAIN}/node/docker-host")
AGENT_PREFIX = f"spiffe://{TRUST_DOMAIN}/agent/"
# Deployment-specific values the base policy may reference as ${NAME} or ${NAME:-default}.
POLICY_VARS = {"PORTAL_PUBLIC_URL": os.environ.get("PORTAL_PUBLIC_URL", "http://localhost:8080").rstrip("/")}


def load_base_policy() -> dict:
    def sub(m):
        value = POLICY_VARS.get(m.group(1)) or m.group(2)
        if value is None:
            raise ValueError(f"{BASE_POLICY}: ${{{m.group(1)}}} is not a known setting")
        return value
    return yaml.safe_load(re.sub(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}", sub, open(BASE_POLICY).read()))


# ------------------------------------------------------------------ SPIRE
def spire(*args) -> str:
    out = subprocess.run(["spire-server", *args, "-socketPath", SOCK], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError(f"spire-server {' '.join(args)}: {out.stderr.strip() or out.stdout.strip()}")
    return out.stdout


def spire_agent_entries() -> dict[str, dict]:
    """Current SPIRE entries for agent workloads, keyed by SPIFFE ID."""
    data = json.loads(spire("entry", "show", "-parentID", PARENT, "-output", "json") or "{}")
    entries = {}
    for e in data.get("entries") or []:
        sid = f"spiffe://{e['spiffe_id']['trust_domain']}{e['spiffe_id']['path']}"
        if sid.startswith(AGENT_PREFIX):
            entries[sid] = {
                "id": e["id"],
                "selectors": sorted(f"{s['type']}:{s['value']}" for s in e.get("selectors") or []),
                "dns": sorted(e.get("dns_names") or []),
                "federates_with": sorted(f.removeprefix("spiffe://") for f in e.get("federates_with") or []),
            }
    return entries


def desired_entry(agent: dict) -> dict:
    return {"selectors": sorted(agent["selectors"]), "dns": [agent["name"]],
            "federates_with": sorted(agent["federates_with"])}


def reconcile_spire(agents: list[dict]) -> list[str]:
    actions = []
    current = spire_agent_entries()
    wanted = {a["spiffe_id"]: a for a in agents if a["effective"] and a["spiffe_id"].startswith(AGENT_PREFIX)}
    for sid, entry in current.items():
        if sid not in wanted:
            spire("entry", "delete", "-entryID", entry["id"])
            agent = next((a for a in agents if a["spiffe_id"] == sid), None)
            actions.append(f"revoked {sid} ({agent['reason'] if agent else 'not in directory'})")
    for sid, agent in wanted.items():
        want = desired_entry(agent)
        have = current.get(sid)
        if have and {k: have[k] for k in want} == want:
            continue
        if have:
            spire("entry", "delete", "-entryID", have["id"])
        args = ["entry", "create", "-parentID", PARENT, "-spiffeID", sid, "-x509SVIDTTL", "3600",
                "-dns", agent["name"]]
        for sel in agent["selectors"]:
            args += ["-selector", sel]
        for td in agent["federates_with"]:
            args += ["-federatesWith", f"spiffe://{td}"]
        spire(*args)
        actions.append(f"{'updated' if have else 'registered'} {sid}")
    return actions


# ------------------------------------------------------------------ effective policy
def render_policy(base: dict, agents: list[dict], sponsors: dict) -> dict:
    policy = copy.deepcopy(base)
    template = policy.pop("agent_client_template", {})
    for a in agents:
        policy["clients"][a["name"]] = {
            **copy.deepcopy(template),
            "description": a["description"],
            "enabled": a["effective"],
            "tls_client_auth_san_uri": a["spiffe_id"],
            "allowed_scopes": a["ceiling"],
            "allowed_resources": a["resources"],
            "directory": {
                "dn": a["dn"], "sponsor": a["sponsor"], "sponsor_name": sponsors.get(a["sponsor"]),
                "status": a["status"], "effective": a["effective"], "reason": a["reason"],
                "expires": a["expires"], "last_recertified": a["last_recertified"],
                "spiffe_id": a["spiffe_id"], "selectors": a["selectors"], "federates_with": a["federates_with"],
            },
        }
    return policy


def write_if_changed(policy: dict) -> bool:
    body = "# GENERATED by directory-sync from the LDAP directory + config/idp-policy.yaml - do not edit\n"
    body += yaml.safe_dump(policy, sort_keys=False)
    old = open(EFFECTIVE).read() if os.path.exists(EFFECTIVE) else ""
    if hashlib.sha256(old.encode()).digest() == hashlib.sha256(body.encode()).digest():
        return False
    tmp = EFFECTIVE + ".tmp"
    with open(tmp, "w") as f:
        f.write(body)
    os.replace(tmp, EFFECTIVE)       # atomic: readers never see a partial file
    return True


def main():
    directory = Directory()
    log.info("syncing %s every %ss -> SPIRE (%s) + %s", directory.agents_base, INTERVAL, PARENT, EFFECTIVE)
    while True:
        try:
            base = load_base_policy()
            agents = directory.agents()
            sponsors = {a["sponsor"]: directory.sponsor_name(a["sponsor"]) for a in agents}
            for action in reconcile_spire(agents):
                log.info("SPIRE: %s", action)
            if write_if_changed(render_policy(base, agents, sponsors)):
                log.info("effective policy updated: %s", ", ".join(
                    f"{a['name']}={'active' if a['effective'] else a['reason']}" for a in agents))
            open(os.path.join(os.path.dirname(EFFECTIVE), ".synced"), "w").write(time.strftime("%FT%T"))
        except Exception as exc:
            log.error("sync failed: %s", exc)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
