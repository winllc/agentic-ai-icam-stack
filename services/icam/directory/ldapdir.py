"""LDAP directory access: people (authentication, entitlements) and agents (non-person
entities). Used by directory-sync and by the PingFederate simulator."""

import datetime as dt
import os

from ldap3 import BASE, SUBTREE, Connection, Server
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

PERSON_ATTRS = ["uid", "displayName", "cn", "mail", "employeeType", "icamEntitlement"]
AGENT_ATTRS = ["cn", "description", "icamSponsor", "icamSpiffeId", "icamWorkloadSelector", "icamScopeCeiling",
               "icamAllowedResource", "icamFederatesWith", "icamLifecycleStatus", "icamExpires",
               "icamLastRecertified"]


def _one(entry, attr, default=None):
    v = entry.get(attr)
    if isinstance(v, list):
        return v[0] if v else default
    return v if v not in (None, "") else default


def _many(entry, attr):
    v = entry.get(attr) or []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _time(v):
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.timezone.utc)
    return None


class Directory:
    def __init__(self, url=None, bind_dn=None, password=None, base=None):
        self.server = Server(url or os.environ.get("LDAP_URL", "ldap://ldap:389"), connect_timeout=5)
        self.bind_dn = bind_dn or os.environ["LDAP_BIND_DN"]
        self.password = password or os.environ["LDAP_BIND_PASSWORD"]
        self.base = base or os.environ.get("LDAP_BASE", "dc=demo,dc=local")
        self.people = f"ou=people,{self.base}"
        self.agents_base = f"ou=agents,{self.base}"

    def _conn(self) -> Connection:
        return Connection(self.server, self.bind_dn, self.password, auto_bind=True, receive_timeout=10,
                          read_only=True)

    # ---------------------------------------------------------------- people
    def authenticate(self, uid: str, password: str) -> dict | None:
        """Simple bind as the user; never accepts an empty password (that would be an
        unauthenticated bind, which LDAP reports as success)."""
        if not uid or not password:
            return None
        dn = f"uid={escape_rdn(uid)},{self.people}"
        conn = Connection(self.server, dn, password, receive_timeout=10, read_only=True)
        try:
            if not conn.bind():
                return None
        finally:
            conn.unbind()
        return self.person(uid)

    def person(self, uid: str) -> dict | None:
        conn = self._conn()
        try:
            conn.search(self.people, f"(uid={escape_filter_chars(uid)})", SUBTREE, attributes=PERSON_ATTRS)
            if not conn.entries:
                return None
            e = conn.entries[0].entry_attributes_as_dict
            return {"uid": _one(e, "uid"), "name": _one(e, "displayName") or _one(e, "cn"),
                    "email": _one(e, "mail"), "groups": _many(e, "employeeType"),
                    "entitlements": _many(e, "icamEntitlement"), "dn": conn.entries[0].entry_dn}
        finally:
            conn.unbind()

    # ---------------------------------------------------------------- agents
    def agents(self) -> list[dict]:
        conn = self._conn()
        try:
            conn.search(self.agents_base, "(objectClass=icamAgent)", SUBTREE, attributes=AGENT_ATTRS)
            now = dt.datetime.now(dt.timezone.utc)
            out = []
            for entry in conn.entries:
                e = entry.entry_attributes_as_dict
                status = (_one(e, "icamLifecycleStatus") or "disabled").lower()
                expires = _time(_one(e, "icamExpires"))
                recert = _time(_one(e, "icamLastRecertified"))
                effective, reason = (True, "active")
                if status != "active":
                    effective, reason = False, f"lifecycle status is {status}"
                elif expires and expires <= now:
                    effective, reason = False, f"expired {expires:%Y-%m-%d}"
                out.append({
                    "name": _one(e, "cn"), "dn": entry.entry_dn, "description": _one(e, "description", ""),
                    "sponsor": _one(e, "icamSponsor"), "spiffe_id": _one(e, "icamSpiffeId"),
                    "selectors": _many(e, "icamWorkloadSelector"), "ceiling": _many(e, "icamScopeCeiling"),
                    "resources": _many(e, "icamAllowedResource"), "federates_with": _many(e, "icamFederatesWith"),
                    "status": status, "expires": expires.isoformat() if expires else None,
                    "last_recertified": recert.isoformat() if recert else None,
                    "effective": effective, "reason": reason,
                })
            return sorted(out, key=lambda a: a["name"])
        finally:
            conn.unbind()

    def sponsor_name(self, dn: str | None) -> str | None:
        if not dn:
            return None
        conn = self._conn()
        try:
            conn.search(dn, "(objectClass=*)", BASE, attributes=["displayName", "cn"])
            if not conn.entries:
                return dn
            e = conn.entries[0].entry_attributes_as_dict
            return _one(e, "displayName") or _one(e, "cn")
        finally:
            conn.unbind()
