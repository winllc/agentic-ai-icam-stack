"""LDAP directory access: people (authentication, entitlements) and agents (non-person
entities). Used by directory-sync and the PingFederate simulator.

Everything directory-specific - base DNs, filters, attribute names - comes from
config/directory-mapping.yaml, so the same code runs against the demo OpenLDAP, a RadiantLogic
FID virtual view or Active Directory. Users are found by search and then bound by DN, so no
DN layout is assumed.
"""

import datetime as dt
import os
import ssl

import yaml
from ldap3 import BASE, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

MAPPING_PATH = os.environ.get("DIRECTORY_MAPPING", "/config/directory-mapping.yaml")


def load_mapping(path: str = MAPPING_PATH) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _values(entry: dict, attr: str) -> list:
    v = entry.get(attr) or []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _one(entry: dict, attr: str, default=None):
    vals = [v for v in _values(entry, attr) if v not in (None, "")]
    return vals[0] if vals else default


def _time(v) -> dt.datetime | None:
    """GeneralizedTime from servers with or without schema info (ldap3 may return str)."""
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.timezone.utc)
    if isinstance(v, (str, bytes)) and v:
        s = v.decode() if isinstance(v, bytes) else v
        for fmt in ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S.%fZ", "%Y%m%d%H%MZ"):
            try:
                return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
            except ValueError:
                continue
    return None


class Directory:
    def __init__(self, url=None, bind_dn=None, password=None, mapping=None):
        url = url or os.environ.get("LDAP_URL", "ldap://ldap:389")
        ca = os.environ.get("LDAP_TLS_CA")            # LDAPS / StartTLS trust anchor
        tls = Tls(ca_certs_file=ca, validate=ssl.CERT_REQUIRED) if ca else None
        self.server = Server(url, connect_timeout=5, tls=tls)
        self.bind_dn = bind_dn or os.environ["LDAP_BIND_DN"]
        self.password = password or os.environ["LDAP_BIND_PASSWORD"]
        self.map = mapping or load_mapping()
        self.people, self.agents_cfg = self.map["people"], self.map["agents"]
        self.agents_base = self.agents_cfg["base"]

    def _conn(self) -> Connection:
        return Connection(self.server, self.bind_dn, self.password, auto_bind=True, receive_timeout=10,
                          read_only=True)

    # ---------------------------------------------------------------- people
    def _find_person(self, conn: Connection, uid: str):
        a = self.people["attributes"]
        flt = self.people["filter"].replace("{uid}", escape_filter_chars(uid))
        conn.search(self.people["base"], flt, SUBTREE, attributes=list(a.values()))
        return conn.entries[0] if len(conn.entries) == 1 else None

    def _person(self, entry) -> dict:
        a, e = self.people["attributes"], entry.entry_attributes_as_dict
        return {"uid": _one(e, a["uid"]), "name": _one(e, a["name"]), "email": _one(e, a["email"]),
                "groups": _values(e, a["groups"]), "entitlements": _values(e, a["entitlements"]),
                "dn": entry.entry_dn}

    def authenticate(self, uid: str, password: str) -> dict | None:
        """Search for the user with the service account, then bind as the found DN. Empty
        passwords are refused (LDAP would treat them as an unauthenticated bind = success)."""
        if not uid or not password:
            return None
        conn = self._conn()
        try:
            entry = self._find_person(conn, uid)
        finally:
            conn.unbind()
        if entry is None:
            return None
        user_conn = Connection(self.server, entry.entry_dn, password, receive_timeout=10, read_only=True)
        try:
            if not user_conn.bind():
                return None
        finally:
            user_conn.unbind()
        return self._person(entry)

    def person(self, uid: str) -> dict | None:
        conn = self._conn()
        try:
            entry = self._find_person(conn, uid)
            return self._person(entry) if entry else None
        finally:
            conn.unbind()

    # ---------------------------------------------------------------- agents
    def agents(self) -> list[dict]:
        a = self.agents_cfg["attributes"]
        active = {v.lower() for v in self.agents_cfg.get("active_values", ["active"])}
        conn = self._conn()
        try:
            conn.search(self.agents_base, self.agents_cfg["filter"], SUBTREE, attributes=list(a.values()))
            now = dt.datetime.now(dt.timezone.utc)
            out = []
            for entry in conn.entries:
                e = entry.entry_attributes_as_dict
                status = str(_one(e, a["status"], "disabled")).lower()
                expires = _time(_one(e, a["expires"]))
                recert = _time(_one(e, a["last_recertified"]))
                effective, reason = True, "active"
                if status not in active:
                    effective, reason = False, f"lifecycle status is {status}"
                elif expires and expires <= now:
                    effective, reason = False, f"expired {expires:%Y-%m-%d}"
                out.append({
                    "name": _one(e, a["name"]), "dn": entry.entry_dn, "description": _one(e, a["description"], ""),
                    "sponsor": _one(e, a["sponsor"]), "spiffe_id": _one(e, a["spiffe_id"]),
                    "selectors": _values(e, a["selectors"]), "ceiling": _values(e, a["ceiling"]),
                    "resources": _values(e, a["resources"]), "federates_with": _values(e, a["federates_with"]),
                    "status": status, "expires": expires.isoformat() if expires else None,
                    "last_recertified": recert.isoformat() if recert else None,
                    "effective": effective, "reason": reason,
                })
            return sorted(out, key=lambda x: x["name"] or "")
        finally:
            conn.unbind()

    def sponsor_name(self, dn: str | None) -> str | None:
        if not dn:
            return None
        a = self.people["attributes"]
        conn = self._conn()
        try:
            conn.search(dn, "(objectClass=*)", BASE, attributes=[a["name"]])
            if not conn.entries:
                return dn
            return _one(conn.entries[0].entry_attributes_as_dict, a["name"], dn)
        finally:
            conn.unbind()
