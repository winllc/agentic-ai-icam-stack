"""Configures HashiCorp Vault for the demo (idempotent, via Vault's HTTP API).

phase "pki" (before SPIRE starts)
  * init + unseal (demo: one key share kept in the vault-keys volume - never do this in prod)
  * pki_spire: "Demo Enterprise SPIRE Issuing CA". The key is generated INSIDE Vault; its CSR is
    signed by the enterprise root (pki-init). SPIRE's UpstreamAuthority "vault" asks this mount
    to sign SPIRE's own CA (pki_spire/root/sign-intermediate) at every SPIRE CA rotation.
  * AppRole "spire-server" scoped to exactly that signing endpoint.

phase "brokers" (once the IdP and the inventory database are up)
  * auth/jwt: trusts the IdP's JWKS. Role "agent-inventory" accepts only DELEGATED tokens:
      aud must contain https://vault:8200, act.sub must be a demo.local agent SPIFFE ID,
      scope must contain systems:read. Token metadata records user + agent (audit trail).
  * database/: PostgreSQL dynamic credentials - role "inventory-reader" (5 min users, SELECT only).
  * an audit device on stdout.
"""

import datetime as dt
import json
import os
import sys
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID  # noqa: F401  (kept for readers extending this)

VAULT = os.environ.get("VAULT_ADDR", "https://vault:8200")
CA = os.environ.get("VAULT_CACERT", "/pki/tls/trust-anchor.pem")
KEYS = os.environ.get("VAULT_KEYS_DIR", "/vault-keys")
ROOT_CRT = os.environ.get("ENTERPRISE_ROOT_CRT", "/pki/enterprise/root-ca.crt")
ROOT_KEY = os.environ.get("ENTERPRISE_ROOT_KEY", "/pki/enterprise/root-ca.key")
SPIRE_SECRET_ID = os.environ.get("VAULT_APPROLE_SECRET_ID", "spire-approle-secret-demo")

http = requests.Session()
http.verify = CA
http.trust_env = False


def log(msg):
    print(f"[vault-setup] {msg}", flush=True)


def api(method, path, body=None, ok=(200, 204), token=True):
    headers = {"X-Vault-Token": root_token()} if token else {}
    r = http.request(method, f"{VAULT}/v1/{path}", json=body, headers=headers, timeout=30)
    if r.status_code not in ok:
        raise RuntimeError(f"{method} {path} -> {r.status_code} {r.text[:500]}")
    return r.json() if r.content else {}


def root_token():
    return json.load(open(f"{KEYS}/init.json"))["root_token"]


def mounted(kind, path):
    table = api("GET", "sys/mounts" if kind == "secret" else "sys/auth")
    return f"{path}/" in table.get("data", table)


# ------------------------------------------------------------------ phase: pki
def init_and_unseal():
    for _ in range(120):
        try:
            status = http.get(f"{VAULT}/v1/sys/seal-status", timeout=5).json()
            break
        except requests.RequestException:
            time.sleep(2)
    else:
        raise SystemExit("Vault never came up")
    if not status["initialized"]:
        init = api("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1}, token=False)
        os.makedirs(KEYS, exist_ok=True)
        with open(f"{KEYS}/init.json", "w") as f:
            json.dump(init, f)
        os.chmod(f"{KEYS}/init.json", 0o600)
        log("initialised Vault (demo: unseal key + root token stored in the vault-keys volume)")
    if http.get(f"{VAULT}/v1/sys/seal-status", timeout=5).json()["sealed"]:
        key = json.load(open(f"{KEYS}/init.json"))["keys"][0]
        api("PUT", "sys/unseal", {"key": key}, token=False)
        log("unsealed")


def spire_issuing_ca():
    if not mounted("secret", "pki_spire"):
        api("POST", "sys/mounts/pki_spire", {"type": "pki", "config": {"max_lease_ttl": "43800h"}})
    issuers = api("LIST", "pki_spire/issuers", ok=(200, 404)).get("data", {}).get("keys", [])
    if issuers:
        log("pki_spire already has its issuing CA")
        return
    csr_pem = api("POST", "pki_spire/intermediate/generate/internal", {
        "common_name": "Demo Enterprise SPIRE Issuing CA", "organization": "Agentic AI ICAM Demo",
        "ou": "Enterprise PKI", "country": "US", "key_type": "ec", "key_bits": 384,
    })["data"]["csr"]
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    root = x509.load_pem_x509_certificate(open(ROOT_CRT, "rb").read())
    root_key = serialization.load_pem_private_key(open(ROOT_KEY, "rb").read(), password=None)
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject).issuer_name(root.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False)
            .sign(root_key, hashes.SHA384()))
    chain = cert.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM)
    api("POST", "pki_spire/intermediate/set-signed", {"certificate": chain.decode()})
    log("pki_spire: issuing CA key generated in Vault, certificate signed by the enterprise root")


def spire_approle():
    if not mounted("auth", "approle"):
        api("POST", "sys/auth/approle", {"type": "approle"})
    api("PUT", "sys/policies/acl/spire-upstream", {"policy": """
path "pki_spire/root/sign-intermediate" { capabilities = ["update"] }
path "pki_spire/cert/ca"                { capabilities = ["read"] }
path "pki_spire/cert/ca_chain"          { capabilities = ["read"] }
"""})
    api("POST", "auth/approle/role/spire-server", {"token_policies": ["spire-upstream"], "token_ttl": "1h",
                                                   "secret_id_num_uses": 0})
    api("POST", "auth/approle/role/spire-server/role-id", {"role_id": "spire-server"})
    existing = api("LIST", "auth/approle/role/spire-server/secret-id", ok=(200, 404)).get("data", {}).get("keys", [])
    if not existing:
        api("POST", "auth/approle/role/spire-server/custom-secret-id", {"secret_id": SPIRE_SECRET_ID})
    log("AppRole spire-server may only call pki_spire/root/sign-intermediate")


# ------------------------------------------------------------------ phase: brokers
def audit_device():
    devices = api("GET", "sys/audit")
    if "stdout/" not in devices.get("data", devices):
        api("PUT", "sys/audit/stdout", {"type": "file", "options": {"file_path": "stdout", "log_raw": "false"}})
        log("audit device -> stdout (every request: who, which policy, which path)")


def wait_for_jwks(url: str, ca: str | None, timeout: int = 600):
    """Vault validates the JWKS URL when the config is written. Wait until the IdP serves keys
    over TLS that chains to the trust anchor (PingFederate shows a default self-signed
    certificate until pf-configurator has installed the enterprise one)."""
    probe = requests.Session()
    probe.trust_env = False
    probe.verify = ca or True
    end, last = time.time() + timeout, None
    while time.time() < end:
        try:
            keys = probe.get(url, timeout=10).json().get("keys", [])
            if keys:
                log(f"IdP JWKS reachable ({len(keys)} keys) at {url}")
                return
            reason = "JWKS has no keys yet"
        except requests.exceptions.SSLError as exc:
            reason = (f"TLS not yet trusted ({exc.__class__.__name__}) - the IdP is probably still on its default "
                      "certificate; waiting for pf-configurator")
        except requests.RequestException as exc:
            reason = f"not reachable ({exc.__class__.__name__})"
        if reason != last:
            log(f"waiting for IdP JWKS: {reason}")
            last = reason
        time.sleep(5)
    raise SystemExit(f"IdP JWKS at {url} never became usable: {last}")


def jwt_auth():
    if not mounted("auth", "jwt"):
        api("POST", "sys/auth/jwt", {"type": "jwt"})
    cfg = {"jwks_url": os.environ["IDP_JWKS_URL"], "bound_issuer": os.environ["IDP_ISSUER"]}
    if os.environ.get("IDP_TLS_CA"):
        cfg["jwks_ca_pem"] = open(os.environ["IDP_TLS_CA"]).read()
    wait_for_jwks(cfg["jwks_url"], os.environ.get("IDP_TLS_CA"))
    api("POST", "auth/jwt/config", cfg)
    api("PUT", "sys/policies/acl/inventory-read", {"policy": """
path "database/creds/inventory-reader" { capabilities = ["read"] }
path "auth/token/revoke-self"          { capabilities = ["update"] }
"""})
    api("POST", "auth/jwt/role/agent-inventory", {
        "role_type": "jwt",
        "bound_audiences": ["https://vault:8200"],          # only tokens minted for Vault (resource)
        "user_claim": "sub",                                # Vault entity alias = the end user
        "bound_claims_type": "glob",
        "bound_claims": {"/act/sub": "spiffe://demo.local/agent/*", "scope": "*systems:read*"},
        "claim_mappings": {"/act/sub": "agent", "client_id": "client_id", "scope": "delegated_scope"},
        "token_policies": ["inventory-read"], "token_ttl": "5m", "token_max_ttl": "10m",
        "token_no_default_policy": True,
    })
    log("auth/jwt: role agent-inventory accepts delegated tokens (aud=vault, act.sub=agent, scope systems:read)")


def database():
    if not mounted("secret", "database"):
        api("POST", "sys/mounts/database", {"type": "database"})
    api("POST", "database/config/inventory", {
        "plugin_name": "postgresql-database-plugin", "allowed_roles": ["inventory-reader"],
        "connection_url": "postgresql://{{username}}:{{password}}@inventory-db:5432/inventory?sslmode=disable",
        "username": os.environ.get("INVENTORY_DB_ADMIN", "vaultadmin"),
        "password": os.environ.get("INVENTORY_DB_ADMIN_PASSWORD", "vaultadmin-secret"),
    })
    api("POST", "database/roles/inventory-reader", {
        "db_name": "inventory", "default_ttl": "5m", "max_ttl": "10m",
        "creation_statements": [
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
            "GRANT SELECT ON assets TO \"{{name}}\";",
        ],
        # Privileges must go first: PostgreSQL refuses to drop a role that still holds grants,
        # which would leave "short-lived" users behind after their lease.
        "revocation_statements": ["REVOKE ALL ON assets FROM \"{{name}}\";", "DROP ROLE IF EXISTS \"{{name}}\";"],
    })
    log("database/: inventory-reader issues 5-minute SELECT-only PostgreSQL users")


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "pki"
    init_and_unseal()
    if phase == "pki":
        spire_issuing_ca()
        spire_approle()
    elif phase == "brokers":
        audit_device()
        jwt_auth()
        database()
    log(f"phase {phase} done")


if __name__ == "__main__":
    main()
