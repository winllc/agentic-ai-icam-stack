"""Configures a real PingFederate (13.x) for the demo through its admin API, from the
same config/idp-policy.yaml the simulator uses, then keeps SPIRE trust in sync.

Objects created (all idempotent - PUT when present, POST otherwise):
  scopes ............... authServerSettings common scopes
  directory ............ LDAP data store + LDAP password validator (people in ou=people)
  htmlform ............. HTML Form IdP Adapter  -> IdP adapter grant mapping
  user-atm ............. JWT ATM for user tokens (aud=agentic-ai-service, entitlements claim)
  portal-oidc .......... OIDC policy (ID token) on user-atm
  agentic-ai-portal .... client: authorization code, PKCE required, client secret
  user-at .............. OAuth Bearer Access Token processor (validates the subject token)
  agent-delegation ..... token-exchange processor policy (subject token -> attributes)
  delegated-atm ........ JWT ATM for delegated tokens (aud=resources, act claim)
  <agent clients> ...... client: token exchange, CERTIFICATE auth (SPIFFE SVID), restricted scopes
  SSL runtime cert ..... enterprise TLS issuing CA (pki-init), SAN pingfederate + localhost
  Trusted CAs .......... SPIRE X.509 authorities (synced continuously)

Enforcement of  User ∩ Agent ∩ Requested  in PingFederate:
  Agent      -> client "Restrict common scopes" (PingFederate rejects anything outside it)
  User       -> issuance criterion: every requested scope ∈ the subject token's entitlements
  Requested  -> PingFederate issues exactly the requested scope
The agent therefore requests (task scopes ∩ its ceiling ∩ the user's entitlements).
"""

import base64
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import time

import requests
import urllib3
import yaml
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from requests.adapters import HTTPAdapter

from icam.common.spiffe_identity import WorkloadIdentity

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pf-configurator] %(message)s")
log = logging.getLogger("pf-configurator")

ADMIN = os.environ.get("PF_ADMIN_URL", "https://pingfederate:9999").rstrip("/")
ADMIN_USER = os.environ.get("PF_ADMIN_USER", "administrator")
ADMIN_PASSWORD = os.environ.get("PF_ADMIN_PASSWORD", "2FederateM0re")
ISSUER = os.environ.get("PF_ISSUER", "https://localhost:9031").rstrip("/")
POLICY_PATH = os.environ.get("PF_POLICY", "/policy/effective-policy.yaml")


def load_policy() -> str:
    """(Re)load the effective policy rendered by directory-sync; returns its content hash."""
    global POLICY
    raw = open(POLICY_PATH, "rb").read()
    POLICY = yaml.safe_load(raw)
    return hashlib.sha256(raw).hexdigest()


POLICY: dict = {}
POLICY_HASH = load_policy()
TRUST_DIR = os.environ.get("PF_TRUST_DIR", "/pf-trust")
TRUST_DOMAIN = os.environ.get("SPIFFE_TRUST_DOMAIN", "demo.local")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "60"))
PKI_DIR = os.environ.get("PF_TLS_PKI_DIR", "/pki/tls")
TLS_P12_PASSWORD = os.environ.get("PF_TLS_P12_PASSWORD", "changeit")

ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
OIDC_SCOPES = {"openid"}


# ------------------------------------------------------------------ admin API session

class PinnedAdapter(HTTPAdapter):
    """The admin console uses a self-signed cert generated at first start: pin it on
    first contact (TOFU) instead of switching verification off."""

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs.update(cert_reqs=ssl.CERT_NONE, assert_fingerprint=self.fingerprint, assert_hostname=False)
        super().init_poolmanager(*args, **kwargs)


def admin_session() -> requests.Session:
    host, port = ADMIN.split("://")[1].split(":")
    for attempt in range(120):
        try:
            pem = ssl.get_server_certificate((host, int(port)), timeout=5)
            break
        except (OSError, socket.timeout):
            if attempt % 10 == 0:
                log.info("waiting for the PingFederate admin API at %s", ADMIN)
            time.sleep(5)
    else:
        raise SystemExit("PingFederate admin API never came up")
    der = ssl.PEM_cert_to_DER_cert(pem)
    fp = hashlib.sha256(der).hexdigest()
    log.info("pinned admin certificate sha256=%s", fp)
    s = requests.Session()
    s.trust_env = False
    # Chain validation is impossible for a self-signed cert; the adapter's
    # assert_fingerprint enforces the pin on every connection instead.
    s.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s.mount(ADMIN, PinnedAdapter(fp))
    s.headers.update({"X-XSRF-Header": "PingFederate", "Content-Type": "application/json"})
    return s


class Api:
    def __init__(self, session: requests.Session):
        self.s = session
        self.base = f"{ADMIN}/pf-admin-api/v1"

    def call(self, method, path, body=None, auth=True, ok=(200, 201, 204)):
        r = self.s.request(method, self.base + path, json=body, timeout=30,
                           auth=(ADMIN_USER, ADMIN_PASSWORD) if auth else None)
        if r.status_code not in ok:
            raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:1500]}")
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else None

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def exists(self, path) -> bool:
        r = self.s.get(self.base + path, auth=(ADMIN_USER, ADMIN_PASSWORD), timeout=30)
        return r.status_code == 200

    def upsert(self, collection: str, obj: dict, key: str = "id"):
        """PUT collection/{key} when it exists, else POST to the collection."""
        if self.exists(f"{collection}/{obj[key]}"):
            self.call("PUT", f"{collection}/{obj[key]}", obj)
            log.info("updated %s/%s", collection, obj[key])
        else:
            self.call("POST", collection, obj)
            log.info("created %s/%s", collection, obj[key])

    def upsert_mapping(self, obj: dict):
        """Access token mappings are keyed by (context, token manager); PingFederate assigns the id."""
        def key(m):
            return (m["context"]["type"], (m["context"].get("contextRef") or {}).get("id"), m["accessTokenManagerRef"]["id"])
        existing = next((m for m in self.get("/oauth/accessTokenMappings") if key(m) == key(obj)), None)
        if existing:
            self.call("PUT", f"/oauth/accessTokenMappings/{existing['id']}", {**obj, "id": existing["id"]})
            log.info("updated access token mapping %s", existing["id"])
        else:
            created = self.call("POST", "/oauth/accessTokenMappings", obj)
            log.info("created access token mapping %s", created["id"])


# ------------------------------------------------------------------ helpers

def fields(**kv) -> list[dict]:
    return [{"name": k, "value": str(v)} for k, v in kv.items()]


def src(type_, id_=None) -> dict:
    return {"type": type_, **({"id": id_} if id_ else {})}


def val(type_, value, id_=None) -> dict:
    return {"source": src(type_, id_), "value": value}


def ognl_map(d: dict) -> str:
    return "#{" + ", ".join(f'"{k}" : "{v}"' for k, v in d.items()) + "}"


def ref(id_: str) -> dict:
    return {"id": id_}


# ------------------------------------------------------------------ bootstrap

def bootstrap(api: Api):
    """First start of a fresh container: accept the license agreement, create the admin."""
    r = api.s.get(api.base + "/version", auth=(ADMIN_USER, ADMIN_PASSWORD), timeout=30)
    if r.status_code == 200 and "version" in r.text:
        log.info("PingFederate %s already bootstrapped", r.json()["version"])
        return
    agreement = api.get("/license/agreement", auth=False)
    if not agreement.get("accepted"):
        api.call("PUT", "/license/agreement", {**agreement, "accepted": True}, auth=False)
        log.info("accepted the PingFederate license agreement")
    r = api.s.get(api.base + "/version", auth=(ADMIN_USER, ADMIN_PASSWORD), timeout=30)
    if r.status_code == 401 or "invalid_credentials" in r.text:
        api.call("POST", "/administrativeAccounts", {
            "username": ADMIN_USER, "password": ADMIN_PASSWORD, "active": True, "auditor": False,
            "description": "demo administrator",
            "roles": ["USER_ADMINISTRATOR", "ADMINISTRATOR", "CRYPTO_ADMINISTRATOR", "EXPRESSION_ADMINISTRATOR"],
        }, auth=False)
        log.info("created initial administrator %s", ADMIN_USER)
    log.info("PingFederate %s, license %s", api.get("/version")["version"],
             {k: api.get("/license").get(k) for k in ("version", "tier", "expirationDate")})


# ------------------------------------------------------------------ configuration

def configure_runtime_tls(api: Api):
    """Runtime HTTPS key pair issued by the enterprise TLS issuing CA (pki-init): valid for the browser
    (localhost) and containers (pingfederate), and stable across PingFederate re-creation."""
    key_id = "runtime-tls"
    if not any(k["id"] == key_id for k in api.get("/keyPairs/sslServer")["items"]):
        with open(os.path.join(PKI_DIR, "pingfederate.p12"), "rb") as f:
            api.call("POST", "/keyPairs/sslServer/import", {
                "id": key_id, "fileData": base64.b64encode(f.read()).decode(),
                "format": "PKCS12", "password": TLS_P12_PASSWORD})
        log.info("imported runtime TLS key pair %s from the enterprise TLS issuing CA", key_id)
    settings = api.get("/keyPairs/sslServer/settings")
    if settings["runtimeServerCertRef"]["id"] != key_id:
        settings["runtimeServerCertRef"] = ref(key_id)
        settings["activeRuntimeServerCerts"] = [ref(key_id)]
        api.call("PUT", "/keyPairs/sslServer/settings", settings)
        log.info("activated runtime TLS certificate %s", key_id)
    os.makedirs(TRUST_DIR, exist_ok=True)
    # Clients trust the enterprise root (the TLS issuing CA chains to it).
    with open(os.path.join(PKI_DIR, "trust-anchor.pem")) as src, open(os.path.join(TRUST_DIR, "pf-ca.pem"), "w") as dst:
        dst.write(src.read())


def configure_scopes(api: Api):
    bad = [n for n in POLICY["scopes"] if not re.fullmatch(r"[A-Za-z0-9:._-]+", n)]
    if bad:  # scope names are embedded in OGNL regexes below
        raise SystemExit(f"unsupported characters in scope names: {bad}")
    settings = api.get("/oauth/authServerSettings")
    have = {s["name"] for s in settings.get("scopes", [])}
    for name, desc in POLICY["scopes"].items():
        if name not in OIDC_SCOPES and name not in have:
            settings.setdefault("scopes", []).append({"name": name, "description": desc, "dynamic": False})
    settings["disallowPlainPKCE"] = True
    api.call("PUT", "/oauth/authServerSettings", settings)
    log.info("scopes: %s", sorted(s["name"] for s in settings["scopes"]))


PEOPLE_BASE = os.environ.get("LDAP_PEOPLE_BASE", "ou=people,dc=demo,dc=local")


def configure_authentication(api: Api):
    """People authenticate against the LDAP directory (simple bind via an LDAP PCV)."""
    store = {
        "type": "LDAP", "id": "directory", "name": "Enterprise directory (OpenLDAP)", "ldapType": "GENERIC",
        "hostnames": [os.environ.get("LDAP_HOST", "ldap:389")], "useSsl": False, "bindAnonymously": False,
        "userDN": os.environ["LDAP_BIND_DN"], "password": os.environ["LDAP_BIND_PASSWORD"],
        "maskAttributeValues": False, "testOnBorrow": True,
    }
    api.upsert("/dataStores", store)
    api.upsert("/passwordCredentialValidators", {
        "id": "directorypcv", "name": "Enterprise directory users",
        "pluginDescriptorRef": ref("org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator"),
        "configuration": {"tables": [{"name": "Authentication Error Overrides", "rows": []}],
                          "fields": fields(**{"LDAP Datastore": "directory", "Search Base": PEOPLE_BASE,
                                              "Search Filter": "uid=${username}", "Scope of Search": "Subtree",
                                              "Case-Sensitive Matching": "false"})},
        "attributeContract": {"coreAttributes": [{"name": n} for n in ("DN", "givenName", "mail", "username")]},
    })
    api.upsert("/idp/adapters", {
        "id": "htmlform", "name": "HTML Form",
        "pluginDescriptorRef": ref("com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"),
        "configuration": {
            "tables": [{"name": "Credential Validators",
                        "rows": [{"fields": fields(**{"Password Credential Validator Instance": "directorypcv"})}]}],
            "fields": fields(**{"Challenge Retries": 3, "Session State": "None", "Session Timeout": 60,
                                "Session Max Timeout": 480, "Login Template": "html.form.login.template.html",
                                "Logout Template": "idp.logout.success.page.template.html"}),
        },
        "attributeContract": {"coreAttributes": [{"name": "username", "masked": False, "pseudonym": True},
                                                 {"name": "policy.action", "masked": False, "pseudonym": False}],
                              "uniqueUserKeyAttribute": "username", "maskOgnlValues": False},
        "attributeMapping": {"attributeContractFulfillment": {
            "username": val("ADAPTER", "username"), "policy.action": val("ADAPTER", "policy.action")}},
    })
    api.upsert("/oauth/idpAdapterMappings", {
        "id": "htmlform", "idpAdapterRef": ref("htmlform"),
        "attributeContractFulfillment": {"USER_KEY": val("ADAPTER", "username"),
                                         "USER_NAME": val("ADAPTER", "username")},
    })
    if api.exists("/passwordCredentialValidators/demopcv"):     # pre-directory versions of this demo
        api.call("DELETE", "/passwordCredentialValidators/demopcv")


def jwt_atm(id_: str, name: str, audience: str, lifetime_min: int, attrs: list[str], resources=None) -> dict:
    atm = {
        "id": id_, "name": name,
        "pluginDescriptorRef": ref("com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"),
        "configuration": {"tables": [{"name": "Symmetric Keys", "rows": []}, {"name": "Certificates", "rows": []}],
                          "fields": fields(**{
                              "Token Lifetime": lifetime_min, "Use Centralized Signing Key": "true",
                              "JWS Algorithm": "RS256", "Issuer Claim Value": ISSUER,
                              "Audience Claim Value": audience, "Include Key ID Header Parameter": "true",
                              "JWT ID Claim Length": 22, "Client ID Claim Name": "client_id",
                              "Scope Claim Name": "scope", "Space Delimit Scope Values": "true",
                              "Include Issued At Claim": "true"})},
        "attributeContract": {"extendedAttributes": [{"name": a, "multiValued": False} for a in attrs],
                              "defaultSubjectAttribute": "sub"},
    }
    if resources:
        atm["selectionSettings"] = {"resourceUris": resources}
    return atm


def configure_user_tokens(api: Api):
    portal_id, portal = next((k, c) for k, c in POLICY["clients"].items() if c.get("redirect_uris"))
    api.upsert("/oauth/accessTokenManagers", jwt_atm(
        "useratm", "User access tokens", portal["access_token_audience"], portal.get("access_token_ttl", 900) // 60,
        ["sub", "name", "email", "groups", "entitlements"]))

    # Attributes are looked up in the directory at token issuance (not cached in config).
    def from_ldap(attr):
        return f'@java.lang.String@join(" ", #this.get("ds.people.{attr}").getValues())'

    api.upsert_mapping({
        "context": {"type": "DEFAULT"}, "accessTokenManagerRef": ref("useratm"),
        "attributeSources": [{
            "type": "LDAP", "id": "people", "description": "Person entry in the directory",
            "dataStoreRef": ref("directory"), "baseDn": PEOPLE_BASE, "searchScope": "SUBTREE",
            "searchFilter": "uid=${USER_KEY}",
            "searchAttributes": ["displayName", "mail", "employeeType", "icamEntitlement"],
        }],
        "attributeContractFulfillment": {
            "sub": val("OAUTH_PERSISTENT_GRANT", "USER_KEY"),
            "name": val("LDAP_DATA_STORE", "displayName", "people"),
            "email": val("LDAP_DATA_STORE", "mail", "people"),
            "groups": val("EXPRESSION", from_ldap("employeeType")),
            # The user's entitlements = the scopes this user may ever delegate (LDAP icamEntitlement).
            "entitlements": val("EXPRESSION", from_ldap("icamEntitlement")),
        },
    })
    api.upsert("/oauth/openIdConnect/policies", {
        "id": "portaloidc", "name": "Agentic AI portal", "accessTokenManagerRef": ref("useratm"),
        "idTokenLifetime": 15,
        "attributeContract": {"coreAttributes": [{"name": "sub"}],
                              "extendedAttributes": [{"name": n} for n in ("name", "email", "groups")]},
        "attributeMapping": {"attributeContractFulfillment": {
            "sub": val("TOKEN", "sub"), "name": val("TOKEN", "name"), "groups": val("TOKEN", "groups"),
            "email": val("TOKEN", "email")}},
        "includeSriInIdToken": False, "includeUserInfoInIdToken": True,
    })
    api.call("PUT", "/oauth/openIdConnect/settings", {"defaultPolicyRef": ref("portaloidc")})

    scopes = [s for s in portal["allowed_scopes"] if s not in OIDC_SCOPES]
    api.upsert("/oauth/clients", {
        "clientId": portal_id, "name": portal.get("description", portal_id), "enabled": True,
        "grantTypes": ["AUTHORIZATION_CODE"], "redirectUris": portal["redirect_uris"],
        "clientAuth": {"type": "SECRET", "secret": portal["client_secret"]},
        "requireProofKeyForCodeExchange": True, "bypassApprovalPage": True,
        "restrictScopes": True, "restrictedScopes": ["openid", *scopes],
        "defaultAccessTokenManagerRef": ref("useratm"), "restrictToDefaultAccessTokenManager": True,
        "oidcPolicy": {"policyGroup": ref("portaloidc"),
                       "postLogoutRedirectUris": [u.rsplit("/", 1)[0] + "/*" for u in portal["redirect_uris"]]},
    }, key="clientId")


def configure_delegation(api: Api, issuer_dn: str):
    agents = {k: c for k, c in POLICY["clients"].items()
              if c.get("token_endpoint_auth_method") == "tls_client_auth"}
    federation = POLICY.get("federation", {})
    partner_as = {f["authorization_server"] for f in federation.values()}
    egress = sorted({sc for f in federation.values() for sc in f["scopes"]})
    # Internal resources only; partner authorization servers get federation grants (below).
    resources = sorted({r for c in agents.values() for r in c["allowed_resources"]} - partner_as)
    portal_id = next(k for k, c in POLICY["clients"].items() if c.get("redirect_uris"))
    subject_auds = sorted({a for c in agents.values() for a in c["subject_token_audiences"]})

    api.upsert("/idp/tokenProcessors", {
        "id": "userat", "name": "User access token (subject token)",
        "pluginDescriptorRef": ref("org.sourceid.wstrust.processor.oauth.BearerAccessTokenTokenProcessor"),
        "configuration": {"fields": fields(**{"Access Token Manager": "useratm", "Scope value as single string": "true"})},
        "attributeContract": {
            "coreAttributes": [{"name": n, "masked": False} for n in
                               ("aud", "authorization_details", "client_id", "expires_at", "iss", "scope")],
            "extendedAttributes": [{"name": n, "masked": False} for n in ("sub", "entitlements", "name")],
            "maskOgnlValues": False},
    })
    api.upsert("/oauth/tokenExchange/processor/policies", {
        "id": "agentdelegation", "name": "Agent delegation (user -> agent)", "actorTokenRequired": False,
        "attributeContract": {"coreAttributes": [{"name": "subject"}],
                              "extendedAttributes": [{"name": n} for n in
                                                     ("entitlements", "user_scope", "user_client_id")]},
        "processorMappings": [{
            "subjectTokenType": ACCESS_TOKEN, "subjectTokenProcessor": ref("userat"),
            "attributeContractFulfillment": {
                "subject": val("SUBJECT_TOKEN", "sub"),
                "entitlements": val("SUBJECT_TOKEN", "entitlements"),
                "user_scope": val("SUBJECT_TOKEN", "scope"),
                "user_client_id": val("SUBJECT_TOKEN", "client_id"),
            },
            "issuanceCriteria": {"conditionalCriteria": [
                {"source": src("SUBJECT_TOKEN"), "attributeName": "client_id", "condition": "EQUALS",
                 "value": portal_id, "errorResult": f"subject token must come from {portal_id}"},
                {"source": src("SUBJECT_TOKEN"), "attributeName": "aud", "condition": "EQUALS",
                 "value": subject_auds[0], "errorResult": "subject token audience not accepted"},
            ]},
        }],
    })
    api.call("PUT", "/oauth/tokenExchange/processor/settings", {"defaultProcessorPolicyRef": ref("agentdelegation")})

    api.upsert("/oauth/accessTokenManagers", jwt_atm(
        "delegatedatm", "Delegated agent tokens", "", 5, ["sub", "act", "cnf", "aud"], resources))

    # PingFederate's OGNL can read the token-exchange request (context.HttpRequest) and the
    # requested scopes (context.OAuthScopes). The subject token was already validated by the
    # "userat" processor, so its payload can be read from the request parameter.
    req = '#this.get("context.HttpRequest").getObjectValue()'
    subject_json = (f'#tok = {req}.getParameter("subject_token"), #json = new java.lang.String('
                    '@java.util.Base64@getUrlDecoder().decode(#tok.split("\\\\.")[1]), "UTF-8")')

    def claim(name):
        return f'(" " + #json.replaceAll(".*\\"{name}\\":\\"([^\\"]*)\\".*", "$1") + " ")'

    def leftover(words_expr):
        # Remove every allowed word from " <requested> "; whatever remains is not allowed.
        # (dots are escaped: scope names such as partner:status.read are regex-literal words)
        return (f'#req.replaceAll(" (?:" + {words_expr}.trim().replace(".", "\\\\.").replaceAll(" +", "|")'
                ' + ")(?= )", "").trim()')

    within_user = (
        f'{subject_json}, '
        '#req = " " + @java.lang.String@join(" ", #this.get("context.OAuthScopes").getValues()) + " ", '
        f'{leftover(claim("entitlements"))}.isEmpty() && {leftover(claim("scope"))}.isEmpty()'
    )
    def resources_within(allowed):
        alternatives = "|".join(f"\\\\Q{r}\\\\E" for r in allowed)
        return (f'#r = {req}.getParameterValues("resource"), #r != null && #r.length > 0 && '
                f'@java.util.Arrays@toString(#r).replaceAll("^\\\\[|\\\\]$", "")'
                f'.replaceAll("(?:^|(?<=, ))(?:{alternatives})(?=, |$)", "").replaceAll("[ ,]", "").isEmpty()')

    def no_scopes_from(words):
        """None of the requested scopes is in `words`."""
        listed = '" ' + " ".join(words) + ' "'
        return (f'#req = " " + @java.lang.String@join(" ", #this.get("context.OAuthScopes").getValues()) + " ", '
                f'{leftover(listed)}.equals(#req.trim())')

    def only_scopes_from(words):
        listed = '" ' + " ".join(words) + ' "'
        return (f'#req = " " + @java.lang.String@join(" ", #this.get("context.OAuthScopes").getValues()) + " ", '
                f'{leftover(listed)}.isEmpty()')

    resources_ok = resources_within(resources)
    cert_thumbprint = (
        f'#certs = {req}.getAttribute("jakarta.servlet.request.X509Certificate"), '
        '#{"x5t#S256": @java.util.Base64@getUrlEncoder().withoutPadding().encodeToString('
        '@java.security.MessageDigest@getInstance("SHA-256").digest(#certs[0].getEncoded()))}'
    )
    api.upsert_mapping({
        "context": {"type": "TOKEN_EXCHANGE_PROCESSOR_POLICY", "contextRef": ref("agentdelegation")},
        "accessTokenManagerRef": ref("delegatedatm"),
        "attributeContractFulfillment": {
            "sub": val("TOKEN_EXCHANGE_PROCESSOR_POLICY", "subject"),
            # RFC 8693 actor = the agent workload (client ids are the SPIFFE path leaf).
            "act": val("EXPRESSION",
                       f'#{{"sub": "spiffe://{TRUST_DOMAIN}/agent/" + #this.get("context.ClientId").getValue()}}'),
            # RFC 8705 certificate binding to the SVID the agent authenticated with.
            "cnf": val("EXPRESSION", cert_thumbprint),
            # RFC 8707: audience = the requested resource servers.
            "aud": val("EXPRESSION", f'@java.util.Arrays@asList({req}.getParameterValues("resource"))'),
        },
        "issuanceCriteria": {"expressionCriteria": [
            {"expression": within_user,
             "errorResult": "requested scope exceeds the user's entitlements or the user's token"},
            {"expression": resources_ok, "errorResult": "resource missing or not allowed for agents"},
            {"expression": no_scopes_from(egress),
             "errorResult": "egress scopes are only issued inside a federation grant"},
        ]},
    })

    # --- Identity chaining: a JWT authorization grant addressed to a partner AS. Same subject
    # token, same User ∩ Agent checks, but a pairwise subject, a 60 s lifetime, only that
    # partner's egress scopes, and the partner AS (from the agent's allowlist) as audience.
    for trust_domain, fed in federation.items():
        atm_id = "fedgrant" + re.sub(r"[^a-z0-9]", "", trust_domain)
        api.upsert("/oauth/accessTokenManagers", jwt_atm(
            atm_id, f"Federation grants for {trust_domain}", "", max(1, fed.get("grant_ttl", 60) // 60),
            ["sub", "act", "cnf", "aud"], [fed["authorization_server"]]))
        pairwise = (
            f'{subject_json}, #sub = {claim("sub")}.trim(), '
            '@java.util.Base64@getUrlEncoder().withoutPadding().encodeToString('
            '@java.security.MessageDigest@getInstance("SHA-256").digest('
            f'(#sub + "|{trust_domain}|{fed["pairwise_salt"]}").getBytes("UTF-8"))).substring(0, 22)'
        ) if fed.get("subject") == "pairwise" else None
        api.upsert_mapping({
            "context": {"type": "TOKEN_EXCHANGE_PROCESSOR_POLICY", "contextRef": ref("agentdelegation")},
            "accessTokenManagerRef": ref(atm_id),
            "attributeContractFulfillment": {
                "sub": val("EXPRESSION", pairwise) if pairwise else val("TOKEN_EXCHANGE_PROCESSOR_POLICY", "subject"),
                "act": val("EXPRESSION",
                           f'#{{"sub": "spiffe://{TRUST_DOMAIN}/agent/" + #this.get("context.ClientId").getValue()}}'),
                "cnf": val("EXPRESSION", cert_thumbprint),
                "aud": val("EXPRESSION", f'@java.util.Arrays@asList({req}.getParameterValues("resource"))'),
            },
            "issuanceCriteria": {"expressionCriteria": [
                {"expression": within_user,
                 "errorResult": "requested scope exceeds the user's entitlements or the user's token"},
                {"expression": resources_within([fed["authorization_server"]]),
                 "errorResult": f"a federation grant is addressed to exactly {fed['authorization_server']}"},
                {"expression": only_scopes_from(fed["scopes"]),
                 "errorResult": f"only {fed['scopes']} may leave for {trust_domain}"},
            ]},
        })

    for client_id, c in agents.items():
        api.upsert("/oauth/clients", {
            # Lifecycle comes from the directory: disabled/expired agents' clients are disabled.
            "clientId": client_id, "name": c.get("description", client_id), "enabled": c.get("enabled", True),
            "grantTypes": ["TOKEN_EXCHANGE"],
            "clientAuth": {"type": "CERTIFICATE", "clientCertIssuerDn": issuer_dn,
                           "clientCertSubjectDn": f"CN={client_id}, O=SPIRE, C=US"},
            "restrictScopes": True, "restrictedScopes": c["allowed_scopes"],
            "tokenExchangeProcessorPolicyRef": ref("agentdelegation"),
            # Not restricted to the default ATM: a partner AS resource selects its federation-grant ATM.
            "defaultAccessTokenManagerRef": ref("delegatedatm"), "restrictToDefaultAccessTokenManager": False,
        }, key="clientId")


# ------------------------------------------------------------------ SPIRE trust sync

def dn(name: x509.Name) -> str:
    """Java-style DN (as PingFederate displays it): most-specific first, ', ' separated."""
    short = {"2.5.4.5": "SERIALNUMBER"}
    parts = []
    for rdn in reversed(name.rdns):
        for a in rdn:
            key = short.get(a.oid.dotted_string) or a.rfc4514_attribute_name
            parts.append(f"{key}={a.value}")
    return ", ".join(parts)


def sync_spire_trust(api: Api, identity: WorkloadIdentity) -> str:
    """Import the SPIRE trust anchors and intermediates as PingFederate Trusted CAs; return the
    DN of the authority currently signing SVIDs (what agent certificates carry as issuer)."""
    identity.fetch()
    authorities = x509.load_pem_x509_certificates(open(identity.bundle_path, "rb").read())
    # With SPIRE chained under the enterprise PKI the bundle holds only the root; PingFederate
    # matches the client's *issuer* DN against a Trusted CA, so also import the intermediates
    # carried in the SVID chain (the current SPIRE CA and the enterprise SPIRE issuing CA).
    authorities += x509.load_pem_x509_certificates(open(identity.cert_path, "rb").read())[1:]
    trusted = {c["sha256Fingerprint"].lower() for c in api.get("/certificates/ca")["items"]}
    for cert in authorities:
        fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
        if fp not in trusted:
            api.call("POST", "/certificates/ca/import", {
                "fileData": base64.b64encode(cert.public_bytes(Encoding.PEM)).decode()})
            log.info("imported trusted CA %s", cert.subject.rfc4514_string())
    leaf = x509.load_pem_x509_certificates(open(identity.cert_path, "rb").read())[0]
    return dn(leaf.issuer)


def configure_all(api: Api, identity: WorkloadIdentity) -> str:
    bootstrap(api)
    configure_runtime_tls(api)
    configure_scopes(api)
    configure_authentication(api)
    configure_user_tokens(api)
    issuer_dn = sync_spire_trust(api, identity)
    configure_delegation(api, issuer_dn)
    return issuer_dn


def main():
    global POLICY_HASH
    api = Api(admin_session())
    identity = WorkloadIdentity(workdir="/run/svid")
    identity.wait_for_svid()
    issuer_dn = configure_all(api, identity)
    open(os.path.join(TRUST_DIR, "ready"), "w").write(time.strftime("%FT%T"))
    log.info("PingFederate configured; agent clients trust issuer %s", issuer_dn)

    failures = 0
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            if (new_hash := hashlib.sha256(open(POLICY_PATH, "rb").read()).hexdigest()) != POLICY_HASH:
                # The directory changed (agent lifecycle, ceiling, resources): re-apply the agent clients.
                POLICY_HASH = load_policy()
                configure_delegation(api, issuer_dn)
                log.info("directory change applied: %s", ", ".join(
                    f"{k}={'enabled' if c.get('enabled', True) else 'disabled'}"
                    for k, c in POLICY["clients"].items() if "directory" in c))
            if not api.exists("/oauth/clients/agentic-ai-portal"):
                # A recreated PingFederate container starts empty: apply everything again.
                log.warning("configuration missing (PingFederate recreated?) - re-applying")
                issuer_dn = configure_all(api, identity)
            # SPIRE rotates its CA: keep Trusted CAs and the agent clients' issuer DN current.
            new_dn = sync_spire_trust(api, identity)
            if new_dn != issuer_dn:
                configure_delegation(api, new_dn)
                issuer_dn = new_dn
                log.info("SPIRE CA rotated; agent clients now trust issuer %s", issuer_dn)
            failures = 0
        except Exception as exc:
            failures += 1
            log.error("sync failed (%d): %s", failures, exc)
            if failures >= 3:
                # e.g. a new admin certificate after a rebuild: exit so the container restarts and re-pins.
                raise SystemExit("PingFederate unreachable or changed; restarting configurator")


if __name__ == "__main__":
    main()
