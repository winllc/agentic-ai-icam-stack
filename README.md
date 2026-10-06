# Agentic AI ICAM stack (demo)

A Docker Compose demo of **identity-aware AI agents**. A user signs in with
PingFederate (OIDC + PKCE) and gives an agent a task. The agent instance gets its
own **SPIFFE workload identity** from SPIRE. It then **exchanges the user's token**
for a short-lived delegated token, scoped to *User ∩ Agent ∩ Requested* and bound
to the agent's X.509-SVID, and uses that token to call enterprise REST and MCP
resources over mTLS. It can also call an **external partner's API in another trust domain**
(`partner.example`) through cross-domain identity chaining over SPIFFE federation.

It follows a **hybrid identity model**. An LDAP directory is the system of record: people carry
their entitlements there, and agents are governed non-person entities with a sponsor, lifecycle,
expiry, recertification date and scope ceiling. SPIRE issues the short-lived runtime credentials,
and its CA is chained to an enterprise PKI root through **HashiCorp Vault**, so SVIDs validate in
ordinary trust stores. Vault also brokers short-lived database users for a legacy system,
using the agent's delegated token.

```
User ─1─► Agentic AI Service ─2 OIDC+PKCE─► PingFederate ─3 tokens─► Agentic AI Service
                                                                            │ 4 task in plain words
                                                                            ▼
                     SPIRE Server ◄─6 verify selectors── SPIRE Agent ◄─5 Workload API── Agent Runtime / Instance
                                  ──7 X.509-SVID──────────────────────────────────────►  AI Agent (user ctx + SVID)
                                                                                         │ 8 Token Exchange + mTLS
                                                         PingFederate (User ∩ Agent ∩ Scope) ─9 delegated token─►
                                                                                         │ 10 API / MCP (mTLS)
                                                                                         ▼
                                                                   Enterprise Resources (systems-api, ops-mcp)

 ── demo.local ─────────────────────────────────────────┼── SPIFFE federation ── partner.example ──────────
 AI Agent ─11 Token Exchange (resource = partner AS)─► PingFederate ─12 JWT grant (pairwise sub, 60 s)─► AI Agent
 AI Agent ─13 jwt-bearer grant + mTLS (federated SVID)─► Partner AS ── partner token ──► AI Agent
 AI Agent ─14 API calls (partner token + mTLS)─► Partner API
```

## Quick start

Two identity-provider modes share the same services, policy file and tests:

```bash
# A) No license needed: PingFederate-compatible simulator
docker compose up -d --build --wait

# B) Real PingFederate 13.1 (license file required; see pingfederate/README.md)
cp /path/to/pingfederate.lic pingfederate/license/pingfederate.lic && chmod 0644 pingfederate/license/pingfederate.lic
docker compose -f docker-compose.yml -f docker-compose.pingfederate.yml up -d --build --wait
```

Open http://localhost:8080 and sign in as `alice/alice` or `bob/bob` (other host names or a
reverse proxy: see [Public URLs](#public-urls-dns-and-reverse-proxies)). In mode B the login page
is PingFederate's own, at `https://localhost:9031`. Its certificate comes from a demo CA you can
trust in your browser.

To check everything from the command line (needs `pip install requests`). Both scripts detect the mode:

```bash
python3 scripts/smoke_test.py        # browser flow, 2 users × 2 agents, steps 1-14, scope intersections + cnf/act
python3 scripts/security_checks.py   # 22 attacks/violations that must fail + 2 controls, plus known GAPs
python3 scripts/governance_checks.py # directory mapping, legacy trust, disable/expire/narrow/revoke (~3 min)
```

Stop with `docker compose down` (add the same `-f` files in mode B). Add `-v` to wipe all state.
**Upgrading from a version without the directory or enterprise PKI requires `down -v` once**,
because SPIRE's CA moves under the enterprise root.

**Requirements:** Docker with Compose v2.24+, on Linux or Docker Desktop. The SPIRE
Agent uses the docker workload attestor, so it runs with `pid: host`, `cgroup: host`
and read-only access to the Docker socket. Set `DOCKER_SOCKET` if yours is not
`/var/run/docker.sock`.

**Optional:** set `ANTHROPIC_API_KEY` in `.env` and the agent will write its
assessment with Claude. Without a key, the summary is rule-based. Either way, the
model only sees data the delegated token allowed the agent to read.

## Services

| Service | Role in the diagram | Port |
|---|---|---|
| `agentic-ai-service` | Agentic AI Service: OIDC client (code + PKCE, confidential), task UI, trace view | `localhost:8080` |
| `pingfederate` | PingFederate. Mode A: compatible simulator (`9031` HTTP, `9443` mTLS). Mode B: [PingFederate 13.1](pingfederate/README.md) (`9031` HTTPS, `9032` mTLS, `9999` admin). | `localhost:9031` |
| `pf-configurator` | Mode B only: configures PingFederate via the admin API from `config/idp-policy.yaml`, keeps SPIRE trust in sync | – |
| `analysis-agent`, `remediation-agent` | Agent Runtime. Each task runs in a **new agent instance process** | internal `8090` |
| `spire-server` | SPIRE Server: trust domain `demo.local`, x509pop node attestation | internal |
| `spire-agent` | SPIRE Agent: Workload API socket, docker workload attestor | internal |
| `systems-api` | Enterprise REST API (inventory, metrics, diagnostics) | internal `8443` mTLS |
| `ops-mcp` | Enterprise MCP server (runbooks, tickets), Streamable HTTP, OAuth per tool | internal `8443` mTLS |
| `vault` | HashiCorp Vault: SPIRE's upstream CA (`pki_spire`) and dynamic PostgreSQL users (JWT auth with delegated tokens). Audit to stdout. | `localhost:8200` (TLS) |
| `vault-init`, `vault-config` | One-shot Vault setup: init/unseal, issuing CA, AppRole (before SPIRE); JWT auth, database role, audit (after the IdP) | – |
| `inventory-db` | A legacy PostgreSQL inventory that understands only database users | internal `5432` |
| `ldap` | OpenLDAP directory (`dc=demo,dc=local`): people with `icamEntitlement`, agents as `icamAgent` non-person entities. Custom schema in `directory/icam.schema`. | internal `389` |
| `directory-sync` | Directory → runtime every 10 s: SPIRE entries for active agents (revokes the rest) and the effective IdP policy | – |
| `pki-init`, `spire-register` | One-shot jobs: node-attestation PKI (both domains), demo enterprise PKI (root, SPIRE and TLS issuing CAs), SPIFFE federation bootstrap, infrastructure registration entries | – |
| `spire-server-partner`, `spire-agent-partner` | The external partner's SPIRE (trust domain `partner.example`), federated with `demo.local` via bundle endpoints | internal |
| `partner-as` | Partner's authorization server: redeems JWT-bearer grants from `demo.local`, issues its own tokens | internal `8443` mTLS |
| `partner-api` | Partner's external API (vendor service status, support cases). Accepts only partner-AS tokens. | internal `8443` mTLS |

## What happens, step by step

1. **Access**: the user opens the Agentic AI Service.
2. **OIDC + PKCE**: the service redirects to `/as/authorization.oauth2` with an S256
   `code_challenge`. PingFederate requires PKCE for this client.
3. **Tokens**: the code is redeemed with the `code_verifier` and client secret. The
   access token (`aud=agentic-ai-service`) carries the scopes the user is entitled to.
4. **Task**: the service forwards the task and the user's access token to an Agent
   Runtime. The runtime validates the token and spawns a fresh agent-instance process.
5. **Workload API**: the instance calls `FetchX509SVID` on the SPIRE Agent socket. It
   holds no secret.
6. **Attestation**: the SPIRE Agent maps the caller's PID to its container and matches
   `docker:label:ai.demo.spiffe-workload=<agent>` against the entries registered under
   the attested node.
7. **SVID**: the instance receives `spiffe://demo.local/agent/<agent>` (1h TTL, DNS SAN = service name).

The user describes a problem in plain words ("card payments are failing at checkout"). The
**agent picks the systems**, not the user:

- **7a Discover**: a token exchange for a *catalog-only* token
  (`authorization_details = [{"type": "system_catalog"}]`, RFC 9396). It can list systems and their
  metadata (criticality, data classification, keywords) but read none of them.
- **7b Plan**: the agent maps the task to at most `MAX_PLAN_TARGETS` (2) systems. With
  `ANTHROPIC_API_KEY` set it asks Claude (structured output; the task and catalog are treated as
  data, not instructions). Otherwise a keyword planner runs. The planner only proposes.
- **7c Policy check**: deterministic code checks the plan: targets must exist in the catalog, and
  the count is capped. **PCI or mission-critical targets need the user's approval**. The run
  then stops and the portal shows the plan. It holds the plan server-side, so the browser can only
  approve or reject it, not edit it.

8. **Token exchange**: the same exchange, now **bound to the approved targets** with
   `authorization_details = [{"type": "system_access", "systems": [...]}]`. It is an RFC 8693
   request to PingFederate's mTLS token endpoint. The client authenticates with its SVID: the simulator matches the SAN URI, and PingFederate matches
   the SVID's subject/issuer DN. `subject_token` = user's token, `resource` = the two
   enterprise resources. `scope` = what the task needs ∩ the agent's ceiling ∩ the user's
   scopes. The AS **rejects** anything outside User ∩ Agent; it never silently narrows.
9. **Delegated token**: `scope` = exactly that intersection, `sub = user`,
   `act.sub = agent SPIFFE ID`, `cnf.x5t#S256 = SVID thumbprint`, `aud = resources`,
   `authorization_details` = the approved targets, 5 min TTL. Exchanging a delegated token again
   is refused.
10. **API / MCP calls**: mTLS with the SVID, with the bearer token checked at each resource for
    signature, issuer, audience, **certificate binding**, **actor = mTLS peer**, and scope.
    Missing scope returns `403 insufficient_scope` (MCP authorization spec style). A system outside
    the token's `authorization_details` returns `403 insufficient_authorization`, on every REST
    route and MCP tool call. So even a confused or prompt-injected agent can't drift to other systems.

Steps 11–14 run when the system depends on a partner's service. `payments-api` depends on
`fraud-scoring` from `partner.example`:

11. **Discovery + token exchange for a grant**: the agent reads the partner API's RFC 9728
    protected-resource metadata to find the partner's authorization server. It then asks our
    PingFederate, over the same mTLS client authentication, for a grant with
    `resource = https://partner-as:8443`, and requests only egress scopes:
    `task needs ∩ agent ceiling ∩ user`.
12. **JWT authorization grant** (draft-ietf-oauth-identity-chaining): `aud` = the partner AS,
    `sub` = a **pairwise** pseudonym, so the partner never sees `alice`. It is valid for 60 s,
    has a `jti`, and is bound to the agent's SVID (`cnf`) with the agent as `act`. Only scopes
    the policy lists for that partner may leave, and only for agents whose egress allowlist
    includes it. Egress scopes are never put in internal tokens.
13. **Redeem at the partner** (RFC 7523 jwt-bearer): mTLS with the same SVID, which the partner
    trusts through SPIFFE federation. The partner checks the signature against our JWKS, the
    audience, lifetime, single use, holder-of-key and actor, then applies **its own** policy:
    grant ∩ its client ceiling. It issues its own token for `partner-api`, bound to the same SVID,
    with provenance (`federated.iss`, `grant_jti`).
14. **External API calls**: mTLS across trust domains plus the partner token. `partner-api`
    rejects tokens from any other issuer, including our internal ones.

The UI shows every step with its details. Steps 9, 12 and 13 render the scope intersections,
and steps 10 and 14 show each call's allow/deny decision.

## Hybrid identity: directory + enterprise PKI + SPIFFE

```
 LDAP  ou=people  (credentials, icamEntitlement)  ──► PingFederate: LDAP PCV + LDAP attribute source
       ou=agents  (icamAgent: sponsor, lifecycle,  ──► directory-sync ──► SPIRE registration entries
                   expiry, recertified, ceiling,                     └──► OAuth clients (enabled, ceiling)
                   selectors, allowed resources)

 Demo Enterprise Root CA ─┬─ SPIRE Issuing CA (key in Vault) ── SPIRE CA (rotates) ── X.509-SVIDs (1 h)
                          └─ TLS Issuing CA ──── PingFederate HTTPS
```

| Layer | Source of truth | What it gives you |
|---|---|---|
| **Governance**: who an agent is, who sponsors it, whether it's still approved | LDAP `ou=agents` (`icamLifecycleStatus`, `icamExpires`, `icamLastRecertified`, `icamSponsor`) | Ordinary IGA: owners, recertification, joiner-mover-leaver. Browse it at http://localhost:8080/directory. |
| **Ceiling**: the most an agent may ever do | LDAP `icamScopeCeiling`, `icamAllowedResource` | Rendered into each agent's OAuth client (restricted scopes) |
| **User entitlements** | LDAP `icamEntitlement` on the person | Read at token issuance (PingFederate LDAP attribute source / simulator LDAP lookup) |
| **Runtime credential** | SPIRE, attested by `icamWorkloadSelector` | Keys never leave the workload; 1 h SVIDs; no secret distribution |
| **Trust anchor** | Demo enterprise root CA | SVIDs and PingFederate's cert validate against one root that legacy stacks can trust. SPIRE CA rotation changes only an intermediate. |
| **Per-request authority** | OAuth delegation (unchanged) | User ∩ agent ceiling ∩ task, bound to the SVID |

**Revocation is directory-driven and doesn't wait for certificate expiry.** Disable or expire an
agent in LDAP and, within one sync interval, `directory-sync` deletes its SPIRE entry, so new
instances get no SVID. It also disables its OAuth client, so even an SVID fetched earlier, still
valid for up to an hour, is refused at token exchange. `scripts/governance_checks.py` shows this
with an SVID held across the change.

Try it yourself (the admin password is `admin`; see `.env.example`):

```bash
printf 'dn: cn=remediation-agent,ou=agents,dc=demo,dc=local\nchangetype: modify\nreplace: icamLifecycleStatus\nicamLifecycleStatus: disabled\n' \
  | docker compose exec -T ldap ldapmodify -x -H ldap://localhost -D cn=admin,dc=demo,dc=local -w admin
docker compose logs directory-sync | tail -3   # "SPIRE: revoked spiffe://demo.local/agent/remediation-agent (...)"
```

## Vault: SPIRE's issuing CA and a credential broker for legacy systems

```
 Enterprise root (pki-init) ──signs CSR──► Vault pki_spire: "Demo Enterprise SPIRE Issuing CA" (key never leaves Vault)
                                              ▲ AppRole spire-server (may only call root/sign-intermediate)
 SPIRE Server ── UpstreamAuthority "vault" ───┘ at every SPIRE CA rotation

 Agent ── delegated token (aud includes https://vault:8200) ──► Vault auth/jwt role agent-inventory
          (bound: act.sub = demo.local agent, scope contains systems:read; entity = the user)
       ◄── 5-minute PostgreSQL user  v-jwt-<user>-inventor-…  (SELECT on assets only)
       ── SQL ──► inventory-db (legacy: understands database users, not OAuth)
       ── revoke-self ──► Vault drops the database user immediately
```

- **No standing secrets:** the agent never holds a database password beyond one task, and the
  database user is named after the *end user*, so the database's own logs show on whose behalf it acted.
- **Same governance:** Vault is just another resource. The directory decides whether an agent
  may use it (`icamAllowedResource: https://vault:8200`), and the delegated scope decides what it gets.
- **Audit:** Vault's audit device (stdout of `vault`) records user, agent (`act.sub`), policy and path.
- **Known gap (`security_checks.py` reports it as `GAP`):** Vault's JWT auth can't check `cnf`, so a
  delegated token lifted from one agent can be redeemed at Vault by another workload during its
  5-minute life. Closing it needs a custom Vault auth plugin that binds JWT and mTLS, or a broker
  in front of Vault. That's one of the custom-software items below.

## Mapping to a customer estate (SailPoint IIQ, RadiantLogic FID, PingFederate, Vault)

| Demo component | Customer product | Notes |
|---|---|---|
| OpenLDAP `ou=people`, `ou=agents` | **RadiantLogic FID** view | Point `config/directory-mapping.yaml` at the FID view: base DNs, filters, attribute names. Users are found by search and then bound, so no DN layout is assumed. `governance_checks.py` verifies an FID-style mapping (compound filters, no schema) gives identical results. |
| Lifecycle edits (`ldapmodify` in the checks) | **SailPoint IIQ** | Agents as a non-human identity type with owner = sponsor, certifications, and a leaver rule suspending owned agents. IIQ provisions `status`, `expires`, `ceiling` and `selectors` to the directory/FID. |
| `pf-configurator` | **PingFederate** | Config-as-code. The OGNL policy expressions should become a supported PingFederate SDK plugin. |
| Vault (`vault`, `vault-init`, `vault-config`) | **HashiCorp Vault** | As here: PKI mount as SPIRE's upstream CA (HSM-backed keys in Enterprise), JWT auth for delegated tokens, database secrets engine. |
| SPIRE | (new platform) | The only component they don't already run. |

Custom software still worth building on that estate: the IIQ → FID → SPIRE/PingFederate/Vault
**event-driven reconciler** (`directory-sync` is the prototype; FID can push changes instead of
polling); a **PingFederate plugin** replacing the OGNL; a **Vault auth plugin or broker** with
certificate binding (the `GAP` above); an **MCP/egress gateway**; and **audit correlation**
across PingFederate, Vault, SPIRE and IIQ.

## The policy

Scopes, the portal client and federation rules are in [`config/idp-policy.yaml`](config/idp-policy.yaml).
User entitlements and agent ceilings are in the directory ([`directory/seed.ldif`](directory/seed.ldif)).
`directory-sync` merges them into the effective policy that both IdP modes enforce. Each task
needs `systems:read systems:analyze metrics:read tickets:read tickets:write`.

| | analysis-agent ceiling<br>`systems:read systems:analyze metrics:read tickets:read` | remediation-agent ceiling<br>`systems:read tickets:read tickets:write` |
|---|---|---|
| **alice** (all five scopes) | `systems:read systems:analyze metrics:read tickets:read`. Tries to open a ticket anyway and gets **403** from the MCP server | `systems:read tickets:read tickets:write`. Opens a ticket, but **can't** see metrics or run diagnostics |
| **bob** (`systems:read metrics:read`) | `systems:read metrics:read` | `systems:read` |

Neither the user's entitlements nor the agent's ceiling can be exceeded, and an
agent only gets what the task asked for.

**Egress to `partner.example`** (`federation` in the same file, plus the partner's own
[`config/partner-policy.yaml`](config/partner-policy.yaml)):

| | analysis-agent (egress `partner:status.read`) | remediation-agent (egress `partner:status.read partner:cases.write`) |
|---|---|---|
| **alice** (both partner scopes) | reads vendor status; opening a support case gets **403** from the partner | reads vendor status and **opens a support case** |
| **bob** (`partner:status.read`) | reads vendor status | reads vendor status; opening a case gets **403** |

## Security properties demonstrated (`scripts/security_checks.py`)

| Attack / violation | Stopped by |
|---|---|
| Token exchange without an SVID | mTLS client auth required for the agent clients |
| Agent B presents its SVID but claims to be agent A | SVID must match the client registration (SAN URI / subject DN) |
| Agent asks for more than its ceiling | client scope restriction → `invalid_scope` |
| Agent asks for a scope the user isn't entitled to | AS policy (PingFederate: issuance criterion) |
| Stolen delegated token replayed by another workload | `cnf.x5t#S256` certificate binding |
| Agent uses the user's raw token at a resource | audience restriction, no `cnf` |
| Non-workload client calls a resource | TLS handshake requires a SPIFFE client cert |
| Re-delegating a delegated token | subject token must be a user token from the portal |
| Federation grant redeemed by a different workload | partner AS: grant `cnf` must match the mTLS client certificate |
| Federation grant redeemed twice | partner AS: single-use `jti`, consumed only after holder-of-key passes (no DoS by burning) |
| Grant requested for a partner not on the agent's allowlist | our AS: `invalid_target` |
| Egress scope smuggled into an internal token | our AS: egress scopes only inside a federation grant |
| Internal token presented to the partner API | partner API trusts only the partner AS as issuer |
| Partner token replayed by a different workload | partner API: `cnf` binding |
| Agent leaves its approved plan (REST or MCP, another system) | resources: `authorization_details` system binding |
| Discovery token used to read a system | resources: `system_catalog` allows the catalog only |
| Sensitive target without the user's approval | agent policy check; the portal holds the plan server-side |
| User token / token without Vault audience used at Vault; Vault token used beyond policy | Vault JWT role `bound_audiences`, `bound_claims`, least-privilege policy |
| Database credentials outliving the task | `revoke-self` drops the dynamic user |

## Layout

```
docker-compose.yml               the stack
docker-compose.pingfederate.yml  overlay: real PingFederate 13.1 instead of the simulator
config/idp-policy.yaml           base policy: scopes, portal client, agent-client template, federation
config/directory-mapping.yaml    where people/agents live in the directory + attribute names (FID, AD, ...)
vault/vault.hcl, inventory-db/   Vault server config; the legacy inventory database
directory/                       OpenLDAP image: icam schema, ACLs, seed (people + agent NPEs)
config/partner-policy.yaml       the external partner's own policy
spire/                           server/agent config (demo.local + partner/), PKI, federation + registration
services/icam/
  common/                        Workload API helper, JWT validation
  idp/                           PingFederate-compatible AS (simulator)
  pfconfig/                      admin-API configurator for real PingFederate
  portal/                        Agentic AI Service
  agent/                         runtime (per-task process) + agent instance
  resources/                     systems-api (REST) and ops-mcp (MCP)
  partner/                       the external partner: authorization server + API
  directory/                     LDAP access (mapping-driven) + directory-sync (SPIRE entries, effective policy)
  vaultsetup/                    Vault init/unseal, SPIRE issuing CA, AppRole, JWT auth, database role
scripts/                         smoke, security and governance checks (both modes)
pingfederate/                    real-PingFederate guide; license/ (git-ignored)
deploy/reverse-proxy/            example overlay: nginx in front of the portal and the IdP
```

## Public URLs, DNS and reverse proxies

Browsers use two URLs; everything else talks container to container. Both URLs come from `.env`:

| Setting | Default | Drives |
|---|---|---|
| `PORTAL_PUBLIC_URL` | `http://localhost:8080` | the portal's links and redirect URI (`<url>/callback`), the registered redirect URI in the IdP (`config/idp-policy.yaml` uses `${PORTAL_PUBLIC_URL}`, filled in by `directory-sync`), `Secure` cookies when HTTPS |
| `PF_PUBLIC_URL` | `http://localhost:9031` (simulator), `https://localhost:9031` (PingFederate) | the issuer (`iss`) every service, Vault and the partner AS validate, the discovery document's endpoints, **PingFederate's base URL** (set by `pf-configurator`), and an extra name on PingFederate's TLS certificate |
| `TRUSTED_PROXY_HOPS` | `0` | how many proxies' `X-Forwarded-*` headers the portal trusts (0: ignored, so clients can't spoof them) |
| `PF_ADMIN_PUBLIC_URL`, `PF_TLS_EXTRA_SANS` | | PingFederate's admin-console URL; more names on its certificate |

Containers keep using `pingfederate`, `systems-api` and so on. Agents, resources, Vault and the
portal's back channel rewrite public IdP URLs to the internal name (`PF_INTERNAL_BASE`), so the
proxy only carries browser traffic. Change the URLs and run `up -d` again. The certificate,
PingFederate's base URL and the redirect URI follow without `down -v`.

**What not to proxy:** the token-exchange endpoint agents use (`pingfederate:9032`, simulator
`:9443`). Agents authenticate there with their SVID as a TLS client certificate, and the delegated
token is bound to it (`cnf`). A proxy that terminates TLS would strip that certificate. Keep it
internal, or use TLS passthrough.

`deploy/reverse-proxy/` is a working example: nginx terminating TLS for both host names, with a
certificate from the demo enterprise CA. The three test scripts pass through it in both modes.

```bash
# /etc/hosts (or real DNS): 127.0.0.1 portal.demo.test sso.demo.test
cat >> .env <<'EOF'
PORTAL_PUBLIC_URL=https://portal.demo.test
PF_PUBLIC_URL=https://sso.demo.test
TRUSTED_PROXY_HOPS=1
# PF_UPSTREAM=https://pingfederate:9031     # with docker-compose.pingfederate.yml
EOF
docker compose -f docker-compose.yml [-f docker-compose.pingfederate.yml] \
  -f deploy/reverse-proxy/docker-compose.proxy.yml up -d --build --wait
python3 scripts/smoke_test.py   # the scripts read the URLs from .env
```

Trust `/pki/enterprise/root-ca.crt` from the `spire-pki` volume in your browser, or put your own
certificate on the proxy (then set `PUBLIC_CA_BUNDLE` for the scripts).

## Demo shortcuts (not for production)

- In-memory portal sessions. In mode A, the simulator also keeps codes in memory and creates a fresh
  signing key on every restart, so sign in again after a restart.
- Plain HTTP for the portal and the portal-to-runtime hop, and in mode A for the IdP's browser endpoints.
  The workload hops always use mTLS.
- Workload selectors use a single container label. In production, pin image digests
  (`docker:image_config_digest`) or use the Kubernetes attestor.
- Werkzeug's development server serves the Python services.
- Demo passwords and service-account secrets: `.env.example`, `directory/seed.ldif`. The client
  secret and pairwise salt are in `config/idp-policy.yaml`.
- LDAP runs without TLS (`ldap://`) on the internal network (set `LDAP_TLS_CA` with an `ldaps://`
  URL for LDAPS). The enterprise root key is a file; real roots are offline in an HSM.
- Vault uses one unseal key stored in the `vault-keys` volume and file storage. In production use
  Raft storage, auto-unseal (HSM/KMS) and no persisted root token.
- `directory-sync` polls every 10 s. A production version would use persistent search or a change
  log, and the IGA tool would write lifecycle changes.
- Both trust domains run on one Docker host and network. A real partner would be reachable only
  through its public endpoints: the SPIFFE bundle endpoint, its AS and its API. Its JWKS
  fetch from our IdP would go over the internet.
- Agents call the partner directly. An **egress gateway** that performs steps 11–13 on the
  agents' behalf, adding a partner allowlist, DLP and rate limits, is a common production variant.
