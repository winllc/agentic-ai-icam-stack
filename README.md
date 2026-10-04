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
and its CA is chained to an enterprise PKI root, so SVIDs validate in ordinary trust stores.

```
User ─1─► Agentic AI Service ─2 OIDC+PKCE─► PingFederate ─3 tokens─► Agentic AI Service
                                                                            │ 4 "Analyze system X"
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

Open http://localhost:8080 and sign in as `alice/alice` or `bob/bob`. In mode B the login page
is PingFederate's own, at `https://localhost:9031`. Its certificate comes from a demo CA you can
trust in your browser.

To check everything from the command line (needs `pip install requests`). Both scripts detect the mode:

```bash
python3 scripts/smoke_test.py        # browser flow, 2 users × 2 agents, steps 1-14, scope intersections + cnf/act
python3 scripts/security_checks.py   # 14 attacks/policy violations that must fail + 2 positive controls
python3 scripts/governance_checks.py # directory-driven lifecycle: disable, expire, narrow, revoke (~3 min)
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
8. **Token exchange**: RFC 8693 request to PingFederate's mTLS token endpoint. The client
   authenticates with its SVID: the simulator matches the SAN URI, and PingFederate matches
   the SVID's subject/issuer DN. `subject_token` = user's token, `resource` = the two
   enterprise resources. `scope` = what the task needs ∩ the agent's ceiling ∩ the user's
   scopes. The AS **rejects** anything outside User ∩ Agent; it never silently narrows.
9. **Delegated token**: `scope` = exactly that intersection, `sub = user`,
   `act.sub = agent SPIFFE ID`, `cnf.x5t#S256 = SVID thumbprint`, `aud = resources`,
   5 min TTL. Exchanging a delegated token again is refused.
10. **API / MCP calls**: mTLS with the SVID, with the bearer token checked at each resource for
    signature, issuer, audience, **certificate binding**, **actor = mTLS peer**, and scope.
    Missing scope returns `403 insufficient_scope` (MCP authorization spec style).

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

 Demo Enterprise Root CA ─┬─ SPIRE Issuing CA ── SPIRE CA (rotates) ── X.509-SVIDs (1 h)
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

## Layout

```
docker-compose.yml               the stack
docker-compose.pingfederate.yml  overlay: real PingFederate 13.1 instead of the simulator
config/idp-policy.yaml           base policy: scopes, portal client, agent-client template, federation
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
  directory/                     LDAP access + directory-sync (SPIRE entries, effective policy)
scripts/                         smoke, security and governance checks (both modes)
pingfederate/                    real-PingFederate guide; license/ (git-ignored)
```

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
- LDAP runs without TLS (`ldap://`) on the internal network, and the enterprise PKI keys are files.
  In production use LDAPS and keep CA keys in an HSM. SPIRE supports HSM-backed and cloud-KMS
  upstream authorities.
- `directory-sync` polls every 10 s. A production version would use persistent search or a change
  log, and the IGA tool would write lifecycle changes.
- Both trust domains run on one Docker host and network. A real partner would be reachable only
  through its public endpoints: the SPIFFE bundle endpoint, its AS and its API. Its JWKS
  fetch from our IdP would go over the internet.
- Agents call the partner directly. An **egress gateway** that performs steps 11–13 on the
  agents' behalf, adding a partner allowlist, DLP and rate limits, is a common production variant.
