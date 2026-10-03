# Agentic AI ICAM stack (demo)

A Docker Compose demo of **identity-aware AI agents**. A user signs in with
PingFederate (OIDC + PKCE) and gives an agent a task. The agent instance gets its
own **SPIFFE workload identity** from SPIRE. It then **exchanges the user's token**
for a short-lived delegated token, scoped to *User ∩ Agent ∩ Requested* and bound
to the agent's X.509-SVID, and uses that token to call enterprise REST and MCP
resources over mTLS.

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
```

## Quick start

```bash
docker compose up -d --build --wait
open http://localhost:8080          # sign in as alice/alice or bob/bob
```

To check everything from the command line (needs `pip install requests`):

```bash
python3 scripts/smoke_test.py        # full browser flow, 2 users × 2 agents, asserts scope intersection
python3 scripts/security_checks.py   # 6 attacks that must fail + 1 positive control
```

Stop with `docker compose down`. Add `-v` to also wipe SPIRE state.

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
| `pingfederate` | PingFederate (PingFederate-compatible simulator by default, [real one via overlay](pingfederate/README.md)) | `localhost:9031` HTTP, `9443` mTLS token endpoint |
| `analysis-agent`, `remediation-agent` | Agent Runtime. Each task runs in a **new agent instance process** | internal `8090` |
| `spire-server` | SPIRE Server: trust domain `demo.local`, x509pop node attestation | internal |
| `spire-agent` | SPIRE Agent: Workload API socket, docker workload attestor | internal |
| `systems-api` | Enterprise REST API (inventory, metrics, diagnostics) | internal `8443` mTLS |
| `ops-mcp` | Enterprise MCP server (runbooks, tickets), Streamable HTTP, OAuth per tool | internal `8443` mTLS |
| `pki-init`, `spire-register` | One-shot jobs: node-attestation PKI, registration entries, trust bundle | – |

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
8. **Token exchange**: RFC 8693 request to the RFC 8705 `mtls_endpoint_aliases` token
   endpoint. The client authenticates with `tls_client_auth`, and the SVID's SAN URI
   must match the client registration. `subject_token` = user's token;
   `resource` = the two enterprise resources.
9. **Delegated token**: `scope = user ∩ agent ceiling ∩ requested`, `sub = user`,
   `act.sub = agent SPIFFE ID`, `cnf.x5t#S256 = SVID thumbprint`, `aud = resources`,
   5 min TTL. Exchanging a delegated token again is refused.
10. **API / MCP calls**: mTLS with the SVID, with the bearer token checked at each resource for
    signature, issuer, audience, **certificate binding**, **actor = mTLS peer**, and scope.
    Missing scope returns `403 insufficient_scope` (MCP authorization spec style).

The UI shows every step with its details. Step 9 renders the scope intersection and
step 10 shows each call's allow/deny decision.

## The policy

Defined in [`config/idp-policy.yaml`](config/idp-policy.yaml). Each task requests
`systems:read systems:analyze metrics:read tickets:read tickets:write`.

| | analysis-agent ceiling<br>`systems:read systems:analyze metrics:read tickets:read` | remediation-agent ceiling<br>`systems:read tickets:read tickets:write` |
|---|---|---|
| **alice** (all five scopes) | `systems:read systems:analyze metrics:read tickets:read`. Wants to open a ticket, gets **403** | `systems:read tickets:read tickets:write`. Opens a ticket, but **can't** see metrics or run diagnostics |
| **bob** (`systems:read metrics:read`) | `systems:read metrics:read` | `systems:read` |

Neither the user's entitlements nor the agent's ceiling can be exceeded, and an
agent only gets what the task asked for.

## Security properties demonstrated (`scripts/security_checks.py`)

| Attack | Stopped by |
|---|---|
| Token exchange without an SVID | mTLS client auth required for the token-exchange grant |
| Agent B presents its SVID but claims to be agent A | SAN URI must match the client's registered SPIFFE ID |
| Stolen delegated token replayed by another workload | `cnf.x5t#S256` certificate binding |
| Agent uses the user's raw token at a resource | audience restriction, no `cnf` |
| Non-workload client calls a resource | TLS handshake requires a SPIFFE client cert |
| Re-delegating a delegated token | subject-token audience check / no nested `act` |

## Layout

```
docker-compose.yml               the stack
docker-compose.pingfederate.yml  overlay: real PingFederate instead of the simulator
config/idp-policy.yaml           users, clients, agent ceilings
spire/                           server/agent config, PKI + registration scripts
services/icam/
  common/                        Workload API helper, JWT validation
  idp/                           PingFederate-compatible AS
  portal/                        Agentic AI Service
  agent/                         runtime (per-task process) + agent instance
  resources/                     systems-api (REST) and ops-mcp (MCP)
scripts/                         smoke test and security checks
pingfederate/README.md           mapping onto real PingFederate configuration
```

## Demo shortcuts (not for production)

- In-memory sessions and codes, and a fresh AS signing key on every restart (sign in again after a restart).
- Plain HTTP for the browser-facing hops and the portal-to-runtime hop. The workload hops use mTLS.
- Workload selectors use a single container label. In production, pin image digests
  (`docker:image_config_digest`) or use the Kubernetes attestor.
- Werkzeug's development server serves the Python services.
- Demo passwords and client secret are in `config/idp-policy.yaml`.
