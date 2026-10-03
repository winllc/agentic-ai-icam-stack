# Running against a real PingFederate

The default stack uses `services/icam/idp`, a small **PingFederate-compatible
authorization server**. It serves PingFederate's endpoint paths
(`/as/authorization.oauth2`, `/as/token.oauth2`, `/pf/JWKS`,
`/idp/userinfo.openid`, `/idp/startSLO.ping`) and its policy comes from
[`config/idp-policy.yaml`](../config/idp-policy.yaml). The simulator lets the demo
run with no license. The other services rely only on standards (OIDC discovery,
PKCE, RFC 8693, RFC 8705, RFC 8707), so they can point at a real PingFederate instead.

> **Status:** the overlay and the mapping below have **not** been run end to end
> against a licensed PingFederate. The automated checks (`scripts/smoke_test.py`,
> `scripts/security_checks.py`) run against the simulator. Admin console labels
> vary between PingFederate versions, so treat this as a configuration checklist.

## 1. Start PingFederate

```bash
cp .env.example .env    # set PING_IDENTITY_DEVOPS_USER / PING_IDENTITY_DEVOPS_KEY
docker compose -f docker-compose.yml -f docker-compose.pingfederate.yml up -d
# admin console: https://localhost:9999/pingfederate/app  (Administrator / 2FederateM0re by default)
```

To bring your own configuration, set `PF_SERVER_PROFILE_URL` and `PF_SERVER_PROFILE_PATH`
to a server profile. Otherwise, configure the objects below in the admin console or
through the admin API (`/pf-admin-api/v1`).

## 2. Trust in both directions

| What | How |
|---|---|
| PingFederate trusts agent SVIDs | Import `/opt/spire-pki/spire-bundle.pem` (mounted into the container) under **Security → Trusted CAs**. SPIRE rotates its CA (`ca_ttl` 168h), so re-import the bundle after rotation or use federation. |
| Services trust PingFederate's TLS cert | Export PingFederate's runtime server certificate (or its issuing CA) to `pingfederate/trust/pf-ca.pem`. The overlay mounts it and sets `PF_TLS_CA` / `REQUESTS_CA_BUNDLE`. Its SAN must include `pingfederate` and `localhost`. |
| mTLS listener | Enable the secondary HTTPS port for client-certificate authentication (`pf.secondary.https.port`). Advertise it as `mtls_endpoint_aliases.token_endpoint`, or set `PF_MTLS_TOKEN_ENDPOINT=https://pingfederate:<port>/as/token.oauth2` in `.env`. |
| Base URL | **System → Server Settings → Federation Info**: base URL `https://localhost:9031`. It must equal `PF_ISSUER`. |

## 3. Objects to create

| Demo policy (`idp-policy.yaml`) | PingFederate object |
|---|---|
| `scopes` | **OAuth Server → Scope Management**: `systems:read`, `systems:analyze`, `metrics:read`, `tickets:read`, `tickets:write` |
| `users` + `entitlements` | Password Credential Validator (Simple Username/Password, or LDAP in real life) + HTML Form IdP Adapter. Expose an `entitlements` attribute and use it to limit granted scopes, for example with an access-token-mapping OGNL issuance criterion or a policy that drops scopes the user isn't entitled to. |
| User access token | **JWT Access Token Manager**: RS256, publish keys at a JWKS endpoint, `aud = agentic-ai-service`. Map `sub`, `client_id`, `scope`, `name`, `groups`. If its JWKS URL is not `/pf/JWKS`, set `PF_JWKS_URL` in `.env`. |
| Client `agentic-ai-portal` | Authorization Code, **Require PKCE** (S256), client secret, redirect URI `http://localhost:8080/callback`, OIDC policy issuing the ID token (`name`, `email`, `groups`). |
| Clients `analysis-agent`, `remediation-agent` | Client authentication **Client TLS Certificate**, matched on the certificate's SAN URI `spiffe://demo.local/agent/<name>` (versions that only match Subject DN need the DN SPIRE puts in the SVID instead). Grant type **Token Exchange**. **Restrict scopes** to the agent ceiling: analysis gets `systems:read systems:analyze metrics:read tickets:read`; remediation gets `systems:read tickets:read tickets:write`. Allowed resources: `https://systems-api:8443`, `https://ops-mcp:8443/mcp`. |
| Delegation (User ∩ Agent ∩ Requested) | **Token Exchange Processor Policy** accepting `urn:ietf:params:oauth:token-type:access_token` subject tokens from the JWT ATM above. Map `sub` from the subject token. Add an `act` claim `{ "sub": <client SPIFFE ID> }`. Restrict scopes so that `requested ∩ client-allowed ∩ subject-token scope` holds. Client restriction covers the first two; the subject-token part needs an OGNL issuance criterion on the token-exchange access token mapping. |
| Delegated token | JWT ATM for the resources: `aud` = requested resource(s), short lifetime (5 min), certificate-bound (`cnf.x5t#S256`) when the client authenticated with mTLS. |

If your PingFederate version cannot emit `cnf` or `act` on exchanged tokens, the
resource servers can relax those checks: set `PF_REQUIRE_CNF=false` and/or
`PF_REQUIRE_ACT=false` in `.env`. Doing so drops the sender-constraint and
actor-identity guarantees that `scripts/security_checks.py` demonstrates.

## 4. Verify

```bash
python3 scripts/smoke_test.py        # expects the same scope intersections as the simulator
```

`demo_policy_evaluation` is an explanation field only the simulator returns. With
real PingFederate, step 9 in the UI shows the granted scope and claims, but not the
per-scope reasons.
