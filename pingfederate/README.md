# Running with a real PingFederate

`docker-compose.pingfederate.yml` replaces the simulator with **PingFederate 13.1**
(`pingidentity/pingfederate:2609-13.1.3`). `pf-configurator` configures it completely
through the admin API from [`config/idp-policy.yaml`](../config/idp-policy.yaml), the
same file the simulator reads. Nothing is configured by hand.

Tested end to end on PingFederate 13.1.3 with a development license.
`scripts/smoke_test.py` passes 4/4 (steps 1–14, including the cross-domain call to
`partner.example`), `scripts/security_checks.py` passes 24/24 (plus one reported Vault GAP) and `scripts/governance_checks.py` 7/7. A
forced SPIRE CA rotation and a re-created PingFederate container both recover
automatically.

## Start

```bash
cp /path/to/pingfederate.lic pingfederate/license/pingfederate.lic   # never committed (.gitignore)
chmod 0644 pingfederate/license/pingfederate.lic                      # PingFederate runs as uid 9031
docker compose -f docker-compose.yml -f docker-compose.pingfederate.yml up -d --build --wait
python3 scripts/smoke_test.py && python3 scripts/security_checks.py
```

- App: http://localhost:8080. PingFederate runtime: https://localhost:9031.
  Admin console: https://localhost:9999/pingfederate/app (`administrator` / `2FederateM0re`;
  override with `PF_ADMIN_PASSWORD`).
- PingFederate's TLS certificate chains to the **Demo Enterprise Root CA** created by `pki-init`.
  To stop browser warnings, trust that root:
  `docker compose cp pki-init:/pki/enterprise/root-ca.crt .` (or copy it out of the `spire-pki` volume).
- Delete `-v` volumes with `docker compose -f docker-compose.yml -f docker-compose.pingfederate.yml down -v`.

## What `pf-configurator` creates

| Demo policy | PingFederate object |
|---|---|
| first start | accepts the license agreement, creates the initial administrator |
| `scopes` | OAuth common scopes. `disallowPlainPKCE` is set. |
| people | **LDAP data store** `directory` (`cn=idp` service account) → **LDAP Username Password Credential Validator** (`uid=${username}` under `ou=people`) → HTML Form IdP Adapter → IdP adapter grant mapping |
| directory layout | Base DN, filters and attribute names come from `config/directory-mapping.yaml`, the same file `directory-sync` and the simulator use. Point it at a RadiantLogic FID view or AD. |
| user `entitlements`, `name`, `email`, `groups` | **LDAP attribute source** on the user-token mapping (`uid=${USER_KEY}`). Read at issuance; multi-valued `icamEntitlement` joined with OGNL `#this.get("ds.people.icamEntitlement")`. |
| user access token | JWT ATM `useratm`: RS256 with the central signing key (`/pf/JWKS`), `iss=https://localhost:9031`, `aud=agentic-ai-service` |
| ID token | OIDC policy `portaloidc` (`sub`, `name`, `email`, `groups`) |
| `agentic-ai-portal` | Authorization Code, **PKCE required**, client secret, restricted scopes |
| subject-token validation | OAuth Bearer Access Token processor `userat` (validates against `useratm`) |
| token exchange | processor policy `agentdelegation`. Requires a subject token from `agentic-ai-portal` with `aud=agentic-ai-service`. |
| agent clients (from LDAP `ou=agents` via `directory-sync`) | **enabled = lifecycle active and not expired**; restricted scopes = `icamScopeCeiling`. Client auth **CERTIFICATE**: subject DN `CN=<agent>, O=SPIRE, C=US` (stable in SPIRE SVIDs), issuer DN = current SPIRE CA. Grant type Token Exchange; **restricted scopes = agent ceiling**. |
| delegated token | JWT ATM `delegatedatm` (5 min) with resource URIs. Mapping from the policy (OGNL over `context.HttpRequest`) adds:<br>`act = {"sub": "spiffe://demo.local/agent/<client>"}`<br>`cnf = {"x5t#S256": SHA-256 of the client's mTLS certificate}`<br>`aud = requested resource(s)` |
| User ∩ Agent ∩ Requested | **Agent:** PingFederate rejects scopes outside the client's restricted scopes (`invalid_scope`).<br>**User:** an issuance criterion rejects any requested scope not in the subject token's `entitlements` and `scope`.<br>**Resources:** a second criterion allows only the registered resource servers. |
| federation grant (steps 11–12) | JWT ATM `fedgrantpartnerexample` (1 min), selected by `resource = https://partner-as:8443`, from the same processor policy. The mapping computes a **pairwise `sub`** (SHA-256 of user, trust domain and salt in OGNL, identical to the simulator) and adds `act`, `cnf` and `aud`. Criteria: User bound, exactly the partner AS as resource, only that partner's egress scopes. Agent clients aren't restricted to the default ATM, so `resource` can select it. The internal mapping rejects egress scopes. |
| runtime TLS | `runtime-tls` key pair from the **enterprise TLS issuing CA** (`pki-init`), SAN `pingfederate`, `localhost` |
| mTLS listener | `PF_ENGINE_SECONDARY_PORT=9032`: agents call `https://pingfederate:9032/as/token.oauth2` |
| SPIRE trust | Enterprise root (the SPIFFE bundle) plus the intermediates in the SVID chain (the current SPIRE CA and the SPIRE issuing CA) in **Trusted CAs**. PingFederate matches a client's issuer DN against a trusted CA, so the rotating SPIRE CA must be present. |

After the initial run the configurator keeps running. Every 10 seconds it:
- imports new SPIRE CAs and updates the agent clients' issuer DN after a rotation (SPIRE puts a
  random `serialNumber` in each CA subject, and PingFederate matches the issuer DN exactly);
- re-applies the agent clients when `directory-sync` renders a directory change: lifecycle, ceiling, resources;
- re-applies everything if PingFederate comes back empty, for example after the container is re-created;
- exits after repeated failures, so Docker restarts it and it re-pins the admin certificate.

The admin API is reached over a TLS connection **pinned to the certificate first seen**.
The admin console's certificate is self-signed, so chain validation isn't possible. The
pin is enforced on every connection instead of disabling verification.

## Behavior differences vs. the simulator

- PingFederate never narrows scope: a request outside User ∩ Agent is **rejected**. The
  simulator does the same, so in both modes the agent requests `task ∩ its ceiling ∩ the user's scopes`.
  The agent reads its ceiling from its own client entry in `config/idp-policy.yaml`.
- PingFederate doesn't advertise RFC 8705 `mtls_endpoint_aliases`, so agents get the mTLS
  endpoint from `PF_MTLS_TOKEN_ENDPOINT`.
- The user access token carries every portal scope the user requested. Per-user limits travel
  in its `entitlements` claim, and token exchange enforces them.
- For the federation grant the agent sends no `requested_token_type`. PingFederate only issues
  `urn:ietf:params:oauth:token-type:jwt` through token-generator plugins, so it would reject
  that type. The grant comes from the federation-grant ATM, which already issues a signed JWT.
- **Task binding (RFC 9396).** PingFederate 13.1 has no processor for custom
  `authorization_details` types, so it rejects the standard parameter. The agents therefore run
  with `AUTHZ_DETAILS_TRANSPORT=params` and send `task_system=<id>` (repeated) or
  `task_catalog=true`. The delegation mapping turns these into the same `authorization_details`
  claim the simulator issues, and an issuance criterion allows only 1–3 lowercase system ids.
  Resources enforce the claim identically in both modes. A production deployment would use an
  SDK authorization-detail processor plugin instead (another custom-software item).
- PingFederate's JWT serializer collapses one-element lists into a plain value
  (`"aud": "x"`, a single `authorization_details` object). Resources accept both shapes.
- Logout goes through PingFederate's `/idp/init_logout.openid` (OIDC RP-initiated logout),
  which shows a confirmation page.

## Notes for production

- The `act`/`cnf`/`aud` OGNL reads the token-exchange request directly. Review it against your
  PingFederate version, and keep the expression administrator role restricted.
- In production, replace the label-only SPIRE selectors with image digests or Kubernetes
  attestation, and federate the trust bundle instead of copying CAs.
