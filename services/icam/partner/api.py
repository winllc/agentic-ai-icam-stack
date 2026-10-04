"""The partner's external API (trust domain partner.example). Accepts only tokens from the
partner's own AS - never demo.local's tokens - bound to the caller's SVID."""

import itertools
import os

from flask import Flask, g, jsonify, request

from icam.common import logs
from icam.resources.auth import audit_view, principal, requires
from icam.resources.serve import serve_mtls

log = logs.setup("partner-api")
app = Flask(__name__)
REALM = "partner-api"
RESOURCE = os.environ["RESOURCE_URI"]
AS = os.environ["PF_ISSUER"]
case_seq = itertools.count(7001)

SERVICES = {   # the partner's view of the services it provides to demo.local
    "fraud-scoring": {"status": "degraded", "incident": "PX-311: elevated latency in us-east-1 scoring cluster",
                      "since": "2026-10-03T01:12:00Z", "eta": "mitigation in progress"},
    "backup-vault": {"status": "operational", "incident": None},
    "payroll-gateway": {"status": "operational", "incident": None},
}


@app.get("/.well-known/oauth-protected-resource")
def protected_resource_metadata():
    """RFC 9728: tells a client which authorization server issues tokens for this API."""
    return jsonify(resource=RESOURCE, authorization_servers=[AS], bearer_methods_supported=["header"],
                   scopes_supported=["partner:status.read", "partner:cases.write"],
                   tls_client_certificate_bound_access_tokens=True)


@app.get("/v1/services/<name>/status")
@requires("partner:status.read", REALM)
def status(name):
    svc = SERVICES.get(name)
    if not svc:
        return jsonify(error="not_found"), 404
    return jsonify(service=name, **svc, authorized=principal(), federated=g.claims.get("federated"))


@app.post("/v1/support-cases")
@requires("partner:cases.write", REALM)
def open_case():
    body = request.get_json(force=True, silent=True) or {}
    case = {"id": f"CASE-{next(case_seq)}", "service": body.get("service"), "summary": body.get("summary"),
            "requested_by": g.claims["sub"],   # pairwise id: the partner never learns who it is
            "via_agent": principal()["actor"], "origin": g.claims.get("federated", {}).get("iss")}
    log.info("support case %s", case)
    return jsonify(case=case, authorized=principal()), 201


@app.get("/audit")
def audit():
    return audit_view()


if __name__ == "__main__":
    serve_mtls(app, log, trust_federated=True)
