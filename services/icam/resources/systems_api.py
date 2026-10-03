"""Enterprise REST API: system inventory, telemetry and diagnostics."""

from flask import Flask, jsonify

from icam.common import logs
from icam.resources.auth import audit_view, principal, requires
from icam.resources.data import SYSTEMS
from icam.resources.serve import serve_mtls

log = logs.setup("systems-api")
app = Flask(__name__)
REALM = "systems-api"


def find(system_id):
    sys = SYSTEMS.get(system_id)
    return sys, (None if sys else (jsonify(error="not_found"), 404))


@app.get("/systems")
@requires("systems:read", REALM)
def list_systems():
    return jsonify(systems=[{"id": k, "name": v["name"], "status": v["status"]} for k, v in SYSTEMS.items()],
                   authorized=principal())


@app.get("/systems/<system_id>")
@requires("systems:read", REALM)
def get_system(system_id):
    sys, err = find(system_id)
    if err:
        return err
    fields = {k: v for k, v in sys.items() if k not in ("metrics", "diagnostics")}
    return jsonify(id=system_id, **fields, authorized=principal())


@app.get("/systems/<system_id>/metrics")
@requires("metrics:read", REALM)
def get_metrics(system_id):
    sys, err = find(system_id)
    if err:
        return err
    return jsonify(id=system_id, metrics=sys["metrics"], authorized=principal())


@app.post("/systems/<system_id>/diagnostics")
@requires("systems:analyze", REALM)
def run_diagnostics(system_id):
    sys, err = find(system_id)
    if err:
        return err
    return jsonify(id=system_id, diagnostics=sys["diagnostics"], authorized=principal())


@app.get("/audit")
def audit():
    return audit_view()


if __name__ == "__main__":
    serve_mtls(app, log)
