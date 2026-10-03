from werkzeug.serving import make_server

from icam.common.spiffe_identity import WorkloadIdentity


def serve_mtls(app, log, port: int = 8443):
    """Serve `app` over mTLS using this workload's SVID; peers must present SVIDs too."""
    identity = WorkloadIdentity(workdir="/run/svid")
    identity.wait_for_svid()
    identity.start_rotation()
    ctx = identity.server_context(require_client_cert=True)
    log.info("listening on :%d as %s (mTLS, SPIFFE peers only)", port, identity.info["spiffe_id"])
    make_server("0.0.0.0", port, app, threaded=True, ssl_context=ctx).serve_forever()
