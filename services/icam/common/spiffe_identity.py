"""SPIFFE Workload API helper: fetch an X.509-SVID + trust bundle and turn them
into TLS material for servers (mTLS listeners) and clients (requests)."""

import base64
import hashlib
import logging
import os
import ssl
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from spiffe import WorkloadApiClient

log = logging.getLogger("spiffe")

DEFAULT_SOCKET = "unix:///run/spire/sockets/agent.sock"


def x5t_s256(cert: x509.Certificate) -> str:
    """RFC 8705 certificate thumbprint (base64url SHA-256 of the DER cert)."""
    digest = hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def spiffe_ids(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [u for u in san.get_values_for_type(x509.UniformResourceIdentifier) if u.startswith("spiffe://")]


def describe_cert(cert: x509.Certificate) -> dict:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        dns = []
    return {
        "spiffe_id": (spiffe_ids(cert) or [None])[0],
        "dns_names": dns,
        "serial": format(cert.serial_number, "x"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "x5t#S256": x5t_s256(cert),
    }


def peer_cert_from_environ(environ) -> x509.Certificate | None:
    """werkzeug's dev server exposes the verified client cert as SSL_CLIENT_CERT (PEM)."""
    pem = environ.get("SSL_CLIENT_CERT")
    return x509.load_pem_x509_certificate(pem.encode()) if pem else None


class WorkloadIdentity:
    """Holds this workload's current X.509-SVID, written to disk for ssl/requests."""

    def __init__(self, workdir: str | None = None, socket_path: str | None = None):
        self.socket_path = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET", DEFAULT_SOCKET)
        self.dir = Path(workdir or tempfile.mkdtemp(prefix="svid-"))
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.dir / "svid.pem"
        self.key_path = self.dir / "svid.key"
        self.bundle_path = self.dir / "bundle.pem"              # own trust domain only
        self.federated_bundle_path = self.dir / "bundles-all.pem"  # own + federated trust domains
        self.info: dict | None = None
        self._server_contexts: list[ssl.SSLContext] = []
        self._lock = threading.Lock()

    def fetch(self) -> dict:
        """One Workload API call: the SPIRE Agent attests the caller and returns its SVID(s)."""
        with WorkloadApiClient(socket_path=self.socket_path) as client:
            ctx = client.fetch_x509_context(timeout=10)
        svid = ctx.default_svid
        bundle = ctx.x509_bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        with self._lock:
            svid.save(self.cert_path, self.key_path, Encoding.PEM)
            os.chmod(self.key_path, 0o600)
            bundle.save(self.bundle_path, Encoding.PEM)
            authorities = [a for b in ctx.x509_bundle_set.bundles for a in b.x509_authorities]
            self.federated_bundle_path.write_bytes(b"".join(a.public_bytes(Encoding.PEM) for a in authorities))
            self.info = describe_cert(svid.leaf)
            self.info["trust_domain"] = str(svid.spiffe_id.trust_domain)
            self.info["bundle_authorities"] = len(bundle.x509_authorities)
            self.info["federated_trust_domains"] = sorted(
                str(b.trust_domain) for b in ctx.x509_bundle_set.bundles if b.trust_domain != bundle.trust_domain)
            for c, federated in self._server_contexts:
                c.load_cert_chain(self.cert_path, self.key_path)
                c.load_verify_locations(cafile=str(self.federated_bundle_path if federated else self.bundle_path))
        return self.info

    def wait_for_svid(self, attempts: int = 60, delay: float = 2.0) -> dict:
        last = None
        for i in range(attempts):
            try:
                info = self.fetch()
                log.info("obtained X.509-SVID %s (expires %s)", info["spiffe_id"], info["not_after"])
                return info
            except Exception as exc:  # agent not up yet / entry not registered yet
                last = exc
                log.warning("waiting for SVID (%d/%d): %s", i + 1, attempts, exc)
                time.sleep(delay)
        raise RuntimeError(f"could not obtain an X.509-SVID from {self.socket_path}: {last}")

    def server_context(self, require_client_cert: bool = True, trust_federated: bool = False) -> ssl.SSLContext:
        """TLS server context presenting our SVID and verifying peers against the SPIFFE bundle
        (plus federated trust domains' bundles when trust_federated is set)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert_path, self.key_path)
        ctx.load_verify_locations(cafile=str(self.federated_bundle_path if trust_federated else self.bundle_path))
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
        self._server_contexts.append((ctx, trust_federated))
        return ctx

    def start_rotation(self, interval: int = 30) -> None:
        """Re-fetch periodically for long-running servers: SVIDs are short-lived (1h) and the
        trust bundle changes when SPIRE rotates its CA - peers with new-CA SVIDs must be accepted."""

        def loop():
            while True:
                time.sleep(interval)
                try:
                    self.fetch()
                    log.info("rotated SVID, new expiry %s", self.info["not_after"])
                except Exception as exc:
                    log.error("SVID rotation failed: %s", exc)

        threading.Thread(target=loop, daemon=True, name="svid-rotation").start()

    @property
    def client_cert(self) -> tuple[str, str]:
        return str(self.cert_path), str(self.key_path)
