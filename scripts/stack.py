"""Helpers shared by the test scripts: detect which identity provider the stack runs
(the simulator or a real PingFederate) and drive the browser login form."""
import html
import os
import re
import subprocess
import tempfile
from urllib.parse import urljoin

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def setting(name: str, default: str | None = None) -> str | None:
    """The environment, else the project's .env (what docker compose used), else the default."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in open(os.path.join(ROOT, ".env")):
            key, _, value = line.strip().partition("=")
            if key == name and value:
                return value.strip().strip('"\'')
    except FileNotFoundError:
        pass
    return default


PORTAL = setting("PORTAL_PUBLIC_URL", "http://localhost:8080").rstrip("/")


def _ca_from_container(container: str, path: str) -> str | None:
    out = subprocess.run(["docker", "exec", container, "cat", path], capture_output=True, text=True)
    if out.returncode != 0 or "BEGIN CERTIFICATE" not in out.stdout:
        return None
    local = os.path.join(tempfile.gettempdir(), f"agentic-icam-{container}-ca.pem")
    with open(local, "w") as f:
        f.write(out.stdout)
    return local


def _ca_from_configurator() -> str | None:
    return _ca_from_container("agentic-icam-pf-configurator-1", "/pf-trust/pf-ca.pem")


class Stack:
    def __init__(self):
        self.ca = _ca_from_configurator()
        self.real_pf = self.ca is not None
        if self.real_pf:   # real PingFederate: HTTPS everywhere, mTLS on the secondary port
            self.pf = setting("PF_PUBLIC_URL", "https://localhost:9031").rstrip("/")
            self.mtls_token_endpoint = "https://pingfederate:9032/as/token.oauth2"
            self.container_ca = "/pf-trust/pf-ca.pem"
        else:              # simulator
            self.pf = setting("PF_PUBLIC_URL", "http://localhost:9031").rstrip("/")
            self.mtls_token_endpoint = "https://pingfederate:9443/as/token.oauth2"
            self.container_ca = None   # the simulator's TLS cert is an SVID: trust the SPIFFE bundle
            if "https://" in (self.pf + PORTAL):   # behind an HTTPS proxy: its cert chains to the enterprise root
                self.ca = _ca_from_container("agentic-icam-vault-1", "/pki/tls/trust-anchor.pem")
        self.ca = setting("PUBLIC_CA_BUNDLE") or self.ca   # e.g. your proxy's public CA
        self.name = "PingFederate" if self.real_pf else "PingFederate simulator"

    def session(self) -> requests.Session:
        s = requests.Session()
        s.trust_env = False
        if self.ca:
            s.verify = self.ca
        return s

    def submit_login(self, s: requests.Session, page: requests.Response, user: str, password: str):
        """Fill and post whichever login form the IdP served; returns the final response
        (or the redirect to the client when allow_redirects=False semantics are needed)."""
        form = re.search(r"<form[^>]*>", page.text).group(0)
        action = re.search(r'action="([^"]*)"', form)
        url = urljoin(page.url, html.unescape(action.group(1))) if action and action.group(1) else page.url
        fields = {m[0]: html.unescape(m[1]) for m in
                  re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page.text)}
        fields.update({m[0]: html.unescape(m[1]) for m in
                       re.findall(r'<input[^>]*name="([^"]+)"[^>]*type="hidden"[^>]*value="([^"]*)"', page.text)})
        fields.update({"pf.username": user, "pf.pass": password, "pf.ok": "clicked"})
        fields.pop("pf.cancel", None)
        return s.post(url, data=fields, allow_redirects=False)

    def follow_to(self, s: requests.Session, r: requests.Response, prefix: str) -> requests.Response:
        """Follow redirects until one points at `prefix` (returned unfollowed)."""
        while r.status_code in (301, 302, 303) and not r.headers["Location"].startswith(prefix):
            r = s.get(urljoin(r.url, r.headers["Location"]), allow_redirects=False)
        return r

    def portal_login(self, user: str) -> requests.Session:
        s = self.session()
        page = s.get(f"{PORTAL}/login")
        assert "pf.username" in page.text, page.text[:300]
        r = self.follow_to(s, self.submit_login(s, page, user, user), PORTAL)
        s.get(r.headers["Location"])          # portal /callback -> /
        assert "Signed in as" in s.get(PORTAL + "/").text, "login failed"
        return s


PAYMENTS_TASK = "Customers report failed card payments since this morning - find out why"


def run_task(s, agent: str, task: str = PAYMENTS_TASK, approve: bool = True) -> dict:
    """Submit a free-text task; if the plan needs approval, approve it (as the user would)."""
    res = s.post(f"{PORTAL}/task", headers={"Accept": "application/json"}, data={"agent": agent, "task": task}).json()
    if res.get("status") == "approval_required" and approve:
        first = res
        res = s.post(f"{PORTAL}/task/approve", headers={"Accept": "application/json"},
                     data={"plan_id": first["plan"]["plan_id"], "decision": "approve"}).json()
        res["approval"] = first
    return res
