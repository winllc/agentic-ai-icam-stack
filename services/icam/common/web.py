"""Settings for browser-facing apps that may sit behind a reverse proxy."""
import os

from werkzeug.middleware.proxy_fix import ProxyFix


def behind_proxy(app, public_url: str):
    """Trust X-Forwarded-For/-Proto/-Host from TRUSTED_PROXY_HOPS proxies (0 = none, the
    default: the headers are then ignored, so clients can't spoof them). Cookies get the
    Secure flag whenever the public URL is HTTPS, even if the proxy talks HTTP to the app."""
    hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "0") or 0)
    if hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=hops)
    secure = public_url.startswith("https://")
    app.config.update(SESSION_COOKIE_SECURE=secure, PREFERRED_URL_SCHEME="https" if secure else "http")
    return secure
