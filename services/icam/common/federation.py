"""Shared bits of cross-domain identity chaining."""

import base64
import hashlib

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TT_JWT = "urn:ietf:params:oauth:token-type:jwt"


def pairwise_subject(sub: str, trust_domain: str, salt: str) -> str:
    """Stable per-partner pseudonym, so partners cannot correlate users across domains.
    The real PingFederate configuration computes the same value in OGNL."""
    digest = hashlib.sha256(f"{sub}|{trust_domain}|{salt}".encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()[:22]
