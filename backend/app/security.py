"""Access control for manual sync / administrative endpoints."""
import ipaddress

from fastapi import HTTPException, Request

from .config import settings

LOOPBACK = ("127.0.0.1", "::1", "localhost")
# exactly the ranges Docker assigns to bridge networks (RFC 1918 + IPv6 unique-local). ipaddress.is_private is NOT used: it also covers documentation, link-local and other ranges.
PROXY_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))


def is_local(request: Request) -> bool:
    """Loopback peer; or, when PYRAMID_TRUST_PROXY=1 (backend reachable only from the bundled proxy), a private-network peer. A public address never qualifies."""
    host = request.client.host if request.client else None
    if host in LOOPBACK:
        return True
    if settings.trust_proxy and host:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in n for n in PROXY_NETWORKS)
    return False


def authorize_sync(request: Request, token: str | None) -> None:
    """Allowed from localhost, or from anywhere with the SYNC_TOKEN header when SYNC_TOKEN is configured."""
    if settings.sync_token:
        if token != settings.sync_token:
            raise HTTPException(403, "Invalid sync token")
    elif not is_local(request):
        raise HTTPException(403, "Manual sync is only allowed from localhost")
