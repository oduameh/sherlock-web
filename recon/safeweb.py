"""Hardened outbound HTTP for enrichment and pivots.

All best-effort fetching of third-party pages, avatars, and public APIs goes
through :func:`async_client`, an ``httpx.AsyncClient`` factory that adds:

* a shared desktop User-Agent (previously copy-pasted into three modules),
* redirects followed **but re-validated** at every hop,
* an SSRF guard (:func:`_guard`) that refuses any request whose target host
  resolves to private / loopback / link-local / reserved IP space.

The guard resolves the hostname and rejects the request if *any* resolved
address is non-public. This closes the common "fetch a profile URL that
redirects to ``http://169.254.169.254/`` (cloud metadata) or an internal
service" class of SSRF once the app is deployed (e.g. Railway).

It is deliberately *not* a defense against a determined DNS-rebinding attacker:
httpx re-resolves at connect time, which can differ from the address we
checked. For a public-data OSINT tool that only ever fetches well-known public
sites, blocking the metadata/internal-service case is the meaningful win and
the residual rebinding risk is accepted and documented here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Any, Optional

import httpx

logger = logging.getLogger("recon.safeweb")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_ALLOWED_SCHEMES = {"http", "https"}


class BlockedRequestError(httpx.RequestError):
    """Raised by the SSRF guard when a destination is disallowed."""


def _is_public_ip(ip: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


async def _resolve(host: str, port: Optional[int]) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port or 0, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


async def _guard(request: httpx.Request) -> None:
    """httpx request hook: block non-public destinations (initial + redirects)."""
    if request.url.scheme not in _ALLOWED_SCHEMES:
        raise BlockedRequestError(
            f"blocked non-http(s) scheme: {request.url.scheme}", request=request
        )
    host = request.url.host
    if not host:
        raise BlockedRequestError("blocked request with no host", request=request)

    # If the host is already an IP literal, check it directly; otherwise resolve.
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        try:
            ips = await _resolve(host, request.url.port)
        except socket.gaierror as exc:
            raise BlockedRequestError(
                f"could not resolve host {host}: {exc}", request=request
            )
    for ip in ips:
        if not _is_public_ip(ip):
            raise BlockedRequestError(
                f"blocked non-public address {ip} for host {host}",
                request=request,
            )


def async_client(*, timeout: float = 10.0, headers: Optional[dict] = None,
                 **kwargs: Any) -> httpx.AsyncClient:
    """Build an SSRF-guarded ``httpx.AsyncClient`` with the shared UA."""
    merged = {"User-Agent": BROWSER_UA}
    if headers:
        merged.update(headers)
    return httpx.AsyncClient(
        timeout=timeout,
        headers=merged,
        follow_redirects=True,
        event_hooks={"request": [_guard]},
        **kwargs,
    )


async def fetch_capped(client: httpx.AsyncClient, url: str,
                       max_bytes: int) -> Optional[bytes]:
    """GET ``url`` streaming at most ``max_bytes`` into memory. None on failure.

    Bounds memory even against a hostile/huge response (the avatar path used to
    read ``resp.content`` in full before checking its size).
    """
    try:
        async with client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                return None
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes(16384):
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    return None
            return b"".join(chunks)
    except Exception:
        return None
