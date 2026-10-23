"""Outbound HTTP for the console: one guarded transport for every request the
backend makes (Kong Admin API, AI providers).

The console is admin-only and self-hosted, so private and loopback addresses
stay allowed: Kong's Admin API lives on a private network and Ollama / LM Studio
on localhost. What is refused is the one destination class no Kong or model
server legitimately uses and that a self-hosted console on a cloud VM can
reach: link-local and cloud metadata addresses.

The check cannot be bypassed with DNS rebinding: the name is resolved once,
every returned address is checked, and the connection goes to the address that
was checked. The original name is kept for the Host header and for TLS (SNI and
certificate verification), so nothing else changes for the request.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket

import httpx

_METADATA = (
    ipaddress.ip_network("169.254.0.0/16"),       # link-local, AWS/GCP/Azure/OpenStack metadata
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),    # AWS metadata over IPv6
    ipaddress.ip_network("100.100.100.200/32"),   # Alibaba Cloud metadata
)
# Metadata services reached by name; refused when a URL is saved, before any lookup.
METADATA_HOSTNAMES = frozenset({"metadata.google.internal", "metadata.google"})


def blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (address.is_link_local or address.is_multicast or address.is_unspecified
            or any(address in net for net in _METADATA))


class BlockedDestination(httpx.ConnectError):
    """Raised for a refused destination; an httpx.HTTPError like any failed connect."""


class GuardedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        try:
            addresses = [ipaddress.ip_address(host)]
            literal = True
        except ValueError:
            literal = False
            port = request.url.port or (443 if request.url.scheme == "https" else 80)
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise httpx.ConnectError(f"cannot resolve {host}", request=request) from exc
            addresses = [ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos]
        if not addresses or any(blocked(a) for a in addresses):
            raise BlockedDestination(f"destination {host} is not allowed (link-local or cloud metadata)",
                                     request=request)
        if not literal:
            # Connect to the address just checked; keep the name for Host and TLS.
            request.url = request.url.copy_with(host=str(addresses[0]))
            if request.url.scheme == "https":
                request.extensions = {**request.extensions, "sni_hostname": host}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def client(**kwargs) -> httpx.AsyncClient:
    """An httpx.AsyncClient whose requests all go through the guard."""
    return httpx.AsyncClient(transport=GuardedTransport(), **kwargs)
