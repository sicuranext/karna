"""Validation and composition for the dashboard's Kong Admin API target."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import egress

_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_name(value) -> str:
    """Validate an operator-facing label without restricting natural names."""
    if not isinstance(value, str):
        raise ValueError("name is required")
    name = " ".join(value.strip().split())
    if not name or len(name) > 64:
        raise ValueError("name must be between 1 and 64 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("name cannot contain control characters")
    return name


def validate(payload: dict) -> dict:
    """Validate and normalize separate protocol, host, and port fields.

    Private and loopback hosts are valid because Kong's Admin API normally
    lives on a private control-plane network. The strict component validation
    prevents paths, credentials, query strings, fragments, and non-HTTP schemes
    from being smuggled into the server-side request URL.
    """
    if not isinstance(payload, dict):
        raise ValueError("Connection settings must be an object")
    unsupported = set(payload) - {"protocol", "host", "port"}
    if unsupported:
        raise ValueError(f"Unsupported connection fields: {', '.join(sorted(unsupported))}")
    protocol = payload.get("protocol")
    if not isinstance(protocol, str) or protocol.lower().strip() not in ("http", "https"):
        raise ValueError("protocol must be http or https")
    protocol = protocol.lower().strip()

    host = payload.get("host")
    if not isinstance(host, str):
        raise ValueError("host is required")
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or len(host) > 253:
        raise ValueError("host must be between 1 and 253 characters")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.is_unspecified:
            raise ValueError("host cannot be an unspecified address")
        if egress.blocked(address):
            raise ValueError("host cannot be a link-local or cloud metadata address")
        normalized_host = address.compressed
    else:
        try:
            normalized_host = host.encode("idna").decode("ascii").rstrip(".")
        except UnicodeError:
            raise ValueError("host is not a valid hostname or IP address") from None
        labels = normalized_host.split(".")
        if not normalized_host or any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
            raise ValueError("host is not a valid hostname or IP address")
        if normalized_host.lower() in egress.METADATA_HOSTNAMES:
            raise ValueError("host cannot be a link-local or cloud metadata address")

    port = payload.get("port")
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        raise ValueError("port must be an integer between 1 and 65535")
    if isinstance(port, str):
        if not port.isdigit():
            raise ValueError("port must be an integer between 1 and 65535")
        port = int(port)
    if port < 1 or port > 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return {"protocol": protocol, "host": normalized_host, "port": port}


def url(connection: dict) -> str:
    """Compose a validated connection, including IPv6 brackets."""
    host = connection["host"]
    url_host = f"[{host}]" if ":" in host else host
    return f"{connection['protocol']}://{url_host}:{connection['port']}"


def parse_url(value: str) -> dict:
    """Parse an origin URL strictly; raises ValueError on anything but scheme://host[:port]."""
    try:
        parsed = urlsplit(value)
        if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        return validate({"protocol": parsed.scheme, "host": parsed.hostname, "port": port})
    except (ValueError, TypeError):
        raise ValueError(f"not a valid origin URL: {value!r}") from None


def from_url(value: str) -> dict:
    """Parse the environment fallback, rejecting components the UI cannot edit."""
    try:
        return parse_url(value)
    except ValueError:
        return {"protocol": "http", "host": "kong", "port": 8001}
