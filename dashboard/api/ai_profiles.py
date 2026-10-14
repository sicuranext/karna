"""Validation, credential handling, and connection probes for AI profiles."""
from __future__ import annotations

import ipaddress
import re
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import HTTPException

import auth
import egress
import store

PROVIDERS = {
    "ollama": {"label": "Ollama", "base_url": "http://host.docker.internal:11434/v1", "local": True, "api_key": False},
    "lmstudio": {"label": "LM Studio", "base_url": "http://host.docker.internal:1234/v1", "local": True, "api_key": False},
    "openai": {"label": "OpenAI", "base_url": "https://api.openai.com/v1", "api_key": True},
    "anthropic": {"label": "Anthropic", "base_url": "https://api.anthropic.com/v1", "api_key": True, "native": True},
    "kimi": {"label": "Kimi", "base_url": "https://api.moonshot.ai/v1", "api_key": True},
    "openrouter": {"label": "OpenRouter", "base_url": "https://openrouter.ai/api/v1", "api_key": True},
    "huggingface": {"label": "Hugging Face", "base_url": "https://router.huggingface.co/v1", "api_key": True},
    "custom": {"label": "Custom OpenAI-compatible", "base_url": "", "api_key": False, "custom": True},
}

_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+~-]{0,199}$")
_BILL_TO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def provider_catalog() -> list[dict]:
    return [
        {
            "id": key,
            "label": value["label"],
            "default_base_url": value["base_url"],
            "local": bool(value.get("local")),
            "api_key_required": bool(value.get("api_key")),
            "native_api": bool(value.get("native")),
        }
        for key, value in PROVIDERS.items()
    ]


def _base_url(provider: str, raw) -> str:
    meta = PROVIDERS[provider]
    supplied = str(raw or "").strip()
    value = supplied or meta["base_url"]
    if not value or len(value) > 512:
        raise HTTPException(422, "Enter a valid provider base URL.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(422, "Enter a valid provider base URL.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(422, "Provider URL must use http or https and include a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(422, "Provider URL cannot contain credentials, query parameters, or fragments.")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved):
        raise HTTPException(422, "Provider URL cannot target a link-local or reserved address.")
    if parsed.hostname.lower() in {"metadata.google.internal", "metadata.google"}:
        raise HTTPException(422, "Provider URL cannot target a cloud metadata service.")
    if port is not None and not 1 <= port <= 65535:
        raise HTTPException(422, "Provider URL contains an invalid port.")
    path = parsed.path.rstrip("/")
    if not (meta.get("local") or meta.get("custom")) and urlunsplit((parsed.scheme, parsed.netloc, path, "", "")) != meta["base_url"]:
        raise HTTPException(422, "Use a custom profile for a non-standard provider endpoint.")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _origin(url: str) -> tuple[str, str, int | None]:
    """scheme, host, port of a URL, with the default port made explicit."""
    try:
        parts = urlsplit(url)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    except ValueError:
        return ("", "", None)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), port)


def normalize(payload: dict, existing: dict | None = None) -> tuple[dict, str | None, bool]:
    if not isinstance(payload, dict):
        raise HTTPException(422, "Profile must be a JSON object.")
    provider = str(payload.get("provider") or "").strip().lower()
    if provider not in PROVIDERS:
        raise HTTPException(422, "Unsupported AI provider.")
    name = str(payload.get("name") or "").strip()
    model = str(payload.get("model") or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise HTTPException(422, "Profile name must contain 1–64 printable characters.")
    if not _MODEL_RE.fullmatch(model):
        raise HTTPException(422, "Enter a valid model identifier.")

    raw_options = payload.get("options") or {}
    if not isinstance(raw_options, dict):
        raise HTTPException(422, "Provider options must be an object.")
    options = {}
    allowed_options = {"bill_to"} if provider == "huggingface" else set()
    unknown_options = set(raw_options) - allowed_options
    if unknown_options:
        raise HTTPException(422, f"Unsupported provider option: {sorted(unknown_options)[0]}")
    if provider == "huggingface" and raw_options.get("bill_to"):
        bill_to = str(raw_options["bill_to"]).strip()
        if not _BILL_TO_RE.fullmatch(bill_to):
            raise HTTPException(422, "Hugging Face bill-to must be an organization slug or resource-group ID.")
        options["bill_to"] = bill_to

    profile_id = existing["id"] if existing else str(payload.get("id") or uuid.uuid4())
    try:
        uuid.UUID(profile_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, "Invalid profile ID.") from exc

    clear_key = payload.get("clear_api_key") is True
    supplied_key = payload.get("api_key")
    if supplied_key is not None and not isinstance(supplied_key, str):
        raise HTTPException(422, "API key must be a string.")
    supplied_key = supplied_key.strip() if isinstance(supplied_key, str) else None
    if supplied_key and len(supplied_key) > 4096:
        raise HTTPException(422, "API key is too long.")
    base_url = _base_url(provider, payload.get("base_url"))
    keep_key = bool(existing and not clear_key and not supplied_key)
    # A saved key is only ever sent where it was saved for: changing the
    # provider or the endpoint's origin (scheme, host, port) requires the key
    # again, so a session cannot redirect a stored credential to a host it picks.
    if keep_key and existing.get("api_key_configured") and (
            provider != existing.get("provider") or _origin(base_url) != _origin(existing.get("base_url") or "")):
        raise HTTPException(422, "The provider or endpoint changed: enter the API key again.")
    has_key = bool(supplied_key) or (keep_key and existing.get("api_key_configured"))
    if PROVIDERS[provider].get("api_key") and not has_key:
        raise HTTPException(422, f"{PROVIDERS[provider]['label']} requires an API key.")

    profile = {
        "id": profile_id,
        "name": name,
        "provider": provider,
        "base_url": base_url,
        "model": model,
        "options": options,
        "is_default": payload.get("is_default") is True,
    }
    cipher = auth.encrypt_credential(supplied_key) if supplied_key else None
    return profile, cipher, keep_key


def saved_with_key(profile_id: str) -> tuple[dict, str | None]:
    profile = store.get_ai_profile(profile_id, include_cipher=True)
    if not profile:
        raise HTTPException(404, "AI profile not found.")
    cipher = profile.pop("api_key_cipher", None)
    key = auth.decrypt_credential(cipher) if cipher else None
    return profile, key


def _headers(profile: dict, api_key: str | None) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if api_key:
        if profile["provider"] == "anthropic":
            headers.update({"x-api-key": api_key, "anthropic-version": "2023-06-01"})
        else:
            headers["authorization"] = f"Bearer {api_key}"
    bill_to = (profile.get("options") or {}).get("bill_to")
    if profile["provider"] == "huggingface" and bill_to:
        headers["X-HF-Bill-To"] = bill_to
    return headers


async def probe(profile: dict, api_key: str | None) -> dict:
    """Probe model discovery without ever returning request headers or credentials."""
    url = profile["base_url"].rstrip("/") + "/models"
    started = time.monotonic()
    try:
        async with egress.client(timeout=10.0, follow_redirects=False) as client:
            response = await client.get(url, headers=_headers(profile, api_key))
        response.raise_for_status()
        body = response.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        detail = "Authentication failed." if status in {401, 403} else f"Provider returned HTTP {status}."
        return {"connected": False, "detail": detail, "status_code": status}
    except (httpx.HTTPError, ValueError):
        return {"connected": False, "detail": "Provider is unreachable or returned an invalid response."}

    raw_models = body.get("data") if isinstance(body, dict) else None
    if raw_models is None and isinstance(body, dict):
        raw_models = body.get("models")
    models = []
    if isinstance(raw_models, list):
        for item in raw_models[:500]:
            model_id = item.get("id") if isinstance(item, dict) else item
            # model identifiers only (name, org/name, name:tag), not arbitrary text
            if isinstance(model_id, str) and _MODEL_RE.fullmatch(model_id):
                models.append(model_id)
    latency_ms = round((time.monotonic() - started) * 1000)
    return {
        "connected": True,
        "detail": "Provider connected.",
        "latency_ms": latency_ms,
        "model_available": profile["model"] in models if models else None,
        "models": models,
    }
