"""Shared httpx client helpers with resilient TLS CA handling.

Render/native Python environments sometimes break default SSL verification
(missing CA bundle, stale SSL_CERT_FILE, or self-signed intercept). Prefer
certifi's Mozilla CA bundle unless an explicit override is provided.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx


def ssl_verify() -> bool | str:
    """Return httpx ``verify`` value.

    Env:
      HTTPX_VERIFY / SSL_VERIFY:
        - false/0/off → disable verify (emergency only)
        - true/1/on → use certifi (or system default)
        - path → custom CA bundle file
      HTTPX_PREFER_CERTIFI (default true): ignore broken SSL_CERT_FILE and use certifi
      SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE: CA path when prefer_certifi is false
    """
    explicit = (os.getenv('HTTPX_VERIFY') or os.getenv('SSL_VERIFY') or '').strip()
    if explicit:
        low = explicit.lower()
        if low in {'0', 'false', 'no', 'off'}:
            return False
        if low in {'1', 'true', 'yes', 'on'}:
            return _certifi_path() or True
        if Path(explicit).is_file():
            return explicit
        return _certifi_path() or True

    prefer_certifi = (os.getenv('HTTPX_PREFER_CERTIFI') or 'true').strip().lower() not in {
        '0', 'false', 'no', 'off',
    }
    if prefer_certifi:
        return _certifi_path() or True

    for key in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        path = (os.getenv(key) or '').strip()
        if path and Path(path).is_file():
            return path
    return _certifi_path() or True


def _certifi_path() -> str | None:
    try:
        import certifi

        path = certifi.where()
        return path if path and Path(path).is_file() else None
    except Exception:
        return None


def async_client(**kwargs: Any) -> httpx.AsyncClient:
    """httpx.AsyncClient with project TLS defaults (caller owns context manager)."""
    if 'verify' not in kwargs:
        kwargs['verify'] = ssl_verify()
    return httpx.AsyncClient(**kwargs)
