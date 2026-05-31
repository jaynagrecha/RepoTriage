from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

URLHAUS_URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"


def _enabled() -> bool:
    return os.getenv("URLHAUS_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _headers() -> dict:
    headers = {"User-Agent": "RepoTriage/1.8"}
    key = os.getenv("URLHAUS_API_KEY") or os.getenv("ABUSECH_API_KEY")
    if key:
        headers["Auth-Key"] = key
    return headers


def _cache_path(base_dir: Path) -> Path:
    p = base_dir / "data" / "urlhaus_cache.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("{}", encoding="utf-8")
    return p


def _load_cache(base_dir: Path) -> dict:
    try:
        return json.loads(_cache_path(base_dir).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(base_dir: Path, cache: dict) -> None:
    _cache_path(base_dir).write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def _host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _urlhaus_url(url: str | None) -> str | None:
    if not url:
        return None
    return f"https://urlhaus.abuse.ch/url/{url}/" if str(url).isdigit() else None


def normalize_url_result(indicator: str, payload: dict, cache_hit: bool = False) -> dict:
    status = payload.get("query_status", "unknown") if isinstance(payload, dict) else "unknown"
    found = status == "ok" and bool(payload.get("id") or payload.get("url"))
    payloads = payload.get("payloads") if isinstance(payload, dict) else []
    if not isinstance(payloads, list):
        payloads = []
    families = []
    hashes = []
    for p in payloads[:25]:
        sig = p.get("signature") or p.get("malware_family")
        if sig and sig not in families:
            families.append(sig)
        h = p.get("sha256_hash") or p.get("md5_hash")
        if h and h not in hashes:
            hashes.append(h)
    return {
        "indicator": indicator,
        "indicator_type": "url",
        "status": "found" if found else ("not_found" if status in {"no_results", "invalid_url", "ok"} else status),
        "query_status": status,
        "found": found,
        "url": payload.get("url") if isinstance(payload, dict) else indicator,
        "url_status": payload.get("url_status") if isinstance(payload, dict) else None,
        "host": payload.get("host") if isinstance(payload, dict) else _host_from_url(indicator),
        "threat": payload.get("threat") if isinstance(payload, dict) else None,
        "tags": payload.get("tags") if isinstance(payload, dict) and isinstance(payload.get("tags"), list) else [],
        "date_added": payload.get("date_added") if isinstance(payload, dict) else None,
        "last_online": payload.get("last_online") if isinstance(payload, dict) else None,
        "payloads": payloads[:25],
        "payload_hashes": hashes,
        "families": families,
        "link": _urlhaus_url(str(payload.get("id"))) if isinstance(payload, dict) and payload.get("id") else None,
        "cache_hit": cache_hit,
    }


def normalize_host_result(host: str, payload: dict, cache_hit: bool = False) -> dict:
    status = payload.get("query_status", "unknown") if isinstance(payload, dict) else "unknown"
    urls = payload.get("urls") if isinstance(payload, dict) else []
    if not isinstance(urls, list):
        urls = []
    found = status == "ok" and bool(urls)
    families = []
    for row in urls[:50]:
        for p in row.get("payloads") or []:
            sig = p.get("signature") or p.get("malware_family")
            if sig and sig not in families:
                families.append(sig)
    return {
        "indicator": host,
        "indicator_type": "domain/host",
        "status": "found" if found else ("not_found" if status in {"no_results", "ok"} else status),
        "query_status": status,
        "found": found,
        "host": host,
        "url_count": len(urls),
        "urls": urls[:50],
        "families": families,
        "cache_hit": cache_hit,
    }


async def lookup_url(url: str, base_dir: Path) -> dict:
    if not _enabled():
        return {"indicator": url, "status": "disabled", "found": False, "indicator_type": "url"}
    cache = _load_cache(base_dir)
    key = "url:" + url.strip().lower()
    if key in cache:
        return normalize_url_result(url, cache[key], cache_hit=True)
    timeout = float(os.getenv("URLHAUS_TIMEOUT", "18"))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(URLHAUS_URL_API, headers=_headers(), data={"url": url})
            r.raise_for_status()
            payload = r.json()
    except Exception as e:
        return {"indicator": url, "indicator_type": "url", "status": "error", "error": str(e), "found": False}
    cache[key] = payload
    _save_cache(base_dir, cache)
    return normalize_url_result(url, payload, cache_hit=False)


async def lookup_host(host: str, base_dir: Path) -> dict:
    host = (host or "").strip().lower()
    if not host:
        return {"indicator": host, "status": "invalid", "found": False, "indicator_type": "domain/host"}
    if not _enabled():
        return {"indicator": host, "status": "disabled", "found": False, "indicator_type": "domain/host"}
    cache = _load_cache(base_dir)
    key = "host:" + host
    if key in cache:
        return normalize_host_result(host, cache[key], cache_hit=True)
    timeout = float(os.getenv("URLHAUS_TIMEOUT", "18"))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(URLHAUS_HOST_API, headers=_headers(), data={"host": host})
            r.raise_for_status()
            payload = r.json()
    except Exception as e:
        return {"indicator": host, "indicator_type": "domain/host", "status": "error", "error": str(e), "found": False}
    cache[key] = payload
    _save_cache(base_dir, cache)
    return normalize_host_result(host, payload, cache_hit=False)


def _summary(results: list[dict]) -> dict:
    found = [r for r in results if r.get("found")]
    families = []
    active = 0
    payload_urls = 0
    for r in found:
        for fam in r.get("families") or []:
            if fam and fam not in families:
                families.append(fam)
        if str(r.get("url_status", "")).lower() == "online":
            active += 1
        if r.get("indicator_type") == "url":
            payload_urls += 1
    return {
        "looked_up": len(results),
        "found": len(found),
        "errors": len([r for r in results if r.get("status") == "error"]),
        "active_urls": active,
        "payload_delivery_urls": payload_urls,
        "families": families,
    }


async def enrich_iocs(iocs: dict, base_dir: Path) -> dict:
    if not _enabled():
        return {"enabled": False, "status": "disabled", "results": [], "summary": {"looked_up": 0, "found": 0}}
    limit = int(os.getenv("URLHAUS_LOOKUP_LIMIT", "75"))
    results = []
    candidates = []
    for u in iocs.get("urls", []) or []:
        if u not in candidates:
            candidates.append(("url", u))
    for d in iocs.get("domains", []) or []:
        if d not in [x[1] for x in candidates]:
            candidates.append(("host", d))
    for typ, value in candidates[:limit]:
        if typ == "url":
            results.append(await lookup_url(value, base_dir))
        else:
            results.append(await lookup_host(value, base_dir))
    return {"enabled": True, "status": "completed", "results": results, "summary": _summary(results)}
