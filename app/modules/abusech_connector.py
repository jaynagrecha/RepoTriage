from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import httpx

FEODO_IPBLOCKLIST = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
SSLBL_IPBLACKLIST = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"


def abusech_key() -> str:
    return os.getenv("ABUSECH_API_KEY") or ""


def _enabled(name: str) -> bool:
    return os.getenv(f"{name}_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _cache_path(base_dir: Path, name: str) -> Path:
    p = base_dir / "data" / f"{name}_cache.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("{}", encoding="utf-8")
    return p


def _load_cache(base_dir: Path, name: str) -> dict:
    try:
        return json.loads(_cache_path(base_dir, name).read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(base_dir: Path, name: str, cache: dict) -> None:
    _cache_path(base_dir, name).write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")


def _parse_csv_text(text: str) -> list[dict]:
    rows = []
    cleaned = "\n".join(line for line in text.splitlines() if line and not line.startswith("#"))
    if not cleaned.strip():
        return []
    reader = csv.DictReader(io.StringIO(cleaned))
    for row in reader:
        rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
    return rows


async def _download_feed(url: str, timeout: float = 20) -> str:
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers={"User-Agent": "RepoTriage/1.8"})
        r.raise_for_status()
        return r.text


def _public_ips(iocs: dict) -> set[str]:
    from .cti_query_policy import is_public_ip_indicator

    out: set[str] = set()
    for raw in iocs.get("ips", []) or []:
        ip = str(raw or "").strip()
        if ip and is_public_ip_indicator(ip):
            out.add(ip)
    return out


async def enrich_feodo(iocs: dict, base_dir: Path) -> dict:
    if not _enabled("FEODO"):
        return {"enabled": False, "status": "disabled", "matches": [], "summary": {"matches": 0}}
    ips = _public_ips(iocs)
    if not ips:
        return {"enabled": True, "status": "completed", "matches": [], "summary": {"looked_up": 0, "matches": 0}}
    cache = _load_cache(base_dir, "feodo")
    feed_max_age = int(os.getenv("FEODO_CACHE_SECONDS", "21600"))
    now = datetime.now(timezone.utc).timestamp()
    rows = cache.get("rows") or []
    if not rows or now - float(cache.get("fetched_at", 0)) > feed_max_age:
        try:
            text = await _download_feed(FEODO_IPBLOCKLIST, timeout=float(os.getenv("FEODO_TIMEOUT", "20")))
            rows = _parse_csv_text(text)
            cache = {"fetched_at": now, "rows": rows}
            _save_cache(base_dir, "feodo", cache)
        except Exception as e:
            return {"enabled": True, "status": "error", "error": str(e), "matches": [], "summary": {"looked_up": len(ips), "matches": 0}}
    matches = []
    for row in rows:
        ip = row.get("dst_ip") or row.get("ip_address") or row.get("ip") or row.get("Host") or row.get("host")
        if ip in ips:
            matches.append({"ip": ip, "malware": row.get("malware") or row.get("malware_family"), "status": row.get("status"), "first_seen": row.get("first_seen"), "last_online": row.get("last_online"), "source": "FeodoTracker", "raw": row})
    return {"enabled": True, "status": "completed", "matches": matches, "summary": {"looked_up": len(ips), "matches": len(matches), "feed_rows": len(rows)}}


async def enrich_sslbl(iocs: dict, base_dir: Path) -> dict:
    if not _enabled("SSLBL"):
        return {"enabled": False, "status": "disabled", "matches": [], "summary": {"matches": 0}}
    ips = _public_ips(iocs)
    if not ips:
        return {"enabled": True, "status": "completed", "matches": [], "summary": {"looked_up": 0, "matches": 0}}
    cache = _load_cache(base_dir, "sslbl")
    feed_max_age = int(os.getenv("SSLBL_CACHE_SECONDS", "21600"))
    now = datetime.now(timezone.utc).timestamp()
    rows = cache.get("rows") or []
    if not rows or now - float(cache.get("fetched_at", 0)) > feed_max_age:
        try:
            text = await _download_feed(SSLBL_IPBLACKLIST, timeout=float(os.getenv("SSLBL_TIMEOUT", "20")))
            rows = _parse_csv_text(text)
            cache = {"fetched_at": now, "rows": rows}
            _save_cache(base_dir, "sslbl", cache)
        except Exception as e:
            return {"enabled": True, "status": "error", "error": str(e), "matches": [], "summary": {"looked_up": len(ips), "matches": 0}}
    matches = []
    for row in rows:
        ip = row.get("dst_ip") or row.get("ip") or row.get("ip_address") or row.get("Host") or row.get("host")
        if ip in ips:
            matches.append({"ip": ip, "port": row.get("dst_port") or row.get("port"), "ja3": row.get("ja3") or row.get("ja3_md5"), "listing_date": row.get("listingdate") or row.get("first_seen"), "source": "SSLBL", "raw": row})
    return {"enabled": True, "status": "completed", "matches": matches, "summary": {"looked_up": len(ips), "matches": len(matches), "feed_rows": len(rows)}}


def abusech_summary(threatfox: dict, malwarebazaar: dict, urlhaus: dict, feodo: dict, sslbl: dict) -> dict:
    families = []
    for src in [threatfox.get("summary", {}), malwarebazaar.get("summary", {}), urlhaus.get("summary", {})]:
        for f in src.get("malware_families") or src.get("families") or []:
            if f and f not in families:
                families.append(f)
    return {
        "auth_configured": bool(abusech_key()),
        "sources": {
            "threatfox": threatfox.get("status"),
            "malwarebazaar": malwarebazaar.get("status"),
            "urlhaus": urlhaus.get("status"),
            "feodo": feodo.get("status"),
            "sslbl": sslbl.get("status"),
        },
        "matches": {
            "threatfox": (threatfox.get("summary") or {}).get("found", 0),
            "malwarebazaar": (malwarebazaar.get("summary") or {}).get("found", 0),
            "urlhaus": (urlhaus.get("summary") or {}).get("found", 0),
            "feodo": (feodo.get("summary") or {}).get("matches", 0),
            "sslbl": (sslbl.get("summary") or {}).get("matches", 0),
        },
        "families": families,
    }
