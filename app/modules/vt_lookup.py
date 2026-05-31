from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import json
import os
import httpx

class VTLookupError(Exception):
    pass


def _cache_path(base_dir: Path) -> Path:
    p = base_dir / "data"
    p.mkdir(parents=True, exist_ok=True)
    return p / "vt_cache.json"


def _load_cache(base_dir: Path) -> dict:
    path = _cache_path(base_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(base_dir: Path, cache: dict) -> None:
    path = _cache_path(base_dir)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _verdict(stats: dict) -> str:
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if harmless > 0 or undetected > 0:
        return "clean/undetected"
    return "unknown"


def _top_detections(results: dict, limit: int = 12) -> list[dict]:
    detections = []
    if not isinstance(results, dict):
        return detections
    for engine, res in results.items():
        if not isinstance(res, dict):
            continue
        category = res.get("category")
        name = res.get("result")
        if category in {"malicious", "suspicious"} or name:
            detections.append({
                "engine": engine,
                "category": category or "unknown",
                "result": name or "",
            })
    # Prefer malicious/suspicious named detections first
    detections.sort(key=lambda d: (d["category"] != "malicious", d["category"] != "suspicious", not d["result"], d["engine"].lower()))
    return detections[:limit]


def _family_from_attrs(attrs: dict, detections: list[dict]) -> dict:
    # VT can expose popular_threat_classification in newer reports.
    ptc = attrs.get("popular_threat_classification") or {}
    suggested = ptc.get("suggested_threat_label")
    if suggested:
        return {"name": suggested, "confidence": 85, "source": "virustotal_popular_threat_classification"}

    # Fallback: extract common detection token patterns from engines.
    tokens = {}
    noise = {"malware", "trojan", "generic", "gen", "agent", "win32", "w32", "heur", "unsafe", "riskware", "variant", "packed", "suspicious", "dropper", "downloader"}
    for d in detections:
        result = (d.get("result") or "").replace("/", ".").replace("-", ".").replace("_", ".")
        for raw in result.split("."):
            t = ''.join(ch for ch in raw if ch.isalnum()).lower()
            if len(t) < 4 or t in noise or t.isdigit():
                continue
            tokens[t] = tokens.get(t, 0) + 1
    if not tokens:
        return {"name": "Unknown", "confidence": 0, "source": "none"}
    name, count = sorted(tokens.items(), key=lambda kv: kv[1], reverse=True)[0]
    confidence = min(75, 25 + count * 10)
    return {"name": name, "confidence": confidence, "source": "detection_name_heuristic"}


def _normalize_file_report(sha256: str, data: dict, cache_hit: bool = False) -> dict:
    obj = data.get("data") or {}
    attrs = obj.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    detections = _top_detections(results)
    verdict = _verdict(stats)
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    family = _family_from_attrs(attrs, detections)
    tags = attrs.get("tags") or []
    names = attrs.get("names") or []

    return {
        "status": "found",
        "cache_hit": cache_hit,
        "sha256": sha256,
        "verdict": verdict,
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "timeout": int(stats.get("timeout") or 0),
        "detections_summary": f"{int(stats.get('malicious') or 0)} malicious / {int(stats.get('suspicious') or 0)} suspicious",
        "top_detections": detections,
        "family": family,
        "tags": tags[:25] if isinstance(tags, list) else [],
        "names": names[:20] if isinstance(names, list) else [],
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "permalink": link,
        "raw_available": True,
    }


async def lookup_file_hash(sha256: str, base_dir: Path, force_refresh: bool = False) -> dict:
    key = sha256.lower().strip()
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "sha256": key,
            "verdict": "unknown",
            "message": "VT_API_KEY is not configured",
            "permalink": f"https://www.virustotal.com/gui/file/{key}",
        }

    cache = _load_cache(base_dir)
    if not force_refresh and key in cache:
        item = cache[key]
        # already normalized in v1.2 cache
        item["cache_hit"] = True
        return item

    url = f"https://www.virustotal.com/api/v3/files/{key}"
    headers = {"x-apikey": api_key}
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(url, headers=headers)

    if resp.status_code == 404:
        result = {
            "status": "not_found",
            "sha256": key,
            "verdict": "unknown/not in VT",
            "malicious": 0,
            "suspicious": 0,
            "permalink": f"https://www.virustotal.com/gui/file/{key}",
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
        cache[key] = result
        _save_cache(base_dir, cache)
        return result

    if resp.status_code == 401 or resp.status_code == 403:
        raise VTLookupError("VirusTotal API rejected the configured VT_API_KEY")
    if resp.status_code == 429:
        raise VTLookupError("VirusTotal API rate limit reached")
    if resp.status_code >= 400:
        raise VTLookupError(f"VirusTotal API error: HTTP {resp.status_code}")

    normalized = _normalize_file_report(key, resp.json(), cache_hit=False)
    normalized["queried_at"] = datetime.now(timezone.utc).isoformat()
    cache[key] = normalized
    _save_cache(base_dir, cache)
    return normalized
