from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Any
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


def _ptc_values(entries: Any, limit: int = 12) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(entries, list):
        return out
    for item in entries:
        if not isinstance(item, dict):
            continue
        value = (item.get('value') or '').strip()
        if not value:
            continue
        try:
            count = int(item.get('count') or 0)
        except Exception:
            count = 0
        out.append({'value': value, 'count': count})
        if len(out) >= limit:
            break
    return out


def _family_from_attrs(attrs: dict, detections: list[dict]) -> dict:
    # VT can expose popular_threat_classification in newer reports.
    ptc = attrs.get("popular_threat_classification") or {}
    suggested = (ptc.get("suggested_threat_label") or "").strip()
    family_labels = _ptc_values(ptc.get("popular_threat_name"))
    categories = _ptc_values(ptc.get("popular_threat_category"))
    if suggested or family_labels:
        primary = family_labels[0]["value"] if family_labels else (suggested.split(".")[-1].split("/")[0] if suggested else "Unknown")
        return {
            "name": suggested or primary,
            "primary_family": primary,
            "popular_threat_label": suggested or None,
            "family_labels": [x["value"] for x in family_labels],
            "family_label_counts": family_labels,
            "threat_categories": [x["value"] for x in categories],
            "threat_category_counts": categories,
            "confidence": 85 if suggested else 70,
            "source": "virustotal_popular_threat_classification",
        }

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
        return {
            "name": "Unknown",
            "primary_family": "Unknown",
            "popular_threat_label": None,
            "family_labels": [],
            "family_label_counts": [],
            "threat_categories": [],
            "threat_category_counts": [],
            "confidence": 0,
            "source": "none",
        }
    name, count = sorted(tokens.items(), key=lambda kv: kv[1], reverse=True)[0]
    confidence = min(75, 25 + count * 10)
    return {
        "name": name,
        "primary_family": name,
        "popular_threat_label": None,
        "family_labels": [name],
        "family_label_counts": [{"value": name, "count": count}],
        "threat_categories": [],
        "threat_category_counts": [],
        "confidence": confidence,
        "source": "detection_name_heuristic",
    }


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
    meaningful = (attrs.get("meaningful_name") or "").strip() or None
    # Prefer VT meaningful/original names first for display.
    ordered_names: list[str] = []
    if meaningful:
        ordered_names.append(meaningful)
    for n in names:
        s = str(n).strip()
        if s and s not in ordered_names:
            ordered_names.append(s)

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
        "popular_threat_label": family.get("popular_threat_label"),
        "family_labels": family.get("family_labels") or [],
        "threat_categories": family.get("threat_categories") or [],
        "tags": tags[:25] if isinstance(tags, list) else [],
        "names": ordered_names[:20],
        "meaningful_name": meaningful,
        "original_filename": meaningful or (ordered_names[0] if ordered_names else None),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "permalink": link,
        "raw_available": True,
        "contacted_domains": [],
        "contacted_ips": [],
        "contacted_urls": [],
        "contacts_fetched": False,
        "relations": {},
        "relations_fetched": False,
        "schema": 3,
    }


def _stats_detections(stats: dict | None) -> dict:
    stats = stats if isinstance(stats, dict) else {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "detections": f"{malicious}/{total}" if total else "-",
    }


def _normalize_relation_item(row: dict, relationship: str) -> dict | None:
    if not isinstance(row, dict):
        return None
    rid = (row.get("id") or "").strip()
    rtype = (row.get("type") or "").strip()
    attrs = row.get("attributes") if isinstance(row.get("attributes"), dict) else {}
    if not rid:
        return None

    item: dict = {
        "id": rid,
        "type": rtype or "unknown",
        "relationship": relationship,
    }

    if rtype == "file" or relationship in {
        "execution_parents", "compressed_parents", "bundled_files", "dropped_files",
    }:
        names = attrs.get("names") or []
        meaningful = (attrs.get("meaningful_name") or "").strip()
        name = meaningful or (names[0] if names else rid[:16])
        stats = _stats_detections(attrs.get("last_analysis_stats"))
        item.update({
            "name": name,
            "names": names[:8] if isinstance(names, list) else [],
            "file_type": attrs.get("type_description") or attrs.get("type_tag") or "",
            "size": attrs.get("size"),
            "sha256": rid if len(rid) == 64 else attrs.get("sha256"),
            "permalink": f"https://www.virustotal.com/gui/file/{rid}",
            **stats,
        })
        from .filename_signals import detect_dual_extension
        dual = detect_dual_extension(name)
        if not dual:
            for n in names[:5]:
                dual = detect_dual_extension(n)
                if dual:
                    break
        if dual:
            item["dual_extension"] = dual
        return item

    if rtype == "url" or relationship in {"itw_urls", "contacted_urls"}:
        stats = _stats_detections(attrs.get("last_analysis_stats"))
        url = attrs.get("url") or rid
        item.update({
            "url": url,
            "name": url,
            "last_http_response_code": attrs.get("last_http_response_code"),
            "permalink": f"https://www.virustotal.com/gui/url/{rid}" if len(rid) == 64 else "",
            **stats,
        })
        return item

    if rtype in {"domain", "ip_address"} or relationship in {
        "itw_domains", "contacted_domains", "contacted_ips",
    }:
        stats = _stats_detections(attrs.get("last_analysis_stats"))
        item.update({
            "name": rid,
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "country": attrs.get("country"),
            "permalink": (
                f"https://www.virustotal.com/gui/domain/{rid}"
                if rtype == "domain" or relationship.endswith("domains")
                else f"https://www.virustotal.com/gui/ip-address/{rid}"
            ),
            **stats,
        })
        return item

    item["name"] = rid
    return item


async def _fetch_relationship_items(
    client: httpx.AsyncClient,
    sha256: str,
    relationship: str,
    headers: dict[str, str],
    limit: int = 20,
) -> list[dict]:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}/{relationship}"
    try:
        resp = await client.get(url, headers=headers, params={"limit": limit})
    except httpx.HTTPError:
        return []
    if resp.status_code != 200:
        return []
    rows = (resp.json().get("data") or [])
    out: list[dict] = []
    for row in rows:
        item = _normalize_relation_item(row, relationship)
        if item:
            out.append(item)
    return out


async def _fetch_relationship_ids(client: httpx.AsyncClient, sha256: str, relationship: str, headers: dict[str, str], limit: int = 40) -> list[str]:
    items = await _fetch_relationship_items(client, sha256, relationship, headers, limit=limit)
    out: list[str] = []
    for item in items:
        # Prefer human identifier
        for key in ("url", "name", "id"):
            val = (item.get(key) or "").strip()
            if val:
                out.append(val)
                break
    return out


_RELATION_KEYS = (
    "execution_parents",
    "compressed_parents",
    "bundled_files",
    "dropped_files",
    "itw_urls",
    "itw_domains",
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
)


async def enrich_vt_contacts(report: dict, base_dir: Path) -> dict:
    """Backward-compatible wrapper — full relations enrichment."""
    return await enrich_vt_relations(report, base_dir)


async def enrich_vt_relations(report: dict, base_dir: Path) -> dict:
    """Attach VT Relations graph: parents, dropped/bundled, ITW, contacted infra."""
    if not isinstance(report, dict) or report.get("status") != "found":
        return report
    sha256 = (report.get("sha256") or "").strip().lower()
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not sha256 or not api_key:
        return report
    if report.get("relations_fetched") and int(report.get("schema") or 0) >= 3:
        return report

    headers = {"x-apikey": api_key}
    relations: dict[str, list] = {k: [] for k in _RELATION_KEYS}
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            for key in _RELATION_KEYS:
                relations[key] = await _fetch_relationship_items(client, sha256, key, headers, limit=20)
    except Exception:
        pass

    report["relations"] = relations
    report["relations_fetched"] = True
    report["contacted_domains"] = [x.get("name") or x.get("id") for x in relations.get("contacted_domains") or [] if x][:40]
    report["contacted_ips"] = [x.get("name") or x.get("id") for x in relations.get("contacted_ips") or [] if x][:40]
    report["contacted_urls"] = [x.get("url") or x.get("name") or x.get("id") for x in relations.get("contacted_urls") or [] if x][:40]
    report["contacts_fetched"] = True
    report["schema"] = 3

    # Dual-extension hits across relation filenames + VT names
    from .filename_signals import scan_names_for_dual_extension
    name_pool: list[str] = list(report.get("names") or [])
    if report.get("original_filename"):
        name_pool.append(report["original_filename"])
    for bucket in ("execution_parents", "compressed_parents", "bundled_files", "dropped_files"):
        for row in relations.get(bucket) or []:
            if row.get("name"):
                name_pool.append(row["name"])
            name_pool.extend(row.get("names") or [])
    report["dual_extensions"] = scan_names_for_dual_extension(name_pool)

    graph_summary = {k: len(relations.get(k) or []) for k in _RELATION_KEYS}
    graph_summary["dual_extensions"] = len(report["dual_extensions"])
    report["relations_graph_summary"] = graph_summary

    try:
        cache = _load_cache(base_dir)
        cache[sha256] = {k: v for k, v in report.items() if k != "cache_hit"}
        _save_cache(base_dir, cache)
    except Exception:
        pass
    return report


async def lookup_file_hash(sha256: str, base_dir: Path, force_refresh: bool = False) -> dict:
    key = sha256.lower().strip()
    api_key = os.getenv("VT_API_KEY", "").strip()
    permalink = f"https://www.virustotal.com/gui/file/{key}"
    if not api_key:
        return {
            "status": "not_configured",
            "sha256": key,
            "verdict": "unknown",
            "message": "VT_API_KEY is not configured",
            "permalink": permalink,
        }

    cache = _load_cache(base_dir)
    if not force_refresh and key in cache:
        item = cache[key]
        # Bust stale cache missing relations schema
        if isinstance(item, dict) and item.get("status") == "found" and int(item.get("schema") or 0) >= 3:
            item["cache_hit"] = True
            if not item.get("relations_fetched"):
                item = await enrich_vt_relations(item, base_dir)
            return item

    url = f"https://www.virustotal.com/api/v3/files/{key}"
    headers = {"x-apikey": api_key}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        return {
            "status": "error",
            "sha256": key,
            "verdict": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "permalink": permalink,
            "message": f"VirusTotal request failed: {exc.__class__.__name__}",
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }

    if resp.status_code == 404:
        result = {
            "status": "not_found",
            "sha256": key,
            "verdict": "unknown/not in VT",
            "malicious": 0,
            "suspicious": 0,
            "permalink": permalink,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }
        cache[key] = result
        _save_cache(base_dir, cache)
        return result

    if resp.status_code in {401, 403}:
        return {
            "status": "auth_error",
            "sha256": key,
            "verdict": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "permalink": permalink,
            "message": "VirusTotal API rejected the configured VT_API_KEY",
            "http": resp.status_code,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }

    if resp.status_code == 429:
        retry_after = (resp.headers.get("Retry-After") or "").strip()
        message = "VirusTotal API rate limit reached"
        if retry_after:
            message = f"{message} (retry after {retry_after}s)"
        return {
            "status": "rate_limited",
            "sha256": key,
            "verdict": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "permalink": permalink,
            "message": message,
            "http": 429,
            "retry_after": retry_after or None,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }

    if resp.status_code >= 400:
        return {
            "status": "error",
            "sha256": key,
            "verdict": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "permalink": permalink,
            "message": f"VirusTotal API error: HTTP {resp.status_code}",
            "http": resp.status_code,
            "queried_at": datetime.now(timezone.utc).isoformat(),
        }

    normalized = _normalize_file_report(key, resp.json(), cache_hit=False)
    normalized["queried_at"] = datetime.now(timezone.utc).isoformat()
    normalized = await enrich_vt_relations(normalized, base_dir)
    cache[key] = {k: v for k, v in normalized.items() if k != "cache_hit"}
    _save_cache(base_dir, cache)
    return normalized
