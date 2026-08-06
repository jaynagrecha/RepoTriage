from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx

from .cti_query_policy import (
    filter_threatfox_matches,
    select_malware_ioc_candidates,
    should_query_threatfox,
)

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def _cache_path(base_dir: Path) -> Path:
    p = base_dir / "data" / "threatfox_cache.json"
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


def _enabled() -> bool:
    return os.getenv("THREATFOX_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def _headers() -> dict:
    headers = {"Content-Type": "application/json"}
    key = os.getenv("THREATFOX_API_KEY") or os.getenv("ABUSECH_API_KEY")
    if key:
        headers["Auth-Key"] = key
    return headers


def _classify_indicator(indicator: str) -> str:
    s = (indicator or "").lower()
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if all(c.isdigit() or c == "." for c in s) and s.count(".") == 3:
        return "ip"
    if len(s) in {32, 40, 64} and all(c in "0123456789abcdef" for c in s):
        return "hash"
    return "domain"


def _tf_link(ioc_id: str | None) -> str | None:
    if not ioc_id:
        return None
    return f"https://threatfox.abuse.ch/ioc/{ioc_id}/"


def _infra_role(threat_type: str | None, indicator: str = "") -> tuple[str, str]:
    t = (threat_type or "").lower().strip()
    s = (indicator or "").lower()
    if t in {"botnet_cc", "c2", "cc", "command_and_control"}:
        return "Probable C2", "High"
    if t in {"payload_delivery", "malware_download", "payload"}:
        return "Payload Delivery", "High"
    if t in {"phishing"}:
        return "Credential Theft / Phishing Infrastructure", "Medium"
    if "discord" in s or "webhook" in s:
        return "Exfiltration / Webhook Channel", "High"
    if "telegram" in s or "t.me/" in s:
        return "Control Channel", "Medium"
    if t:
        return t.replace("_", " ").title(), "Medium"
    return "ThreatFox Match", "Medium"


def _severity_from_confidence(confidence: Any) -> str:
    try:
        c = int(confidence)
    except Exception:
        return "Unknown"
    if c >= 80:
        return "High"
    if c >= 50:
        return "Medium"
    return "Low"


def normalize_result(indicator: str, payload: dict, cache_hit: bool = False) -> dict:
    status = payload.get("query_status", "unknown") if isinstance(payload, dict) else "unknown"
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        rows = []

    cleaned = []
    max_rows = int(os.getenv("THREATFOX_MAX_ROWS_PER_IOC", "10"))
    for row in rows[:max_rows]:
        ioc = row.get("ioc") or indicator
        role, role_conf = _infra_role(row.get("threat_type"), ioc)
        cleaned.append({
            "ioc_id": row.get("id"),
            "ioc": ioc,
            "ioc_type": row.get("ioc_type") or _classify_indicator(ioc),
            "threat_type": row.get("threat_type"),
            "infrastructure_role": role,
            "infrastructure_confidence": role_conf,
            "malware": row.get("malware") or row.get("malware_printable"),
            "malware_printable": row.get("malware_printable"),
            "malware_alias": row.get("malware_alias"),
            "confidence_level": row.get("confidence_level"),
            "confidence_band": _severity_from_confidence(row.get("confidence_level")),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "reference": row.get("reference"),
            "tags": row.get("tags") or [],
            "reporter": row.get("reporter"),
            "threatfox_link": _tf_link(str(row.get("id")) if row.get("id") else None),
        })

    cleaned = filter_threatfox_matches(indicator, cleaned)

    return {
        "indicator": indicator,
        "indicator_type": _classify_indicator(indicator),
        "status": "found" if cleaned else ("not_found" if status in {"no_result", "ok"} else status),
        "query_status": status,
        "matches": cleaned,
        "match_count": len(cleaned),
        "cache_hit": cache_hit,
    }


async def lookup_ioc(indicator: str, base_dir: Path, *, allow_domain: bool = False) -> dict:
    indicator = (indicator or "").strip()
    if not indicator:
        return {"indicator": indicator, "status": "invalid", "matches": [], "match_count": 0}
    if not _enabled():
        return {"indicator": indicator, "status": "disabled", "matches": [], "match_count": 0}

    allowed, skip_reason = should_query_threatfox(indicator, allow_domain=allow_domain)
    if not allowed:
        return {
            "indicator": indicator,
            "indicator_type": _classify_indicator(indicator),
            "status": "skipped",
            "skip_reason": skip_reason,
            "matches": [],
            "match_count": 0,
            "exact_match_only": True,
        }

    cache = _load_cache(base_dir)
    key = f"exact:{indicator.lower()}"
    if key in cache:
        return normalize_result(indicator, cache[key], cache_hit=True)

    timeout = float(os.getenv("THREATFOX_TIMEOUT", "18"))
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                THREATFOX_API,
                headers=_headers(),
                json={"query": "search_ioc", "search_term": indicator, "exact_match": True},
            )
            r.raise_for_status()
            payload = r.json()
    except Exception as e:
        return {"indicator": indicator, "status": "error", "error": str(e), "matches": [], "match_count": 0}

    cache[key] = payload
    _save_cache(base_dir, cache)
    result = normalize_result(indicator, payload, cache_hit=False)
    result["exact_match_only"] = True
    return result


def _build_relationships(found: list[dict]) -> dict:
    by_family = defaultdict(list)
    by_threat_type = defaultdict(list)
    by_role = defaultdict(list)
    timeline = []
    all_matches = []

    for item in found:
        for m in item.get("matches", []) or []:
            match = {"source_indicator": item.get("indicator"), **m}
            all_matches.append(match)
            fam = m.get("malware") or "Unknown"
            typ = m.get("threat_type") or "unknown"
            role = m.get("infrastructure_role") or "ThreatFox Match"
            by_family[fam].append(match)
            by_threat_type[typ].append(match)
            by_role[role].append(match)
            if m.get("first_seen") or m.get("last_seen"):
                timeline.append({
                    "indicator": m.get("ioc") or item.get("indicator"),
                    "malware": fam,
                    "threat_type": typ,
                    "first_seen": m.get("first_seen"),
                    "last_seen": m.get("last_seen"),
                    "confidence_level": m.get("confidence_level"),
                })

    def compact(mapping):
        return {k: v[:25] for k, v in sorted(mapping.items(), key=lambda kv: (-len(kv[1]), kv[0]))}

    timeline.sort(key=lambda x: (x.get("first_seen") or "9999", x.get("indicator") or ""))
    return {
        "all_matches": all_matches,
        "by_family": compact(by_family),
        "by_threat_type": compact(by_threat_type),
        "by_infrastructure_role": compact(by_role),
        "timeline": timeline[:100],
    }


def _build_summary(lookups: list[dict], found: list[dict]) -> dict:
    malware_families = []
    threat_types = []
    roles = defaultdict(int)
    highest = None
    active = 0
    oldest = None
    newest = None
    match_count = 0

    for item in found:
        for m in item.get("matches", []) or []:
            match_count += 1
            fam = m.get("malware")
            typ = m.get("threat_type")
            role = m.get("infrastructure_role") or "ThreatFox Match"
            if fam and fam not in malware_families:
                malware_families.append(fam)
            if typ and typ not in threat_types:
                threat_types.append(typ)
            roles[role] += 1
            if m.get("last_seen"):
                active += 1
            if m.get("first_seen") and (oldest is None or m.get("first_seen") < oldest):
                oldest = m.get("first_seen")
            if m.get("first_seen") and (newest is None or m.get("first_seen") > newest):
                newest = m.get("first_seen")
            try:
                conf = int(m.get("confidence_level") or 0)
                if highest is None or conf > int(highest.get("confidence_level") or 0):
                    highest = {"indicator": m.get("ioc") or item.get("indicator"), "confidence_level": conf, "malware": fam, "threat_type": typ, "role": role}
            except Exception:
                pass

    return {
        "looked_up": len(lookups),
        "found": len(found),
        "match_count": match_count,
        "malware_families": malware_families,
        "threat_types": threat_types,
        "infrastructure_roles": dict(roles),
        "probable_c2": roles.get("Probable C2", 0),
        "payload_delivery": roles.get("Payload Delivery", 0),
        "malware_downloads": roles.get("Malware Hosting", 0) + roles.get("Payload Delivery", 0),
        "highest_confidence": highest,
        "oldest_first_seen": oldest,
        "newest_first_seen": newest,
        "active_or_recent_rows": active,
    }


async def enrich_iocs(iocs: dict, base_dir: Path) -> dict:
    """Lookup malware IOCs in ThreatFox — exact match; VT-contacted domains allowed."""
    from .cti_query_policy import vt_sourced_domains

    if not _enabled():
        return {"enabled": False, "status": "disabled", "lookups": [], "found": [], "summary": {"looked_up": 0, "found": 0}, "relationships": {}}

    limit = int(os.getenv("THREATFOX_LOOKUP_LIMIT", "75"))
    candidates = select_malware_ioc_candidates(iocs, limit=limit, include_vt_domains=True)
    vt_domains = {d.lower() for d in vt_sourced_domains(iocs)}

    lookups = []
    found = []
    for indicator in candidates:
        allow_domain = indicator.strip().lower() in vt_domains
        res = await lookup_ioc(indicator, base_dir, allow_domain=allow_domain)
        lookups.append(res)
        if res.get("status") == "found":
            found.append(res)

    relationships = _build_relationships(found)
    summary = _build_summary(lookups, found)

    return {
        "enabled": True,
        "status": "completed",
        "exact_match_only": True,
        "vt_domains_queried": sorted(vt_domains),
        "lookups": lookups,
        "found": found,
        "summary": summary,
        "relationships": relationships,
        "policy_note": (
            "Queries malware IOCs (URLs, IPs, hashes, webhooks) plus VirusTotal contacted domains. "
            "Static-extracted bare domains/emails/wallets stay display-only. Exact match; platform hosts skipped. "
            "Query-only — RepoTriage does not submit IOCs to ThreatFox."
        ),
    }
