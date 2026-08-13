from pathlib import Path
import os
import shutil
from datetime import datetime, timezone, timedelta
import asyncio
import json
import uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .modules.downloader import download_file, DownloadError
from .modules.job_cache import cache_job_inventory, cached_file_path, load_manifest, manifest_entry
from .modules.static_analysis import StaticAnalysisError, analyze_file_async
from .modules.static_analysis.store import load_record, public_record, save_record
from .modules.static_analysis.versioning import is_stale_record, STATIC_ANALYSIS_VERSION
from .modules.hash_engine import hash_file
from .modules.file_type import guess_file_type
from .modules.vt_lookup import lookup_file_hash, VTLookupError
from .modules.extractor import extract_recursive, is_archive
from .modules.ioc_extractor import extract_iocs_from_file, merge_iocs, classify_infrastructure
from .modules.cti_query_policy import threatfox_match_is_exact
from .modules.threatfox import enrich_iocs
from .modules.malwarebazaar import enrich_files as enrich_malwarebazaar
from .modules.urlhaus import enrich_iocs as enrich_urlhaus
from .modules.abusech_connector import enrich_feodo, enrich_sslbl, abusech_summary, abusech_key
from .modules.cti_selftest import run_cti_selftest
from .modules.repo_hunt import HuntState, RepoHuntConfig, run_repo_hunt
from .modules.repo_hunt.analysis_alerts import collect_wu_hits_from_analysis, maybe_send_analysis_wu_alert
from .modules.filename_signals import detect_dual_extension, scan_names_for_dual_extension
from .modules.mitre_mapper import map_mitre
from .modules.narrative import generate_attack_narrative
from .modules.cti_fusion import build_cti_dashboard, build_infrastructure_graph, discover_related_samples, build_campaign_analysis, build_threat_actor_assessment, build_correlation_matrix, build_analyst_report, export_csv, export_stix, export_misp
from .modules.rate_limit import UsageLimiter, RateLimitExceeded
from .platform import PlatformDB, TaskQueue
from .platform.worker_config import inline_worker_enabled
from .modules.deep_analysis.llm_semantic import llm_configured

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

APP_VERSION = '4.0.0-alpha.38'
PLATFORM_VERSION = '4.0.0-alpha.38'

app = FastAPI(title='RepoTriage', version=APP_VERSION)
app.mount('/static', StaticFiles(directory=str(BASE_DIR / 'app' / 'static')), name='static')

USAGE_LIMITER = UsageLimiter(BASE_DIR)
PLATFORM_DB = PlatformDB(BASE_DIR)
TASK_QUEUE = TaskQueue(PLATFORM_DB)


@app.on_event('startup')
async def _startup_platform():
    app.state.platform_db = PLATFORM_DB
    app.state.base_dir = BASE_DIR
    app.state.task_queue = TASK_QUEUE
    from .v4_routes import router as v4_router

    app.include_router(v4_router)
    if inline_worker_enabled():
        from .worker_main import worker_loop

        poll = float(os.getenv('WORKER_POLL_SECONDS', '2'))
        app.state.deep_worker_active = True
        asyncio.create_task(worker_loop(poll))
    else:
        app.state.deep_worker_active = False


def _enqueue_deep_analysis_for_job(job_id: str) -> None:
    if not _env_truthy('AUTO_DEEP_ANALYSIS', False):
        return
    manifest = load_manifest(BASE_DIR, job_id) or {}
    for entry in manifest.get('files') or []:
        if not entry.get('cached') or not entry.get('sha256'):
            continue
        TASK_QUEUE.enqueue(
            'deep_analysis',
            job_id=job_id,
            sha256=entry['sha256'],
            payload={
                'filename': entry.get('display_name') or entry.get('filename'),
                'file_type': entry.get('file_type'),
                'vt_verdict': entry.get('vt_verdict'),
            },
        )


def _env_truthy(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}


def get_client_ip(request: Request) -> str:
    if _env_truthy('TRUST_PROXY'):
        xff = request.headers.get('x-forwarded-for')
        if xff:
            return xff.split(',')[0].strip()
        xrip = request.headers.get('x-real-ip')
        if xrip:
            return xrip.strip()
    return request.client.host if request.client else 'unknown'


def _strip_local_paths(obj):
    if isinstance(obj, dict):
        return {k: _strip_local_paths(v) for k, v in obj.items() if k != 'local_path'}
    if isinstance(obj, list):
        return [_strip_local_paths(v) for v in obj]
    return obj


def _public_result(result: dict | None) -> dict | None:
    if not result:
        return result
    sanitized = _strip_local_paths(result)
    source = sanitized.get('source')
    if isinstance(source, dict):
        source = dict(source)
        source.pop('local_path', None)
        sanitized['source'] = source
    extraction = sanitized.get('extraction')
    if isinstance(extraction, dict):
        extraction = dict(extraction)
        extraction.pop('extract_dir', None)
        sanitized['extraction'] = extraction
    return sanitized


def _public_job(job: dict) -> dict:
    public = dict(job)
    public.pop('client_ip', None)
    if public.get('result'):
        public['result'] = _public_result(public['result'])
    return public


def _quarantine_targets(meta: dict | None, extraction: dict | None) -> list[Path]:
    targets: list[Path] = []
    if meta and meta.get('local_path'):
        targets.append(Path(meta['local_path']))
    if extraction and extraction.get('extract_dir'):
        targets.append(Path(extraction['extract_dir']))
    return targets


def _cleanup_quarantine(meta: dict | None, extraction: dict | None) -> None:
    if _env_truthy('KEEP_QUARANTINE'):
        return
    for target in _quarantine_targets(meta, extraction):
        try:
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
            elif target.is_file():
                target.unlink(missing_ok=True)
        except Exception:
            pass

def active_jobs_for_ip(ip: str) -> int:
    count = 0
    seen_ids: set[str] = set()
    for job in JOBS.values():
        if job.get('client_ip') == ip and job.get('status') in {'queued', 'running'}:
            count += 1
            if job.get('job_id'):
                seen_ids.add(job['job_id'])
    jobs_dir = BASE_DIR / 'data' / 'jobs'
    for p in jobs_dir.glob('*.json'):
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            jid = data.get('job_id')
            if jid and jid in seen_ids:
                continue
            if data.get('client_ip') == ip and data.get('status') in {'queued', 'running'}:
                count += 1
        except Exception:
            continue
    return count

class AnalyzeRequest(BaseModel):
    file_url: str = Field(
        ...,
        examples=[
            'https://github.com/user/repo/blob/main/payload.zip',
            'https://github.com/user/malware-drop.7z',
            'https://gist.github.com/user/gistid',
            'https://gitlab.com/group/project',
            'https://gitlab.com/group/project/-/blob/main/payload.zip',
        ],
    )

    @field_validator('file_url')
    @classmethod
    def strip_file_url(cls, value: str) -> str:
        return (value or '').strip()


def build_summary(meta: dict, hashes: dict, file_type: str, vt: dict) -> str:
    verdict = vt.get('verdict', 'unknown')
    family = (vt.get('family') or {}).get('name', 'Unknown')
    popular = vt.get('popular_threat_label') or (vt.get('family') or {}).get('popular_threat_label')
    family_labels = vt.get('family_labels') or (vt.get('family') or {}).get('family_labels') or []
    malicious = vt.get('malicious', 0)
    suspicious = vt.get('suspicious', 0)
    status = vt.get('status')
    if status == 'not_configured':
        vt_line = 'VirusTotal enrichment was skipped because VT_API_KEY is not configured.'
    elif status == 'not_found':
        vt_line = 'VirusTotal does not currently have a report for this file hash.'
    elif status == 'rate_limited':
        vt_line = vt.get('message') or 'VirusTotal enrichment was skipped due to API rate limiting.'
    elif status == 'auth_error':
        vt_line = vt.get('message') or 'VirusTotal enrichment was skipped because VT_API_KEY was rejected.'
    elif status == 'error':
        vt_line = vt.get('message') or 'VirusTotal enrichment failed; continuing without VT verdict.'
    else:
        vt_line = f"VirusTotal verdict: {verdict} ({malicious} malicious / {suspicious} suspicious)."
    family_line = f"Family/label: {family}."
    if popular:
        family_line += f" Popular threat label: {popular}."
    if family_labels:
        family_line += f" Family labels: {', '.join(family_labels)}."
    names = vt.get('names') or []
    name_line = ''
    if vt.get('original_filename') or names:
        shown = vt.get('original_filename') or names[0]
        extras = [n for n in names if n and n != shown][:5]
        name_line = f"\nVT original name: {shown}."
        if extras:
            name_line += f" Also known as: {', '.join(extras)}."
    contacts = []
    contacts.extend(vt.get('contacted_domains') or [])
    contacts.extend(vt.get('contacted_ips') or [])
    contacts.extend((vt.get('contacted_urls') or [])[:5])
    contact_line = ''
    if contacts:
        contact_line = f"\nVT contacted infrastructure: {', '.join(contacts[:12])}."
    return (
        f"RepoTriage {APP_VERSION} acquired the remote-hosted file and calculated MD5/SHA1/SHA256.\n\n"
        f"File: {meta.get('filename')}\n"
        f"Type: {file_type}\n"
        f"SHA256: {hashes.get('sha256')}\n\n"
        f"{vt_line}\n"
        f"{family_line}"
        f"{name_line}"
        f"{contact_line}\n\n"
        f"Archive extraction, IOC extraction, Abuse.ch CTI enrichment, MITRE ATT&CK mapping, and infrastructure classification are enabled in this build."
    )


def _annotate_dual_extension(entry: dict) -> dict:
    names = [
        entry.get('filename'),
        entry.get('original_name'),
        entry.get('path'),
        entry.get('vt_original_filename'),
        entry.get('vt_meaningful_name'),
    ]
    names.extend(entry.get('vt_names') or [])
    hits = scan_names_for_dual_extension(names)
    if hits:
        entry['dual_extension'] = hits[0]
        entry['dual_extensions'] = hits
    return entry


def _build_relations_view(vt_result: dict, inventory: list[dict], meta: dict) -> dict:
    """Merge VT Relations with local extraction hierarchy for the UI."""
    vt_rel = (vt_result.get('relations') if isinstance(vt_result, dict) else None) or {}
    dual = list(vt_result.get('dual_extensions') or []) if isinstance(vt_result, dict) else []

    local_extracted = []
    for item in inventory[1:]:
        row = {
            'id': item.get('sha256'),
            'sha256': item.get('sha256'),
            'name': item.get('original_name') or item.get('filename') or item.get('path'),
            'file_type': item.get('file_type'),
            'size': item.get('size_bytes'),
            'malicious': item.get('vt_malicious') or 0,
            'suspicious': item.get('vt_suspicious') or 0,
            'detections': (
                f"{item.get('vt_malicious') or 0}/?"
                if item.get('vt_verdict') else '-'
            ),
            'permalink': item.get('vt_link'),
            'relationship': 'extracted_children',
            'source': 'local_extraction',
            'parent_archive': item.get('parent_archive'),
            'depth': item.get('depth'),
        }
        dual_hit = item.get('dual_extension') or detect_dual_extension(row['name'])
        if dual_hit:
            row['dual_extension'] = dual_hit
            dual.append(dual_hit)
        local_extracted.append(row)

    # Dedup dual extensions
    dual = scan_names_for_dual_extension([d.get('filename') for d in dual if isinstance(d, dict)] + [
        x.get('name') for x in local_extracted
    ])

    graph = dict(vt_result.get('relations_graph_summary') or {}) if isinstance(vt_result, dict) else {}
    for key in (
        'execution_parents', 'compressed_parents', 'bundled_files', 'dropped_files',
        'itw_urls', 'itw_domains', 'contacted_domains', 'contacted_ips', 'contacted_urls',
    ):
        graph.setdefault(key, len(vt_rel.get(key) or []))
    graph['extracted_children'] = len(local_extracted)
    graph['dual_extensions'] = len(dual)

    return {
        'execution_parents': list(vt_rel.get('execution_parents') or []),
        'compressed_parents': list(vt_rel.get('compressed_parents') or []),
        'bundled_files': list(vt_rel.get('bundled_files') or []),
        'dropped_files': list(vt_rel.get('dropped_files') or []),
        'extracted_children': local_extracted,
        'itw_urls': list(vt_rel.get('itw_urls') or []),
        'itw_domains': list(vt_rel.get('itw_domains') or []),
        'contacted_domains': list(vt_rel.get('contacted_domains') or []),
        'contacted_ips': list(vt_rel.get('contacted_ips') or []),
        'contacted_urls': list(vt_rel.get('contacted_urls') or []),
        'dual_extensions': dual,
        'graph_summary': graph,
        'permalink': (vt_result or {}).get('permalink'),
        'root_name': meta.get('filename') or (inventory[0].get('filename') if inventory else None),
        'root_sha256': (inventory[0].get('sha256') if inventory else None) or (vt_result or {}).get('sha256'),
    }


def _vt_inventory_fields(vt: dict | None) -> dict:
    vt = vt if isinstance(vt, dict) else {}
    family = vt.get('family') if isinstance(vt.get('family'), dict) else {}
    return {
        'vt_verdict': vt.get('verdict'),
        'vt_malicious': vt.get('malicious'),
        'vt_suspicious': vt.get('suspicious'),
        'vt_link': vt.get('permalink'),
        'vt_names': list(vt.get('names') or []),
        'vt_meaningful_name': vt.get('meaningful_name'),
        'vt_original_filename': vt.get('original_filename'),
        'vt_popular_threat_label': vt.get('popular_threat_label') or family.get('popular_threat_label'),
        'vt_family_labels': list(vt.get('family_labels') or family.get('family_labels') or []),
        'vt_threat_categories': list(vt.get('threat_categories') or family.get('threat_categories') or []),
        'vt_contacted_domains': list(vt.get('contacted_domains') or []),
        'vt_contacted_ips': list(vt.get('contacted_ips') or []),
        'vt_contacted_urls': list(vt.get('contacted_urls') or []),
    }


def merge_vt_contacts_into_iocs(iocs: dict, vt_reports: list[dict]) -> dict:
    """Fold VirusTotal contacted_* relationships into merged IOC buckets."""
    from urllib.parse import urlparse

    merged = dict(iocs or {})
    for key in ('urls', 'domains', 'ips', 'emails', 'discord_webhooks', 'telegram', 'wallets'):
        merged.setdefault(key, [])
    details = dict(merged.get('ioc_details') or {})
    domain_details = {str(r.get('indicator', '')).lower(): r for r in (details.get('domains') or []) if isinstance(r, dict)}
    ip_details = {str(r.get('indicator', '')).lower(): r for r in (details.get('ips') or []) if isinstance(r, dict)}
    url_details = {str(r.get('indicator', '')).lower(): r for r in (details.get('urls') or []) if isinstance(r, dict)}

    def _note(bucket_map: dict, indicator: str, source: str) -> None:
        key = indicator.lower()
        if key in bucket_map:
            srcs = bucket_map[key].setdefault('sources', [])
            if source not in srcs:
                srcs.append(source)
            return
        bucket_map[key] = {
            'indicator': indicator,
            'confidence': 'High',
            'reason': 'VirusTotal sandbox/behavior relationship',
            'sources': [source],
        }

    for report in vt_reports:
        if not isinstance(report, dict) or report.get('status') != 'found':
            continue
        sha = (report.get('sha256') or '')[:12] or 'vt'
        src = f'VirusTotal:{sha}'
        for domain in report.get('contacted_domains') or []:
            d = str(domain).strip().lower()
            if not d:
                continue
            merged['domains'].append(d)
            _note(domain_details, d, src)
        for ip in report.get('contacted_ips') or []:
            ip_s = str(ip).strip()
            if not ip_s:
                continue
            merged['ips'].append(ip_s)
            _note(ip_details, ip_s, src)
        for url in report.get('contacted_urls') or []:
            u = str(url).strip()
            if not u:
                continue
            merged['urls'].append(u)
            _note(url_details, u, src)
            try:
                host = (urlparse(u).hostname or '').lower()
            except Exception:
                host = ''
            if host:
                merged['domains'].append(host)
                _note(domain_details, host, src)

    def _uniq(seq: list) -> list:
        out, seen = [], set()
        for item in seq:
            k = str(item).strip().lower()
            if not k or k in seen:
                continue
            seen.add(k)
            out.append(item if not isinstance(item, str) else item.strip())
        return out

    for key in ('urls', 'domains', 'ips', 'emails', 'discord_webhooks', 'telegram', 'wallets'):
        merged[key] = _uniq(merged.get(key) or [])
    details['domains'] = list(domain_details.values())
    details['ips'] = list(ip_details.values())
    details['urls'] = list(url_details.values())
    merged['ioc_details'] = details
    return merged


def integrate_vt_infrastructure(infra: dict, vt_reports: list[dict]) -> dict:
    """Surface VT contacted_* as staging/contacted infra (not CTI-confirmed C2)."""
    infra = dict(infra or {})
    infra.setdefault('vt_contacted', [])
    infra.setdefault('probable_c2', [])
    seen = set()
    for bucket, rows in list(infra.items()):
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    seen.add((bucket, str(row.get('indicator')).lower()))

    for report in vt_reports:
        if not isinstance(report, dict) or report.get('status') != 'found':
            continue
        permalink = report.get('permalink')
        for domain in report.get('contacted_domains') or []:
            indicator = str(domain).strip().lower()
            key = ('vt_contacted', indicator)
            if not indicator or key in seen:
                continue
            seen.add(key)
            infra['vt_contacted'].append({
                'indicator': indicator,
                'type': 'VT Contacted Domain',
                'severity': 'Medium',
                'source': 'VirusTotal',
                'reference': permalink,
                'cti_note': 'Queried on ThreatFox + URLHaus host API; Feodo/SSLBL need IPs',
            })
        for ip in report.get('contacted_ips') or []:
            indicator = str(ip).strip()
            key = ('vt_contacted', indicator.lower())
            if not indicator or key in seen:
                continue
            seen.add(key)
            infra['vt_contacted'].append({
                'indicator': indicator,
                'type': 'VT Contacted IP',
                'severity': 'Medium',
                'source': 'VirusTotal',
                'reference': permalink,
                'cti_note': 'Checked against ThreatFox + FeodoTracker + SSLBL feeds',
            })
        for url in report.get('contacted_urls') or []:
            indicator = str(url).strip()
            key = ('vt_contacted', indicator.lower())
            if not indicator or key in seen:
                continue
            seen.add(key)
            infra['vt_contacted'].append({
                'indicator': indicator,
                'type': 'VT Contacted URL',
                'severity': 'Medium',
                'source': 'VirusTotal',
                'reference': permalink,
                'cti_note': 'Queried on ThreatFox + URLHaus URL API',
            })
    return infra

def integrate_threatfox_infrastructure(infra: dict, threatfox: dict) -> dict:
    """Merge ThreatFox classifications into the Infrastructure tab."""
    infra = dict(infra or {})
    infra.setdefault('probable_c2', [])
    infra.setdefault('control_channels', [])
    infra.setdefault('exfil_channels', [])
    infra.setdefault('config_sources', [])
    infra.setdefault('payload_delivery', [])
    infra.setdefault('malware_downloads', [])
    infra.setdefault('known_bad_infrastructure', [])

    role_to_bucket = {
        'Probable C2': 'probable_c2',
        'Payload Delivery': 'payload_delivery',
        'Malware Hosting': 'malware_downloads',
        'Control Channel': 'control_channels',
        'Exfiltration / Webhook Channel': 'exfil_channels',
        'Credential Theft / Phishing Infrastructure': 'known_bad_infrastructure',
    }
    seen = set()
    for bucket, rows in list(infra.items()):
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    seen.add((bucket, str(row.get('indicator')).lower()))

    for item in (threatfox or {}).get('found', []) or []:
        queried = item.get('indicator') or ''
        for m in item.get('matches', []) or []:
            if not threatfox_match_is_exact(queried, str(m.get('ioc') or '')):
                continue
            role = m.get('infrastructure_role') or 'ThreatFox Match'
            bucket = role_to_bucket.get(role, 'known_bad_infrastructure')
            indicator = m.get('ioc') or item.get('indicator')
            key = (bucket, str(indicator).lower())
            if not indicator or key in seen:
                continue
            seen.add(key)
            infra.setdefault(bucket, []).append({
                'indicator': indicator,
                'type': role,
                'confidence': m.get('infrastructure_confidence') or m.get('confidence_band') or 'Medium',
                'source': 'ThreatFox',
                'malware': m.get('malware'),
                'threat_type': m.get('threat_type'),
                'confidence_level': m.get('confidence_level'),
                'first_seen': m.get('first_seen'),
                'last_seen': m.get('last_seen'),
                'reference': m.get('reference') or m.get('threatfox_link'),
            })
    return infra



def integrate_abusech_infrastructure(infra: dict, urlhaus: dict, feodo: dict, sslbl: dict) -> dict:
    """Merge URLHaus/Feodo/SSLBL matches into the Infrastructure tab."""
    infra = dict(infra or {})
    infra.setdefault('payload_delivery', [])
    infra.setdefault('probable_c2', [])
    infra.setdefault('known_bad_infrastructure', [])
    seen = set()
    for bucket, rows in list(infra.items()):
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    seen.add((bucket, str(row.get('indicator')).lower()))

    for row in (urlhaus or {}).get('results', []) or []:
        if not row.get('found'):
            continue
        is_host = str(row.get('indicator_type') or '') in {'domain/host', 'host', 'domain'}
        indicator = row.get('url') or row.get('indicator') or row.get('host')
        bucket = 'payload_delivery'
        key = (bucket, str(indicator).lower())
        if indicator and key not in seen:
            seen.add(key)
            infra[bucket].append({
                'indicator': indicator,
                'type': (
                    'URLHaus Host Match'
                    if is_host else
                    'Payload Delivery / Malware URL'
                ),
                'confidence': 'High',
                'source': 'URLHaus',
                'threat': row.get('threat'),
                'families': row.get('families'),
                'status': row.get('url_status'),
                'url_count': row.get('url_count'),
                'reference': row.get('link') or (
                    f"https://urlhaus.abuse.ch/host/{indicator}/" if is_host and indicator else None
                ),
            })

    for row in (feodo or {}).get('matches', []) or []:
        indicator = row.get('ip')
        bucket = 'probable_c2'
        key = (bucket, str(indicator).lower())
        if indicator and key not in seen:
            seen.add(key)
            infra[bucket].append({
                'indicator': indicator,
                'type': 'Botnet C2',
                'confidence': 'High',
                'source': 'FeodoTracker',
                'malware': row.get('malware'),
                'status': row.get('status'),
                'reference': 'https://feodotracker.abuse.ch/browse/',
            })

    for row in (sslbl or {}).get('matches', []) or []:
        indicator = row.get('ip')
        bucket = 'known_bad_infrastructure'
        key = (bucket, str(indicator).lower())
        if indicator and key not in seen:
            seen.add(key)
            infra[bucket].append({
                'indicator': indicator,
                'type': 'Malicious SSL / JA3 Infrastructure',
                'confidence': 'High',
                'source': 'SSLBL',
                'ja3': row.get('ja3'),
                'port': row.get('port'),
                'reference': 'https://sslbl.abuse.ch/',
            })
    return infra

@app.get('/')
async def home():
    return FileResponse(str(BASE_DIR / 'app' / 'static' / 'index.html'))

JOBS: dict[str, dict] = {}
JOBS_DIR = BASE_DIR / 'data' / 'jobs'
JOBS_DIR.mkdir(parents=True, exist_ok=True)

def _job_file(job_id: str) -> Path:
    safe = ''.join(ch for ch in job_id if ch.isalnum() or ch in '-_')
    return JOBS_DIR / f'{safe}.json'

def _save_job(job_id: str) -> None:
    try:
        with _job_file(job_id).open('w', encoding='utf-8') as f:
            json.dump(JOBS[job_id], f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _load_job(job_id: str) -> dict | None:
    if job_id in JOBS:
        return JOBS[job_id]
    p = _job_file(job_id)
    if not p.exists():
        return None
    try:
        job = json.loads(p.read_text(encoding='utf-8'))
        JOBS[job_id] = job
        return job
    except Exception:
        return None

def _cleanup_old_jobs() -> None:
    ttl_hours = int(os.getenv('JOB_TTL_HOURS', '24'))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    for p in JOBS_DIR.glob('*.json'):
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            ts = data.get('created_at') or data.get('updated_at')
            if ts and datetime.fromisoformat(ts.replace('Z','+00:00')) < cutoff:
                p.unlink(missing_ok=True)
        except Exception:
            continue

def _require_admin(request: Request) -> None:
    expected = (USAGE_LIMITER.admin_bypass_token or os.getenv('ADMIN_BYPASS_TOKEN') or '').strip()
    provided = (request.headers.get('x-admin-bypass-token') or '').strip()
    if not expected or provided != expected:
        raise HTTPException(status_code=404, detail='Not found')


@app.get('/api/health')
async def health():
    return {
        'ok': True,
        'app': 'RepoTriage',
        'version': APP_VERSION,
        'vt_configured': bool(os.getenv('VT_API_KEY')),
        'abusech_configured': bool(abusech_key()),
        'analysis_mode': os.getenv('ANALYSIS_MODE', 'local_dev'),
        'server_analysis_mode': os.getenv('SERVER_ANALYSIS_MODE', 'false').lower() == 'true',
        'job_mode': True,
        'rate_limit_enabled': USAGE_LIMITER.enabled,
        'free_daily_analysis_limit': USAGE_LIMITER.free_daily_limit,
        'static_analysis_enabled': _env_truthy('STATIC_ANALYSIS_ENABLED', True),
        'platform_version': PLATFORM_VERSION,
        'auto_deep_analysis': _env_truthy('AUTO_DEEP_ANALYSIS', False),
        'worker_mode': _env_truthy('WORKER_ENABLED', True),
        'worker_inline': inline_worker_enabled(),
        'deep_worker_active': getattr(app.state, 'deep_worker_active', inline_worker_enabled()),
        'r2_available': bool(shutil.which(os.getenv('R2_BINARY', 'r2') or 'r2')),
        'burst_analysis_limit_per_minute': USAGE_LIMITER.burst_limit,
        'semantic_llm_configured': llm_configured(),
        'semantic_llm_provider': os.getenv('SEMANTIC_LLM_PROVIDER', 'openai'),
        'semantic_llm_model': os.getenv('OPENAI_MODEL', os.getenv('ANTHROPIC_MODEL', 'gpt-4o-mini')),
    }


@app.get('/api/admin/cti-selftest')
async def cti_selftest(request: Request):
    """Live Abuse.ch proof. Requires header x-admin-bypass-token = ADMIN_BYPASS_TOKEN."""
    _require_admin(request)
    report = await run_cti_selftest(BASE_DIR)
    status = 200 if report.get('ok') else 503
    return JSONResponse(report, status_code=status)


class RepoHuntIngestRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    repo: str | None = None
    path: str | None = None
    html_url: str | None = None
    src: str | None = 'repotrace'

    @field_validator('url')
    @classmethod
    def strip_url(cls, value: str) -> str:
        return (value or '').strip()


def _require_repo_hunt_webhook(request: Request) -> None:
    cfg = RepoHuntConfig.from_env()
    expected = (cfg.webhook_secret or '').strip()
    provided = (request.headers.get('x-repo-hunt-secret') or request.headers.get('x-webhook-secret') or '').strip()
    if not expected or provided != expected:
        raise HTTPException(status_code=401, detail='Invalid repo-hunt webhook secret')


@app.post('/api/repo-hunt/ingest')
async def repo_hunt_ingest(req: RepoHuntIngestRequest, request: Request):
    """A3 — RepoTrace / external handoff into the hunt queue."""
    _require_repo_hunt_webhook(request)
    state = HuntState(BASE_DIR)
    state.enqueue_webhook({
        'url': req.url,
        'repo': req.repo,
        'path': req.path,
        'html_url': req.html_url or req.url,
        'src': req.src or 'repotrace',
        'ingested_at': datetime.now(timezone.utc).isoformat(),
    })
    return {'ok': True, 'queued': True, 'url': req.url}


@app.post('/api/admin/repo-hunt/run')
async def repo_hunt_run(request: Request, send: bool = True):
    """Admin trigger for discovery → local JsOutProx prefilter → VT confirm → SMTP."""
    _require_admin(request)
    report = await run_repo_hunt(BASE_DIR, send=send)
    status = 200 if report.get('ok') else 503
    return JSONResponse(report, status_code=status)


@app.get('/api/admin/repo-hunt/status')
async def repo_hunt_status(request: Request):
    _require_admin(request)
    cfg = RepoHuntConfig.from_env()
    state = HuntState(BASE_DIR)
    return {
        'enabled': cfg.enabled,
        'smtp_ready': cfg.smtp_ready(),
        'github_token': bool(cfg.github_token),
        'vt_confirm': cfg.vt_confirm,
        'vt_configured': bool(cfg.vt_api_key),
        'livehunt_rule_id': cfg.vt_livehunt_rule_id or None,
        'livehunt_wu_rule_id': cfg.vt_livehunt_wu_rule_id or None,
        'wu_hunt_enabled': cfg.wu_hunt_enabled,
        'analysis_alert_email': cfg.analysis_alert_email,
        'hunt_loop': _env_truthy('REPO_HUNT_LOOP'),
        'hunt_interval_seconds': int(os.getenv('REPO_HUNT_INTERVAL_SECONDS') or '300'),
        'wu_scan': {
            'scheduled': True,
            'interval_seconds': int(os.getenv('REPO_HUNT_INTERVAL_SECONDS') or '300'),
            'email_only_on_hit': True,
            'rule': 'DETECT_GTI_MaliciousFilesWithWUKeywords',
        },
        'watched_orgs': cfg.github_orgs,
        'watched_users': cfg.github_users,
        'webhook_secret_configured': bool(cfg.webhook_secret),
        'queue_depth': len(state._load(state.queue_path, []) or []),
        'last_run': state.last_run(),
    }


async def _run_job(job_id: str, req: AnalyzeRequest) -> None:
    now = datetime.now(timezone.utc).isoformat()
    JOBS[job_id].update({'status': 'running', 'stage': 'analysis_started', 'updated_at': now})
    _save_job(job_id)
    try:
        result = await run_analysis(req, job_id=job_id)
        JOBS[job_id].update({
            'status': 'completed',
            'stage': 'completed',
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'result': result,
            'error': None,
        })
        _enqueue_deep_analysis_for_job(job_id)
    except Exception as e:
        detail = getattr(e, 'detail', None) or str(e)
        JOBS[job_id].update({
            'status': 'failed',
            'stage': 'failed',
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'error': str(detail),
        })
    _save_job(job_id)

@app.get('/api/usage')
async def usage_status(request: Request):
    ip = get_client_ip(request)
    admin_token = request.headers.get('x-admin-bypass-token')
    is_admin = bool(USAGE_LIMITER.admin_bypass_token and admin_token == USAGE_LIMITER.admin_bypass_token)
    return USAGE_LIMITER.get_status(ip, active_jobs_for_ip(ip), is_admin)

@app.post('/api/jobs')
async def create_job(req: AnalyzeRequest, request: Request):
    _cleanup_old_jobs()
    ip = get_client_ip(request)
    admin_token = request.headers.get('x-admin-bypass-token')
    try:
        usage = USAGE_LIMITER.check_and_consume(ip, req.file_url, active_jobs_for_ip(ip), admin_token)
    except RateLimitExceeded as e:
        raise HTTPException(status_code=429, detail={'message': e.message, 'usage': e.status})
    job_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    JOBS[job_id] = {
        'job_id': job_id,
        'status': 'queued',
        'stage': 'queued',
        'file_url': req.file_url,
        'client_ip': ip,
        'usage': usage,
        'created_at': now,
        'updated_at': now,
        'result': None,
        'error': None,
        'safety': {
            'user_endpoint_receives_samples': False,
            'samples_downloaded_on_backend_only': True,
            'analysis_mode': os.getenv('ANALYSIS_MODE', 'local_dev'),
            'server_analysis_mode': os.getenv('SERVER_ANALYSIS_MODE', 'false').lower() == 'true',
        },
    }
    _save_job(job_id)
    asyncio.create_task(_run_job(job_id, req))
    return {'job_id': job_id, 'status': 'queued', 'poll_url': f'/api/jobs/{job_id}', 'usage': usage}

@app.get('/api/jobs/{job_id}')
async def get_job(job_id: str):
    job = _load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    return _public_job(job)


@app.get('/api/jobs/{job_id}/export/json')
async def export_job_json(job_id: str):
    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Completed job result not found')
    return JSONResponse(_public_result(job['result']))

@app.get('/api/jobs/{job_id}/export/csv', response_class=PlainTextResponse)
async def export_job_csv(job_id: str):
    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Completed job result not found')
    return PlainTextResponse(export_csv(_public_result(job['result']) or {}), media_type='text/csv')

@app.get('/api/jobs/{job_id}/export/stix')
async def export_job_stix(job_id: str):
    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Completed job result not found')
    return JSONResponse(export_stix(_public_result(job['result']) or {}))

@app.get('/api/jobs/{job_id}/export/misp')
async def export_job_misp(job_id: str):
    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Completed job result not found')
    return JSONResponse(export_misp(_public_result(job['result']) or {}))

@app.get('/api/jobs/{job_id}/report/html', response_class=HTMLResponse)
async def export_job_report_html(job_id: str):
    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Completed job result not found')
    result = job['result']
    report = result.get('analyst_report') if isinstance(result.get('analyst_report'), dict) else None
    # Rebuild when missing or still on the legacy markdown→<br> HTML stub
    if not report or report.get('format') != 'templated_html_v1' or '<!DOCTYPE html>' not in str(report.get('html') or ''):
        report = build_analyst_report(result)
        result['analyst_report'] = report
        try:
            _save_job(job_id)
        except Exception:
            pass
    return HTMLResponse(report.get('html') or '')


STATIC_ANALYSIS_TASKS: dict[str, asyncio.Task] = {}


def _static_task_key(job_id: str, sha256: str) -> str:
    return f'{job_id}:{sha256.lower()}'


def _require_static_analysis_enabled() -> None:
    if not _env_truthy('STATIC_ANALYSIS_ENABLED', True):
        raise HTTPException(status_code=503, detail='Static analysis is disabled on this deployment')


async def _execute_static_analysis(job_id: str, sha256: str, entry: dict) -> None:
    key = _static_task_key(job_id, sha256)
    record = {
        'job_id': job_id,
        'sha256': sha256.lower(),
        'status': 'running',
        'started_at': datetime.now(timezone.utc).isoformat(),
        'filename': entry.get('display_name') or entry.get('filename'),
        'file_type': entry.get('file_type'),
    }
    save_record(BASE_DIR, job_id, sha256, record)
    try:
        path = cached_file_path(BASE_DIR, job_id, sha256)
        if not path:
            raise StaticAnalysisError('Cached file bytes are unavailable for this hash')
        report = await analyze_file_async(
            path,
            filename=entry.get('display_name') or entry.get('filename'),
            declared_type=entry.get('file_type'),
            sha256=sha256,
            vt_verdict=entry.get('vt_verdict'),
        )
        record.update(public_record(report) or {})
        record['status'] = 'completed'
        record['completed_at'] = datetime.now(timezone.utc).isoformat()
        save_record(BASE_DIR, job_id, sha256, record)
    except Exception as exc:
        record.update({
            'status': 'failed',
            'error': str(exc)[:500],
            'completed_at': datetime.now(timezone.utc).isoformat(),
        })
        save_record(BASE_DIR, job_id, sha256, record)
    finally:
        STATIC_ANALYSIS_TASKS.pop(key, None)


@app.get('/api/jobs/{job_id}/static-analysis')
async def list_static_analysis(job_id: str):
    _require_static_analysis_enabled()
    job = _load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    manifest = load_manifest(BASE_DIR, job_id) or {'files': []}
    items = []
    for entry in manifest.get('files') or []:
        sha256 = (entry.get('sha256') or '').lower()
        if not sha256:
            continue
        record = public_record(load_record(BASE_DIR, job_id, sha256)) or {'status': 'not_started'}
        stale = is_stale_record(record if record.get('status') == 'completed' else None)
        items.append({
            'sha256': sha256,
            'filename': entry.get('display_name') or entry.get('filename'),
            'file_type': entry.get('file_type'),
            'cached': bool(entry.get('cached')),
            'cache_reason': entry.get('cache_reason'),
            'vt_verdict': entry.get('vt_verdict'),
            'static_status': record.get('status', 'not_started'),
            'static_verdict': (record.get('static_verdict') or {}).get('verdict'),
            'static_verdict_label': (record.get('static_verdict') or {}).get('verdict_label'),
            'static_confidence': (record.get('static_verdict') or {}).get('confidence'),
            'analysis_version': record.get('analysis_version'),
            'stale': stale,
            'indicator_url_count': ((record.get('extracted_indicators') or {}).get('counts') or {}).get('urls', 0),
            'indicator_total': (record.get('extracted_indicators') or {}).get('total', 0),
        })
    return {
        'job_id': job_id,
        'job_status': job.get('status'),
        'files': items,
        'static_analysis_enabled': True,
        'static_analysis_version': STATIC_ANALYSIS_VERSION,
    }


@app.get('/api/jobs/{job_id}/files/{sha256}/static-analysis')
async def get_static_analysis(job_id: str, sha256: str):
    _require_static_analysis_enabled()
    job = _load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    record = public_record(load_record(BASE_DIR, job_id, sha256.lower()))
    if not record:
        entry = manifest_entry(BASE_DIR, job_id, sha256.lower())
        if not entry:
            raise HTTPException(status_code=404, detail='File hash not found in this job')
        return {
            'job_id': job_id,
            'sha256': sha256.lower(),
            'status': 'not_started',
            'cached': bool(entry.get('cached')),
            'cache_reason': entry.get('cache_reason'),
        }
    return record


@app.post('/api/jobs/{job_id}/files/{sha256}/static-analysis')
async def start_static_analysis(job_id: str, sha256: str, request: Request, force: bool = False):
    _require_static_analysis_enabled()
    job = _load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    if job.get('status') != 'completed':
        raise HTTPException(status_code=409, detail='Job must complete before static analysis can run')

    target = sha256.lower()
    entry = manifest_entry(BASE_DIR, job_id, target)
    if not entry:
        raise HTTPException(status_code=404, detail='File hash not found in this job inventory')
    if not entry.get('cached'):
        raise HTTPException(status_code=409, detail=entry.get('cache_reason') or 'File bytes were not cached for static analysis')

    existing = load_record(BASE_DIR, job_id, target)
    stale = is_stale_record(existing)
    if force or stale:
        existing = None
    if existing and existing.get('status') == 'running':
        return public_record(existing)
    if existing and existing.get('status') == 'completed':
        out = public_record(existing) or {}
        out['stale'] = False
        return out

    ip = get_client_ip(request)
    admin_token = request.headers.get('x-admin-bypass-token')
    if not stale:
        try:
            USAGE_LIMITER.check_static_analysis(ip, admin_token)
        except RateLimitExceeded as e:
            raise HTTPException(status_code=429, detail={'message': e.message, 'usage': e.status})

    key = _static_task_key(job_id, target)
    if key in STATIC_ANALYSIS_TASKS and not STATIC_ANALYSIS_TASKS[key].done():
        record = public_record(load_record(BASE_DIR, job_id, target))
        return record or {'status': 'running', 'job_id': job_id, 'sha256': target}

    queued = {
        'job_id': job_id,
        'sha256': target,
        'status': 'queued',
        'queued_at': datetime.now(timezone.utc).isoformat(),
        'filename': entry.get('display_name') or entry.get('filename'),
    }
    save_record(BASE_DIR, job_id, target, queued)
    STATIC_ANALYSIS_TASKS[key] = asyncio.create_task(_execute_static_analysis(job_id, target, entry))
    return public_record(load_record(BASE_DIR, job_id, target)) or queued

@app.post('/api/analyze')
async def analyze_endpoint(req: AnalyzeRequest):
    if not _env_truthy('ALLOW_SYNC_ANALYZE'):
        raise HTTPException(status_code=404, detail='Not found')
    try:
        return await run_analysis(req)
    except VTLookupError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except DownloadError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def run_analysis(req: AnalyzeRequest, job_id: str | None = None) -> dict:
    meta: dict | None = None
    extraction: dict = {'root_is_archive': False}
    try:
        file_url = (req.file_url or '').strip()
        if not file_url:
            raise DownloadError('file_url is required')
        meta = await download_file(file_url, BASE_DIR / 'quarantine' / 'downloads')
        hashes = hash_file(meta['local_path'])
        file_type = guess_file_type(meta['local_path'])
        vt_result = await lookup_file_hash(hashes['sha256'], BASE_DIR)

        max_depth = int(os.getenv('MAX_EXTRACT_DEPTH', '3'))
        max_files = int(os.getenv('MAX_EXTRACT_FILES', '250'))
        max_extract_bytes = int(os.getenv('MAX_EXTRACT_BYTES', '100000000'))
        extraction = {
            'enabled': True,
            'root_is_archive': False,
            'files': [],
            'errors': [],
            'max_depth': max_depth,
            'max_files': max_files,
        }

        # Always include the GitHub/GitLab-hosted root file first.
        inventory = [{
            'filename': meta['filename'],
            'path': meta.get('path') or meta['filename'],
            'local_path': meta['local_path'],
            'file_type': file_type,
            'size_bytes': hashes.get('size_bytes'),
            'md5': hashes.get('md5'),
            'sha1': hashes.get('sha1'),
            'sha256': hashes.get('sha256'),
            'parent_archive': None,
            'depth': 0,
            'is_archive': is_archive(meta['local_path']),
            'iocs': extract_iocs_from_file(meta['local_path']),
            **_vt_inventory_fields(vt_result),
        }]
        vt_reports: list[dict] = [vt_result]

        # If root file is an archive, extract it recursively and analyze every child file.
        if is_archive(meta['local_path']):
            extraction = extract_recursive(
                meta['local_path'],
                BASE_DIR / 'quarantine' / 'extracted',
                max_depth=max_depth,
                max_files=max_files,
                max_total_bytes=max_extract_bytes,
            )
            vt_sem = asyncio.Semaphore(int(os.getenv('VT_CONCURRENT_LIMIT', '5')))

            async def _lookup_vt_bounded(sha256: str) -> dict:
                async with vt_sem:
                    return await lookup_file_hash(sha256, BASE_DIR)

            pending_children: list[tuple] = []
            for child in extraction.get('files', []):
                child_path = child.get('local_path')
                try:
                    if child_path and Path(child_path).exists():
                        child_hashes = hash_file(child_path)
                        child_type = guess_file_type(child_path)
                        child_iocs = extract_iocs_from_file(child_path)
                    else:
                        child_hashes = {
                            'md5': child.get('md5'),
                            'sha1': child.get('sha1'),
                            'sha256': child.get('sha256'),
                            'size_bytes': child.get('size_bytes'),
                        }
                        child_type = guess_file_type(child.get('original_name') or child.get('filename') or 'sample.bin')
                        child_iocs = {}
                    if not child_hashes.get('sha256'):
                        raise ValueError('missing SHA256 after extraction')
                    pending_children.append((child, child_path, child_hashes, child_type, child_iocs))
                except Exception as e:
                    display_name = child.get('original_name') or child.get('filename') or child.get('path') or 'extracted file'
                    extraction.setdefault('errors', []).append(f"{display_name}: analysis failed after extraction: {e.__class__.__name__}: {str(e)[:180]}")

            if pending_children:
                vt_results = await asyncio.gather(
                    *[_lookup_vt_bounded(item[2]['sha256']) for item in pending_children],
                    return_exceptions=True,
                )
                for (child, child_path, child_hashes, child_type, child_iocs), child_vt in zip(pending_children, vt_results):
                    if isinstance(child_vt, Exception):
                        display_name = child.get('original_name') or child.get('filename') or child.get('path') or 'extracted file'
                        extraction.setdefault('errors', []).append(
                            f"{display_name}: VT lookup failed: {child_vt.__class__.__name__}: {str(child_vt)[:180]}"
                        )
                        continue
                    inventory.append({
                        'filename': child.get('filename'),
                        'original_name': child.get('original_name'),
                        'stored_name': child.get('stored_name'),
                        'path': child.get('path') or child.get('filename'),
                        'local_path': child_path,
                        'extracted_to_disk': child.get('extracted_to_disk'),
                        'blocked_by_local_av': child.get('blocked_by_local_av'),
                        'analysis_note': child.get('analysis_note'),
                        'file_type': child_type,
                        'size_bytes': child_hashes.get('size_bytes'),
                        'md5': child_hashes.get('md5'),
                        'sha1': child_hashes.get('sha1'),
                        'sha256': child_hashes.get('sha256'),
                        'parent_archive': child.get('parent_archive'),
                        'depth': child.get('depth'),
                        'is_archive': child.get('is_archive'),
                        'iocs': child_iocs,
                        **_vt_inventory_fields(child_vt),
                    })
                    vt_reports.append(child_vt)

        for entry in inventory:
            _annotate_dual_extension(entry)

        malicious_count = sum(1 for x in inventory if str(x.get('vt_verdict','')).lower() == 'malicious')
        suspicious_count = sum(1 for x in inventory if str(x.get('vt_verdict','')).lower() == 'suspicious')
        child_inventory = inventory[1:]
        child_malicious_count = sum(1 for x in child_inventory if str(x.get('vt_verdict','')).lower() == 'malicious')
        child_suspicious_count = sum(1 for x in child_inventory if str(x.get('vt_verdict','')).lower() == 'suspicious')
        unknown_count = sum(1 for x in inventory if 'unknown' in str(x.get('vt_verdict','')).lower() or not x.get('vt_verdict'))
        extracted_count = max(0, len(inventory) - 1)
        ioc_sources = [{'path': x.get('path') or x.get('filename'), 'iocs': x.get('iocs') or {}} for x in inventory]
        merged_iocs = merge_iocs(ioc_sources)
        merged_iocs = merge_vt_contacts_into_iocs(merged_iocs, vt_reports)
        infra = classify_infrastructure(merged_iocs)
        infra = integrate_vt_infrastructure(infra, vt_reports)
        threatfox = await enrich_iocs(merged_iocs, BASE_DIR)
        malwarebazaar = await enrich_malwarebazaar(inventory, BASE_DIR)
        urlhaus = await enrich_urlhaus(merged_iocs, BASE_DIR)
        feodo = await enrich_feodo(merged_iocs, BASE_DIR)
        sslbl = await enrich_sslbl(merged_iocs, BASE_DIR)
        abusech = abusech_summary(threatfox, malwarebazaar, urlhaus, feodo, sslbl)
        threat_intel_bundle = {'abusech': abusech, 'threatfox': threatfox, 'malwarebazaar': malwarebazaar, 'urlhaus': urlhaus, 'feodo': feodo, 'sslbl': sslbl}
        mitre = map_mitre(inventory, merged_iocs, threat_intel_bundle, infra, vt_result.get('family') or {'name':'Unknown'})
        infra = integrate_threatfox_infrastructure(infra, threatfox)
        infra = integrate_abusech_infrastructure(infra, urlhaus, feodo, sslbl)
        ioc_total = sum(len(v) for k, v in merged_iocs.items() if k != 'ioc_details')
        now = datetime.now(timezone.utc).isoformat()

        vt_configured = vt_result.get('status') not in {'not_configured', None}
        vt_lookup_ok = vt_result.get('status') in {'found', 'not_found'}
        children_vt_done = extracted_count > 0 and vt_configured and any(
            x.get('vt_verdict') is not None for x in inventory[1:]
        )
        pipeline = {
            'downloaded': True,
            'hashed': True,
            'vt_lookup': vt_lookup_ok,
            'vt_status': vt_result.get('status'),
            'archive_extraction': bool(extraction.get('root_is_archive')),
            'children_hashed': extracted_count > 0,
            'children_vt_lookup': children_vt_done,
            'ioc_extraction': True,
            'threat_intel': True,
            'mitre_mapping': True,
            'executive_summary': True,
            'cti_fusion': True,
        }

        summary = build_summary(meta, hashes, file_type, vt_result)
        if ioc_total:
            summary += f"\n\nIOC extraction: {ioc_total} indicator(s) extracted across {len([x for x in ioc_sources if sum(len(v) for v in (x.get('iocs') or {}).values())])} file(s)."
        if threatfox.get('summary', {}).get('found'):
            tf_sum = threatfox.get('summary', {})
            families = ', '.join(tf_sum.get('malware_families') or []) or 'Unknown'
            summary += f"\n\nThreatFox enrichment: {tf_sum.get('found', 0)} IOC(s) matched across {tf_sum.get('match_count', 0)} row(s). Families observed: {families}. Probable C2: {tf_sum.get('probable_c2', 0)}. Payload delivery: {tf_sum.get('payload_delivery', 0)}."

        mb_sum = malwarebazaar.get('summary', {})
        if mb_sum.get('found'):
            mb_families = ', '.join(mb_sum.get('families') or []) or 'Unknown'
            summary += f"\n\nMalwareBazaar enrichment: {mb_sum.get('found', 0)} known sample(s) matched. Families/signatures observed: {mb_families}."

        uh_sum = urlhaus.get('summary', {})
        if uh_sum.get('found'):
            uh_families = ', '.join(uh_sum.get('families') or []) or 'Unknown'
            summary += f"\n\nURLHaus enrichment: {uh_sum.get('found', 0)} URL/domain indicator(s) matched. Active payload URLs: {uh_sum.get('active_urls', 0)}. Families observed: {uh_families}."

        if feodo.get('summary', {}).get('matches') or sslbl.get('summary', {}).get('matches'):
            summary += f"\n\nAbuseCH infrastructure feeds: FeodoTracker C2 matches: {feodo.get('summary', {}).get('matches', 0)}. SSLBL matches: {sslbl.get('summary', {}).get('matches', 0)}."

        mitre_sum = mitre.get('summary', {}) if isinstance(mitre, dict) else {}
        if mitre_sum.get('count'):
            summary += f"\n\nMITRE ATT&CK mapping: {mitre_sum.get('count')} technique(s) across {mitre_sum.get('tactics')} tactic(s). High-confidence mappings: {mitre_sum.get('high_confidence', 0)}."

        if extraction.get('root_is_archive'):
            summary += f"\n\nArchive extraction: {extracted_count} child file(s) extracted/listed. Malicious children: {child_malicious_count}. Suspicious children: {child_suspicious_count}."
            if extraction.get('errors'):
                summary += f"\nExtraction notes/errors: {len(extraction.get('errors', []))}."

        preliminary = {
            'source': meta,
            'root_file': {
                'filename': meta['filename'],
                'path': meta.get('path'),
                'file_type': file_type,
                'vt_original_filename': vt_result.get('original_filename'),
                'vt_names': vt_result.get('names') or [],
                **hashes,
            },
            'vt': vt_result,
            'extraction': extraction,
            'file_stats': {
                'total_listed': len(inventory),
                'root_files': 1,
                'extracted_children': extracted_count,
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'child_malicious': child_malicious_count,
                'child_suspicious': child_suspicious_count,
                'unknown': unknown_count,
                'errors': len(extraction.get('errors', [])),
                'iocs': ioc_total,
            },
            'files': inventory,
            'iocs': merged_iocs,
            'ioc_sources': ioc_sources,
            'threat_intel': threat_intel_bundle,
            'family': vt_result.get('family') or {'name': 'Unknown', 'confidence': 0},
            'mitre': mitre,
            'infrastructure': infra,
        }
        attack_narrative = generate_attack_narrative(preliminary)
        preliminary['attack_narrative'] = attack_narrative
        cti_dashboard = build_cti_dashboard(preliminary)
        infrastructure_graph = build_infrastructure_graph(preliminary)
        related_samples = discover_related_samples(preliminary)
        campaign_analysis = build_campaign_analysis(preliminary)
        threat_actor_assessment = build_threat_actor_assessment(preliminary)
        correlation_matrix = build_correlation_matrix(preliminary)
        preliminary['cti_dashboard'] = cti_dashboard
        preliminary['infrastructure_graph'] = infrastructure_graph
        preliminary['related_samples'] = related_samples
        preliminary['campaign_analysis'] = campaign_analysis
        preliminary['threat_actor_assessment'] = threat_actor_assessment
        preliminary['correlation_matrix'] = correlation_matrix
        analyst_report = build_analyst_report(preliminary)
        summary += "\n\n---\n\n" + attack_narrative.get('markdown', '')

        result = {
            'status': 'completed',
            'version': APP_VERSION,
            'analyzed_at': now,
            'source': meta,
            'root_file': {
                'filename': meta['filename'],
                'path': meta.get('path'),
                'file_type': file_type,
                'vt_original_filename': vt_result.get('original_filename'),
                'vt_names': vt_result.get('names') or [],
                **hashes,
            },
            'pipeline': pipeline,
            'safety': {
                'analysis_mode': os.getenv('ANALYSIS_MODE', 'local_dev'),
                'server_analysis_mode': os.getenv('SERVER_ANALYSIS_MODE', 'false').lower() == 'true',
                'local_sample_warning': os.getenv('SERVER_ANALYSIS_MODE', 'false').lower() != 'true',
                'metadata_first_extraction': True,
                'user_endpoint_receives_samples': False,
            },
            'vt': vt_result,
            'extraction': extraction,
            'file_stats': {
                'total_listed': len(inventory),
                'root_files': 1,
                'extracted_children': extracted_count,
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'child_malicious': child_malicious_count,
                'child_suspicious': child_suspicious_count,
                'unknown': unknown_count,
                'errors': len(extraction.get('errors', [])),
                'iocs': ioc_total,
            },
            'files': inventory,
            'iocs': merged_iocs,
            'ioc_sources': ioc_sources,
            'threat_intel': threat_intel_bundle,
            'family': vt_result.get('family') or {'name': 'Unknown', 'confidence': 0},
            'mitre': mitre,
            'infrastructure': infra,
            'attack_narrative': attack_narrative,
            'cti_dashboard': cti_dashboard,
            'infrastructure_graph': infrastructure_graph,
            'related_samples': related_samples,
            'campaign_analysis': campaign_analysis,
            'threat_actor_assessment': threat_actor_assessment,
            'correlation_matrix': correlation_matrix,
            'analyst_report': analyst_report,
            'exports_stix': export_stix(preliminary),
            'exports_misp': export_misp(preliminary),
            'exports_available': ['json', 'csv', 'stix', 'misp', 'html_report'],
            'summary': summary,
            'relations': _build_relations_view(vt_result, inventory, meta),
        }
        rel = result['relations']
        if rel.get('dual_extensions'):
            summary += (
                f"\n\nDual-extension / masquerade filenames: {len(rel['dual_extensions'])} "
                f"({', '.join(d.get('label') or d.get('filename') for d in rel['dual_extensions'][:5])})."
            )
            result['summary'] = summary
        graph = rel.get('graph_summary') or {}
        if any(graph.get(k) for k in (
            'execution_parents', 'dropped_files', 'bundled_files', 'compressed_parents', 'extracted_children',
        )):
            summary += (
                f"\n\nVT/local relations: "
                f"execution_parents={graph.get('execution_parents', 0)}, "
                f"compressed_parents={graph.get('compressed_parents', 0)}, "
                f"bundled={graph.get('bundled_files', 0)}, "
                f"dropped={graph.get('dropped_files', 0)}, "
                f"extracted_children={graph.get('extracted_children', 0)}."
            )
            result['summary'] = summary
        wu_hits = collect_wu_hits_from_analysis(result)
        result['livehunt_matches'] = wu_hits
        if wu_hits:
            kw = sorted({k for h in wu_hits for k in (h.get('matched_keywords') or [])})
            summary += (
                f"\n\nLiveHunt WU/MTCN: {len(wu_hits)} file(s) matched "
                f"DETECT_GTI_MaliciousFilesWithWUKeywords"
                + (f" ({', '.join(kw)})." if kw else '.')
            )
            result['summary'] = summary
        result['alert_email'] = maybe_send_analysis_wu_alert(result, job_id=job_id)
        if job_id:
            cache_job_inventory(BASE_DIR, job_id, inventory)
        return _public_result(result)
    finally:
        _cleanup_quarantine(meta, extraction)
