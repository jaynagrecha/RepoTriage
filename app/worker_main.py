from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from .platform import PlatformDB, TaskQueue
from .modules.job_cache import cached_file_path
from .modules.yara_scanner import scan_file as yara_scan_file
from .modules.sandbox_lite import run_sandbox_lite
from .modules.macro_extractor import extract_office_macros
from .modules.similarity_engine import compute_ssdeep, similarity_report
from .modules.ioc_reputation import enrich_indicators
from .modules.cert_intel import enrich_domains
from .modules.family_parser import parse_family_indicators
from .modules.deep_analysis import run_deep_exclusive, build_deep_narrative, build_attack_chain
from .modules.deep_analysis.intel import enrich_file_intel
from .modules.static_analysis.store import load_record
from .modules.static_analysis import analyze_file_async
from .modules.static_analysis.indicators import build_extracted_indicators

BASE_DIR = Path(__file__).resolve().parent.parent
PLATFORM_VERSION = '4.0.0-alpha.2'
LOG = logging.getLogger('repotriage.worker')


async def handle_deep_analysis(db: PlatformDB, task: dict) -> dict:
    job_id = task.get('job_id') or ''
    sha256 = (task.get('sha256') or '').lower()
    payload = json.loads(task.get('payload_json') or '{}')
    filename = payload.get('filename') or 'file'
    file_type = payload.get('file_type')
    vt_verdict = payload.get('vt_verdict')

    path = cached_file_path(BASE_DIR, job_id, sha256)
    if not path:
        raise RuntimeError('cached file missing')

    bundle: dict = {'version': PLATFORM_VERSION, 'sha256': sha256, 'filename': filename, 'analysis_type': 'deep'}

    static = load_record(BASE_DIR, job_id, sha256)
    if static and static.get('status') == 'completed':
        bundle['static_reference'] = {'available': True, 'verdict': (static.get('static_verdict') or {}).get('verdict_label')}
    else:
        static = await analyze_file_async(path, filename=filename, declared_type=file_type, sha256=sha256, vt_verdict=vt_verdict)
        bundle['static_reference'] = {'available': True, 'verdict': (static.get('static_verdict') or {}).get('verdict_label'), 'note': 'static was not cached; ran during deep pass'}

    bundle['deep_exclusive'] = run_deep_exclusive(path, filename=filename, static=static)
    db.save_artifact(job_id, sha256, 'deep_exclusive', bundle['deep_exclusive'], PLATFORM_VERSION)

    bundle['yara'] = yara_scan_file(path, BASE_DIR)
    db.save_artifact(job_id, sha256, 'yara', bundle['yara'], PLATFORM_VERSION)

    bundle['sandbox_lite'] = run_sandbox_lite(path, filename=filename)
    db.save_artifact(job_id, sha256, 'sandbox_lite', bundle['sandbox_lite'], PLATFORM_VERSION)

    if filename.lower().endswith(('.docm', '.xlsm', '.pptm', '.docx', '.xlsx', '.pptx')):
        bundle['macros'] = extract_office_macros(path)
        db.save_artifact(job_id, sha256, 'macros', bundle['macros'], PLATFORM_VERSION)

    ssdeep = compute_ssdeep(path)
    db.upsert_fingerprint(sha256, ssdeep, job_id, filename)
    bundle['similarity'] = similarity_report(BASE_DIR, sha256, ssdeep, db)
    db.save_artifact(job_id, sha256, 'similarity', bundle['similarity'], PLATFORM_VERSION)

    indicators = build_extracted_indicators(static) if static else {}
    pe_embedded = (bundle['deep_exclusive'].get('pe') or {}).get('embedded_urls') or []
    script_urls = (bundle['deep_exclusive'].get('script') or {}).get('c2_urls') or []
    merged_iocs = dict(indicators)
    merged_iocs['urls'] = list(dict.fromkeys((indicators.get('urls') or []) + pe_embedded + script_urls))[:40]

    bundle['file_intel'] = await enrich_file_intel(sha256, filename, BASE_DIR, merged_iocs)
    db.save_artifact(job_id, sha256, 'file_intel', bundle['file_intel'], PLATFORM_VERSION)

    bundle['ioc_reputation'] = await enrich_indicators(merged_iocs, BASE_DIR)
    db.save_artifact(job_id, sha256, 'ioc_reputation', bundle['ioc_reputation'], PLATFORM_VERSION)

    domains = list(dict.fromkeys((indicators.get('domains') or []) + (bundle['deep_exclusive'].get('script') or {}).get('c2_domains') or []))[:12]
    bundle['cert_intel'] = await enrich_domains(domains)
    db.save_artifact(job_id, sha256, 'cert_intel', bundle['cert_intel'], PLATFORM_VERSION)

    bundle['family_hints'] = parse_family_indicators(path)
    db.save_artifact(job_id, sha256, 'family_hints', bundle['family_hints'], PLATFORM_VERSION)

    bundle['combined_verdict'] = _combined_verdict(bundle, static)
    bundle['attack_chain'] = build_attack_chain(bundle)
    bundle['deep_narrative'] = build_deep_narrative(bundle)
    bundle['confidence_explanation'] = _confidence_explanation(bundle, static)
    db.save_artifact(job_id, sha256, 'deep_analysis_bundle', bundle, PLATFORM_VERSION)

    if bundle['combined_verdict'] in {'malicious', 'suspicious'}:
        await send_webhook('deep_analysis.completed', {'job_id': job_id, 'sha256': sha256, 'verdict': bundle['combined_verdict'], 'filename': filename})

    return bundle


def _combined_verdict(bundle: dict, static: dict | None = None) -> str:
    scores = []
    static_v = ((static or {}).get('static_verdict') or {}).get('verdict')
    if static_v in {'malicious', 'suspicious'}:
        scores.append(static_v)
    yara_v = (bundle.get('yara') or {}).get('verdict')
    if yara_v in {'malicious', 'suspicious'}:
        scores.append(yara_v)
    sb_v = (bundle.get('sandbox_lite') or {}).get('verdict')
    if sb_v in {'malicious', 'suspicious'}:
        scores.append(sb_v)
    if (bundle.get('ioc_reputation') or {}).get('malicious_urls', 0) > 0:
        scores.append('malicious')
    if (bundle.get('file_intel') or {}).get('malwarebazaar', {}).get('found'):
        scores.append('malicious')
    if (bundle.get('family_hints') or {}).get('match_count', 0) >= 2:
        scores.append('suspicious')
    deep = bundle.get('deep_exclusive') or {}
    if (deep.get('script') or {}).get('likely_stages', 0) >= 3:
        scores.append('malicious')
    if (deep.get('pe') or {}).get('risk_score', 0) >= 40:
        scores.append('suspicious')
    if 'malicious' in scores:
        return 'malicious'
    if 'suspicious' in scores:
        return 'suspicious'
    if static_v == 'needs_review':
        return 'needs_review'
    return static_v or 'clean'


def _confidence_explanation(bundle: dict, static: dict | None = None) -> dict:
    reasons = []
    for item in (bundle.get('deep_exclusive') or {}).get('delta', {}).get('exclusive_findings') or []:
        reasons.append({'source': 'deep_exclusive', 'label': item.get('type'), 'evidence': item.get('value', '')[:200]})
    for m in (bundle.get('yara') or {}).get('matches') or []:
        reasons.append({'source': 'yara', 'label': m.get('rule'), 'evidence': (m.get('meta') or {}).get('description', '')})
    for b in (bundle.get('sandbox_lite') or {}).get('behaviors') or []:
        reasons.append({'source': 'sandbox_lite', 'label': b, 'evidence': 'behavioral marker'})
    mb = (bundle.get('file_intel') or {}).get('malwarebazaar') or {}
    if mb.get('found'):
        reasons.append({'source': 'malwarebazaar', 'label': mb.get('family'), 'evidence': 'Known sample in MalwareBazaar'})
    static_v = ((static or {}).get('static_verdict') or {})
    for sig in (static_v.get('signals') or [])[:3]:
        reasons.append({'source': 'static_reference', 'label': sig.get('label'), 'evidence': sig.get('evidence')})
    return {'reasons': reasons[:12], 'upgrade_hint': 'Deep analysis adds execution chains, PE import risk, live CTI, and YARA — beyond fast static RE.'}


HANDLERS = {
    'deep_analysis': handle_deep_analysis,
}


async def process_task(db: PlatformDB, task: dict) -> None:
    queue = TaskQueue(db)
    task_id = task['task_id']
    task_type = task['task_type']
    LOG.info('processing task %s type=%s job=%s sha256=%s', task_id, task_type, task.get('job_id'), task.get('sha256'))
    handler = HANDLERS.get(task_type)
    if not handler:
        queue.fail(task_id, f'unknown task type: {task_type}')
        return
    try:
        result = await handler(db, task)
        queue.complete(task_id, result)
        LOG.info('completed task %s type=%s', task_id, task_type)
    except Exception as exc:
        LOG.exception('failed task %s: %s', task_id, exc)
        queue.fail(task_id, str(exc))


async def worker_loop(poll_seconds: float = 2.0) -> None:
    db = PlatformDB(BASE_DIR)
    queue = TaskQueue(db)
    LOG.info('deep worker loop started poll=%ss db=%s', poll_seconds, db.db_path)
    while True:
        task = queue.claim()
        if not task:
            await asyncio.sleep(poll_seconds)
            continue
        await process_task(db, task)


def main() -> None:
    poll = float(os.getenv('WORKER_POLL_SECONDS', '2'))
    asyncio.run(worker_loop(poll))


if __name__ == '__main__':
    main()
