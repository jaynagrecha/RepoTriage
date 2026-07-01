from __future__ import annotations

import asyncio
import json
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
from .modules.static_analysis import analyze_file_async
from .modules.static_analysis.indicators import build_extracted_indicators
from .modules.integrations import send_webhook

BASE_DIR = Path(__file__).resolve().parent.parent
PLATFORM_VERSION = '4.0.0-alpha.1'


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

    bundle: dict = {'version': PLATFORM_VERSION, 'sha256': sha256, 'filename': filename}

    static = await analyze_file_async(path, filename=filename, declared_type=file_type, sha256=sha256, vt_verdict=vt_verdict)
    bundle['static_analysis'] = static

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

    indicators = static.get('extracted_indicators') or build_extracted_indicators(static)
    bundle['ioc_reputation'] = await enrich_indicators(indicators, BASE_DIR)
    db.save_artifact(job_id, sha256, 'ioc_reputation', bundle['ioc_reputation'], PLATFORM_VERSION)

    domains = (indicators.get('domains') or [])[:12]
    bundle['cert_intel'] = await enrich_domains(domains)
    db.save_artifact(job_id, sha256, 'cert_intel', bundle['cert_intel'], PLATFORM_VERSION)

    bundle['family_hints'] = parse_family_indicators(path)
    db.save_artifact(job_id, sha256, 'family_hints', bundle['family_hints'], PLATFORM_VERSION)

    bundle['combined_verdict'] = _combined_verdict(bundle)
    bundle['confidence_explanation'] = _confidence_explanation(bundle)
    db.save_artifact(job_id, sha256, 'deep_analysis_bundle', bundle, PLATFORM_VERSION)

    if bundle['combined_verdict'] in {'malicious', 'suspicious'}:
        await send_webhook('deep_analysis.completed', {'job_id': job_id, 'sha256': sha256, 'verdict': bundle['combined_verdict'], 'filename': filename})

    return bundle


def _combined_verdict(bundle: dict) -> str:
    scores = []
    static_v = ((bundle.get('static_analysis') or {}).get('static_verdict') or {}).get('verdict')
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
    if (bundle.get('family_hints') or {}).get('match_count', 0) >= 2:
        scores.append('suspicious')
    if 'malicious' in scores:
        return 'malicious'
    if 'suspicious' in scores:
        return 'suspicious'
    if static_v == 'needs_review':
        return 'needs_review'
    return static_v or 'clean'


def _confidence_explanation(bundle: dict) -> dict:
    reasons = []
    static = (bundle.get('static_analysis') or {}).get('static_verdict') or {}
    for sig in (static.get('signals') or [])[:5]:
        reasons.append({'source': 'static', 'label': sig.get('label'), 'evidence': sig.get('evidence')})
    for m in (bundle.get('yara') or {}).get('matches') or []:
        reasons.append({'source': 'yara', 'label': m.get('rule'), 'evidence': (m.get('meta') or {}).get('description', '')})
    for b in (bundle.get('sandbox_lite') or {}).get('behaviors') or []:
        reasons.append({'source': 'sandbox_lite', 'label': b, 'evidence': 'behavioral marker'})
    return {'reasons': reasons, 'upgrade_hint': 'Re-run deep analysis after engine updates or when sandbox-lite adds new behavior rules.'}


HANDLERS = {
    'deep_analysis': handle_deep_analysis,
}


async def process_task(db: PlatformDB, task: dict) -> None:
    queue = TaskQueue(db)
    task_id = task['task_id']
    task_type = task['task_type']
    handler = HANDLERS.get(task_type)
    if not handler:
        queue.fail(task_id, f'unknown task type: {task_type}')
        return
    try:
        result = await handler(db, task)
        queue.complete(task_id, result)
    except Exception as exc:
        queue.fail(task_id, str(exc))


async def worker_loop(poll_seconds: float = 2.0) -> None:
    db = PlatformDB(BASE_DIR)
    queue = TaskQueue(db)
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
