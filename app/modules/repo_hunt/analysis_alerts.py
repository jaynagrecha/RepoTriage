"""Analysis-time WU/MTCN LiveHunt evaluation + SMTP alert."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .config import RepoHuntConfig
from .detect.wu_keywords import RULE_ID, evaluate_wu_from_vt, match_wu_names
from .notify.smtp_mailer import build_analysis_wu_alert_email, send_email


def collect_wu_hits_from_analysis(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan inventory + root VT for WU/MTCN keywords with VT malicious > 0."""
    hits: list[dict[str, Any]] = []
    root_vt = result.get('vt') if isinstance(result.get('vt'), dict) else {}
    source = result.get('source') if isinstance(result.get('source'), dict) else {}
    root_file = result.get('root_file') if isinstance(result.get('root_file'), dict) else {}

    files = result.get('files') if isinstance(result.get('files'), list) else []
    if not files:
        # Synthesize root-only view
        files = [{
            'filename': root_file.get('filename') or source.get('filename'),
            'path': root_file.get('path') or source.get('path'),
            'original_name': root_file.get('vt_original_filename'),
            'sha256': root_file.get('sha256'),
            'size_bytes': root_file.get('size_bytes'),
            'vt_verdict': root_vt.get('verdict'),
            'vt_malicious': root_vt.get('malicious'),
            'vt_link': root_vt.get('permalink'),
            'vt_names': root_vt.get('names') or root_file.get('vt_names') or [],
            'vt_original_filename': root_vt.get('original_filename') or root_file.get('vt_original_filename'),
            'vt_popular_threat_label': root_vt.get('popular_threat_label'),
            'vt_family_labels': root_vt.get('family_labels') or [],
        }]

    for item in files:
        if not isinstance(item, dict):
            continue
        local_names = [
            item.get('filename'),
            item.get('original_name'),
            item.get('path'),
            item.get('vt_original_filename'),
            item.get('vt_meaningful_name'),
            source.get('filename'),
            source.get('path'),
            source.get('repo'),
            source.get('project'),
        ]
        # Prefer per-file VT fields; fall back to root VT for root row
        vt_report = {
            'status': 'found' if item.get('vt_verdict') else root_vt.get('status'),
            'verdict': item.get('vt_verdict') or root_vt.get('verdict'),
            'malicious': item.get('vt_malicious') if item.get('vt_malicious') is not None else root_vt.get('malicious'),
            'suspicious': item.get('vt_suspicious') if item.get('vt_suspicious') is not None else root_vt.get('suspicious'),
            'permalink': item.get('vt_link') or root_vt.get('permalink'),
            'names': item.get('vt_names') or root_vt.get('names') or [],
            'original_filename': item.get('vt_original_filename') or root_vt.get('original_filename'),
            'meaningful_name': item.get('vt_meaningful_name') or root_vt.get('meaningful_name'),
            'popular_threat_label': item.get('vt_popular_threat_label') or root_vt.get('popular_threat_label'),
            'family_labels': item.get('vt_family_labels') or root_vt.get('family_labels') or [],
            'size': item.get('size_bytes'),
        }
        hit = evaluate_wu_from_vt(
            local_names=local_names,
            vt_report=vt_report,
            filesize=int(item.get('size_bytes') or 0),
        )
        if not hit:
            continue
        hits.append({
            'rule': RULE_ID,
            'filename': item.get('filename') or item.get('path'),
            'path': item.get('path'),
            'url': source.get('display_url') or source.get('download_url') or source.get('html_url'),
            'sha256': item.get('sha256'),
            'matched_keywords': list(hit.matched_strings),
            'vt_verdict': vt_report.get('verdict'),
            'vt_malicious': vt_report.get('malicious'),
            'vt_link': vt_report.get('permalink'),
            'popular_threat_label': vt_report.get('popular_threat_label'),
            'family_labels': vt_report.get('family_labels') or [],
        })
    return hits


def maybe_send_analysis_wu_alert(
    result: dict[str, Any],
    *,
    job_id: str | None = None,
    cfg: RepoHuntConfig | None = None,
) -> dict[str, Any]:
    """Send SMTP alert when analysis finds WU/MTCN + VT malicious. Never raises."""
    cfg = cfg or RepoHuntConfig.from_env()
    if not cfg.analysis_alert_email:
        return {'ok': False, 'skipped': True, 'reason': 'ANALYSIS_ALERT_EMAIL disabled'}
    if not cfg.smtp_ready():
        return {'ok': False, 'skipped': True, 'reason': 'smtp_not_configured'}

    hits = collect_wu_hits_from_analysis(result)
    if not hits:
        return {'ok': True, 'skipped': True, 'reason': 'no_wu_hits', 'hits': 0}

    source = result.get('source') if isinstance(result.get('source'), dict) else {}
    source_url = source.get('display_url') or source.get('download_url') or ''
    triage = ''
    if cfg.triage_base_url and source_url:
        triage = f"{cfg.triage_base_url}/?url={quote(source_url, safe='')}&auto=1&src=wu-alert"
    elif job_id and cfg.triage_base_url:
        triage = f'{cfg.triage_base_url}/?job={quote(job_id, safe="")}'

    msg = build_analysis_wu_alert_email(
        cfg=cfg,
        job_id=job_id,
        source_url=source_url,
        hits=hits,
        triage_url=triage,
        scan_mode='analyze',
    )
    sent = send_email(msg, cfg)
    sent['hits'] = len(hits)
    sent['rule'] = RULE_ID
    sent['keywords'] = sorted({k for h in hits for k in (h.get('matched_keywords') or [])})
    return sent
