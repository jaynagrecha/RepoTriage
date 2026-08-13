from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..downloader import DownloadError, download_file
from .config import RepoHuntConfig
from .detect.local_jsoutprox import scan_bytes
from .detect.vt_confirm import confirm_with_virustotal
from .detect.wu_keywords import (
    DEFAULT_LIVEHUNT_RULE_ID as WU_LIVEHUNT_ID,
    RULE_ID as WU_RULE_ID,
    match_wu_names,
    scan_wu_names,
)
from .discovery.github_search import discover_github_code_search, discover_wu_github_repos
from .discovery.gitlab_search import discover_wu_gitlab_projects, expand_financial_gitlab_repos
from .discovery.org_watch import discover_watched_orgs_users
from .discovery.repo_commit_scan import RULE_ID as FINANCIAL_RULE_ID
from .discovery.repo_commit_scan import expand_financial_repos
from .discovery.webhook_queue import discover_webhook_queue
from .notify.smtp_mailer import build_findings_email, send_email
from .state import HuntState
from .types import Candidate, DetectionHit, Finding


def _dedupe_candidates(items: list[Candidate]) -> list[Candidate]:
    seen: set[str] = set()
    out: list[Candidate] = []
    for c in items:
        key = (c.url or '').strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _triage_link(cfg: RepoHuntConfig, file_url: str) -> str:
    if not cfg.triage_base_url:
        return ''
    return f"{cfg.triage_base_url}/?url={quote(file_url, safe='')}&auto=1&src=repotrace"


def _is_repo_watch_file(cand: Candidate) -> bool:
    return bool((cand.extra or {}).get('repo_watch_file')) or cand.source == 'financial_repo_watch'


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as fh:
        while True:
            chunk = fh.read(1024 * 256)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


async def _fetch_candidate_bytes(
    candidate: Candidate,
    out_dir: Path,
    *,
    max_bytes: int | None = None,
    keep_bytes: bool = True,
) -> tuple[bytes, str, str, int]:
    """Return (data_or_empty, filename, sha256, size).

    For VT-hash-only paths set keep_bytes=False to avoid loading whole files into RAM.
    """
    meta = await download_file(candidate.url, out_dir=out_dir, max_bytes=max_bytes)
    path = Path(meta['local_path'])
    size = int(meta.get('downloaded_bytes') or path.stat().st_size)
    sha256 = _sha256_file(path)
    filename = meta.get('filename') or path.name
    data = b''
    if keep_bytes:
        data = path.read_bytes()
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass
    return data, filename, sha256, size


async def collect_candidates(
    cfg: RepoHuntConfig,
    state: HuntState,
) -> tuple[list[Candidate], dict[str, int], list[str]]:
    sources: dict[str, int] = {}
    errors: list[str] = []
    all_items: list[Candidate] = []

    async def _safe(name: str, coro) -> list[Candidate]:
        try:
            return await coro
        except Exception as exc:
            errors.append(f'{name}: {exc.__class__.__name__}: {exc}')
            return []

    search = await _safe('github_search', discover_github_code_search(cfg))
    sources['github_search'] = len(search)
    all_items.extend(search)

    wu_repos = await _safe('github_repo_search_wu', discover_wu_github_repos(cfg))
    sources['github_repo_search_wu'] = len(wu_repos)
    wu_repos = wu_repos[: max(0, int(cfg.repo_watch_max_repos))]

    # Expand keyword-matched repos → last N commits / top M newest files.
    repo_files = await _safe('financial_repo_watch', expand_financial_repos(cfg, wu_repos))
    sources['financial_repo_watch'] = len(repo_files)
    all_items.extend(repo_files)

    gl_repos = await _safe('gitlab_repo_search_wu', discover_wu_gitlab_projects(cfg))
    sources['gitlab_repo_search_wu'] = len(gl_repos)
    gl_repos = gl_repos[: max(0, int(cfg.repo_watch_max_repos))]
    gl_files = await _safe('financial_repo_watch_gitlab', expand_financial_gitlab_repos(cfg, gl_repos))
    sources['financial_repo_watch_gitlab'] = len(gl_files)
    all_items.extend(gl_files)

    watched = await _safe('org_watch', discover_watched_orgs_users(cfg))
    sources['org_watch'] = len(watched)
    all_items.extend(watched)

    try:
        queued = discover_webhook_queue(state)
    except Exception as exc:
        errors.append(f'webhook: {exc.__class__.__name__}: {exc}')
        queued = []
    sources['webhook'] = len(queued)
    all_items.extend(queued)
    if errors:
        sources['discovery_errors'] = len(errors)

    classic = [c for c in all_items if not _is_repo_watch_file(c)]
    watch = [c for c in all_items if _is_repo_watch_file(c)]
    watch = _dedupe_candidates(watch)[: max(0, int(cfg.repo_watch_max_files))]
    deduped = _dedupe_candidates(classic)[: cfg.max_candidates] + watch
    return deduped, sources, errors


def _wu_hit_from_names(
    *,
    names: list[str],
    filesize: int,
    livehunt_rule_id: str,
) -> DetectionHit | None:
    hit = scan_wu_names(names, filesize=filesize)
    if not hit:
        return None
    hit.vt_confirm = {
        'livehunt_rule_id': livehunt_rule_id or WU_LIVEHUNT_ID,
        'status': 'pending_vt',
    }
    return hit


def _wu_passes_vt(hit: DetectionHit) -> bool:
    """VT malicious > 0 (or explicit malicious verdict)."""
    vt = hit.vt_confirm or {}
    try:
        malicious = int(vt.get('malicious') or 0)
    except Exception:
        malicious = 0
    verdict = str(vt.get('verdict') or '').lower()
    return malicious > 0 or verdict == 'malicious'


def _repo_watch_keywords(cand: Candidate) -> list[str]:
    q = str((cand.extra or {}).get('query') or '').strip()
    return [q] if q else ['financial_repo_watch']


async def run_repo_hunt(base_dir: Path, *, cfg: RepoHuntConfig | None = None, send: bool = True) -> dict[str, Any]:
    cfg = cfg or RepoHuntConfig.from_env()
    state = HuntState(base_dir)
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    report: dict[str, Any] = {
        'ok': False,
        'enabled': cfg.enabled,
        'started_at': started,
        'sources': {},
        'candidates': 0,
        'downloaded': 0,
        'local_matches': 0,
        'wu_name_matches': 0,
        'wu_vt_clean_skips': 0,
        'financial_repo_files': 0,
        'financial_repo_vt_clean': 0,
        'watch_skipped_oversized': 0,
        'new_findings': 0,
        'findings': [],
        'email': None,
        'errors': [],
    }

    if not cfg.enabled:
        report['error'] = 'REPO_HUNT_ENABLED is false'
        state.write_last_run(report)
        return report

    candidates, sources, discovery_errors = await collect_candidates(cfg, state)
    if discovery_errors:
        report['errors'].extend(discovery_errors)
    report['sources'] = sources
    report['candidates'] = len(candidates)

    dl_dir = Path(base_dir) / 'quarantine' / 'repo_hunt'
    dl_dir.mkdir(parents=True, exist_ok=True)

    findings: list[Finding] = []
    for cand in candidates:
        is_watch = _is_repo_watch_file(cand)
        try:
            data, filename, sha256, filesize = await _fetch_candidate_bytes(
                cand,
                dl_dir,
                max_bytes=(cfg.repo_watch_max_file_bytes if is_watch else None),
                keep_bytes=not is_watch,
            )
            report['downloaded'] += 1
        except DownloadError as exc:
            msg = str(exc)
            # Oversized watch files are expected on starter plans — don't treat as hard errors.
            if is_watch and 'exceeds safety limit' in msg:
                report['watch_skipped_oversized'] += 1
            else:
                report['errors'].append(f'{cand.url}: download {exc}')
            continue
        except Exception as exc:
            report['errors'].append(f'{cand.url}: {exc.__class__.__name__}: {exc}')
            continue

        dedup_key = sha256 or cand.url
        if state.is_seen(dedup_key):
            continue

        # --- Financial / WU keyword repo watch: any file → VT → email if malicious ---
        if is_watch and cfg.wu_hunt_enabled:
            report['financial_repo_files'] += 1
            report['local_matches'] += 1
            seed = DetectionHit(
                rule=FINANCIAL_RULE_ID,
                matched_strings=_repo_watch_keywords(cand),
                filesize=filesize,
                local_match=True,
                notes=[
                    f'Repo keyword watch: {cand.repo} matched discovery query; '
                    f'scanned recent file {cand.path or filename}',
                ],
            )
            confirmed = await confirm_with_virustotal(sha256, seed, cfg, base_dir=base_dir)
            vt = confirmed.vt_confirm or {}
            if _wu_passes_vt(confirmed):
                findings.append(Finding(
                    candidate=cand,
                    sha256=sha256,
                    filename=filename,
                    detection=DetectionHit(
                        rule=FINANCIAL_RULE_ID,
                        matched_strings=list(confirmed.matched_strings),
                        filesize=filesize,
                        local_match=True,
                        vt_confirm={
                            **dict(vt),
                            'livehunt_rule_id': cfg.vt_livehunt_wu_rule_id or WU_LIVEHUNT_ID,
                        },
                        notes=list(confirmed.notes),
                    ),
                    triage_url=_triage_link(cfg, cand.url),
                ))
                state.mark_seen(dedup_key, {
                    'url': cand.url,
                    'source': cand.source,
                    'rules': [FINANCIAL_RULE_ID],
                    'repo': cand.repo,
                })
            else:
                report['financial_repo_vt_clean'] += 1
                state.mark_seen(dedup_key, {
                    'url': cand.url,
                    'sha256': sha256,
                    'note': 'financial_repo_vt_clean',
                    'source': cand.source,
                })
            continue

        name_pool = [filename, cand.path, cand.repo, cand.url, (cand.extra or {}).get('name')]
        js_hit = scan_bytes(
            data,
            path=cand.path or filename,
            min_bytes=cfg.min_bytes,
            max_bytes=cfg.max_bytes,
        )
        wu_hit = _wu_hit_from_names(
            names=[str(x) for x in name_pool if x],
            filesize=filesize or len(data),
            livehunt_rule_id=cfg.vt_livehunt_wu_rule_id,
        ) if cfg.wu_hunt_enabled else None

        if not js_hit and not wu_hit:
            state.mark_seen(f'nomatch:{cand.url}', {'sha256': sha256, 'source': cand.source})
            continue

        report['local_matches'] += 1
        if wu_hit:
            report['wu_name_matches'] += 1

        # Shared VT confirm when either detector fired
        seed = js_hit or wu_hit
        assert seed is not None
        confirmed = await confirm_with_virustotal(sha256, seed, cfg, base_dir=base_dir)
        vt = confirmed.vt_confirm or {}
        vt_names = list(vt.get('names') or [])

        emitted_rules: set[str] = set()

        if js_hit:
            js_confirmed = DetectionHit(
                rule=js_hit.rule,
                matched_strings=list(js_hit.matched_strings),
                filesize=js_hit.filesize,
                local_match=True,
                vt_confirm=dict(vt),
                notes=list(js_hit.notes) + list(confirmed.notes),
            )
            if cfg.vt_livehunt_rule_id:
                js_confirmed.vt_confirm['livehunt_rule_id'] = cfg.vt_livehunt_rule_id
            findings.append(Finding(
                candidate=cand,
                sha256=sha256,
                filename=filename,
                detection=js_confirmed,
                triage_url=_triage_link(cfg, cand.url),
            ))
            emitted_rules.add(js_confirmed.rule)

        if wu_hit or match_wu_names(name_pool + vt_names):
            keywords = match_wu_names(name_pool + vt_names) or list(wu_hit.matched_strings if wu_hit else [])
            wu_confirmed = DetectionHit(
                rule=WU_RULE_ID,
                matched_strings=keywords,
                filesize=filesize or len(data),
                local_match=True,
                vt_confirm={
                    **dict(vt),
                    'livehunt_rule_id': cfg.vt_livehunt_wu_rule_id or WU_LIVEHUNT_ID,
                },
                notes=[
                    f'LiveHunt mirror: MaliciousFilesWithWUKeywords keywords={",".join(keywords)}',
                    *list(confirmed.notes),
                ],
            )
            if _wu_passes_vt(wu_confirmed):
                findings.append(Finding(
                    candidate=cand,
                    sha256=sha256,
                    filename=filename,
                    detection=wu_confirmed,
                    triage_url=_triage_link(cfg, cand.url),
                ))
                emitted_rules.add(WU_RULE_ID)
            else:
                report['wu_vt_clean_skips'] += 1

        if emitted_rules:
            state.mark_seen(dedup_key, {
                'url': cand.url,
                'source': cand.source,
                'rules': sorted(emitted_rules),
                'repo': cand.repo,
            })
        else:
            state.mark_seen(dedup_key, {
                'url': cand.url,
                'sha256': sha256,
                'note': 'wu_name_without_vt_malicious',
                'source': cand.source,
            })

    report['new_findings'] = len(findings)
    report['findings'] = [f.to_dict() for f in findings[: cfg.max_findings_email]]

    js_findings = [f for f in findings if f.detection.rule not in {WU_RULE_ID, FINANCIAL_RULE_ID}]
    wu_findings = [f for f in findings if f.detection.rule in {WU_RULE_ID, FINANCIAL_RULE_ID}]
    report['js_findings'] = len(js_findings)
    report['wu_findings'] = len(wu_findings)

    report['email'] = {'ok': True, 'skipped': True, 'reason': 'no_new_findings'}
    report['wu_email'] = {'ok': True, 'skipped': True, 'reason': 'no_wu_hits'}

    if send:
        if js_findings:
            msg = build_findings_email(
                js_findings,
                cfg,
                run_meta={
                    'sources': sources,
                    'candidates': report['candidates'],
                    'local_matches': report['local_matches'],
                    'wu_name_matches': report['wu_name_matches'],
                    'financial_repo_files': report['financial_repo_files'],
                },
            )
            report['email'] = send_email(msg, cfg)
        if wu_findings and cfg.analysis_alert_email:
            from .notify.smtp_mailer import build_analysis_wu_alert_email

            hits = []
            for f in wu_findings:
                vt = f.detection.vt_confirm or {}
                hits.append({
                    'filename': f.filename,
                    'path': f.candidate.path,
                    'url': f.candidate.html_url or f.candidate.url,
                    'sha256': f.sha256,
                    'matched_keywords': list(f.detection.matched_strings),
                    'vt_verdict': vt.get('verdict'),
                    'vt_malicious': vt.get('malicious'),
                    'vt_link': vt.get('permalink'),
                    'popular_threat_label': vt.get('popular_threat_label'),
                    'family_labels': vt.get('family_labels') or [],
                    'triage_url': f.triage_url,
                    'rule': f.detection.rule,
                    'repo': f.candidate.repo,
                })
            wu_msg = build_analysis_wu_alert_email(
                cfg=cfg,
                job_id='scheduled-hunt',
                source_url='repo-hunt-5min-scan',
                hits=hits,
                triage_url=cfg.triage_base_url or '',
                scan_mode='scheduled',
            )
            report['wu_email'] = send_email(wu_msg, cfg)
        elif wu_findings:
            report['wu_email'] = {'ok': False, 'skipped': True, 'reason': 'ANALYSIS_ALERT_EMAIL disabled'}
    elif findings:
        report['email'] = {'ok': False, 'skipped': True, 'reason': 'send=false'}
        report['wu_email'] = {'ok': False, 'skipped': True, 'reason': 'send=false'}

    report['ok'] = True
    report['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    summary = {
        **report,
        'findings': report['findings'][:10],
        'errors': report['errors'][:20],
    }
    state.write_last_run(summary)
    return report
