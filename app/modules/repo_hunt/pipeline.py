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
from .discovery.github_search import discover_github_code_search
from .discovery.org_watch import discover_watched_orgs_users
from .discovery.webhook_queue import discover_webhook_queue
from .notify.smtp_mailer import build_findings_email, send_email
from .state import HuntState
from .types import Candidate, Finding


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


async def _fetch_candidate_bytes(candidate: Candidate, out_dir: Path) -> tuple[bytes, str, str]:
    """Return (data, filename, sha256)."""
    meta = await download_file(candidate.url, out_dir=out_dir)
    path = Path(meta['local_path'])
    data = path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    filename = meta.get('filename') or path.name
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass
    return data, filename, sha256


async def collect_candidates(cfg: RepoHuntConfig, state: HuntState) -> tuple[list[Candidate], dict[str, int]]:
    sources: dict[str, int] = {}
    all_items: list[Candidate] = []

    search = await discover_github_code_search(cfg)
    sources['github_search'] = len(search)
    all_items.extend(search)

    watched = await discover_watched_orgs_users(cfg)
    sources['org_watch'] = len(watched)
    all_items.extend(watched)

    queued = discover_webhook_queue(state)
    sources['webhook'] = len(queued)
    all_items.extend(queued)

    deduped = _dedupe_candidates(all_items)[: cfg.max_candidates]
    return deduped, sources


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
        'new_findings': 0,
        'findings': [],
        'email': None,
        'errors': [],
    }

    if not cfg.enabled:
        report['error'] = 'REPO_HUNT_ENABLED is false'
        state.write_last_run(report)
        return report

    candidates, sources = await collect_candidates(cfg, state)
    report['sources'] = sources
    report['candidates'] = len(candidates)

    dl_dir = Path(base_dir) / 'quarantine' / 'repo_hunt'
    dl_dir.mkdir(parents=True, exist_ok=True)

    findings: list[Finding] = []
    for cand in candidates:
        try:
            data, filename, sha256 = await _fetch_candidate_bytes(cand, dl_dir)
            report['downloaded'] += 1
        except DownloadError as exc:
            report['errors'].append(f'{cand.url}: download {exc}')
            continue
        except Exception as exc:
            report['errors'].append(f'{cand.url}: {exc.__class__.__name__}: {exc}')
            continue

        dedup_key = sha256 or cand.url
        if state.is_seen(dedup_key):
            continue

        hit = scan_bytes(
            data,
            path=cand.path or filename,
            min_bytes=cfg.min_bytes,
            max_bytes=cfg.max_bytes,
        )
        if not hit:
            # Mark lightly so we don't re-download forever; use url key only for non-matches
            state.mark_seen(f'nomatch:{cand.url}', {'sha256': sha256, 'source': cand.source})
            continue

        report['local_matches'] += 1
        hit = await confirm_with_virustotal(sha256, hit, cfg, base_dir=base_dir)
        finding = Finding(
            candidate=cand,
            sha256=sha256,
            filename=filename,
            detection=hit,
            triage_url=_triage_link(cfg, cand.url),
        )
        findings.append(finding)
        state.mark_seen(dedup_key, {
            'url': cand.url,
            'source': cand.source,
            'rule': hit.rule,
            'repo': cand.repo,
        })

    report['new_findings'] = len(findings)
    report['findings'] = [f.to_dict() for f in findings[: cfg.max_findings_email]]

    if findings and send:
        msg = build_findings_email(
            findings,
            cfg,
            run_meta={
                'sources': sources,
                'candidates': report['candidates'],
                'local_matches': report['local_matches'],
            },
        )
        report['email'] = send_email(msg, cfg)
    elif findings:
        report['email'] = {'ok': False, 'skipped': True, 'reason': 'send=false'}
    else:
        report['email'] = {'ok': True, 'skipped': True, 'reason': 'no_new_findings'}

    report['ok'] = True
    report['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    # Don't persist full findings forever in last_run (keep summary)
    summary = {
        **report,
        'findings': report['findings'][:10],
        'errors': report['errors'][:20],
    }
    state.write_last_run(summary)
    return report
