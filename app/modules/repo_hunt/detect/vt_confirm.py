"""VT confirmation layer after local prefilter (LiveHunt-aware when configured)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from ..config import RepoHuntConfig
from ..types import DetectionHit


async def confirm_with_virustotal(
    sha256: str,
    hit: DetectionHit,
    cfg: RepoHuntConfig,
    *,
    base_dir: Path | None = None,
) -> DetectionHit:
    """
    Confirm a local hit via VirusTotal file metadata.

    - Always records LiveHunt rule id when VT_LIVEHUNT_RULE_ID is set (for analyst linkage).
    - Uses VT file report for type/size corroboration when VT_API_KEY is present.
    - Soft-fails: local match remains valid if VT is rate-limited/unavailable.
    """
    notes = list(hit.notes)
    vt: dict[str, Any] = {
        'configured': bool(cfg.vt_api_key),
        'livehunt_rule_id': cfg.vt_livehunt_rule_id or None,
        'status': 'skipped',
    }
    if cfg.vt_livehunt_rule_id:
        notes.append(f'Linked LiveHunt rule id: {cfg.vt_livehunt_rule_id}')
        vt['livehunt_note'] = (
            'Local rule mirrors LiveHunt strings; set VT Enterprise hunting notifications '
            'to stream corpus hits for the same rule id.'
        )

    if not cfg.vt_confirm:
        vt['status'] = 'disabled'
        hit.vt_confirm = vt
        hit.notes = notes
        return hit

    if not cfg.vt_api_key:
        vt['status'] = 'not_configured'
        notes.append('VT confirm skipped — VT_API_KEY not set')
        hit.vt_confirm = vt
        hit.notes = notes
        return hit

    # Prefer existing VT cache/lookup path when available
    try:
        from ...vt_lookup import lookup_file_hash

        if base_dir is None:
            raise RuntimeError('base_dir required for vt_lookup')
        report = await lookup_file_hash(sha256, base_dir)
        vt['status'] = report.get('status') or 'unknown'
        vt['verdict'] = report.get('verdict')
        vt['malicious'] = report.get('malicious')
        vt['suspicious'] = report.get('suspicious')
        vt['permalink'] = report.get('permalink')
        vt['names'] = report.get('names') or []
        vt['tags'] = report.get('tags') or []
        if report.get('status') == 'found':
            notes.append(
                f"VT confirm: verdict={report.get('verdict')} "
                f"({report.get('malicious')}/{report.get('suspicious')} mal/sus)"
            )
        elif report.get('status') == 'rate_limited':
            notes.append(report.get('message') or 'VT rate limited — kept local match')
        elif report.get('status') == 'not_found':
            notes.append('VT has no report yet — kept local match (prefilter only)')
        else:
            notes.append(f"VT status={report.get('status')} — kept local match")
    except Exception as exc:
        # Direct lightweight fallback
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.get(
                    f'https://www.virustotal.com/api/v3/files/{sha256}',
                    headers={'x-apikey': cfg.vt_api_key},
                )
            vt['http'] = resp.status_code
            if resp.status_code == 200:
                attrs = ((resp.json().get('data') or {}).get('attributes') or {})
                stats = attrs.get('last_analysis_stats') or {}
                vt['status'] = 'found'
                vt['type_description'] = attrs.get('type_description')
                vt['size'] = attrs.get('size')
                vt['malicious'] = stats.get('malicious')
                vt['suspicious'] = stats.get('suspicious')
                notes.append(f"VT confirm via API: type={attrs.get('type_description')}")
            elif resp.status_code == 404:
                vt['status'] = 'not_found'
                notes.append('VT has no report yet — kept local match')
            elif resp.status_code == 429:
                vt['status'] = 'rate_limited'
                notes.append('VT rate limited — kept local match')
            else:
                vt['status'] = 'error'
                notes.append(f'VT confirm HTTP {resp.status_code} — kept local match')
        except Exception as inner:
            vt['status'] = 'error'
            vt['error'] = f'{exc.__class__.__name__}/{inner.__class__.__name__}'
            notes.append('VT confirm failed — kept local match')

    hit.vt_confirm = vt
    hit.notes = notes
    return hit
