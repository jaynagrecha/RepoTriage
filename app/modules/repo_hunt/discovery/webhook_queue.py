from __future__ import annotations

from ..state import HuntState
from ..types import Candidate


def discover_webhook_queue(state: HuntState) -> list[Candidate]:
    """A3 — drain RepoTrace / external ingest queue."""
    out: list[Candidate] = []
    for item in state.drain_webhook_queue():
        if not isinstance(item, dict):
            continue
        url = (item.get('url') or item.get('file_url') or item.get('html_url') or '').strip()
        if not url:
            continue
        out.append(
            Candidate(
                url=url,
                source='webhook',
                path=(item.get('path') or ''),
                repo=(item.get('repo') or ''),
                html_url=(item.get('html_url') or url),
                size_bytes=item.get('size_bytes'),
                sha=item.get('sha'),
                extra={'ingested_at': item.get('ingested_at'), 'src': item.get('src')},
            )
        )
    return out
