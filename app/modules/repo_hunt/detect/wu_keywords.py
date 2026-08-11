"""Western Union / MTCN filename detector (VirusTotal LiveHunt rule mirror).

Mirrors LiveHunt rule DETECT_GTI_MaliciousFilesWithWUKeywords:
  vt.metadata.new_file and
  vt.metadata.file_name matches /(?i)(westernunion|western union|western_union|
      westernunionbank|pagofacil|wupos|_mtcn|mtcn_| mtcn )/ and
  vt.metadata.analysis_stats.malicious > 0

RepoTriage tightens `_mtcn` with a trailing non-alnum boundary so face-detection
`MTCNN` / `_mtcnn` paths (e.g. ZQCNN) are not treated as Western Union MTCN.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..types import DetectionHit

RULE_ID = 'DETECT_GTI_MaliciousFilesWithWUKeywords'
RULE_NAME = 'MaliciousFilesWithWUKeywords'
DEFAULT_LIVEHUNT_RULE_ID = '20744291635'

# LiveHunt-compatible tokens, with `_mtcn` bounded so it does not match inside `_mtcnn`.
WU_FILENAME_RE = re.compile(
    r'(?i)(westernunion|western union|western_union|westernunionbank|pagofacil|wupos|'
    r'_mtcn(?![a-z0-9])|mtcn_|\smtcn\s)'
)

# Human-readable keyword tokens for email/UI (subset of the alternation).
WU_KEYWORD_LABELS = (
    'westernunion',
    'western union',
    'western_union',
    'westernunionbank',
    'pagofacil',
    'wupos',
    '_mtcn',
    'mtcn_',
    ' mtcn ',
)


def extract_wu_keywords(name: str) -> list[str]:
    """Return matched LiveHunt keyword spans for a single filename/path."""
    text = name or ''
    if not text:
        return []
    found: list[str] = []
    for m in WU_FILENAME_RE.finditer(text):
        token = m.group(0)
        # Normalize whitespace-only edges for display
        label = token if token.strip() != 'mtcn' else ' mtcn '
        if label not in found:
            found.append(label)
    return found


def match_wu_names(names: Iterable[str | None]) -> list[str]:
    """Deduped keyword hits across any candidate names (file, path, repo, VT names)."""
    hits: list[str] = []
    seen: set[str] = set()
    for raw in names:
        for token in extract_wu_keywords(str(raw or '')):
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            hits.append(token)
    return hits


def scan_wu_names(
    names: Iterable[str | None],
    *,
    filesize: int = 0,
    require_malicious: bool = False,
    vt_malicious: int = 0,
) -> DetectionHit | None:
    """
    Local prefilter: WU/MTCN keywords in any provided name.

    When require_malicious=True, also requires vt_malicious > 0 (full LiveHunt condition).
    """
    matched = match_wu_names(names)
    if not matched:
        return None
    if require_malicious and int(vt_malicious or 0) <= 0:
        return None
    return DetectionHit(
        rule=RULE_ID,
        matched_strings=matched,
        filesize=int(filesize or 0),
        local_match=True,
        notes=[
            f'LiveHunt mirror: {RULE_NAME} — WU/MTCN keywords in filename/path',
            f'matched={",".join(matched)}',
        ],
    )


def evaluate_wu_from_vt(
    *,
    local_names: Iterable[str | None],
    vt_report: dict | None,
    filesize: int = 0,
) -> DetectionHit | None:
    """Combine local names + VT names; require VT malicious > 0."""
    vt = vt_report if isinstance(vt_report, dict) else {}
    names = list(local_names or [])
    names.extend(vt.get('names') or [])
    if vt.get('original_filename'):
        names.append(vt.get('original_filename'))
    if vt.get('meaningful_name'):
        names.append(vt.get('meaningful_name'))
    matched = match_wu_names(names)
    if not matched:
        return None
    malicious = int(vt.get('malicious') or 0)
    verdict = str(vt.get('verdict') or '').lower()
    if malicious <= 0 and verdict != 'malicious':
        return None
    hit = DetectionHit(
        rule=RULE_ID,
        matched_strings=matched,
        filesize=int(filesize or vt.get('size') or 0),
        local_match=True,
        vt_confirm={
            'status': vt.get('status'),
            'verdict': vt.get('verdict'),
            'malicious': malicious,
            'suspicious': vt.get('suspicious'),
            'permalink': vt.get('permalink'),
            'names': vt.get('names') or [],
            'livehunt_rule_id': DEFAULT_LIVEHUNT_RULE_ID,
            'popular_threat_label': vt.get('popular_threat_label'),
            'family_labels': vt.get('family_labels') or [],
        },
        notes=[
            f'LiveHunt mirror: {RULE_NAME} — keywords + VT malicious>0',
            f'matched={",".join(matched)}',
            f'VT malicious={malicious}',
        ],
    )
    return hit
