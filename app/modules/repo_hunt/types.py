from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Candidate:
    url: str
    source: str  # github_search | org_watch | webhook | manual
    path: str = ''
    repo: str = ''
    html_url: str = ''
    size_bytes: int | None = None
    sha: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DetectionHit:
    rule: str
    matched_strings: list[str]
    filesize: int
    local_match: bool
    vt_confirm: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    candidate: Candidate
    sha256: str
    filename: str
    detection: DetectionHit
    triage_url: str = ''

    def to_dict(self) -> dict[str, Any]:
        return {
            'candidate': self.candidate.to_dict(),
            'sha256': self.sha256,
            'filename': self.filename,
            'detection': self.detection.to_dict(),
            'triage_url': self.triage_url,
        }
