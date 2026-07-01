from __future__ import annotations

from pathlib import Path
from typing import Any


def compute_ssdeep(path: Path) -> str | None:
    try:
        import ssdeep  # type: ignore

        return ssdeep.hash(path.read_bytes())
    except Exception:
        return None


def similarity_report(base_dir, sha256: str, ssdeep_hash: str | None, db) -> dict[str, Any]:
    similar = db.similar_fingerprints(ssdeep_hash or '') if ssdeep_hash else []
    return {
        'sha256': sha256.lower(),
        'ssdeep': ssdeep_hash,
        'similar_samples': similar,
        'corpus_matches': len(similar),
    }
