from __future__ import annotations

from typing import Any

from .heuristics import collect_signals

VERDICT_LABELS = {
    'malicious': 'Likely malware',
    'suspicious': 'Suspicious — investigate',
    'needs_review': 'Uncertain — needs review',
    'clean': 'Likely clean',
}


def build_verdict(report: dict[str, Any]) -> dict[str, Any]:
    signals = collect_signals(report)
    score = sum(int(s.get('weight') or 0) for s in signals)
    categories = sorted({s['category'] for s in signals})

    if score >= 55:
        verdict = 'malicious'
        confidence = min(97, 60 + score // 3)
    elif score >= 28:
        verdict = 'suspicious'
        confidence = min(90, 45 + score // 3)
    elif score >= 12:
        verdict = 'needs_review'
        confidence = min(70, 30 + score)
    else:
        verdict = 'clean'
        confidence = max(40, 75 - score)

    rationale = []
    if signals:
        top = sorted(signals, key=lambda s: s.get('weight', 0), reverse=True)[:6]
        rationale = [f"{s['label'].replace('_', ' ')}: {s['evidence']}" for s in top]
    else:
        rationale = ['No strong malicious static indicators were found in this file.']

    return {
        'verdict': verdict,
        'verdict_label': VERDICT_LABELS.get(verdict, verdict),
        'confidence': confidence,
        'score': score,
        'signal_count': len(signals),
        'categories': categories,
        'signals': signals[:40],
        'rationale': rationale,
        'note': 'Static verdict is based on code/content analysis. It is separate from VirusTotal but should be read alongside it.',
    }
