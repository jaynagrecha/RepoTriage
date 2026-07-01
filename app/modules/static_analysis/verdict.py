from __future__ import annotations

from typing import Any

from .heuristics import collect_signals


def build_verdict(report: dict[str, Any]) -> dict[str, Any]:
    signals = collect_signals(report)
    score = sum(int(s.get('weight') or 0) for s in signals)
    categories = sorted({s['category'] for s in signals})

    if score >= 70:
        verdict = 'malicious'
        confidence = min(95, 55 + score // 2)
    elif score >= 35:
        verdict = 'suspicious'
        confidence = min(85, 40 + score // 2)
    elif score >= 10:
        verdict = 'inconclusive'
        confidence = min(60, 20 + score)
    else:
        verdict = 'clean'
        confidence = max(35, 70 - score)

    rationale = []
    if signals:
        top = sorted(signals, key=lambda s: s.get('weight', 0), reverse=True)[:6]
        rationale = [f"{s['label']}: {s['evidence']}" for s in top]
    else:
        rationale = ['No strong malicious static indicators observed across universal and typed analyzers.']

    return {
        'verdict': verdict,
        'confidence': confidence,
        'score': score,
        'signal_count': len(signals),
        'categories': categories,
        'signals': signals[:40],
        'rationale': rationale,
        'note': 'Static verdict is independent from VirusTotal and based on code/content analysis only.',
    }
