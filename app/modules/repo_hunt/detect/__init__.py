from .local_jsoutprox import scan_bytes
from .vt_confirm import confirm_with_virustotal
from .wu_keywords import evaluate_wu_from_vt, match_wu_names, scan_wu_names

__all__ = [
    'scan_bytes',
    'confirm_with_virustotal',
    'match_wu_names',
    'scan_wu_names',
    'evaluate_wu_from_vt',
]
