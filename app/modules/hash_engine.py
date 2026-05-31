import hashlib
from pathlib import Path

def hash_file(path: str | Path) -> dict:
    p = Path(path)
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        'md5': md5.hexdigest(),
        'sha1': sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'size_bytes': p.stat().st_size,
    }
