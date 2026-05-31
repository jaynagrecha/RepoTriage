# RepoTriage v2.0

GitHub Payload Intelligence Platform — public job-based GitHub file URL analysis with server-side acquisition, hashing, extraction, VT enrichment, AbuseCH CTI, MITRE mapping and result-only browser output.

## v2.0 Highlights

- Public worker-style analysis flow
- Browser submits only GitHub file URLs; sample bytes are never returned to the browser
- Async job creation and polling API
- Server-side quarantine storage and TTL-ready job result storage
- Automatic MITRE ATT&CK mapping from:
  - VirusTotal family/verdicts
  - File types and script launchers
  - Extracted IOCs
  - ThreatFox threat types and confidence
  - MalwareBazaar family/signature data
  - URLHaus payload delivery matches
  - FeodoTracker C2 IP matches
  - SSLBL malicious SSL/JA3 infrastructure matches
- Dedicated MITRE ATT&CK tab
- Techniques grouped by tactic
- Confidence levels per technique
- Evidence and source attribution per mapped technique
- Executive Summary now includes MITRE mapping count

## Existing Capabilities

- GitHub file acquisition
- Root file hashing
- Recursive archive extraction
- Child file hashing
- VirusTotal verdicts for root and child files
- IOC extraction and cleanup
- Unified AbuseCH connector model
- ThreatFox, MalwareBazaar, URLHaus, FeodoTracker and SSLBL enrichment
- Infrastructure classification

## Architecture

```text
RepoTriage
├── GitHub Acquisition
├── Hash Engine
├── VirusTotal
├── Archive Extraction
├── IOC Extraction
├── AbuseCH
│   ├── ThreatFox
│   ├── MalwareBazaar
│   ├── URLHaus
│   ├── FeodoTracker
│   └── SSLBL
├── Infrastructure Classification
└── Archive Extraction Hardening
```

## Environment

```env
VT_API_KEY=
ABUSECH_API_KEY=

THREATFOX_ENABLED=true
MALWAREBAZAAR_ENABLED=true
URLHAUS_ENABLED=true
FEODO_ENABLED=true
SSLBL_ENABLED=true

THREATFOX_LOOKUP_LIMIT=75
MALWAREBAZAAR_LOOKUP_LIMIT=250
URLHAUS_LOOKUP_LIMIT=75

MAX_DOWNLOAD_BYTES=50000000
MAX_EXTRACT_DEPTH=3
MAX_EXTRACT_FILES=250
MAX_EXTRACT_BYTES=100000000
```

`ABUSECH_API_KEY` is used as the shared Auth-Key for AbuseCH sources where applicable. Individual keys such as `THREATFOX_API_KEY`, `MALWAREBAZAAR_API_KEY`, or `URLHAUS_API_KEY` can still override it if needed.

## Run

```powershell
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Safety

RepoTriage performs static acquisition, hashing, extraction, and OSINT enrichment. It does not execute malware and does not upload files to VirusTotal.


## v1.9.3 Stability + Quarantine

- Safe filename sanitization during extraction.
- Windows reserved-name and invalid-character protection.
- Short extraction paths to reduce MAX_PATH failures.
- Quarantine-style storage under `quarantine/`.
- Extraction issues are captured as analyst-friendly notes instead of raw tracebacks.
- Root archive is excluded from malicious child counts.

Extracted samples are never executed. Treat all downloaded/extracted files as malicious.

## v1.9.4 Safe Analysis Architecture

RepoTriage should not download malware to end-user workstations in production. Users should submit only a GitHub file URL through the browser. The backend/worker downloads, extracts, hashes, and enriches the sample in an isolated analysis environment, and the browser receives only metadata, hashes, verdicts, IOCs, CTI enrichment, and reports.

Recommended production model:

```text
Browser -> RepoTriage API -> isolated analysis worker/container/VM -> result JSON only
```

Local development mode is still useful, but it means your own machine is the analysis backend. Run local testing only inside a disposable VM/lab.

New safety flags:

```env
ANALYSIS_MODE=local_dev
SERVER_ANALYSIS_MODE=false
```

For production:

```env
ANALYSIS_MODE=server
SERVER_ANALYSIS_MODE=true
```

v1.9.4 also uses metadata-first extraction. Archive members are read and hashed in memory before best-effort quarantine storage. If local AV blocks/quarantines a child file during disk write, RepoTriage still keeps the file's hashes and can continue VT/CTI enrichment instead of dropping the file entirely.


## v2.0 Public Worker Architecture

RepoTriage v2.0 introduces a job-based workflow suitable for public hosting:

```text
Browser
  -> /api/jobs
  -> backend/worker downloads GitHub file
  -> backend/worker extracts/hashes/enriches
  -> browser polls /api/jobs/{job_id}
  -> result JSON only
```

The browser never receives malware bytes. In local development your machine is still the backend, so test only in a lab/VM.

New environment variables:

```env
ANALYSIS_MODE=local_dev
SERVER_ANALYSIS_MODE=false
JOB_TTL_HOURS=24
```

For production:

```env
ANALYSIS_MODE=server
SERVER_ANALYSIS_MODE=true
JOB_TTL_HOURS=1
```

For a hardened public deployment, run the analysis process inside an isolated Linux worker/container/VM with strict network egress, non-executable quarantine storage, resource limits and automatic cleanup.


## v2.21A CTI Fusion

Added infrastructure graph, CTI summary dashboard, related sample discovery, analyst report generator, and JSON/CSV/STIX/MISP export support.

## Public Rate Limiting

RepoTriage protects expensive VT/AbuseCH lookups at the analysis-job creation endpoint.

Recommended public settings:

```env
PUBLIC_MODE=true
RATE_LIMIT_ENABLED=true
FREE_DAILY_ANALYSIS_LIMIT=10
BURST_ANALYSIS_LIMIT_PER_MINUTE=3
MAX_RUNNING_JOBS_PER_IP=2
MAX_INPUT_URL_LENGTH=2048
```

Only `/api/jobs` consumes quota. Polling job status and exporting completed results do not consume additional quota.

For trusted internal testing you can set `ADMIN_BYPASS_TOKEN` and send it as the `x-admin-bypass-token` header.

## Cloudflare R2 / Persistent Storage

The current build still defaults to local temporary storage. For public deployment, configure R2 or another S3-compatible storage later and keep local samples short-lived with TTL cleanup.

```env
STORAGE_BACKEND=local
R2_ACCOUNT_ID=
R2_ACCESS_KEY_ID=
R2_SECRET_ACCESS_KEY=
R2_BUCKET=
R2_ENDPOINT_URL=
```
