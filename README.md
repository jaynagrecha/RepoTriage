# RepoTriage v4.0.0-alpha.1

GitHub and GitLab Payload Intelligence Platform — public job-based file URL analysis with server-side acquisition, hashing, extraction, VT enrichment, AbuseCH CTI, MITRE mapping, on-demand universal static analysis, **deep analysis worker pipeline**, and result-only browser output.

## Changelog

### v4.0.0-alpha.2 — Deep analysis distinct from static

- **Deep** no longer duplicates the static RE report — it adds execution chain reconstruction, PE import risk, MalwareBazaar/ThreatFox file intel, attack chain, and "exclusive findings" static missed
- Deep UI is a separate blue-themed investigation report with reconstructed commands, kill chain, and CTI cards
- Run **Analyse** first for static RE; **Deep** for investigation layer (or Deep alone — it references static if cached)

### v4.0.0-alpha.1 — Platform foundation (Render web + worker)

**Deep analysis pipeline** (Render worker service or `WORKER_INLINE=true` for single-service dev):

- SQLite task queue + persistent artifacts on Render disk (`PLATFORM_DATA_DIR=/var/data`)
- **Deep** button per cached file: static + YARA + sandbox-lite + Office macros + ssdeep similarity + VT URL reputation + crt.sh cert intel + family/config hints
- Combined verdict with confidence explanation panel in UI
- **Cases & Notes** tab: investigation cases, job notes, case linking
- **Blocklist & Diff** tab: plain/Suricata/hosts exports, job-to-job diff
- Webhooks (`WEBHOOK_URL`) on malicious deep-analysis completion
- API keys admin endpoint (`POST /api/v4/admin/api-keys` with `x-admin-bypass-token`)
- Docker image with libyara, ssdeep, radare2; `render.yaml` Blueprint for **web + worker** sharing one persistent disk

**Sandbox-lite (Render-safe):** scripts analysed statically for behavioral markers; PE/ELF binaries are **not executed**. This replaces a separate RepoSandbox VM while staying within Render budget.

**New environment variables**

```env
PLATFORM_DATA_DIR=/var/data
WORKER_ENABLED=true
WORKER_INLINE=false
WORKER_POLL_SECONDS=2
AUTO_DEEP_ANALYSIS=false
WEBHOOK_URL=
WEBHOOK_SECRET=
YARA_RULES_DIR=
```

**Deploy on Render**

**Option A — Native Python (simplest, no Docker):**

1. Runtime: **Python 3** (not Docker)
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Add disk mounted at `/var/data`; set `PLATFORM_DATA_DIR=/var/data`, `WORKER_INLINE=true`, `VT_API_KEY`, `TRUST_PROXY=true`

YARA/ssdeep are optional on native Python (Deep analysis still runs; those modules degrade gracefully).

**Option B — Docker (full YARA + ssdeep):**

1. Runtime: **Docker** (uses `Dockerfile` + `requirements-docker.txt`)
2. Add disk at `/var/data`; same env vars as Option A
3. Optional second worker: `python -m app.worker_main` with `WORKER_INLINE=false`

**Option C — Blueprint:** apply `render.yaml` (Docker web + worker).

**v4 API highlights**

- `POST /api/v4/jobs/{job_id}/files/{sha256}/deep-analysis`
- `GET /api/v4/jobs/{job_id}/files/{sha256}/deep-analysis`
- `GET /api/v4/jobs/{job_id}/export/blocklist?fmt=plain|suricata|hosts`
- `GET /api/v4/jobs/diff?job_a=&job_b=`
- `POST/GET /api/v4/cases`, `POST /api/v4/jobs/{job_id}/notes`

### v2.3.0 — Universal on-demand static analysis

- **Static Analysis** tab with per-file **Disassemble & Analyse** for every inventory file type
- Job-scoped byte cache (`data/job_cache/{job_id}/{sha256}`) retained after quarantine cleanup
- Universal pipeline: entropy, strings, IOC extraction, de-obfuscation (Base64/hex/ROT13/XOR/PowerShell/JS)
- Typed analyzers: PE/ELF/binary (Capstone + optional radare2), scripts, documents, archives, images, text/unknown
- Function/method logic extraction and cross-correlation with separate **static verdict** from VT
- API:
  - `GET /api/jobs/{job_id}/static-analysis`
  - `POST /api/jobs/{job_id}/files/{sha256}/static-analysis`
  - `GET /api/jobs/{job_id}/files/{sha256}/static-analysis`
- Separate static-analysis rate limits (`STATIC_ANALYSIS_DAILY_LIMIT`, `STATIC_ANALYSIS_BURST_LIMIT`)

**New environment variables**

```env
STATIC_ANALYSIS_ENABLED=true
STATIC_ANALYSIS_TIMEOUT=180
STATIC_ANALYSIS_DAILY_LIMIT=25
STATIC_ANALYSIS_BURST_LIMIT=5
STATIC_ANALYSIS_R2_TIMEOUT=120
R2_BINARY=r2
MAX_CACHED_FILE_BYTES=50000000
```

**Production note:** Install `radare2` on the worker for deepest disassembly/decompilation. Without r2, PE/ELF analysis falls back to Capstone + pefile.

### v4.0.0-alpha.21 — Repo hunt + SMTP alerts (JsOutProx)

Automated discovery of new JS droppers matching your LiveHunt-style JsOutProx rule, with VT confirm and mailbox alerts.

**Discovery (all three)**
1. GitHub code search (`REPO_HUNT_SEARCH_QUERY`)
2. Watched orgs/users (`REPO_HUNT_GITHUB_ORGS` / `REPO_HUNT_GITHUB_USERS`)
3. Webhook ingest from RepoTrace: `POST /api/repo-hunt/ingest` + `x-repo-hunt-secret`

**Detection**
- Local prefilter: size 500KB–1MB + all six JsOutProx strings
- VT confirm via file report + optional `VT_LIVEHUNT_RULE_ID` linkage

**Email**
- SMTP (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `REPO_HUNT_TO_EMAIL`)

**Run**
```bash
# cron / one-shot
python scripts/repo_hunt_worker.py

# admin
curl -X POST -H "x-admin-bypass-token: $ADMIN_BYPASS_TOKEN" \
  'https://YOUR_HOST/api/admin/repo-hunt/run'
```

### v4.0.0-alpha.20 — CTI live proof

- Fixture + unit tests prove ThreatFox/URLHaus exact matches flow into Infrastructure (probable C2 / payload delivery).
- Admin endpoint `GET /api/admin/cti-selftest` (header `x-admin-bypass-token`) pulls a fresh ThreatFox IOC with your `ABUSECH_API_KEY` and verifies an exact match.
- CLI: `python scripts/cti_smoke_test.py`
- Health now exposes `abusech_configured`.

### v4.0.0-alpha.18 — Private GitHub via Contents API

- Optional `GITHUB_TOKEN` (or `GH_TOKEN`) for private GitHub blob/raw URLs.
- When set, downloads use the GitHub Contents API (`Accept: application/vnd.github.raw`) instead of anonymous raw.githubusercontent.com.
- Clearer 401/403/404 messages when the token is missing or cannot access the repo.

**New environment variables**

```env
GITHUB_TOKEN=
```

### v2.2B.4 — GitLab file URL support

- Accept GitLab blob and raw file URLs (`/-/blob/` and `/-/raw/` paths), including nested group projects.
- Optional `GITLAB_TOKEN` for private GitLab repositories (`PRIVATE-TOKEN` header).
- Optional `GITLAB_BASE_URL` for self-hosted GitLab instances.
- Download redirect validation extended to allowed GitLab hosts.
- UI and API examples updated for GitHub + GitLab URLs.

**New environment variables**

```env
GITLAB_TOKEN=
GITLAB_BASE_URL=
```

### v2.2B.3 — Mobile layout and touch support

- Responsive breakpoints at 1000px, 720px, and 420px for phones and small tablets.
- Full-width Analyze button, single-column summary cards, and stacked tab groups on mobile.
- Tables keep horizontal scroll instead of breaking the page layout.
- Infrastructure graph supports touch pan and tap-to-select on mobile.
- Larger tap targets (44px minimum) for tabs and controls.

### v2.2B.2 — Infrastructure graph UX

- Cleaner radial layout with collision spacing so nodes and labels no longer overlap.
- Removed cluttered edge labels from the canvas; relationships show on node click and in the table.
- Pan (drag background), zoom (scroll wheel + controls), and reset view.
- Node click highlights connected edges and dims unrelated nodes.
- Labels moved below nodes for readability; curved edges reduce visual crossing.

### v2.2B.1 — Security, reliability, and UX hardening

**Security**
- `POST /api/analyze` is disabled by default (`ALLOW_SYNC_ANALYZE=false`). The supported public path remains `POST /api/jobs`.
- `TRUST_PROXY=false` by default; enable only when running behind a trusted reverse proxy.
- Rate-limit counters use file locking to reduce concurrent write races.
- GitHub downloads validate the final redirect host stays on GitHub / `*.githubusercontent.com`.
- GitLab downloads validate redirects stay on allowed GitLab hosts (`gitlab.com` or `GITLAB_BASE_URL`).
- API responses no longer expose `local_path`, `extract_dir`, or `client_ip`.

**Reliability**
- Archive extraction enforces decompressed byte limits during read (zip/tar/rar bomb mitigation).
- Quarantine files are removed after each analysis unless `KEEP_QUARANTINE=true`.
- Child VirusTotal lookups run in parallel (`VT_CONCURRENT_LIMIT=5`).
- Persisted jobs reload into memory; active-job counting scans disk after restarts.

**Correctness**
- Fixed narrative risk scoring for Abuse.ch match counts.
- Refreshed Executive Summary text (removed stale “upcoming versions” wording).
- Fixed `children_vt_lookup` pipeline flag.
- STIX file IDs use stable UUID-like hashes instead of truncated SHA256.

**UI**
- Tabs grouped into Summary / CTI Fusion / Intel Sources / Reporting.
- Usage quota bar via `/api/usage`.
- Readable rate-limit (429) error messages.
- Analyze button disabled while running; polling timeout extended to ~8 minutes.
- Full hash values available via hover tooltips; safer infrastructure graph node clicks.

**New environment variables**

```env
TRUST_PROXY=false
ALLOW_SYNC_ANALYZE=false
KEEP_QUARANTINE=false
VT_CONCURRENT_LIMIT=5
```

**Deployment notes**
- Production behind nginx/Cloudflare: set `TRUST_PROXY=true`.
- Lab debugging with on-disk samples: set `KEEP_QUARANTINE=true`.
- Legacy direct callers of `/api/analyze`: set `ALLOW_SYNC_ANALYZE=true` (not recommended for public hosts).

---

- Public worker-style analysis flow
- Browser submits GitHub or GitLab file URLs; sample bytes are never returned to the browser
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

- GitHub and GitLab file acquisition
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

When deployed behind a reverse proxy, also set:

```env
TRUST_PROXY=true
```

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
