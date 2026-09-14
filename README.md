# NekoRoute v0.4.1

NekoRoute is a Dockerized regional availability, moderation and defensive website-analysis service. It discovers public HTTP/HTTPS/SOCKS4/SOCKS5 exits, persists proxy health in SQLite, compares HTTP behaviour across regions, provides a browser-like proxied preview, and scans public websites using local heuristics plus optional threat-intelligence providers.

> **Responsible-use notice:** Users are responsible for complying with applicable law and website terms. Public proxies are third-party infrastructure. NekoRoute does not guarantee anonymity, privacy, safety, availability, or that a target leaves no trace at the VPS/network-provider layer.

## Tools

### Dashboard `/`

- Persistent SQLite proxy inventory and health history.
- Full country names such as `France (FR)` and `United Kingdom (GB)`.
- Clean responsive region cards instead of the old geographic mosaic layout.
- Filters by region, country, protocol and online/degraded/offline state.

### Site Tester `/tester`

Compare one public HTTP/HTTPS URL across multiple healthy exits. Results include HTTP status, redirect, latency, country, region and protocol.

### Proxy Preview `/preview`

The preview remains deliberately safer than a transparent open proxy, but is now more browser-like:

- Back / forward / reload and URL bar.
- Proxied page-to-page navigation.
- Simple `GET`/search forms work through the selected exit.
- Images, CSS, fonts and page-linked audio/video resources are fetched through the same proxy.
- Page-linked media/image/PDF downloads are tokenised per preview session and can be downloaded through the same proxy.
- Remote third-party JavaScript, cookies, authentication, POST forms, service workers and WebSockets remain disabled.
- Private/reserved destinations and non-standard web ports remain blocked.

Resource endpoints use per-session tokens instead of accepting arbitrary resource URLs, which prevents the media route from becoming an unrestricted binary relay.

### Malware & Domain Scanner `/scanner`

The scanner fetches a public website through the selected proxy without executing remote JavaScript and combines:

- NekoRoute local HTML/header/redirect heuristics.
- **OpenPhish Community feed** cached locally (no API key and no remote lookup per scan).
- Optional **ClamAV** sidecar for fully self-hosted content scanning with no API key.
- Optional VirusTotal API v3.
- Optional Google Web Risk.

OpenPhish/community-provider terms still apply. The local cache means there is no provider request for each visitor scan, but the feed itself should only be refreshed at a reasonable interval. NekoRoute defaults to 12 hours.

## SQLite persistence

NekoRoute uses Sequelize + SQLite at:

```text
/app/data/nekoroute.sqlite
```

Nodes are never deleted simply because they go offline. Their status/history remains in SQLite and the health cursor is persisted so checks resume where they stopped after a restart. Offline nodes continue to be revisited and can return to `online` later.

## Public API v1

API documentation and discovery:

```text
GET /api/docs          # human-readable docs page
GET /api/v1            # discovery JSON
GET /api/openapi.json  # raw OpenAPI 3.1 JSON
```

Useful endpoints:

```text
GET  /api/v1/health
GET  /api/v1/stats
GET  /api/v1/regions
GET  /api/v1/countries?region=Europe
GET  /api/v1/nodes?status=online&country=FR&protocol=socks5
GET  /api/v1/threat-intel
POST /api/v1/test
POST /api/v1/test-matrix
POST /api/v1/scan
POST /api/v1/preview/session
```

The older `/api/...` endpoints remain for compatibility.

Example test request:

```bash
curl -sS https://proxyweb.example.com/api/v1/test-matrix \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/","country":"FR","limit":8}'
```

Example node list:

```bash
curl -sS 'https://proxyweb.example.com/api/v1/nodes?status=online&region=Europe&limit=100'
```

## Run

```bash
cp .env.example .env
nano .env

docker compose up -d --build
docker compose logs -f nekoroute
```

Open:

```text
http://SERVER-IP:3210/
http://SERVER-IP:3210/tester
http://SERVER-IP:3210/preview
http://SERVER-IP:3210/scanner
http://SERVER-IP:3210/api/docs
```

## Optional ClamAV

For self-hosted, no-key ClamAV scanning:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.clamav.yml \
  up -d --build
```

The overlay configures:

```dotenv
CLAMAV_HOST=clamav
CLAMAV_PORT=3310
```

ClamAV signature data is kept in its own Docker volume.

## Recommended environment

```dotenv
PORT=3210
ADMIN_TOKEN=use-a-long-random-maintenance-secret
SQLITE_PATH=/app/data/nekoroute.sqlite

PUBLIC_RATE_LIMIT_WINDOW_MS=60000
PUBLIC_RATE_LIMIT_MAX=60
SCAN_RATE_LIMIT_MAX=12
STORE_SCAN_HISTORY=false

OPENPHISH_ENABLED=true
THREAT_FEED_REFRESH_MS=43200000
THREAT_FEED_CACHE_PATH=/app/data/openphish-cache.json

EXPOSE_NODE_ADDRESSES=false
PREVIEW_TIMEOUT_MS=45000
```

`ADMIN_TOKEN` is maintenance-only and protects forced refresh/sweep endpoints. Normal visitor tools do not require it.

## Safety controls

Public URLs are restricted to HTTP/HTTPS ports 80/443. NekoRoute rejects localhost/private/link-local/CGNAT/reserved targets and credentials embedded in URLs. Preview resource downloads must first be discovered from a page inside that preview session and are represented by opaque tokens.

Public proxies are untrusted. Do not send passwords, cookies, API keys, payment data or other sensitive information through them.
