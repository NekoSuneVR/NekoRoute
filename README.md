# NekoRoute v0.5.2

NekoRoute is a Dockerized regional availability, moderation and defensive website-analysis service. It discovers public HTTP/HTTPS/SOCKS4/SOCKS5 exits, persists proxy health in SQLite, compares HTTP behaviour across regions, provides a safe server-side preview, and can hand a selected route to an optional **local Firefox Bridge** for full browser compatibility and direct-to-PC downloads.

> **Responsible-use notice:** Users are responsible for complying with applicable law and website terms. Public proxies are third-party infrastructure. NekoRoute does not guarantee anonymity, privacy, safety or availability. Do not send passwords, private tokens, payment data or other sensitive traffic through random public proxies.

## Tools

### Dashboard `/`

- Persistent SQLite proxy inventory and health history.
- Full country names such as `France (FR)` and `United Kingdom (GB)`.
- Filters by region, country, protocol and state.
- **Paginated proxy table** with 25/50/100/200 rows per page.

### Site Tester `/tester`

Compare one public HTTP/HTTPS URL across multiple healthy exits. Results include HTTP status, redirect, latency, country, region and protocol.

The specific-node selector is paginated (50 nodes per page) instead of loading hundreds of `<option>` rows at once.

### Safe Proxy Preview `/preview`

The server-side preview remains intentionally safer than a transparent browser:

- Back / forward / reload and URL bar.
- Proxied page-to-page navigation.
- Simple `GET`/search forms.
- Images, CSS, fonts and discovered audio/video/PDF resources through the same selected proxy.
- Tokenised page-linked downloads.
- Client-rendered pages receive an extracted fallback instead of a silent blank page.
- Remote third-party JavaScript, cookies, authentication, POST forms, service workers and WebSockets remain disabled.

Use **Open in real Firefox** when a site requires JavaScript or normal browser behaviour.

### Real Firefox Bridge `/browser`

This is the v0.5 feature for sites that cannot work in the safe preview.

The optional Firefox extension:

1. Receives a short-lived, one-time NekoRoute route ticket.
2. Opens the target in a **real Firefox tab on the visitor's own PC**.
3. Routes that tab through the selected HTTP/HTTPS/SOCKS4/SOCKS5 public proxy.
4. Allows ordinary JavaScript, cookies, browser media handling, forms and navigation because the site is running in actual Firefox.
5. Lets Firefox save downloads **directly to the visitor's computer**. NekoRoute does not spool those browser-mode files onto the VPS.

This architecture is intentional: a Firefox instance physically running inside a Docker/VNC session on the VPS would necessarily receive/download the file on the server first. A website also cannot silently change a user's local Firefox proxy settings. The bridge extension is the way to satisfy both “real Firefox” and “download straight to my PC”.

The bridge defaults to trusting:

```text
https://proxyweb.nekosunevr.co.uk
```

Self-hosted users can add their own NekoRoute origin in the extension options.

Development extension source/download:

```text
/firefox-extension/
/downloads/nekoroute-firefox-bridge.zip
```

For permanent one-click public installation in normal Firefox, the extension should be signed through Mozilla Add-ons. For development, load `manifest.json` from `about:debugging#/runtime/this-firefox`.

The bridge also supports optional leak protection while routed tabs exist: Firefox network prediction is temporarily disabled and WebRTC is set to proxy-only, then the previous settings are restored after the final routed tab closes.

### Malware & Domain Scanner `/scanner`

The scanner fetches a public website through the selected proxy without executing remote JavaScript and combines:

- NekoRoute local HTML/header/redirect heuristics.
- OpenPhish Community feed cached locally.
- Optional self-hosted ClamAV.
- Optional VirusTotal API v3.
- Optional Google Web Risk.

## Public proxy providers

NekoRoute v0.5.2 merges and de-duplicates multiple independent public sources:

- **Proxifly** — metadata-rich HTTP/HTTPS/SOCKS lists.
- **ProxyScrape** — metadata-rich HTTP/HTTPS/SOCKS lists.
- **Proxio** — multi-protocol JSON list.
- **IPLocate** — verified `all-proxies.txt` list (protocol/IP/port; country is filled from richer sources when the same node overlaps).
- **GeoNode** — paginated API with country, city, anonymity, uptime and response-time metadata.
- **Fresh Proxy List (vakhov)** — separate HTTP, HTTPS, SOCKS4 and SOCKS5 feeds.
- **Rola IP** — paginated daily API with country, protocol, anonymity, response time and uptime.
- **DataBay** — paginated no-key JSON API with protocol, country, latency and uptime.
- **Advanced.name** — optional operator-configured plain-text export, queried separately for HTTP/HTTPS/SOCKS4/SOCKS5 so protocol is retained. Set `ADVANCED_NAME_FEED_URL` to enable it; the token-like export URL is intentionally not hard-coded.
- **ProxMint** — paginated no-key JSON API with protocol, country, anonymity, latency, uptime and provider score.
- **Socks5Proxies.com** — public offset-paginated JSON feed; protocol flags, country, city, anonymity, uptime/check data and health score are used when available. Its public endpoint is best-effort/IP-rate-limited, so NekoRoute defaults this provider to five pages per refresh even if the global page cap is higher.
- **Static** — optional operator-supplied trusted nodes from `STATIC_PROXY_NODES`.

Paginated providers are fetched only up to `SOURCE_PROVIDER_ITEM_CAP` (default 2500 per provider) so a single large feed cannot dominate refresh time. Cross-provider duplicates are merged before the final region/protocol diversity pick. NekoRoute prefers richer country/city/anonymity metadata when the same endpoint appears in multiple sources.

`topfreeproxylist.com` is intentionally not scraped because it currently exposes a browser table/export UI rather than a documented stable machine API. Scraping its HTML would be brittle and could break NekoRoute whenever that site changes layout.

Useful tuning:

```dotenv
MAX_PROXIES=5000
SOURCE_PROVIDER_ITEM_CAP=2500
SOURCE_MAX_PAGES=20
SOURCE_CONCURRENCY=4
SOURCE_PAGE_CONCURRENCY=2
SOCKS5PROXIES_MAX_PAGES=5
ADVANCED_NAME_FEED_URL=
```

## SQLite persistence

NekoRoute uses Sequelize + SQLite at:

```text
/app/data/nekoroute.sqlite
```

Nodes are not deleted just because they go offline. Their health history remains in SQLite, the health cursor is persisted across restarts, and offline nodes are revisited so they can become online again later.

## Paginated node API

The v1 node endpoint now returns a pagination object:

```http
GET /api/v1/nodes?status=online&country=FR&page=1&pageSize=50
```

Example response shape:

```json
{
  "items": [],
  "total": 543,
  "page": 1,
  "pageSize": 50,
  "pages": 11,
  "hasPrevious": false,
  "hasNext": true
}
```

`pageSize` is capped at 200.

The compatibility endpoint remains an array and supports `limit` + `offset`:

```http
GET /api/proxies?status=online&limit=50&offset=100
```

It also returns `X-Total-Count`, `X-Offset` and `X-Limit` headers.

## Public API v1

Documentation:

```text
GET /api/docs
GET /api/v1
GET /api/openapi.json
```

Useful endpoints:

```text
GET  /api/v1/health
GET  /api/v1/stats
GET  /api/v1/regions
GET  /api/v1/countries?region=Europe
GET  /api/v1/nodes?status=online&country=FR&page=1&pageSize=50
GET  /api/v1/threat-intel
POST /api/v1/test
POST /api/v1/test-matrix
POST /api/v1/scan
POST /api/v1/preview/session
GET  /api/v1/preview/session/:id/resources
POST /api/v1/browser-ticket
GET  /api/v1/browser-ticket/:ticket
```

### Firefox Bridge ticket

Create a one-time ticket:

```bash
curl -sS https://proxyweb.example.com/api/v1/browser-ticket \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/","country":"FR"}'
```

The public response contains the opaque ticket and selected node metadata, not the raw proxy address. The Firefox extension consumes `ticketUrl` once; that one-time response contains the raw public proxy host/port needed by Firefox.

Tickets expire quickly (`BROWSER_TICKET_TTL_MS`, default 90 seconds) and are removed after first successful consumption.

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
http://SERVER-IP:3210/browser
http://SERVER-IP:3210/scanner
http://SERVER-IP:3210/api/docs
```

## Optional ClamAV

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.clamav.yml \
  up -d --build
```

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
BROWSER_TICKET_TTL_MS=90000
```

`ADMIN_TOKEN` is maintenance-only. Normal visitor tools do not require it.

## Safety controls

Public server-side URL tools are restricted to HTTP/HTTPS ports 80/443. NekoRoute rejects localhost/private/link-local/CGNAT/reserved targets and credentials embedded in URLs.

The local Firefox Bridge is different: after the route ticket is consumed, the visitor's Firefox communicates directly with the selected public proxy. The NekoRoute VPS is no longer in that page/download data path. The public proxy itself remains untrusted and can observe the visitor's connection to it.
