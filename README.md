# NekoRoute

NekoRoute is a Dockerized, region-aware public web diagnostics dashboard for **regional availability, moderation checks, compatibility testing and defensive website analysis**.

It discovers public HTTP/HTTPS/SOCKS4/SOCKS5 exits, continuously health-checks them, persists their history in SQLite, compares HTTP behaviour across regions, offers a sandboxed safe rendered preview, and can inspect a public website for suspicious indicators without executing the site's JavaScript.

> **Use notice:** NekoRoute is intended for professional/defensive diagnostics. Users are responsible for complying with applicable law and website terms. The project does not guarantee anonymity, and the safe preview is intentionally not an unrestricted web relay.

## Main tools

### Dashboard `/`

- Public proxy pool health and regional/country/protocol filters.
- `online`, `degraded`, `offline`, and `unknown` status.
- Latency, reliability, last-success and health history.
- Public node addresses are hidden unless `EXPOSE_NODE_ADDRESSES=true`.

### Site Tester `/tester`

The Site Tester is public and does not require the admin token. It checks a normal public HTTP/HTTPS URL through multiple healthy exits and compares:

- 2xx / 3xx / 403 / 404 / 429 / 5xx behaviour
- redirects
- latency
- country/region/protocol
- timeout and connection errors

For safety it only permits ordinary HTTP/HTTPS web traffic on ports 80 and 443, rejects credentials in URLs, and rejects loopback/private/link-local/CGNAT/reserved destinations.

### Safe Proxy Preview `/preview`

Safe Preview is public and accepts **any public HTTP/HTTPS domain**. Every target and rewritten resource is still validated: private/reserved networks, URL credentials, non-HTTP(S) schemes, and non-standard web ports are blocked. Preview remains a sandboxed rendered view rather than a transparent general-purpose proxy.

The preview rewrites HTML/CSS/images/fonts through the selected proxy while disabling remote scripts, cookies, forms, authentication, WebSockets and service workers. JavaScript-heavy websites can therefore show only their server-rendered shell.

### Malware & Domain Scanner `/scanner`

The scanner fetches a public HTTP/HTTPS URL through a selected healthy proxy without executing remote JavaScript. It reports heuristic indicators such as:

- security header presence
- redirect chain
- cross-domain form submissions
- password fields combined with cross-domain forms
- executable/installable download links
- iframe density
- meta refresh
- common obfuscation/dynamic-code patterns such as `eval`, `Function`, `atob`, large base64-like blobs and `document.write`

Optional reputation lookups are supported with environment keys for:

- **VirusTotal API v3** — NekoRoute looks up an existing URL report and does not automatically submit unknown URLs.
- **Google Web Risk Lookup API** — checks malware, social-engineering and unwanted-software lists.

Scanner findings are indicators, not a guarantee that a website is safe or malicious. Target page content is fetched through the selected proxy. Optional reputation-provider lookups are made directly by NekoRoute so API keys are never sent through an untrusted public proxy. `STORE_SCAN_HISTORY=false` is the default, so visitor scan targets/results are not persisted by the application unless the operator opts in.

## Persistent SQLite proxy state

NekoRoute v0.3 uses **Sequelize + SQLite** at `/app/data/nekoroute.sqlite`.

The database stores every discovered node and its health history. A source refresh **does not delete missing nodes**. If a public node disappears, NekoRoute keeps it, marks it offline/degraded through normal health checks, and revisits it later so it can recover automatically.

The health-check cursor is persisted too, so a container restart continues from the previous position instead of always starting at node 0. Existing `/app/data/proxy-state.json` data is migrated into SQLite automatically when the database is initially empty.

## Run with Docker Compose

```bash
cp .env.example .env
nano .env

docker compose up -d --build
docker compose logs -f nekoroute
```

Open:

```text
http://SERVER-IP:3210/
```

For a public deployment, put NekoRoute behind HTTPS/reverse proxying and set `TRUST_PROXY=true` only when your reverse proxy is trusted and correctly strips client-supplied forwarding headers.

## Recommended `.env`

```dotenv
PORT=3210
ADMIN_TOKEN=use-a-long-random-maintenance-secret
SQLITE_PATH=/app/data/nekoroute.sqlite

PUBLIC_RATE_LIMIT_WINDOW_MS=60000
PUBLIC_RATE_LIMIT_MAX=60
SCAN_RATE_LIMIT_MAX=12
STORE_SCAN_HISTORY=false

EXPOSE_NODE_ADDRESSES=false
```

`ADMIN_TOKEN` is maintenance-only. It protects:

- `POST /api/admin/refresh`
- `POST /api/admin/sweep`

Visitors do **not** need it for the Site Tester, Safe Preview session creation, or Malware Scanner.

## API overview

Public read/diagnostic endpoints:

```text
GET  /api/health
GET  /api/stats
GET  /api/config
GET  /api/proxies
POST /api/test-route
POST /api/test-matrix
POST /api/preview-session
GET  /api/preview/:sessionId
GET  /api/preview-resource/:sessionId
POST /api/scan
```

Maintenance endpoints:

```text
POST /api/admin/refresh
POST /api/admin/sweep
```

Send the maintenance token as:

```text
x-admin-token: YOUR_ADMIN_TOKEN
```

## Abuse resistance

Public diagnostic routes include rate limiting. Tester, Scanner, and Safe Preview accept arbitrary public HTTP/HTTPS targets on ports 80/443, while private/reserved networks, embedded URL credentials, non-web schemes, and non-standard ports are blocked.

These controls should remain enabled on public deployments. They reduce SSRF, internal-network probing, generic port-scanning and open-relay abuse.

## Optional VPN sidecar

The existing Gluetun example can provide a trusted SOCKS5 sidecar using OpenVPN or WireGuard. Add it as a `STATIC_PROXY_NODES` entry if you operate an authorised exit yourself.

Public scraped proxy nodes are untrusted. Do not send passwords, cookies, API keys, payment details, or other sensitive data through them.
