# NekoRoute

NekoRoute is a Dockerized, region-aware **public proxy health dashboard and safe egress tester**. It ingests public HTTP/HTTPS/SOCKS4/SOCKS5 node lists, groups nodes by country/region, continuously checks a bounded rotating sample, scores recent reliability/latency, and selects healthy fallbacks.

> **Intended use:** privacy experiments, network diagnostics, and checking how services you own/control behave from different egress regions. It is not designed as an open browsing proxy or as a mechanism to defeat access controls or regional restrictions.

## Features

- Dark, modern, green TailwindCSS UI.
- HTTP, HTTPS, SOCKS4 and SOCKS5 node ingestion.
- Country + world-region filters.
- Health states: unknown → online / degraded / offline.
- Rotating checks rather than hammering thousands of public endpoints at once.
- Reliability + latency scoring and automatic route failover.
- Persistent health state in a Docker volume.
- Admin-only route tester.
- URL tester blocks private/reserved IPs and permits only `ALLOWED_TEST_HOSTS`.
- Node addresses are masked by default; set `EXPOSE_NODE_ADDRESSES=true` for your private deployment.
- GitHub Actions workflow builds and publishes a GHCR image.

## Source

The default sources are Proxifly and Proxio public lists. NekoRoute deduplicates them, keeps a country/protocol-diverse bounded pool, and performs its own health checks before marking a node usable.

## Start

```bash
cp .env.example .env
# Edit ADMIN_TOKEN and ALLOWED_TEST_HOSTS
docker compose up -d --build
```

Open `http://localhost:3210`.

## Important settings

```dotenv
ADMIN_TOKEN=use-a-long-random-value
ALLOWED_TEST_HOSTS=example.com,my-own-site.example
EXPOSE_NODE_ADDRESSES=false
MAX_PROXIES=1500
HEALTHCHECK_BATCH_SIZE=80
HEALTHCHECK_INTERVAL_MS=60000
```

`ALLOWED_TEST_HOSTS` accepts a comma-separated hostname list. Subdomains are permitted automatically. DNS is resolved before a test; loopback, RFC1918, link-local, CGNAT and other reserved destinations are rejected.

## How health checking works

The source list is refreshed on an interval. A rotating batch of nodes is then tested through `HEALTHCHECK_URL`. One failure marks a node `degraded`; two consecutive failures mark it `offline`. Successful checks reset the failure streak. Selection only chooses `online` nodes.

Public proxy availability changes quickly, so **zero downtime cannot be guaranteed**. The pool reduces disruption by keeping multiple recently healthy nodes and failing over during a test.

## OpenVPN / WireGuard

NekoRoute deliberately does **not** scrape and auto-connect arbitrary free VPN profiles. Public VPN profiles can execute routing/DNS changes at the container/host level and have a much larger trust and privilege surface than application-level proxy agents.

A safer extension is a bring-your-own egress adapter using VPN profiles you trust. Run that as a separate container/network namespace, then register its local SOCKS/HTTP gateway with NekoRoute. This keeps the web process unprivileged (`cap_drop: ALL`). An example is included in `docker-compose.vpn-example.yml`.

Register one or more trusted gateways with `STATIC_PROXY_NODES`, for example:

```dotenv
STATIC_PROXY_NODES=socks5://gluetun:1080|GB|London|Gluetun;socks5://gluetun-us:1080|US|New York|Gluetun
```

The country/label is operator-supplied so the UI can place the VPN exit in the correct region. Do not put proxy credentials in this value; keep the gateway on the private Docker network instead.

## Security notes

Public proxies can observe or tamper with traffic that is not end-to-end encrypted. Do not transmit credentials, session cookies, private API keys, personal data, payment data, or other secrets through unknown relays. Use the admin tester only against systems you are authorized to test.

## API

- `GET /api/health`
- `GET /api/stats`
- `GET /api/proxies?region=Europe&country=DE&protocol=socks5&status=online`
- `POST /api/admin/refresh` with `x-admin-token`
- `POST /api/admin/sweep` with `x-admin-token`
- `POST /api/test-route` with `x-admin-token`

Example test body:

```json
{
  "url": "https://example.com/",
  "region": "Europe",
  "protocol": "socks5"
}
```

## Development

```bash
npm install
npm run build
npm start
```

Node.js 22+ is recommended.
