# HTTP Proxy

A configurable HTTP forward proxy for the PoC stack. It forwards HTTP requests
with a **custom User-Agent** header and applies a **configurable rate limit**.
Both settings are managed from a small web frontend.

## Components

| Service              | Folder      | Role |
|----------------------|-------------|------|
| `http-proxy`         | `backend/`  | The forward proxy + its configuration API |
| `http-proxy-frontend`| `frontend/` | Web UI for editing the User-Agent and rate limit |

The backend is implemented entirely with the Python standard library (no
dependencies). It runs two HTTP servers in one process:

* **Forward proxy** — port `8899`. Clients point their `HTTP_PROXY` at it.
* **Configuration API** — port `8890`. Serves/accepts the JSON config.

## Networking

```
                       scanner-hexstrike-network
  http-proxy-frontend ──────────────┐
   (nginx, /api/ -> :8890)          │
                                    ▼
                            hexstrike-vpn  (gluetun)
                            ┌─────────────────────────┐
                            │ shared network namespace│
                            │   mcp-hexstrike         │
                            │   http-proxy  :8899 :8890├──► VPN ──► internet
                            └─────────────────────────┘
```

`http-proxy` joins the VPN container's network namespace
(`network_mode: service:hexstrike-vpn`), exactly like `mcp-hexstrike`. As a
result:

* **All upstream traffic from the proxy egresses through the Proton VPN.**
* The hexstrike container reaches the proxy on `127.0.0.1:8899` (shared
  loopback). Other services on `scanner-hexstrike-network` reach it via
  `hexstrike-vpn:8899`.
* Ports `8899` and `8890` are added to gluetun's `FIREWALL_INPUT_PORTS` so the
  frontend (and any other service) can reach them.

## Using the proxy from hexstrike

```sh
# from inside the mcp-hexstrike container
curl -x http://127.0.0.1:8899 http://httpbin.org/headers   # see the injected UA
```

`https://` targets are tunnelled with the `CONNECT` method. Because that
payload is end-to-end encrypted the User-Agent **cannot** be rewritten for
HTTPS; the tunnel is still rate-limited like any other forwarded request.

## Configuration

Open the web UI at <http://localhost:8092> (published by `docker compose`).

| Setting                 | Meaning |
|-------------------------|---------|
| `user_agent`            | Header value forced onto every forwarded HTTP request |
| `rate_limit`            | Max forwarded requests, in the unit below; `0` disables limiting |
| `rate_limit_unit`       | Unit for `rate_limit`: `per_second` or `per_minute` |
| `rate_limit_burst`      | Requests allowed to burst before the steady rate applies |

Changes take effect immediately — no restart needed — and are persisted to the
`http_proxy_data` volume (`/data/proxy_config.json`), so they survive restarts.

The same configuration can be scripted against the API directly:

```sh
curl hexstrike-vpn:8890/config
curl -X PUT hexstrike-vpn:8890/config \
  -H 'Content-Type: application/json' \
  -d '{"user_agent":"my-scanner/2.0","rate_limit":5,"rate_limit_unit":"per_second"}'
```

## Backend layout

```
backend/proxyserver/
  config.py        file-backed, thread-safe configuration store
  rate_limiter.py  token-bucket request throttle
  forward_proxy.py forward proxy HTTP handler (HTTP forwarding + CONNECT tunnels)
  config_api.py    REST API consumed by the frontend
  __main__.py      wires the pieces together and runs both servers
```
