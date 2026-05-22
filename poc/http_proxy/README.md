# HTTP Proxy

A configurable HTTP/HTTPS forward proxy for the PoC stack. It forwards requests
through mitmproxy, forces a **custom User-Agent** header, and applies a
**configurable rate limit**. Both settings are managed from a small web
frontend.

## Components

| Service | Folder | Role |
|---------|--------|------|
| `http-proxy` | `backend/` | mitmproxy forward proxy + configuration API |
| `http-proxy-frontend` | `frontend/` | Web UI for editing the User-Agent and rate limit |

The backend runs two cooperating processes:

* **mitmproxy forward proxy** - port `8899`. Clients point `HTTP_PROXY` and
  `HTTPS_PROXY` at it.
* **Configuration API** - port `8890`. Serves/accepts the JSON config used by
  the web UI and the mitmproxy addon.

## Networking

```
                       scanner-hexstrike-network
  http-proxy-frontend ----------------+
   (nginx, /api/ -> :8890)            |
                                      v
                            hexstrike-vpn  (gluetun)
                            +-------------------------+
                            | shared network namespace|
                            |   mcp-hexstrike         |
                            |   http-proxy  :8899 :8890 ----> VPN ----> internet
                            +-------------------------+
```

`http-proxy` joins the VPN container's network namespace
(`network_mode: service:hexstrike-vpn`), exactly like `mcp-hexstrike`. As a
result:

* All upstream traffic from the proxy egresses through the Proton VPN.
* The hexstrike container reaches the proxy on `127.0.0.1:8899` (shared
  loopback). Other services on `scanner-hexstrike-network` reach it via
  `hexstrike-vpn:8899`.
* Ports `8899` and `8890` are added to gluetun's `FIREWALL_INPUT_PORTS` so the
  frontend and other services can reach them.

## HTTPS interception and certificates

mitmproxy generates its own certificate authority the first time the backend
starts. Docker Compose bind-mounts that state into:

```
poc/http_proxy/resources/
```

The main CA file is:

```
poc/http_proxy/resources/mitmproxy-ca-cert.pem
```

The same folder is mounted read-only into `mcp-hexstrike` at
`/http_proxy/resources` so scanner commands can reference the CA file directly.

Clients must trust that CA for HTTPS requests to succeed without certificate
errors. After the CA is trusted, mitmproxy can decrypt proxied HTTPS requests
and replace the outbound `User-Agent` header with the configured value.

## Using the proxy from hexstrike

```sh
# from inside the mcp-hexstrike container
export HTTP_PROXY=http://127.0.0.1:8899
export HTTPS_PROXY=http://127.0.0.1:8899

curl http://httpbin.org/headers
curl --cacert /http_proxy/resources/mitmproxy-ca-cert.pem https://httpbin.org/headers
```

For ad-hoc HTTPS checks, tools such as `curl -k` will ignore certificate trust
errors, but that does not install trust for other scanners. Prefer importing
`mitmproxy-ca-cert.pem` into the scanner client's trust store.

## Configuration

Open the web UI at <http://localhost:8092> (published by `docker compose`).

| Setting | Meaning |
|---------|---------|
| `user_agent` | Header value forced onto every forwarded request |
| `rate_limit` | Max forwarded requests, in the unit below; `0` disables limiting |
| `rate_limit_unit` | Unit for `rate_limit`: `per_second` or `per_minute` |
| `rate_limit_burst` | Requests allowed to burst before the steady rate applies |

Changes take effect on subsequent forwarded requests and are persisted to the
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
  config.py      file-backed, thread-safe configuration store
  rate_limiter.py token-bucket request throttle
  mitm_addon.py  mitmproxy request hook for User-Agent and rate limiting
  config_api.py  REST API consumed by the frontend
  __main__.py    runs mitmdump and the configuration API
```
