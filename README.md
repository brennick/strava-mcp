# strava-mcp

A remote MCP server that exposes a single user's Strava data as tools, designed
to plug into Claude.ai (and Claude Code) as a [custom connector](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

The server is a single-user personal connector with a minimal embedded OAuth 2.1
issuer. Claude Desktop's connector UI accepts a URL only (no static bearer
field), so the server publishes OAuth discovery metadata and renders a one-click
"Approve" page on `/authorize`. The Approve page can be password-gated with
`MCP_APPROVE_PASSWORD`.

Strava-side authentication uses the standard refresh-token flow. Strava rotates
the refresh token on every refresh; this server persists the new value to disk
so the connector keeps working past the first access-token expiry.

## Tools

| Tool                    | What it does                                                                 |
|-------------------------|------------------------------------------------------------------------------|
| `list_activities`       | Recent activities, newest first. Supports `after`, `before`, `types`, `limit`. |
| `get_activity`          | Full detail (splits, description, gear, calories, map).                      |
| `get_athlete_stats`     | Lifetime / YTD / 4-week totals for run, ride, swim.                          |
| `summarize`             | Weekly or monthly rollups: distance, time, elevation, count, avg pace.       |
| `get_activity_streams`  | Time-series streams (heartrate, velocity, altitude, etc.).                   |

Every tool accepts an optional `units` parameter (`"imperial"` or `"metric"`).
The default is imperial unless the deployment's credentials file overrides it.

---

## 1. Get a Strava refresh token

You need a Strava API app and a one-time OAuth handshake to get the initial
refresh token. The full doc is at
<https://developers.strava.com/docs/getting-started/>; the short version:

1. Go to <https://www.strava.com/settings/api> and create an app. Set
   "Authorization Callback Domain" to `localhost`. Save **Client ID** and
   **Client Secret**.
2. In a browser, visit (replace `<CLIENT_ID>`):
   ```
   https://www.strava.com/oauth/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=http://localhost/exchange_token&approval_prompt=force&scope=read,activity:read_all,profile:read_all
   ```
   Approve, then copy the `code=...` value out of the redirected URL.
3. Exchange the code for tokens:
   ```bash
   curl -X POST https://www.strava.com/oauth/token \
     -d client_id=<CLIENT_ID> \
     -d client_secret=<CLIENT_SECRET> \
     -d code=<CODE> \
     -d grant_type=authorization_code
   ```
   Save `refresh_token` from the response. The `access_token` is not needed —
   the server will mint a fresh one on first start.

You now have the three values you need: `client_id`, `client_secret`,
`refresh_token`.

---

## 2. Deploy

The stack is two containers: the MCP server itself, and Caddy as a
TLS-terminating reverse proxy. Before deploying, make sure:

- Docker Engine and the Compose plugin are installed on the host.
- A public hostname resolves to the host's IPv4 address.
- TCP ports 80 and 443 are reachable from the public internet — Caddy uses
  port 80 for the Let's Encrypt HTTP-01 challenge and port 443 to serve the
  connector.

```bash
git clone <this-repo-url> strava-mcp
cd strava-mcp
cp .env.example .env
# Fill in: STRAVA_CLIENT_ID, STRAVA_CLIENT_SECRET, STRAVA_REFRESH_TOKEN,
#          MCP_APPROVE_PASSWORD, DOMAIN.
mkdir -p data
docker compose up -d --build
```

`DOMAIN` is the public hostname Caddy serves on. On first start Caddy obtains
a Let's Encrypt certificate for it (allow ~30 seconds).

If you already have a Strava credentials JSON file using the same schema
(`client_id`, `client_secret`, `refresh_token`, optional `access_token` +
`expires_at`, `units`), copy it to `data/tokens.json` and the server will load
it on startup instead of seeding from environment variables.

Verify:

```bash
curl https://<DOMAIN>/health
# -> ok
docker compose logs -f strava-mcp
```

---

## 3. Register the connector in Claude.ai

In Claude Desktop (or web):

1. Settings → **Connectors** → **Add custom connector**.
2. **URL**: `https://strava-mcp.example.com/mcp`
3. Leave **Client ID** and **Client Secret** blank — the server uses RFC 7591
   dynamic client registration so Claude self-registers.
4. Click **Add**. A browser window pops open to the Approve page on
   `https://strava-mcp.example.com/authorize`.
5. Enter `MCP_APPROVE_PASSWORD` if you set one, then click **Approve**. The
   browser redirects back to Claude with an authorization code, and Claude
   exchanges it for an access token automatically.

Access tokens last 1 hour and Claude refreshes them automatically using the
refresh token (rotated on every use). Both kinds of tokens, and registered
clients, persist to `/data/oauth.json` so they survive container restarts.

---

## Local development

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

To run the server locally without Docker:

```bash
export STRAVA_CLIENT_ID=...
export STRAVA_CLIENT_SECRET=...
export STRAVA_REFRESH_TOKEN=...
export MCP_APPROVE_PASSWORD=hunter2
export STRAVA_TOKEN_PATH=$PWD/data/tokens.json
export OAUTH_STORE_PATH=$PWD/data/oauth.json
mkdir -p data
python -m strava_mcp.server
```

Then in another shell:

```bash
# Discovery — public, no auth.
curl http://localhost:8080/.well-known/oauth-authorization-server

# Hitting /mcp without a token returns 401 + WWW-Authenticate.
curl -i http://localhost:8080/mcp
```

To obtain a token manually: `POST /register`, open `/authorize?...` in a
browser, then `POST /token` with the returned code. In normal usage Claude
Desktop performs all three steps automatically when the connector is added.

## File layout

```
strava-mcp/
├─ pyproject.toml
├─ Dockerfile
├─ docker-compose.yml      # strava-mcp + caddy
├─ Caddyfile
├─ .env.example
├─ src/strava_mcp/
│  ├─ server.py            # FastMCP app, tools, OAuth routes, ASGI dispatcher
│  ├─ oauth.py             # OAuth 2.1 issuer with PKCE + DCR + persistence
│  ├─ strava.py            # async Strava client (OAuth refresh + rotation)
│  ├─ storage.py           # tokens.json reader/writer (atomic)
│  └─ aggregations.py      # weekly/monthly rollups powering the summarize tool
└─ tests/
   ├─ test_oauth.py        # OAuth metadata, PKCE roundtrip, expiry, refresh
   ├─ test_strava.py       # token refresh + rotation persistence + 401 retry
   └─ test_tools.py        # tool shapes, summarize math, auth gate
```

## Operating notes

- **Token rotation**: every Strava refresh issues a new `refresh_token`.
  `data/tokens.json` is the only place it's stored. Re-run the Strava OAuth
  handshake to recover if it is lost.
- **Rate limits**: Strava's free tier allows 200 requests per 15 minutes and
  2000 per day. The server does not rate-limit internally; sustained heavy
  usage will surface 429 responses from upstream.
- **Backups**: snapshot the `data/` volume periodically. It contains both
  `tokens.json` (Strava credentials) and `oauth.json` (issued access /
  refresh tokens and registered Claude clients). Losing it requires
  re-running both OAuth handshakes.
- **Updates**: `git pull && docker compose up -d --build`.
