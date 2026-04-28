"""FastMCP server exposing personal Strava data over streamable HTTP.

Auth: a minimal embedded OAuth 2.1 issuer (see oauth.py). Claude Desktop's
custom-connector UI accepts a URL only — it discovers the OAuth flow via
/.well-known/oauth-authorization-server and walks the user through a one-click
"Approve" page on /authorize.

/health is exempt so an upstream load balancer or reverse proxy can probe it.
"""
from __future__ import annotations

import html
import json
import os
import urllib.parse
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from .aggregations import (
    bucketed,
    cardio_summary,
    distance_unit,
    distance_value,
    elevation_unit,
    elevation_value,
    speed_value,
    trim_activity,
)
from .oauth import OAuthError, OAuthProvider, OAuthStore, RateLimiter
from .storage import TokenStore
from .strava import StravaClient

DEFAULT_TOKEN_PATH = "/data/tokens.json"
DEFAULT_OAUTH_PATH = "/data/oauth.json"
DEFAULT_PORT = 8080

PUBLIC_PATHS = frozenset(
    {
        "/health",
        "/healthz",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/register",
        "/authorize",
        "/token",
    }
)


# ---------- shared helpers ----------

def _iso_to_epoch(s: str | None) -> int | None:
    if not s:
        return None
    raw = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        dt = datetime.fromisoformat(raw + "T00:00:00+00:00")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _resolve_units(client: StravaClient, override: str | None) -> str:
    if override is None:
        return client.units
    if override not in ("imperial", "metric"):
        raise ValueError("units must be 'imperial' or 'metric'")
    return override


# ---------- tool implementations (plain async fns; tests call these directly) ----------

async def tool_list_activities(
    client: StravaClient,
    *,
    after: str | None,
    before: str | None,
    types: list[str] | None,
    limit: int,
    units: str | None,
) -> dict[str, Any]:
    u = _resolve_units(client, units)
    if limit <= 0:
        return {"activities": [], "count": 0, "units": u}
    after_ep = _iso_to_epoch(after)
    before_ep = _iso_to_epoch(before)
    type_set = set(types) if types else None

    fetched: list[dict] = []
    page = 1
    per_page = 100
    while True:
        batch = await client.list_activities(
            after=after_ep, before=before_ep, per_page=per_page, page=page
        )
        if not batch:
            break
        fetched.extend(batch)
        kept = (
            sum(1 for a in fetched if a.get("type") in type_set)
            if type_set
            else len(fetched)
        )
        if kept >= limit or len(batch) < per_page:
            break
        page += 1

    if type_set:
        fetched = [a for a in fetched if a.get("type") in type_set]
    fetched = fetched[:limit]
    return {
        "activities": [trim_activity(a, u) for a in fetched],
        "count": len(fetched),
        "units": u,
    }


async def tool_get_activity(
    client: StravaClient, *, activity_id: int, units: str | None
) -> dict[str, Any]:
    u = _resolve_units(client, units)
    raw = await client.get_activity(activity_id)
    out = trim_activity(raw, u)
    passthrough = (
        "description",
        "calories",
        "kudos_count",
        "comment_count",
        "achievement_count",
        "pr_count",
        "private",
        "trainer",
        "commute",
        "device_name",
        "gear_id",
        "average_cadence",
        "average_watts",
        "average_temp",
        "map",
        "splits_metric",
        "splits_standard",
        "best_efforts",
    )
    for k in passthrough:
        if raw.get(k) is not None:
            out[k] = raw[k]
    if raw.get("max_speed") is not None:
        out["max_speed"] = round(speed_value(float(raw["max_speed"]), u), 3)
    return out


def _convert_totals_block(blk: Any, units: str) -> Any:
    if not isinstance(blk, dict):
        return blk
    out = dict(blk)
    if "distance" in blk and blk["distance"] is not None:
        out["distance"] = round(distance_value(blk["distance"], units), 3)
    if "elevation_gain" in blk and blk["elevation_gain"] is not None:
        out["elevation_gain"] = round(elevation_value(blk["elevation_gain"], units), 1)
    return out


async def tool_athlete_stats(
    client: StravaClient, *, units: str | None
) -> dict[str, Any]:
    u = _resolve_units(client, units)
    raw = await client.get_athlete_stats()
    out: dict[str, Any] = {
        "units": u,
        "distance_unit": distance_unit(u),
        "elevation_unit": elevation_unit(u),
    }
    if raw.get("biggest_ride_distance") is not None:
        out["biggest_ride_distance"] = round(distance_value(raw["biggest_ride_distance"], u), 3)
    if raw.get("biggest_climb_elevation_gain") is not None:
        out["biggest_climb_elevation_gain"] = round(
            elevation_value(raw["biggest_climb_elevation_gain"], u), 1
        )
    for key in (
        "recent_run_totals",
        "recent_ride_totals",
        "recent_swim_totals",
        "ytd_run_totals",
        "ytd_ride_totals",
        "ytd_swim_totals",
        "all_run_totals",
        "all_ride_totals",
        "all_swim_totals",
    ):
        if key in raw:
            out[key] = _convert_totals_block(raw[key], u)
    return out


async def tool_summarize(
    client: StravaClient,
    *,
    period: str,
    count: int,
    types: list[str] | None,
    units: str | None,
) -> dict[str, Any]:
    if period not in ("week", "month"):
        raise ValueError("period must be 'week' or 'month'")
    if count <= 0:
        raise ValueError("count must be positive")
    u = _resolve_units(client, units)
    types_list = list(types) if types else ["Run", "Walk"]

    today = datetime.now(timezone.utc).date()
    if period == "week":
        anchor = today - timedelta(days=today.weekday())
        earliest = anchor - timedelta(days=7 * (count - 1))
    else:
        y, m = today.year, today.month - (count - 1)
        while m <= 0:
            m += 12
            y -= 1
        earliest = date(y, m, 1)
    after_ep = int(
        datetime(earliest.year, earliest.month, earliest.day, tzinfo=timezone.utc).timestamp()
    )

    acts: list[dict] = []
    async for a in client.iter_activities(after=after_ep, per_page=100):
        acts.append(a)

    return {
        "period": period,
        "count": count,
        "types": types_list,
        "units": u,
        "distance_unit": distance_unit(u),
        "elevation_unit": elevation_unit(u),
        "overall": cardio_summary(acts, types=types_list, units=u),
        "buckets": bucketed(acts, period=period, count=count, types=types_list, units=u, today=today),
    }


async def tool_streams(
    client: StravaClient, *, activity_id: int, keys: list[str] | None, units: str | None
) -> dict[str, Any]:
    u = _resolve_units(client, units)
    keys = keys or ["heartrate", "velocity_smooth", "altitude"]
    raw = await client.get_streams(activity_id, keys)
    return {"id": activity_id, "keys": keys, "units": u, "streams": raw}


# ---------- FastMCP wiring ----------

def make_mcp(client: StravaClient) -> FastMCP:
    mcp = FastMCP("strava-mcp")

    @mcp.tool()
    async def list_activities(
        after: str | None = None,
        before: str | None = None,
        types: list[str] | None = None,
        limit: int = 30,
        units: str | None = None,
    ) -> dict:
        """Recent Strava activities, newest first.

        - after / before: ISO 8601 date or datetime ("2025-01-01" or "2025-01-01T00:00:00Z").
        - types: optional Strava activity types like ["Run","Walk","Ride"]; filtered client-side.
        - limit: cap on returned activities (default 30).
        - units: "imperial" (mi/ft/mph) or "metric" (km/m/kmh). Falls back to the user's saved preference.
        """
        return await tool_list_activities(
            client, after=after, before=before, types=types, limit=limit, units=units
        )

    @mcp.tool()
    async def get_activity(id: int, units: str | None = None) -> dict:
        """Full detail for one activity (splits, description, calories, gear, map, etc.)."""
        return await tool_get_activity(client, activity_id=id, units=units)

    @mcp.tool()
    async def get_athlete_stats(units: str | None = None) -> dict:
        """Lifetime / YTD / 4-week totals for run, ride, swim. Distances in mi or km."""
        return await tool_athlete_stats(client, units=units)

    @mcp.tool()
    async def summarize(
        period: str = "week",
        count: int = 8,
        types: list[str] | None = None,
        units: str | None = None,
    ) -> dict:
        """Roll up activities into N week or month buckets.

        - period: "week" or "month".
        - count: number of buckets (default 8).
        - types: which activity types to include (default ["Run","Walk"]).
        - Returns per-bucket distance, moving time, elevation gain, count, and avg pace,
          plus an `overall` summary across the whole window.
        """
        return await tool_summarize(
            client, period=period, count=count, types=types, units=units
        )

    @mcp.tool()
    async def get_activity_streams(
        id: int,
        keys: list[str] | None = None,
        units: str | None = None,
    ) -> dict:
        """Time-series streams for an activity.

        Default keys: ["heartrate","velocity_smooth","altitude"]. Streams come back in
        Strava's raw SI units (m, m/s, bpm) — the `units` field tells callers which
        unit system to display.
        """
        return await tool_streams(client, activity_id=id, keys=keys, units=units)

    return mcp


# ---------- OAuth route handlers ----------

def _issuer_from_request(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if not host:
        host = request.url.netloc
    return f"{proto}://{host}".rstrip("/")


_APPROVE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Approve MCP access</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{{color-scheme:light dark;--bg:#fafafa;--card:#fff;--text:#1a1a1a;--muted:#666;--border:#e5e5e5;--btn:#0a7afe}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#1a1d24;--text:#e5e5e7;--muted:#a0a2a9;--border:#2a2e37;--btn:#3590ff}}}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:grid;place-items:center;padding:24px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:28px;max-width:420px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.04)}}
h1{{margin:0 0 6px;font-size:20px;font-weight:650;letter-spacing:-.01em}}
p{{margin:0 0 14px;color:var(--muted);font-size:14px;line-height:1.5}}
ul{{margin:6px 0 18px;padding-left:18px;color:var(--muted);font-size:13.5px}}
input[type=password]{{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text);font-size:14px;margin-bottom:12px}}
button{{width:100%;background:var(--btn);color:#fff;border:0;padding:12px;font-size:15px;font-weight:600;border-radius:8px;cursor:pointer}}
button:hover{{filter:brightness(1.05)}}
.detail{{font-size:12px;color:var(--muted);margin-top:14px;word-break:break-all}}
.detail b{{color:var(--text);font-weight:600}}
</style>
</head><body>
<div class="card">
  <h1>Approve MCP access</h1>
  <p>{client_name} is requesting access to your Strava data through this MCP server.</p>
  <ul>
    <li>Read your activities, splits, and streams</li>
    <li>Read your athlete profile and totals</li>
  </ul>
  <form method="post" action="/authorize">
{hidden_inputs}
{password_field}
    <button type="submit">Approve</button>
  </form>
  <div class="detail">
    Redirecting to: <b>{redirect_uri}</b>
  </div>
</div>
</body></html>
"""


def _password_field_html(provider: OAuthProvider) -> str:
    if not provider.approve_password:
        return ""
    return (
        '    <input type="password" name="approve_password" '
        'placeholder="approval password" autocomplete="off" required>\n'
    )


def _hidden_inputs(params: dict[str, str]) -> str:
    rows = []
    for k, v in params.items():
        rows.append(f'    <input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">')
    return "\n".join(rows)


def _request_client_ip(request: Request) -> str:
    """Best-effort real client IP, honoring common reverse-proxy headers."""
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def make_oauth_routes(
    provider: OAuthProvider,
    *,
    authorize_rate_limiter: RateLimiter | None = None,
) -> list[Route]:

    async def health(_request: Request) -> Response:
        return JSONResponse({"ok": True})

    async def authz_metadata(request: Request) -> Response:
        return JSONResponse(provider.authorization_server_metadata(_issuer_from_request(request)))

    async def resource_metadata(request: Request) -> Response:
        return JSONResponse(provider.protected_resource_metadata(_issuer_from_request(request)))

    async def register(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
        try:
            return JSONResponse(provider.register_client(body), status_code=201)
        except OAuthError as e:
            return JSONResponse(
                {"error": e.code, "error_description": e.description},
                status_code=e.status,
            )

    async def authorize(request: Request) -> Response:
        if request.method == "GET":
            params = dict(request.query_params)
            if params.get("response_type") != "code":
                return PlainTextResponse("unsupported_response_type", status_code=400)
            for required in ("client_id", "redirect_uri", "code_challenge"):
                if not params.get(required):
                    return PlainTextResponse(f"missing parameter: {required}", status_code=400)
            method = params.get("code_challenge_method", "plain")
            if method not in ("S256", "plain"):
                return PlainTextResponse("unsupported code_challenge_method", status_code=400)

            try:
                client_record = provider.validate_authorize_request(
                    params["client_id"], params["redirect_uri"]
                )
            except OAuthError as e:
                return PlainTextResponse(
                    f"{e.code}: {e.description}", status_code=e.status
                )

            client_name = client_record.get("client_name") or "An MCP client"
            page = _APPROVE_PAGE.format(
                client_name=html.escape(client_name),
                hidden_inputs=_hidden_inputs(params),
                password_field=_password_field_html(provider),
                redirect_uri=html.escape(params["redirect_uri"]),
            )
            return HTMLResponse(page)

        # POST — rate-limit FIRST so password brute-force is throttled.
        if authorize_rate_limiter is not None:
            ip = _request_client_ip(request)
            if not authorize_rate_limiter.allow(ip):
                return PlainTextResponse(
                    "rate limit exceeded; try again in a minute",
                    status_code=429,
                    headers={"Retry-After": "60"},
                )

        form = await request.form()
        params = {k: str(v) for k, v in form.items()}
        if provider.approve_password:
            if params.get("approve_password") != provider.approve_password:
                return PlainTextResponse("approval password incorrect", status_code=403)
        for required in ("client_id", "redirect_uri", "code_challenge"):
            if not params.get(required):
                return PlainTextResponse(f"missing parameter: {required}", status_code=400)
        try:
            provider.validate_authorize_request(
                params["client_id"], params["redirect_uri"]
            )
        except OAuthError as e:
            return PlainTextResponse(
                f"{e.code}: {e.description}", status_code=e.status
            )
        code = provider.issue_code(
            client_id=params["client_id"],
            redirect_uri=params["redirect_uri"],
            scope=params.get("scope", "mcp"),
            state=params.get("state", ""),
            code_challenge=params["code_challenge"],
            code_challenge_method=params.get("code_challenge_method", "plain"),
        )
        # Build redirect URL, preserving any existing query string in the redirect_uri.
        parsed = urllib.parse.urlsplit(params["redirect_uri"])
        existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        existing.append(("code", code))
        if params.get("state"):
            existing.append(("state", params["state"]))
        new_query = urllib.parse.urlencode(existing)
        target = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
        return RedirectResponse(target, status_code=302)

    async def token(request: Request) -> Response:
        try:
            form = await request.form()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        params = {k: str(v) for k, v in form.items()}
        grant_type = params.get("grant_type")
        try:
            if grant_type == "authorization_code":
                for required in ("code", "code_verifier", "client_id", "redirect_uri"):
                    if not params.get(required):
                        raise OAuthError("invalid_request", f"missing {required}")
                resp = provider.exchange_code(
                    code=params["code"],
                    code_verifier=params["code_verifier"],
                    client_id=params["client_id"],
                    redirect_uri=params["redirect_uri"],
                )
            elif grant_type == "refresh_token":
                for required in ("refresh_token", "client_id"):
                    if not params.get(required):
                        raise OAuthError("invalid_request", f"missing {required}")
                resp = provider.refresh(
                    refresh_token=params["refresh_token"],
                    client_id=params["client_id"],
                )
            else:
                raise OAuthError("unsupported_grant_type", f"grant_type={grant_type!r}")
        except OAuthError as e:
            return JSONResponse(
                {"error": e.code, "error_description": e.description},
                status_code=e.status,
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(resp, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    return [
        Route("/health", health, methods=["GET"]),
        Route("/healthz", health, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authz_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", resource_metadata, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET", "POST"]),
        Route("/token", token, methods=["POST"]),
    ]


# ---------- ASGI dispatcher ----------

class StravaMCPApp:
    """Top-level ASGI app.

    - Lifespan scopes go to the FastMCP app so its session manager initializes.
    - Public paths (/health, /.well-known/*, /register, /authorize, /token) go to
      the Starlette app with OAuth route handlers.
    - Everything else (i.e., /mcp and any MCP session-bound paths) requires a
      Bearer access token issued by our OAuth provider.
    """

    def __init__(self, mcp_app: Any, oauth_app: Any, oauth_provider: OAuthProvider):
        self.mcp_app = mcp_app
        self.oauth_app = oauth_app
        self.oauth_provider = oauth_provider

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.mcp_app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.mcp_app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in PUBLIC_PATHS:
            await self.oauth_app(scope, receive, send)
            return

        token = _extract_bearer(scope)
        claims = self.oauth_provider.verify_access_token(token)
        if claims is None:
            await _send_401(scope, send)
            return
        await self.mcp_app(scope, receive, send)


def _extract_bearer(scope) -> str | None:
    for name, value in scope.get("headers") or []:
        if name == b"authorization":
            v = value.decode()
            if v.lower().startswith("bearer "):
                return v[7:].strip()
    return None


async def _send_401(scope, send) -> None:
    proto, host = _derive_origin(scope)
    resource_metadata_url = f"{proto}://{host}/.well-known/oauth-protected-resource"
    body = json.dumps(
        {"error": "unauthorized", "error_description": "missing or invalid access token"}
    ).encode()
    www_auth = (
        f'Bearer realm="MCP", error="invalid_token", '
        f'resource_metadata="{resource_metadata_url}"'
    )
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", www_auth.encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _derive_origin(scope) -> tuple[str, str]:
    headers = {k: v for k, v in (scope.get("headers") or [])}
    proto = (
        headers.get(b"x-forwarded-proto", b"").decode()
        or scope.get("scheme")
        or "http"
    )
    host = (
        headers.get(b"x-forwarded-host", b"").decode()
        or headers.get(b"host", b"").decode()
    )
    if not host:
        s = scope.get("server") or ("localhost", 80)
        host = f"{s[0]}:{s[1]}"
    return proto, host


# ---------- App factory + entrypoint ----------

def _get_http_app(mcp: FastMCP):
    if hasattr(mcp, "http_app"):
        return mcp.http_app()
    if hasattr(mcp, "streamable_http_app"):
        return mcp.streamable_http_app()
    raise RuntimeError("This FastMCP build has neither http_app() nor streamable_http_app()")


def build_app(
    client: StravaClient | None = None,
    *,
    oauth_provider: OAuthProvider | None = None,
    authorize_rate_limiter: RateLimiter | None = None,
):
    if client is None:
        token_path = Path(os.environ.get("STRAVA_TOKEN_PATH", DEFAULT_TOKEN_PATH))
        store = TokenStore(token_path)
        store.load_or_seed()
        client = StravaClient(store)

    if oauth_provider is None:
        oauth_path = Path(os.environ.get("OAUTH_STORE_PATH", DEFAULT_OAUTH_PATH))
        oauth_store = OAuthStore(oauth_path)
        oauth_store.load()
        approve_pw = os.environ.get("MCP_APPROVE_PASSWORD")
        if not approve_pw:
            raise RuntimeError(
                "MCP_APPROVE_PASSWORD env var is required. Set it to a strong, "
                "random secret — it is what guards the /authorize Approve page."
            )
        disable_dcr = os.environ.get(
            "DISABLE_DYNAMIC_CLIENT_REGISTRATION", ""
        ).lower() in ("1", "true", "yes")
        oauth_provider = OAuthProvider(
            oauth_store,
            approve_password=approve_pw,
            disable_dcr=disable_dcr,
        )

    if authorize_rate_limiter is None:
        authorize_rate_limiter = RateLimiter(max_attempts=5, window_seconds=60)

    mcp = make_mcp(client)
    mcp_app = _get_http_app(mcp)

    oauth_routes = make_oauth_routes(
        oauth_provider, authorize_rate_limiter=authorize_rate_limiter
    )
    oauth_app = Starlette(routes=oauth_routes)

    return StravaMCPApp(mcp_app, oauth_app, oauth_provider)


def run() -> None:
    app = build_app()
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level=os.environ.get("LOG_LEVEL", "info"),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    run()
