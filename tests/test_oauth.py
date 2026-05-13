"""OAuth provider + endpoint tests."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from pathlib import Path

import httpx
import pytest

from strava_mcp.oauth import (
    AUTH_CODE_TTL,
    OAuthError,
    OAuthProvider,
    OAuthStore,
    RateLimiter,
    verify_pkce,
)
from strava_mcp.server import StravaMCPApp, make_oauth_routes
from strava_mcp.storage import TokenStore
from strava_mcp.strava_oauth import StravaOAuthClient


def _wizard_deps(tmp_path):
    """Build the wizard dependencies make_oauth_routes now requires.

    The Strava OAuth client and token store aren't exercised by these older
    OAuth-flow tests, so dummy values are fine.
    """
    token_path = tmp_path / "tokens.json"
    import json as _json
    token_path.write_text(_json.dumps({
        "client_id": "1", "client_secret": "shh",
        "refresh_token": "rt", "access_token": "at",
        "expires_at": 0, "units": "imperial",
    }))
    ts = TokenStore(token_path)
    ts.load_or_seed()
    so = StravaOAuthClient(client_id="1", client_secret="shh")
    return ts, so
from starlette.applications import Starlette


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _new_pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


# ---------- pure-unit tests ----------

def test_verify_pkce_s256():
    verifier = "abc.123_xyz~something-something"
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    assert verify_pkce(verifier, challenge, "S256") is True
    assert verify_pkce(verifier, challenge + "x", "S256") is False
    assert verify_pkce("nope", challenge, "S256") is False


def test_verify_pkce_plain():
    assert verify_pkce("a", "a", "plain") is True
    assert verify_pkce("a", "b", "plain") is False


def test_authorization_server_metadata_shape(tmp_path):
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    p = OAuthProvider(store)
    md = p.authorization_server_metadata("https://mcp.example.com")
    assert md["issuer"] == "https://mcp.example.com"
    assert md["authorization_endpoint"] == "https://mcp.example.com/authorize"
    assert md["token_endpoint"] == "https://mcp.example.com/token"
    assert md["registration_endpoint"] == "https://mcp.example.com/register"
    assert "code" in md["response_types_supported"]
    assert "authorization_code" in md["grant_types_supported"]
    assert "refresh_token" in md["grant_types_supported"]
    assert "S256" in md["code_challenge_methods_supported"]
    assert "none" in md["token_endpoint_auth_methods_supported"]


def test_protected_resource_metadata_shape(tmp_path):
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    p = OAuthProvider(store)
    md = p.protected_resource_metadata("https://mcp.example.com")
    assert md["resource"] == "https://mcp.example.com"
    assert md["authorization_servers"] == ["https://mcp.example.com"]
    assert "header" in md["bearer_methods_supported"]


def test_register_client_returns_client_id_and_persists(tmp_path):
    path = tmp_path / "oauth.json"
    store = OAuthStore(path)
    store.load()
    p = OAuthProvider(store)
    out = p.register_client({"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude Desktop"})
    assert out["client_id"]
    assert out["redirect_uris"] == ["https://claude.ai/cb"]
    assert out["token_endpoint_auth_method"] == "none"
    on_disk = json.loads(path.read_text())
    assert out["client_id"] in on_disk["clients"]


# ---------- full code → token PKCE roundtrip ----------

def _setup_provider(tmp_path: Path, *, password: str | None = None) -> OAuthProvider:
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    return OAuthProvider(store, approve_password=password)


def test_pkce_roundtrip(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://cb.example/cb"], "client_name": "X"})
    cid = client["client_id"]

    verifier, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid,
        redirect_uri="https://cb.example/cb",
        scope="mcp",
        state="abc",
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    tokens = p.exchange_code(
        code=code,
        code_verifier=verifier,
        client_id=cid,
        redirect_uri="https://cb.example/cb",
    )
    assert tokens["token_type"] == "Bearer"
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["expires_in"] > 0
    # access token verifies
    assert p.verify_access_token(tokens["access_token"]) is not None


def test_code_cannot_be_used_twice(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    verifier, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    p.exchange_code(code=code, code_verifier=verifier, client_id=cid, redirect_uri="https://cb/cb")
    with pytest.raises(OAuthError):
        p.exchange_code(code=code, code_verifier=verifier, client_id=cid, redirect_uri="https://cb/cb")


def test_pkce_mismatch_rejected(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    _, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    with pytest.raises(OAuthError) as ei:
        p.exchange_code(code=code, code_verifier="wrong-verifier", client_id=cid,
                        redirect_uri="https://cb/cb")
    assert ei.value.code == "invalid_grant"


def test_redirect_uri_must_match(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    verifier, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    with pytest.raises(OAuthError):
        p.exchange_code(code=code, code_verifier=verifier, client_id=cid,
                        redirect_uri="https://cb/different")


# ---------- expiry and refresh ----------

def test_expired_access_token_is_rejected(tmp_path):
    p = _setup_provider(tmp_path)
    p.access_ttl = 1
    client = p.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    verifier, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    tokens = p.exchange_code(code=code, code_verifier=verifier, client_id=cid,
                              redirect_uri="https://cb/cb")
    # Force expiry by rewriting the stored expires_at into the past.
    p.store.data["access_tokens"][tokens["access_token"]]["expires_at"] = int(time.time()) - 5
    assert p.verify_access_token(tokens["access_token"]) is None


def test_refresh_issues_new_pair_and_revokes_old(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    verifier, challenge = _new_pkce_pair()
    code = p.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    first = p.exchange_code(code=code, code_verifier=verifier, client_id=cid,
                             redirect_uri="https://cb/cb")

    second = p.refresh(refresh_token=first["refresh_token"], client_id=cid)
    assert second["access_token"] != first["access_token"]
    assert second["refresh_token"] != first["refresh_token"]
    # Old access token revoked
    assert p.verify_access_token(first["access_token"]) is None
    # Old refresh token can no longer be used
    with pytest.raises(OAuthError):
        p.refresh(refresh_token=first["refresh_token"], client_id=cid)
    # New access token works
    assert p.verify_access_token(second["access_token"]) is not None


def test_persistence_survives_reopen(tmp_path):
    path = tmp_path / "oauth.json"
    s1 = OAuthStore(path)
    s1.load()
    p1 = OAuthProvider(s1)
    client = p1.register_client({"redirect_uris": ["https://cb/cb"], "client_name": "X"})
    cid = client["client_id"]
    verifier, challenge = _new_pkce_pair()
    code = p1.issue_code(
        client_id=cid, redirect_uri="https://cb/cb", scope="mcp", state="",
        code_challenge=challenge, code_challenge_method="S256",
    )
    tokens = p1.exchange_code(code=code, code_verifier=verifier, client_id=cid,
                               redirect_uri="https://cb/cb")

    # Reopen fresh from disk
    s2 = OAuthStore(path)
    s2.load()
    p2 = OAuthProvider(s2)
    assert p2.verify_access_token(tokens["access_token"]) is not None


# ---------- HTTP-level tests through the StravaMCPApp + Starlette OAuth routes ----------

@pytest.fixture
def app(tmp_path):
    """Wire up a real StravaMCPApp with a no-op MCP backend."""
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    provider = OAuthProvider(store, approve_password=None)

    async def fake_mcp_app(scope, receive, send):
        # If lifespan: no-op (we don't bring up FastMCP for these tests).
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"mcp":"ok"}'})

    ts, so = _wizard_deps(tmp_path)
    routes = make_oauth_routes(provider, token_store=ts, strava_oauth=so)
    return StravaMCPApp(fake_mcp_app, Starlette(routes=routes), provider)


@pytest.mark.asyncio
async def test_metadata_endpoint_returns_json_with_issuer(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        r = await c.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        body = r.json()
        assert body["issuer"] == "https://mcp.test"
        assert body["authorization_endpoint"] == "https://mcp.test/authorize"


@pytest.mark.asyncio
async def test_metadata_honors_x_forwarded_prefix(app):
    """When a gateway mounts this server at a subpath, issuer URLs include it."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://gateway.test") as c:
        r = await c.get(
            "/.well-known/oauth-authorization-server",
            headers={"x-forwarded-prefix": "/strava"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["issuer"] == "https://gateway.test/strava"
        assert body["authorization_endpoint"] == "https://gateway.test/strava/authorize"
        assert body["token_endpoint"] == "https://gateway.test/strava/token"
        assert body["registration_endpoint"] == "https://gateway.test/strava/register"


@pytest.mark.asyncio
async def test_unauth_mcp_resource_metadata_url_honors_prefix(app):
    """The 401 WWW-Authenticate resource_metadata URL also picks up the prefix."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://gateway.test") as c:
        r = await c.get("/mcp", headers={"x-forwarded-prefix": "/strava"})
        assert r.status_code == 401
        www_auth = r.headers["www-authenticate"]
        assert 'resource_metadata="https://gateway.test/strava/.well-known/oauth-protected-resource"' in www_auth


@pytest.mark.asyncio
async def test_authorize_form_action_honors_prefix(app):
    """The Approve-page POST target stays inside the mount path."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://gateway.test") as c:
        # Need a registered client first.
        r = await c.post("/register", json={"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude"})
        assert r.status_code == 201
        client_id = r.json()["client_id"]

        _, challenge = _new_pkce_pair()
        r = await c.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/cb",
                "scope": "mcp",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            headers={"x-forwarded-prefix": "/strava"},
        )
        assert r.status_code == 200
        assert 'action="/strava/authorize"' in r.text


@pytest.mark.asyncio
async def test_unknown_well_known_returns_404_not_401(app):
    """OIDC and other /.well-known/* probes must 404, not 401.

    Claude.ai's MCP connector probes /.well-known/openid-configuration during
    discovery. A 401 there made it think the authorization server was broken
    and bail out; a 404 correctly says "no OIDC, use OAuth 2.0" and it falls
    back to the metadata it already got from oauth-protected-resource.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        r = await c.get("/.well-known/openid-configuration")
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_unauth_mcp_returns_401_with_www_authenticate(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        r = await c.get("/mcp")
        assert r.status_code == 401
        assert "Bearer" in r.headers.get("www-authenticate", "")
        assert "resource_metadata" in r.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_full_authorize_token_roundtrip_over_http(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        # Register client (DCR)
        r = await c.post("/register", json={"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude"})
        assert r.status_code == 201
        client_id = r.json()["client_id"]

        # Generate PKCE pair
        verifier, challenge = _new_pkce_pair()

        # GET /authorize → HTML form
        r = await c.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/cb",
                "scope": "mcp",
                "state": "xyz",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 200
        assert "Approve" in r.text
        assert client_id in r.text

        # POST /authorize → 303 to wizard (no longer mints code directly)
        r = await c.post(
            "/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/cb",
                "scope": "mcp",
                "state": "xyz",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        from urllib.parse import urlparse, parse_qs
        wiz_loc = r.headers["location"]
        session = parse_qs(urlparse(wiz_loc).query)["session"][0]

        # The fixture's TokenStore was seeded with a refresh_token, so the
        # wizard considers Strava already connected and shows the Done button.
        # POST /wizard/done → 302 to claude with code+state.
        r = await c.post(
            "/wizard/done", data={"session": session}, follow_redirects=False
        )
        assert r.status_code == 302
        loc = r.headers["location"]
        assert loc.startswith("https://claude.ai/cb")
        qs = parse_qs(urlparse(loc).query)
        code = qs["code"][0]
        assert qs["state"] == ["xyz"]

        # POST /token → access + refresh
        r = await c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "client_id": client_id,
                "redirect_uri": "https://claude.ai/cb",
            },
        )
        assert r.status_code == 200
        body = r.json()
        access = body["access_token"]
        refresh = body["refresh_token"]
        assert body["token_type"] == "Bearer"

        # Authenticated /mcp call passes through to the fake MCP app
        r = await c.get("/mcp", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200

        # /mcp with garbage token → 401
        r = await c.get("/mcp", headers={"Authorization": "Bearer garbage"})
        assert r.status_code == 401

        # Refresh exchanges for a new access token
        r = await c.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": client_id,
            },
        )
        assert r.status_code == 200
        new_body = r.json()
        assert new_body["access_token"] != access

        # Old access is revoked
        r = await c.get("/mcp", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 401
        # New access works
        r = await c.get("/mcp", headers={"Authorization": f"Bearer {new_body['access_token']}"})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_authorize_password_gate(tmp_path):
    """When MCP_APPROVE_PASSWORD is set, POST /authorize without it returns 403."""
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    provider = OAuthProvider(store, approve_password="hunter2")

    async def fake_mcp_app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

    ts, so = _wizard_deps(tmp_path)
    routes = make_oauth_routes(provider, token_store=ts, strava_oauth=so)
    app = StravaMCPApp(fake_mcp_app, Starlette(routes=routes), provider)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = (await c.post("/register", json={"redirect_uris": ["https://x/cb"]})).json()["client_id"]
        _, challenge = _new_pkce_pair()
        # GET form should include a password field
        r = await c.get(
            "/authorize",
            params={
                "response_type": "code", "client_id": client_id,
                "redirect_uri": "https://x/cb", "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert r.status_code == 200
        assert 'name="approve_password"' in r.text

        # POST without password → 403
        r = await c.post("/authorize", data={
            "response_type": "code", "client_id": client_id,
            "redirect_uri": "https://x/cb", "code_challenge": challenge,
            "code_challenge_method": "S256",
        }, follow_redirects=False)
        assert r.status_code == 403

        # POST with correct password → 303 to the wizard (no longer a direct
        # client redirect — the wizard finalizes that).
        r = await c.post("/authorize", data={
            "response_type": "code", "client_id": client_id,
            "redirect_uri": "https://x/cb", "code_challenge": challenge,
            "code_challenge_method": "S256", "approve_password": "hunter2",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/wizard?session=")


# ---------- DCR disable + client_id/redirect_uri validation + rate limit ----------

def test_disable_dcr_blocks_register(tmp_path):
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    p = OAuthProvider(store, disable_dcr=True)
    with pytest.raises(OAuthError) as ei:
        p.register_client({"redirect_uris": ["https://x/cb"]})
    assert ei.value.code == "registration_disabled"
    assert ei.value.status == 403


def test_validate_authorize_unknown_client_raises(tmp_path):
    p = _setup_provider(tmp_path)
    with pytest.raises(OAuthError) as ei:
        p.validate_authorize_request("does-not-exist", "https://x/cb")
    assert ei.value.code == "invalid_client"
    assert ei.value.status == 401


def test_validate_authorize_redirect_uri_mismatch(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://allowed/cb"]})
    with pytest.raises(OAuthError) as ei:
        p.validate_authorize_request(client["client_id"], "https://other/cb")
    assert ei.value.code == "invalid_request"


def test_validate_authorize_redirect_uri_match(tmp_path):
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": ["https://allowed/cb"]})
    rec = p.validate_authorize_request(client["client_id"], "https://allowed/cb")
    assert rec["client_id"] == client["client_id"]


def test_validate_authorize_skips_when_no_redirect_uris_registered(tmp_path):
    """Defensive: if a client registers without redirect_uris, accept any value."""
    p = _setup_provider(tmp_path)
    client = p.register_client({"redirect_uris": []})
    rec = p.validate_authorize_request(client["client_id"], "https://anything/cb")
    assert rec["client_id"] == client["client_id"]


def test_rate_limiter_allows_then_blocks():
    rl = RateLimiter(max_attempts=3, window_seconds=60)
    assert rl.allow("ip1") is True
    assert rl.allow("ip1") is True
    assert rl.allow("ip1") is True
    assert rl.allow("ip1") is False
    # Independent buckets per key.
    assert rl.allow("ip2") is True


def test_rate_limiter_window_expires():
    rl = RateLimiter(max_attempts=2, window_seconds=60)
    rl.allow("ip")
    rl.allow("ip")
    assert rl.allow("ip") is False
    # Force the bucket entries past the window.
    bucket = rl._buckets["ip"]
    bucket[0] = time.time() - 120
    bucket[1] = time.time() - 120
    assert rl.allow("ip") is True


# ---------- HTTP-level: validation + DCR disable + rate limit ----------

def _make_app_with(provider, *, rate_limiter=None, tmp_path=None):
    async def fake_mcp_app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"ok":true}'})

    # If tmp_path isn't passed, the caller doesn't care about the wizard deps;
    # use ephemeral in-memory wizard deps anchored in a process-temp dir.
    if tmp_path is None:
        import tempfile
        tmp_path = Path(tempfile.mkdtemp())
    ts, so = _wizard_deps(tmp_path)
    routes = make_oauth_routes(
        provider, token_store=ts, strava_oauth=so, authorize_rate_limiter=rate_limiter
    )
    return StravaMCPApp(fake_mcp_app, Starlette(routes=routes), provider)


@pytest.mark.asyncio
async def test_register_returns_403_when_dcr_disabled(tmp_path):
    store = OAuthStore(tmp_path / "oauth.json")
    store.load()
    provider = OAuthProvider(store, disable_dcr=True)
    app = _make_app_with(provider)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        r = await c.post("/register", json={"redirect_uris": ["https://x/cb"]})
        assert r.status_code == 403
        assert r.json()["error"] == "registration_disabled"


@pytest.mark.asyncio
async def test_authorize_get_unknown_client_returns_401(tmp_path):
    provider = _setup_provider(tmp_path)
    app = _make_app_with(provider)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        _, challenge = _new_pkce_pair()
        r = await c.get("/authorize", params={
            "response_type": "code", "client_id": "does-not-exist",
            "redirect_uri": "https://x/cb", "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        assert r.status_code == 401
        assert "invalid_client" in r.text


@pytest.mark.asyncio
async def test_authorize_post_redirect_uri_mismatch_returns_400(tmp_path):
    provider = _setup_provider(tmp_path)
    client = provider.register_client({"redirect_uris": ["https://allowed/cb"]})
    app = _make_app_with(provider)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        _, challenge = _new_pkce_pair()
        r = await c.post("/authorize", data={
            "response_type": "code", "client_id": client["client_id"],
            "redirect_uri": "https://elsewhere/cb",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }, follow_redirects=False)
        assert r.status_code == 400
        assert "invalid_request" in r.text


@pytest.mark.asyncio
async def test_authorize_post_rate_limited(tmp_path):
    provider = _setup_provider(tmp_path, password="hunter2")
    client = provider.register_client({"redirect_uris": ["https://x/cb"]})
    rl = RateLimiter(max_attempts=3, window_seconds=60)
    app = _make_app_with(provider, rate_limiter=rl)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        _, challenge = _new_pkce_pair()
        # 3 wrong-password attempts: each gets 403 (still under limit)
        for _ in range(3):
            r = await c.post("/authorize", data={
                "response_type": "code", "client_id": client["client_id"],
                "redirect_uri": "https://x/cb",
                "code_challenge": challenge, "code_challenge_method": "S256",
                "approve_password": "wrong",
            }, follow_redirects=False)
            assert r.status_code == 403
        # 4th attempt: rate limited
        r = await c.post("/authorize", data={
            "response_type": "code", "client_id": client["client_id"],
            "redirect_uri": "https://x/cb",
            "code_challenge": challenge, "code_challenge_method": "S256",
            "approve_password": "wrong",
        }, follow_redirects=False)
        assert r.status_code == 429
        assert r.headers.get("retry-after") == "60"


def test_build_app_requires_mcp_approve_password(monkeypatch, tmp_path):
    """MCP_APPROVE_PASSWORD is required and build_app must refuse to start without it."""
    from strava_mcp.server import build_app

    monkeypatch.delenv("MCP_APPROVE_PASSWORD", raising=False)
    monkeypatch.setenv("STRAVA_TOKEN_PATH", str(tmp_path / "tokens.json"))
    monkeypatch.setenv("OAUTH_STORE_PATH", str(tmp_path / "oauth.json"))
    monkeypatch.setenv("STRAVA_CLIENT_ID", "1")
    monkeypatch.setenv("STRAVA_CLIENT_SECRET", "s")
    monkeypatch.setenv("STRAVA_REFRESH_TOKEN", "r")

    with pytest.raises(RuntimeError, match="MCP_APPROVE_PASSWORD"):
        build_app()


@pytest.mark.asyncio
async def test_rate_limit_uses_cf_connecting_ip(tmp_path):
    """Different CF-Connecting-IP values get independent buckets."""
    provider = _setup_provider(tmp_path, password="hunter2")
    client = provider.register_client({"redirect_uris": ["https://x/cb"]})
    rl = RateLimiter(max_attempts=2, window_seconds=60)
    app = _make_app_with(provider, rate_limiter=rl)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        _, challenge = _new_pkce_pair()
        data = {
            "response_type": "code", "client_id": client["client_id"],
            "redirect_uri": "https://x/cb",
            "code_challenge": challenge, "code_challenge_method": "S256",
            "approve_password": "wrong",
        }
        # IP A: exhaust the limit
        for _ in range(2):
            r = await c.post("/authorize", data=data, headers={"cf-connecting-ip": "1.1.1.1"}, follow_redirects=False)
            assert r.status_code == 403
        r = await c.post("/authorize", data=data, headers={"cf-connecting-ip": "1.1.1.1"}, follow_redirects=False)
        assert r.status_code == 429
        # IP B: still has its own quota
        r = await c.post("/authorize", data=data, headers={"cf-connecting-ip": "2.2.2.2"}, follow_redirects=False)
        assert r.status_code == 403
