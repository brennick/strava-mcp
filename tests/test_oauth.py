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
    verify_pkce,
)
from strava_mcp.server import StravaMCPApp, make_oauth_routes
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

    routes = make_oauth_routes(provider)
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

        # POST /authorize → 302 redirect with code
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
        assert r.status_code == 302
        loc = r.headers["location"]
        assert loc.startswith("https://claude.ai/cb")
        # Pull the code out
        from urllib.parse import urlparse, parse_qs
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

    routes = make_oauth_routes(provider)
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

        # POST with correct password → 302
        r = await c.post("/authorize", data={
            "response_type": "code", "client_id": client_id,
            "redirect_uri": "https://x/cb", "code_challenge": challenge,
            "code_challenge_method": "S256", "approve_password": "hunter2",
        }, follow_redirects=False)
        assert r.status_code == 302
