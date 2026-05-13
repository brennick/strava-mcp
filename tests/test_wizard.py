"""Tests for the combined-flow authorize wizard.

Walks: GET /authorize → POST password → /wizard → /wizard/connect → simulated
Strava callback → /wizard → /wizard/done → redirect to client.
"""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from pathlib import Path

import httpx
import pytest
import respx
from starlette.applications import Starlette

from strava_mcp.oauth import OAuthProvider, OAuthStore
from strava_mcp.server import StravaMCPApp, make_oauth_routes
from strava_mcp.storage import TokenStore
from strava_mcp.strava_oauth import StravaOAuthClient


async def _ok_app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] == "http":
        await send(
            {"type": "http.response.start", "status": 200,
             "headers": [(b"content-type", b"text/plain")]}
        )
        await send({"type": "http.response.body", "body": b"ok"})


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _new_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(b"a" * 64)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


def _make_app(tmp_path: Path, *, seed_token: bool = False):
    oauth_store = OAuthStore(tmp_path / "oauth.json")
    oauth_store.load()
    provider = OAuthProvider(oauth_store, approve_password="testpw")

    token_path = tmp_path / "tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "client_id": "scid",
                "client_secret": "scs",
                "refresh_token": "rt-seed" if seed_token else "",
                "access_token": "",
                "expires_at": 0,
                "units": "imperial",
            }
        )
    )
    ts = TokenStore(token_path)
    ts.load_or_seed()
    so = StravaOAuthClient(client_id="scid", client_secret="scs")
    routes = make_oauth_routes(provider, token_store=ts, strava_oauth=so)
    app = StravaMCPApp(_ok_app, Starlette(routes=routes), provider)
    return app, provider, ts


async def _register_client(c: httpx.AsyncClient) -> str:
    r = await c.post(
        "/register",
        json={"redirect_uris": ["https://claude.ai/cb"], "client_name": "Claude"},
    )
    assert r.status_code == 201
    return r.json()["client_id"]


async def _post_approve(c: httpx.AsyncClient, *, client_id: str, code_challenge: str,
                        state: str = "S") -> str:
    r = await c.post(
        "/authorize",
        data={
            "approve_password": "testpw",
            "client_id": client_id,
            "redirect_uri": "https://claude.ai/cb",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "mcp",
        },
    )
    assert r.status_code == 303, r.text
    location = r.headers["location"]
    assert location.startswith("/wizard?session=")
    return urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["session"][0]


@pytest.mark.asyncio
async def test_approve_redirects_to_wizard(tmp_path):
    app, _, _ = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        assert session


@pytest.mark.asyncio
async def test_wizard_shows_connect_when_no_strava_token(tmp_path):
    app, _, _ = _make_app(tmp_path, seed_token=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.get(f"/wizard?session={session}")
        assert r.status_code == 200
        assert "Connect Strava" in r.text
        assert "Not connected" in r.text
        # Done button only appears when connected.
        assert 'action="/wizard/done"' not in r.text


@pytest.mark.asyncio
async def test_wizard_shows_reconnect_and_done_when_already_connected(tmp_path):
    app, _, _ = _make_app(tmp_path, seed_token=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.get(f"/wizard?session={session}")
        assert r.status_code == 200
        assert "Reconnect" in r.text
        assert 'action="/wizard/done"' in r.text


@pytest.mark.asyncio
async def test_wizard_connect_redirects_to_strava_with_state(tmp_path):
    app, _, _ = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.post("/wizard/connect", data={"session": session})
        assert r.status_code == 303
        loc = r.headers["location"]
        assert loc.startswith("https://www.strava.com/oauth/authorize?")
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
        assert qs["state"][0] == session
        assert qs["redirect_uri"][0] == "https://mcp.test/oauth/callback"
        # Forces consent on reconnect.
        assert qs["approval_prompt"][0] == "force"
        # Scopes: activity:read_all + profile:read_all (comma-separated).
        assert "activity:read_all" in qs["scope"][0]
        assert "profile:read_all" in qs["scope"][0]


@pytest.mark.asyncio
@respx.mock
async def test_strava_callback_persists_tokens_and_athlete(tmp_path):
    app, _, ts = _make_app(tmp_path)
    respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "at-new",
                "refresh_token": "rt-new",
                "expires_at": 9999999999,
                "athlete": {"id": 12345, "firstname": "Conner", "lastname": "B"},
            },
        )
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.get(f"/oauth/callback?code=g-code&state={session}")
        assert r.status_code == 303
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)
        assert qs["notice_kind"] == ["ok"]
        assert "Conner B" in qs["notice"][0]
    assert ts.data["refresh_token"] == "rt-new"
    assert ts.data["access_token"] == "at-new"
    assert ts.data["athlete_id"] == 12345
    assert ts.data["athlete_name"] == "Conner B"


@pytest.mark.asyncio
async def test_strava_callback_with_error_redirects_to_wizard_with_notice(tmp_path):
    app, _, ts = _make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.get(f"/oauth/callback?error=access_denied&state={session}")
        assert r.status_code == 303
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)
        assert qs["notice_kind"] == ["err"]
        assert "access_denied" in qs["notice"][0]
    assert ts.data["refresh_token"] == ""


@pytest.mark.asyncio
async def test_wizard_done_with_no_strava_bounces_back(tmp_path):
    app, _, _ = _make_app(tmp_path, seed_token=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        r = await c.post("/wizard/done", data={"session": session})
        assert r.status_code == 303
        loc = r.headers["location"]
        assert loc.startswith("/wizard?")
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
        assert qs["notice_kind"] == ["err"]


@pytest.mark.asyncio
async def test_full_happy_path_with_simulated_strava_callback(tmp_path):
    """End-to-end: approve → wizard → connect → Strava callback → done → Claude."""
    app, _, _ = _make_app(tmp_path)
    with respx.mock:
        respx.post("https://www.strava.com/oauth/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "at",
                    "refresh_token": "rt",
                    "expires_at": 9999999999,
                    "athlete": {"id": 1, "firstname": "C", "lastname": ""},
                },
            )
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
            client_id = await _register_client(c)
            _, challenge = _new_pkce_pair()
            session = await _post_approve(
                c, client_id=client_id, code_challenge=challenge, state="claudeS"
            )
            r = await c.get(f"/oauth/callback?code=g&state={session}")
            assert r.status_code == 303
            r = await c.get(f"/wizard?session={session}")
            assert "Connected as C" in r.text
            assert 'action="/wizard/done"' in r.text
            r = await c.post("/wizard/done", data={"session": session})
            assert r.status_code == 302
            loc = r.headers["location"]
            assert loc.startswith("https://claude.ai/cb?")
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
            assert "code" in qs
            assert qs["state"][0] == "claudeS"


@pytest.mark.asyncio
async def test_expired_session_is_rejected(tmp_path):
    app, provider, _ = _make_app(tmp_path, seed_token=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://mcp.test") as c:
        client_id = await _register_client(c)
        _, challenge = _new_pkce_pair()
        session = await _post_approve(c, client_id=client_id, code_challenge=challenge)
        rec = provider.store.data["pending_authorizations"][session]
        rec["expires_at"] = 0
        provider.store.save()
        r = await c.get(f"/wizard?session={session}")
        assert r.status_code == 400
        assert "expired" in r.text
