"""Tests for the Strava client and token persistence."""
from __future__ import annotations

import json
import time

import httpx
import pytest
import respx

from strava_mcp.storage import TokenStore
from strava_mcp.strava import StravaClient


@pytest.mark.asyncio
@respx.mock
async def test_refresh_fires_when_expires_within_leeway(stale_client, token_file):
    """If expires_at - 120 < now(), the next API call must refresh first."""
    refresh_route = respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access_after_refresh",
                "refresh_token": "refresh_rotated",
                "expires_at": int(time.time()) + 21600,
            },
        )
    )
    activities_route = respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(200, json=[])
    )

    await stale_client.list_activities()

    assert refresh_route.called, "refresh should have fired since token was within leeway"
    # Authorization on the activities call must use the refreshed token.
    auth = activities_route.calls.last.request.headers["authorization"]
    assert auth == "Bearer access_after_refresh"


@pytest.mark.asyncio
@respx.mock
async def test_no_refresh_when_token_is_fresh(fresh_client):
    """If the cached token is well outside the leeway, no refresh call is made."""
    refresh_route = respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(200, json=[])
    )
    await fresh_client.list_activities()
    assert not refresh_route.called, "fresh token must not trigger a refresh"


@pytest.mark.asyncio
@respx.mock
async def test_rotated_refresh_token_is_persisted_to_disk(stale_client, token_file):
    """When Strava returns a new refresh_token, it must be written to tokens.json.
    This is THE failure mode this server exists to prevent."""
    respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access_after_refresh",
                "refresh_token": "refresh_rotated_NEW",
                "expires_at": int(time.time()) + 21600,
            },
        )
    )
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(200, json=[])
    )

    await stale_client.list_activities()

    on_disk = json.loads(token_file.read_text())
    assert on_disk["refresh_token"] == "refresh_rotated_NEW"
    assert on_disk["access_token"] == "access_after_refresh"
    assert on_disk["expires_at"] > time.time() + 1000


@pytest.mark.asyncio
@respx.mock
async def test_refresh_keeps_existing_refresh_token_when_strava_omits_it(stale_client, token_file):
    """Defensive: if Strava ever omits refresh_token from a response, keep the old one."""
    respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access_after_refresh",
                "expires_at": int(time.time()) + 21600,
            },
        )
    )
    respx.get("https://www.strava.com/api/v3/athlete/activities").mock(
        return_value=httpx.Response(200, json=[])
    )
    await stale_client.list_activities()
    on_disk = json.loads(token_file.read_text())
    assert on_disk["refresh_token"] == "refresh_initial"


@pytest.mark.asyncio
@respx.mock
async def test_401_triggers_one_retry_with_fresh_token(fresh_client, token_file):
    """If Strava returns 401 with a cached token (revoked mid-flight), refresh and retry once."""
    activities_route = respx.get("https://www.strava.com/api/v3/athlete/activities")
    activities_route.mock(
        side_effect=[
            httpx.Response(401, text="bad token"),
            httpx.Response(200, json=[{"id": 1, "type": "Run"}]),
        ]
    )
    refresh_route = respx.post("https://www.strava.com/oauth/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "access_recovered",
                "refresh_token": "refresh_recovered",
                "expires_at": int(time.time()) + 21600,
            },
        )
    )
    out = await fresh_client.list_activities()
    assert out == [{"id": 1, "type": "Run"}]
    assert refresh_route.called
    # Second call uses the new token.
    assert activities_route.calls[1].request.headers["authorization"] == "Bearer access_recovered"


def test_storage_seeds_from_env_when_no_file(monkeypatch, tmp_path):
    monkeypatch.setenv("STRAVA_CLIENT_ID", "111")
    monkeypatch.setenv("STRAVA_CLIENT_SECRET", "secret")
    monkeypatch.setenv("STRAVA_REFRESH_TOKEN", "rT")
    monkeypatch.setenv("STRAVA_UNITS", "metric")

    p = tmp_path / "subdir" / "tokens.json"
    s = TokenStore(p)
    s.load_or_seed()

    on_disk = json.loads(p.read_text())
    assert on_disk["client_id"] == "111"
    assert on_disk["refresh_token"] == "rT"
    assert on_disk["units"] == "metric"
    assert set(on_disk.keys()) >= {
        "client_id",
        "client_secret",
        "refresh_token",
        "access_token",
        "expires_at",
        "units",
    }


def test_storage_prefers_disk_over_env(monkeypatch, tmp_path):
    monkeypatch.setenv("STRAVA_CLIENT_ID", "999_FROM_ENV")
    monkeypatch.setenv("STRAVA_CLIENT_SECRET", "ENV_SECRET")
    monkeypatch.setenv("STRAVA_REFRESH_TOKEN", "ENV_REFRESH")

    p = tmp_path / "tokens.json"
    p.write_text(
        json.dumps(
            {
                "client_id": "555_FROM_DISK",
                "client_secret": "DISK_SECRET",
                "refresh_token": "DISK_REFRESH",
                "access_token": "disk_access",
                "expires_at": int(time.time()) + 3600,
                "units": "imperial",
            }
        )
    )
    s = TokenStore(p)
    data = s.load_or_seed()
    assert data["client_id"] == "555_FROM_DISK"
    assert data["refresh_token"] == "DISK_REFRESH"
